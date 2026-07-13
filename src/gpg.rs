use anyhow::{bail, Result};
use base64::{engine::general_purpose, DecodeError, Engine as _};
use chrono::{TimeZone, Utc};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::not_line_ending,
    error::Error,
    sequence::separated_pair,
    AsChar, Finish, IResult, Parser,
};
use std::{
    fmt::{self, Display},
    fs,
    io::Read,
    path::Path,
    process::Command,
    str::FromStr,
};
use std::{io::Write, process::Stdio};
use thiserror::Error;

/// Provides details about the installed GPG client
#[derive(Debug)]
pub struct GpgInfo {
    /// The GnuPG version
    pub version: String,
    /// The version of libgcrypt used by GnuPG
    pub libgcrypt: String,
    /// The home directory, where configuration files are stored
    pub home_dir: String,
}

impl FromStr for GpgInfo {
    type Err = Error<String>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match parse_gpg_info(s).finish() {
            Ok((_, info)) => Ok(info),
            Err(Error { input, code }) => Err(Error {
                input: input.to_string(),
                code,
            }),
        }
    }
}

impl Display for GpgInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "version: {} (libgcrypt: {})",
            self.version, self.libgcrypt
        )?;
        writeln!(f, "homedir: {}", self.home_dir)?;
        Ok(())
    }
}

fn parse_gpg_info(input: &str) -> IResult<&str, GpgInfo> {
    let (i, version) = separated_pair(
        separated_pair(
            tag("gpg"),
            tag(" "),
            alt((tag("(GnuPG)"), tag("(GnuPG/MacGPG2)"))),
        ),
        tag(" "),
        not_line_ending,
    )
    .parse(input)?;
    let (i, _) = take_until("libgcrypt")(i)?;
    let (i, libgcrypt) = separated_pair(tag("libgcrypt"), tag(" "), not_line_ending).parse(i)?;
    let (i, _) = take_until("Home: ")(i)?;
    let (i, home_dir) = separated_pair(tag("Home:"), tag(" "), not_line_ending).parse(i)?;

    Ok((
        i,
        GpgInfo {
            version: version.1.into(),
            libgcrypt: libgcrypt.1.into(),
            home_dir: home_dir.1.into(),
        },
    ))
}

/// Builds a `Command` for the given GPG binary, pinned to the `C` locale so
/// that any human-oriented output it produces is deterministic and untranslated
fn gpg_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("LC_ALL", "C").env_remove("LANGUAGE");
    cmd
}

/// Inspects the OS for a GPG client and retrieves details about the
/// currently installed version
pub fn detect_version() -> Result<GpgInfo> {
    let gpg_details = gpg_command("gpg").arg("--version").output()?;

    let output = String::from_utf8(gpg_details.stdout)?;
    let gpg_info = output.parse::<GpgInfo>()?;

    Ok(gpg_info)
}

/// Configure GPG with sensible defaults
pub fn configure_defaults(home_dir: &str) -> Result<()> {
    let path = Path::new(home_dir).join("gpg.conf");
    fs::create_dir_all(home_dir)?;
    fs::write(
        path,
        b"use-agent
pinentry-mode loopback",
    )?;
    Ok(())
}

/// Configure the GPG agent with sensible defaults
pub fn configure_agent_defaults(home_dir: &str) -> Result<()> {
    let path = Path::new(home_dir).join("gpg-agent.conf");
    fs::create_dir_all(home_dir)?;
    fs::write(
        path,
        b"default-cache-ttl 21600
max-cache-ttl 31536000
allow-preset-passphrase
allow-loopback-pinentry",
    )?;
    reload_agent()
}

fn reload_agent() -> Result<()> {
    gpg_command("gpg-connect-agent")
        .args(vec!["RELOADAGENT", "/bye"])
        .output()?;

    Ok(())
}

/// A GPG private key
#[derive(Debug)]
pub struct GpgPrivateKey {
    /// The user identities associated with the private key; the first is
    /// used as the default git identity
    pub uids: Vec<GpgUid>,
    /// Internal details of the secret key
    pub secret_key: GpgKeyDetails,
    /// Internal details of the secret subkeys (0..N)
    pub subkeys: Vec<GpgKeyDetails>,
}

impl GpgPrivateKey {
    /// The primary user identity, used as the default git identity
    pub fn primary_uid(&self) -> &GpgUid {
        self.uids.first().expect(
            "GpgPrivateKey invariant violated: uids must be non-empty (only construct via parsing)",
        )
    }
}

/// A user identity associated with a GPG key
#[derive(Debug, PartialEq, Eq)]
pub struct GpgUid {
    /// The name portion of the user id
    pub name: String,
    /// The email portion of the user id
    pub email: String,
}

/// Contains internal details of a GPG private key
#[derive(Debug)]
pub struct GpgKeyDetails {
    /// The date of when the private key was generated
    pub creation_date: i64,
    /// The date for when the private key will expire
    pub expiration_date: Option<i64>,
    /// A fingerprint used for verification of the private key
    pub fingerprint: String,
    /// An 8 digit hexadecimal identifier for the private key
    pub key_id: String,
    /// A 20-byte hash identifier for the private key
    pub keygrip: String,
    /// The operations this key or subkey is capable of
    pub capabilities: GpgCapabilities,
}

/// The set of operations a GPG key or subkey is capable of, derived from the
/// lowercase letters in the colon-format capabilities field. Uppercase
/// letters in that field summarise the primary key's aggregate capability
/// across all subkeys and are ignored here in favour of this key's own.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GpgCapabilities {
    /// The key can be used to create signatures
    pub sign: bool,
    /// The key can be used to encrypt data
    pub encrypt: bool,
    /// The key can be used to certify other keys
    pub certify: bool,
    /// The key can be used for authentication
    pub authenticate: bool,
}

impl From<&str> for GpgCapabilities {
    fn from(field: &str) -> Self {
        GpgCapabilities {
            sign: field.contains('s'),
            encrypt: field.contains('e'),
            certify: field.contains('c'),
            authenticate: field.contains('a'),
        }
    }
}

impl FromStr for GpgPrivateKey {
    type Err = GpgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_gpg_key_details(s)
    }
}

impl Display for GpgPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for uid in &self.uids {
            if uid.email.is_empty() {
                writeln!(f, "user:           {}", uid.name)?;
            } else {
                writeln!(f, "user:           {} <{}>", uid.name, uid.email)?;
            }
        }
        writeln!(f, "fingerprint:    {}", self.secret_key.fingerprint)?;
        writeln!(f, "keygrip:        {}", self.secret_key.keygrip)?;
        writeln!(f, "key_id:         {}", self.secret_key.key_id)?;
        writeln!(
            f,
            "created_on:     {}",
            format_timestamp(self.secret_key.creation_date)
        )?;

        if let Some(expiration_date) = self.secret_key.expiration_date {
            writeln!(
                f,
                "expires_on:     {}",
                format_expiration_in_days(expiration_date)
            )?;
        }

        for subkey in &self.subkeys {
            writeln!(f, "sub_keygrip:    {}", subkey.keygrip)?;
            writeln!(f, "sub_key_id:     {}", subkey.key_id)?;
            writeln!(
                f,
                "sub_created_on: {}",
                format_timestamp(subkey.creation_date)
            )?;
            if let Some(expiration_date) = subkey.expiration_date {
                writeln!(
                    f,
                    "sub_expires_on: {}",
                    format_expiration_in_days(expiration_date)
                )?;
            }
        }
        Ok(())
    }
}

fn format_timestamp(secs_since_epoch: i64) -> String {
    let dt = Utc.timestamp_opt(secs_since_epoch, 0).unwrap();
    dt.to_rfc2822()
}

fn format_expiration_in_days(secs_since_epoch: i64) -> String {
    let expires_on = Utc.timestamp_opt(secs_since_epoch, 0).unwrap();
    let now = Utc::now();
    let days_until_expiry = (expires_on - now).num_days();

    let days_text = if days_until_expiry == 1 {
        "in 1 day".to_string()
    } else if days_until_expiry == 0 {
        "expires today".to_string()
    } else {
        format!("in {days_until_expiry} days")
    };

    format!("{} ({})", expires_on.to_rfc2822(), days_text)
}

/// Extracts the fingerprint of the first successfully imported key from
/// `--status-file` records (looks for an `IMPORT_OK` line), e.g.:
///
/// ```text
/// [GNUPG:] IMPORT_OK 17 BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127
/// ```
fn parse_status_import(status: &str) -> Option<String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("[GNUPG:] IMPORT_OK "))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .map(String::from)
}

/// Field indices (0-based, after splitting a colon-format line on `:`),
/// verified against real `gpg --with-colons --with-keygrip` output.
mod colon_field {
    pub const KEY_ID: usize = 4;
    pub const CREATION_DATE: usize = 5;
    pub const EXPIRATION_DATE: usize = 6;
    pub const CAPABILITIES: usize = 11;
    /// Shared by `fpr` (fingerprint), `grp` (keygrip) and `uid` (user id text)
    pub const RECORD_VALUE: usize = 9;
}

/// Parses gpg `--with-colons --with-keygrip` output for a single private key
/// into a [`GpgPrivateKey`]. Each line is dispatched independently on its
/// leading record tag, so a `uid` value containing text that happens to
/// match another tag (e.g. `ssb`) cannot derail parsing.
fn parse_gpg_key_details(input: &str) -> Result<GpgPrivateKey, GpgError> {
    let mut secret_key: Option<GpgKeyDetails> = None;
    let mut subkeys: Vec<GpgKeyDetails> = Vec::new();
    let mut uids: Vec<GpgUid> = Vec::new();

    for (line_no, line) in input.lines().enumerate() {
        let fields: Vec<&str> = line.split(':').collect();

        match fields.first().copied().unwrap_or_default() {
            "sec" | "ssb" => {
                let details = GpgKeyDetails {
                    key_id: field(&fields, colon_field::KEY_ID, line_no, line)?.to_string(),
                    creation_date: parse_timestamp(
                        field(&fields, colon_field::CREATION_DATE, line_no, line)?,
                        line_no,
                        line,
                    )?,
                    expiration_date: parse_optional_timestamp(
                        field(&fields, colon_field::EXPIRATION_DATE, line_no, line)?,
                        line_no,
                        line,
                    )?,
                    fingerprint: String::new(),
                    keygrip: String::new(),
                    capabilities: field(&fields, colon_field::CAPABILITIES, line_no, line)?.into(),
                };

                if fields[0] == "sec" {
                    if secret_key.is_some() {
                        return Err(GpgError::InvalidGpgKeyData(
                            "multiple primary keys (sec records) found in input; expected exactly one"
                                .to_string(),
                        ));
                    }
                    secret_key = Some(details);
                } else {
                    subkeys.push(details);
                }
            }
            "fpr" => {
                current_key(&mut secret_key, &mut subkeys, line_no, line)?.fingerprint =
                    field(&fields, colon_field::RECORD_VALUE, line_no, line)?.to_string();
            }
            "grp" => {
                current_key(&mut secret_key, &mut subkeys, line_no, line)?.keygrip =
                    field(&fields, colon_field::RECORD_VALUE, line_no, line)?.to_string();
            }
            "uid" => {
                uids.push(parse_uid(
                    field(&fields, colon_field::RECORD_VALUE, line_no, line)?,
                    line_no,
                    line,
                )?);
            }
            _ => {}
        }
    }

    let secret_key =
        secret_key.ok_or_else(|| GpgError::InvalidGpgKeyData("missing sec record".to_string()))?;
    if uids.is_empty() {
        return Err(GpgError::InvalidGpgKeyData(
            "missing uid record".to_string(),
        ));
    }

    validate_key_details(&secret_key, "primary key")?;
    for (i, subkey) in subkeys.iter().enumerate() {
        validate_key_details(subkey, &format!("subkey {}", i + 1))?;
    }

    Ok(GpgPrivateKey {
        uids,
        secret_key,
        subkeys,
    })
}

/// Ensures a `sec`/`ssb` record was followed by its `fpr` and `grp` records;
/// without them the fingerprint/keygrip are silently empty, which surfaces
/// as a confusing failure much later (e.g. presetting the passphrase for an
/// empty keygrip) rather than here, at parse time.
fn validate_key_details(details: &GpgKeyDetails, label: &str) -> Result<(), GpgError> {
    if details.fingerprint.is_empty() || details.keygrip.is_empty() {
        return Err(GpgError::InvalidGpgKeyData(format!(
            "{label} is missing its fingerprint or keygrip (no matching fpr/grp record)"
        )));
    }
    Ok(())
}

/// Returns the key details that a following `fpr`/`grp` record applies to:
/// the most recently opened subkey, falling back to the primary key.
fn current_key<'a>(
    secret_key: &'a mut Option<GpgKeyDetails>,
    subkeys: &'a mut [GpgKeyDetails],
    line_no: usize,
    line: &str,
) -> Result<&'a mut GpgKeyDetails, GpgError> {
    subkeys
        .last_mut()
        .or(secret_key.as_mut())
        .ok_or_else(|| GpgError::MalformedKeyRecord(line_no + 1, line.to_string()))
}

fn field<'a>(
    fields: &[&'a str],
    idx: usize,
    line_no: usize,
    line: &str,
) -> Result<&'a str, GpgError> {
    fields
        .get(idx)
        .copied()
        .ok_or_else(|| GpgError::MalformedKeyRecord(line_no + 1, line.to_string()))
}

fn parse_timestamp(value: &str, line_no: usize, line: &str) -> Result<i64, GpgError> {
    value
        .parse::<i64>()
        .map_err(|_| GpgError::MalformedKeyRecord(line_no + 1, line.to_string()))
}

fn parse_optional_timestamp(
    value: &str,
    line_no: usize,
    line: &str,
) -> Result<Option<i64>, GpgError> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_timestamp(value, line_no, line).map(Some)
    }
}

/// Decodes GnuPG's `--with-colons` escaping for free-form text fields
/// (currently only the uid field). Bytes that would be ambiguous in the
/// colon-delimited format -- notably `:` and `\` -- are written as
/// `\xHH`; verified against real gpg output (`Batman: Dark Knight` is
/// emitted as `Batman\x3a Dark Knight`, a literal `\` as `\x5c`).
/// Everything else, including multi-byte UTF-8, passes through as-is.
fn unescape_colon_field(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
            let hi = (bytes[i + 2] as char).to_digit(16);
            let lo = (bytes[i + 3] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// Parses a uid field, expected to look like `Name <email>`. GnuPG doesn't
/// guarantee an email is present (e.g. name-only user ids), so a missing
/// ` <...>` segment is treated as a name-only uid rather than an error; an
/// unterminated one (` <` with no closing `>`) is still malformed.
fn parse_uid(value: &str, line_no: usize, line: &str) -> Result<GpgUid, GpgError> {
    let value = unescape_colon_field(value);
    let Some((name, rest)) = value.split_once(" <") else {
        return Ok(GpgUid {
            name: value.to_string(),
            email: String::new(),
        });
    };

    let email = rest
        .strip_suffix('>')
        .ok_or_else(|| GpgError::MalformedKeyRecord(line_no + 1, line.to_string()))?;

    Ok(GpgUid {
        name: name.to_string(),
        email: email.to_string(),
    })
}

/// Errors that can occur when working with GPG keys
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GpgError {
    /// The provided key input was empty
    #[error("gpg key input is empty")]
    EmptyKeyInput,

    /// An invalid byte was detected during base64 decoding
    #[error("detected invalid byte at position {0} within gpg key '{1}'")]
    InvalidByteInGpgKey(usize, char),

    /// The decoded data is not a valid GPG key
    #[error("decoded data is not a valid gpg key: {0}")]
    InvalidGpgKeyData(String),

    /// A colon-format record from gpg could not be parsed
    #[error("malformed gpg colon record on line {0}: {1}")]
    MalformedKeyRecord(usize, String),

    /// The specified key was not found in the keyring
    #[error("gpg key not found: {0}")]
    KeyNotFound(String),

    /// The specified fingerprint was not found in the key
    #[error("fingerprint not found in key: {0}")]
    FingerprintNotFound(String),
}

/// Detects the key format and returns the raw key bytes.
/// Supports ASCII armored keys in both plain text and base64 encoded formats.
fn decode_key_input(key: &str) -> Result<Vec<u8>> {
    if key.is_empty() {
        bail!(GpgError::EmptyKeyInput);
    }

    if key.trim_start().starts_with("-----BEGIN PGP") {
        return Ok(key.as_bytes().to_vec());
    }

    match general_purpose::STANDARD.decode(key) {
        Ok(decoded_key) => Ok(decoded_key),
        Err(e) => match e {
            DecodeError::InvalidByte(offset, byte) => {
                bail!(GpgError::InvalidByteInGpgKey(offset, byte.as_char()))
            }
            _ => Err(e.into()),
        },
    }
}

/// Previews a GPG private key without importing it.
/// Returns key details by parsing the key data without adding it to the keyring.
pub fn preview_key(key: &str) -> Result<GpgPrivateKey> {
    let decoded = decode_key_input(key)?;

    let temp_dir = tempfile::tempdir()?;
    let key_path = temp_dir.path().join("key.asc");
    fs::write(&key_path, &decoded)?;

    let gpg_preview = gpg_command("gpg")
        .args([
            "--import-options",
            "show-only",
            "--with-colons",
            "--with-keygrip",
            "--import",
        ])
        .arg(&key_path)
        .output()?;

    if !gpg_preview.status.success() {
        let stderr = String::from_utf8_lossy(&gpg_preview.stderr);
        bail!(GpgError::InvalidGpgKeyData(stderr.trim().to_string()));
    }

    let output = String::from_utf8(gpg_preview.stdout)?;
    let key_details = output.parse::<GpgPrivateKey>()?;

    Ok(key_details)
}

/// Attempts to import a GPG private key
pub fn import_secret_key(key: &str) -> Result<String> {
    let decoded = decode_key_input(key)?;

    let status_file = tempfile::NamedTempFile::new()?;
    let status_path = status_file
        .path()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("status file path is not valid UTF-8"))?;

    let mut gpg_import = gpg_command("gpg")
        .args(["--status-file", status_path, "--import", "--batch", "--yes"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    gpg_import
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to open stdin for gpg process"))?
        .write_all(&decoded)?;

    let mut stderr = String::default();
    gpg_import
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to open stderr for gpg process"))?
        .read_to_string(&mut stderr)?;

    let status = gpg_import.wait()?;
    let status_records = fs::read_to_string(status_file.path())?;

    match (status.success(), parse_status_import(&status_records)) {
        (true, Some(fingerprint)) => Ok(fingerprint),
        _ => {
            let detail = stderr.trim();
            let detail = if detail.is_empty() {
                status_records.trim()
            } else {
                detail
            };
            Err(GpgError::InvalidGpgKeyData(detail.to_string()).into())
        }
    }
}

/// Extracts internal details for a given GPG private key and verifies its validity
pub fn extract_key_info(key_id: &str) -> Result<GpgPrivateKey> {
    let gpg_key_details = gpg_command("gpg")
        .args(vec![
            "--batch",
            "--with-colons",
            "--with-keygrip",
            "--list-secret-keys",
            "--fixed-list-mode",
            key_id,
        ])
        .output()?;

    if !gpg_key_details.status.success() {
        bail!(GpgError::KeyNotFound(key_id.to_string()));
    }

    let output = String::from_utf8(gpg_key_details.stdout)?;
    let key_details = output.parse::<GpgPrivateKey>()?;

    let current_timestamp = Utc::now().timestamp();
    if let Some(expiration_date) = key_details.secret_key.expiration_date {
        if expiration_date <= current_timestamp {
            bail!(
                "GPG secret key has expired on {}",
                Utc.timestamp_opt(expiration_date, 0).unwrap().to_rfc2822()
            );
        }
    }

    // Subkey expiry is intentionally not checked here: which subkey (if any)
    // is actually used for signing isn't known until the caller resolves a
    // signing key (e.g. via --fingerprint), so an expired, non-selected
    // subkey must not block an otherwise-usable key. See
    // GpgImport::configure_git_signing, which validates expiry for the
    // specific key that was selected.
    Ok(key_details)
}

/// Presets the passphrase for a given keygrip, ensuring it is cached for any
/// subsequent signing request
pub fn preset_passphrase(keygrip: &str, passphrase: &str) -> Result<()> {
    let set_passphrase = gpg_command("gpg-connect-agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;

    set_passphrase
        .stdin
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("failed to open stdin for gpg-connect-agent"))?
        .write_all(
            format!(
                "PRESET_PASSPHRASE {} -1 {}",
                keygrip,
                &hex::encode(passphrase).to_uppercase()
            )
            .as_bytes(),
        )?;
    set_passphrase.wait_with_output()?;
    Ok(())
}

/// Assign a trust level to an imported key
pub fn assign_trust_level(key_id: &str, trust_level: u8) -> Result<()> {
    let set_trust = gpg_command("gpg")
        .args(vec![
            "--batch",
            "--no-tty",
            "--command-fd",
            "0",
            "--edit-key",
            key_id,
            "trust",
            "quit",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;

    set_trust
        .stdin
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("failed to open stdin for gpg process"))?
        .write_all(format!("{trust_level}\ny\n").as_bytes())?;
    set_trust.wait_with_output()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Duration;
    use std::ffi::OsStr;
    use tempfile::TempDir;

    #[test]
    fn gpg_command_pins_c_locale() {
        let cmd = gpg_command("gpg");
        let envs: Vec<_> = cmd.get_envs().collect();

        assert!(envs.contains(&(OsStr::new("LC_ALL"), Some(OsStr::new("C")))));
        assert!(envs.contains(&(OsStr::new("LANGUAGE"), None)));
    }

    #[test]
    fn parse_status_import_extracts_fingerprint() {
        let status = "[GNUPG:] KEY_CONSIDERED BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127 0
[GNUPG:] IMPORT_OK 17 BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127
[GNUPG:] IMPORTED FDEFE8AB8796E127 batman <batman@dc.com>
[GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 0 1 0 0 0 0";

        let result = parse_status_import(status);
        assert_eq!(
            result,
            Some("BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127".to_string())
        );
    }

    #[test]
    fn parse_status_import_ignores_localised_noise() {
        // Regression: previously anchored on gettext-translated "gpg: key " stderr
        // prose; status-fd records are locale-stable regardless of surrounding output.
        let status = "gpg: Schlüssel BEEA4CDB4B0A80CB: geheimer Schlüssel importiert
[GNUPG:] IMPORT_OK 17 BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127";

        let result = parse_status_import(status);
        assert_eq!(
            result,
            Some("BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127".to_string())
        );
    }

    #[test]
    fn parse_status_import_returns_none_without_import_ok() {
        let status = "[GNUPG:] NODATA 1
[GNUPG:] IMPORT_RES 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";

        assert_eq!(parse_status_import(status), None);
    }

    #[test]
    fn parse_status_import_returns_none_for_empty_input() {
        assert_eq!(parse_status_import(""), None);
    }

    #[test]
    fn parse_gpg_version_output() {
        let gpg_output = "gpg (GnuPG) 2.4.5
libgcrypt 1.10.3
Copyright (C) 2024 g10 Code GmbH
License GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Home: /home/user/.gnupg
Supported algorithms:
Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA";

        let result = gpg_output.parse::<GpgInfo>();
        assert!(result.is_ok(), "Should parse GPG version output");

        let info = result.unwrap();
        assert_eq!(info.version, "2.4.5");
        assert_eq!(info.libgcrypt, "1.10.3");
        assert_eq!(info.home_dir, "/home/user/.gnupg");
    }

    #[test]
    fn configure_defaults_creates_gpg_conf() {
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_str().unwrap();

        let result = configure_defaults(home_dir);
        assert!(result.is_ok(), "Should create gpg.conf");

        let gpg_conf = temp_dir.path().join("gpg.conf");
        assert!(gpg_conf.exists(), "gpg.conf should exist");

        let content = fs::read_to_string(gpg_conf).unwrap();
        insta::assert_snapshot!(content);
    }

    #[test]
    fn configure_agent_defaults_creates_gpg_agent_conf() {
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_str().unwrap();

        let result = configure_agent_defaults(home_dir);
        assert!(result.is_ok(), "Should create gpg-agent.conf");

        let agent_conf = temp_dir.path().join("gpg-agent.conf");
        assert!(agent_conf.exists(), "gpg-agent.conf should exist");

        let content = fs::read_to_string(agent_conf).unwrap();
        insta::assert_snapshot!(content);
    }

    #[test]
    fn display_gpg_info() {
        let info = GpgInfo {
            version: "2.4.5".to_string(),
            libgcrypt: "1.10.3".to_string(),
            home_dir: "/home/user/.gnupg".to_string(),
        };
        insta::assert_snapshot!(info.to_string());
    }

    #[test]
    fn display_gpg_private_key_without_expiration() {
        let key = GpgPrivateKey {
            uids: vec![GpgUid {
                name: "batman".to_string(),
                email: "batman@dc.com".to_string(),
            }],
            secret_key: GpgKeyDetails {
                creation_date: 1700000000,
                expiration_date: None,
                fingerprint: "BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127".to_string(),
                key_id: "FDEFE8AB8796E127".to_string(),
                keygrip: "C4403DA4AF911084480BA46743E707CCDD082A24".to_string(),
                capabilities: GpgCapabilities {
                    sign: true,
                    certify: true,
                    ..Default::default()
                },
            },
            subkeys: vec![GpgKeyDetails {
                creation_date: 1700000000,
                expiration_date: None,
                fingerprint: "F36BE03211AF1D3CE26D8B3ABE6663F6A323FBE8".to_string(),
                key_id: "BE6663F6A323FBE8".to_string(),
                keygrip: "4AC8E7E7FD8B405DF2761726D296F98C9B778875".to_string(),
                capabilities: GpgCapabilities {
                    encrypt: true,
                    ..Default::default()
                },
            }],
        };
        insta::assert_snapshot!(key.to_string());
    }

    #[test]
    fn display_gpg_private_key_with_name_only_uid() {
        let key = GpgPrivateKey {
            uids: vec![GpgUid {
                name: "batman".to_string(),
                email: String::new(),
            }],
            secret_key: GpgKeyDetails {
                creation_date: 1700000000,
                expiration_date: None,
                fingerprint: "BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127".to_string(),
                key_id: "FDEFE8AB8796E127".to_string(),
                keygrip: "C4403DA4AF911084480BA46743E707CCDD082A24".to_string(),
                capabilities: GpgCapabilities {
                    sign: true,
                    certify: true,
                    ..Default::default()
                },
            },
            subkeys: vec![],
        };
        insta::assert_snapshot!(key.to_string());
    }

    fn generate_gpg_colon_format(
        secret_key_creation: i64,
        secret_key_expiration: i64,
        secret_subkey_creation: i64,
        secret_subkey_expiration: i64,
    ) -> String {
        format!(
            "sec:u:4096:1:FDEFE8AB8796E127:{}:{}::u:::scESC:::+:::23::0:
fpr:::::::::BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127:
grp:::::::::C4403DA4AF911084480BA46743E707CCDD082A24:
uid:u::::{}::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::batman <batman@dc.com>::::::::::0:
ssb:u:4096:1:BE6663F6A323FBE8:{}:{}:::::e:::+:::23:
fpr:::::::::F36BE03211AF1D3CE26D8B3ABE6663F6A323FBE8:
grp:::::::::4AC8E7E7FD8B405DF2761726D296F98C9B778875:",
            secret_key_creation,
            secret_key_expiration,
            secret_key_creation,
            secret_subkey_creation,
            secret_subkey_expiration
        )
    }

    #[test]
    fn extract_key_info() {
        let now = Utc::now();
        let secret_key_expiration = now + Duration::days(10);
        let secret_subkey_expiration = now + Duration::days(5);

        let gpg_colon_format = generate_gpg_colon_format(
            now.timestamp(),
            secret_key_expiration.timestamp(),
            now.timestamp(),
            secret_subkey_expiration.timestamp(),
        );

        let result = gpg_colon_format.parse::<GpgPrivateKey>();
        assert!(result.is_ok(), "Should parse GPG colon format");

        let key = result.unwrap();
        assert_eq!(key.uids.len(), 1);
        assert_eq!(key.primary_uid().name, "batman");
        assert_eq!(key.primary_uid().email, "batman@dc.com");
        assert_eq!(key.secret_key.creation_date, now.timestamp());
        assert_eq!(
            key.secret_key.expiration_date,
            Some(secret_key_expiration.timestamp())
        );
        assert_eq!(
            key.secret_key.fingerprint,
            "BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127"
        );
        assert_eq!(key.secret_key.key_id, "FDEFE8AB8796E127");
        assert_eq!(
            key.secret_key.keygrip,
            "C4403DA4AF911084480BA46743E707CCDD082A24"
        );
        assert!(key.secret_key.capabilities.sign);
        assert!(key.secret_key.capabilities.certify);
        assert!(!key.secret_key.capabilities.encrypt);

        assert_eq!(key.subkeys.len(), 1);
        let subkey = &key.subkeys[0];
        assert_eq!(subkey.creation_date, now.timestamp());
        assert_eq!(
            subkey.expiration_date,
            Some(secret_subkey_expiration.timestamp())
        );
        assert_eq!(subkey.key_id, "BE6663F6A323FBE8");
        assert_eq!(subkey.keygrip, "4AC8E7E7FD8B405DF2761726D296F98C9B778875");
        assert!(subkey.capabilities.encrypt);
        assert!(!subkey.capabilities.sign);
    }

    #[test]
    fn parse_sign_only_key_without_subkey() {
        let gpg_colon_format = "sec:u:4096:1:CA953C1735BEEB77:1700000000:::u:::scSC:::+:::23::0:
fpr:::::::::53C53C910B205E504F69EEA3CA953C1735BEEB77:
grp:::::::::591F029DF76C1A0673B7122D97CF0FA3962561DD:
uid:u::::1700000000::96652C75728C60697573C3570C362BED95E6544::robin <robin@dc.com>::::::::::0:";

        let result = gpg_colon_format.parse::<GpgPrivateKey>();
        assert!(result.is_ok(), "Should parse a sign-only key");

        let key = result.unwrap();
        assert!(key.subkeys.is_empty());
        assert_eq!(key.primary_uid().name, "robin");
    }

    #[test]
    fn parse_multiple_subkeys_with_capabilities() {
        let gpg_colon_format = "sec:u:2048:1:B8527C5AED483BE3:1700000000:::u:::scESCA:::+:::23::0:
fpr:::::::::24DA69B1615F5F3C6A9C3A60B8527C5AED483BE3:
grp:::::::::4D74903B8F3C8B017B3DC9FAA602D29429748FEE:
uid:u::::1700000000::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::batman <batman@dc.com>::::::::::0:
ssb:u:2048:1:B5F51E0E91062E1F:1700000000::::::e:::+:::23:
fpr:::::::::1151789CA9BEAFCB8998FB0CB5F51E0E91062E1F:
grp:::::::::7C1FAF12BFE4399DF3C64D6C16354057232DD75A:
ssb:u:2048:1:28BA2DEA0CFC5717:1700000100::::::s:::+:::23:
fpr:::::::::15404EFABA5A81EDBFA6C6B628BA2DEA0CFC5717:
grp:::::::::B644058C06C9EDA6E0EFBAAD8C847A86739DE73F:
ssb:u:2048:1:34E7EF9A6D5E41E6:1700000200::::::a:::+:::23:
fpr:::::::::AA5C366A86714B60DAD2DEA634E7EF9A6D5E41E6:
grp:::::::::6CD0471E9E43B60B911B7DA083B836ED51494DB7:";

        let result = gpg_colon_format.parse::<GpgPrivateKey>();
        assert!(result.is_ok(), "Should parse a key with 3 subkeys");

        let key = result.unwrap();
        assert_eq!(key.subkeys.len(), 3);

        assert_eq!(key.subkeys[0].key_id, "B5F51E0E91062E1F");
        assert!(key.subkeys[0].capabilities.encrypt);
        assert!(!key.subkeys[0].capabilities.sign);

        assert_eq!(key.subkeys[1].key_id, "28BA2DEA0CFC5717");
        assert!(key.subkeys[1].capabilities.sign);
        assert!(!key.subkeys[1].capabilities.encrypt);

        assert_eq!(key.subkeys[2].key_id, "34E7EF9A6D5E41E6");
        assert!(key.subkeys[2].capabilities.authenticate);
    }

    #[test]
    fn parse_multiple_uids() {
        let gpg_colon_format = "sec:u:4096:1:FDEFE8AB8796E127:1700000000:::u:::scESC:::+:::23::0:
fpr:::::::::BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127:
grp:::::::::C4403DA4AF911084480BA46743E707CCDD082A24:
uid:u::::1700000000::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::batman <batman@dc.com>::::::::::0:
uid:u::::1700000000::1E9C7598797E7F7A380A72A58B9B7FA28160AB07::bruce wayne <bruce@wayne.com>::::::::::0:";

        let result = gpg_colon_format.parse::<GpgPrivateKey>();
        assert!(result.is_ok(), "Should parse a key with multiple uids");

        let key = result.unwrap();
        assert_eq!(key.uids.len(), 2);
        assert_eq!(key.primary_uid().name, "batman");
        assert_eq!(key.uids[1].name, "bruce wayne");
        assert_eq!(key.uids[1].email, "bruce@wayne.com");
    }

    #[test]
    fn unescape_colon_field_decodes_hex_escapes() {
        // Verified against real gpg --with-colons output: a literal `:` is
        // written as \x3a, a literal `\` as \x5c.
        assert_eq!(
            unescape_colon_field("Batman\\x3a Dark Knight"),
            "Batman: Dark Knight"
        );
        assert_eq!(
            unescape_colon_field("Batman \\x5c Robin"),
            "Batman \\ Robin"
        );
        assert_eq!(unescape_colon_field("Bätman Ünïcode"), "Bätman Ünïcode");
        assert_eq!(unescape_colon_field("no escapes here"), "no escapes here");
    }

    #[test]
    fn unescape_colon_field_ignores_malformed_escape() {
        assert_eq!(
            unescape_colon_field("Batman\\xZZ Robin"),
            "Batman\\xZZ Robin"
        );
        assert_eq!(unescape_colon_field("Batman\\x3"), "Batman\\x3");
    }

    #[test]
    fn parse_uid_decodes_colon_hex_escape() {
        let gpg_colon_format = "sec:u:4096:1:FDEFE8AB8796E127:1700000000:::u:::scESC:::+:::23::0:
fpr:::::::::BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127:
grp:::::::::C4403DA4AF911084480BA46743E707CCDD082A24:
uid:u::::1700000000::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::Batman\\x3a Dark Knight <batman@dc.com>::::::::::0:";

        let result = gpg_colon_format.parse::<GpgPrivateKey>();
        assert!(
            result.is_ok(),
            "Should parse a uid containing a C-quoted colon"
        );

        let key = result.unwrap();
        assert_eq!(key.primary_uid().name, "Batman: Dark Knight");
        assert_eq!(key.primary_uid().email, "batman@dc.com");
    }

    #[test]
    fn parse_uid_without_email() {
        assert_eq!(
            parse_uid("batman", 0, "uid:...:batman:").unwrap(),
            GpgUid {
                name: "batman".to_string(),
                email: String::new(),
            }
        );
    }

    #[test]
    fn parse_uid_with_unterminated_email_fails() {
        let result = parse_uid("batman <batman@dc.com", 0, "uid:...:batman <batman@dc.com:");
        assert!(matches!(result, Err(GpgError::MalformedKeyRecord(1, _))));
    }

    #[test]
    fn parse_name_only_uid_key() {
        let gpg_colon_format = "sec:u:4096:1:FDEFE8AB8796E127:1700000000:::u:::scESC:::+:::23::0:
fpr:::::::::BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127:
grp:::::::::C4403DA4AF911084480BA46743E707CCDD082A24:
uid:u::::1700000000::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::batman::::::::::0:";

        let result = gpg_colon_format.parse::<GpgPrivateKey>();
        assert!(result.is_ok(), "A name-only uid should not fail parsing");

        let key = result.unwrap();
        assert_eq!(key.primary_uid().name, "batman");
        assert_eq!(key.primary_uid().email, "");
    }

    #[test]
    fn parse_uid_containing_record_tag_substrings() {
        let gpg_colon_format = "sec:u:4096:1:FDEFE8AB8796E127:1700000000:::u:::scESC:::+:::23::0:
fpr:::::::::BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127:
grp:::::::::C4403DA4AF911084480BA46743E707CCDD082A24:
uid:u::::1700000000::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::grossberg fpr sec ssb <grossberg@dc.com>::::::::::0:
ssb:u:4096:1:BE6663F6A323FBE8:1700000000::::::e:::+:::23:
fpr:::::::::F36BE03211AF1D3CE26D8B3ABE6663F6A323FBE8:
grp:::::::::4AC8E7E7FD8B405DF2761726D296F98C9B778875:";

        let result = gpg_colon_format.parse::<GpgPrivateKey>();
        assert!(
            result.is_ok(),
            "A uid containing ssb/sec/fpr substrings should not derail parsing"
        );

        let key = result.unwrap();
        assert_eq!(key.primary_uid().name, "grossberg fpr sec ssb");
        assert_eq!(key.primary_uid().email, "grossberg@dc.com");
        assert_eq!(key.subkeys.len(), 1);
        assert_eq!(key.subkeys[0].key_id, "BE6663F6A323FBE8");
    }

    #[test]
    fn parse_missing_sec_record_fails() {
        let result = "uid:u::::1700000000::hash::batman <batman@dc.com>::::::::::0:"
            .parse::<GpgPrivateKey>();

        assert!(matches!(result, Err(GpgError::InvalidGpgKeyData(_))));
    }

    #[test]
    fn parse_missing_uid_record_fails() {
        let result = "sec:u:4096:1:FDEFE8AB8796E127:1700000000:::u:::scESC:::+:::23::0:
fpr:::::::::BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127:
grp:::::::::C4403DA4AF911084480BA46743E707CCDD082A24:"
            .parse::<GpgPrivateKey>();

        assert!(matches!(result, Err(GpgError::InvalidGpgKeyData(_))));
    }

    #[test]
    fn parse_truncated_record_reports_line_number() {
        let result = "sec:u:4096:1:FDEFE8AB8796E127:1700000000\nuid:u::::1700000000::hash::batman <batman@dc.com>::::::::::0:"
            .parse::<GpgPrivateKey>();

        match result {
            Err(GpgError::MalformedKeyRecord(line_no, _)) => assert_eq!(line_no, 1),
            other => panic!("expected MalformedKeyRecord on line 1, got {other:?}"),
        }
    }

    #[test]
    fn parse_sec_missing_fpr_and_grp_fails() {
        let result = "sec:u:4096:1:FDEFE8AB8796E127:1700000000:::u:::scESC:::+:::23::0:
uid:u::::1700000000::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::batman <batman@dc.com>::::::::::0:"
            .parse::<GpgPrivateKey>();

        assert!(
            matches!(result, Err(GpgError::InvalidGpgKeyData(_))),
            "A sec record with no matching fpr/grp should not yield an empty fingerprint/keygrip: {result:?}"
        );
    }

    #[test]
    fn parse_ssb_missing_fpr_and_grp_fails() {
        let result = "sec:u:4096:1:FDEFE8AB8796E127:1700000000:::u:::scESC:::+:::23::0:
fpr:::::::::BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127:
grp:::::::::C4403DA4AF911084480BA46743E707CCDD082A24:
uid:u::::1700000000::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::batman <batman@dc.com>::::::::::0:
ssb:u:4096:1:BE6663F6A323FBE8:1700000000::::::e:::+:::23:"
            .parse::<GpgPrivateKey>();

        assert!(
            matches!(result, Err(GpgError::InvalidGpgKeyData(_))),
            "An ssb record with no matching fpr/grp should not yield an empty fingerprint/keygrip: {result:?}"
        );
    }

    #[test]
    fn parse_multiple_sec_records_fails() {
        let result = "sec:u:4096:1:FDEFE8AB8796E127:1700000000:::u:::scESC:::+:::23::0:
fpr:::::::::BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127:
grp:::::::::C4403DA4AF911084480BA46743E707CCDD082A24:
uid:u::::1700000000::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::batman <batman@dc.com>::::::::::0:
sec:u:4096:1:AAAAAAAAAAAAAAAA:1700000000:::u:::scESC:::+:::23::0:
fpr:::::::::1111111111111111111111111111111111111111:
grp:::::::::2222222222222222222222222222222222222222:
uid:u::::1700000000::1E9C7598797E7F7A380A72A58B9B7FA28160AB07::robin <robin@dc.com>::::::::::0:"
            .parse::<GpgPrivateKey>();

        assert!(
            matches!(result, Err(GpgError::InvalidGpgKeyData(_))),
            "A second sec record must not silently merge into a hybrid of two keys: {result:?}"
        );
    }
}
