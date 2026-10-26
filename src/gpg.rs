use anyhow::{Result, bail};
use base64::{DecodeError, Engine as _, engine::general_purpose};
use chrono::{DateTime, Datelike, Utc};
use std::{
    fmt::{self, Display},
    fs,
    path::Path,
    process::{Command, Output},
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
    type Err = GpgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_gpg_info(s).ok_or_else(|| GpgError::UnrecognisedVersionOutput(s.to_string()))
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

/// Parses the `gpg --version` header, e.g.:
///
/// ```text
/// gpg (GnuPG) 2.4.5
/// libgcrypt 1.10.3
/// ...
/// Home: /home/user/.gnupg
/// ```
fn parse_gpg_info(input: &str) -> Option<GpgInfo> {
    let first_line = input.lines().next()?;
    let version = first_line
        .strip_prefix("gpg (GnuPG) ")
        .or_else(|| first_line.strip_prefix("gpg (GnuPG/MacGPG2) "))?;
    let value_of = |prefix: &str| input.lines().find_map(|line| line.strip_prefix(prefix));

    Some(GpgInfo {
        version: version.to_string(),
        libgcrypt: value_of("libgcrypt ")?.to_string(),
        home_dir: value_of("Home: ")?.to_string(),
    })
}

/// Builds a `Command` for the given GPG binary, pinned to the `C` locale so
/// that any human-oriented output it produces is deterministic and untranslated
fn gpg_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env("LC_ALL", "C").env_remove("LANGUAGE");
    cmd
}

/// Runs a GPG binary to completion and fails with its trimmed stderr if it
/// exits non-zero. `input` is written from a separate thread while stdout
/// and stderr are drained, so neither side can block on a full pipe, and the
/// process is always waited on, even if it exits before reading its input
fn run(program: &str, args: &[&str], input: &[u8]) -> Result<Output> {
    let mut child = gpg_command(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to open stdin for {program}"))?;

    let (output, written) = std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(input));
        let output = child.wait_with_output();
        (output, writer.join())
    });
    let output = output?;

    // Check the exit status first: a process that exits early also breaks
    // the stdin pipe, and its stderr explains why
    if !output.status.success() {
        // Fall back to stdout, e.g. `--status-fd 1` records, if stderr is empty
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = match stderr.trim() {
            "" => String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr => stderr.to_string(),
        };
        bail!(GpgError::CommandFailed(
            program.to_string(),
            output.status.to_string(),
            detail
        ));
    }
    written.map_err(|_| anyhow::anyhow!("stdin writer for {program} panicked"))??;

    Ok(output)
}

/// Inspects the OS for a GPG client and retrieves details about the
/// currently installed version
pub fn detect_version() -> Result<GpgInfo> {
    let gpg_details = run("gpg", &["--version"], b"")?;

    let output = String::from_utf8(gpg_details.stdout)?;
    let gpg_info = output.parse::<GpgInfo>()?;

    Ok(gpg_info)
}

/// Configure GPG with sensible defaults, unless `gpg.conf` already exists.
/// Returns whether the file was written
pub fn configure_defaults(home_dir: &str) -> Result<bool> {
    write_if_missing(
        home_dir,
        "gpg.conf",
        b"use-agent
pinentry-mode loopback",
    )
}

/// Configure the GPG agent with sensible defaults, unless `gpg-agent.conf`
/// already exists. Returns whether the file was written
pub fn configure_agent_defaults(home_dir: &str) -> Result<bool> {
    let written = write_if_missing(
        home_dir,
        "gpg-agent.conf",
        b"default-cache-ttl 21600
max-cache-ttl 31536000
allow-preset-passphrase
allow-loopback-pinentry",
    )?;
    // Reloading also clears the agent's passphrase cache, so leave an agent
    // running with the user's own config alone
    if written {
        reload_agent(home_dir)?;
    }
    Ok(written)
}

/// Writes a config file only if it does not exist, so a user's own GPG
/// configuration is never overwritten
fn write_if_missing(home_dir: &str, name: &str, contents: &[u8]) -> Result<bool> {
    fs::create_dir_all(home_dir)?;
    create_new_with(&Path::new(home_dir).join(name), |file| {
        file.write_all(contents)
    })
}

/// Creates `path` and fills it with `write`, returning false if it already
/// exists. If `write` fails, the new file is removed: a partly written config
/// would otherwise count as existing on every later run
fn create_new_with(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> std::io::Result<()>,
) -> Result<bool> {
    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e.into()),
    };

    if let Err(e) = write(&mut file) {
        // create_new guarantees this run created the file, so it is safe to remove
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    Ok(true)
}

/// Reloads the agent serving `home_dir`, the directory whose config was just written
fn reload_agent(home_dir: &str) -> Result<()> {
    agent_command(&["--homedir", home_dir], "RELOADAGENT")
}

/// Sends a single command to gpg-agent over stdin (keeping secrets out of
/// the process table). `gpg-connect-agent` exits 0 even when the agent
/// answers `ERR`, so success is only reported if the agent replied `OK`
fn agent_command(args: &[&str], command: &str) -> Result<()> {
    let output = run("gpg-connect-agent", args, format!("{command}\n").as_bytes())?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.lines().any(|line| line.starts_with("OK")) {
        return Ok(());
    }

    let reason = stdout
        .lines()
        .find(|line| line.starts_with("ERR"))
        .map(str::to_string)
        .unwrap_or_else(|| String::from_utf8_lossy(&output.stderr).trim().to_string());
    bail!("gpg-agent rejected the request: {reason}")
}

/// A GPG private key
#[derive(Debug)]
pub struct GpgPrivateKey {
    /// The user identities associated with the private key; the first is
    /// used as the default git identity
    pub uids: Vec<GpgUid>,
    /// Internal details of the primary key
    pub primary_key: GpgKeyDetails,
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
        writeln!(f, "fingerprint:    {}", self.primary_key.fingerprint)?;
        writeln!(f, "keygrip:        {}", self.primary_key.keygrip)?;
        writeln!(f, "key_id:         {}", self.primary_key.key_id)?;
        writeln!(
            f,
            "created_on:     {}",
            format_timestamp(self.primary_key.creation_date)
        )?;

        if let Some(expiration_date) = self.primary_key.expiration_date {
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

/// Returns the timestamp as a date only if `to_rfc2822` can format it
/// without panicking, which needs a year from 0 to 9999
fn rfc2822_datetime(secs_since_epoch: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(secs_since_epoch, 0).filter(|dt| (0..=9999).contains(&dt.year()))
}

/// Formats as RFC 2822, falling back to the raw seconds if out of range
pub(crate) fn format_timestamp(secs_since_epoch: i64) -> String {
    rfc2822_datetime(secs_since_epoch)
        .map_or_else(|| secs_since_epoch.to_string(), |dt| dt.to_rfc2822())
}

fn format_expiration_in_days(secs_since_epoch: i64) -> String {
    let Some(expires_on) = rfc2822_datetime(secs_since_epoch) else {
        return secs_since_epoch.to_string();
    };
    let now = Utc::now();
    let days_until_expiry = (expires_on - now).num_days();

    let days_text = if expires_on <= now {
        match -days_until_expiry {
            0 => "expired today".to_string(),
            1 => "expired 1 day ago".to_string(),
            days => format!("expired {days} days ago"),
        }
    } else if days_until_expiry == 1 {
        "in 1 day".to_string()
    } else if days_until_expiry == 0 {
        "expires today".to_string()
    } else {
        format!("in {days_until_expiry} days")
    };

    format!("{} ({})", expires_on.to_rfc2822(), days_text)
}

/// Extracts the fingerprint of the imported secret key from `--status-fd`
/// records: an `IMPORT_OK` line with flag bit 16 set, e.g.:
///
/// ```text
/// [GNUPG:] IMPORT_OK 17 BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127
/// ```
///
/// gpg writes a public-key record (flags `1`, or `0` if already present)
/// before the secret one, so every `IMPORT_OK` line is checked. A second
/// fingerprint, public or secret, means the input held more than one key.
fn parse_status_import(status: &str) -> Result<String, GpgError> {
    let mut fingerprints: Vec<&str> = Vec::new();
    let mut secret_key = None;

    for rest in status
        .lines()
        .filter_map(|line| line.strip_prefix("[GNUPG:] IMPORT_OK "))
    {
        let mut fields = rest.split_whitespace();
        let (Some(Ok(flags)), Some(fpr)) = (fields.next().map(str::parse::<u32>), fields.next())
        else {
            continue;
        };

        if !fingerprints.contains(&fpr) {
            fingerprints.push(fpr);
        }
        if flags & 16 != 0 {
            secret_key = Some(fpr);
        }
    }

    if fingerprints.len() > 1 {
        return Err(GpgError::MultipleKeys(
            fingerprints.into_iter().map(String::from).collect(),
        ));
    }
    secret_key.map(String::from).ok_or(GpgError::NoSecretKey)
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
    let mut primary_key: Option<GpgKeyDetails> = None;
    let mut subkeys: Vec<GpgKeyDetails> = Vec::new();
    let mut uids: Vec<GpgUid> = Vec::new();

    // A public key's records would otherwise attach to the secret key's
    let primary_keys = input
        .lines()
        .filter(|line| line.starts_with("sec:") || line.starts_with("pub:"))
        .count();
    if primary_keys > 1 {
        return Err(GpgError::InvalidGpgKeyData(
            "multiple primary keys (sec or pub records) found in input; expected exactly one"
                .to_string(),
        ));
    }

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
                    primary_key = Some(details);
                } else {
                    subkeys.push(details);
                }
            }
            "fpr" => {
                current_key(&mut primary_key, &mut subkeys, line_no, line)?.fingerprint =
                    field(&fields, colon_field::RECORD_VALUE, line_no, line)?.to_string();
            }
            "grp" => {
                current_key(&mut primary_key, &mut subkeys, line_no, line)?.keygrip =
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

    let primary_key =
        primary_key.ok_or_else(|| GpgError::InvalidGpgKeyData("missing sec record".to_string()))?;
    if uids.is_empty() {
        return Err(GpgError::InvalidGpgKeyData(
            "missing uid record".to_string(),
        ));
    }

    validate_key_details(&primary_key, "primary key")?;
    for (i, subkey) in subkeys.iter().enumerate() {
        validate_key_details(subkey, &format!("subkey {}", i + 1))?;
    }

    Ok(GpgPrivateKey {
        uids,
        primary_key,
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
    primary_key: &'a mut Option<GpgKeyDetails>,
    subkeys: &'a mut [GpgKeyDetails],
    line_no: usize,
    line: &str,
) -> Result<&'a mut GpgKeyDetails, GpgError> {
    subkeys
        .last_mut()
        .or(primary_key.as_mut())
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
        .ok()
        .filter(|secs| DateTime::from_timestamp(*secs, 0).is_some())
        .ok_or_else(|| GpgError::MalformedKeyRecord(line_no + 1, line.to_string()))
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

    /// The imported key had no secret key material
    #[error(
        "the provided key contains no secret key material; export it with 'gpg --armor --export-secret-key <id>'"
    )]
    NoSecretKey,

    /// `gpg --version` output did not have the expected header
    #[error("unrecognised gpg --version output: {0}")]
    UnrecognisedVersionOutput(String),

    /// The input held more than one key, listed by fingerprint
    #[error("the provided input contains {} keys ({}); import one key per run", .0.len(), .0.join(", "))]
    MultipleKeys(Vec<String>),

    /// The specified key was not found in the keyring
    #[error("gpg key not found: {0}")]
    KeyNotFound(String),

    /// The specified fingerprint was not found in the key
    #[error("fingerprint not found in key: {0}")]
    FingerprintNotFound(String),

    /// The selected key or subkey is not signing-capable
    #[error("selected key cannot sign: {0}")]
    KeyCannotSign(String),

    /// The imported key could not make and verify a test signature
    #[error(
        "couldn't make a test signature with {0}; check the passphrase is correct (or pass --skip-verify): {1}"
    )]
    SigningCheckFailed(String, String),

    /// A GPG process ran but exited non-zero: program, exit status, stderr
    /// (or stdout if stderr was empty)
    #[error("{0} failed ({1}): {2}")]
    CommandFailed(String, String, String),
}

/// Detects the key format and returns the raw key bytes.
/// Supports ASCII armored keys in both plain text and base64 encoded formats.
// Public, but hidden from the docs, only so the fuzz targets in fuzz/ can call it
#[doc(hidden)]
pub fn decode_key_input(key: &str) -> Result<Vec<u8>> {
    if key.trim_start().starts_with("-----BEGIN PGP") {
        return Ok(key.as_bytes().to_vec());
    }

    // `base64` wraps its output at 76 columns by default, and secrets often
    // gain a trailing newline, so ignore whitespace rather than reject it.
    let non_whitespace = || {
        key.bytes()
            .enumerate()
            .filter(|(_, b)| !b.is_ascii_whitespace())
    };
    let stripped: Vec<u8> = non_whitespace().map(|(_, b)| b).collect();
    if stripped.is_empty() {
        bail!(GpgError::EmptyKeyInput);
    }

    match general_purpose::STANDARD.decode(&stripped) {
        Ok(decoded_key) => Ok(decoded_key),
        Err(e) => match e {
            DecodeError::InvalidByte(offset, byte) => {
                // Report the position within the key as supplied, not the stripped copy.
                let position = non_whitespace().nth(offset).map_or(offset, |(i, _)| i);
                bail!(GpgError::InvalidByteInGpgKey(position, char::from(byte)))
            }
            _ => Err(e.into()),
        },
    }
}

/// Previews a GPG private key without importing it.
/// Returns key details by parsing the key data without adding it to the keyring.
pub fn preview_key(key: &str) -> Result<GpgPrivateKey> {
    let decoded = decode_key_input(key)?;

    let gpg_preview = run_gpg_import(
        &[
            "--import-options",
            "show-only",
            "--with-colons",
            "--with-keygrip",
            "--import",
        ],
        &decoded,
    )?;

    let output = String::from_utf8(gpg_preview.stdout)?;
    let key_details = output.parse::<GpgPrivateKey>()?;

    Ok(key_details)
}

/// Attempts to import a GPG private key
pub fn import_secret_key(key: &str) -> Result<String> {
    let decoded = decode_key_input(key)?;

    // `gpg --import` writes nothing else to stdout, so it holds only the
    // status records
    let output = run_gpg_import(
        &["--status-fd", "1", "--import", "--batch", "--yes"],
        &decoded,
    )?;
    Ok(parse_status_import(&String::from_utf8_lossy(
        &output.stdout,
    ))?)
}

/// Runs a gpg import with the key on stdin. Only gpg rejecting the key means
/// the key is invalid. Failing to start gpg or talk to it is passed through
/// unchanged
fn run_gpg_import(args: &[&str], key: &[u8]) -> Result<Output> {
    run("gpg", args, key).map_err(|e| match e.downcast::<GpgError>() {
        Ok(GpgError::CommandFailed(_, _, stderr)) => GpgError::InvalidGpgKeyData(stderr).into(),
        Ok(other) => other.into(),
        Err(e) => e,
    })
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
    if let Some(expiration_date) = key_details.primary_key.expiration_date
        && expiration_date <= current_timestamp
    {
        bail!(
            "GPG secret key has expired on {}",
            format_timestamp(expiration_date)
        );
    }

    // Subkey expiry is intentionally not checked here: which subkey (if any)
    // is actually used for signing isn't known until the caller resolves a
    // signing key (e.g. via --fingerprint), so an expired, non-selected
    // subkey must not block an otherwise-usable key. See
    // GpgImport::configure_git_signing, which validates expiry for the
    // specific key that was selected.
    Ok(key_details)
}

/// Proves `signing_key` can sign: signs a short message with it, exactly as
/// git would, then verifies the signature. Returns the fingerprint of the key
/// or subkey that signed. `--pinentry-mode error` fails rather than prompting,
/// so a missing or wrong passphrase is reported instead of opening a dialog
pub fn verify_signing(signing_key: &str) -> Result<String> {
    let signed = run(
        "gpg",
        &[
            "--batch",
            "--pinentry-mode",
            "error",
            "--local-user",
            signing_key,
            "--sign",
            "--armor",
        ],
        b"gpg-import signing check\n",
    )
    .map_err(|e| match e.downcast::<GpgError>() {
        // gpg repeats the same failure line, so keep only the last
        Ok(GpgError::CommandFailed(_, _, stderr)) => GpgError::SigningCheckFailed(
            signing_key.to_string(),
            stderr.lines().last().unwrap_or_default().to_string(),
        )
        .into(),
        Ok(other) => other.into(),
        Err(e) => e,
    })?;

    let verified = run(
        "gpg",
        &["--batch", "--status-fd", "1", "--verify"],
        &signed.stdout,
    )?;
    parse_validsig(&String::from_utf8_lossy(&verified.stdout)).ok_or_else(|| {
        GpgError::SigningCheckFailed(
            signing_key.to_string(),
            "the signature did not verify".to_string(),
        )
        .into()
    })
}

/// Extracts the fingerprint of the signing key from a `--status-fd` record:
///
/// ```text
/// [GNUPG:] VALIDSIG <signing key fpr> <date> <timestamp> ... <primary key fpr>
/// ```
fn parse_validsig(status: &str) -> Option<String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("[GNUPG:] VALIDSIG "))
        .and_then(|rest| rest.split_whitespace().next())
        .map(String::from)
}

/// Presets the passphrase for a given keygrip, ensuring it is cached for any
/// subsequent signing request
pub fn preset_passphrase(keygrip: &str, passphrase: &str) -> Result<()> {
    agent_command(
        &[],
        &format!(
            "PRESET_PASSPHRASE {} -1 {}",
            keygrip,
            passphrase
                .bytes()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
        ),
    )
}

/// Assign a trust level to an imported key
pub fn assign_trust_level(key_id: &str, trust_level: u8) -> Result<()> {
    run(
        "gpg",
        &[
            "--batch",
            "--no-tty",
            "--command-fd",
            "0",
            "--edit-key",
            key_id,
            "trust",
            "quit",
        ],
        format!("{trust_level}\ny\n").as_bytes(),
    )?;
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
            Ok("BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127".to_string())
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
            Ok("BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127".to_string())
        );
    }

    #[test]
    fn parse_status_import_returns_no_secret_key_without_import_ok() {
        let status = "[GNUPG:] NODATA 1
[GNUPG:] IMPORT_RES 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";

        assert_eq!(parse_status_import(status), Err(GpgError::NoSecretKey));
    }

    #[test]
    fn parse_status_import_returns_no_secret_key_for_public_only_key() {
        let status = "[GNUPG:] IMPORT_OK 1 294B469239FA3BAA8F3189C306DAA1368B5ABCC8
[GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0";

        assert_eq!(parse_status_import(status), Err(GpgError::NoSecretKey));
    }

    #[test]
    fn parse_status_import_returns_no_secret_key_for_public_key_already_in_keyring() {
        let status = "[GNUPG:] IMPORT_OK 0 294B469239FA3BAA8F3189C306DAA1368B5ABCC8
[GNUPG:] IMPORT_RES 1 0 0 0 1 0 0 0 0 0 0 0 0 0 0";

        assert_eq!(parse_status_import(status), Err(GpgError::NoSecretKey));
    }

    #[test]
    fn parse_status_import_finds_secret_record_after_public_one() {
        let status = "[GNUPG:] IMPORT_OK 1 294B469239FA3BAA8F3189C306DAA1368B5ABCC8
[GNUPG:] IMPORT_OK 17 294B469239FA3BAA8F3189C306DAA1368B5ABCC8";

        assert_eq!(
            parse_status_import(status),
            Ok("294B469239FA3BAA8F3189C306DAA1368B5ABCC8".to_string())
        );
    }

    #[test]
    fn parse_status_import_accepts_secret_key_already_in_keyring() {
        let status = "[GNUPG:] IMPORT_OK 0 294B469239FA3BAA8F3189C306DAA1368B5ABCC8
[GNUPG:] IMPORT_OK 16 294B469239FA3BAA8F3189C306DAA1368B5ABCC8";

        assert_eq!(
            parse_status_import(status),
            Ok("294B469239FA3BAA8F3189C306DAA1368B5ABCC8".to_string())
        );
    }

    #[test]
    fn parse_status_import_rejects_more_than_one_secret_key() {
        let status = "[GNUPG:] IMPORT_OK 1 BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127
[GNUPG:] IMPORT_OK 17 BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127
[GNUPG:] IMPORT_OK 1 294B469239FA3BAA8F3189C306DAA1368B5ABCC8
[GNUPG:] IMPORT_OK 17 294B469239FA3BAA8F3189C306DAA1368B5ABCC8";

        assert_eq!(
            parse_status_import(status),
            Err(GpgError::MultipleKeys(vec![
                "BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127".to_string(),
                "294B469239FA3BAA8F3189C306DAA1368B5ABCC8".to_string(),
            ]))
        );
    }

    #[test]
    fn parse_status_import_rejects_a_public_key_alongside_the_secret_key() {
        let status = "[GNUPG:] IMPORT_OK 1 BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127
[GNUPG:] IMPORT_OK 17 BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127
[GNUPG:] IMPORT_OK 1 294B469239FA3BAA8F3189C306DAA1368B5ABCC8";

        assert_eq!(
            parse_status_import(status),
            Err(GpgError::MultipleKeys(vec![
                "BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127".to_string(),
                "294B469239FA3BAA8F3189C306DAA1368B5ABCC8".to_string(),
            ]))
        );
    }

    #[test]
    fn multiple_keys_error_lists_the_fingerprints() {
        let err = GpgError::MultipleKeys(vec!["AAAA".to_string(), "BBBB".to_string()]);

        assert_eq!(
            err.to_string(),
            "the provided input contains 2 keys (AAAA, BBBB); import one key per run"
        );
    }

    #[test]
    fn parse_validsig_returns_the_signing_key_fingerprint() {
        // A signature by a subkey: the first field is the subkey, the last
        // the primary key
        let status = "[GNUPG:] NEWSIG
[GNUPG:] GOODSIG FF7AC16EFBD58A81 batman <batman@dc.com>
[GNUPG:] VALIDSIG 3E44D0598C6A8BEF3E44D0598C6A8BEF3E44D059 2026-10-25 1792921764 0 4 0 1 10 00 E9D7C62839888A9DE8A1643EFF7AC16EFBD58A81";

        assert_eq!(
            parse_validsig(status),
            Some("3E44D0598C6A8BEF3E44D0598C6A8BEF3E44D059".to_string())
        );
    }

    #[test]
    fn parse_validsig_returns_none_without_a_valid_signature() {
        let status = "[GNUPG:] NEWSIG
[GNUPG:] BADSIG FF7AC16EFBD58A81 batman <batman@dc.com>";

        assert_eq!(parse_validsig(status), None);
    }

    #[test]
    fn parse_status_import_returns_no_secret_key_for_empty_input() {
        assert_eq!(parse_status_import(""), Err(GpgError::NoSecretKey));
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
    fn parse_macgpg2_version_output() {
        let gpg_output = "gpg (GnuPG/MacGPG2) 2.2.41
libgcrypt 1.8.10
Copyright (C) 2022 g10 Code GmbH

Home: /Users/user/.gnupg";

        let info = gpg_output.parse::<GpgInfo>().unwrap();
        assert_eq!(info.version, "2.2.41");
        assert_eq!(info.libgcrypt, "1.8.10");
        assert_eq!(info.home_dir, "/Users/user/.gnupg");
    }

    #[test]
    fn parse_unrecognised_version_output_fails() {
        for output in [
            "",
            "gpg (Unknown) 2.4.5\nlibgcrypt 1.10.3\nHome: /home/user/.gnupg",
            "gpg (GnuPG) 2.4.5\nHome: /home/user/.gnupg",
            "gpg (GnuPG) 2.4.5\nlibgcrypt 1.10.3",
        ] {
            assert!(
                output.parse::<GpgInfo>().is_err(),
                "Should reject: {output:?}"
            );
        }
    }

    #[test]
    fn configure_defaults_creates_gpg_conf() {
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_str().unwrap();

        let result = configure_defaults(home_dir);
        assert!(result.unwrap(), "Should create gpg.conf");

        let gpg_conf = temp_dir.path().join("gpg.conf");
        assert!(gpg_conf.exists(), "gpg.conf should exist");

        let content = fs::read_to_string(gpg_conf).unwrap();
        insta::assert_snapshot!(content);
    }

    #[test]
    fn configure_defaults_leaves_existing_gpg_conf_untouched() {
        let temp_dir = TempDir::new().unwrap();
        let gpg_conf = temp_dir.path().join("gpg.conf");
        fs::write(&gpg_conf, "keyserver hkps://keys.openpgp.org\n").unwrap();

        let result = configure_defaults(temp_dir.path().to_str().unwrap());
        assert!(!result.unwrap(), "Should report gpg.conf as left untouched");
        assert_eq!(
            fs::read_to_string(gpg_conf).unwrap(),
            "keyserver hkps://keys.openpgp.org\n"
        );
    }

    #[test]
    fn create_new_with_removes_file_when_write_fails() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("gpg.conf");

        let result = create_new_with(&path, |_| Err(std::io::Error::other("disk full")));
        assert!(result.is_err());
        assert!(
            !path.exists(),
            "A partly written file must not be left behind"
        );
    }

    #[test]
    fn create_new_with_never_removes_an_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("gpg.conf");
        fs::write(&path, "keyserver hkps://keys.openpgp.org\n").unwrap();

        let result = create_new_with(&path, |_| Err(std::io::Error::other("disk full")));
        assert!(!result.unwrap(), "Should report the file as left untouched");
        assert!(path.exists());
    }

    #[test]
    fn configure_agent_defaults_leaves_existing_gpg_agent_conf_untouched() {
        let temp_dir = TempDir::new().unwrap();
        let agent_conf = temp_dir.path().join("gpg-agent.conf");
        fs::write(&agent_conf, "pinentry-program /usr/bin/pinentry-gnome3\n").unwrap();

        let result = configure_agent_defaults(temp_dir.path().to_str().unwrap());
        assert!(
            !result.unwrap(),
            "Should report gpg-agent.conf as left untouched"
        );
        assert_eq!(
            fs::read_to_string(agent_conf).unwrap(),
            "pinentry-program /usr/bin/pinentry-gnome3\n"
        );
    }

    #[test]
    fn configure_agent_defaults_creates_gpg_agent_conf() {
        let temp_dir = TempDir::new().unwrap();
        let home_dir = temp_dir.path().to_str().unwrap();

        let result = configure_agent_defaults(home_dir);
        assert!(result.unwrap(), "Should create gpg-agent.conf");

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
            primary_key: GpgKeyDetails {
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
            primary_key: GpgKeyDetails {
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
        assert_eq!(key.primary_key.creation_date, now.timestamp());
        assert_eq!(
            key.primary_key.expiration_date,
            Some(secret_key_expiration.timestamp())
        );
        assert_eq!(
            key.primary_key.fingerprint,
            "BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127"
        );
        assert_eq!(key.primary_key.key_id, "FDEFE8AB8796E127");
        assert_eq!(
            key.primary_key.keygrip,
            "C4403DA4AF911084480BA46743E707CCDD082A24"
        );
        assert!(key.primary_key.capabilities.sign);
        assert!(key.primary_key.capabilities.certify);
        assert!(!key.primary_key.capabilities.encrypt);

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
    fn parse_out_of_range_timestamp_fails() {
        let result = format!(
            "sec:u:4096:1:FDEFE8AB8796E127:{}:::u:::scESC:::+:::23::0:",
            i64::MAX
        )
        .parse::<GpgPrivateKey>();

        assert!(matches!(result, Err(GpgError::MalformedKeyRecord(1, _))));
    }

    #[test]
    fn format_out_of_range_timestamp_does_not_panic() {
        assert_eq!(format_timestamp(i64::MAX), i64::MAX.to_string());
        assert!(format_expiration_in_days(i64::MAX).starts_with(&i64::MAX.to_string()));
    }

    #[test]
    fn format_expiration_in_days_marks_expired_dates() {
        let ago =
            |duration: Duration| format_expiration_in_days((Utc::now() - duration).timestamp());

        assert!(ago(Duration::hours(1)).ends_with("(expired today)"));
        assert!(ago(Duration::days(1) + Duration::hours(1)).ends_with("(expired 1 day ago)"));
        assert!(ago(Duration::days(300) + Duration::hours(1)).ends_with("(expired 300 days ago)"));
    }

    #[test]
    fn format_timestamp_outside_rfc2822_years_does_not_panic() {
        // 0000-01-01T00:00:00Z and 9999-12-31T23:59:59Z are the RFC 2822 bounds
        const YEAR_0_START: i64 = -62_167_219_200;
        const YEAR_9999_END: i64 = 253_402_300_799;

        assert_eq!(
            format_timestamp(YEAR_0_START),
            "Sat, 1 Jan 0000 00:00:00 +0000"
        );
        assert_eq!(
            format_timestamp(YEAR_9999_END),
            "Fri, 31 Dec 9999 23:59:59 +0000"
        );
        assert_eq!(format_timestamp(YEAR_0_START - 1), "-62167219201");
        assert_eq!(format_timestamp(YEAR_9999_END + 1), "253402300800");
        assert_eq!(format_expiration_in_days(YEAR_0_START - 1), "-62167219201");
        assert_eq!(format_expiration_in_days(YEAR_9999_END + 1), "253402300800");
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
    fn parse_public_key_alongside_secret_key_fails() {
        let result = "sec:u:4096:1:FDEFE8AB8796E127:1700000000:::u:::scESC:::+:::23::0:
fpr:::::::::BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127:
grp:::::::::C4403DA4AF911084480BA46743E707CCDD082A24:
uid:u::::1700000000::0E9C7598797E7F7A380A72A58B9B7FA28160AB06::batman <batman@dc.com>::::::::::0:
pub:u:255:22:E02531BF955351B6:1700000000:::u:::scSC:::::ed25519:::0:
fpr:::::::::7454482F61FB411BB041D4C0E02531BF955351B6:
grp:::::::::3C0C28748C83AC5160FC051B0487F47391FF6D1B:
uid:u::::1700000000::96652C75728C60697573C3570C362BED95E65447::robin <robin@dc.com>::::::::::0:"
            .parse::<GpgPrivateKey>();

        assert!(
            matches!(result, Err(GpgError::InvalidGpgKeyData(_))),
            "A public key's records must not merge into the secret key: {result:?}"
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

    #[test]
    fn decode_key_input_ignores_ascii_whitespace() {
        // "hello world" encoded, then wrapped with CRLF, a tab and spaces.
        let decoded = decode_key_input("aGVsbG8g\r\nd29y\tbGQ= \n").unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn decode_key_input_rejects_invalid_byte_within_wrapped_input() {
        let err = decode_key_input("aGVsbG8g\nd2!y\nbGQ=\n").unwrap_err();
        assert!(matches!(
            err.downcast_ref::<GpgError>(),
            Some(GpgError::InvalidByteInGpgKey(11, '!'))
        ));
    }

    const MIB: usize = 1024 * 1024;

    #[test]
    fn run_reports_stderr_on_non_zero_exit() {
        let err = run("sh", &["-c", "echo boom >&2; exit 3"], b"").unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
    }

    #[test]
    fn run_reports_stdout_when_stderr_is_empty() {
        // e.g. `--status-fd 1` records are the only detail if gpg fails silently
        let err = run(
            "sh",
            &["-c", "echo '[GNUPG:] FAILURE import 11'; exit 2"],
            b"",
        )
        .unwrap_err();
        assert!(err.to_string().contains("FAILURE import 11"), "{err}");
    }

    #[test]
    fn run_drains_stderr_while_writing_stdin() {
        // Fills the stderr pipe before reading stdin, which deadlocks if
        // stdin is written in full before stderr is drained
        let script = "head -c 1048576 /dev/zero | tr '\\0' x >&2; cat >/dev/null";
        let output = run("sh", &["-c", script], &vec![b'y'; MIB]).unwrap();
        assert_eq!(output.stderr.len(), MIB);
    }

    #[test]
    fn run_reports_exit_when_child_stops_reading_stdin() {
        let err = run("sh", &["-c", "echo early >&2; exit 4"], &vec![b'y'; MIB]).unwrap_err();
        assert!(err.to_string().contains("early"), "{err}");
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;
        use proptest::sample::Index;

        /// Escapes text the way gpg does in `--with-colons` uid fields
        fn escape_colon_field(value: &str) -> String {
            value.replace('\\', "\\x5c").replace(':', "\\x3a")
        }

        fn whitespace() -> impl Strategy<Value = &'static str> {
            prop_oneof![Just(" "), Just("\n"), Just("\r\n"), Just("\t")]
        }

        /// Either an `IMPORT_OK` record (flags, fingerprint), or another
        /// status line that parse_status_import must ignore
        #[derive(Clone, Debug)]
        enum StatusLine {
            ImportOk(u32, &'static str),
            Other(&'static str),
        }

        /// Two keys, so a status often holds one key and often more
        const FINGERPRINTS: [&str; 2] = [
            "BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127",
            "294B469239FA3BAA8F3189C306DAA1368B5ABCC8",
        ];

        fn status_line() -> impl Strategy<Value = StatusLine> {
            prop_oneof![
                (0u32..32, prop::sample::select(&FINGERPRINTS[..]))
                    .prop_map(|(flags, fpr)| StatusLine::ImportOk(flags, fpr)),
                prop_oneof![
                    Just("[GNUPG:] KEY_CONSIDERED BEEA4CDB4B0A80CBABB99B45FDEFE8AB8796E127 0"),
                    Just("[GNUPG:] IMPORTED FDEFE8AB8796E127 batman <batman@dc.com>"),
                    Just("[GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 1 1 0 0 0 0"),
                    Just("gpg: key FDEFE8AB8796E127: secret key imported"),
                ]
                .prop_map(StatusLine::Other),
            ]
        }

        proptest! {
            #[test]
            fn decode_key_input_ignores_whitespace_in_base64(
                key in prop::collection::vec(any::<u8>(), 1..512),
                inserts in prop::collection::vec((any::<Index>(), whitespace()), 0..16),
            ) {
                let mut encoded = general_purpose::STANDARD.encode(&key);
                for (index, ws) in inserts {
                    let at = index.index(encoded.len() + 1);
                    encoded.insert_str(at, ws);
                }

                prop_assert_eq!(decode_key_input(&encoded).unwrap(), key);
            }

            #[test]
            fn unescape_colon_field_reverses_gpg_escaping(value in any::<String>()) {
                prop_assert_eq!(unescape_colon_field(&escape_colon_field(&value)), value);
            }

            // Each strategy gets a third of the cases. chrono represents only
            // about ±8.2e12 seconds, a tiny fraction of i64, and only years 0 to
            // 9999 (-62167219200 to 253402300799) are formatted as dates, so
            // both ranges are sampled directly as well as the whole of i64
            #[test]
            fn timestamp_formatting_never_panics(
                secs in prop_oneof![
                    any::<i64>(),
                    -10_000_000_000_000i64..10_000_000_000_000,
                    -62_167_219_200i64..=253_402_300_799,
                ],
            ) {
                format_timestamp(secs);
                format_expiration_in_days(secs);
            }

            #[test]
            fn parse_status_import_finds_the_only_secret_key(
                lines in prop::collection::vec(status_line(), 0..12),
            ) {
                let status = lines
                    .iter()
                    .map(|line| match line {
                        StatusLine::ImportOk(flags, fpr) => format!("[GNUPG:] IMPORT_OK {flags} {fpr}"),
                        StatusLine::Other(text) => text.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let mut fingerprints: Vec<String> = Vec::new();
                for line in &lines {
                    if let StatusLine::ImportOk(_, fpr) = line
                        && !fingerprints.iter().any(|f| f == fpr)
                    {
                        fingerprints.push(fpr.to_string());
                    }
                }
                let expected = if fingerprints.len() > 1 {
                    Err(GpgError::MultipleKeys(fingerprints))
                } else {
                    lines
                        .iter()
                        .find_map(|line| match line {
                            StatusLine::ImportOk(flags, fpr) if flags & 16 != 0 => Some(fpr.to_string()),
                            _ => None,
                        })
                        .ok_or(GpgError::NoSecretKey)
                };

                prop_assert_eq!(parse_status_import(&status), expected);
            }
        }
    }
}
