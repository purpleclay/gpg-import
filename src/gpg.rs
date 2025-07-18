use anyhow::{bail, Result};
use base64::{engine::general_purpose, DecodeError, Engine as _};
use chrono::{TimeZone, Utc};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::not_line_ending,
    error::Error,
    multi::count,
    sequence::{pair, separated_pair},
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

/// Inspects the OS for a GPG client and retrieves details about the
/// currently installed version
pub fn detect_version() -> Result<GpgInfo> {
    let gpg_details = Command::new("gpg").arg("--version").output()?;

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
    Command::new("gpg-connect-agent")
        .args(vec!["RELOADAGENT", "/bye"])
        .output()?;

    Ok(())
}

/// A GPG private key
#[derive(Debug)]
pub struct GpgPrivateKey {
    /// The user name associated with the private key
    pub user_name: String,
    /// The user email associated with the private key
    pub user_email: String,
    /// Internal details of the secret key
    pub secret_key: GpgKeyDetails,
    /// Internal details of the secret subkey
    pub secret_subkey: GpgKeyDetails,
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
}

impl FromStr for GpgPrivateKey {
    type Err = Error<String>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match parse_gpg_key_details(s).finish() {
            Ok((_, info)) => Ok(info),
            Err(Error { input, code }) => Err(Error {
                input: input.to_string(),
                code,
            }),
        }
    }
}

impl Display for GpgPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "user:           {} <{}>",
            self.user_name, self.user_email
        )?;
        writeln!(f, "fingerprint:    {}", self.secret_key.fingerprint)?;
        writeln!(f, "keygrip:        {}", self.secret_key.keygrip)?;
        writeln!(f, "key_id:         {}", self.secret_key.key_id)?;
        writeln!(
            f,
            "created_on:     {}",
            format_timestamp(self.secret_key.creation_date)
        )?;

        if self.secret_key.expiration_date.is_some() {
            writeln!(
                f,
                "expires_on:     {}",
                format_expiration_in_days(self.secret_key.expiration_date.unwrap())
            )?;
        }
        writeln!(f, "sub_keygrip:    {}", self.secret_subkey.keygrip)?;
        writeln!(f, "sub_key_id:     {}", self.secret_subkey.key_id)?;
        writeln!(
            f,
            "sub_created_on: {}",
            format_timestamp(self.secret_subkey.creation_date)
        )?;
        if self.secret_subkey.expiration_date.is_some() {
            writeln!(
                f,
                "sub_expires_on: {}",
                format_expiration_in_days(self.secret_subkey.expiration_date.unwrap())
            )?;
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

fn parse_gpg_import(input: &str) -> IResult<&str, String> {
    let (i, _) = take_until("gpg: key ")(input)?;
    let (i, key) = separated_pair(tag("gpg: key"), tag(" "), take_until(":")).parse(i)?;
    Ok((i, key.1.into()))
}

fn parse_gpg_key_details(input: &str) -> IResult<&str, GpgPrivateKey> {
    let (i, _) = (tag("sec"), count(pair(take_until(":"), tag(":")), 4)).parse(input)?;
    let (i, sec) = count(pair(take_until(":"), tag(":")), 3).parse(i)?;
    let (i, _) = (take_until("fpr"), tag("fpr"), count(tag(":"), 9)).parse(i)?;
    let (i, sec_fpr) = take_until(":")(i)?;
    let (i, _) = (take_until("grp"), tag("grp"), count(tag(":"), 9)).parse(i)?;
    let (i, sec_grp) = take_until(":")(i)?;
    let (i, _) = (
        take_until("uid"),
        tag("uid"),
        count(pair(take_until(":"), tag(":")), 9),
    )
        .parse(i)?;
    let (i, uid) = separated_pair(take_until(" <"), tag(" <"), take_until(">")).parse(i)?;
    let (i, _) = take_until("ssb")(i)?;
    let (i, _) = (tag("ssb"), count(pair(take_until(":"), tag(":")), 4)).parse(i)?;
    let (i, ssb) = count(pair(take_until(":"), tag(":")), 3).parse(i)?;
    let (i, _) = (take_until("fpr"), tag("fpr"), count(tag(":"), 9)).parse(i)?;
    let (i, ssb_fpr) = take_until(":")(i)?;
    let (i, _) = (take_until("grp"), tag("grp"), count(tag(":"), 9)).parse(i)?;
    let (i, ssb_grp) = take_until(":")(i)?;

    Ok((
        i,
        GpgPrivateKey {
            user_name: uid.0.into(),
            user_email: uid.1.into(),
            secret_key: GpgKeyDetails {
                creation_date: sec[1].0.parse::<i64>().unwrap(),
                expiration_date: if sec[2].0.is_empty() {
                    None
                } else {
                    Some(sec[2].0.parse::<i64>().unwrap())
                },
                fingerprint: sec_fpr.into(),
                key_id: sec[0].0.into(),
                keygrip: sec_grp.into(),
            },
            secret_subkey: GpgKeyDetails {
                creation_date: ssb[1].0.parse::<i64>().unwrap(),
                expiration_date: if ssb[2].0.is_empty() {
                    None
                } else {
                    Some(ssb[2].0.parse::<i64>().unwrap())
                },
                fingerprint: ssb_fpr.into(),
                key_id: ssb[0].0.into(),
                keygrip: ssb_grp.into(),
            },
        },
    ))
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("detected invalid byte at position {0} within gpg key '{1}'")]
struct InvalidByteInGpgKey(usize, char);

/// Attempts to import a GPG private key
pub fn import_secret_key(key: &str) -> Result<String> {
    let decoded = match general_purpose::STANDARD.decode(key) {
        Ok(decoded_key) => Ok(decoded_key),
        Err(e) => match e {
            DecodeError::InvalidByte(offset, byte) => {
                bail!(InvalidByteInGpgKey(offset, byte.as_char()))
            }
            _ => Err(e),
        },
    }?;

    let gpg_import_info = Command::new("gpg")
        .args(vec!["--import", "--batch", "--yes"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    gpg_import_info.stdin.unwrap().write_all(&decoded)?;
    let mut s = String::default();
    gpg_import_info
        .stderr
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();

    let key = parse_gpg_import(&s).unwrap();
    Ok(key.1)
}

/// Extracts internal details for a given GPG private key and verifies its validity
pub fn extract_key_info(key_id: &str) -> Result<GpgPrivateKey> {
    let gpg_key_details = Command::new("gpg")
        .args(vec![
            "--batch",
            "--with-colons",
            "--with-keygrip",
            "--list-secret-keys",
            "--fixed-list-mode",
            key_id,
        ])
        .output()?;

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

    if let Some(expiration_date) = key_details.secret_subkey.expiration_date {
        if expiration_date <= current_timestamp {
            bail!(
                "GPG secret subkey has expired on {}",
                Utc.timestamp_opt(expiration_date, 0).unwrap().to_rfc2822()
            );
        }
    }

    Ok(key_details)
}

/// Presets the passphrase for a given keygrip, ensuring it is cached for any
/// subsequent signing request
pub fn preset_passphrase(keygrip: &str, passphrase: &str) -> Result<()> {
    let set_passphrase = Command::new("gpg-connect-agent")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;

    set_passphrase.stdin.as_ref().unwrap().write_all(
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
    let set_trust = Command::new("gpg")
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
        .unwrap()
        .write_all(format!("{trust_level}\ny\n").as_bytes())?;
    set_trust.wait_with_output()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Duration;

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
        assert_eq!(key.user_name, "batman");
        assert_eq!(key.user_email, "batman@dc.com");
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
        assert_eq!(key.secret_subkey.creation_date, now.timestamp());
        assert_eq!(
            key.secret_subkey.expiration_date,
            Some(secret_subkey_expiration.timestamp())
        );
        assert_eq!(key.secret_subkey.key_id, "BE6663F6A323FBE8");
        assert_eq!(
            key.secret_subkey.keygrip,
            "4AC8E7E7FD8B405DF2761726D296F98C9B778875"
        );
    }
}
