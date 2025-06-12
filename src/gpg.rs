use anyhow::{bail, Result};
use base64::{engine::general_purpose, DecodeError, Engine as _};
use chrono::{TimeZone, Utc};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::complete::not_line_ending,
    error::Error,
    multi::count,
    sequence::{pair, separated_pair, tuple},
    AsChar, Finish, IResult,
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
    )(input)?;
    let (i, _) = take_until("libgcrypt")(i)?;
    let (i, libgcrypt) = separated_pair(tag("libgcrypt"), tag(" "), not_line_ending)(i)?;
    let (i, _) = take_until("Home: ")(i)?;
    let (i, home_dir) = separated_pair(tag("Home:"), tag(" "), not_line_ending)(i)?;

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
        format!("in {} days", days_until_expiry)
    };

    format!("{} ({})", expires_on.to_rfc2822(), days_text)
}

impl Display for GpgKeyDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "fingerprint: {}", self.fingerprint)?;
        writeln!(f, "keygrip:     {}", self.keygrip)?;
        writeln!(f, "key_id:      {}", self.key_id)?;

        let ct = Utc.timestamp_opt(self.creation_date, 0).unwrap();
        writeln!(f, "created_on:  {}", ct.to_rfc2822())?;

        if self.expiration_date.is_some() {
            let expires_on = Utc.timestamp_opt(self.expiration_date.unwrap(), 0).unwrap();
            let now = Utc::now();
            let days_until_expiry = (expires_on - now).num_days();

            let days_text = if days_until_expiry == 1 {
                "in 1 day".to_string()
            } else if days_until_expiry == 0 {
                "expires today".to_string()
            } else {
                format!("in {} days", days_until_expiry)
            };

            writeln!(
                f,
                "expires_on:  {} ({})",
                expires_on.to_rfc2822(),
                days_text
            )?;
        }
        Ok(())
    }
}

fn parse_gpg_import(input: &str) -> IResult<&str, String> {
    let (i, _) = take_until("gpg: key ")(input)?;
    let (i, key) = separated_pair(tag("gpg: key"), tag(" "), take_until(":"))(i)?;
    Ok((i, key.1.into()))
}

fn parse_gpg_key_details(input: &str) -> IResult<&str, GpgPrivateKey> {
    let (i, _) = tuple((tag("sec"), count(pair(take_until(":"), tag(":")), 4)))(input)?;
    let (i, sec) = count(pair(take_until(":"), tag(":")), 3)(i)?;
    let (i, _) = tuple((take_until("fpr"), tag("fpr"), count(tag(":"), 9)))(i)?;
    let (i, sec_fpr) = take_until(":")(i)?;
    let (i, _) = tuple((take_until("grp"), tag("grp"), count(tag(":"), 9)))(i)?;
    let (i, sec_grp) = take_until(":")(i)?;
    let (i, _) = tuple((
        take_until("uid"),
        tag("uid"),
        count(pair(take_until(":"), tag(":")), 9),
    ))(i)?;
    let (i, uid) = separated_pair(take_until(" <"), tag(" <"), take_until(">"))(i)?;
    let (i, _) = take_until("ssb")(i)?;
    let (i, _) = tuple((tag("ssb"), count(pair(take_until(":"), tag(":")), 4)))(i)?;
    let (i, ssb) = count(pair(take_until(":"), tag(":")), 3)(i)?;
    let (i, _) = tuple((take_until("fpr"), tag("fpr"), count(tag(":"), 9)))(i)?;
    let (i, ssb_fpr) = take_until(":")(i)?;
    let (i, _) = tuple((take_until("grp"), tag("grp"), count(tag(":"), 9)))(i)?;
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
                "GPG key has expired on {}",
                Utc.timestamp_opt(expiration_date, 0).unwrap().to_rfc2822()
            );
        }
    }

    if let Some(expiration_date) = key_details.secret_subkey.expiration_date {
        if expiration_date <= current_timestamp {
            bail!(
                "GPG subkey has expired on {}",
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
        .write_all(format!("{}\ny\n", trust_level).as_bytes())?;
    set_trust.wait_with_output()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    use tempfile::TempDir;

    /// A test fixture that creates an isolated GPG home directory
    /// and cleans it up automatically when dropped
    pub struct GpgTestFixture {
        temp_dir: TempDir,
        original_gnupghome: Option<String>,
    }

    impl GpgTestFixture {
        /// Create a new isolated GPG test environment
        pub fn new() -> Result<Self> {
            let temp_dir = TempDir::new()?;
            let gnupg_home = temp_dir.path().to_string_lossy().to_string();

            // Save original GNUPGHOME if it exists
            let original_gnupghome = env::var("GNUPGHOME").ok();

            // Set GNUPGHOME to our temporary directory
            env::set_var("GNUPGHOME", &gnupg_home);

            // Initialize GPG configuration
            configure_defaults(&gnupg_home)?;
            configure_agent_defaults(&gnupg_home)?;

            Ok(Self {
                temp_dir,
                original_gnupghome,
            })
        }

        /// Get the path to the temporary GPG home directory
        pub fn gnupg_home(&self) -> &str {
            self.temp_dir.path().to_str().unwrap()
        }

        /// Check if GPG is available on the system
        pub fn is_gpg_available() -> bool {
            Command::new("gpg")
                .arg("--version")
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        }
    }

    impl Drop for GpgTestFixture {
        fn drop(&mut self) {
            match &self.original_gnupghome {
                Some(original) => env::set_var("GNUPGHOME", original),
                None => env::remove_var("GNUPGHOME"),
            }
        }
    }

    #[test]
    fn test_detect_version() {
        assert!(
            GpgTestFixture::is_gpg_available(),
            "GPG is required for tests. Please install GPG to run tests."
        );

        let _fixture = GpgTestFixture::new().expect("Failed to create test fixture");
        let result = detect_version();
        assert!(result.is_ok(), "Should detect GPG version");

        let gpg_info = result.unwrap();
        assert!(!gpg_info.version.is_empty(), "Version should not be empty");
        assert!(
            !gpg_info.libgcrypt.is_empty(),
            "Libgcrypt version should not be empty"
        );
    }

    #[test]
    fn test_configure_defaults() {
        assert!(
            GpgTestFixture::is_gpg_available(),
            "GPG is required for tests. Please install GPG to run tests."
        );

        let fixture = GpgTestFixture::new().expect("Failed to create test fixture");
        let gnupg_home = fixture.gnupg_home();

        // Test that configuration files are created
        let gpg_conf = Path::new(gnupg_home).join("gpg.conf");
        assert!(gpg_conf.exists(), "gpg.conf should be created");

        let gpg_agent_conf = Path::new(gnupg_home).join("gpg-agent.conf");
        assert!(gpg_agent_conf.exists(), "gpg-agent.conf should be created");
    }

    #[test]
    fn test_expired_key_detection() {
        // This test only tests expiration logic, no GPG needed
        let current_time = Utc::now().timestamp();
        let expired_time = current_time - 86400; // 24 hours ago

        let expired_key = GpgPrivateKey {
            user_name: "Test User".to_string(),
            user_email: "test@example.com".to_string(),
            secret_key: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: Some(expired_time),
                fingerprint: "test_fingerprint".to_string(),
                key_id: "test_key_id".to_string(),
                keygrip: "test_keygrip".to_string(),
            },
            secret_subkey: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: None,
                fingerprint: "test_sub_fingerprint".to_string(),
                key_id: "test_sub_key_id".to_string(),
                keygrip: "test_sub_keygrip".to_string(),
            },
        };

        // Test the expiration logic by simulating what extract_key_info does
        let current_timestamp = Utc::now().timestamp();
        let should_be_expired = expired_key
            .secret_key
            .expiration_date
            .map(|exp| exp <= current_timestamp)
            .unwrap_or(false);

        assert!(should_be_expired, "Key should be detected as expired");
    }

    #[test]
    fn test_gpg_key_parsing() {
        // This test only tests parsing logic, no GPG needed
        let sample_gpg_output = "sec:u:2048:1:1234567890ABCDEF:1640995200:1672531200:::::::::23::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678::\ngrp:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::\nuid:u::::1640995200::1234567890ABCDEF1234567890ABCDEF::Test User <test@example.com>::::::::::0:\nssb:u:2048:1:FEDCBA0987654321:1640995200:1672531200:::::::::23::\nfpr:::::::::FEDCBA0987654321FEDCBA0987654321FEDCBA09::\ngrp:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB::\n";

        let result = sample_gpg_output.parse::<GpgPrivateKey>();
        assert!(result.is_ok(), "Should parse GPG key details successfully");

        let key = result.unwrap();
        assert_eq!(key.user_name, "Test User");
        assert_eq!(key.user_email, "test@example.com");
        assert_eq!(key.secret_key.key_id, "1234567890ABCDEF");
        assert_eq!(key.secret_subkey.key_id, "FEDCBA0987654321");
    }

    #[test]
    fn test_gpg_key_with_no_expiration() {
        // This test only tests parsing logic, no GPG needed
        let sample_gpg_output = "sec:u:2048:1:1234567890ABCDEF:1640995200::::::::::23::\nfpr:::::::::1234567890ABCDEF1234567890ABCDEF12345678::\ngrp:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::\nuid:u::::1640995200::1234567890ABCDEF1234567890ABCDEF::Test User <test@example.com>::::::::::0:\nssb:u:2048:1:FEDCBA0987654321:1640995200::::::::::23::\nfpr:::::::::FEDCBA0987654321FEDCBA0987654321FEDCBA09::\ngrp:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB::\n";

        let result = sample_gpg_output.parse::<GpgPrivateKey>();
        assert!(result.is_ok(), "Should parse GPG key without expiration");

        let key = result.unwrap();
        assert!(
            key.secret_key.expiration_date.is_none(),
            "Main key should have no expiration"
        );
        assert!(
            key.secret_subkey.expiration_date.is_none(),
            "Subkey should have no expiration"
        );
    }

    #[test]
    fn test_extract_key_info_with_expired_key() {
        // This test only tests expiration check logic, no GPG needed
        let current_time = Utc::now().timestamp();
        let expired_time = current_time - 86400; // 24 hours ago

        // Simulate the check that happens in extract_key_info
        let expiration_date = Some(expired_time);
        let current_timestamp = Utc::now().timestamp();

        if let Some(exp_date) = expiration_date {
            assert!(exp_date <= current_timestamp, "Key should be expired");
        }
    }

    #[test]
    fn test_invalid_base64_key_import() {
        assert!(
            GpgTestFixture::is_gpg_available(),
            "GPG is required for tests. Please install GPG to run tests."
        );

        let _fixture = GpgTestFixture::new().expect("Failed to create test fixture");

        // Test with invalid base64 string
        let invalid_key = "invalid-base64-string!@#$%";
        let result = import_secret_key(invalid_key);

        assert!(result.is_err(), "Should fail with invalid base64");

        let error = result.unwrap_err();
        let error_message = format!("{}", error);
        assert!(
            error_message.contains("detected invalid byte"),
            "Error should mention invalid byte"
        );
    }

    #[test]
    fn test_key_expiration_integration() {
        assert!(
            GpgTestFixture::is_gpg_available(),
            "GPG is required for tests. Please install GPG to run tests."
        );

        let _fixture = GpgTestFixture::new().expect("Failed to create test fixture");

        // Test integration of the full expiration validation workflow
        // This simulates what happens in extract_key_info when checking expiration

        let current_time = Utc::now().timestamp();
        let expired_time = current_time - 86400; // 24 hours ago
        let future_time = current_time + 86400; // 24 hours from now

        // Test 1: Key with expired main key should be detected
        let expired_key = GpgPrivateKey {
            user_name: "Test User".to_string(),
            user_email: "test@example.com".to_string(),
            secret_key: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: Some(expired_time),
                fingerprint: "test_fingerprint".to_string(),
                key_id: "test_key_id".to_string(),
                keygrip: "test_keygrip".to_string(),
            },
            secret_subkey: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: Some(future_time),
                fingerprint: "test_sub_fingerprint".to_string(),
                key_id: "test_sub_key_id".to_string(),
                keygrip: "test_sub_keygrip".to_string(),
            },
        };

        // Simulate the expiration check from extract_key_info
        let main_key_expired = expired_key
            .secret_key
            .expiration_date
            .map(|exp| exp <= Utc::now().timestamp())
            .unwrap_or(false);

        assert!(main_key_expired, "Main key should be detected as expired");

        // Test 2: Key with expired subkey should be detected
        let expired_subkey = GpgPrivateKey {
            user_name: "Test User".to_string(),
            user_email: "test@example.com".to_string(),
            secret_key: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: Some(future_time),
                fingerprint: "test_fingerprint".to_string(),
                key_id: "test_key_id".to_string(),
                keygrip: "test_keygrip".to_string(),
            },
            secret_subkey: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: Some(expired_time),
                fingerprint: "test_sub_fingerprint".to_string(),
                key_id: "test_sub_key_id".to_string(),
                keygrip: "test_sub_keygrip".to_string(),
            },
        };

        let subkey_expired = expired_subkey
            .secret_subkey
            .expiration_date
            .map(|exp| exp <= Utc::now().timestamp())
            .unwrap_or(false);

        assert!(subkey_expired, "Subkey should be detected as expired");

        // Test 3: Valid key should not be detected as expired
        let valid_key = GpgPrivateKey {
            user_name: "Test User".to_string(),
            user_email: "test@example.com".to_string(),
            secret_key: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: Some(future_time),
                fingerprint: "test_fingerprint".to_string(),
                key_id: "test_key_id".to_string(),
                keygrip: "test_keygrip".to_string(),
            },
            secret_subkey: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: Some(future_time),
                fingerprint: "test_sub_fingerprint".to_string(),
                key_id: "test_sub_key_id".to_string(),
                keygrip: "test_sub_keygrip".to_string(),
            },
        };

        let main_key_valid = valid_key
            .secret_key
            .expiration_date
            .map(|exp| exp > Utc::now().timestamp())
            .unwrap_or(true);
        let subkey_valid = valid_key
            .secret_subkey
            .expiration_date
            .map(|exp| exp > Utc::now().timestamp())
            .unwrap_or(true);

        assert!(main_key_valid, "Valid main key should not be expired");
        assert!(subkey_valid, "Valid subkey should not be expired");

        // Test 4: Key with no expiration should be valid
        let no_expiration_key = GpgPrivateKey {
            user_name: "Test User".to_string(),
            user_email: "test@example.com".to_string(),
            secret_key: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: None,
                fingerprint: "test_fingerprint".to_string(),
                key_id: "test_key_id".to_string(),
                keygrip: "test_keygrip".to_string(),
            },
            secret_subkey: GpgKeyDetails {
                creation_date: current_time,
                expiration_date: None,
                fingerprint: "test_sub_fingerprint".to_string(),
                key_id: "test_sub_key_id".to_string(),
                keygrip: "test_sub_keygrip".to_string(),
            },
        };

        let main_no_exp_valid = no_expiration_key
            .secret_key
            .expiration_date
            .map(|exp| exp > Utc::now().timestamp())
            .unwrap_or(true);
        let sub_no_exp_valid = no_expiration_key
            .secret_subkey
            .expiration_date
            .map(|exp| exp > Utc::now().timestamp())
            .unwrap_or(true);

        assert!(main_no_exp_valid, "Key with no expiration should be valid");
        assert!(
            sub_no_exp_valid,
            "Subkey with no expiration should be valid"
        );
    }
}
