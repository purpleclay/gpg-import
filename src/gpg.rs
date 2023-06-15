use base64::{engine::general_purpose, Engine as _};
use chrono::{TimeZone, Utc};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_until},
    character::streaming::not_line_ending,
    error::Error,
    multi::count,
    sequence::{pair, separated_pair, tuple},
    Finish, IResult,
};
use std::{
    fmt::{self, Display},
    io::Read,
    process::Command,
    str::FromStr,
};
use std::{io::Write, process::Stdio};

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
pub fn detect_version() -> Result<GpgInfo, Box<dyn std::error::Error>> {
    let gpg_details = Command::new("gpg").arg("--version").output()?;

    let output = String::from_utf8(gpg_details.stdout)?;
    let gpg_info = output.parse::<GpgInfo>()?;

    Ok(gpg_info)
}

/// A GPG private key
#[derive(Debug)]
pub struct GpgPrivateKey {
    /// The user name associated with the private key
    pub user_name: String,
    /// The user email associated with the private key
    pub user_email: String,
    /// Internal details of the private key
    pub secret_key: GpgKeyDetails,
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
        writeln!(f, "fingerprint: {}", self.secret_key.fingerprint)?;
        writeln!(f, "keygrip:     {}", self.secret_key.keygrip)?;
        writeln!(f, "key_id:      {}", self.secret_key.key_id)?;
        writeln!(f, "user:        {} <{}>", self.user_name, self.user_email)?;

        let ct = Utc.timestamp_opt(self.secret_key.creation_date, 0).unwrap();
        writeln!(f, "created_on:  {}", ct.to_rfc2822())?;

        if self.secret_key.expiration_date.is_some() {
            let et = Utc
                .timestamp_opt(self.secret_key.expiration_date.unwrap(), 0)
                .unwrap();
            writeln!(f, "expires_on:  {}", et.to_rfc2822())?;
        }
        Ok(())
    }
}

fn parse_gpg_import(input: &str) -> IResult<&str, String> {
    let (i, _) = take_until("gpg: key")(input)?;
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
    let (i, uid) = separated_pair(take_until(" "), tag(" "), take_until(":"))(i)?;

    Ok((
        i,
        GpgPrivateKey {
            user_name: uid.0.into(),
            user_email: uid.1[1..uid.1.len() - 1].into(),
            secret_key: GpgKeyDetails {
                creation_date: sec[1].0.parse::<i64>().unwrap(),
                expiration_date: if sec[2].0.is_empty() {
                    None
                } else {
                    Some(sec[2].0.parse::<i64>().unwrap())
                },
                key_id: sec[0].0.into(),
                fingerprint: sec_fpr.into(),
                keygrip: sec_grp.into(),
            },
        },
    ))
}

/// Attempts to import a GPG private key
pub fn import_secret_key(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let decoded = general_purpose::STANDARD.decode(key)?;
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

/// Extracts internal details for a given GPG private key
pub fn extract_key_info(key_id: &str) -> Result<GpgPrivateKey, Box<dyn std::error::Error>> {
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
    Ok(key_details)
}
