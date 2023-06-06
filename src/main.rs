extern crate exitcode;

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
use std::{env, io::Read, println, process::exit, process::Command, str::FromStr};
use std::{io::Write, process::Stdio};

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
    let (i, uid) = take_until(":")(i)?;

    Ok((
        i,
        GpgPrivateKey {
            user: uid.into(),
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

struct GpgInfo {
    version: String,
    libgcrypt: String,
    home_dir: String,
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

struct GpgPrivateKey {
    user: String,
    secret_key: GpgKeyDetails,
}

struct GpgKeyDetails {
    creation_date: i64,
    expiration_date: Option<i64>,
    fingerprint: String,
    key_id: String,
    keygrip: String,
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

fn detect_gpg_version() -> Result<GpgInfo, Box<dyn std::error::Error>> {
    let gpg_details = Command::new("gpg").arg("--version").output()?;

    let output = String::from_utf8(gpg_details.stdout)?;
    let gpg_info = output.parse::<GpgInfo>()?;

    Ok(gpg_info)
}

fn import_secret_key(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let decoded = general_purpose::STANDARD.decode(key)?;
    let gpg_import_info = Command::new("gpg")
        .args(vec!["--import", "--batch", "--yes"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    gpg_import_info.stdin.unwrap().write_all(&decoded)?;
    let mut s = String::new();
    gpg_import_info
        .stderr
        .unwrap()
        .read_to_string(&mut s)
        .unwrap();

    let key = parse_gpg_import(&s).unwrap();
    Ok(key.1)
}

fn extract_key_info(key_id: &str) -> Result<GpgPrivateKey, Box<dyn std::error::Error>> {
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
    let key_details = output.parse::<GpgPrivateKey>().unwrap();
    Ok(key_details)
}

fn main() {
    let gpg_private_key =
        env::var("GPG_PRIVATE_KEY").expect("env variable GPG_PRIVATE_KEY must bet set");

    let info = detect_gpg_version().unwrap();
    println!("gpg:     {} (libgcrypt: {})", info.version, info.libgcrypt);
    println!("homedir: {}", info.home_dir);

    let key_id = import_secret_key(&gpg_private_key).unwrap();
    let private_key = extract_key_info(&key_id).unwrap();
    println!();
    println!("fingerprint: {}", private_key.secret_key.fingerprint);
    println!("keygrip:     {}", private_key.secret_key.keygrip);
    println!("key id:      {}", private_key.secret_key.key_id);
    println!("user:        {}", private_key.user);
    let ct = Utc
        .timestamp_opt(private_key.secret_key.creation_date, 0)
        .unwrap();
    println!("created on:  {}", ct.to_rfc2822());
    if private_key.secret_key.expiration_date.is_some() {
        let et = Utc
            .timestamp_opt(private_key.secret_key.expiration_date.unwrap(), 0)
            .unwrap();
        println!("expires on:  {}", et.to_rfc2822());
    }

    exit(exitcode::OK)
}
