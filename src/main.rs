use anyhow::Result;
use clap::{command, Parser, ValueEnum};
use gpg_import::{git, gpg};
use std::println;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// A base64 encoded GPG private key in armored format
    #[arg(
        short,
        long,
        env = "GPG_PRIVATE_KEY",
        value_name = "BASE64_ARMORED_KEY"
    )]
    key: String,

    /// The passphrase of the GPG private key if set
    #[arg(short, long, env = "GPG_PASSPHRASE")]
    passphrase: Option<String>,

    /// A level of trust to be associated with the owner of the GPG private key
    #[arg(short, long, env = "GPG_TRUST_LEVEL", value_enum)]
    trust_level: Option<TrustLevel>,

    /// Skip all GPG configuration for the detected git repository
    #[arg(short, long, env = "GPG_SKIP_GIT", default_value_t = false)]
    skip_git: bool,
}

#[derive(Clone, Debug, ValueEnum)]
enum TrustLevel {
    #[value(help = "I don't know or won't say", name = "1")]
    Undefined,
    #[value(help = "I do NOT trust", name = "2")]
    Never,
    #[value(help = "I trust marginally", name = "3")]
    Marginal,
    #[value(help = "I trust fully", name = "4")]
    Full,
    #[value(help = "I trust ultimately", name = "5")]
    Ultimate,
}

impl TrustLevel {
    fn trust_db_value(&self) -> u8 {
        match self {
            TrustLevel::Undefined => 1,
            TrustLevel::Never => 2,
            TrustLevel::Marginal => 3,
            TrustLevel::Full => 4,
            TrustLevel::Ultimate => 5,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let info = gpg::detect_version()?;
    println!("> Detected GnuPG:");
    println!("{}", info);

    let key_id = gpg::import_secret_key(&args.key)?;
    let private_key = gpg::extract_key_info(&key_id)?;
    println!("> Imported GPG key:");
    println!("{}", private_key);

    gpg::configure_defaults(&info.home_dir)?;
    gpg::configure_agent_defaults(&info.home_dir)?;

    if let Some(passphrase) = args.passphrase {
        gpg::preset_passphrase(&private_key.secret_key.keygrip, &passphrase)?;
        gpg::preset_passphrase(&private_key.secret_subkey.keygrip, &passphrase)?;

        println!("> Setting Passphrase:");
        println!(
            "keygrip: {} [{}]",
            private_key.secret_key.keygrip, private_key.secret_key.key_id
        );
        println!(
            "keygrip: {} [{}]",
            private_key.secret_subkey.keygrip, private_key.secret_subkey.key_id
        );
    }

    if let Some(trust_level) = args.trust_level {
        gpg::assign_trust_level(&private_key.secret_key.key_id, trust_level.trust_db_value())?;
        println!("\n> Setting Trust Level:");
        println!(
            "trust_level: {} [{}]",
            trust_level.trust_db_value(),
            private_key.secret_key.key_id
        );
    }

    if !args.skip_git {
        if let Some(repo) = git::is_repo() {
            println!("> Git config set:");

            let git_cfg = git::SigningConfig {
                user_name: private_key.user_name,
                user_email: private_key.user_email,
                key_id: private_key.secret_key.key_id,
                commit_sign: true,
                tag_sign: true,
                push_sign: true,
            };
            git::configure_signing(&repo, &git_cfg)?;
            println!("{}", git_cfg);
        }
    }
    Ok(())
}
