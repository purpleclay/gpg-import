use anyhow::Result;
use clap::{command, Parser, Subcommand, ValueEnum};
use gpg_import::import::GpgImport;
use std::println;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Parser, Debug)]
#[command(author, about, long_about = None, disable_version_flag = true, disable_help_subcommand = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// An ASCII armored GPG private key (optionally encoded as a base64 string)
    #[arg(short, long, env = "GPG_PRIVATE_KEY", value_name = "GPG_KEY")]
    key: Option<String>,

    /// The passphrase of the GPG private key if set
    #[arg(short, long, env = "GPG_PASSPHRASE")]
    passphrase: Option<String>,

    /// The fingerprint of a specific key or subkey to use for signing
    #[arg(short, long, env = "GPG_FINGERPRINT", value_name = "FINGERPRINT")]
    fingerprint: Option<String>,

    /// A level of trust to associate with the GPG private key
    #[arg(short, long, env = "GPG_TRUST_LEVEL", value_enum)]
    trust_level: Option<TrustLevel>,

    /// Skip all GPG configuration for the detected git repository
    #[arg(short, long, env = "GPG_SKIP_GIT")]
    skip_git: bool,

    /// Simulate the import without making changes
    #[arg(long, env = "GPG_DRY_RUN")]
    dry_run: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print build time version information
    Version {
        /// Only print the version number
        #[arg(short, long)]
        short: bool,
    },
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

    match args.command {
        Some(Commands::Version { short }) => {
            if short {
                print_version_short();
            } else {
                print_version_info();
            }
            return Ok(());
        }
        None => {
            // Continue with normal GPG import flow
        }
    }

    let key = args.key.ok_or_else(|| anyhow::anyhow!("Key is required for GPG import. Use --key or set GPG_PRIVATE_KEY environment variable."))?;

    GpgImport::new(key)
        .with_passphrase(args.passphrase)
        .with_fingerprint(args.fingerprint)
        .with_trust_level(args.trust_level.map(|t| t.trust_db_value()))
        .skip_git(args.skip_git)
        .dry_run(args.dry_run)
        .import()
}

fn print_version_short() {
    println!("{}", built_info::PKG_VERSION);
}

fn print_version_info() {
    println!("version:    {}", built_info::PKG_VERSION);
    println!("rustc:      {}", built_info::RUSTC_VERSION);
    println!("target:     {}", built_info::TARGET);

    if let Some(git_ref) = built_info::GIT_HEAD_REF {
        println!(
            "git_branch: {}",
            git_ref.strip_prefix("refs/heads/").unwrap_or(git_ref)
        );
    }

    if let Some(commit_hash) = built_info::GIT_COMMIT_HASH {
        println!("git_commit: {commit_hash}");
    }
    println!("build_date: {}", built_info::BUILT_TIME_UTC);
}
