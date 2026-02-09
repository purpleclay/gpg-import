use anyhow::Result;
use clap::{command, Parser, Subcommand, ValueEnum};
use gpg_import::import::GpgImport;
use std::io::Read;
use std::println;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Parser, Debug)]
#[command(author, about, long_about = None, disable_version_flag = true, disable_help_subcommand = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// An ASCII armored GPG private key (optionally base64 encoded). Use - for
    /// stdin or @path to read from a file
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

    /// Apply git signing configuration globally
    #[arg(long, env = "GPG_GIT_GLOBAL_CONFIG")]
    git_global_config: bool,

    /// Override the committer name instead of using the value from the GPG key
    #[arg(long, env = "GPG_GIT_COMMITTER_NAME", value_name = "NAME")]
    git_committer_name: Option<String>,

    /// Override the committer email instead of using the value from the GPG key
    #[arg(long, env = "GPG_GIT_COMMITTER_EMAIL", value_name = "EMAIL")]
    git_committer_email: Option<String>,

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

/// Resolves the key input from stdin, a file, or a direct value.
fn resolve_key_input(key: &str) -> Result<String> {
    if key == "-" {
        let mut buffer = String::default();
        std::io::stdin().read_to_string(&mut buffer)?;
        Ok(buffer)
    } else if let Some(path) = key.strip_prefix('@') {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read key file '{}': {}", path, e))
    } else {
        Ok(key.to_string())
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

    let key_input = args.key.ok_or_else(|| anyhow::anyhow!("Key is required for GPG import. Use --key or set GPG_PRIVATE_KEY environment variable."))?;
    let key = resolve_key_input(&key_input)?;

    GpgImport::new(key)
        .with_passphrase(args.passphrase)
        .with_fingerprint(args.fingerprint)
        .with_trust_level(args.trust_level.map(|t| t.trust_db_value()))
        .skip_git(args.skip_git)
        .git_global_config(args.git_global_config)
        .with_git_committer_name(args.git_committer_name)
        .with_git_committer_email(args.git_committer_email)
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
