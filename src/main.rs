#![cfg_attr(not(test), warn(clippy::unwrap_used))]

use anyhow::Result;
use clap::{
    Parser, Subcommand, ValueEnum,
    builder::{FalseyValueParser, styling::Styles},
};
use gpg_import::import::GpgImport;
use std::io::Read;

const EXAMPLES: &str = "  # Import the key in GPG_PRIVATE_KEY and preset the passphrase in GPG_PASSPHRASE
  $ gpg-import

  # Pipe a key straight from gpg
  $ gpg --armor --export-secret-key batman@dc.com | gpg-import --key -

  # Read the key and passphrase from files (only one of them can read stdin)
  $ gpg-import --key @/path/to/private.key --passphrase @/path/to/passphrase

  # Configure git globally instead of the current repository
  $ gpg-import --git-global-config

  # Sign with a specific subkey. List fingerprints with
  # `gpg --list-secret-keys --with-subkey-fingerprints` and pick one marked [S]
  $ gpg-import --fingerprint \"$SUBKEY_FINGERPRINT\"

  # Use a different committer identity from the one in the key
  $ gpg-import --git-committer-name \"Bruce Wayne\" --git-committer-email \"bruce@wayne.enterprises\"

  # Preview the import without changing anything
  $ gpg-import --dry-run";

/// Places the examples straight after the usage line, as Cobra does. clap
/// writes two newlines before `{after-help}`, and omits it for `-h`, which
/// then keeps clap's default layout
const HELP_TEMPLATE: &str = "\
{before-help}{about-with-newline}
{usage-heading} {usage}{after-help}

{all-args}";

/// The examples, under a heading styled like clap's own (bold, underlined)
fn examples() -> String {
    let styles = Styles::styled();
    let header = styles.get_header();
    format!("{header}Examples:{header:#}\n{EXAMPLES}")
}

#[derive(Parser, Debug)]
#[command(author, about, long_about = None, help_template = HELP_TEMPLATE, after_long_help = examples(), disable_version_flag = true, disable_help_subcommand = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// An ASCII armored GPG private key (optionally base64 encoded). Use - for
    /// stdin or @path to read from a file
    ///
    /// Don't pass the key itself as the value: an armored key starts with
    /// -----BEGIN, which is read as an option, and the key would be visible
    /// to other processes. Use GPG_PRIVATE_KEY, - or @path instead
    #[arg(
        short,
        long,
        env = "GPG_PRIVATE_KEY",
        value_name = "GPG_KEY",
        hide_env_values = true
    )]
    key: Option<String>,

    /// The passphrase of the GPG private key if set. Use - for stdin or @path
    /// to read from a file
    ///
    /// A passphrase given directly is visible to other processes, e.g.
    /// through ps. Use GPG_PASSPHRASE, - or @path instead
    #[arg(short, long, env = "GPG_PASSPHRASE", hide_env_values = true)]
    passphrase: Option<String>,

    /// The fingerprint of a specific key or subkey to use for signing
    #[arg(short, long, env = "GPG_FINGERPRINT", value_name = "FINGERPRINT")]
    fingerprint: Option<String>,

    /// A level of trust to associate with the GPG private key
    #[arg(short, long, env = "GPG_TRUST_LEVEL", value_enum)]
    trust_level: Option<TrustLevel>,

    /// Skip all GPG configuration for the detected git repository
    #[arg(short, long, env = "GPG_SKIP_GIT", value_parser = FalseyValueParser::new())]
    skip_git: bool,

    /// Apply git signing configuration globally
    #[arg(long, env = "GPG_GIT_GLOBAL_CONFIG", value_parser = FalseyValueParser::new())]
    git_global_config: bool,

    /// Override the committer name instead of using the value from the GPG key
    #[arg(long, env = "GPG_GIT_COMMITTER_NAME", value_name = "NAME")]
    git_committer_name: Option<String>,

    /// Override the committer email instead of using the value from the GPG key
    #[arg(long, env = "GPG_GIT_COMMITTER_EMAIL", value_name = "EMAIL")]
    git_committer_email: Option<String>,

    /// Simulate the import without making changes
    #[arg(long, env = "GPG_DRY_RUN", value_parser = FalseyValueParser::new())]
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

/// Resolves a secret (key or passphrase) from stdin, a file, or a direct value.
fn resolve_secret_input(name: &str, value: &str) -> Result<String> {
    if value == "-" {
        let mut buffer = String::default();
        std::io::stdin().read_to_string(&mut buffer)?;
        Ok(buffer)
    } else if let Some(path) = value.strip_prefix('@') {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read {} file '{}': {}", name, path, e))
    } else {
        Ok(value.to_string())
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

    let key_input = args.key.ok_or_else(|| {
        anyhow::anyhow!(
            "Key is required for GPG import. Use --key or set GPG_PRIVATE_KEY environment variable."
        )
    })?;
    if key_input == "-" && args.passphrase.as_deref() == Some("-") {
        anyhow::bail!(
            "--key and --passphrase cannot both read from stdin. Pass one of them with @path instead."
        );
    }
    let key = resolve_secret_input("key", &key_input)?;
    let passphrase = args
        .passphrase
        .map(|passphrase| resolve_secret_input("passphrase", &passphrase))
        .transpose()?;

    GpgImport::new(key)
        .with_passphrase(passphrase)
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
    println!("{}", env!("CARGO_PKG_VERSION"));
}

fn print_version_info() {
    let fields = [
        ("version", Some(env!("CARGO_PKG_VERSION"))),
        ("rustc", option_env!("GPG_IMPORT_RUSTC")),
        ("target", option_env!("GPG_IMPORT_TARGET")),
        ("git_branch", option_env!("GPG_IMPORT_GIT_REF")),
        ("git_commit", option_env!("GPG_IMPORT_GIT_SHA")),
        ("commit_date", option_env!("GPG_IMPORT_COMMIT_DATE")),
    ];
    for (name, value) in fields {
        if let Some(value) = value {
            println!("{:<12} {value}", format!("{name}:"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn parse_with_env(var: &str, value: Option<&str>, cli: &[&str]) -> Args {
        // SAFETY: #[serial] stops tests in this binary touching the environment concurrently
        unsafe {
            match value {
                Some(value) => std::env::set_var(var, value),
                None => std::env::remove_var(var),
            }
        }
        let args = Args::try_parse_from(std::iter::once("gpg-import").chain(cli.iter().copied()));
        unsafe { std::env::remove_var(var) };
        args.unwrap_or_else(|e| panic!("{var}={value:?} {cli:?}: {e}"))
    }

    #[test]
    #[serial]
    fn boolean_env_vars_accept_common_truthy_and_falsey_values() {
        type Flag = (&'static str, &'static str, fn(&Args) -> bool);
        let flags: [Flag; 3] = [
            ("GPG_SKIP_GIT", "--skip-git", |a| a.skip_git),
            ("GPG_GIT_GLOBAL_CONFIG", "--git-global-config", |a| {
                a.git_global_config
            }),
            ("GPG_DRY_RUN", "--dry-run", |a| a.dry_run),
        ];
        let cases = [
            (None, false),
            (Some("true"), true),
            (Some("1"), true),
            (Some("false"), false),
            (Some("0"), false),
            (Some(""), false),
        ];

        for (var, flag, get) in flags {
            for (value, expected) in cases {
                let args = parse_with_env(var, value, &[]);
                assert_eq!(get(&args), expected, "{var}={value:?}");
            }

            // An explicit flag still wins over a falsey env var
            let args = parse_with_env(var, Some("0"), &[flag]);
            assert!(get(&args), "{flag} with {var}=0");
        }
    }
}
