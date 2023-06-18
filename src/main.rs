use clap::{command, Parser};
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

    /// Skip all GPG configuration for the detected git repository
    #[arg(short, long, env = "GPG_SKIP_GIT", default_value_t = false)]
    skip_git: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let info = gpg::detect_version()?;
    println!("> Detected GnuPG:");
    println!("{}", info);

    let key_id = gpg::import_secret_key(&args.key)?;
    let private_key = gpg::extract_key_info(&key_id)?;
    println!("> Imported GPG key:");
    println!("{}", private_key);

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
