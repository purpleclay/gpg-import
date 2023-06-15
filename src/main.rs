use gpg_import::{git, gpg};
use std::{env, println};

static GPG_PRIVATE_KEY: &str = "GPG_PRIVATE_KEY";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gpg_private_key = env::var(GPG_PRIVATE_KEY)
        .unwrap_or_else(|_| panic!("env variable {} must bet set", GPG_PRIVATE_KEY));

    let info = gpg::detect_version()?;
    println!("> Detected GnuPG:");
    println!("{}", info);

    let key_id = gpg::import_secret_key(&gpg_private_key)?;
    let private_key = gpg::extract_key_info(&key_id)?;
    println!("> Imported GPG key:");
    println!("{}", private_key);

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
    Ok(())
}
