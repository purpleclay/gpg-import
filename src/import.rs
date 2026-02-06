use crate::{git, gpg};
use anyhow::{bail, Result};

/// A builder for importing GPG keys with optional configuration.
pub struct GpgImport {
    key: String,
    passphrase: Option<String>,
    fingerprint: Option<String>,
    trust_level: Option<u8>,
    skip_git: bool,
    dry_run: bool,
}

impl GpgImport {
    /// Create a new GPG import with the given base64-encoded key.
    pub fn new(key: String) -> Self {
        Self {
            key,
            passphrase: None,
            fingerprint: None,
            trust_level: None,
            skip_git: false,
            dry_run: false,
        }
    }

    /// Set the passphrase for the key.
    pub fn with_passphrase(mut self, passphrase: Option<String>) -> Self {
        self.passphrase = passphrase;
        self
    }

    /// Set the fingerprint of a specific key or subkey to use for signing.
    pub fn with_fingerprint(mut self, fingerprint: Option<String>) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    /// Set the trust level for the key (1-5).
    pub fn with_trust_level(mut self, level: Option<u8>) -> Self {
        self.trust_level = level;
        self
    }

    /// Skip git repository configuration.
    pub fn skip_git(mut self, skip: bool) -> Self {
        self.skip_git = skip;
        self
    }

    /// Enable dry-run mode (preview without making changes).
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Execute the GPG import.
    pub fn import(self) -> Result<()> {
        if self.dry_run {
            println!("No changes will be made will running in dry-run mode\n");
        }

        let info = gpg::detect_version()?;
        println!("> Detected GnuPG:");
        println!("{info}");

        let private_key = if self.dry_run {
            gpg::preview_key(self.key.trim())?
        } else {
            let key_id = gpg::import_secret_key(self.key.trim())?;
            gpg::extract_key_info(&key_id)?
        };

        println!("> Imported GPG key:");
        println!("{private_key}");

        if !self.dry_run {
            gpg::configure_defaults(&info.home_dir)?;
            gpg::configure_agent_defaults(&info.home_dir)?;
        }

        if let Some(passphrase) = &self.passphrase {
            let passphrase_cleaned = passphrase.trim();

            if !self.dry_run {
                gpg::preset_passphrase(&private_key.secret_key.keygrip, passphrase_cleaned)?;
                gpg::preset_passphrase(&private_key.secret_subkey.keygrip, passphrase_cleaned)?;
            }

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

        if let Some(trust_level) = self.trust_level {
            if !self.dry_run {
                gpg::assign_trust_level(&private_key.secret_key.key_id, trust_level)?;
            }

            println!("\n> Setting Trust Level:");
            println!(
                "trust_level: {} [{}]",
                trust_level, private_key.secret_key.key_id
            );
        }

        if !self.skip_git {
            if let Some(repo) = git::is_repo() {
                let signing_key = if let Some(ref fp) = self.fingerprint {
                    if fp != &private_key.secret_key.fingerprint
                        && fp != &private_key.secret_subkey.fingerprint
                    {
                        bail!(gpg::GpgError::FingerprintNotFound(fp.clone()));
                    }
                    fp.clone()
                } else {
                    private_key.secret_key.key_id.clone()
                };

                let git_cfg = git::SigningConfig {
                    user_name: private_key.user_name,
                    user_email: private_key.user_email,
                    key_id: signing_key,
                    commit_sign: true,
                    tag_sign: true,
                    push_sign: true,
                };

                if !self.dry_run {
                    git::configure_signing(&repo, &git_cfg)?;
                }

                println!("\n> Git config set:");
                println!("{git_cfg}");
            }
        }
        Ok(())
    }
}
