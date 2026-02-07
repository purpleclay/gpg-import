use crate::{git, gpg};
use anyhow::{bail, Result};
use git2::Repository;

/// A builder for importing GPG keys with optional configuration.
pub struct GpgImport {
    key: String,
    passphrase: Option<String>,
    fingerprint: Option<String>,
    trust_level: Option<u8>,
    skip_git: bool,
    git_global_config: bool,
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
            git_global_config: false,
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

    /// Apply git signing configuration globally.
    pub fn git_global_config(mut self, global: bool) -> Self {
        self.git_global_config = global;
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

        let private_key = self.import_gpg_key(&info)?;
        self.configure_gpg_passphrase(&private_key)?;
        self.configure_gpg_trust_level(&private_key)?;
        self.configure_git_signing(&private_key)?;

        Ok(())
    }

    fn import_gpg_key(&self, info: &gpg::GpgInfo) -> Result<gpg::GpgPrivateKey> {
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

        Ok(private_key)
    }

    fn configure_gpg_passphrase(&self, private_key: &gpg::GpgPrivateKey) -> Result<()> {
        let Some(passphrase) = &self.passphrase else {
            return Ok(());
        };

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

        Ok(())
    }

    fn configure_gpg_trust_level(&self, private_key: &gpg::GpgPrivateKey) -> Result<()> {
        let Some(trust_level) = self.trust_level else {
            return Ok(());
        };

        if !self.dry_run {
            gpg::assign_trust_level(&private_key.secret_key.key_id, trust_level)?;
        }

        println!("\n> Setting Trust Level:");
        println!(
            "trust_level: {} [{}]",
            trust_level, private_key.secret_key.key_id
        );

        Ok(())
    }

    fn configure_git_signing(&self, private_key: &gpg::GpgPrivateKey) -> Result<()> {
        if self.skip_git {
            return Ok(());
        }

        let repo = git::is_repo();
        if !self.git_global_config && repo.is_none() {
            return Ok(());
        }

        let signing_key = self.resolve_signing_key(private_key)?;
        let git_cfg = git::SigningConfig {
            user_name: private_key.user_name.clone(),
            user_email: private_key.user_email.clone(),
            key_id: signing_key,
            commit_sign: true,
            tag_sign: true,
            push_sign: true,
        };

        self.apply_git_config(&git_cfg, repo.as_ref())?;
        println!("{git_cfg}");

        Ok(())
    }

    fn resolve_signing_key(&self, private_key: &gpg::GpgPrivateKey) -> Result<String> {
        match &self.fingerprint {
            Some(fp) => {
                if fp != &private_key.secret_key.fingerprint
                    && fp != &private_key.secret_subkey.fingerprint
                {
                    bail!(gpg::GpgError::FingerprintNotFound(fp.clone()));
                }
                Ok(fp.clone())
            }
            None => Ok(private_key.secret_key.key_id.clone()),
        }
    }

    fn apply_git_config(&self, cfg: &git::SigningConfig, repo: Option<&Repository>) -> Result<()> {
        if self.git_global_config {
            if !self.dry_run {
                git::configure_signing_global(cfg)?;
            }
            println!("\n> Git config set (global):");
        } else if let Some(repo) = repo {
            if !self.dry_run {
                git::configure_signing(repo, cfg)?;
            }
            println!("\n> Git config set (local):");
        }

        Ok(())
    }
}
