use crate::{git, gpg};
use anyhow::{bail, Result};
use chrono::{TimeZone, Utc};
use git2::Repository;

/// A builder for importing GPG keys with optional configuration.
pub struct GpgImport {
    key: String,
    passphrase: Option<String>,
    fingerprint: Option<String>,
    trust_level: Option<u8>,
    skip_git: bool,
    git_global_config: bool,
    git_committer_name: Option<String>,
    git_committer_email: Option<String>,
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
            git_committer_name: None,
            git_committer_email: None,
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

    /// Override the committer name instead of using the value from the GPG key.
    pub fn with_git_committer_name(mut self, name: Option<String>) -> Self {
        self.git_committer_name = name;
        self
    }

    /// Override the committer email instead of using the value from the GPG key.
    pub fn with_git_committer_email(mut self, email: Option<String>) -> Self {
        self.git_committer_email = email;
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
            for subkey in &private_key.subkeys {
                gpg::preset_passphrase(&subkey.keygrip, passphrase_cleaned)?;
            }
        }

        println!("> Setting Passphrase:");
        println!(
            "keygrip: {} [{}]",
            private_key.secret_key.keygrip, private_key.secret_key.key_id
        );
        for subkey in &private_key.subkeys {
            println!("keygrip: {} [{}]", subkey.keygrip, subkey.key_id);
        }

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
        validate_signing_key_expiry(private_key, &signing_key)?;
        let primary_uid = private_key.primary_uid();
        let user_email = self
            .git_committer_email
            .clone()
            .unwrap_or_else(|| primary_uid.email.clone());
        if user_email.trim().is_empty() {
            bail!("primary GPG UID has no email; provide a Git committer email override");
        }

        let git_cfg = git::SigningConfig {
            user_name: self
                .git_committer_name
                .clone()
                .unwrap_or_else(|| primary_uid.name.clone()),
            user_email,
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
                let matches_subkey = private_key
                    .subkeys
                    .iter()
                    .any(|subkey| fp == &subkey.fingerprint);

                if fp != &private_key.secret_key.fingerprint && !matches_subkey {
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

/// Validates that the key actually selected for signing (as resolved by
/// `resolve_signing_key`) isn't expired. `signing_key` is either a subkey's
/// fingerprint (explicit `--fingerprint` selecting a subkey), the primary
/// key's fingerprint, or the primary key's key id (default, no
/// `--fingerprint`) -- only the first case names a subkey, so this only has
/// something to check when `signing_key` matches one. The primary key's own
/// expiry is already checked unconditionally by `gpg::extract_key_info`.
fn validate_signing_key_expiry(private_key: &gpg::GpgPrivateKey, signing_key: &str) -> Result<()> {
    let Some(subkey) = private_key
        .subkeys
        .iter()
        .find(|subkey| subkey.fingerprint == signing_key)
    else {
        return Ok(());
    };

    if let Some(expiration_date) = subkey.expiration_date {
        if expiration_date <= Utc::now().timestamp() {
            bail!(
                "the selected signing subkey has expired on {}",
                Utc.timestamp_opt(expiration_date, 0).unwrap().to_rfc2822()
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpg::{GpgCapabilities, GpgKeyDetails, GpgPrivateKey, GpgUid};
    use serial_test::serial;
    use std::{env, path::Path};
    use tempfile::TempDir;

    /// Temporarily changes the process's current directory, restoring it
    /// when dropped. `git::is_repo` resolves the repo via
    /// `Repository::open(".")`, so tests exercising git configuration need
    /// to point the process at a throwaway repo instead of this project's
    /// own checkout.
    struct CwdGuard {
        original: std::path::PathBuf,
    }

    impl CwdGuard {
        fn change_to(path: &Path) -> std::io::Result<Self> {
            let original = env::current_dir()?;
            env::set_current_dir(path)?;
            Ok(Self { original })
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = env::set_current_dir(&self.original);
        }
    }

    fn key_with_uid_email(email: &str) -> GpgPrivateKey {
        GpgPrivateKey {
            uids: vec![GpgUid {
                name: "batman".to_string(),
                email: email.to_string(),
            }],
            secret_key: GpgKeyDetails {
                creation_date: 0,
                expiration_date: None,
                fingerprint: "PRIMARYFPR".to_string(),
                key_id: "PRIMARYKEYID".to_string(),
                keygrip: "PRIMARYGRIP".to_string(),
                capabilities: GpgCapabilities {
                    sign: true,
                    certify: true,
                    ..Default::default()
                },
            },
            subkeys: vec![],
        }
    }

    #[test]
    #[serial]
    fn configure_git_signing_bails_when_primary_uid_has_no_email() {
        let repo_dir = TempDir::new().unwrap();
        Repository::init(repo_dir.path()).expect("Failed to init throwaway git repo");
        let _cwd_guard =
            CwdGuard::change_to(repo_dir.path()).expect("Failed to change into throwaway repo");

        let key = key_with_uid_email("");
        let import = GpgImport::new("irrelevant".to_string());

        let result = import.configure_git_signing(&key);
        assert!(
            result.is_err(),
            "Should bail when the primary uid has no email and no override is given"
        );
    }

    #[test]
    #[serial]
    fn configure_git_signing_accepts_committer_email_override_for_name_only_uid() {
        let repo_dir = TempDir::new().unwrap();
        Repository::init(repo_dir.path()).expect("Failed to init throwaway git repo");
        let _cwd_guard =
            CwdGuard::change_to(repo_dir.path()).expect("Failed to change into throwaway repo");

        let key = key_with_uid_email("");
        let import = GpgImport::new("irrelevant".to_string())
            .with_git_committer_email(Some("batman@dc.com".to_string()));

        let result = import.configure_git_signing(&key);
        assert!(
            result.is_ok(),
            "A committer email override should satisfy the check: {:?}",
            result.err()
        );

        let repo = Repository::open(repo_dir.path()).expect("Failed to reopen throwaway repo");
        let config = repo.config().expect("Failed to read throwaway repo config");
        assert_eq!(config.get_string("user.email").unwrap(), "batman@dc.com");
    }

    fn key_with_expiring_subkeys(subkeys: &[(&str, Option<i64>)]) -> GpgPrivateKey {
        GpgPrivateKey {
            uids: vec![GpgUid {
                name: "batman".to_string(),
                email: "batman@dc.com".to_string(),
            }],
            secret_key: GpgKeyDetails {
                creation_date: 0,
                expiration_date: None,
                fingerprint: "PRIMARYFPR".to_string(),
                key_id: "PRIMARYKEYID".to_string(),
                keygrip: "PRIMARYGRIP".to_string(),
                capabilities: GpgCapabilities {
                    sign: true,
                    certify: true,
                    ..Default::default()
                },
            },
            subkeys: subkeys
                .iter()
                .enumerate()
                .map(|(i, (fp, expiration_date))| GpgKeyDetails {
                    creation_date: 0,
                    expiration_date: *expiration_date,
                    fingerprint: fp.to_string(),
                    key_id: format!("SUBKEYID{i}"),
                    keygrip: format!("SUBKEYGRIP{i}"),
                    capabilities: GpgCapabilities {
                        sign: true,
                        ..Default::default()
                    },
                })
                .collect(),
        }
    }

    #[test]
    #[serial]
    fn configure_git_signing_rejects_expired_selected_subkey() {
        let repo_dir = TempDir::new().unwrap();
        Repository::init(repo_dir.path()).expect("Failed to init throwaway git repo");
        let _cwd_guard =
            CwdGuard::change_to(repo_dir.path()).expect("Failed to change into throwaway repo");

        let expired = Utc::now().timestamp() - 86_400;
        let key = key_with_expiring_subkeys(&[
            ("FIRSTSUBKEYFPR", None),
            ("SECONDSUBKEYFPR", Some(expired)),
        ]);
        let import = GpgImport::new("irrelevant".to_string())
            .with_fingerprint(Some("SECONDSUBKEYFPR".to_string()));

        let result = import.configure_git_signing(&key);
        assert!(
            result.is_err(),
            "Should reject an expired subkey that was explicitly selected"
        );
    }

    #[test]
    #[serial]
    fn configure_git_signing_ignores_expired_unselected_subkey() {
        let repo_dir = TempDir::new().unwrap();
        Repository::init(repo_dir.path()).expect("Failed to init throwaway git repo");
        let _cwd_guard =
            CwdGuard::change_to(repo_dir.path()).expect("Failed to change into throwaway repo");

        let expired = Utc::now().timestamp() - 86_400;
        // subkeys[0] is expired but not selected; a different, valid subkey is.
        let key = key_with_expiring_subkeys(&[
            ("FIRSTSUBKEYFPR", Some(expired)),
            ("SECONDSUBKEYFPR", None),
        ]);
        let import = GpgImport::new("irrelevant".to_string())
            .with_fingerprint(Some("SECONDSUBKEYFPR".to_string()));

        let result = import.configure_git_signing(&key);
        assert!(
            result.is_ok(),
            "An expired, unselected subkey must not block a different, valid selected subkey: {:?}",
            result.err()
        );
    }

    fn key_with_subkeys(subkey_fingerprints: &[&str]) -> GpgPrivateKey {
        GpgPrivateKey {
            uids: vec![GpgUid {
                name: "batman".to_string(),
                email: "batman@dc.com".to_string(),
            }],
            secret_key: GpgKeyDetails {
                creation_date: 0,
                expiration_date: None,
                fingerprint: "PRIMARYFPR".to_string(),
                key_id: "PRIMARYKEYID".to_string(),
                keygrip: "PRIMARYGRIP".to_string(),
                capabilities: GpgCapabilities {
                    sign: true,
                    certify: true,
                    ..Default::default()
                },
            },
            subkeys: subkey_fingerprints
                .iter()
                .enumerate()
                .map(|(i, fp)| GpgKeyDetails {
                    creation_date: 0,
                    expiration_date: None,
                    fingerprint: fp.to_string(),
                    key_id: format!("SUBKEYID{i}"),
                    keygrip: format!("SUBKEYGRIP{i}"),
                    capabilities: GpgCapabilities {
                        sign: true,
                        ..Default::default()
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn resolve_signing_key_accepts_non_first_subkey_fingerprint() {
        let key = key_with_subkeys(&["FIRSTSUBKEYFPR", "SECONDSUBKEYFPR", "THIRDSUBKEYFPR"]);
        let import = GpgImport::new("irrelevant".to_string())
            .with_fingerprint(Some("THIRDSUBKEYFPR".to_string()));

        let result = import.resolve_signing_key(&key);
        assert!(
            result.is_ok(),
            "A --fingerprint matching a non-first subkey should resolve, not error: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), "THIRDSUBKEYFPR");
    }

    #[test]
    fn resolve_signing_key_rejects_unknown_fingerprint() {
        let key = key_with_subkeys(&["FIRSTSUBKEYFPR"]);
        let import =
            GpgImport::new("irrelevant".to_string()).with_fingerprint(Some("NOPE".to_string()));

        let result = import.resolve_signing_key(&key);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_signing_key_defaults_to_primary_key_id() {
        let key = key_with_subkeys(&["FIRSTSUBKEYFPR"]);
        let import = GpgImport::new("irrelevant".to_string());

        let result = import.resolve_signing_key(&key);
        assert_eq!(result.unwrap(), "PRIMARYKEYID");
    }
}
