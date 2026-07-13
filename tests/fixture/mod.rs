//! Shared test fixtures, used across integration test binaries. Each
//! binary only exercises a subset of these, so allow dead code rather
//! than have every binary warn about the helpers it doesn't call.
#![allow(dead_code)]

use anyhow::{bail, Ok, Result};
use gpg_import::gpg;
use std::{env, fs, process::Command};
use tempfile::TempDir;

static GNUPGHOME: &str = "GNUPGHOME";

/// Formats a bare `YYYY-MM-DD` date into a frozen `faketime -f` spec.
///
/// Plain `faketime <date>` (without `-f`) only sets a starting point; the
/// wall clock then keeps advancing in real elapsed time from each process's
/// own start. Two separate faketime invocations sharing the same bare date
/// (e.g. generating a primary key, then later adding a subkey to it) can
/// therefore drift against each other by a fraction of a second, which gpg
/// intermittently rejects with "key ... was created 1 second in the future
/// (time warp or clock problem)" -- reproduced directly under concurrent
/// load. `-f "YYYY-MM-DD hh:mm:ss"` freezes the clock at an exact instant,
/// so every invocation using the same date reports the identical timestamp.
fn freeze_at(date: &str) -> String {
    format!("{date} 00:00:00")
}

/// Restores the process's original GNUPGHOME on drop. Installed as a local
/// variable before any fallible configuration step during fixture
/// construction, so an early `?` return still restores the environment
/// (via normal drop-on-return) before the temp directory it pointed at is
/// deleted; folded into `GpgTestFixture` on success to keep protecting it
/// for the fixture's lifetime.
struct GnupghomeGuard {
    original: Option<String>,
}

impl GnupghomeGuard {
    fn install(new_value: &str) -> Self {
        let original = env::var(GNUPGHOME).ok();
        env::set_var(GNUPGHOME, new_value);
        Self { original }
    }
}

impl Drop for GnupghomeGuard {
    fn drop(&mut self) {
        match &self.original {
            Some(original) => env::set_var(GNUPGHOME, original),
            None => env::remove_var(GNUPGHOME),
        }
    }
}

/// A test fixture that creates an isolated GPG home directory
/// and cleans it up automatically when dropped
pub struct GpgTestFixture {
    temp_dir: TempDir,
    gnupghome_guard: GnupghomeGuard,
}

impl GpgTestFixture {
    pub fn new() -> Result<Self> {
        if !Self::is_gpg_available() {
            bail!("GPG is required for tests. Please install GPG to run tests.")
        }

        let temp_dir = TempDir::new()?;
        let gnupg_home = temp_dir.path().to_string_lossy().to_string();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(temp_dir.path())?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(temp_dir.path(), perms)?;
        }

        let gnupghome_guard = GnupghomeGuard::install(&gnupg_home);

        gpg::configure_defaults(&gnupg_home)?;
        gpg::configure_agent_defaults(&gnupg_home)?;

        Ok(Self {
            temp_dir,
            gnupghome_guard,
        })
    }

    fn is_gpg_available() -> bool {
        Command::new("gpg")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    #[cfg(unix)]
    pub fn batch_generate_key_on(&self, batch_config: &str, yyyy_mm_dd: &str) -> Result<String> {
        self.generate_key(batch_config, Some(yyyy_mm_dd))
    }

    pub fn generate_key(&self, batch_config: &str, created_date: Option<&str>) -> Result<String> {
        let batch_file_path = self.temp_dir.path().join("batch_config.txt");
        fs::write(&batch_file_path, batch_config)?;

        let output = if let Some(date) = created_date {
            Command::new("faketime")
                .arg("-f")
                .arg(freeze_at(date))
                .arg("gpg")
                .arg("--batch")
                .arg("--generate-key")
                .arg(&batch_file_path)
                .output()?
        } else {
            Command::new("gpg")
                .arg("--batch")
                .arg("--generate-key")
                .arg(&batch_file_path)
                .output()?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("Failed to generate GPG key: {}", stderr);
            bail!("Failed to generate GPG key: {}", stderr);
        }

        // Get the fingerprint of the generated key
        self.get_latest_key_fingerprint()
    }

    /// Adds an additional subkey with the given usage (e.g. "sign", "encrypt",
    /// "auth") to an existing, unprotected primary key
    pub fn add_subkey(&self, fingerprint: &str, usage: &str) -> Result<()> {
        let output = Command::new("gpg")
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--yes",
                "--quick-add-key",
                fingerprint,
                "rsa2048",
                usage,
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to add {} subkey: {}", usage, stderr);
        }

        Ok(())
    }

    /// Adds an additional subkey protected by the given passphrase to an
    /// existing, passphrase-protected primary key
    pub fn add_protected_subkey(
        &self,
        fingerprint: &str,
        usage: &str,
        passphrase: &str,
    ) -> Result<()> {
        let output = Command::new("gpg")
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                passphrase,
                "--yes",
                "--quick-add-key",
                fingerprint,
                "rsa2048",
                usage,
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to add {} subkey: {}", usage, stderr);
        }

        Ok(())
    }

    /// Exports the ASCII-armored secret key material for a fingerprint
    /// already present in the keyring
    pub fn export_secret_key(&self, fingerprint: &str) -> Result<String> {
        let output = Command::new("gpg")
            .args(["--armor", "--export-secret-key", fingerprint])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to export secret key: {}", stderr);
        }

        Ok(String::from_utf8(output.stdout)?)
    }

    /// Exports the ASCII-armored secret key material for a passphrase-protected
    /// fingerprint already present in the keyring
    pub fn export_protected_secret_key(
        &self,
        fingerprint: &str,
        passphrase: &str,
    ) -> Result<String> {
        let output = Command::new("gpg")
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                passphrase,
                "--armor",
                "--export-secret-key",
                fingerprint,
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to export secret key: {}", stderr);
        }

        Ok(String::from_utf8(output.stdout)?)
    }

    /// Kills this fixture's gpg-agent (it respawns fresh, with an empty
    /// cache, on the next gpg invocation). Setup steps that authenticate
    /// with a real passphrase (e.g. `add_protected_subkey`,
    /// `export_protected_secret_key`) may leave agent-implementation-defined
    /// cache state behind; call this before asserting that a later signing
    /// step genuinely required its own explicit passphrase preset, so the
    /// assertion doesn't depend on incidental caching from setup.
    pub fn kill_agent(&self) -> Result<()> {
        let output = Command::new("gpgconf")
            .args(["--kill", "gpg-agent"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to kill gpg-agent: {}", stderr);
        }

        Ok(())
    }

    /// Get the fingerprint of the most recently generated key
    fn get_latest_key_fingerprint(&self) -> Result<String> {
        let output = Command::new("gpg")
            .arg("--list-secret-keys")
            .arg("--with-colons")
            .arg("--fingerprint")
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to list GPG keys: {}", stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            if line.starts_with("fpr:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() > 9 && !parts[9].is_empty() {
                    return Ok(parts[9].to_string());
                }
            }
        }

        bail!("Could not find fingerprint in GPG output")
    }

    pub fn create_and_sign_file(&self, fingerprint: &str) -> Result<()> {
        let content = "Lorem ipsum dolor sit amet consectetur adipiscing elit. \
                       Quisque faucibus ex sapien vitae pellentesque sem placerat. \
                       In id cursus mi pretium tellus duis convallis. \
                       Tempus leo eu aenean sed diam urna tempor. \
                       Pulvinar vivamus fringilla lacus nec metus bibendum egestas. \
                       Iaculis massa nisl malesuada lacinia integer nunc posuere. \
                       Ut hendrerit semper vel class aptent taciti sociosqu. \
                       Ad litora torquent per conubia nostra inceptos himenaeos.";

        let file_path = self.temp_dir.path().join("test_file.txt");
        fs::write(&file_path, content)?;

        let signature_path = file_path.with_extension("sig");
        let output = Command::new("gpg")
            .arg("--batch")
            .arg("--yes")
            .arg("--local-user")
            .arg(fingerprint)
            .arg("--detach-sign")
            .arg("--output")
            .arg(&signature_path)
            .arg(&file_path)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("Failed to sign file: {}", stderr);
        }

        if !signature_path.exists() {
            bail!("Signature file was not created");
        }

        Ok(())
    }
}
