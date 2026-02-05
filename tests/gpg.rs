use anyhow::{bail, Ok, Result};
use chrono::{Duration, Utc};
use gpg_import::gpg;
use serial_test::serial;
use std::{env, fs, process::Command};
use tempfile::TempDir;

static GNUPGHOME: &str = "GNUPGHOME";

#[derive(Default)]
struct GpgBatchConfig {
    expires_on: Option<String>,
    subkey_expires_on: Option<String>,
}

impl GpgBatchConfig {
    fn expires_on(mut self, yyyy_mm_dd: &str) -> Self {
        self.expires_on = Some(yyyy_mm_dd.to_string());
        self
    }

    fn subkey_expires_on(mut self, yyyy_mm_dd: &str) -> Self {
        self.subkey_expires_on = Some(yyyy_mm_dd.to_string());
        self
    }

    fn build(self) -> String {
        let mut batch_content = "Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 4096
Subkey-Usage: encrypt
Name-Real: batman
Name-Email: batman@dc.com"
            .to_string();

        if let Some(expires_on) = self.expires_on {
            batch_content.push_str(&format!("\nExpire-Date: {}", expires_on));
        }

        if let Some(subkey_expires_on) = self.subkey_expires_on {
            batch_content.push_str(&format!("\nSubkey-Expire-Date: {}", subkey_expires_on));
        }

        batch_content.push_str("\n%no-protection");
        batch_content.push_str("\n%commit\n");
        batch_content
    }
}

/// A test fixture that creates an isolated GPG home directory
/// and cleans it up automatically when dropped
struct GpgTestFixture {
    temp_dir: TempDir,
    original_gnupghome: Option<String>,
}

impl GpgTestFixture {
    fn new() -> Result<Self> {
        if !Self::is_gpg_available() {
            bail!("GPG is required for tests. Please install GPG to run tests.")
        }

        let temp_dir = TempDir::new()?;
        let gnupg_home = temp_dir.path().to_string_lossy().to_string();

        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(temp_dir.path())?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(temp_dir.path(), perms)?;

        // Save original GNUPGHOME, allowing it to be restored later
        let original_gnupghome = env::var(GNUPGHOME).ok();
        env::set_var(GNUPGHOME, &gnupg_home);

        gpg::configure_defaults(&gnupg_home)?;
        gpg::configure_agent_defaults(&gnupg_home)?;

        Ok(Self {
            temp_dir,
            original_gnupghome,
        })
    }

    fn is_gpg_available() -> bool {
        Command::new("gpg")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    #[cfg(unix)]
    fn batch_generate_key_on(&self, batch_config: &str, yyyy_mm_dd: &str) -> Result<String> {
        self.generate_key(batch_config, Some(yyyy_mm_dd))
    }

    fn generate_key(&self, batch_config: &str, created_date: Option<&str>) -> Result<String> {
        let batch_file_path = self.temp_dir.path().join("batch_config.txt");
        fs::write(&batch_file_path, batch_config)?;

        let output = if let Some(date) = created_date {
            Command::new("faketime")
                .arg(date)
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

    fn create_and_sign_file(&self, fingerprint: &str) -> Result<()> {
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

impl Drop for GpgTestFixture {
    fn drop(&mut self) {
        match &self.original_gnupghome {
            Some(original) => env::set_var(GNUPGHOME, original),
            _ => env::remove_var(GNUPGHOME),
        }
    }
}

#[test]
#[serial]
fn import_secret_key() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let gpg_key = include_str!("testdata/no-passphrase.key");
    let result = gpg::import_secret_key(gpg_key);
    assert!(result.is_ok(), "Failed to import GPG key");

    let fingerprint = result.unwrap();
    let sign_result = fixture.create_and_sign_file(&fingerprint);
    assert!(sign_result.is_ok(), "Failed to create and sign test file");
}

#[test]
#[serial]
fn import_secret_key_with_passphrase() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let gpg_key = include_str!("testdata/passphrase.key");
    let result = gpg::import_secret_key(gpg_key);
    assert!(result.is_ok(), "Failed to import GPG key");

    let passphrase = "gotham";
    assert!(
        gpg::preset_passphrase("A38A309DBDD35F6597F3AB132ECDE01CCA68D62F", passphrase).is_ok(),
        "Failed to preset passphrase"
    );
    assert!(
        gpg::preset_passphrase("60C07F604DC06BA2F6DF829A8CF2F7380089C409", passphrase).is_ok(),
        "Failed to preset passphrase"
    );

    let fingerprint = result.unwrap();
    let sign_result = fixture.create_and_sign_file(&fingerprint);
    assert!(sign_result.is_ok(), "Failed to create and sign test file");
}

#[test]
#[serial]
fn extract_key_info_expired_secret_key() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");

    let created_on = Utc::now() - Duration::days(10);
    let expired_on = created_on + Duration::days(5);

    let fixture = fixture.unwrap();
    let batch_config = GpgBatchConfig::default()
        .expires_on(&expired_on.format("%Y-%m-%d").to_string())
        .build();

    let result =
        fixture.batch_generate_key_on(&batch_config, &created_on.format("%Y-%m-%d").to_string());
    assert!(result.is_ok(), "Failed to generate GPG key");

    let result = gpg::extract_key_info(&result.unwrap());
    assert!(
        result.is_err(),
        "Failed to extract key info for expired secret key"
    );

    let error = result.unwrap_err();
    let error_message = format!("{}", error);
    assert!(
        error_message.contains("GPG secret key has expired on"),
        "Expected error message does not match"
    );
}

#[test]
#[serial]
fn extract_key_info_expired_secret_subkey() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");

    let created_on = Utc::now() - Duration::days(10);
    let not_expired = created_on + Duration::days(30);
    let subkey_expired_on = created_on + Duration::days(5);

    let fixture = fixture.unwrap();
    let batch_config = GpgBatchConfig::default()
        .expires_on(&not_expired.format("%Y-%m-%d").to_string())
        .subkey_expires_on(&subkey_expired_on.format("%Y-%m-%d").to_string())
        .build();

    let result =
        fixture.batch_generate_key_on(&batch_config, &created_on.format("%Y-%m-%d").to_string());
    assert!(result.is_ok(), "Failed to generate GPG key");

    let result = gpg::extract_key_info(&result.unwrap());
    assert!(
        result.is_err(),
        "Failed to extract key info for expired secret subkey"
    );

    let error = result.unwrap_err();
    let error_message = format!("{}", error);
    assert!(
        error_message.contains("GPG secret subkey has expired on"),
        "Expected error message does not match"
    );
}

#[test]
#[serial]
fn assign_trust_level() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let _fixture = fixture.unwrap();

    let gpg_key = include_str!("testdata/no-passphrase.key");
    let result = gpg::import_secret_key(gpg_key);
    assert!(result.is_ok(), "Failed to import GPG key");

    let key_id = result.unwrap();
    let key_info = gpg::extract_key_info(&key_id);
    assert!(key_info.is_ok(), "Failed to extract key info");

    let key_info = key_info.unwrap();
    let result = gpg::assign_trust_level(&key_info.secret_key.key_id, 5);
    assert!(result.is_ok(), "Failed to assign trust level");
}

#[test]
fn preview_key_returns_key_details() {
    let gpg_key = include_str!("testdata/no-passphrase.key");
    let result = gpg::preview_key(gpg_key);
    assert!(result.is_ok(), "Should preview GPG key");

    let key = result.unwrap();
    assert_eq!(key.user_name, "batman");
    assert_eq!(key.user_email, "batman@dc.com");
    assert!(!key.secret_key.fingerprint.is_empty());
    assert!(!key.secret_key.key_id.is_empty());
    assert!(!key.secret_key.keygrip.is_empty());
    assert!(!key.secret_subkey.key_id.is_empty());
    assert!(!key.secret_subkey.keygrip.is_empty());
}

#[test]
fn import_secret_key_invalid_base64() {
    let invalid_base64 = "not-valid-base64!!!";
    let result = gpg::import_secret_key(invalid_base64);

    let err = result.unwrap_err();
    let gpg_err = err.downcast_ref::<gpg::GpgError>().unwrap();
    assert!(
        matches!(gpg_err, gpg::GpgError::InvalidByteInGpgKey(_, _)),
        "Expected InvalidByteInGpgKey error, got: {}",
        gpg_err
    );
}

#[test]
fn import_secret_key_empty_input() {
    let result = gpg::import_secret_key("");

    let err = result.unwrap_err();
    let gpg_err = err.downcast_ref::<gpg::GpgError>().unwrap();
    assert!(
        matches!(gpg_err, gpg::GpgError::EmptyKeyInput),
        "Expected EmptyKeyInput error, got: {}",
        gpg_err
    );
}

#[test]
#[serial]
fn import_secret_key_valid_base64_invalid_gpg_data() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let _fixture = fixture.unwrap();

    use base64::{engine::general_purpose, Engine as _};
    let invalid_gpg_data = general_purpose::STANDARD.encode("not a gpg key");

    let result = gpg::import_secret_key(&invalid_gpg_data);

    let err = result.unwrap_err();
    let gpg_err = err.downcast_ref::<gpg::GpgError>().unwrap();
    assert!(
        matches!(gpg_err, gpg::GpgError::InvalidGpgKeyData(_)),
        "Expected InvalidGpgKeyData error, got: {}",
        gpg_err
    );
}

#[test]
#[serial]
fn extract_key_info_nonexistent_key() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let _fixture = fixture.unwrap();

    let result = gpg::extract_key_info("NONEXISTENT1234567890");

    let err = result.unwrap_err();
    let gpg_err = err.downcast_ref::<gpg::GpgError>().unwrap();
    assert!(
        matches!(gpg_err, gpg::GpgError::KeyNotFound(_)),
        "Expected KeyNotFound error, got: {}",
        gpg_err
    );
}
