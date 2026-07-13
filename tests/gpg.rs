use chrono::{Duration, Utc};
use gpg_import::gpg;
use serial_test::serial;
use std::env;

mod fixture;
use fixture::GpgTestFixture;

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

#[test]
#[serial]
fn import_secret_key_base64() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let gpg_key = include_str!("testdata/no-passphrase.base64.key");
    let result = gpg::import_secret_key(gpg_key);
    assert!(result.is_ok(), "Failed to import GPG key");

    let fingerprint = result.unwrap();
    let sign_result = fixture.create_and_sign_file(&fingerprint);
    assert!(sign_result.is_ok(), "Failed to create and sign test file");
}

/// Temporarily overrides locale env vars for the current process, restoring
/// the original values (or absence) when dropped
struct LocaleGuard {
    originals: Vec<(&'static str, Option<String>)>,
}

impl LocaleGuard {
    fn set(vars: &[(&'static str, &str)]) -> Self {
        let originals = vars
            .iter()
            .map(|(name, value)| {
                let original = env::var(name).ok();
                env::set_var(name, value);
                (*name, original)
            })
            .collect();

        Self { originals }
    }
}

impl Drop for LocaleGuard {
    fn drop(&mut self) {
        for (name, original) in &self.originals {
            match original {
                Some(value) => env::set_var(name, value),
                None => env::remove_var(name),
            }
        }
    }
}

#[test]
#[serial]
fn import_secret_key_under_non_c_locale() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    // gpg's status-fd records are locale-stable, unlike its stderr prose.
    // This asserts the import succeeds even when the calling process runs
    // under a locale that would gettext-translate gpg's human-readable output.
    let _locale_guard = LocaleGuard::set(&[
        ("LANG", "de_DE.UTF-8"),
        ("LC_ALL", "de_DE.UTF-8"),
        ("LANGUAGE", "de"),
    ]);

    let gpg_key = include_str!("testdata/no-passphrase.base64.key");
    let result = gpg::import_secret_key(gpg_key);
    assert!(
        result.is_ok(),
        "Failed to import GPG key under non-C locale: {:?}",
        result.err()
    );

    let fingerprint = result.unwrap();
    let sign_result = fixture.create_and_sign_file(&fingerprint);
    assert!(sign_result.is_ok(), "Failed to create and sign test file");
}

#[test]
#[serial]
fn import_secret_key_base64_with_passphrase() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let gpg_key = include_str!("testdata/passphrase.base64.key");
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
fn extract_key_info_does_not_reject_expired_subkey() {
    // extract_key_info doesn't know which key (if any) will be selected for
    // signing, so it intentionally leaves subkey-expiry enforcement to
    // GpgImport::configure_git_signing, which validates expiry for the
    // specific key actually resolved for signing. See
    // configure_git_signing_rejects_expired_selected_subkey and
    // configure_git_signing_ignores_expired_unselected_subkey in import.rs.
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
        result.is_ok(),
        "extract_key_info should not fail on an expired subkey: {:?}",
        result.err()
    );
}

#[test]
#[serial]
fn extract_key_info_sign_only_no_subkey() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let batch_config = "Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: robin
Name-Email: robin@dc.com
%no-protection
%commit
";

    let fingerprint = fixture.generate_key(batch_config, None);
    assert!(fingerprint.is_ok(), "Failed to generate sign-only GPG key");
    let fingerprint = fingerprint.unwrap();

    let key_info = gpg::extract_key_info(&fingerprint);
    assert!(
        key_info.is_ok(),
        "Should extract info for a sign-only key with no subkey"
    );

    let key_info = key_info.unwrap();
    assert!(
        key_info.subkeys.is_empty(),
        "Sign-only key should have no subkeys"
    );
    assert_eq!(key_info.primary_uid().name, "robin");

    let sign_result = fixture.create_and_sign_file(&key_info.secret_key.fingerprint);
    assert!(
        sign_result.is_ok(),
        "Sign-only key should still be able to sign"
    );
}

#[test]
#[serial]
fn extract_key_info_multiple_subkeys() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let batch_config = "Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: batman
Name-Email: batman@dc.com
%no-protection
%commit
";

    let fingerprint = fixture.generate_key(batch_config, None);
    assert!(fingerprint.is_ok(), "Failed to generate primary key");
    let fingerprint = fingerprint.unwrap();

    // The signing-capable subkey is deliberately added after an encryption
    // subkey, mirroring key rotation where the original encrypt subkey
    // precedes a later-added signing subkey.
    assert!(
        fixture.add_subkey(&fingerprint, "encrypt").is_ok(),
        "Failed to add encrypt subkey"
    );
    assert!(
        fixture.add_subkey(&fingerprint, "sign").is_ok(),
        "Failed to add sign subkey"
    );
    assert!(
        fixture.add_subkey(&fingerprint, "auth").is_ok(),
        "Failed to add auth subkey"
    );

    let key_info = gpg::extract_key_info(&fingerprint);
    assert!(
        key_info.is_ok(),
        "Should extract info for a key with 3 subkeys"
    );

    let key_info = key_info.unwrap();
    assert_eq!(key_info.subkeys.len(), 3, "Should parse all 3 subkeys");
    assert!(key_info.subkeys[0].capabilities.encrypt);
    assert!(key_info.subkeys[1].capabilities.sign);
    assert!(key_info.subkeys[2].capabilities.authenticate);

    let signing_subkey = key_info.subkeys.iter().find(|k| k.capabilities.sign);
    assert!(
        signing_subkey.is_some_and(|k| !k.fingerprint.is_empty() && !k.keygrip.is_empty()),
        "The non-first signing-capable subkey should have a fingerprint and keygrip"
    );
}

#[test]
#[serial]
fn preset_passphrase_for_every_subkey_allows_non_first_subkey_to_sign() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let passphrase = "gotham";
    let batch_config = format!(
        "Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: batman
Name-Email: batman@dc.com
Passphrase: {passphrase}
%commit
"
    );

    let fingerprint = fixture.generate_key(&batch_config, None);
    assert!(fingerprint.is_ok(), "Failed to generate primary key");
    let fingerprint = fingerprint.unwrap();

    // Signing-capable subkey deliberately not first, mirroring the scenario
    // where configure_gpg_passphrase previously only preset subkeys.first().
    assert!(
        fixture
            .add_protected_subkey(&fingerprint, "encrypt", passphrase)
            .is_ok(),
        "Failed to add encrypt subkey"
    );
    assert!(
        fixture
            .add_protected_subkey(&fingerprint, "sign", passphrase)
            .is_ok(),
        "Failed to add sign subkey"
    );

    let key_info = gpg::extract_key_info(&fingerprint);
    assert!(key_info.is_ok(), "Failed to extract key info");
    let key_info = key_info.unwrap();
    assert_eq!(key_info.subkeys.len(), 2);

    // add_protected_subkey authenticated with the real passphrase above; kill
    // the agent so any residual cache from that setup can't make the signing
    // assertion below pass regardless of whether the preset loop works.
    assert!(fixture.kill_agent().is_ok(), "Failed to kill gpg-agent");

    // Mirrors GpgImport::configure_gpg_passphrase: preset primary + every subkey.
    assert!(gpg::preset_passphrase(&key_info.secret_key.keygrip, passphrase).is_ok());
    for subkey in &key_info.subkeys {
        assert!(
            gpg::preset_passphrase(&subkey.keygrip, passphrase).is_ok(),
            "Failed to preset passphrase for subkey {}",
            subkey.key_id
        );
    }

    // The non-first (sign) subkey must be able to sign without prompting,
    // since its passphrase was preset above.
    let signing_subkey = &key_info.subkeys[1];
    assert!(signing_subkey.capabilities.sign);
    let sign_result = fixture.create_and_sign_file(&signing_subkey.fingerprint);
    assert!(
        sign_result.is_ok(),
        "Non-first subkey should sign without a passphrase prompt: {:?}",
        sign_result.err()
    );
}

#[test]
#[serial]
fn preview_key_sign_only_no_subkey() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let batch_config = "Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: robin
Name-Email: robin@dc.com
%no-protection
%commit
";

    let fingerprint = fixture.generate_key(batch_config, None);
    assert!(fingerprint.is_ok(), "Failed to generate sign-only GPG key");
    let fingerprint = fingerprint.unwrap();

    let armored = fixture.export_secret_key(&fingerprint);
    assert!(armored.is_ok(), "Failed to export sign-only GPG key");

    // preview_key uses a different gpg invocation (`--import-options show-only`,
    // without --fixed-list-mode) to extract_key_info's (`--list-secret-keys`),
    // so the zero-subkey case is verified independently here.
    let result = gpg::preview_key(&armored.unwrap());
    assert!(result.is_ok(), "Should preview a sign-only key");

    let key = result.unwrap();
    assert!(
        key.subkeys.is_empty(),
        "Sign-only key should have no subkeys"
    );
    assert_eq!(key.primary_uid().name, "robin");
}

#[test]
#[serial]
fn preview_key_multiple_subkeys() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let batch_config = "Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Name-Real: batman
Name-Email: batman@dc.com
%no-protection
%commit
";

    let fingerprint = fixture.generate_key(batch_config, None);
    assert!(fingerprint.is_ok(), "Failed to generate primary key");
    let fingerprint = fingerprint.unwrap();

    // Same encrypt-then-sign-then-auth ordering as extract_key_info_multiple_subkeys,
    // exercised here through preview_key's separate gpg invocation.
    assert!(
        fixture.add_subkey(&fingerprint, "encrypt").is_ok(),
        "Failed to add encrypt subkey"
    );
    assert!(
        fixture.add_subkey(&fingerprint, "sign").is_ok(),
        "Failed to add sign subkey"
    );
    assert!(
        fixture.add_subkey(&fingerprint, "auth").is_ok(),
        "Failed to add auth subkey"
    );

    let armored = fixture.export_secret_key(&fingerprint);
    assert!(armored.is_ok(), "Failed to export multi-subkey GPG key");

    let result = gpg::preview_key(&armored.unwrap());
    assert!(result.is_ok(), "Should preview a key with 3 subkeys");

    let key = result.unwrap();
    assert_eq!(key.subkeys.len(), 3, "Should parse all 3 subkeys");
    assert!(key.subkeys[0].capabilities.encrypt);
    assert!(key.subkeys[1].capabilities.sign);
    assert!(key.subkeys[2].capabilities.authenticate);
}

#[test]
#[serial]
fn assign_trust_level() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let _fixture = fixture.unwrap();

    let gpg_key = include_str!("testdata/no-passphrase.base64.key");
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
#[serial]
fn preview_key_base64() {
    let gpg_key = include_str!("testdata/no-passphrase.base64.key");
    let result = gpg::preview_key(gpg_key);
    assert!(result.is_ok(), "Should preview GPG key");

    let key = result.unwrap();
    assert_eq!(key.primary_uid().name, "batman");
    assert_eq!(key.primary_uid().email, "batman@dc.com");
    assert!(!key.secret_key.fingerprint.is_empty());
    assert!(!key.secret_key.key_id.is_empty());
    assert!(!key.secret_key.keygrip.is_empty());
    assert_eq!(key.subkeys.len(), 1);
    assert!(!key.subkeys[0].key_id.is_empty());
    assert!(!key.subkeys[0].keygrip.is_empty());
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

#[test]
#[serial]
fn import_secret_key_ascii_armored() {
    let fixture = GpgTestFixture::new();
    assert!(fixture.is_ok(), "Failed to create GPG test fixture");
    let fixture = fixture.unwrap();

    let gpg_key = include_str!("testdata/no-passphrase.asc");
    let result = gpg::import_secret_key(gpg_key);
    assert!(result.is_ok(), "Failed to import ASCII armored GPG key");

    let fingerprint = result.unwrap();
    let sign_result = fixture.create_and_sign_file(&fingerprint);
    assert!(sign_result.is_ok(), "Failed to create and sign test file");
}

#[test]
#[serial]
fn preview_key_ascii_armored() {
    let gpg_key = include_str!("testdata/no-passphrase.asc");
    let result = gpg::preview_key(gpg_key);
    assert!(result.is_ok(), "Should preview ASCII armored GPG key");

    let key = result.unwrap();
    assert_eq!(key.primary_uid().name, "batman");
    assert_eq!(key.primary_uid().email, "batman@dc.com");
    assert!(!key.secret_key.fingerprint.is_empty());
    assert!(!key.secret_key.key_id.is_empty());
    assert!(!key.secret_key.keygrip.is_empty());
    assert_eq!(key.subkeys.len(), 1);
    assert!(!key.subkeys[0].key_id.is_empty());
    assert!(!key.subkeys[0].keygrip.is_empty());
}

#[test]
fn fingerprint_not_found_error_format() {
    let err = gpg::GpgError::FingerprintNotFound("ABC123".to_string());
    assert_eq!(format!("{}", err), "fingerprint not found in key: ABC123");
}
