use gpg_import::{gpg, import::GpgImport};
use serial_test::serial;
use std::{env, path::Path, process::Command};
use tempfile::TempDir;

mod fixture;
use fixture::GpgTestFixture;

/// Temporarily changes the process's current directory, restoring it when
/// dropped. `git::is_repo` resolves the repo from the current directory,
/// so tests that exercise git configuration need to point the process at a
/// throwaway repo instead of this project's own checkout.
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

fn git_init(dir: &Path) {
    let status = Command::new("git")
        .args(["init", "-q"])
        .arg(dir)
        .status()
        .expect("Failed to run git init");
    assert!(status.success(), "Failed to init throwaway git repo");
}

fn git_config_get(dir: &Path, key: &str) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["config", "--local", "--get", key])
        .output()
        .expect("Failed to run git config");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
#[serial]
fn import_resolves_and_signs_with_non_first_subkey_via_fingerprint() {
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

    // Signing-capable subkey deliberately added after an encrypt subkey, so
    // it is not subkeys[0] -- exactly the case resolve_signing_key's
    // matches_subkey fix addresses.
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

    let armored = fixture.export_protected_secret_key(&fingerprint, passphrase);
    assert!(armored.is_ok(), "Failed to export multi-subkey GPG key");
    let armored = armored.unwrap();

    // export_protected_secret_key authenticated with the real passphrase
    // above; kill the agent so any residual cache from that setup can't make
    // the signing assertion below pass regardless of whether
    // GpgImport::import()'s own passphrase-preset step actually works.
    assert!(fixture.kill_agent().is_ok(), "Failed to kill gpg-agent");

    let key_info = gpg::extract_key_info(&fingerprint);
    assert!(key_info.is_ok(), "Failed to extract key info");
    let key_info = key_info.unwrap();
    assert_eq!(key_info.subkeys.len(), 2, "Expected 2 subkeys");
    assert!(
        key_info.subkeys[1].capabilities.sign,
        "The non-first subkey should be the signing-capable one"
    );
    let signing_subkey_fingerprint = key_info.subkeys[1].fingerprint.clone();

    // Run GpgImport::import() against a throwaway repo (never the real
    // project checkout), selecting the non-first subkey by fingerprint --
    // the CLI --fingerprint path affected by the resolve_signing_key bug.
    let repo_dir = TempDir::new().unwrap();
    git_init(repo_dir.path());
    let _cwd_guard =
        CwdGuard::change_to(repo_dir.path()).expect("Failed to change into throwaway repo");

    let result = GpgImport::new(armored)
        .with_passphrase(Some(passphrase.to_string()))
        .with_fingerprint(Some(signing_subkey_fingerprint.clone()))
        .import();

    assert!(
        result.is_ok(),
        "GpgImport::import() should resolve a non-first subkey fingerprint, not error: {:?}",
        result.err()
    );

    let signing_key = git_config_get(repo_dir.path(), "user.signingKey");
    assert_eq!(
        signing_key,
        format!("{signing_subkey_fingerprint}!"),
        "git should be configured to sign with the requested non-first subkey"
    );

    let sign_result = fixture.create_and_sign_file(&signing_subkey_fingerprint);
    assert!(
        sign_result.is_ok(),
        "The selected non-first subkey should sign without a passphrase prompt: {:?}",
        sign_result.err()
    );
}

#[test]
#[serial]
fn import_pins_selected_older_signing_subkey() {
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

    let fingerprint = fixture.batch_generate_key_on(batch_config, "2024-01-01");
    assert!(fingerprint.is_ok(), "Failed to generate primary key");
    let fingerprint = fingerprint.unwrap();

    // Distinct creation dates, so GPG's default choice (the newest signing
    // subkey) differs from the older one selected below.
    for date in ["2024-01-02", "2024-01-03"] {
        assert!(
            fixture.add_subkey_on(&fingerprint, "sign", date).is_ok(),
            "Failed to add sign subkey on {date}"
        );
    }

    let armored = fixture.export_secret_key(&fingerprint);
    assert!(armored.is_ok(), "Failed to export multi-subkey GPG key");
    let armored = armored.unwrap();

    let key_info = gpg::extract_key_info(&fingerprint);
    assert!(key_info.is_ok(), "Failed to extract key info");
    let key_info = key_info.unwrap();
    assert_eq!(key_info.subkeys.len(), 2, "Expected 2 subkeys");
    let older_subkey_fingerprint = key_info.subkeys[0].fingerprint.clone();

    let repo_dir = TempDir::new().unwrap();
    git_init(repo_dir.path());
    let _cwd_guard =
        CwdGuard::change_to(repo_dir.path()).expect("Failed to change into throwaway repo");

    let result = GpgImport::new(armored)
        .with_fingerprint(Some(older_subkey_fingerprint.clone()))
        .import();
    assert!(
        result.is_ok(),
        "GpgImport::import() failed: {:?}",
        result.err()
    );

    // Sign through git itself, so the configured user.signingKey is what
    // selects the key. Global and system config are ignored so a developer's
    // own signing settings (e.g. gpg.format=ssh) can't affect the result.
    let git = || {
        let mut cmd = Command::new("git");
        cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1");
        cmd
    };
    let commit = git()
        .args(["commit", "--allow-empty", "-m", "signed"])
        .output()
        .expect("Failed to run git commit");
    assert!(
        commit.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    let log = git()
        .args(["log", "-1", "--format=%GF"])
        .output()
        .expect("Failed to run git log");
    assert_eq!(
        String::from_utf8_lossy(&log.stdout).trim(),
        older_subkey_fingerprint,
        "the commit should be signed by the selected older subkey, not the newest one"
    );
}
