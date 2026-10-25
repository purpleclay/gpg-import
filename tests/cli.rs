use serial_test::serial;
use std::io::Write;
use std::process::{Command, Output, Stdio};

mod fixture;
use fixture::GpgTestFixture;

const PASSPHRASE_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testdata/passphrase.base64.key"
);

/// Builds a command for the binary without any GPG_* option variables from
/// the developer's environment, which would otherwise change its behaviour.
/// GNUPGHOME is kept, so the fixture's keyring is still used
fn gpg_import_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gpg-import"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("GPG_") {
            cmd.env_remove(name);
        }
    }
    cmd
}

/// Runs the binary against the fixture's GNUPGHOME (inherited from the
/// process environment), feeding `stdin` to it
fn gpg_import(args: &[&str], stdin: &str) -> Output {
    let mut child = gpg_import_command()
        .args(args)
        .args(["--skip-git"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to run gpg-import");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// The fixture's agent refuses to sign without a cached passphrase, so a
/// successful signature proves gpg-import preset the right one
fn assert_passphrase_preset(fixture: &GpgTestFixture, output: &Output) {
    assert!(
        output.status.success(),
        "gpg-import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed = fixture.create_and_sign_file("batman@dc.com");
    assert!(
        signed.is_ok(),
        "Signing should use the preset passphrase: {:?}",
        signed.err()
    );
}

#[test]
#[serial]
fn passphrase_from_file_with_trailing_newline() {
    let fixture = GpgTestFixture::new().expect("Failed to create GPG test fixture");
    let dir = tempfile::TempDir::new().unwrap();
    let passphrase_file = dir.path().join("passphrase");
    std::fs::write(&passphrase_file, "gotham\n").unwrap();

    let key = format!("@{PASSPHRASE_KEY}");
    let passphrase = format!("@{}", passphrase_file.display());
    let output = gpg_import(&["--key", &key, "--passphrase", &passphrase], "");

    assert_passphrase_preset(&fixture, &output);
}

#[test]
#[serial]
fn passphrase_from_stdin() {
    let fixture = GpgTestFixture::new().expect("Failed to create GPG test fixture");

    let key = format!("@{PASSPHRASE_KEY}");
    let output = gpg_import(&["--key", &key, "--passphrase", "-"], "gotham\n");

    assert_passphrase_preset(&fixture, &output);
}

#[test]
#[serial]
fn key_and_passphrase_cannot_both_read_stdin() {
    let _fixture = GpgTestFixture::new().expect("Failed to create GPG test fixture");

    let output = gpg_import(&["--key", "-", "--passphrase", "-"], "");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--key and --passphrase cannot both read from stdin"),
        "unexpected error: {stderr}"
    );
}

#[test]
#[serial]
fn dry_run_reports_what_would_change() {
    let _fixture = GpgTestFixture::new().expect("Failed to create GPG test fixture");

    // Not through gpg_import, which adds --skip-git. A dry run never writes
    // git config, so --git-global-config is safe here
    let key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/no-passphrase.asc"
    );
    let output = gpg_import_command()
        .args([
            "--dry-run",
            "--git-global-config",
            "--key",
            &format!("@{key}"),
        ])
        .output()
        .expect("Failed to run gpg-import");

    assert!(
        output.status.success(),
        "gpg-import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No changes will be made while running in dry-run mode"),
        "{stdout}"
    );
    assert!(
        stdout.contains("> Git config would be set (global):"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("Verified signing"),
        "A dry run imports nothing, so it can't sign: {stdout}"
    );
}

#[test]
#[serial]
fn import_verifies_the_key_can_sign() {
    let _fixture = GpgTestFixture::new().expect("Failed to create GPG test fixture");

    let key = format!("@{PASSPHRASE_KEY}");
    let output = gpg_import(&["--key", &key, "--passphrase", "-"], "gotham\n");

    assert!(
        output.status.success(),
        "gpg-import failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("> Verified signing:"), "{stdout}");
}

#[test]
#[serial]
fn wrong_passphrase_fails_the_signing_check() {
    let _fixture = GpgTestFixture::new().expect("Failed to create GPG test fixture");

    let key = format!("@{PASSPHRASE_KEY}");
    let output = gpg_import(&["--key", &key, "--passphrase", "-"], "joker\n");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("test signature") && stderr.contains("passphrase"),
        "unexpected error: {stderr}"
    );
}

#[test]
#[serial]
fn skip_verify_skips_the_signing_check() {
    let _fixture = GpgTestFixture::new().expect("Failed to create GPG test fixture");

    let key = format!("@{PASSPHRASE_KEY}");
    let output = gpg_import(
        &["--key", &key, "--passphrase", "-", "--skip-verify"],
        "joker\n",
    );

    assert!(
        output.status.success(),
        "--skip-verify should not sign, so a wrong passphrase goes unnoticed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Verified signing"), "{stdout}");
}

#[test]
fn help_does_not_print_secret_env_values() {
    let output = Command::new(env!("CARGO_BIN_EXE_gpg-import"))
        .arg("--help")
        .env("GPG_PRIVATE_KEY", "secret-key-value")
        .env("GPG_PASSPHRASE", "secret-passphrase-value")
        .output()
        .expect("Failed to run gpg-import");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GPG_PRIVATE_KEY"), "{stdout}");
    assert!(!stdout.contains("secret-key-value"), "{stdout}");
    assert!(!stdout.contains("secret-passphrase-value"), "{stdout}");
}

#[test]
fn help_output() {
    // A clean environment, so no GPG_* variable shows up in the snapshot
    let output = Command::new(env!("CARGO_BIN_EXE_gpg-import"))
        .arg("--help")
        .env_clear()
        .output()
        .expect("Failed to run gpg-import");

    assert!(output.status.success());
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stdout));
}
