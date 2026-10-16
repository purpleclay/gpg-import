use serial_test::serial;
use std::io::Write;
use std::process::{Command, Output, Stdio};

mod fixture;
use fixture::GpgTestFixture;

const PASSPHRASE_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testdata/passphrase.base64.key"
);

/// Runs the binary against the fixture's GNUPGHOME (inherited from the
/// process environment), feeding `stdin` to it
fn gpg_import(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_gpg-import"))
        .args(args)
        .args(["--skip-git"])
        .env_remove("GPG_PRIVATE_KEY")
        .env_remove("GPG_PASSPHRASE")
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
