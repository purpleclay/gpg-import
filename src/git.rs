use anyhow::{Result, bail};
use std::{
    fmt::{self, Display},
    io::ErrorKind,
    process::{Command, Output},
};

/// Git GPG signing configuration that will written to the local
/// .git/config of the repository
#[derive(Debug)]
pub struct SigningConfig {
    /// User name associated with the signing key, maps to user.name
    pub user_name: String,
    /// User email associated with the signing key, maps to user.email
    pub user_email: String,
    /// The shortform ID of the signing key, maps to user.signingKey
    pub key_id: String,
    /// A flag to enable GPG signing of commits, maps to commit.gpgsign
    pub commit_sign: bool,
    /// A flag to enable GPG signing of tags, maps to tag.gpgsign
    pub tag_sign: bool,
    /// A flag to enable GPG signing of pushes, maps to push.gpgsign
    pub push_sign: bool,
}

impl Display for SigningConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "user.name:       {}", self.user_name)?;
        writeln!(f, "user.email:      {}", self.user_email)?;
        writeln!(f, "user.signingKey: {}", self.key_id)?;
        writeln!(f, "commit.gpgsign:  {}", self.commit_sign)?;
        writeln!(f, "tag.gpgsign:     {}", self.tag_sign)?;
        if self.push_sign {
            writeln!(f, "push.gpgsign:    if-asked")?;
        }
        Ok(())
    }
}

/// Runs git pinned to the `C` locale, so its error messages can be matched,
/// and fails with its trimmed stderr if it exits non-zero
fn git(args: &[&str]) -> Result<Output> {
    let output = Command::new("git")
        .args(args)
        .env("LC_ALL", "C")
        .env_remove("LANGUAGE")
        .output()?;
    if !output.status.success() {
        bail!(
            "git {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

/// Determines if the current working directory is within a git repository,
/// searching parent directories. A missing git binary counts as no repository,
/// but any other git failure (e.g. a repository with dubious ownership) is an
/// error rather than a silent skip
pub fn is_repo() -> Result<bool> {
    match git(&["rev-parse", "--git-dir"]) {
        Ok(_) => Ok(true),
        Err(e) if e.to_string().contains("not a git repository") => Ok(false),
        Err(e) => match e.downcast_ref::<std::io::Error>() {
            Some(io) if io.kind() == ErrorKind::NotFound => Ok(false),
            _ => Err(e),
        },
    }
}

/// Configures the current repository to support GPG signing based on
/// the provided config
pub fn configure_signing(cfg: &SigningConfig) -> Result<()> {
    apply_signing_config(&["--local"], cfg)
}

/// Configures GPG signing globally based on the provided config
pub fn configure_signing_global(cfg: &SigningConfig) -> Result<()> {
    apply_signing_config(&["--global"], cfg)
}

fn apply_signing_config(scope: &[&str], cfg: &SigningConfig) -> Result<()> {
    let commit_sign = cfg.commit_sign.to_string();
    let tag_sign = cfg.tag_sign.to_string();
    let mut entries = vec![
        ("user.name", cfg.user_name.as_str()),
        ("user.email", cfg.user_email.as_str()),
        ("user.signingKey", cfg.key_id.as_str()),
        ("commit.gpgsign", commit_sign.as_str()),
        ("tag.gpgsign", tag_sign.as_str()),
    ];
    if cfg.push_sign {
        entries.push(("push.gpgsign", "if-asked"));
    }

    // --end-of-options stops a value such as a name starting with `-` being
    // read as an option
    for (key, value) in entries {
        git(&[&["config"], scope, &["--end-of-options", key, value]].concat())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::Path;
    use tempfile::TempDir;

    fn signing_config(user_name: &str, tag_sign: bool, push_sign: bool) -> SigningConfig {
        SigningConfig {
            user_name: user_name.to_string(),
            user_email: "batman@dc.com".to_string(),
            key_id: "FDEFE8AB8796E127".to_string(),
            commit_sign: true,
            tag_sign,
            push_sign,
        }
    }

    /// Reads a key from a standalone config file, so neither the user's own
    /// config nor this project's checkout can affect the result. Tests that
    /// spawn git are serial with the tests that change the current directory,
    /// as git fails if that directory is deleted while it starts
    fn config_get(file: &Path, key: &str) -> Option<String> {
        let file = file.to_str().unwrap();
        git(&["config", "--file", file, "--get", key])
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    #[test]
    #[serial]
    fn apply_signing_config_sets_git_config() {
        let temp_dir = TempDir::new().unwrap();
        let file = temp_dir.path().join("config");

        let result = apply_signing_config(
            &["--file", file.to_str().unwrap()],
            &signing_config("batman", true, true),
        );
        assert!(
            result.is_ok(),
            "Should configure signing: {:?}",
            result.err()
        );

        assert_eq!(config_get(&file, "user.name").as_deref(), Some("batman"));
        assert_eq!(
            config_get(&file, "user.email").as_deref(),
            Some("batman@dc.com")
        );
        assert_eq!(
            config_get(&file, "user.signingKey").as_deref(),
            Some("FDEFE8AB8796E127")
        );
        assert_eq!(config_get(&file, "commit.gpgsign").as_deref(), Some("true"));
        assert_eq!(config_get(&file, "tag.gpgsign").as_deref(), Some("true"));
        assert_eq!(
            config_get(&file, "push.gpgsign").as_deref(),
            Some("if-asked")
        );
    }

    #[test]
    #[serial]
    fn apply_signing_config_gates_push_gpgsign_on_push_sign() {
        for (tag_sign, push_sign) in [(true, false), (false, true)] {
            let temp_dir = TempDir::new().unwrap();
            let file = temp_dir.path().join("config");

            apply_signing_config(
                &["--file", file.to_str().unwrap()],
                &signing_config("batman", tag_sign, push_sign),
            )
            .unwrap();

            assert_eq!(
                config_get(&file, "push.gpgsign").as_deref(),
                push_sign.then_some("if-asked"),
                "tag_sign={tag_sign} push_sign={push_sign}"
            );
        }
    }

    #[test]
    #[serial]
    fn apply_signing_config_writes_values_starting_with_a_dash() {
        let temp_dir = TempDir::new().unwrap();
        let file = temp_dir.path().join("config");

        let result = apply_signing_config(
            &["--file", file.to_str().unwrap()],
            &signing_config("--batman", true, true),
        );
        assert!(
            result.is_ok(),
            "Should configure signing: {:?}",
            result.err()
        );
        assert_eq!(config_get(&file, "user.name").as_deref(), Some("--batman"));
    }

    #[test]
    fn display_signing_config() {
        let cfg = SigningConfig {
            user_name: "batman".to_string(),
            user_email: "batman@dc.com".to_string(),
            key_id: "FDEFE8AB8796E127".to_string(),
            commit_sign: true,
            tag_sign: true,
            push_sign: true,
        };
        insta::assert_snapshot!(cfg.to_string());
    }

    #[test]
    fn display_signing_config_without_push_sign() {
        let cfg = SigningConfig {
            user_name: "batman".to_string(),
            user_email: "batman@dc.com".to_string(),
            key_id: "FDEFE8AB8796E127".to_string(),
            commit_sign: true,
            tag_sign: true,
            push_sign: false,
        };
        insta::assert_snapshot!(cfg.to_string());
    }
}
