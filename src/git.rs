use anyhow::Result;
use git2::{Config, Repository};
use std::fmt::{self, Display};

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

/// Determines if the current working directory is in fact a git repository
pub fn is_repo() -> Option<Repository> {
    Repository::open(".").ok()
}

/// Configures the current repository to support GPG signing based on
/// the provided config
pub fn configure_signing(repo: &Repository, cfg: &SigningConfig) -> Result<()> {
    let mut config = repo.config()?;
    apply_signing_config(&mut config, cfg)
}

/// Configures GPG signing globally based on the provided config
pub fn configure_signing_global(cfg: &SigningConfig) -> Result<()> {
    let mut config = Config::open_default()?;
    apply_signing_config(&mut config, cfg)
}

fn apply_signing_config(config: &mut Config, cfg: &SigningConfig) -> Result<()> {
    config.set_str("user.name", &cfg.user_name)?;
    config.set_str("user.email", &cfg.user_email)?;
    config.set_str("user.signingKey", &cfg.key_id)?;
    config.set_bool("commit.gpgsign", cfg.commit_sign)?;
    config.set_bool("tag.gpgsign", cfg.tag_sign)?;
    if cfg.tag_sign {
        config.set_str("push.gpgsign", "if-asked")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn configure_signing_sets_git_config() {
        let temp_dir = TempDir::new().unwrap();
        let repo = Repository::init(temp_dir.path()).unwrap();

        let cfg = SigningConfig {
            user_name: "batman".to_string(),
            user_email: "batman@dc.com".to_string(),
            key_id: "FDEFE8AB8796E127".to_string(),
            commit_sign: true,
            tag_sign: true,
            push_sign: true,
        };

        let result = configure_signing(&repo, &cfg);
        assert!(result.is_ok(), "Should configure signing");

        let config = repo.config().unwrap();
        assert_eq!(config.get_string("user.name").unwrap(), "batman");
        assert_eq!(config.get_string("user.email").unwrap(), "batman@dc.com");
        assert_eq!(
            config.get_string("user.signingKey").unwrap(),
            "FDEFE8AB8796E127"
        );
        assert!(config.get_bool("commit.gpgsign").unwrap());
        assert!(config.get_bool("tag.gpgsign").unwrap());
        assert_eq!(config.get_string("push.gpgsign").unwrap(), "if-asked");
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
