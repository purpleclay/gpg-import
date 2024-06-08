use anyhow::Result;
use git2::Repository;
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
    match Repository::open(".") {
        Ok(r) => Some(r),
        Err(_) => None,
    }
}

/// Configures the current repository to support GPG signing based on
/// the provided config
pub fn configure_signing(repo: &Repository, cfg: &SigningConfig) -> Result<()> {
    let mut config = repo.config()?;

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
