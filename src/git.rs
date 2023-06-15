use std::fmt::{self, Display};

use git2::{Error, Repository};

#[derive(Debug)]
pub struct SigningConfig {
    pub user_name: String,
    pub user_email: String,
    pub key_id: String,
    pub commit_sign: bool,
    pub tag_sign: bool,
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

pub fn is_repo() -> Option<Repository> {
    return match Repository::open(".") {
        Ok(r) => Some(r),
        Err(_) => None,
    };
}

pub fn configure_signing(repo: &Repository, cfg: &SigningConfig) -> Result<(), Error> {
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
