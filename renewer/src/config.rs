//! Account configuration, loaded from environment variables (GitHub Secrets).
//!
//! Two layouts are supported:
//!
//! 1. `KATABUMP_ACCOUNTS` – a JSON array, one entry per account, each with
//!    any number of servers (`servers` is optional, see below):
//!
//!    ```json
//!    [
//!      { "email": "a@example.com", "password": "pass-a", "servers": ["id1", "id2"] },
//!      { "email": "b@example.com", "password": "pass-b", "servers": ["id3"] }
//!    ]
//!    ```
//!
//! 2. Single-account mode: `KATABUMP_EMAIL` and `KATABUMP_PASSWORD`.
//!
//! Server ids: an account without its own `servers` list uses `SERVER_ID`
//! (comma-separated for several). If that is unset too, the bot finds the
//! servers on the dashboard by itself.

use std::env;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Account {
    pub email: String,
    pub password: String,
    #[serde(default, alias = "server_ids")]
    pub servers: Vec<String>,
}

impl Account {
    /// Secrets are often pasted with a trailing space or line break.
    fn normalize(&mut self) {
        self.email = self.email.trim().to_owned();
        self.password = self
            .password
            .trim_end_matches(|c: char| c == '\r' || c == '\n')
            .to_owned();
    }

    fn validate(&self, index: usize) -> Result<()> {
        if self.email.trim().is_empty() || self.password.is_empty() {
            bail!("account #{index}: email and password must not be empty");
        }
        Ok(())
    }
}

/// Reads an environment variable, treating empty values as missing.
fn var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Server ids from `SERVER_ID`. Empty means "discover them on the dashboard".
fn default_servers() -> Vec<String> {
    var("SERVER_ID")
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

pub fn load_accounts() -> Result<Vec<Account>> {
    let mut accounts = match var("KATABUMP_ACCOUNTS") {
        Some(raw) => serde_json::from_str::<Vec<Account>>(&raw)
            .context("KATABUMP_ACCOUNTS is not valid JSON")?,
        None => vec![legacy_account()?],
    };

    if accounts.is_empty() {
        bail!("no accounts configured");
    }
    for (i, account) in accounts.iter_mut().enumerate() {
        account.normalize();
        account.validate(i + 1)?;
        if account.servers.iter().all(|s| s.trim().is_empty()) {
            account.servers = default_servers();
        }
    }
    Ok(accounts)
}

fn legacy_account() -> Result<Account> {
    let (Some(email), Some(password)) = (var("KATABUMP_EMAIL"), var("KATABUMP_PASSWORD")) else {
        bail!(
            "no credentials found: set KATABUMP_ACCOUNTS, or \
             KATABUMP_EMAIL + KATABUMP_PASSWORD"
        );
    };

    Ok(Account {
        email,
        password,
        servers: default_servers(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_cleaned() {
        let mut a = Account {
            email: " a@b.c\n".to_owned(),
            password: "pw \r\n".to_owned(),
            servers: vec![],
        };
        a.normalize();
        assert_eq!(a.email, "a@b.c");
        assert_eq!(a.password, "pw ");
    }

    #[test]
    fn server_defaults_and_overrides() {
        std::env::remove_var("SERVER_ID");
        std::env::set_var(
            "KATABUMP_ACCOUNTS",
            r#"[
            {"email":"a@b.c","password":"x"},
            {"email":"d@e.f","password":"y","servers":["s1","s2"]}
        ]"#,
        );
        let a = load_accounts().unwrap();
        assert!(a[0].servers.is_empty());
        assert_eq!(a[1].servers, vec!["s1", "s2"]);

        std::env::set_var("SERVER_ID", "z1, z2");
        let a = load_accounts().unwrap();
        assert_eq!(a[0].servers, vec!["z1", "z2"]);
        assert_eq!(a[1].servers, vec!["s1", "s2"]);

        std::env::remove_var("KATABUMP_ACCOUNTS");
        std::env::set_var("KATABUMP_EMAIL", "a@b.c");
        std::env::set_var("KATABUMP_PASSWORD", "x");
        std::env::remove_var("SERVER_ID");
        assert!(load_accounts().unwrap()[0].servers.is_empty());
    }
}
