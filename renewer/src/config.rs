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
//! (comma-separated for several), and if that is unset too, the built-in
//! default id below.

use std::env;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Used when neither the account nor the `SERVER_ID` secret names a server.
const DEFAULT_SERVER_ID: &str = "d1712508";

#[derive(Deserialize)]
pub struct Account {
    pub email: String,
    pub password: String,
    #[serde(default, alias = "server_ids")]
    pub servers: Vec<String>,
}

impl Account {
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

/// Server ids from `SERVER_ID`, or the built-in default.
fn default_servers() -> Vec<String> {
    let raw = var("SERVER_ID").unwrap_or_else(|| DEFAULT_SERVER_ID.to_owned());
    raw.split(',').map(|s| s.trim().to_owned()).collect()
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
        assert_eq!(a[0].servers, vec!["d1712508"]);
        assert_eq!(a[1].servers, vec!["s1", "s2"]);

        std::env::set_var("SERVER_ID", "z1, z2");
        let a = load_accounts().unwrap();
        assert_eq!(a[0].servers, vec!["z1", "z2"]);
        assert_eq!(a[1].servers, vec!["s1", "s2"]);

        std::env::remove_var("KATABUMP_ACCOUNTS");
        std::env::set_var("KATABUMP_EMAIL", "a@b.c");
        std::env::set_var("KATABUMP_PASSWORD", "x");
        std::env::remove_var("SERVER_ID");
        assert_eq!(load_accounts().unwrap()[0].servers, vec!["d1712508"]);
    }
}
