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
//! Cookie login (use this when the login page shows a CAPTCHA): log in once by
//! hand in your own browser, solve the CAPTCHA yourself, then export the panel's
//! cookies and give them to the bot. Per account add `"cookies"` (a JSON array in
//! the format of the "Cookie-Editor" extension, or a `"name=value; name2=value2"`
//! string). In single-account mode use the `KATABUMP_COOKIES` secret. When cookies
//! are present, `email` and `password` become optional.
//!
//! Server ids: an account without its own `servers` list uses `SERVER_ID`
//! (comma-separated for several). If that is unset too, the bot finds the
//! servers on the dashboard by itself.

use std::env;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// One cookie as exported by browser extensions such as Cookie-Editor.
/// Unknown fields (`httpOnly`, `hostOnly`, `session`, ...) are ignored.
#[derive(Deserialize, Clone, Debug)]
pub struct CookieEntry {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub secure: Option<bool>,
    /// Unix time in seconds (Cookie-Editor calls it `expirationDate`).
    #[serde(default, alias = "expirationDate", alias = "expires")]
    pub expiry: Option<f64>,
    #[serde(default, alias = "sameSite")]
    pub same_site: Option<String>,
}

/// Cookies may be given as a JSON array or as a `Cookie:` header string.
#[derive(Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum CookieInput {
    List(Vec<CookieEntry>),
    Header(String),
}

impl CookieInput {
    fn into_entries(self) -> Vec<CookieEntry> {
        match self {
            CookieInput::List(list) => list,
            CookieInput::Header(raw) => parse_cookie_header(&raw),
        }
    }
}

/// "a=1; b=2" -> [a=1, b=2]. Accepts an optional leading "Cookie:".
pub fn parse_cookie_header(raw: &str) -> Vec<CookieEntry> {
    let raw = raw.trim();
    let raw = raw
        .strip_prefix("Cookie:")
        .or_else(|| raw.strip_prefix("cookie:"))
        .unwrap_or(raw);
    raw.split(';')
        .filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some(CookieEntry {
                name: name.to_owned(),
                value: value.trim().to_owned(),
                domain: None,
                path: None,
                secure: None,
                expiry: None,
                same_site: None,
            })
        })
        .collect()
}

#[derive(Deserialize)]
pub struct Account {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub password: String,
    #[serde(default, alias = "server_ids")]
    pub servers: Vec<String>,
    #[serde(default)]
    cookies: Option<CookieInput>,
    /// Filled in by `load_accounts` from `cookies`.
    #[serde(skip)]
    pub cookie_list: Vec<CookieEntry>,
}

impl Account {
    pub fn has_credentials(&self) -> bool {
        !self.email.trim().is_empty() && !self.password.is_empty()
    }
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
        if self.cookie_list.is_empty() && !self.has_credentials() {
            bail!("account #{index}: give either cookies, or both email and password");
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
        if let Some(input) = account.cookies.take() {
            account.cookie_list = input.into_entries();
        }
        account.normalize();
        account.validate(i + 1)?;
        if account.servers.iter().all(|s| s.trim().is_empty()) {
            account.servers = default_servers();
        }
    }
    Ok(accounts)
}

/// `KATABUMP_COOKIES` for single-account mode: JSON array or header string.
fn legacy_cookies() -> Result<Vec<CookieEntry>> {
    let Some(raw) = var("KATABUMP_COOKIES") else {
        return Ok(Vec::new());
    };
    let input = match serde_json::from_str::<CookieInput>(raw.trim()) {
        Ok(CookieInput::Header(h)) => CookieInput::Header(h),
        Ok(list) => list,
        // Not JSON: treat it as a plain "name=value; ..." string.
        Err(_) => CookieInput::Header(raw),
    };
    Ok(input.into_entries())
}

fn legacy_account() -> Result<Account> {
    let cookie_list = legacy_cookies()?;
    let email = var("KATABUMP_EMAIL").unwrap_or_default();
    let password = var("KATABUMP_PASSWORD").unwrap_or_default();
    if cookie_list.is_empty() && (email.is_empty() || password.is_empty()) {
        bail!(
            "no credentials found: set KATABUMP_ACCOUNTS, or KATABUMP_COOKIES, or \
             KATABUMP_EMAIL + KATABUMP_PASSWORD"
        );
    }

    Ok(Account {
        email,
        password,
        servers: default_servers(),
        cookies: None,
        cookie_list,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests change process-wide environment variables, so they run one at a time.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn credentials_are_cleaned() {
        let mut a = Account {
            email: " a@b.c\n".to_owned(),
            password: "pw \r\n".to_owned(),
            servers: vec![],
            cookies: None,
            cookie_list: vec![],
        };
        a.normalize();
        assert_eq!(a.email, "a@b.c");
        assert_eq!(a.password, "pw ");
    }

    #[test]
    fn server_defaults_and_overrides() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

    #[test]
    fn cookie_header_is_parsed() {
        let c = parse_cookie_header("Cookie: a=1; b=x=y ; ;c=");
        assert_eq!(c.len(), 3);
        assert_eq!((c[0].name.as_str(), c[0].value.as_str()), ("a", "1"));
        assert_eq!(c[1].value, "x=y");
        assert_eq!(c[2].value, "");
    }

    #[test]
    fn cookies_replace_credentials() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("SERVER_ID");
        std::env::set_var(
            "KATABUMP_ACCOUNTS",
            r#"[
            {"cookies":[{"name":"s","value":"v","domain":".katabump.com","expirationDate":1893456000.5,"httpOnly":true,"sameSite":"lax"}]},
            {"cookies":"a=1; b=2"},
            {"email":"a@b.c","password":"x"}
        ]"#,
        );
        let a = load_accounts().unwrap();
        assert_eq!(a[0].cookie_list.len(), 1);
        assert_eq!(a[0].cookie_list[0].expiry, Some(1893456000.5));
        assert_eq!(a[1].cookie_list.len(), 2);
        assert!(a[2].cookie_list.is_empty());

        std::env::set_var("KATABUMP_ACCOUNTS", r#"[{"email":"a@b.c"}]"#);
        assert!(load_accounts().is_err());
        std::env::remove_var("KATABUMP_ACCOUNTS");
    }
}
