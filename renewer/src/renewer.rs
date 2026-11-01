//! Browser automation: log in to the panel and press "Renew" on a server.

use std::env;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use thirtyfour::prelude::*;

const DEFAULT_BASE_URL: &str = "https://dashboard.katabump.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

const ELEMENT_TIMEOUT: Duration = Duration::from_secs(30);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const SETTLE_DELAY: Duration = Duration::from_secs(3);

const USER_FIELD: &str =
    r#"input[name="username"], input[name="email"], input[type="email"], input[type="text"]"#;
const PASS_FIELD: &str = r#"input[name="password"], input[type="password"]"#;
const SUBMIT_BTN: &str = r#"button[type="submit"], input[type="submit"]"#;

/// Case-insensitive match for a button or link containing "renew".
const RENEW_XPATH: &str = "//*[self::button or self::a]\
    [contains(translate(normalize-space(.), 'RENW', 'renw'), 'renew')]";

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Renewed,
    NotAvailable,
}

/// Panel address without a trailing slash. Override with `KATABUMP_URL`.
fn base_url() -> String {
    env::var("KATABUMP_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_owned())
}

/// Starts a fresh headless Chrome session (clean cookies per account).
pub async fn open_session(webdriver_url: &str) -> Result<WebDriver> {
    let mut caps = DesiredCapabilities::chrome();
    caps.set_headless()?;
    caps.set_no_sandbox()?;
    caps.set_disable_dev_shm_usage()?;
    caps.add_arg("--window-size=1280,720")?;
    caps.add_arg("--disable-blink-features=AutomationControlled")?;
    caps.add_arg(&format!("--user-agent={USER_AGENT}"))?;

    WebDriver::new(webdriver_url, caps)
        .await
        .with_context(|| format!("cannot reach WebDriver at {webdriver_url}"))
}

/// Finds the first element matching `by`, waiting until it is displayed.
async fn wait_for(driver: &WebDriver, by: By) -> Result<WebElement> {
    driver
        .query(by)
        .wait(ELEMENT_TIMEOUT, POLL_INTERVAL)
        .and_displayed()
        .first()
        .await
        .context("element did not appear in time")
}

pub async fn login(driver: &WebDriver, email: &str, password: &str) -> Result<()> {
    driver.goto(format!("{}/auth/login", base_url())).await?;

    let user = wait_for(driver, By::Css(USER_FIELD)).await?;
    let pass = wait_for(driver, By::Css(PASS_FIELD)).await?;
    user.send_keys(email).await?;
    pass.send_keys(password).await?;
    wait_for(driver, By::Css(SUBMIT_BTN)).await?.click().await?;

    // Success means we have left the login page.
    let started = Instant::now();
    while started.elapsed() < LOGIN_TIMEOUT {
        if !driver.current_url().await?.path().contains("/auth/login") {
            return Ok(());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    bail!("still on the login page – check the email/password");
}

pub async fn renew_server(driver: &WebDriver, server_id: &str) -> Result<Outcome> {
    driver
        .goto(format!("{}/server/{server_id}", base_url()))
        .await?;

    let buttons = driver
        .query(By::XPath(RENEW_XPATH))
        .wait(ELEMENT_TIMEOUT, POLL_INTERVAL)
        .and_displayed()
        .first_opt()
        .await?;

    match buttons {
        Some(button) => {
            button.click().await?;
            tokio::time::sleep(SETTLE_DELAY).await;
            Ok(Outcome::Renewed)
        }
        None => Ok(Outcome::NotAvailable),
    }
}
