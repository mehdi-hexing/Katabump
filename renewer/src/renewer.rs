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
/// How long the confirm button may stay disabled (a pending CAPTCHA does that).
const CONFIRM_WAIT: Duration = Duration::from_secs(25);
const DIALOG_TIMEOUT: Duration = Duration::from_secs(8);

const USER_FIELD: &str =
    r#"input[name="username"], input[name="email"], input[type="email"], input[type="text"]"#;
const PASS_FIELD: &str = r#"input[name="password"], input[type="password"]"#;
const SUBMIT_BTN: &str = r#"button[type="submit"], input[type="submit"]"#;

/// The same fields, but only inside the form that holds the password box.
const FORM_USER_XPATH: &str =
    "./ancestor::form//input[@type='email' or @name='email' or @name='username' or @type='text']";
const FORM_SUBMIT_XPATH: &str =
    "./ancestor::form//button[@type='submit'] | ./ancestor::form//input[@type='submit']";

/// Dashboard links that open a server ("See" -> /servers/edit?id=383509).
const SERVER_LINK: &str = r#"a[href*="/servers/edit"]"#;

/// A visible Renew/Confirm button inside an open dialog.
const CONFIRM_XPATH: &str = "//*[contains(@class,'modal')]//button\
    [contains(translate(normalize-space(.), 'RENWCOFIM', 'renwcofim'), 'renew') \
     or contains(translate(normalize-space(.), 'RENWCOFIM', 'renwcofim'), 'confirm')]";

/// Widgets that would stop a headless browser from logging in.
const CAPTCHA_SEL: &str = r#"iframe[src*="turnstile"], iframe[src*="recaptcha"], iframe[src*="hcaptcha"], .cf-turnstile, .g-recaptcha, .h-captcha"#;

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

/// Short description of what the browser is showing. It never contains the
/// email or the password (typed values are not part of the page text).
async fn describe_page(driver: &WebDriver, with_text: bool) -> String {
    let path = driver
        .current_url()
        .await
        .map(|u| u.path().to_owned())
        .unwrap_or_default();
    let title = driver.title().await.unwrap_or_default();
    let body = if with_text {
        match driver
            .execute("return document.body ? document.body.innerText : '';", Vec::new())
            .await
        {
            Ok(ret) => ret.json().as_str().unwrap_or("").to_owned(),
            Err(_) => String::new(),
        }
    } else {
        String::new()
    };
    let text: String = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(400)
        .collect();
    let captcha = has_captcha(driver).await;
    if with_text {
        format!("page: path={path} title={title:?} captcha_widget={captcha} text={text:?}")
    } else {
        format!("page: path={path} title={title:?} captcha_widget={captcha}")
    }
}

async fn has_captcha(driver: &WebDriver) -> bool {
    driver
        .find_all(By::Css(CAPTCHA_SEL))
        .await
        .map(|found| !found.is_empty())
        .unwrap_or(false)
}

pub async fn login(driver: &WebDriver, email: &str, password: &str) -> Result<()> {
    driver.goto(format!("{}/auth/login", base_url())).await?;

    let pass = match wait_for(driver, By::Css(PASS_FIELD)).await {
        Ok(el) => el,
        Err(err) => bail!("{err:#}. {}", describe_page(driver, true).await),
    };
    // Prefer the user field of the same form as the password box.
    let user = match pass.find(By::XPath(FORM_USER_XPATH)).await {
        Ok(el) => el,
        Err(_) => wait_for(driver, By::Css(USER_FIELD)).await?,
    };

    let _ = user.clear().await;
    user.send_keys(email).await?;
    let _ = pass.clear().await;
    pass.send_keys(password).await?;

    // Prefer the submit button of the same form (the page may have others).
    match pass.find(By::XPath(FORM_SUBMIT_XPATH)).await {
        Ok(button) => button.click().await?,
        Err(_) => wait_for(driver, By::Css(SUBMIT_BTN)).await?.click().await?,
    }

    // Success means we have left the login page.
    let started = Instant::now();
    while started.elapsed() < LOGIN_TIMEOUT {
        let path = driver.current_url().await?.path().to_owned();
        if path.contains("/checkpoint") {
            bail!(
                "this account asks for a two-factor code, which the bot cannot enter. \
                 Turn two-factor off for it or use another account"
            );
        }
        if !path.contains("/auth/login") {
            return Ok(());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    if has_captcha(driver).await {
        bail!(
            "the login page shows a CAPTCHA (Cloudflare Turnstile). This bot does not solve \
             captchas, so it cannot log in. {}",
            describe_page(driver, true).await
        );
    }
    bail!(
        "still on the login page after submitting (this does not prove the password is wrong). {}",
        describe_page(driver, true).await
    );
}

/// "https://host/servers/edit?id=383509" -> "383509"
fn server_id_from_href(href: &str) -> Option<String> {
    let tail = &href[href.find("/servers/edit")?..];
    let rest = &tail[tail.find("id=")? + 3..];
    let id: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// Finds the ids of all servers listed on the dashboard (the "See" links).
pub async fn discover_servers(driver: &WebDriver) -> Result<Vec<String>> {
    driver.goto(format!("{}/dashboard", base_url())).await?;

    let started = Instant::now();
    let mut ids: Vec<String> = Vec::new();
    while ids.is_empty() && started.elapsed() < ELEMENT_TIMEOUT {
        for link in driver.find_all(By::Css(SERVER_LINK)).await? {
            if let Some(href) = link.attr("href").await? {
                if let Some(id) = server_id_from_href(&href) {
                    if !ids.contains(&id) {
                        ids.push(id);
                    }
                }
            }
        }
        if ids.is_empty() {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
    Ok(ids)
}

pub async fn renew_server(driver: &WebDriver, server_id: &str) -> Result<Outcome> {
    let url = format!("{}/servers/edit?id={server_id}", base_url());
    driver.goto(&url).await?;

    let button = driver
        .query(By::XPath(RENEW_XPATH))
        .wait(ELEMENT_TIMEOUT, POLL_INTERVAL)
        .and_displayed()
        .first_opt()
        .await?;
    let Some(button) = button else {
        return Ok(Outcome::NotAvailable);
    };
    button.click().await?;
    tokio::time::sleep(SETTLE_DELAY).await;

    // The panel may ask to confirm in a dialog (which can carry a CAPTCHA).
    let confirm = driver
        .query(By::XPath(CONFIRM_XPATH))
        .wait(DIALOG_TIMEOUT, POLL_INTERVAL)
        .and_displayed()
        .first_opt()
        .await?;
    if let Some(confirm) = confirm {
        let started = Instant::now();
        while !confirm.is_enabled().await? {
            if started.elapsed() > CONFIRM_WAIT {
                bail!(
                    "the confirm button stays disabled, which usually means a CAPTCHA is waiting \
                     for a human. Renew this server by hand: {url}"
                );
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        confirm.click().await?;
        tokio::time::sleep(SETTLE_DELAY).await;
    }

    // No page text here: signed-in pages may show personal data and logs can be public.
    println!("    {}", describe_page(driver, false).await);
    Ok(Outcome::Renewed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_ids() {
        assert_eq!(
            server_id_from_href("https://dashboard.katabump.com/servers/edit?id=383509"),
            Some("383509".to_owned())
        );
        assert_eq!(
            server_id_from_href("/servers/edit?id=12&x=1"),
            Some("12".to_owned())
        );
        assert_eq!(server_id_from_href("/dashboard"), None);
        assert_eq!(server_id_from_href("/servers/edit?id="), None);
    }
}
