//! Browser automation: log in to the panel and press "Renew" on a server.

use std::env;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use thirtyfour::prelude::*;

use crate::config::CookieEntry;

const DEFAULT_BASE_URL: &str = "https://dashboard.katabump.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

const ELEMENT_TIMEOUT: Duration = Duration::from_secs(30);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const SETTLE_DELAY: Duration = Duration::from_secs(3);
/// The proof-of-work widget in the Renew dialog may need a while on a slow runner.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(120);
const DIALOG_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Id of the Bootstrap dialog (`<div class="modal fade" id="renew-modal">`) that opens
/// when the Renew button of the server page is pressed.
const RENEW_MODAL_ID: &str = "renew-modal";

/// The real Renew button inside the dialog. Pressing it starts the ALTCHA
/// proof-of-work: the button reads "Verifying... N%", and at 100% the form
/// submits itself and the panel redirects.
const RENEW_SUBMIT: &str = "#renew-modal button[type='submit'], #renew-modal form button";


/// Widgets that would stop a headless browser from logging in.
const CAPTCHA_SEL: &str = r#"iframe[src*="turnstile"], iframe[src*="recaptcha"], iframe[src*="hcaptcha"], .cf-turnstile, .g-recaptcha, .h-captcha"#;

/// The Renew button that opens the dialog (never one inside the dialog itself).
const RENEW_OPEN_XPATH: &str = "//*[self::button or self::a]\
    [@data-bs-target='#renew-modal' or @href='#renew-modal' \
     or contains(translate(normalize-space(.), 'RENW', 'renw'), 'renew')]\
    [not(ancestor::*[@id='renew-modal'])]";

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
    // A Cloudflare cookie (cf_clearance) is tied to the browser that earned it, so
    // KATABUMP_USER_AGENT lets you copy the exact User-Agent of your own browser.
    let user_agent = env::var("KATABUMP_USER_AGENT")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| USER_AGENT.to_owned());
    caps.add_arg(&format!("--user-agent={user_agent}"))?;

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

/// Signs in with cookies exported from the user's own browser (where the user
/// solved the CAPTCHA by hand). No password and no CAPTCHA are involved.
pub async fn login_with_cookies(driver: &WebDriver, cookies: &[CookieEntry]) -> Result<()> {
    // A cookie can only be set while the browser is on its domain.
    driver.goto(format!("{}/auth/login", base_url())).await?;


    let mut added = 0;
    for entry in cookies {
        if try_add_cookie(driver, entry, true).await
            || try_add_cookie(driver, entry, false).await
        {
            added += 1;
        } else {
            // Name only: never print the value.
            eprintln!("  warning: cookie {:?} was rejected by the browser", entry.name);
        }
    }
    if added == 0 {
        bail!("none of the {} cookie(s) could be set in the browser", cookies.len());
    }
    println!("  set {added}/{} cookie(s)", cookies.len());

    driver.goto(format!("{}/dashboard", base_url())).await?;

    let started = Instant::now();
    while started.elapsed() < LOGIN_TIMEOUT {
        let path = driver.current_url().await?.path().to_owned();
        if path.contains("/checkpoint") {
            bail!("the panel asks for a two-factor code, which the bot cannot enter");
        }
        if !path.contains("/auth/login") && driver.title().await.map(|t| !t.contains("Just a moment")).unwrap_or(true) {
            return Ok(());
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    bail!(
        "the cookies were not accepted: they are expired, the session was logged out, or \
         Cloudflare rejected them (cf_clearance is tied to your IP and browser; set the \
         KATABUMP_USER_AGENT secret to your browser's User-Agent, or run the bot from the \
         same network). Export fresh cookies after a new manual login. {}",
        describe_page(driver, true).await
    );
}

/// Adds one cookie. With `with_domain` the exported domain is kept; without it the
/// cookie becomes host-only, which works when the exported domain does not match.
async fn try_add_cookie(driver: &WebDriver, entry: &CookieEntry, with_domain: bool) -> bool {
    let mut cookie = Cookie::new(entry.name.clone(), entry.value.clone());
    cookie.set_path(entry.path.clone().unwrap_or_else(|| "/".to_owned()));
    if with_domain {
        match &entry.domain {
            Some(domain) if !domain.is_empty() => cookie.set_domain(domain.clone()),
            _ => return false, // nothing different to try
        }
    }
    if let Some(secure) = entry.secure {
        cookie.set_secure(secure);
    }
    if let Some(expiry) = entry.expiry {
        cookie.set_expiry(expiry as i64);
    }
    match entry.same_site.as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("strict") => cookie.set_same_site(SameSite::Strict),
        Some("lax") => cookie.set_same_site(SameSite::Lax),
        Some("none") | Some("no_restriction") => cookie.set_same_site(SameSite::None),
        _ => {}
    }
    driver.add_cookie(cookie).await.is_ok()
}

/// "https://host/servers/edit?id=383509" -> "383509"
fn server_id_from_href(href: &str) -> Option<String> {
    let tail = &href[href.find("/servers/edit")?..];
    let rest = &tail[tail.find("id=")? + 3..];
    let id: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
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

async fn find_renew_button(driver: &WebDriver, wait: Duration) -> Result<Option<WebElement>> {
    Ok(driver
        .query(By::XPath(RENEW_OPEN_XPATH))
        .wait(wait, POLL_INTERVAL)
        .and_displayed()
        .first_opt()
        .await?)
}

pub async fn renew_server(driver: &WebDriver, server_id: &str) -> Result<Outcome> {
    let url = format!("{}/servers/edit?id={server_id}", base_url());
    driver.goto(&url).await?;

    let Some(open) = find_renew_button(driver, ELEMENT_TIMEOUT).await? else {
        return Ok(Outcome::NotAvailable);
    };
    open.click().await?;

    // 1) The dialog #renew-modal slides in from the top.
    let modal = driver
        .query(By::Id(RENEW_MODAL_ID))
        .wait(DIALOG_TIMEOUT, POLL_INTERVAL)
        .and_displayed()
        .first_opt()
        .await?;
    if modal.is_none() {
        bail!("the Renew dialog (#{RENEW_MODAL_ID}) did not open: {url}");
    }
    let submit = driver
        .query(By::Css(RENEW_SUBMIT))
        .wait(DIALOG_TIMEOUT, POLL_INTERVAL)
        .and_displayed()
        .first_opt()
        .await?;
    let Some(submit) = submit else {
        bail!("the Renew dialog has no submit button: {url}");
    };
    tokio::time::sleep(Duration::from_secs(1)).await; // let the fade-in finish

    // A page reload (the panel's redirect) wipes this marker, so it tells us when
    // the renewal was submitted, whatever the new address is.
    driver
        .execute("window.__renewMarker = true;", Vec::new())
        .await?;

    // The widget may already be verifying on its own; click only when it is usable.
    if submit.is_enabled().await? {
        submit.click().await?;
    }

    // 2) The widget computes its proof of work inside the browser ("Verifying... N%").
    //    At 100% the page submits the form by itself and redirects.
    let started = Instant::now();
    let mut saw_working = false;
    loop {
        if started.elapsed() > VERIFY_TIMEOUT {
            bail!(
                "the verification in the Renew dialog did not finish within {}s. {}",
                VERIFY_TIMEOUT.as_secs(),
                describe_page(driver, false).await
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;

        // Errors here are normal while the page is navigating; just keep polling.
        if let Ok(ret) = driver
            .execute("return window.__renewMarker === true;", Vec::new())
            .await
        {
            if !ret.json().as_bool().unwrap_or(false) {
                break; // the page was reloaded: the panel redirected us
            }
        }
        match submit.is_enabled().await {
            Ok(false) => saw_working = true,
            Ok(true) if saw_working => bail!(
                "the verification was reset (error or expired) before it reached 100%. \
                 Renew this server by hand: {url}"
            ),
            _ => {}
        }
    }
    tokio::time::sleep(SETTLE_DELAY).await;

    // No page text here: signed-in pages may show personal data and logs can be public.
    println!("    {}", describe_page(driver, false).await);

    // Look again: after a successful renewal the Renew button normally goes away.
    driver.goto(&url).await?;
    if find_renew_button(driver, Duration::from_secs(5))
        .await?
        .is_some()
    {
        println!("    note: the Renew button is still shown, check the server by hand");
    } else {
        println!("    the Renew button is gone (good sign)");
    }
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
        assert_eq!(
            server_id_from_href("/servers/edit?id=d8a9824b"),
            Some("d8a9824b".to_owned())
        );
        assert_eq!(server_id_from_href("/dashboard"), None);
        assert_eq!(server_id_from_href("/servers/edit?id="), None);
    }
}
