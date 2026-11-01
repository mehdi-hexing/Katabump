mod config;
mod renewer;

use std::env;
use std::process::ExitCode;

use anyhow::Result;

use config::Account;
use renewer::Outcome;

const DEFAULT_WEBDRIVER_URL: &str = "http://localhost:9515";

/// Processes every server of one account. Returns the number of failures.
async fn process_account(webdriver_url: &str, account: &Account) -> Result<usize> {
    let driver = renewer::open_session(webdriver_url).await?;

    let result = async {
        renewer::login(&driver, &account.email, &account.password).await?;
        println!("  logged in");

        let mut servers: Vec<String> = account
            .servers
            .iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        if servers.is_empty() {
            servers = renewer::discover_servers(&driver).await?;
            if servers.is_empty() {
                anyhow::bail!("no servers found on the dashboard");
            }
            println!("  found {} server(s) on the dashboard", servers.len());
        }

        let mut failures = 0;
        for server in servers.iter().map(|s| s.as_str()) {
            match renewer::renew_server(&driver, server).await {
                Ok(Outcome::Renewed) => println!("  [{server}] renewed"),
                Ok(Outcome::NotAvailable) => {
                    println!("  [{server}] no renew button (not due yet?)")
                }
                Err(err) => {
                    eprintln!("  [{server}] failed: {err:#}");
                    failures += 1;
                }
            }
        }
        Ok::<usize, anyhow::Error>(failures)
    }
    .await;

    // Always release the browser, whatever happened above.
    let _ = driver.quit().await;
    result
}

#[tokio::main]
async fn main() -> ExitCode {
    let accounts = match config::load_accounts() {
        Ok(accounts) => accounts,
        Err(err) => {
            eprintln!("configuration error: {err:#}");
            return ExitCode::FAILURE;
        }
    };

    let webdriver_url =
        env::var("WEBDRIVER_URL").unwrap_or_else(|_| DEFAULT_WEBDRIVER_URL.to_owned());

    let mut failures = 0;
    for (index, account) in accounts.iter().enumerate() {
        println!("account {}/{}", index + 1, accounts.len());
        match process_account(&webdriver_url, account).await {
            Ok(count) => failures += count,
            Err(err) => {
                eprintln!("  account failed: {err:#}");
                failures += 1;
            }
        }
    }

    if failures == 0 {
        println!("done");
        ExitCode::SUCCESS
    } else {
        eprintln!("finished with {failures} failure(s)");
        ExitCode::FAILURE
    }
}
