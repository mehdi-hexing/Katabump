# Xray-Sing for Katabump

Everything you need to run a free proxy server on **Katabump** and keep it alive, in one repository:

| Folder | What it does |
|---|---|
| [`server/`](server) | **Xray-Sing**, the proxy server (Node.js). Upload it to your Katabump server. |
| [`renewer/`](renewer) | **Auto-renew bot** (Rust). Runs on GitHub Actions and clicks "Renew" for you, so the server never expires. |

**Full step-by-step guide with screenshots:**
[English](https://mehdi-hexing.github.io/mehdi-hexing/en/topics/KataBumpConfigSetup) · [فارسی](https://mehdi-hexing.github.io/mehdi-hexing/topics/KataBumpConfigSetup)
More guides: <https://mehdi-hexing.github.io/mehdi-hexing/en/>

---

## 1. Server

A proxy server for Node.js hosts that give you only one port, such as the Katabump free plan. It starts everything for you, then prints a web panel address, subscription links and ready-to-use share links in the console.

### Quick start

1. Create an account at [dashboard.katabump.com](https://dashboard.katabump.com) and create a server.
2. *(Optional)* Change any setting you want **before uploading** (see [Changing settings](#changing-settings)).
3. Upload `server/index.js` and `server/package.json` to the server's root folder (`/home/container/`).
4. Start the server and open the console.
5. Wait for the **READY** section. It shows the **panel URL**, a **one-time setup code** (use it to create your panel password), the **subscription URLs** and every **share link**.

The first start downloads the proxy engines, so it takes a little longer than usual.

**Good to know**

- **Renew your server about every 4 days**, or it will be disabled. You can do it by hand from the dashboard, or let the [auto-renew bot](#2-auto-renew-bot) do it.
- The console is cleared after **3 minutes**. All links are also saved to `links.txt` in the data folder.
- Everything is stored in `xray-sing/` next to `index.js` (created automatically). Keep it, so your UUID, paths and keys survive restarts.
- Very small plans can run the main services with a few hundred MB of disk. The Argo tunnel needs roughly 200-300 MB more. If there is not enough space, Argo is skipped and everything else keeps working.

### Changing settings

Every setting has a default inside `index.js`. There are two ways to change one:

1. **Environment variable.** Use this if your host lets you define them.
2. **Edit the file.** Some Katabump plans do not support environment variables. In that case change the default value in the `CONFIG` block near the top of `index.js` **before uploading**.

**Example: turn Argo off on a low-resource plan**

```js
// before
ENABLE_ARGO: !(process.env.ENABLE_ARGO === "0" || process.env.ENABLE_ARGO === "false"),

// after
ENABLE_ARGO: false,
```

**Example: change a default value**

```js
// before
SB_SNI: process.env.SB_SNI || "www.google.com",

// after
SB_SNI: process.env.SB_SNI || "www.example.com",
```

---

### Subscription URLs

Replace `HOST`, `PORT`, `SUB_PATH` and the `TOKEN_...` parts with the values printed in the console (or shown in the panel).

| URL | Content |
|---|---|
| `http://HOST:PORT/SUB_PATH/TOKEN_ALL` | All links (v2rayN, NekoBox, Hiddify, sing-box, Shadowrocket, ...) |
| `http://HOST:PORT/SUB_PATH/TOKEN_SB` | sing-box links only |
| `http://HOST:PORT/SUB_PATH/TOKEN_XRAY` | Xray-core / Argo links only |
| `http://HOST:PORT/SUB_PATH/TOKEN_CLASH` | Clash Meta / Mihomo YAML (add `?download=1` to download it) |

`SUB_PATH` and every `TOKEN_...` are random and saved, so they stay the same after a restart. The panel is at `/panel-login`. Set `SUB_PATH` or `PANEL_PATH` to choose your own.

---

### Settings reference

All settings are optional. Switches accept `0` or `false` to turn a feature off.

#### General

| Variable | Default | Description |
|---|---|---|
| `SB_PORT` / `SERVER_PORT` / `PORT` | `2705` | Public port (checked in this order) |
| `UUID` / `SB_UUID` | random, saved | User ID for the VLESS-based links |
| `NAME` | `vless` | Prefix for node names |
| `SB_DOMAIN` / `DOMAIN` | public IP | Host name used in the links |
| `FILE_PATH` | auto | Data folder |
| `SUB_PATH` | random, saved | Base path of the subscription URLs (each URL also has its own random last part) |
| `PANEL_PATH` | `panel-login` | Path of the web panel |
| `QUIET` | off | `1` = fewer status messages (the final link summary is still printed) |
| `CPU_LIMIT_PERCENT` | off | Limit each engine to this percent of one CPU core |
| `ENABLE_SYSCTL` | off | `1` = try network tuning (needs root) |

#### Hysteria2 / sing-box

| Variable | Default | Description |
|---|---|---|
| `SB_VERSION` | `1.11.15` | sing-box version to download |
| `SB_URL` | GitHub release | Custom download URL for the sing-box archive |
| `SB_NAME` | `HY2` | Node name |
| `SB_SNI` | `www.google.com` | SNI used in the Hysteria2 link |
| `SB_OBFS_PWD` | random, saved | Obfuscation password |
| `SB_MASS_PROXY` | `https://www.gstatic.com` | Fallback site for non-Hysteria2 requests (masquerade) |
| `EXTERNAL_CERT` / `EXTERNAL_KEY` | none | Paths to your own TLS certificate. Without them a self-signed one is created and the links use `insecure=1` |

#### Protocol switches

All switches are on by default.

| Switch | Related settings |
|---|---|
| `ENABLE_HTTPUPGRADE` | `HTTPUPGRADE_PATH`, `HTTPUPGRADE_NAME` |
| `ENABLE_XHTTP` | `XHTTP_PATH`, `XHTTP_MODE`, `XHTTP_NAME` |
| `ENABLE_XHTTP_REALITY` | `XHTTP_REALITY_TARGET`, `XHTTP_REALITY_ENC` (`x25519` or `mlkem`), `XHTTP_REALITY_FP`, `XHTTP_REALITY_PATH`, `XHTTP_REALITY_MODE`, `XHTTP_REALITY_SHORT_ID`, `XHTTP_REALITY_MLDSA`, `XHTTP_REALITY_NAME` |
| `ENABLE_REALITY` | `REALITY_TARGET`, `REALITY_TARGET_PORT`, `REALITY_SHORT_ID`, `REALITY_NAME` |
| `ENABLE_GRPC` | `GRPC_SNI`, `GRPC_SERVICE_NAME`, `GRPC_NAME` |
| `ENABLE_SHADOWTLS_VLESS` | `SHADOWTLS_VLESS_SNI`, `SHADOWTLS_VLESS_PASSWORD`, `SHADOWTLS_VLESS_NAME` |
| `ENABLE_SS` | `SS_METHOD`, `SS_PASSWORD`, `SS_NAME` |
| `ENABLE_SOCKS` | `SOCKS_USER`, `SOCKS_PASS`, `SOCKS_NAME` |
| `ENABLE_HTTP_PROXY` | `HTTP_PROXY_USER`, `HTTP_PROXY_PASS`, `HTTP_PROXY_NAME` |

Internal ports (`SS_PORT`, `SOCKS_PORT`, `REALITY_PORT`, `GRPC_PORT`, ...) are chosen automatically. Set them only if you need fixed values.

#### Cloudflare Argo

| Variable | Default | Description |
|---|---|---|
| `ENABLE_ARGO` | on | `0` or `false` = disable the tunnel |
| `ARGO_DOMAIN` | none | Your tunnel's domain (named tunnel only) |
| `ARGO_AUTH` | none | Tunnel token or JSON credentials (named tunnel). Leave empty for a free quick tunnel |
| `ARGO_PORT` | `8001` | Local port the tunnel forwards to |
| `CFIP` / `CFPORT` | Argo domain / `443` | Address and port written into the Argo link |
| `BOT_URL` | built-in mirror | Custom download URL for the `cloudflared` binary |
| `ARGO_FORCE` | off | `1` = try Argo even when disk space is low |
| `XRAY_URL` / `XRAY_VERSION` | latest | Custom Xray-core download, or a pinned version |

---

### Files in the data folder

| File | Purpose |
|---|---|
| `links.txt` | All share links from the last start |
| `uuid.txt`, `obfs.txt` | Saved UUID and Hysteria2 password |
| `panel_secrets.json` | Saved random paths |
| `reality_keys.json` | Saved REALITY keys |
| `sb/`, `xray/` | Downloaded engines, configs and logs |
| `boot.log` | Argo tunnel log |

Log files above 5 MB are trimmed automatically to protect your disk quota.

---

---

## 2. Auto-renew bot

A small Rust program that logs in to the Katabump panel and presses **Renew** for each of your servers. GitHub Actions runs it **every 3 days** (and whenever you start it by hand), so you never have to remember.

### Setup

1. **Fork or push this repository** to your own GitHub account.
2. Go to **Settings → Secrets and variables → Actions → New repository secret**.
3. Create the secret `KATABUMP_ACCOUNTS` and paste a JSON list of your accounts:

   ```json
   [
     { "email": "a@example.com", "password": "pass-a", "servers": ["id1", "id2"] },
     { "email": "b@example.com", "password": "pass-b", "servers": ["id3"] }
   ]
   ```

   - Add as many accounts as you like. Each account can have several servers.
   - A **server ID** is the part after `/server/` in the address of your server's page.
   - `servers` is optional. If you leave it out, the `SERVER_ID` secret is used (several IDs separated by commas), and if that is empty too, the default ID built into `renewer/src/config.rs`.
4. Open the **Actions** tab, choose **Katabump Auto Renew** and click **Run workflow** once to test it. Read the log to confirm it logged in and found the Renew button.

**Only one account?** You can skip the JSON and create these secrets instead: `KATABUMP_EMAIL`, `KATABUMP_PASSWORD` and (optional) `SERVER_ID`.

**Different panel address?** Add an optional secret `KATABUMP_URL`. The default is `https://control.katabump.com`.

### How it behaves

- Every account gets a fresh browser session.
- If one account or server fails, the others still run. At the end the job is marked as failed, so GitHub emails you.
- If the Renew button is not shown, the bot reports "not due yet" and moves on.
- Passwords are never printed. They stay in GitHub Secrets.

### Run it on your own computer

```bash
chromedriver --port=9515 &
export KATABUMP_ACCOUNTS='[{"email":"a@example.com","password":"x","servers":["id1"]}]'
cd renewer && cargo run --release
```

---

## Security notes

- **The panel uses plain HTTP.** Its path (`/panel-login`) is easy to guess, so choose a strong password. The setup code is printed only in the server console.
- **Unpinned Xray-core.** Unless you set `XRAY_VERSION`, the newest release is downloaded on first start.
- **Self-signed certificates.** Hysteria2 and gRPC use one unless you provide `EXTERNAL_CERT` and `EXTERNAL_KEY`.
- **Use it responsibly.** Check Katabump's terms and your local laws before running a proxy server or automating renewals.

---

## Troubleshooting

- **"Argo link not ready" or a low-disk message:** there is not enough free space (about 60 MB or more is needed for `cloudflared`). The other services still work. If you do not need Argo, turn it off (see [Changing settings](#changing-settings)).
- **No links shown:** look for red error lines in the console. Running out of disk space is the most common cause.
- **One service is missing:** the server checks every backend at start-up and disables the ones that did not come up. The console says which one. Restart to try again.
- **Two TLS-based services conflict:** give each one a different SNI (`REALITY_TARGET`, `XHTTP_REALITY_TARGET`, `GRPC_SNI`, `SHADOWTLS_VLESS_SNI`).
- **Server stopped after a few days:** renew it from the dashboard, and check that the auto-renew workflow is running (see below).
- **Auto-renew stopped running:** GitHub pauses scheduled workflows in a public repository after 60 days without any activity. Open the **Actions** tab and re-enable the workflow, or push any small commit.
- **Auto-renew cannot log in:** check the secrets for typos. If the panel shows a captcha or a bot check, automatic login may not work, and you will need to renew by hand.

---

## Credits

Server built on [sing-box](https://github.com/SagerNet/sing-box), [Xray-core](https://github.com/XTLS/Xray-core) and [cloudflared](https://github.com/cloudflare/cloudflared). The renewer uses [thirtyfour](https://github.com/Vrtgs/thirtyfour) for browser control.

## License

ISC. See [`LICENSE`](LICENSE).
