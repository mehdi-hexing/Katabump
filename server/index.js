/* Xray-Sing: a multi-protocol proxy server that serves Hysteria2 (UDP) and many TCP protocols from one public port. */
const express = require("express");
const axios = require("axios");
const os = require("os");
const fs = require("fs");
const path = require("path");
const net = require("net");
const http = require("http");
const crypto = require("crypto");
const zlib = require("zlib");
const { exec, execSync, spawn, spawnSync } = require("child_process");

/* Ask the OS for a free local TCP port instead of hardcoding one. */
function getFreePort() {
    return new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.unref();
        srv.on("error", reject);
        srv.listen(0, "127.0.0.1", () => {
            const { port } = srv.address();
            srv.close(() => resolve(port));
        });
    });
}

/* Check that a local backend port accepts connections. Retries a few times because the backend may still be starting. */
function verifyLocalPort(port, { retries = 8, delayMs = 500, timeoutMs = 800 } = {}) {
    const attempt = () => new Promise((resolve) => {
        const sock = net.connect({ port, host: "127.0.0.1", timeout: timeoutMs });
        sock.once("connect", () => { sock.destroy(); resolve(true); });
        sock.once("timeout", () => { sock.destroy(); resolve(false); });
        sock.once("error", () => resolve(false));
    });

    return (async () => {
        for (let i = 0; i < retries; i++) {
            if (await attempt()) return true;
            await new Promise((r) => setTimeout(r, delayMs));
        }
        return false;
    })();
}

/* Check that every backend port sing-box should be listening on is really reachable. Backends that never come up are disabled for this run. */
async function verifyMuxedBackends() {
    const checks = [
        ["ENABLE_SS", "SS_PORT", "Shadowsocks"],
        ["ENABLE_SOCKS", "SOCKS_PORT", "SOCKS5"],
        ["ENABLE_SHADOWTLS_VLESS", "SHADOWTLS_VLESS_PORT", "ShadowTLS-VLESS"],
        ["ENABLE_REALITY", "REALITY_PORT", "REALITY"],
        ["ENABLE_GRPC", "GRPC_PORT", "VLESS-gRPC"],
        ["ENABLE_HTTP_PROXY", "HTTP_PROXY_PORT", "HTTP-proxy"],
    ];

    for (const [enableKey, portKey, label] of checks) {
        if (!CONFIG[enableKey]) continue;
        const port = CONFIG[portKey];
        const up = await verifyLocalPort(port);
        if (up) {
            Logger.success(`${label} backend confirmed on 127.0.0.1:${port}`);
        } else {
            Logger.warning(`${label} backend never came up on 127.0.0.1:${port} - disabling ${label} for this run so its traffic doesn't get routed nowhere; restart to retry`);
            CONFIG[enableKey] = false;
        }
    }

    for (const d of Extras.active("sb")) {
        const up = await verifyLocalPort(d.port);
        if (up) {
            Logger.success(`${d.label} backend confirmed on 127.0.0.1:${d.port}`);
        } else {
            Logger.warning(`${d.label} backend never came up on 127.0.0.1:${d.port} - disabling it for this run`);
            d.enabled = false;
        }
    }
}

/* Pull the SNI (server_name extension) out of a raw TLS ClientHello. */
function extractSNI(buffer) {
    try {
        if (buffer.length < 6 || buffer[0] !== 0x16 || buffer[1] !== 0x03) return null;
        let pos = 5;
        if (buffer[pos] !== 0x01) return null; // handshake type: ClientHello
        pos += 4;               // handshake header (type + 3-byte length)
        pos += 2;                // client_version
        pos += 32;               // random
        if (pos >= buffer.length) return null;
        const sessionIdLen = buffer[pos]; pos += 1 + sessionIdLen;
        if (pos + 2 > buffer.length) return null;
        const cipherSuitesLen = buffer.readUInt16BE(pos); pos += 2 + cipherSuitesLen;
        if (pos >= buffer.length) return null;
        const compMethodsLen = buffer[pos]; pos += 1 + compMethodsLen;
        if (pos + 2 > buffer.length) return null;
        const extTotalLen = buffer.readUInt16BE(pos); pos += 2;
        const extEnd = Math.min(pos + extTotalLen, buffer.length);
        while (pos + 4 <= extEnd) {
            const extType = buffer.readUInt16BE(pos); pos += 2;
            const extLen = buffer.readUInt16BE(pos); pos += 2;
            if (extType === 0x00) { // server_name
                let p = pos + 2;    // server_name_list length
                if (p + 3 > buffer.length) return null;
                p += 1;              // name_type (0 = host_name)
                const nameLen = buffer.readUInt16BE(p); p += 2;
                if (p + nameLen > buffer.length) return null;
                return buffer.toString("utf8", p, p + nameLen);
            }
            pos += extLen;
        }
        return null;
    } catch {
        return null;
    }
}

// CONFIGURATION
const _publicPort = parseInt(process.env.SB_PORT || process.env.SERVER_PORT || process.env.PORT || "2705", 10);
const _defaultUuid = process.env.UUID || crypto.randomUUID();

/* Pick a writable data directory. FILE_PATH wins if set; otherwise the first usable candidate below is used. */
function resolveDataDir() {
    if (process.env.FILE_PATH) return process.env.FILE_PATH;

    const candidates = [
        "/home/container/xray-sing",      // Katabump project root (persistent disk)
        path.join(__dirname, "xray-sing"), // next to this script, wherever it runs
        path.join(process.cwd(), "xray-sing"), // current working directory fallback
        path.join(os.tmpdir(), "xray-sing"),   // last resort (may be tmpfs/RAM)
    ];

    for (const dir of candidates) {
        try {
            fs.mkdirSync(dir, { recursive: true });
            fs.accessSync(dir, fs.constants.W_OK);
            return dir;
        } catch {
            // try next candidate
        }
    }
    // Nothing was writable (this should not happen), so fall back to the system temp directory anyway.
    return path.join(os.tmpdir(), "xray-sing");
}

const _dataDir = resolveDataDir();

/* Persistent random values (panel path, subscription path, XHTTP-REALITY path).
   Stored next to the other state files so restarts keep the same URLs. */
const Secrets = (() => {
    const file = path.join(_dataDir, "panel_secrets.json");
    let data = {};
    try { data = JSON.parse(fs.readFileSync(file, "utf8")) || {}; } catch { data = {}; }
    const persist = () => {
        try {
            fs.mkdirSync(_dataDir, { recursive: true });
            fs.writeFileSync(file, JSON.stringify(data), { mode: 0o600 });
        } catch { /* ignore */ }
    };
    return {
        get(key, factory) {
            if (typeof data[key] !== "string" || !data[key]) { data[key] = factory(); persist(); }
            return data[key];
        },
        set(key, value) { data[key] = value; persist(); }
    };
})();

/* URL-safe random token (letters, digits, "-" and "_") */
function randomToken(len) {
    return crypto.randomBytes(Math.ceil(len * 3 / 4) + 2).toString("base64")
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "").slice(0, len);
}

const WORDLIST = ["amber", "anchor", "apple", "arctic", "aurora", "autumn", "badger", "bamboo", "beacon", "birch", "breeze", "bronze", "canyon", "cedar", "cherry", "cinder", "clover", "cobalt", "comet", "copper", "coral", "cotton", "crimson", "crystal", "dagger", "delta", "desert", "dolphin", "dragon", "dusk", "eagle", "ember", "falcon", "fern", "fjord", "flint", "forest", "frost", "garnet", "glacier", "granite", "harbor", "hazel", "heron", "indigo", "island", "ivory", "jade", "jasper", "jungle", "kestrel", "lagoon", "lantern", "lava", "lemon", "lilac", "lotus", "lunar", "maple", "marble", "meadow", "mist", "moss", "nectar", "nomad", "oasis", "olive", "onyx", "orchid", "otter", "pearl", "pebble", "pine", "plum", "polar", "quartz", "quill", "raven", "reef", "ridge", "river", "robin", "saffron", "sage", "sandal", "shadow", "silver", "sparrow", "spruce", "summit", "sunset", "thistle", "thunder", "tidal", "tulip", "velvet", "violet", "willow", "winter", "zephyr"];

/* Random words joined with hyphens, e.g. "lunar-river-copper-falcon" */
function randomWords(count) {
    const out = [];
    for (let i = 0; i < count; i++) out.push(WORDLIST[crypto.randomInt(WORDLIST.length)]);
    return out.join("-");
}

const CONFIG = {
    UUID: _defaultUuid,
    FILE_PATH: _dataDir,
    // Subscription URLs live under a random, persisted base path (SUB_PATH). Each URL also has its own random last part (SUB_TOKENS).
    // The panel sits at the fixed, readable path "panel-login" unless PANEL_PATH is set.
    SUB_PATH: process.env.SUB_PATH || Secrets.get("subPath", () => randomToken(24)),
    SUB_PATH_FIXED: !!process.env.SUB_PATH,
    PANEL_PATH: process.env.PANEL_PATH || "panel-login",
    SUB_TOKENS: {
        all: Secrets.get("subTokenAll", () => randomToken(16)),
        sb: Secrets.get("subTokenSb", () => randomToken(16)),
        xray: Secrets.get("subTokenXray", () => randomToken(16)),
        clash: Secrets.get("subTokenClash", () => randomToken(16))
    },
    // VMess cipher written into the share links (the server accepts whatever the client picks)
    VMESS_CIPHER: ["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"].includes((process.env.VMESS_CIPHER || "auto").toLowerCase())
        ? (process.env.VMESS_CIPHER || "auto").toLowerCase() : "auto",
    // ML-DSA-65 on the Xray REALITY inbounds of the VLESS/VMess/Trojan family (the original XHTTP-REALITY keeps XHTTP_REALITY_MLDSA)
    XRAY_REALITY_MLDSA: !(process.env.XRAY_REALITY_MLDSA === "0" || process.env.XRAY_REALITY_MLDSA === "false"),
    TROJAN_PASSWORD: process.env.TROJAN_PASSWORD || Secrets.get("trojanPassword", () => randomToken(24)),
    PORT: _publicPort,
    NAME: process.env.NAME || "vless",

    CFPORT: parseInt(process.env.CFPORT || "443", 10),

    // Argo enabled by default (set ENABLE_ARGO=0 to disable)
    ENABLE_ARGO: !(process.env.ENABLE_ARGO === "0" || process.env.ENABLE_ARGO === "false"),
    ARGO_DOMAIN: process.env.ARGO_DOMAIN || "",
    ARGO_AUTH: process.env.ARGO_AUTH || "",
    ARGO_PORT: parseInt(process.env.ARGO_PORT || "8001", 10),

    // sing-box is pinned to a known-good version so the generated configs always match the binary. Override with SB_VERSION.
    SB_VERSION: process.env.SB_VERSION || "1.11.15",
    SB_NAME: process.env.SB_NAME || "HY2",
    SB_PORT: _publicPort,
    VLESS_LOCAL_PORT: process.env.VLESS_LOCAL_PORT ? parseInt(process.env.VLESS_LOCAL_PORT, 10) : null,
    VLESS_HTTPUPGRADE_LOCAL_PORT: process.env.VLESS_HTTPUPGRADE_LOCAL_PORT ? parseInt(process.env.VLESS_HTTPUPGRADE_LOCAL_PORT, 10) : null,
    SB_UUID: process.env.SB_UUID || _defaultUuid,
    SB_SNI: process.env.SB_SNI || "www.google.com",
    SB_MASS_PROXY: process.env.SB_MASS_PROXY || "https://www.gstatic.com",
    SB_DOMAIN: process.env.SB_DOMAIN || process.env.DOMAIN || "",
    SB_HOST: process.env.SB_HOST || "127.0.0.1",
    // Generated and saved by Application.initialize() when not set.
    SB_OBFS_PWD: process.env.SB_OBFS_PWD || "",

    WS_PATH: process.env.WS_PATH || Secrets.get("wsPath", () => randomWords(4)),
    VLESS_NAME: process.env.VLESS_NAME || "VLESS-WS",

    // VLESS + HTTPUpgrade. It listens on its own local port and shares the public port through the TCP mux.
    ENABLE_HTTPUPGRADE: !(process.env.ENABLE_HTTPUPGRADE === "0" || process.env.ENABLE_HTTPUPGRADE === "false"),
    HTTPUPGRADE_PATH: process.env.HTTPUPGRADE_PATH || `/${Secrets.get("huPath", () => randomWords(4))}`,
    HTTPUPGRADE_NAME: process.env.HTTPUPGRADE_NAME || "VLESS-HTTPUpgrade",
    // The local ports below (VLESS_LOCAL_PORT, SS_PORT, SOCKS_PORT, ...) are picked automatically at startup unless set in the environment.

    // VLESS + XHTTP - needs Xray-core, sing-box doesn't implement it
    ENABLE_XHTTP: !(process.env.ENABLE_XHTTP === "0" || process.env.ENABLE_XHTTP === "false"),
    XRAY_LOCAL_PORT: process.env.XRAY_LOCAL_PORT ? parseInt(process.env.XRAY_LOCAL_PORT, 10) : null,
    XHTTP_PATH: process.env.XHTTP_PATH || `/${Secrets.get("xhttpPath", () => randomWords(4))}`,
    XHTTP_MODE: process.env.XHTTP_MODE || "auto",
    XHTTP_NAME: process.env.XHTTP_NAME || "VLESS-XHTTP",

    // VLESS + XHTTP + REALITY + VLESS Encryption (ML-KEM-768/X25519) + ML-DSA-65.
    // Runs inside Xray-core on its own local port and shares the public port
    // through the SNI mux, so XHTTP_REALITY_TARGET must differ from the other
    // SNIs (REALITY_TARGET, GRPC_SNI, SHADOWTLS_VLESS_SNI).
    ENABLE_XHTTP_REALITY: !(process.env.ENABLE_XHTTP_REALITY === "0" || process.env.ENABLE_XHTTP_REALITY === "false"),
    XHTTP_REALITY_PORT: process.env.XHTTP_REALITY_PORT ? parseInt(process.env.XHTTP_REALITY_PORT, 10) : null,
    XHTTP_REALITY_TARGET: process.env.XHTTP_REALITY_TARGET || "www.apple.com",
    XHTTP_REALITY_TARGET_PORT: parseInt(process.env.XHTTP_REALITY_TARGET_PORT || "443", 10),
    XHTTP_REALITY_SHORT_ID: process.env.XHTTP_REALITY_SHORT_ID || "",
    XHTTP_REALITY_PATH: process.env.XHTTP_REALITY_PATH ||
        `/${Secrets.get("xhttpRealityPath", () => randomWords(Math.min(8, Math.max(2, parseInt(process.env.XHTTP_REALITY_PATH_WORDS || "4", 10) || 4))))}`,
    XHTTP_REALITY_MODE: process.env.XHTTP_REALITY_MODE || "auto",
    XHTTP_REALITY_FP: process.env.XHTTP_REALITY_FP || "chrome",
    XHTTP_REALITY_NAME: process.env.XHTTP_REALITY_NAME || "VLESS-XHTTP-REALITY",
    // "x25519" (classic key exchange) or "mlkem" (post-quantum authentication)
    XHTTP_REALITY_ENC: (process.env.XHTTP_REALITY_ENC || "x25519").toLowerCase(),
    // Optional JSON string that replaces the client-side "extra" block in the link
    XHTTP_REALITY_EXTRA: process.env.XHTTP_REALITY_EXTRA || "",
    // VLESS Encryption tuning (see xtls.github.io -> VLESS inbound "decryption")
    XHTTP_REALITY_ENC_MODE: (process.env.XHTTP_REALITY_ENC_MODE || "native").toLowerCase(), // native | xorpub | random
    XHTTP_REALITY_RTT: (process.env.XHTTP_REALITY_RTT || "0rtt").toLowerCase(),               // client: 0rtt | 1rtt
    XHTTP_REALITY_TICKET: process.env.XHTTP_REALITY_TICKET || "600s",                         // server ticket lifetime: 600s | 300-600s | 0s
    XHTTP_REALITY_PADDING_SERVER: process.env.XHTTP_REALITY_PADDING_SERVER || "",             // e.g. 100-111-1111.75-0-111.50-0-3333
    XHTTP_REALITY_PADDING_CLIENT: process.env.XHTTP_REALITY_PADDING_CLIENT || "",
    // ML-DSA-65 certificate signature (needs a target whose certificate chain is > 3500 bytes)
    XHTTP_REALITY_MLDSA: !(process.env.XHTTP_REALITY_MLDSA === "0" || process.env.XHTTP_REALITY_MLDSA === "false"),
    // Filled at runtime (generated once with the xray binary and persisted)
    XHTTP_REALITY_PRIVATE_KEY: "",
    XHTTP_REALITY_PUBLIC_KEY: "",
    XHTTP_REALITY_MLDSA_SEED: "",
    XHTTP_REALITY_MLDSA_VERIFY: "",
    XHTTP_REALITY_DECRYPTION: "",
    XHTTP_REALITY_ENCRYPTION: "",

    // Shadowsocks (localhost only, reached via the port mux)
    ENABLE_SS: !(process.env.ENABLE_SS === "0" || process.env.ENABLE_SS === "false"),
    SS_PORT: process.env.SS_PORT ? parseInt(process.env.SS_PORT, 10) : null,
    // "aes-256-gcm" accepts any plain-text password. The newer 2022-blake3 methods require a base64 key of a fixed length instead.
    SS_METHOD: process.env.SS_METHOD || "aes-256-gcm",
    SS_PASSWORD: process.env.SS_PASSWORD || _defaultUuid,
    SS_NAME: process.env.SS_NAME || "SS",

    // SOCKS5 (localhost only, reached via the port mux)
    ENABLE_SOCKS: !(process.env.ENABLE_SOCKS === "0" || process.env.ENABLE_SOCKS === "false"),
    SOCKS_PORT: process.env.SOCKS_PORT ? parseInt(process.env.SOCKS_PORT, 10) : null,
    SOCKS_USER: process.env.SOCKS_USER || "",
    SOCKS_PASS: process.env.SOCKS_PASS || "",
    SOCKS_NAME: process.env.SOCKS_NAME || "SOCKS5",

    // VLESS + REALITY. It listens on its own local port; the mux forwards the raw TLS ClientHello to it.
    ENABLE_REALITY: !(process.env.ENABLE_REALITY === "0" || process.env.ENABLE_REALITY === "false"),
    REALITY_PORT: process.env.REALITY_PORT ? parseInt(process.env.REALITY_PORT, 10) : null,
    REALITY_TARGET: process.env.REALITY_TARGET || "www.microsoft.com",
    REALITY_TARGET_PORT: parseInt(process.env.REALITY_TARGET_PORT || "443", 10),
    REALITY_SHORT_ID: process.env.REALITY_SHORT_ID || "",
    REALITY_PRIVATE_KEY: "",
    REALITY_PUBLIC_KEY: "",
    REALITY_NAME: process.env.REALITY_NAME || "VLESS-REALITY",

    // ShadowTLS v3 in front of VLESS (plain ShadowTLS, not combined with any other transport).
    ENABLE_SHADOWTLS_VLESS: !(process.env.ENABLE_SHADOWTLS_VLESS === "0" || process.env.ENABLE_SHADOWTLS_VLESS === "false"),
    SHADOWTLS_VLESS_PORT: process.env.SHADOWTLS_VLESS_PORT ? parseInt(process.env.SHADOWTLS_VLESS_PORT, 10) : null,
    SHADOWTLS_VLESS_SNI: process.env.SHADOWTLS_VLESS_SNI || "www.bing.com",
    SHADOWTLS_VLESS_PASSWORD: process.env.SHADOWTLS_VLESS_PASSWORD || _defaultUuid,
    SHADOWTLS_VLESS_NAME: process.env.SHADOWTLS_VLESS_NAME || "ShadowTLS-VLESS",

    // Plain HTTP proxy using sing-box's native "http" inbound (CONNECT and absolute-form requests, RFC 7231).
    ENABLE_HTTP_PROXY: !(process.env.ENABLE_HTTP_PROXY === "0" || process.env.ENABLE_HTTP_PROXY === "false"),
    HTTP_PROXY_PORT: process.env.HTTP_PROXY_PORT ? parseInt(process.env.HTTP_PROXY_PORT, 10) : null,
    HTTP_PROXY_USER: process.env.HTTP_PROXY_USER || "",
    HTTP_PROXY_PASS: process.env.HTTP_PROXY_PASS || "",
    HTTP_PROXY_NAME: process.env.HTTP_PROXY_NAME || "HTTP",

    // VLESS + gRPC - own local port, TLS terminated by sing-box itself
    ENABLE_GRPC: !(process.env.ENABLE_GRPC === "0" || process.env.ENABLE_GRPC === "false"),
    GRPC_PORT: process.env.GRPC_PORT ? parseInt(process.env.GRPC_PORT, 10) : null,
    GRPC_SNI: process.env.GRPC_SNI || "www.google.com",
    GRPC_SERVICE_NAME: process.env.GRPC_SERVICE_NAME || "grpc",
    GRPC_NAME: process.env.GRPC_NAME || "VLESS-gRPC",

    BOT_URL: process.env.BOT_URL || "",

    // Limit each proxy engine's CPU usage (percent of ONE core). Uses `cpulimit` if installed, otherwise the built-in watchdog.
    CPU_LIMIT_PERCENT: process.env.CPU_LIMIT_PERCENT ? parseInt(process.env.CPU_LIMIT_PERCENT, 10) : null
};

// CONSTANTS
const COLORS = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    dim: '\x1b[2m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m'
};

// SYSTEM VARIABLES
const ARCH = (() => {
    const arch = os.arch();
    return (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') ? 'arm64' : 'amd64';
})();

/* ---------- VMess / Trojan inbounds (mirror of the VLESS set) ----------
   Every one is reachable on the public port (same number Hysteria2 uses over UDP):
   path-routed ones by HTTP path, TLS/REALITY ones by SNI. Toggle with ENABLE_VMESS /
   ENABLE_TROJAN or one flag each, e.g. ENABLE_VMESS_WS=0, ENABLE_TROJAN_REALITY=0.
   Overrides: <PROTO>_<TRANSPORT>_PATH / _SNI / _SERVICE_NAME (dashes become underscores). */
const EXTRA_DEFS = (() => {
    const flag = (name) => {
        const v = process.env[name];
        return v === undefined || v === "" ? true : !(v === "0" || v === "false");
    };
    const master = { vmess: flag("ENABLE_VMESS"), trojan: flag("ENABLE_TROJAN"), vless: true };
    const PROTO_NAME = { vmess: "VMess", trojan: "Trojan", vless: "VLESS" };
    const TITLE = { ws: "WS", httpupgrade: "HTTPUpgrade", xhttp: "XHTTP", grpc: "gRPC", tls: "TLS", reality: "REALITY", "xhttp-reality": "XHTTP-REALITY" };
    const ALPN = { ws: "http/1.1", httpupgrade: "http/1.1", grpc: "h2", tls: "" };
    // [proto, transport, engine, routing, default SNI, optional { id, label }]
    const spec = [
        ["vmess", "ws", "sb", "path"],
        ["vmess", "httpupgrade", "sb", "path"],
        ["vmess", "xhttp", "xray", "path"],
        ["vmess", "grpc", "sb", "sni", "www.yahoo.com"],
        ["vmess", "tls", "sb", "sni", "www.wikipedia.org"],
        ["vmess", "reality", "xray", "sni", "dl.google.com"],
        ["vmess", "xhttp-reality", "xray", "sni", "www.nvidia.com"],
        ["trojan", "ws", "sb", "sni", "www.bbc.com"],
        ["trojan", "httpupgrade", "sb", "sni", "www.reuters.com"],
        ["trojan", "grpc", "sb", "sni", "www.theguardian.com"],
        ["trojan", "tls", "sb", "sni", "www.python.org"],
        ["trojan", "reality", "xray", "sni", "www.amazon.com"],
        ["trojan", "xhttp-reality", "xray", "sni", "addons.mozilla.org"],
        // Plain REALITY over raw TCP on Xray-core: VLESS encryption + ML-DSA-65 like VLESS-XHTTP-REALITY.
        // (The sing-box VLESS-REALITY stays as it is; sing-box has neither feature.)
        ["vless", "reality", "xray", "sni", "www.intel.com", { id: "vless-reality-xr", label: "VLESS-REALITY-Xray" }]
    ];
    return spec.map(([proto, transport, engine, route, defSni, over]) => {
        const id = (over && over.id) || `${proto}-${transport}`;
        const envKey = id.toUpperCase().replace(/-/g, "_");
        const d = {
            id, proto, transport, engine, route,
            enabled: master[proto] && flag(`ENABLE_${envKey}`),
            label: (over && over.label) || `${PROTO_NAME[proto]}-${TITLE[transport]}`,
            port: null,
            links: [],
            name: "",
            host: "",
            alpn: ALPN[transport] || ""
        };
        if (["ws", "httpupgrade", "xhttp", "xhttp-reality"].includes(transport)) {
            const p = process.env[`${envKey}_PATH`] || `/${Secrets.get(`path_${id}`, () => randomWords(4))}`;
            d.path = (p.startsWith("/") ? p : `/${p}`).replace(/\/+$/, "") || "/";
        }
        if (route === "sni") d.sni = (process.env[`${envKey}_SNI`] || defSni).toLowerCase();
        if (transport === "grpc") d.service = process.env[`${envKey}_SERVICE_NAME`] || Secrets.get(`svc_${id}`, () => randomWords(2));
        return d;
    });
})();

const TAR_NAME = `sing-box-${CONFIG.SB_VERSION}-linux-${ARCH}.tar.gz`;
const DOWNLOAD_URL = process.env.SB_URL ||
    `https://github.com/SagerNet/sing-box/releases/download/v${CONFIG.SB_VERSION}/${TAR_NAME}`;

// Xray-core is needed for XHTTP. The same binary is also reused to run the Argo tunnel.
const XRAY_ARCH = ARCH === 'arm64' ? 'arm64-v8a' : '64';
const XRAY_ZIP_NAME = `Xray-linux-${XRAY_ARCH}.zip`;
// No version is pinned by default: "latest/download" always resolves to the newest release. Set XRAY_VERSION or XRAY_URL to override.
const XRAY_DOWNLOAD_URL = process.env.XRAY_URL ||
    (process.env.XRAY_VERSION
        ? `https://github.com/XTLS/Xray-core/releases/download/v${process.env.XRAY_VERSION}/${XRAY_ZIP_NAME}`
        : `https://github.com/XTLS/Xray-core/releases/latest/download/${XRAY_ZIP_NAME}`);

// File paths
const PATHS = {
    SB_BASE_DIR: path.join(CONFIG.FILE_PATH, "sb"),
    SB_CERT_DIR: path.join(CONFIG.FILE_PATH, "sb", "cert"),
    SB_CERT_PATH: path.join(CONFIG.FILE_PATH, "sb", "cert", "cert.pem"),
    SB_KEY_PATH: path.join(CONFIG.FILE_PATH, "sb", "cert", "key.pem"),
    SB_JSON: path.join(CONFIG.FILE_PATH, "sb", "sb.json"),
    SB_BIN: path.join(CONFIG.FILE_PATH, "sb", "sb"),
    SB_LOG_FILE: path.join(CONFIG.FILE_PATH, "sb", "sb.log"),
    X_CONFIG: path.join(CONFIG.FILE_PATH, 'config.json'),
    BOOT_LOG: path.join(CONFIG.FILE_PATH, 'boot.log'),
    XRAY_BASE_DIR: path.join(CONFIG.FILE_PATH, "xray"),
    XRAY_BIN: path.join(CONFIG.FILE_PATH, "xray", "xray"),
    XRAY_JSON: path.join(CONFIG.FILE_PATH, "xray", "xray.json"),
    XRAY_LOG_FILE: path.join(CONFIG.FILE_PATH, "xray", "xray.log")
};

// Global state
const state = {
    xLinks: [],
    sboxLinks: [],          // Hysteria2 links
    vlessWsLinks: [],       // VLESS-WS links (same port as HY2)
    vlessHuLinks: [],       // VLESS-HTTPUpgrade links (same port as HY2)
    vlessXhttpRealityLinks: [], // VLESS-XHTTP-REALITY links (Xray-core, muxed by SNI)
    vlessXhttpLinks: [],    // VLESS-XHTTP links (Xray-core, reverse-proxied)
    ssLinks: [],            // Shadowsocks links (muxed onto the same port)
    socksLinks: [],         // SOCKS5 links (muxed onto the same port)
    realityLinks: [],       // VLESS-REALITY links (muxed onto the same port)
    grpcLinks: [],          // VLESS-gRPC links (muxed onto the same port, self-signed TLS)
    shadowtlsVlessLinks: [],// ShadowTLS-VLESS links (pure ShadowTLS, muxed onto the same port)
    httpProxyLinks: [],     // Plain HTTP proxy links (sing-box http inbound, muxed onto the same port)
    xBase64: "",
    sboxBase64: "",
    vlessWsBase64: "",
    vlessHuBase64: "",
    ssBase64: "",
    sbProcess: null,
    xrayProcess: null,
    xCoreProcess: null,
    cloudflaredProcess: null
};

// LOGGER
class Logger {
    static quiet = process.env.QUIET === "1" || process.env.QUIET === "true";

    static info(message) {
        if (!this.quiet) console.log(`${COLORS.cyan}[i] ${message}${COLORS.reset}`);
    }

    static success(message) {
        if (!this.quiet) console.log(`${COLORS.green}[OK] ${message}${COLORS.reset}`);
    }

    static warning(message) {
        if (!this.quiet) console.log(`${COLORS.yellow}[!] ${message}${COLORS.reset}`);
    }

    static error(message) {
        console.log(`${COLORS.red}[X] ${message}${COLORS.reset}`);
    }

    static step(message) {
        if (!this.quiet) console.log(`${COLORS.blue}-> ${message}${COLORS.reset}`);
    }

    static header(message) {
        if (!this.quiet) {
            console.log(`\n${COLORS.bright}${COLORS.magenta}${"=".repeat(56)}${COLORS.reset}`);
            console.log(`${COLORS.bright}${COLORS.magenta}  ${message}${COLORS.reset}`);
            console.log(`${COLORS.bright}${COLORS.magenta}${"=".repeat(56)}${COLORS.reset}\n`);
        }
    }

    static divider() {
        if (!this.quiet) console.log(`${COLORS.dim}${"-".repeat(56)}${COLORS.reset}`);
    }

    static config(key, value) {
        if (!this.quiet) console.log(`  ${COLORS.cyan}${key}:${COLORS.reset} ${COLORS.yellow}${value}${COLORS.reset}`);
    }

    /* Clear terminal (ANSI + fallback for panel log viewers) */
    static clearConsole() {
        try {
            if (typeof console.clear === "function") console.clear();
        } catch { /* ignore */ }
        try {
            process.stdout.write("\x1B[2J\x1B[3J\x1B[H\x1Bc");
        } catch { /* ignore */ }
        // Panels that ignore ANSI still get a visual break
        console.log("\n".repeat(8));
    }
}

// SYSTEM UTILITIES
class SystemUtils {
    /* Get public IP address synchronously */
    static getPublicIpSync() {
        const ipRegex = /\b((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(?!$)|$)){4}\b/;
        const curlCandidates = [
            "https://ifconfig.co",
            "https://ifconfig.me/ip",
            "https://api.ipify.org",
            "https://ifconfig.io/ip",
        ];

        for (const url of curlCandidates) {
            try {
                const result = spawnSync("curl", ["-sS", url], {
                    encoding: "utf8",
                    timeout: 8000,
                });
                if (result.status === 0 && result.stdout) {
                    const match = result.stdout.trim().match(ipRegex);
                    if (match) return match[0];
                }
            } catch {
                // Continue to next candidate
            }
        }

        try {
            const result = spawnSync("dig", ["+short", "myip.opendns.com", "@resolver1.opendns.com"], {
                encoding: "utf8",
                timeout: 8000,
            });
            if (result.status === 0 && result.stdout) {
                const match = result.stdout.trim().match(ipRegex);
                if (match) return match[0];
            }
        } catch {
            // Fall through
        }

        return null;
    }

    /* Build a short ISP / location label (for example "Hetzner_Germany") that is added to every node name. */
    static async getISPInfo() {
        const sanitize = (s) => String(s || '')
            .replace(/[^\w.\-]+/g, '_')
            .replace(/_+/g, '_')
            .replace(/^_|_$/g, '')
            .slice(0, 48) || 'UNKNOWN';

        // 1) Cloudflare speed meta (JSON)
        try {
            const r = spawnSync('curl', ['-sS', '--max-time', '6', 'https://speed.cloudflare.com/meta'], {
                encoding: 'utf8',
                timeout: 8000
            });
            if (r.status === 0 && r.stdout) {
                const j = JSON.parse(r.stdout);
                // Typical fields: colo, city, clientIp, asOrganization / asn
                const org = j.asOrganization || j.asn || j.clientAsn || '';
                const city = j.city || j.colo || '';
                const label = [org, city].filter(Boolean).join('-');
                if (label) return sanitize(label);
            }
        } catch {
            // continue
        }

        // 2) ipinfo.io
        try {
            const r = spawnSync('curl', ['-sS', '--max-time', '6', 'https://ipinfo.io/json'], {
                encoding: 'utf8',
                timeout: 8000
            });
            if (r.status === 0 && r.stdout) {
                const j = JSON.parse(r.stdout);
                const label = [j.org, j.city || j.country].filter(Boolean).join('-');
                if (label) return sanitize(label);
            }
        } catch {
            // continue
        }

        // 3) ip-api.com
        try {
            const r = spawnSync('curl', ['-sS', '--max-time', '6', 'http://ip-api.com/json/?fields=status,isp,org,as,city,country'], {
                encoding: 'utf8',
                timeout: 8000
            });
            if (r.status === 0 && r.stdout) {
                const j = JSON.parse(r.stdout);
                if (j.status === 'success') {
                    const label = [j.isp || j.org || j.as, j.city || j.country].filter(Boolean).join('-');
                    if (label) return sanitize(label);
                }
            }
        } catch {
            // continue
        }

        return 'UNKNOWN';
    }

    /* Ensure directory exists */
    static ensureDirectory(dirPath) {
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
            Logger.success(`Directory created: ${dirPath}`);
        }
    }

    /* Free disk space in MB on the filesystem that contains dirPath (null if it cannot be determined). */
    static getFreeDiskMB(dirPath) {
        try {
            const result = spawnSync("df", ["-Pk", dirPath], { encoding: "utf8", timeout: 5000 });
            if (result.status !== 0 || !result.stdout) return null;
            const lines = result.stdout.trim().split("\n");
            const fields = lines[lines.length - 1].trim().split(/\s+/);
            const availableKB = parseInt(fields[3], 10);
            if (Number.isNaN(availableKB)) return null;
            return Math.floor(availableKB / 1024);
        } catch {
            return null;
        }
    }

    /* Whether a command exists on PATH (cached - checked often). */
    static commandExists(cmd) {
        if (!this._cmdCache) this._cmdCache = {};
        if (cmd in this._cmdCache) return this._cmdCache[cmd];
        const result = spawnSync("which", [cmd], { timeout: 5000 });
        const exists = result.status === 0;
        this._cmdCache[cmd] = exists;
        return exists;
    }

    /* Wrap a command with `cpulimit` when CPU_LIMIT_PERCENT is set and the tool is installed. Otherwise run it unchanged (the built-in watchdog takes over). */
    static withCpuLimit(binPath, args) {
        if (!CONFIG.CPU_LIMIT_PERCENT) return { command: binPath, args, wrapped: false };
        if (!this.commandExists("cpulimit")) {
            if (!this._cpulimitWarned) {
                this._cpulimitWarned = true;
                Logger.info("cpulimit not installed - using the built-in CPU watchdog (SIGSTOP/SIGCONT) instead, no package install needed.");
            }
            return { command: binPath, args, wrapped: false };
        }
        return { command: "cpulimit", args: ["-l", String(CONFIG.CPU_LIMIT_PERCENT), "--", binPath, ...args], wrapped: true };
    }

    /* Cached CLK_TCK (clock ticks/sec) used to convert /proc/[pid]/stat times to seconds. */
    static getClkTck() {
        if (this._clkTck) return this._clkTck;
        try {
            const r = spawnSync("getconf", ["CLK_TCK"], { encoding: "utf8", timeout: 3000 });
            const v = parseInt((r.stdout || "").trim(), 10);
            this._clkTck = (r.status === 0 && v > 0) ? v : 100;
        } catch {
            this._clkTck = 100; // standard default on Linux
        }
        return this._clkTck;
    }

    /* Total CPU ticks (user + system time) a process has used so far, read from /proc/[pid]/stat. */
    static readProcCpuTicks(pid) {
        try {
            const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
            // The command name (field 2) sits in parentheses and may itself contain spaces or parentheses,
            // so parsing starts after the LAST ")".
            const afterComm = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
            // afterComm[0] is the state (field 3). utime is field 14, so index 11 here; stime is field 15, so index 12.
            const utime = parseInt(afterComm[11], 10);
            const stime = parseInt(afterComm[12], 10);
            if (Number.isNaN(utime) || Number.isNaN(stime)) return null;
            return utime + stime;
        } catch {
            return null;
        }
    }

    static isPidAlive(pid) {
        try {
            process.kill(pid, 0);
            return true;
        } catch {
            return false;
        }
    }

    /* Built-in replacement for `cpulimit`, used on hosts where that binary is not installed.
       It pauses and resumes the process (SIGSTOP / SIGCONT) so its average CPU use stays near the limit. */
    static startCpuWatchdog(pid, label, limitPercent, periodMs = 100) {
        if (!pid || !limitPercent) return null;
        if (!fs.existsSync(`/proc/${pid}/stat`)) {
            Logger.warning(`CPU watchdog: /proc/${pid}/stat not readable - can't cap ${label} on this host`);
            return null;
        }

        const clkTck = this.getClkTck();
        const onMs = periodMs * (limitPercent / 100);
        const offMs = periodMs - onMs;

        try {
            process.kill(pid, "SIGSTOP");
        } catch {
            return null; // already gone
        }

        let stopped = true;
        let cancelled = false;

        (async () => {
            while (!cancelled && this.isPidAlive(pid)) {
                if (stopped) {
                    try { process.kill(pid, "SIGCONT"); } catch { break; }
                    stopped = false;
                }
                const before = this.readProcCpuTicks(pid);
                await new Promise(r => setTimeout(r, onMs));
                if (cancelled || !this.isPidAlive(pid)) break;
                const after = this.readProcCpuTicks(pid);
                if (before === null || after === null) continue;
                const usedOnMs = ((after - before) / clkTck) * 1000;
                if (usedOnMs > onMs * 0.85) {
                    try {
                        process.kill(pid, "SIGSTOP");
                        stopped = true;
                    } catch {
                        break;
                    }
                    await new Promise(r => setTimeout(r, offMs));
                }
            }
        })();

        Logger.info(`CPU watchdog active for ${label}: capped at ${limitPercent}% (throttled from launch)`);
        return { cancel: () => { cancelled = true; try { process.kill(pid, "SIGCONT"); } catch { /* ignore */ } } };
    }

    /* Download a file into the data directory, unless a reasonably sized copy is already there. */
    static downloadFile(fileName, fileUrl) {
        return new Promise((resolve, reject) => {
            const filePath = path.join(CONFIG.FILE_PATH, fileName);

            // Skip download only if a reasonably sized binary already exists
            try {
                const minSize = (fileName === "web" || fileName === "bot") ? 500 * 1024 : 1024;
                if (fs.existsSync(filePath) && fs.statSync(filePath).size >= minSize) {
                    fs.chmodSync(filePath, 0o755);
                    Logger.info(`Already present, skip download: ${fileName}`);
                    return resolve(fileName);
                }
            } catch {
                // continue to download
            }

            const writer = fs.createWriteStream(filePath);

            axios({
                method: 'get',
                url: fileUrl,
                responseType: 'stream',
                timeout: 30000
            })
            .then(response => {
                response.data.pipe(writer);

                writer.on('finish', () => {
                    writer.close();
                    fs.chmodSync(filePath, 0o755);
                    Logger.success(`Downloaded: ${fileName}`);
                    resolve(fileName);
                });

                writer.on('error', err => {
                    fs.unlink(filePath, () => {});
                    if (err.code === 'ENOSPC') {
                        const freeMB = SystemUtils.getFreeDiskMB(CONFIG.FILE_PATH);
                        reject(`Download error ${fileName}: disk is full writing to ${CONFIG.FILE_PATH}` +
                            (freeMB !== null ? ` (~${freeMB}MB free)` : '') +
                            `. Free up space, point FILE_PATH at a volume with more room, or set ENABLE_ARGO=0 / ENABLE_XHTTP=0 to skip binaries you don't need.`);
                        return;
                    }
                    reject(`Download error ${fileName}: ${err.message}`);
                });
            })
            .catch(err => {
                reject(`Download error ${fileName}: ${err.message}`);
            });
        });
    }

    /* Apply system optimizations for better performance */
    static applySystemOptimizations() {
        Logger.step("Applying system optimizations for maximum performance...");

        try {
            const optimizations = [
                // TCP optimizations
                'sysctl -w net.core.rmem_max=268435456',
                'sysctl -w net.core.wmem_max=268435456',
                'sysctl -w net.ipv4.tcp_rmem="4096 87380 268435456"',
                'sysctl -w net.ipv4.tcp_wmem="4096 16384 268435456"',
                'sysctl -w net.core.netdev_max_backlog=100000',
                'sysctl -w net.core.somaxconn=65535',
                'sysctl -w net.ipv4.tcp_max_syn_backlog=65535',

                // BBR congestion control
                'sysctl -w net.ipv4.tcp_congestion_control=bbr',
                'sysctl -w net.ipv4.tcp_fastopen=3',
                'sysctl -w net.core.default_qdisc=fq_codel',

                // File descriptor limits
                'sysctl -w fs.file-max=2097152',
                'sysctl -w fs.nr_open=2097152',

                // Memory optimizations
                'sysctl -w net.ipv4.tcp_mem="786432 2097152 3145728"',
                'sysctl -w net.ipv4.udp_mem="786432 2097152 3145728"',

                // Additional optimizations
                'sysctl -w net.ipv4.tcp_slow_start_after_idle=0',
                'sysctl -w net.ipv4.tcp_tw_reuse=1',
                'sysctl -w net.ipv4.tcp_fin_timeout=30',
                'sysctl -w net.ipv4.tcp_keepalive_time=1200',
                'sysctl -w net.ipv4.tcp_keepalive_intvl=30',
                'sysctl -w net.ipv4.tcp_keepalive_probes=3'
            ];

            let applied = 0;
            for (const cmd of optimizations) {
                try {
                    execSync(cmd, { stdio: 'ignore' });
                    applied++;
                } catch {
                    // Ignore errors if no root privileges
                }
            }

            if (applied > 0) {
                Logger.success(`Applied ${applied} system optimizations`);
            } else {
                Logger.warning("Could not apply system optimizations (root privileges required)");
            }
        } catch (error) {
            Logger.warning("Error applying system optimizations");
        }
    }
}

// SB MANAGER (Hysteria2 + VLESS-WS)
class SbManager {
    /* Get server host (domain, IP, or fallback) */
    static async getServerHost() {
        if (CONFIG.SB_DOMAIN) {
            Logger.info(`Using domain: ${CONFIG.SB_DOMAIN}`);
            return CONFIG.SB_DOMAIN;
        }

        const publicIp = SystemUtils.getPublicIpSync();
        if (publicIp) {
            Logger.info(`Using public IP: ${publicIp}`);
            return publicIp;
        }

        Logger.warning(`Using fallback host: ${CONFIG.SB_HOST}`);
        return CONFIG.SB_HOST;
    }

    /* Ensure TLS certificates exist (used by Hysteria2) */
    static ensureCertificates() {
        SystemUtils.ensureDirectory(PATHS.SB_CERT_DIR);

        // Use external certificates if provided
        if (process.env.EXTERNAL_CERT && process.env.EXTERNAL_KEY &&
            fs.existsSync(process.env.EXTERNAL_CERT) && fs.existsSync(process.env.EXTERNAL_KEY)) {
            Logger.info("Using external TLS certificates");
            return {
                cert: process.env.EXTERNAL_CERT,
                key: process.env.EXTERNAL_KEY
            };
        }

        // Generate self-signed certificates
        if (!fs.existsSync(PATHS.SB_CERT_PATH) || !fs.existsSync(PATHS.SB_KEY_PATH)) {
            Logger.step("Generating self-signed TLS certificate");
            const result = spawnSync("openssl", [
                "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-subj", `/CN=${CONFIG.SB_SNI}`,
                "-keyout", PATHS.SB_KEY_PATH,
                "-out", PATHS.SB_CERT_PATH,
                "-days", "365",
            ]);

            if (result.status !== 0) {
                Logger.error("Failed to generate TLS certificate");
                return { cert: null, key: null };
            }
            Logger.success("TLS certificate generated");
        }

        return { cert: PATHS.SB_CERT_PATH, key: PATHS.SB_KEY_PATH };
    }

    /* Ensure sb binary is downloaded and ready */
    static ensureBinary() {
        if (fs.existsSync(PATHS.SB_BIN)) {
            // A cached binary from an older SB_VERSION may exist. Keep it only when its version matches the expected one.
            const versionCheck = spawnSync(PATHS.SB_BIN, ["version"], { encoding: "utf8", timeout: 10000 });
            const reportedVersion = versionCheck.stdout && versionCheck.stdout.match(/version\s+([0-9][^\s,]*)/i);
            if (versionCheck.status === 0 && reportedVersion && reportedVersion[1] === CONFIG.SB_VERSION) {
                return true;
            }
            Logger.warning(`Cached sb binary is ${reportedVersion ? reportedVersion[1] : "unknown version"}, expected ${CONFIG.SB_VERSION} - re-downloading`);
            try { fs.unlinkSync(PATHS.SB_BIN); } catch { /* ignore */ }
        }

        SystemUtils.ensureDirectory(PATHS.SB_BASE_DIR);
        Logger.step(`Downloading sb (${ARCH})`);

        const freeMB = SystemUtils.getFreeDiskMB(PATHS.SB_BASE_DIR);
        if (freeMB !== null && freeMB < 100) {
            Logger.warning(`Low disk space before downloading sb: ~${freeMB}MB free in ${PATHS.SB_BASE_DIR}. Download may fail with ENOSPC.`);
        }

        const tarPath = path.join(PATHS.SB_BASE_DIR, TAR_NAME);

        // Download sb
        const curlResult = spawnSync("curl", ["-L", "-sS", "-o", tarPath, DOWNLOAD_URL], {
            timeout: 60000
        });

        if (curlResult.status !== 0) {
            Logger.error("Failed to download sb");
            return false;
        }

        // Extract archive
        const tarResult = spawnSync("tar", ["-xzf", tarPath, "-C", PATHS.SB_BASE_DIR]);
        if (tarResult.status !== 0) {
            Logger.error("Failed to extract sb archive");
            return false;
        }

        // Move binary to correct location
        const extractedDir = path.join(PATHS.SB_BASE_DIR, `sing-box-${CONFIG.SB_VERSION}-linux-${ARCH}`);
        if (fs.existsSync(path.join(extractedDir, "sing-box"))) {
            fs.renameSync(path.join(extractedDir, "sing-box"), PATHS.SB_BIN);
            spawnSync("chmod", ["+x", PATHS.SB_BIN]);
            // Free disk: remove archive and extracted folder
            try {
                fs.unlinkSync(tarPath);
                fs.rmSync(extractedDir, { recursive: true, force: true });
            } catch {
                // ignore cleanup errors
            }
            Logger.success("sb installed successfully");
            return true;
        }

        Logger.error("sb binary not found in archive");
        return false;
    }

    /* Create sing-box configuration */
    static writeConfiguration(cert, key) {
        Logger.step("Creating sb configuration (Hysteria2 + VLESS-WS + VMess/Trojan)");

        // Normalize WS path: must start with / for the transport
        const wsPath = CONFIG.WS_PATH.startsWith('/') ? CONFIG.WS_PATH : `/${CONFIG.WS_PATH}`;
        const huPath = CONFIG.HTTPUPGRADE_PATH.startsWith('/') ? CONFIG.HTTPUPGRADE_PATH : `/${CONFIG.HTTPUPGRADE_PATH}`;

        const config = {
            "log": {
                "level": "info",
                "timestamp": true
            },
            "inbounds": [
                // Hysteria2 (UDP / QUIC) on public port
                {
                    "type": "hysteria2",
                    "tag": "hy2-in",
                    "listen": "::",
                    "listen_port": CONFIG.SB_PORT,
                    "users": [
                        {
                            "password": CONFIG.SB_UUID
                        }
                    ],
                    "tls": {
                        "enabled": true,
                        "server_name": CONFIG.SB_SNI,
                        "alpn": ["h3"],
                        "certificate_path": cert,
                        "key_path": key
                    },
                    "obfs": {
                        "type": "salamander",
                        "password": CONFIG.SB_OBFS_PWD
                    },
                    "masquerade": {
                        "type": "proxy",
                        "url": CONFIG.SB_MASS_PROXY,
                        "rewrite_host": true
                    },
                    "ignore_client_bandwidth": false,
                    "up_mbps": 100,
                    "down_mbps": 100
                },
                // VLESS + WebSocket (TCP) on localhost only
                {
                    "type": "vless",
                    "tag": "vless-ws-in",
                    "listen": "127.0.0.1",
                    "listen_port": CONFIG.VLESS_LOCAL_PORT,
                    "users": [
                        {
                            "uuid": CONFIG.SB_UUID,
                            "flow": ""
                        }
                    ],
                    "tls": {
                        "enabled": false
                    },
                    "transport": {
                        "type": "ws",
                        "path": wsPath,
                        "max_early_data": 2560,
                        "early_data_header_name": "Sec-WebSocket-Protocol"
                    }
                },
                // VLESS + HTTPUpgrade (TCP) on localhost only
                ...(CONFIG.ENABLE_HTTPUPGRADE ? [{
                    "type": "vless",
                    "tag": "vless-hu-in",
                    "listen": "127.0.0.1",
                    "listen_port": CONFIG.VLESS_HTTPUPGRADE_LOCAL_PORT,
                    "users": [
                        {
                            "uuid": CONFIG.SB_UUID,
                            "flow": ""
                        }
                    ],
                    "tls": {
                        "enabled": false
                    },
                    "transport": {
                        "type": "httpupgrade",
                        "path": huPath
                    }
                }] : []),
                // Shadowsocks (localhost only, reached through the TCP mux)
                ...(CONFIG.ENABLE_SS ? [{
                    "type": "shadowsocks",
                    "tag": "ss-in",
                    "listen": "127.0.0.1",
                    "listen_port": CONFIG.SS_PORT,
                    "method": CONFIG.SS_METHOD,
                    "password": CONFIG.SS_PASSWORD
                }] : []),
                // SOCKS5 (localhost only, reached through the same TCP mux)
                ...(CONFIG.ENABLE_SOCKS ? [{
                    "type": "socks",
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": CONFIG.SOCKS_PORT,
                    "users": CONFIG.SOCKS_USER
                        ? [{ "username": CONFIG.SOCKS_USER, "password": CONFIG.SOCKS_PASS }]
                        : []
                }] : []),
                // VLESS + REALITY (localhost only, the mux forwards the raw TLS ClientHello here)
                ...(CONFIG.ENABLE_REALITY ? [{
                    "type": "vless",
                    "tag": "vless-reality-in",
                    "listen": "127.0.0.1",
                    "listen_port": CONFIG.REALITY_PORT,
                    "users": [
                        {
                            "uuid": CONFIG.SB_UUID,
                            "flow": "xtls-rprx-vision"
                        }
                    ],
                    "tls": {
                        "enabled": true,
                        "server_name": CONFIG.REALITY_TARGET,
                        "alpn": ["http/1.1"],
                        "reality": {
                            "enabled": true,
                            "handshake": {
                                "server": CONFIG.REALITY_TARGET,
                                "server_port": CONFIG.REALITY_TARGET_PORT
                            },
                            "private_key": CONFIG.REALITY_PRIVATE_KEY,
                            "short_id": [CONFIG.REALITY_SHORT_ID]
                        }
                    }
                }] : []),
                // ShadowTLS v3 + VLESS, plain (localhost only, the mux forwards the raw TLS ClientHello here)
                ...(CONFIG.ENABLE_SHADOWTLS_VLESS ? [
                    {
                        "type": "shadowtls",
                        "tag": "shadowtls-vless-in",
                        "listen": "127.0.0.1",
                        "listen_port": CONFIG.SHADOWTLS_VLESS_PORT,
                        "version": 3,
                        "users": [
                            { "name": CONFIG.SB_UUID, "password": CONFIG.SHADOWTLS_VLESS_PASSWORD }
                        ],
                        "handshake": {
                            "server": CONFIG.SHADOWTLS_VLESS_SNI,
                            "server_port": 443
                        },
                        "strict_mode": true,
                        "detour": "vless-shadowtls-detour-in"
                    },
                    {
                        "type": "vless",
                        "tag": "vless-shadowtls-detour-in",
                        "users": [
                            { "uuid": CONFIG.SB_UUID, "flow": "" }
                        ]
                    }
                ] : []),
                // VLESS + gRPC (localhost only, the mux forwards the raw TLS ClientHello here)
                ...(CONFIG.ENABLE_GRPC ? [{
                    "type": "vless",
                    "tag": "vless-grpc-in",
                    "listen": "127.0.0.1",
                    "listen_port": CONFIG.GRPC_PORT,
                    "users": [
                        {
                            "uuid": CONFIG.SB_UUID,
                            "flow": ""
                        }
                    ],
                    "tls": {
                        "enabled": true,
                        "server_name": CONFIG.GRPC_SNI,
                        "alpn": ["h2"],
                        "certificate_path": cert,
                        "key_path": key
                    },
                    "transport": {
                        "type": "grpc",
                        "service_name": CONFIG.GRPC_SERVICE_NAME
                    }
                }] : []),
                // Plain HTTP proxy (localhost only, sing-box's own "http" inbound reached through the mux)
                ...(CONFIG.ENABLE_HTTP_PROXY ? [{
                    "type": "http",
                    "tag": "http-in",
                    "listen": "127.0.0.1",
                    "listen_port": CONFIG.HTTP_PROXY_PORT,
                    "users": CONFIG.HTTP_PROXY_USER
                        ? [{ "username": CONFIG.HTTP_PROXY_USER, "password": CONFIG.HTTP_PROXY_PASS }]
                        : []
                }] : []),
                // VMess / Trojan inbounds (localhost only, muxed onto the public port)
                ...Extras.sbInbounds(cert, key)
            ],
            "outbounds": [
                {
                    "type": "direct",
                    "tag": "direct"
                },
                {
                    "type": "block",
                    "tag": "block"
                }
            ]
        };

        fs.writeFileSync(PATHS.SB_JSON, JSON.stringify(config, null, 2));
        let sbMsg = `sb config: HY2 UDP :${CONFIG.SB_PORT} + VLESS-WS 127.0.0.1:${CONFIG.VLESS_LOCAL_PORT}`;
        if (CONFIG.ENABLE_HTTPUPGRADE) sbMsg += ` + VLESS-HTTPUpgrade 127.0.0.1:${CONFIG.VLESS_HTTPUPGRADE_LOCAL_PORT}`;
        if (CONFIG.ENABLE_SS) sbMsg += ` + SS :${CONFIG.SS_PORT}`;
        if (CONFIG.ENABLE_SOCKS) sbMsg += ` + SOCKS5 :${CONFIG.SOCKS_PORT}`;
        if (CONFIG.ENABLE_SHADOWTLS_VLESS) sbMsg += ` + ShadowTLS-VLESS 127.0.0.1:${CONFIG.SHADOWTLS_VLESS_PORT}`;
        if (CONFIG.ENABLE_REALITY) sbMsg += ` + VLESS-REALITY 127.0.0.1:${CONFIG.REALITY_PORT}`;
        if (CONFIG.ENABLE_GRPC) sbMsg += ` + VLESS-gRPC 127.0.0.1:${CONFIG.GRPC_PORT}`;
        if (CONFIG.ENABLE_HTTP_PROXY) sbMsg += ` + HTTP 127.0.0.1:${CONFIG.HTTP_PROXY_PORT}`;
        if (Extras.active("sb").length) sbMsg += ` + ${Extras.active("sb").length} VMess/Trojan`;
        Logger.success(sbMsg);
    }

    /* Start sb process */
    static start() {
        Logger.step("Starting sb...");

        if (!fs.existsSync(PATHS.SB_BIN)) {
            Logger.error("sb binary not found");
            return null;
        }

        // Validate configuration first
        const checkResult = spawnSync(PATHS.SB_BIN, ["check", "-c", PATHS.SB_JSON], {
            encoding: 'utf8'
        });

        if (checkResult.status !== 0) {
            Logger.error(`sb configuration error: ${checkResult.stderr}`);
            return null;
        }

        Logger.success("sb configuration validated");

        // Start sb process
        const logFile = fs.openSync(PATHS.SB_LOG_FILE, 'a');
        const { command: sbCommand, args: sbArgs, wrapped: sbWrapped } = SystemUtils.withCpuLimit(PATHS.SB_BIN, ["run", "-c", PATHS.SB_JSON]);
        const child = spawn(sbCommand, sbArgs, {
            stdio: ['ignore', logFile, logFile],
            detached: false,
        });
        if (!sbWrapped && CONFIG.CPU_LIMIT_PERCENT) {
            SystemUtils.startCpuWatchdog(child.pid, "sing-box", CONFIG.CPU_LIMIT_PERCENT);
        }

        // Process event handlers
        child.on("error", (err) => {
            Logger.error(`Failed to start sb: ${err.message}`);
            fs.closeSync(logFile);
        });

        child.on("exit", (code, signal) => {
            fs.closeSync(logFile);
            if (signal) {
                Logger.error(`sb terminated with signal: ${signal}`);
            } else if (code !== 0) {
                Logger.error(`sb exited with code: ${code}`);
            } else {
                Logger.info("sb stopped normally");
            }
        });

        // Verify process started successfully
        setTimeout(() => {
            if (child.exitCode === null) {
                Logger.success("sb started successfully");
            }
        }, 2000);

        return child;
    }

    /* Initialize sb service */
    static async initialize() {
        Logger.header("SB CONFIGURATION");

        // Choose free local ports for the internal-only backends, unless the user already set them in the environment.
        if (CONFIG.VLESS_LOCAL_PORT === null) CONFIG.VLESS_LOCAL_PORT = await getFreePort();
        if (CONFIG.ENABLE_HTTPUPGRADE && CONFIG.VLESS_HTTPUPGRADE_LOCAL_PORT === null) {
            CONFIG.VLESS_HTTPUPGRADE_LOCAL_PORT = await getFreePort();
        }
        if (CONFIG.ENABLE_SS && CONFIG.SS_PORT === null) CONFIG.SS_PORT = await getFreePort();
        if (CONFIG.ENABLE_SOCKS && CONFIG.SOCKS_PORT === null) CONFIG.SOCKS_PORT = await getFreePort();
        if (CONFIG.ENABLE_SHADOWTLS_VLESS && CONFIG.SHADOWTLS_VLESS_PORT === null) CONFIG.SHADOWTLS_VLESS_PORT = await getFreePort();
        if (CONFIG.ENABLE_HTTP_PROXY && CONFIG.HTTP_PROXY_PORT === null) CONFIG.HTTP_PROXY_PORT = await getFreePort();
        if (CONFIG.ENABLE_GRPC && CONFIG.GRPC_PORT === null) CONFIG.GRPC_PORT = await getFreePort();
        // Display configuration
        Logger.config("Node Name", CONFIG.SB_NAME);
        Logger.config("Public port", CONFIG.SB_PORT);
        Logger.config("VLESS local", CONFIG.VLESS_LOCAL_PORT);
        Logger.config("UUID", CONFIG.SB_UUID);
        Logger.config("SNI (HY2)", CONFIG.SB_SNI);
        Logger.config("WS Path", CONFIG.WS_PATH.startsWith('/') ? CONFIG.WS_PATH : `/${CONFIG.WS_PATH}`);
        Logger.config("Domain", CONFIG.SB_DOMAIN || 'Not set');
        Logger.config("Fallback Host", CONFIG.SB_HOST);
        Logger.config("Version", CONFIG.SB_VERSION);
        Logger.config("Architecture", ARCH);

        // Setup certificates
        const certs = this.ensureCertificates();
        if (!certs.cert || !certs.key) {
            Logger.error("Certificate setup failed, skipping sb");
            return null;
        }

        // Download binary
        if (!this.ensureBinary()) {
            Logger.error("Binary download failed, skipping sb");
            return null;
        }

        // REALITY: generate a key pair and short id once and save them (this needs the sing-box binary).
        if (CONFIG.ENABLE_REALITY) {
            const realityKeyFile = path.join(CONFIG.FILE_PATH, "reality_keys.json");
            let keys = null;
            try {
                if (fs.existsSync(realityKeyFile)) {
                    keys = JSON.parse(fs.readFileSync(realityKeyFile, "utf8"));
                }
            } catch {
                keys = null;
            }

            if (!keys || !keys.privateKey || !keys.publicKey) {
                const gen = spawnSync(PATHS.SB_BIN, ["generate", "reality-keypair"], { encoding: "utf8" });
                const privMatch = /PrivateKey:\s*(\S+)/.exec(gen.stdout || "");
                const pubMatch = /PublicKey:\s*(\S+)/.exec(gen.stdout || "");
                if (privMatch && pubMatch) {
                    keys = { privateKey: privMatch[1], publicKey: pubMatch[1] };
                    try { fs.writeFileSync(realityKeyFile, JSON.stringify(keys)); } catch { /* ignore */ }
                } else {
                    Logger.error("Failed to generate REALITY keypair - disabling REALITY");
                    CONFIG.ENABLE_REALITY = false;
                }
            }

            if (keys) {
                CONFIG.REALITY_PRIVATE_KEY = keys.privateKey;
                CONFIG.REALITY_PUBLIC_KEY = keys.publicKey;
            }
        }

        if (CONFIG.ENABLE_REALITY && !CONFIG.REALITY_SHORT_ID) {
            const shortIdFile = path.join(CONFIG.FILE_PATH, "reality_sid.txt");
            try {
                if (fs.existsSync(shortIdFile)) {
                    CONFIG.REALITY_SHORT_ID = fs.readFileSync(shortIdFile, "utf8").trim();
                }
            } catch { /* ignore */ }
            if (!CONFIG.REALITY_SHORT_ID) {
                CONFIG.REALITY_SHORT_ID = crypto.randomBytes(4).toString("hex");
                try { fs.writeFileSync(shortIdFile, CONFIG.REALITY_SHORT_ID); } catch { /* ignore */ }
            }
        }

        if (CONFIG.ENABLE_REALITY && CONFIG.REALITY_PORT === null) {
            CONFIG.REALITY_PORT = await getFreePort();
        }

        // VMess/Trojan: SNI conflict check + local ports (after every other local port is known)
        await Extras.prepare();

        // Create configuration and start
        this.writeConfiguration(certs.cert, certs.key);
        return this.start();
    }

    /* Generate shareable links for both Hysteria2 and VLESS-WS */
    static async generateLinks() {
        const isp = await SystemUtils.getISPInfo();
        const serverHost = await this.getServerHost();
        const insecure = process.env.EXTERNAL_CERT ? "0" : "1";

        // Hysteria2 link
        const hy2Url = `hysteria2://${CONFIG.SB_UUID}@${serverHost}:${CONFIG.SB_PORT}/?sni=${CONFIG.SB_SNI}&obfs=salamander&obfs-password=${CONFIG.SB_OBFS_PWD}&insecure=${insecure}#${CONFIG.SB_NAME}-${isp}`;

        // VLESS-WS link (matches the requested format)
        const wsPathForLink = CONFIG.WS_PATH.startsWith('/') ? CONFIG.WS_PATH.slice(1) : CONFIG.WS_PATH;
        const vlessWsUrl = `vless://${CONFIG.SB_UUID}@${serverHost}:${CONFIG.SB_PORT}?encryption=none&security=none&type=ws&path=${encodeURIComponent(wsPathForLink)}&packetEncoding=xudp#${CONFIG.VLESS_NAME}-${isp}`;

        state.sboxLinks = [hy2Url];
        state.vlessWsLinks = [vlessWsUrl];
        state.sboxBase64 = Buffer.from(hy2Url).toString('base64');
        state.vlessWsBase64 = Buffer.from(vlessWsUrl).toString('base64');

        let vlessHuUrl = null;
        if (CONFIG.ENABLE_HTTPUPGRADE) {
            const huPathForLink = CONFIG.HTTPUPGRADE_PATH.startsWith('/') ? CONFIG.HTTPUPGRADE_PATH.slice(1) : CONFIG.HTTPUPGRADE_PATH;
            vlessHuUrl = `vless://${CONFIG.SB_UUID}@${serverHost}:${CONFIG.SB_PORT}?encryption=none&security=none&type=httpupgrade&path=${encodeURIComponent(huPathForLink)}&packetEncoding=xudp#${CONFIG.HTTPUPGRADE_NAME}-${isp}`;
            state.vlessHuLinks = [vlessHuUrl];
            state.vlessHuBase64 = Buffer.from(vlessHuUrl).toString('base64');
        }

        let ssUrl = null;
        if (CONFIG.ENABLE_SS) {
            // SIP002: ss://base64(method:password)@host:port#name
            const userInfo = Buffer.from(`${CONFIG.SS_METHOD}:${CONFIG.SS_PASSWORD}`).toString('base64');
            ssUrl = `ss://${userInfo}@${serverHost}:${CONFIG.PORT}#${CONFIG.SS_NAME}-${isp}`;
            state.ssLinks = [ssUrl];
            state.ssBase64 = Buffer.from(ssUrl).toString('base64');
        }

        let socksUrl = null;
        if (CONFIG.ENABLE_SOCKS) {
            // SOCKS5 has no official URI standard, so this widely supported form is used: socks5://[user:pass@]host:port
            const auth = CONFIG.SOCKS_USER ? `${CONFIG.SOCKS_USER}:${CONFIG.SOCKS_PASS}@` : '';
            socksUrl = `socks5://${auth}${serverHost}:${CONFIG.PORT}#${CONFIG.SOCKS_NAME}-${isp}`;
            state.socksLinks = [socksUrl];
        }

        // ShadowTLS + VLESS: no single URI scheme can express "wrap protocol X inside ShadowTLS".
        // So a URL-style link is produced together with a sing-box outbound JSON for clients that need the full chain.
        let shadowtlsVlessUrl = null, shadowtlsVlessJson = null;
        if (CONFIG.ENABLE_SHADOWTLS_VLESS) {
            shadowtlsVlessUrl = `vless://${CONFIG.SB_UUID}@${serverHost}:${CONFIG.PORT}?encryption=none&security=none&type=tcp&headerType=none&shadow-tls=1&shadow-tls-sni=${encodeURIComponent(CONFIG.SHADOWTLS_VLESS_SNI)}&shadow-tls-password=${encodeURIComponent(CONFIG.SHADOWTLS_VLESS_PASSWORD)}&shadow-tls-version=3&packetEncoding=xudp#${encodeURIComponent(CONFIG.SHADOWTLS_VLESS_NAME + '-' + isp)}`;
            shadowtlsVlessJson = JSON.stringify({
                type: "vless",
                tag: CONFIG.SHADOWTLS_VLESS_NAME,
                server: serverHost,
                server_port: CONFIG.PORT,
                uuid: CONFIG.SB_UUID,
                flow: "",
                detour: "shadowtls-vless-out",
                _detour_outbound: {
                    type: "shadowtls",
                    tag: "shadowtls-vless-out",
                    server: serverHost,
                    server_port: CONFIG.PORT,
                    version: 3,
                    password: CONFIG.SHADOWTLS_VLESS_PASSWORD,
                    tls: { enabled: true, server_name: CONFIG.SHADOWTLS_VLESS_SNI, utls: { enabled: true, fingerprint: "chrome" } }
                }
            });
            state.shadowtlsVlessLinks = [shadowtlsVlessUrl, shadowtlsVlessJson];
        }

        // Plain HTTP proxy: native sing-box "http" inbound, reached through the mux on the shared public port.
        let httpProxyUrl = null;
        if (CONFIG.ENABLE_HTTP_PROXY) {
            const httpAuth = CONFIG.HTTP_PROXY_USER ? `${encodeURIComponent(CONFIG.HTTP_PROXY_USER)}:${encodeURIComponent(CONFIG.HTTP_PROXY_PASS)}@` : '';
            httpProxyUrl = `http://${httpAuth}${serverHost}:${CONFIG.PORT}#${encodeURIComponent(CONFIG.HTTP_PROXY_NAME + '-' + isp)}`;
            state.httpProxyLinks = [httpProxyUrl];
        }

        // VLESS + REALITY: the mux forwards the raw TLS ClientHello to the REALITY backend.
        let realityUrl = null;
        if (CONFIG.ENABLE_REALITY && CONFIG.REALITY_PUBLIC_KEY) {
            realityUrl = `vless://${CONFIG.SB_UUID}@${serverHost}:${CONFIG.PORT}?encryption=none&security=reality&flow=xtls-rprx-vision&pbk=${CONFIG.REALITY_PUBLIC_KEY}&sid=${CONFIG.REALITY_SHORT_ID}&sni=${CONFIG.REALITY_TARGET}&fp=chrome&alpn=${encodeURIComponent('http/1.1')}&packetEncoding=xudp&type=tcp#${encodeURIComponent(CONFIG.REALITY_NAME + '-' + isp)}`;
            state.realityLinks = [realityUrl];
        }

        // VLESS + gRPC: the mux forwards the raw TLS ClientHello to the gRPC backend.
        let grpcUrl = null;
        if (CONFIG.ENABLE_GRPC) {
            grpcUrl = `vless://${CONFIG.SB_UUID}@${serverHost}:${CONFIG.PORT}?encryption=none&security=tls&sni=${CONFIG.GRPC_SNI}&alpn=${encodeURIComponent('h2')}&fp=chrome&allowInsecure=1&type=grpc&serviceName=${encodeURIComponent(CONFIG.GRPC_SERVICE_NAME)}&mode=gun&packetEncoding=xudp#${encodeURIComponent(CONFIG.GRPC_NAME + '-' + isp)}`;
            state.grpcLinks = [grpcUrl];
        }

        return {
            hy2: hy2Url, vlessWs: vlessWsUrl, vlessHu: vlessHuUrl, ss: ssUrl, socks: socksUrl,
            shadowtlsVless: shadowtlsVlessUrl, httpProxy: httpProxyUrl,
            reality: realityUrl, grpc: grpcUrl
        };
    }
}

// XRAY-CORE MANAGER (XHTTP only)
class XCoreManager {
    /* Pure-JavaScript zip reader, used when none of unzip, bsdtar or python3 is installed on the host. */
    static extractZipEntryPureJS(zipPath, entryName) {
        const buf = fs.readFileSync(zipPath);
        const EOCD_SIG = 0x06054b50;
        let eocdOffset = -1;
        // EOCD is a fixed 22-byte record at (or near) the end of the file;
        for (let i = buf.length - 22; i >= 0; i--) {
            if (buf.readUInt32LE(i) === EOCD_SIG) { eocdOffset = i; break; }
        }
        if (eocdOffset === -1) throw new Error("not a valid zip (EOCD not found)");

        const totalEntries = buf.readUInt16LE(eocdOffset + 10);
        let offset = buf.readUInt32LE(eocdOffset + 16); // central directory start

        for (let i = 0; i < totalEntries; i++) {
            if (buf.readUInt32LE(offset) !== 0x02014b50) throw new Error("malformed central directory");
            const method = buf.readUInt16LE(offset + 10);
            const compSize = buf.readUInt32LE(offset + 20);
            const nameLen = buf.readUInt16LE(offset + 28);
            const extraLen = buf.readUInt16LE(offset + 30);
            const commentLen = buf.readUInt16LE(offset + 32);
            const localHeaderOffset = buf.readUInt32LE(offset + 42);
            const name = buf.toString("utf8", offset + 46, offset + 46 + nameLen);

            if (name === entryName) {
                if (buf.readUInt32LE(localHeaderOffset) !== 0x04034b50) throw new Error("malformed local file header");
                const localNameLen = buf.readUInt16LE(localHeaderOffset + 26);
                const localExtraLen = buf.readUInt16LE(localHeaderOffset + 28);
                const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
                const compData = buf.subarray(dataStart, dataStart + compSize);
                if (method === 0) return compData;           // stored (no compression)
                if (method === 8) return zlib.inflateRawSync(compData); // deflate
                throw new Error(`unsupported zip compression method ${method}`);
            }
            offset += 46 + nameLen + extraLen + commentLen;
        }
        throw new Error(`entry '${entryName}' not found in zip`);
    }

    /* Extract a zip archive with whichever tool is available on this host, falling back to the pure-JS reader. */
    static extractZip(zipPath, destDir) {
        const targetFile = path.join(destDir, "xray");

        const attempts = [
            { cmd: "unzip", args: ["-o", zipPath, "xray", "-d", destDir] },
            { cmd: "bsdtar", args: ["-xf", zipPath, "-C", destDir, "xray"] },
            {
                cmd: "python3",
                args: ["-c", `import zipfile; zipfile.ZipFile(${JSON.stringify(zipPath)}).extract("xray", ${JSON.stringify(destDir)})`]
            }
        ];

        for (const { cmd, args } of attempts) {
            const result = spawnSync(cmd, args);
            if (result.error && result.error.code === "ENOENT") {
                continue; // tool not installed - try the next one
            }
            if (result.status === 0 && fs.existsSync(targetFile)) {
                Logger.info(`Extracted Xray-core with '${cmd}'`);
                return true;
            }
        }

        try {
            const data = this.extractZipEntryPureJS(zipPath, "xray");
            fs.writeFileSync(targetFile, data);
            Logger.info("Extracted Xray-core with built-in zlib (no system tool needed)");
            return true;
        } catch (err) {
            Logger.warning(`Pure-JS zip fallback also failed: ${err.message}`);
        }

        return false;
    }

    /* Download and extract the Xray-core binary (it ships as a zip, unlike sing-box which ships as a tar.gz). */
    static ensureBinary() {
        if (fs.existsSync(PATHS.XRAY_BIN)) {
            return true;
        }

        SystemUtils.ensureDirectory(PATHS.XRAY_BASE_DIR);
        Logger.info(`Downloading Xray-core (${XRAY_ARCH})...`);

        const freeMB = SystemUtils.getFreeDiskMB(PATHS.XRAY_BASE_DIR);
        if (freeMB !== null && freeMB < 100) {
            Logger.warning(`Low disk space before downloading Xray-core: ~${freeMB}MB free in ${PATHS.XRAY_BASE_DIR}. Download may fail with ENOSPC.`);
        }

        const zipPath = path.join(PATHS.XRAY_BASE_DIR, XRAY_ZIP_NAME);
        const dl = spawnSync("curl", ["-L", "-sS", "-o", zipPath, XRAY_DOWNLOAD_URL], { timeout: 60000 });
        if (dl.status !== 0 || !fs.existsSync(zipPath)) {
            Logger.error("Failed to download Xray-core");
            return false;
        }

        if (!this.extractZip(zipPath, PATHS.XRAY_BASE_DIR)) {
            Logger.error("Xray-core extraction failed - none of unzip/bsdtar/python3 worked. Install one of these on the host.");
            return false;
        }

        fs.renameSync(path.join(PATHS.XRAY_BASE_DIR, "xray"), PATHS.XRAY_BIN);
        spawnSync("chmod", ["+x", PATHS.XRAY_BIN]);
        try { fs.unlinkSync(zipPath); } catch { /* ignore cleanup errors */ }
        Housekeeping.pruneXrayExtras();

        Logger.success("Xray-core installed successfully");
        return true;
    }

    /* Write the Xray-core config: a VLESS + XHTTP inbound on 127.0.0.1 plus the other Xray-based inbounds when enabled. */
    static writeConfiguration() {
        const inbounds = [];

        if (CONFIG.ENABLE_XHTTP) {
            const xhttpPath = CONFIG.XHTTP_PATH.startsWith('/') ? CONFIG.XHTTP_PATH : `/${CONFIG.XHTTP_PATH}`;
            inbounds.push({
                "tag": "xhttp-in",
                "listen": "127.0.0.1",
                "port": CONFIG.XRAY_LOCAL_PORT,
                "protocol": "vless",
                "settings": {
                    "clients": [{ "id": CONFIG.SB_UUID, "flow": "" }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {
                        "path": xhttpPath,
                        "mode": CONFIG.XHTTP_MODE
                    }
                }
            });
        }

        if (CONFIG.ENABLE_XHTTP_REALITY) {
            const realityPath = CONFIG.XHTTP_REALITY_PATH.startsWith('/') ? CONFIG.XHTTP_REALITY_PATH : `/${CONFIG.XHTTP_REALITY_PATH}`;
            inbounds.push({
                "tag": "xhttp-reality-in",
                "listen": "127.0.0.1",
                "port": CONFIG.XHTTP_REALITY_PORT,
                "protocol": "vless",
                "settings": {
                    // flow must stay empty when XHTTP is combined with VLESS encryption
                    "clients": [{ "id": CONFIG.SB_UUID, "flow": "" }],
                    "decryption": CONFIG.XHTTP_REALITY_DECRYPTION
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "reality",
                    "realitySettings": {
                        "show": false,
                        "target": `${CONFIG.XHTTP_REALITY_TARGET}:${CONFIG.XHTTP_REALITY_TARGET_PORT}`,
                        "xver": 0,
                        "serverNames": [CONFIG.XHTTP_REALITY_TARGET],
                        "privateKey": CONFIG.XHTTP_REALITY_PRIVATE_KEY,
                        "shortIds": [CONFIG.XHTTP_REALITY_SHORT_ID],
                        ...(CONFIG.XHTTP_REALITY_MLDSA ? { "mldsa65Seed": CONFIG.XHTTP_REALITY_MLDSA_SEED } : {})
                    },
                    "xhttpSettings": {
                        "path": realityPath,
                        "mode": CONFIG.XHTTP_REALITY_MODE
                    }
                }
            });
        }

        Extras.xrayInbounds().forEach((i) => inbounds.push(i));

        const config = {
            "log": { "loglevel": "warning" },
            "inbounds": inbounds,
            "outbounds": [
                { "protocol": "freedom", "tag": "direct" }
            ]
        };

        fs.writeFileSync(PATHS.XRAY_JSON, JSON.stringify(config, null, 2));
        if (CONFIG.ENABLE_XHTTP) Logger.success(`xray config: VLESS-XHTTP 127.0.0.1:${CONFIG.XRAY_LOCAL_PORT}`);
        if (CONFIG.ENABLE_XHTTP_REALITY) Logger.success(`xray config: VLESS-XHTTP-REALITY 127.0.0.1:${CONFIG.XHTTP_REALITY_PORT}`);
        if (Extras.anyXray()) Logger.success(`xray config: ${Extras.active("xray").length} VMess/Trojan inbound(s)`);
    }

    /* Start Xray-core with the config written above. Logs go to xray.log in the data directory. */
    static start() {
        const logFile = fs.openSync(PATHS.XRAY_LOG_FILE, 'a');
        const { command: xrayCommand, args: xrayArgs, wrapped: xrayWrapped } = SystemUtils.withCpuLimit(PATHS.XRAY_BIN, ["run", "-c", PATHS.XRAY_JSON]);
        const child = spawn(xrayCommand, xrayArgs, {
            detached: false,
            stdio: ["ignore", logFile, logFile]
        });
        if (!xrayWrapped && CONFIG.CPU_LIMIT_PERCENT) {
            SystemUtils.startCpuWatchdog(child.pid, "Xray-core (XHTTP)", CONFIG.CPU_LIMIT_PERCENT);
        }

        child.on("error", (err) => Logger.error(`xray-core spawn error: ${err.message}`));
        child.on("exit", (code) => {
            if (code !== 0 && code !== null) {
                Logger.error(`xray-core exited with code ${code} - check ${PATHS.XRAY_LOG_FILE}`);
            }
        });

        return child;
    }

    /* Run an xray CLI subcommand and return stdout, or null on failure. */
    static runXray(args) {
        const r = spawnSync(PATHS.XRAY_BIN, args, { encoding: "utf8", timeout: 20000 });
        if (r.error || r.status !== 0) return null;
        return r.stdout || "";
    }

    /* Generate (once) and persist every secret the XHTTP-REALITY inbound needs:
       REALITY x25519 pair, ML-DSA-65 seed/verify, VLESS encryption pair and a short id. */
    static prepareXhttpRealityKeys() {
        const mode = CONFIG.XHTTP_REALITY_ENC === "mlkem" ? "mlkem" : "x25519";
        const keyFile = path.join(CONFIG.FILE_PATH, "xhttp_reality_keys.json");

        let keys = null;
        try {
            if (fs.existsSync(keyFile)) keys = JSON.parse(fs.readFileSync(keyFile, "utf8"));
        } catch { keys = null; }

        const complete = (k) => k && k.encMode === mode && k.privateKey && k.publicKey &&
            k.mldsaSeed && k.mldsaVerify && k.decryption && k.encryption;

        if (!complete(keys)) {
            Logger.info("Generating XHTTP-REALITY keys (x25519 + ML-DSA-65 + VLESS encryption)...");

            const x = this.runXray(["x25519"]);
            const m = this.runXray(["mldsa65"]);
            const v = this.runXray(["vlessenc"]);
            if (!x || !m || !v) {
                Logger.error("xray key generation failed (needs a recent Xray-core with 'vlessenc' and 'mldsa65')");
                return false;
            }

            const priv = x.match(/Private\s*Key:\s*(\S+)/i);
            const pub = x.match(/(?:Public\s*Key|Password)[^:\n]*:\s*(\S+)/i);
            const seed = m.match(/Seed:\s*(\S+)/i);
            const verify = m.match(/Verify:\s*(\S+)/i);

            const decs = [], encs = [];
            for (const hit of v.matchAll(/(decryption|encryption)"?\s*[:=]\s*"?(mlkem768x25519plus\.[^"\s,]+)/gi)) {
                (hit[1].toLowerCase() === "decryption" ? decs : encs).push(hit[2]);
            }
            const idx = mode === "mlkem" ? 1 : 0;

            if (!priv || !pub || !seed || !verify || !decs[idx] || !encs[idx]) {
                Logger.error("Could not parse xray key output - XHTTP-REALITY disabled");
                return false;
            }

            keys = {
                encMode: mode,
                privateKey: priv[1],
                publicKey: pub[1],
                mldsaSeed: seed[1],
                mldsaVerify: verify[1],
                decryption: decs[idx],
                encryption: encs[idx],
                shortId: crypto.randomBytes(8).toString("hex")
            };
            try { fs.writeFileSync(keyFile, JSON.stringify(keys)); } catch { /* ignore */ }
        }

        CONFIG.XHTTP_REALITY_PRIVATE_KEY = keys.privateKey;
        CONFIG.XHTTP_REALITY_PUBLIC_KEY = keys.publicKey;
        CONFIG.XHTTP_REALITY_MLDSA_SEED = keys.mldsaSeed;
        CONFIG.XHTTP_REALITY_MLDSA_VERIFY = keys.mldsaVerify;
        CONFIG.XHTTP_REALITY_DECRYPTION = this.composeVlessEncryption(keys.decryption, "server");
        CONFIG.XHTTP_REALITY_ENCRYPTION = this.composeVlessEncryption(keys.encryption, "client");
        if ((CONFIG.ENABLE_XHTTP_REALITY && CONFIG.XHTTP_REALITY_MLDSA) || (Extras.needsRealityKeys() && CONFIG.XRAY_REALITY_MLDSA)) {
            Logger.info(`ML-DSA-65 is on: for good camouflage every REALITY target should return a certificate chain larger than 3500 bytes (check each one with: xray tls ping <target>)`);
        }
        if (!CONFIG.XHTTP_REALITY_SHORT_ID) {
            CONFIG.XHTTP_REALITY_SHORT_ID = keys.shortId || crypto.randomBytes(8).toString("hex");
            if (!keys.shortId) {
                keys.shortId = CONFIG.XHTTP_REALITY_SHORT_ID;
                try { fs.writeFileSync(keyFile, JSON.stringify(keys)); } catch { /* ignore */ }
            }
        }
        return true;
    }

    /* Validate "probability-min-max" padding/delay blocks joined by dots.
       Odd number of blocks (padding, delay, padding, ...); first block 100% and min > 0. */
    static parsePadding(raw, label) {
        if (!raw) return [];
        const blocks = String(raw).split(".").filter(Boolean);
        const okShape = blocks.length % 2 === 1 && blocks.every((b) => /^\d{1,3}-\d+-\d+$/.test(b));
        const first = okShape ? blocks[0].split("-").map(Number) : null;
        if (!okShape || first[0] !== 100 || first[1] < 1) {
            Logger.warning(`${label} is invalid (expected e.g. 100-111-1111.75-0-111.50-0-3333) - ignored`);
            return [];
        }
        return blocks;
    }

    /* Rewrite the output of "xray vlessenc" with the configured mode / ticket / rtt / padding.
       Format: mlkem768x25519plus.<native|xorpub|random>.<ticket|rtt>.<padding...>.<keys...> */
    static composeVlessEncryption(base, side) {
        const parts = String(base).split(".");
        if (parts.length < 4 || parts[0] !== "mlkem768x25519plus") return base;

        let mode = CONFIG.XHTTP_REALITY_ENC_MODE;
        if (!["native", "xorpub", "random"].includes(mode)) {
            Logger.warning(`XHTTP_REALITY_ENC_MODE "${mode}" is not valid - using native`);
            mode = "native";
        }

        let third;
        if (side === "server") {
            third = CONFIG.XHTTP_REALITY_TICKET;
            if (!/^\d+(-\d+)?s$/.test(third)) {
                Logger.warning(`XHTTP_REALITY_TICKET "${third}" is not valid - using 600s`);
                third = "600s";
            }
        } else {
            third = CONFIG.XHTTP_REALITY_RTT;
            if (!["0rtt", "1rtt"].includes(third)) {
                Logger.warning(`XHTTP_REALITY_RTT "${third}" is not valid - using 0rtt`);
                third = "0rtt";
            }
        }

        // Drop any padding blocks already present, keep the key material
        const rest = parts.slice(3);
        while (rest.length && /^\d+-\d+-\d+$/.test(rest[0])) rest.shift();

        const padding = side === "server"
            ? this.parsePadding(CONFIG.XHTTP_REALITY_PADDING_SERVER, "XHTTP_REALITY_PADDING_SERVER")
            : this.parsePadding(CONFIG.XHTTP_REALITY_PADDING_CLIENT, "XHTTP_REALITY_PADDING_CLIENT");

        return ["mlkem768x25519plus", mode, third, ...padding, ...rest].join(".");
    }

    /* Full setup: resolve local ports, download binary, write config, spawn. */
    static async initialize() {
        if (CONFIG.ENABLE_XHTTP_REALITY) {
            const t = CONFIG.XHTTP_REALITY_TARGET;
            const clash = (CONFIG.ENABLE_REALITY && t === CONFIG.REALITY_TARGET) ||
                (CONFIG.ENABLE_GRPC && t === CONFIG.GRPC_SNI) ||
                (CONFIG.ENABLE_SHADOWTLS_VLESS && t === CONFIG.SHADOWTLS_VLESS_SNI);
            if (clash) {
                Logger.warning(`XHTTP_REALITY_TARGET (${t}) collides with another SNI-routed inbound - set a different XHTTP_REALITY_TARGET. XHTTP-REALITY disabled.`);
                CONFIG.ENABLE_XHTTP_REALITY = false;
            }
        }
        await Extras.prepare();
        if (!CONFIG.ENABLE_XHTTP && !CONFIG.ENABLE_XHTTP_REALITY && !Extras.anyXray()) return null;

        if (CONFIG.XRAY_LOCAL_PORT === null) {
            CONFIG.XRAY_LOCAL_PORT = await getFreePort();
        }
        if (CONFIG.ENABLE_XHTTP_REALITY && CONFIG.XHTTP_REALITY_PORT === null) {
            const taken = new Set([CONFIG.XRAY_LOCAL_PORT, ...Extras.active().map((d) => d.port)]);
            let p = await getFreePort();
            for (let i = 0; i < 10 && taken.has(p); i++) p = await getFreePort();
            CONFIG.XHTTP_REALITY_PORT = p;
        }

        if (!this.ensureBinary()) {
            Logger.error("Xray-core binary unavailable - XHTTP / XHTTP-REALITY / Xray VMess+Trojan disabled for this run");
            CONFIG.ENABLE_XHTTP = false;
            CONFIG.ENABLE_XHTTP_REALITY = false;
            Extras.disableEngine("xray");
            return null;
        }

        if ((CONFIG.ENABLE_XHTTP_REALITY || Extras.needsRealityKeys()) && !this.prepareXhttpRealityKeys()) {
            CONFIG.ENABLE_XHTTP_REALITY = false;
            Extras.disableReality();
        }
        if (!CONFIG.ENABLE_XHTTP && !CONFIG.ENABLE_XHTTP_REALITY && !Extras.anyXray()) return null;

        this.writeConfiguration();
        let child = this.start();

        // Make sure every Xray backend is really listening; drop the ones that are not
        const checks = [];
        if (CONFIG.ENABLE_XHTTP_REALITY) {
            checks.push({ label: "XHTTP-REALITY", port: CONFIG.XHTTP_REALITY_PORT, off: () => { CONFIG.ENABLE_XHTTP_REALITY = false; } });
        }
        for (const d of Extras.active("xray")) {
            checks.push({ label: d.label, port: d.port, off: () => { d.enabled = false; } });
        }
        let dropped = false;
        for (const c of checks) {
            const up = await verifyLocalPort(c.port, { retries: 10, delayMs: 500 });
            if (up) {
                Logger.success(`${c.label} backend confirmed on 127.0.0.1:${c.port}`);
            } else {
                Logger.warning(`${c.label} backend never came up - disabling it for this run (see ${PATHS.XRAY_LOG_FILE})`);
                c.off();
                dropped = true;
            }
        }
        if (dropped) {
            try { child.kill("SIGTERM"); } catch { /* ignore */ }
            if (!CONFIG.ENABLE_XHTTP && !CONFIG.ENABLE_XHTTP_REALITY && !Extras.anyXray()) return null;
            // Restart with the inbounds that did work
            this.writeConfiguration();
            child = this.start();
        }
        return child;
    }

    /* Client-side "extra" block that goes into the share link. */
    static buildXhttpRealityExtra() {
        if (CONFIG.XHTTP_REALITY_EXTRA) {
            try { return JSON.parse(CONFIG.XHTTP_REALITY_EXTRA); } catch {
                Logger.warning("XHTTP_REALITY_EXTRA is not valid JSON - using defaults");
            }
        }
        return {
            "mode": CONFIG.XHTTP_REALITY_MODE,
            "xPaddingBytes": "100-1000",
            "xmux": {
                "cMaxReuseTimes": 0,
                "hKeepAlivePeriod": 0,
                "hMaxRequestTimes": "600-900",
                "hMaxReusableSecs": "1800-3000",
                "maxConcurrency": "",
                "maxConnections": 3
            }
        };
    }

    /* Build the VLESS-XHTTP share link. It uses the shared public port and the XHTTP path. */
    static async generateLink() {
        if (!CONFIG.ENABLE_XHTTP && !CONFIG.ENABLE_XHTTP_REALITY) return null;

        const serverHost = await SbManager.getServerHost();
        const isp = await SystemUtils.getISPInfo();

        let xhttpUrl = null;
        if (CONFIG.ENABLE_XHTTP) {
            const xhttpPath = CONFIG.XHTTP_PATH.startsWith('/') ? CONFIG.XHTTP_PATH.slice(1) : CONFIG.XHTTP_PATH;
            xhttpUrl = `vless://${CONFIG.SB_UUID}@${serverHost}:${CONFIG.PORT}?encryption=none&security=none&type=xhttp&path=${encodeURIComponent('/' + xhttpPath)}&mode=${CONFIG.XHTTP_MODE}#${CONFIG.XHTTP_NAME}-${isp}`;
            state.vlessXhttpLinks = [xhttpUrl];
        }

        if (CONFIG.ENABLE_XHTTP_REALITY) {
            const p = CONFIG.XHTTP_REALITY_PATH.startsWith('/') ? CONFIG.XHTTP_REALITY_PATH : `/${CONFIG.XHTTP_REALITY_PATH}`;
            const extra = encodeURIComponent(JSON.stringify(this.buildXhttpRealityExtra()));
            const realityUrl = `vless://${CONFIG.SB_UUID}@${serverHost}:${CONFIG.PORT}` +
                `?encryption=${encodeURIComponent(CONFIG.XHTTP_REALITY_ENCRYPTION)}` +
                `&extra=${extra}` +
                `&fp=${CONFIG.XHTTP_REALITY_FP}` +
                `&mode=${CONFIG.XHTTP_REALITY_MODE}` +
                `&path=${encodeURIComponent(p)}` +
                `&pbk=${CONFIG.XHTTP_REALITY_PUBLIC_KEY}` +
                (CONFIG.XHTTP_REALITY_MLDSA ? `&pqv=${CONFIG.XHTTP_REALITY_MLDSA_VERIFY}` : "") +
                `&security=reality` +
                `&sid=${CONFIG.XHTTP_REALITY_SHORT_ID}` +
                `&sni=${CONFIG.XHTTP_REALITY_TARGET}` +
                `&type=xhttp#${encodeURIComponent(CONFIG.XHTTP_REALITY_NAME + '-' + isp)}`;
            state.vlessXhttpRealityLinks = [realityUrl];
        }

        return xhttpUrl;
    }
}

// X MANAGER
class XManager {
    /* Create X configuration */
    static createConfiguration() {
        Logger.step("Creating X configuration");

        const config = {
            log: {
                access: '/dev/null',
                error: '/dev/null',
                loglevel: 'none'
            },
            inbounds: [
                {
                    port: CONFIG.ARGO_PORT,
                    protocol: 'vless',
                    settings: {
                        clients: [{
                            id: CONFIG.UUID,
                            flow: 'xtls-rprx-vision'
                        }],
                        decryption: 'none',
                        fallbacks: [
                            { dest: 3001 },
                            { path: "/vless-argo", dest: 3002 }
                        ]
                    },
                    streamSettings: { network: 'tcp' }
                },
                {
                    port: 3001,
                    listen: "127.0.0.1",
                    protocol: "vless",
                    settings: {
                        clients: [{ id: CONFIG.UUID }],
                        decryption: "none"
                    },
                    streamSettings: {
                        network: "ws",
                        security: "none",
                        wsSettings: { path: "/vless-argo" }
                    }
                },
                {
                    port: 3002,
                    listen: "127.0.0.1",
                    protocol: "vless",
                    settings: {
                        clients: [{ id: CONFIG.UUID, level: 0 }],
                        decryption: "none"
                    },
                    streamSettings: {
                        network: "ws",
                        security: "none",
                        wsSettings: { path: "/vless-argo" }
                    },
                    sniffing: {
                        enabled: true,
                        destOverride: ["http", "tls", "quic"],
                        metadataOnly: false
                    }
                }
            ],
            dns: {
                servers: ["https+local://8.8.8.8/dns-query"]
            },
            outbounds: [
                { protocol: "freedom", tag: "direct" },
                { protocol: "blackhole", tag: "block" }
            ]
        };

        fs.writeFileSync(PATHS.X_CONFIG, JSON.stringify(config, null, 2));
        Logger.success("X configuration created");
    }

    /* Get system architecture */
    static getSystemArchitecture() {
        const arch = os.arch();
        return (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') ? 'arm' : 'amd';
    }

    /* Get files to download for current architecture */
    static getFilesForArchitecture(architecture) {
        const isArm = architecture === "arm";
        // Default cloudflared mirror (the file is saved as "bot"). Set BOT_URL to download from another source, such as the official Cloudflare release.
        const botDefault = isArm
            ? "https://arm64.ssss.nyc.mn/2go"
            : "https://amd64.ssss.nyc.mn/2go";

        return [
            { fileName: "bot", fileUrl: CONFIG.BOT_URL || botDefault }
        ];
    }

    /* Remove stale / incomplete binaries so they re-download */
    static purgeBadBinary(fileName, minBytes = 1024 * 500) {
        const p = path.join(CONFIG.FILE_PATH, fileName);
        try {
            if (fs.existsSync(p) && fs.statSync(p).size < minBytes) {
                fs.unlinkSync(p);
                Logger.warning(`Removed incomplete binary: ${fileName}`);
            }
        } catch { /* ignore */ }
    }

    /* Download and setup X components. */
    static async downloadAndRun() {
        // Make sure the shared Xray-core binary exists (nothing to do if XHTTP already downloaded it).
        if (!XCoreManager.ensureBinary()) {
            Logger.warning("X core binary missing - skipping X server");
            return;
        }

        const architecture = this.getSystemArchitecture();
        const filesToDownload = this.getFilesForArchitecture(architecture);

        if (filesToDownload.length === 0) {
            Logger.warning(`No files found for architecture: ${architecture}`);
            return;
        }

        // Delete truncated downloads left over from earlier runs that ran out of disk space (ENOSPC).
        this.purgeBadBinary("bot");

        // cloudflared itself is roughly 40-50 MB depending on the architecture, so make sure there is enough free disk space first.
        const ARGO_MIN_FREE_MB = 60;
        const freeMB = SystemUtils.getFreeDiskMB(CONFIG.FILE_PATH);
        if (freeMB !== null && freeMB < ARGO_MIN_FREE_MB && process.env.ARGO_FORCE !== "1") {
            Logger.error(`Not enough disk space for Argo: ~${freeMB}MB free in ${CONFIG.FILE_PATH} (cloudflared needs ~${ARGO_MIN_FREE_MB}MB+). Disabling Argo for this run - free up space, or set ARGO_FORCE=1 to attempt it anyway.`);
            CONFIG.ENABLE_ARGO = false;
            return;
        } else if (freeMB !== null && freeMB < 150) {
            Logger.warning(`Low disk space in ${CONFIG.FILE_PATH}: ~${freeMB}MB free. Cloudflared download may still fail with ENOSPC.`);
        }

        Logger.step(`Downloading cloudflared for ${architecture} architecture`);

        try {
            const downloadPromises = filesToDownload.map(file =>
                SystemUtils.downloadFile(file.fileName, file.fileUrl)
            );
            await Promise.all(downloadPromises);
            Logger.success("All files downloaded successfully");
        } catch (error) {
            Logger.warning(`X components download failed: ${error}`);
            Logger.warning("Continuing without Argo/X - Hysteria2 and VLESS-WS remain available");
        }

        const botPath = path.join(CONFIG.FILE_PATH, "bot");
        if (fs.existsSync(botPath)) {
            try { fs.chmodSync(botPath, 0o755); } catch { /* ignore */ }
        }

        // Stop previous instances so ports/logs are clean.
        try {
            execSync(`pkill -f "${PATHS.X_CONFIG}" 2>/dev/null || true`, { shell: true });
            execSync(`pkill -f "${botPath}" 2>/dev/null || true`, { shell: true });
        } catch { /* ignore */ }

        if (fs.existsSync(PATHS.XRAY_BIN)) {
            await this.startXCore();
            // Let Xray bind ARGO_PORT before cloudflared connects
            await new Promise((r) => setTimeout(r, 2500));
        } else {
            Logger.warning("X core binary missing - skipping X server");
            return;
        }

        if (fs.existsSync(botPath)) {
            await this.startCloudflared();
        } else {
            Logger.warning("Cloudflared binary missing - skipping Argo tunnel");
        }
    }

    /* Start Xray-core for the Argo tunnel. It uses the shared Xray-core binary with the config at PATHS.X_CONFIG. */
    static async startXCore() {
        const xcoreLog = path.join(CONFIG.FILE_PATH, "xcore.log");
        const cmd = `nohup "${PATHS.XRAY_BIN}" -c "${PATHS.X_CONFIG}" >> "${xcoreLog}" 2>&1 &`;
        try {
            exec(cmd);
            Logger.success("X core started");
        } catch (error) {
            Logger.error(`Failed to start X core: ${error}`);
        }
    }

    /* Start Cloudflared tunnel. */
    static async startCloudflared() {
        const botPath = path.join(CONFIG.FILE_PATH, "bot");
        if (!fs.existsSync(botPath)) {
            return;
        }

        try { fs.writeFileSync(PATHS.BOOT_LOG, ""); } catch { /* ignore */ }

        let args;
        const auth = CONFIG.ARGO_AUTH || "";

        if (/^[A-Z0-9a-z=]{120,250}$/.test(auth)) {
            args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${auth}`;
        } else if (/TunnelSecret/.test(auth)) {
            args = `tunnel --edge-ip-version auto --config "${CONFIG.FILE_PATH}/tunnel.yml" run`;
        } else {
            // Quick tunnel (no token or credentials): cloudflared writes structured JSON logs to boot.log, and
            // the info log level makes those lines include the generated trycloudflare.com hostname.
            args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile "${PATHS.BOOT_LOG}" --loglevel info --metrics 127.0.0.1:2000 --url http://127.0.0.1:${CONFIG.ARGO_PORT}`;
        }

        try {
            const cmd = `nohup "${botPath}" ${args} &`;
            exec(cmd);
            Logger.success("Cloudflared tunnel started");
        } catch (error) {
            Logger.error(`Failed to start Cloudflared: ${error}`);
        }
    }

    /* Read the trycloudflare.com hostname from the cloudflared log content (returns null if none is found). */
    static parseArgoDomainFromLog(content) {
        if (!content) return null;

        const validHost = (h) => {
            h = (h || "").replace(/^https?:\/\//, "").split("/")[0].trim().toLowerCase();
            return h.endsWith(".trycloudflare.com") &&
                   h !== "trycloudflare.com" &&
                   h !== "fallback.trycloudflare.com"
                ? h : null;
        };

        // 1) Structured JSON log lines
        for (const line of content.split("\n")) {
            const trimmed = line.trim();
            if (!trimmed.startsWith("{")) continue;
            try {
                const obj = JSON.parse(trimmed);
                // Fields seen across cloudflared versions: url, hostname, message
                for (const key of ["url", "hostname"]) {
                    const h = validHost(obj[key]);
                    if (h) return h;
                }
                // Some builds embed the URL inside the message string
                if (typeof obj.message === "string") {
                    const m = obj.message.match(/https?:\/\/([a-z0-9-]+\.trycloudflare\.com)/i);
                    if (m) { const h = validHost(m[1]); if (h) return h; }
                }
            } catch { /* not valid JSON, skip */ }
        }

        // 2) Fallback: scan the raw text for any trycloudflare.com URL (the last match wins)
        const re = /(?:https?:\/\/)?([a-z0-9-]+\.trycloudflare\.com)/gi;
        let match, last = null;
        while ((match = re.exec(content)) !== null) {
            const h = validHost(match[1]);
            if (h) last = h;
        }
        return last;
    }

    /* Try to read the quick-tunnel hostname from cloudflared's local metrics endpoint. */
    static async queryMetricsApi(port = 2000) {
        const base = `http://127.0.0.1:${port}`;

        // Helper: make a plain http GET with a short timeout, no retries
        const httpGet = (url) => new Promise((resolve, reject) => {
            const req = http.get(url, { timeout: 3000 }, (res) => {
                let data = "";
                res.on("data", (chunk) => { data += chunk; });
                res.on("end", () => resolve(data));
            });
            req.on("error", reject);
            req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
        });

        // 1) /quicktunnel returns a JSON object with the hostname
        try {
            const raw = await httpGet(`${base}/quicktunnel`);
            const json = JSON.parse(raw);
            const host = (json.hostname || "").replace(/^https?:\/\//, "").trim().toLowerCase();
            if (host && host.endsWith(".trycloudflare.com")) return host;
        } catch { /* not ready yet or endpoint absent */ }

        // 2) /metrics exposes the hostname in a userHostname label
        try {
            const raw = await httpGet(`${base}/metrics`);
            // The line looks like: userHostname="https://xxxx.trycloudflare.com"
            const m = raw.match(/userHostname="https?:\/\/([a-z0-9-]+\.trycloudflare\.com)"/i);
            if (m) return m[1].toLowerCase();
        } catch { /* not ready yet */ }

        return null;
    }

    /* Wait for the Argo domain. The cloudflared metrics API is checked first (primary), then boot.log (fallback). */
    static async waitForArgoDomain(timeoutMs = 60000, intervalMs = 2000) {
        const started = Date.now();
        const metricsPorts = [2000, 2001, 2002];

        while (Date.now() - started < timeoutMs) {
            // Primary: query the local metrics/quicktunnel API
            for (const port of metricsPorts) {
                try {
                    const domain = await this.queryMetricsApi(port);
                    if (domain) return domain;
                } catch { /* keep trying */ }
            }

            // Secondary: scan the log file (catches older cloudflared builds)
            try {
                if (fs.existsSync(PATHS.BOOT_LOG)) {
                    const content = fs.readFileSync(PATHS.BOOT_LOG, "utf8");
                    const domain = this.parseArgoDomainFromLog(content);
                    if (domain) return domain;
                }
            } catch { /* keep polling */ }

            await new Promise((r) => setTimeout(r, intervalMs));
        }
        return null;
    }

    /* Extract Argo tunnel domains */
    static async extractDomains() {
        let argoDomain;

        // Named tunnel: user must set ARGO_DOMAIN
        if (CONFIG.ARGO_AUTH && CONFIG.ARGO_DOMAIN) {
            argoDomain = CONFIG.ARGO_DOMAIN;
            Logger.config("ARGO_DOMAIN", argoDomain);
            await this.generateLinks(argoDomain);
            return argoDomain;
        }

        if (CONFIG.ARGO_AUTH && !CONFIG.ARGO_DOMAIN) {
            Logger.warning("ARGO_AUTH set without ARGO_DOMAIN - cannot build Argo link host");
        }

        Logger.step("Waiting for Cloudflare quick tunnel domain (API + log)...");
        argoDomain = await this.waitForArgoDomain(60000, 2000);

        if (!argoDomain) {
            // Both the metrics API and the log file came back empty, so no domain is available.
            Logger.error("Argo domain not found after 60 s (API + log both empty). Argo links will be unavailable this run. Check boot.log and ensure cloudflared can reach Cloudflare's edge.");
            return null;
        }

        Logger.config("Argo Domain", argoDomain);
        await this.generateLinks(argoDomain);
        return argoDomain;
    }

    /* Generate X shareable links */
    static async generateLinks(argoDomain) {
        const isp = await SystemUtils.getISPInfo();
        // Always connect straight to the Argo domain we actually received
        const cfip = process.env.CFIP || argoDomain;

        return new Promise((resolve) => {
            setTimeout(() => {
                const vlessLink = `vless://${CONFIG.UUID}@${cfip}:${CONFIG.CFPORT}?encryption=none&security=tls&sni=${argoDomain}&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${CONFIG.NAME}-${isp}`;

                state.xLinks = [vlessLink];
                state.xBase64 = Buffer.from(vlessLink).toString('base64');

                resolve(vlessLink);
            }, 2000);
        });
    }
}

// CLASH META CONVERTER
class ClashConverter {
    /* Safe double-quoted YAML scalar */
    static yamlString(value) {
        return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
    }

    static safeDecode(value) {
        if (!value) return '';
        try { return decodeURIComponent(value); } catch { return value; }
    }

    /** Parse a hysteria2:// link into a Clash Meta "hysteria2" proxy block */
    static fromHysteria2(uri) {
        try {
            const u = new URL(uri);
            const name = this.safeDecode(u.hash ? u.hash.slice(1) : '') || 'Hysteria2';
            const password = this.safeDecode(u.username);
            const sni = u.searchParams.get('sni') || u.hostname;
            const obfs = u.searchParams.get('obfs') || '';
            const obfsPassword = u.searchParams.get('obfs-password') || '';
            const insecure = u.searchParams.get('insecure') === '1';

            const lines = [];
            lines.push(`  - name: ${this.yamlString(name)}`);
            lines.push(`    type: hysteria2`);
            lines.push(`    server: ${this.yamlString(u.hostname)}`);
            lines.push(`    port: ${parseInt(u.port, 10) || 443}`);
            lines.push(`    password: ${this.yamlString(password)}`);
            if (obfs) {
                lines.push(`    obfs: ${this.yamlString(obfs)}`);
                lines.push(`    obfs-password: ${this.yamlString(obfsPassword)}`);
            }
            lines.push(`    sni: ${this.yamlString(sni)}`);
            lines.push(`    skip-cert-verify: ${insecure ? 'true' : 'false'}`);
            lines.push(`    alpn:`);
            lines.push(`      - h3`);
            return { name, uri, yaml: lines.join('\n') };
        } catch {
            return null;
        }
    }

    /** Parse a vless:// link (WS, plain or TLS) into a Clash Meta "vless" proxy block */
    static fromVless(uri) {
        try {
            const u = new URL(uri);
            const name = this.safeDecode(u.hash ? u.hash.slice(1) : '') || 'VLESS';
            const uuid = this.safeDecode(u.username);
            const security = (u.searchParams.get('security') || 'none').toLowerCase();
            const netType = (u.searchParams.get('type') || 'tcp').toLowerCase();
            const isReality = security === 'reality';
            const isTls = security === 'tls' || isReality;
            const host = u.searchParams.get('host') || u.hostname;
            const sni = u.searchParams.get('sni') || host;
            const fp = u.searchParams.get('fp') || 'chrome';
            const pbk = u.searchParams.get('pbk') || '';
            const sid = u.searchParams.get('sid') || '';
            const flow = u.searchParams.get('flow') || '';
            const allowInsecure = u.searchParams.get('allowInsecure') === '1';
            const serviceName = u.searchParams.get('serviceName') ? this.safeDecode(u.searchParams.get('serviceName')) : '';
            let wsPath = u.searchParams.get('path') ? this.safeDecode(u.searchParams.get('path')) : '/';
            if (!wsPath.startsWith('/')) wsPath = `/${wsPath}`;

            const lines = [];
            lines.push(`  - name: ${this.yamlString(name)}`);
            lines.push(`    type: vless`);
            lines.push(`    server: ${this.yamlString(u.hostname)}`);
            lines.push(`    port: ${parseInt(u.port, 10) || (isTls ? 443 : 80)}`);
            lines.push(`    uuid: ${this.yamlString(uuid)}`);
            lines.push(`    udp: true`);
            lines.push(`    tls: ${isTls ? 'true' : 'false'}`);
            if (flow) lines.push(`    flow: ${this.yamlString(flow)}`);
            if (isTls) {
                lines.push(`    servername: ${this.yamlString(sni)}`);
                lines.push(`    client-fingerprint: ${this.yamlString(fp)}`);
                lines.push(`    skip-cert-verify: ${allowInsecure ? 'true' : 'false'}`);
            }
            if (isReality && pbk) {
                lines.push(`    reality-opts:`);
                lines.push(`      public-key: ${this.yamlString(pbk)}`);
                if (sid) lines.push(`      short-id: ${this.yamlString(sid)}`);
            }
            if (netType === 'ws') {
                lines.push(`    network: ws`);
                lines.push(`    ws-opts:`);
                lines.push(`      path: ${this.yamlString(wsPath)}`);
                lines.push(`      headers:`);
                lines.push(`        Host: ${this.yamlString(host)}`);
            } else if (netType === 'httpupgrade') {
                // Mihomo/Clash-Meta represents HTTPUpgrade as network: ws
                lines.push(`    network: ws`);
                lines.push(`    ws-opts:`);
                lines.push(`      path: ${this.yamlString(wsPath)}`);
                lines.push(`      v2ray-http-upgrade: true`);
                lines.push(`      headers:`);
                lines.push(`        Host: ${this.yamlString(host)}`);
            } else if (netType === 'grpc') {
                lines.push(`    network: grpc`);
                lines.push(`    grpc-opts:`);
                lines.push(`      grpc-service-name: ${this.yamlString(serviceName)}`);
            } else {
                lines.push(`    network: tcp`);
            }
            return { name, uri, yaml: lines.join('\n') };
        } catch {
            return null;
        }
    }

    /** Build the full Clash Meta / Mihomo YAML from every currently active link */
    static buildYaml() {
        const proxies = [];
        for (const link of state.sboxLinks) {
            const p = this.fromHysteria2(link);
            if (p) proxies.push(p);
        }
        for (const link of state.vlessWsLinks) {
            const p = this.fromVless(link);
            if (p) proxies.push(p);
        }
        for (const link of state.vlessHuLinks) {
            const p = this.fromVless(link);
            if (p) proxies.push(p);
        }
        for (const link of state.xLinks) {
            const p = this.fromVless(link);
            if (p) proxies.push(p);
        }
        for (const link of state.realityLinks) {
            const p = this.fromVless(link);
            if (p) proxies.push(p);
        }
        for (const link of state.grpcLinks) {
            const p = this.fromVless(link);
            if (p) proxies.push(p);
        }
        for (const p of Extras.clashProxies()) proxies.push(p);
        // ShadowTLS-VLESS cannot be expressed as a Clash proxy. It is delivered as sing-box outbound JSON instead, so it is skipped here.

        if (proxies.length === 0) {
            return `# Xray-Sing - no active nodes yet.\n# Reload this URL once Xray-Sing has finished starting.\nproxies: []\n`;
        }

        // De-duplicate names so Clash doesn't choke on repeats
        const seen = new Map();
        for (const p of proxies) {
            const count = seen.get(p.name) || 0;
            seen.set(p.name, count + 1);
            if (count > 0) p.name = `${p.name}-${count + 1}`;
        }

        const names = proxies.map((p) => this.yamlString(p.name));
        const proxyBlock = proxies.map((p) => p.yaml).join('\n');
        const groupProxies = names.map((n) => `      - ${n}`).join('\n');

        return `# Xray-Sing - Clash Meta / Mihomo subscription
# Generated ${new Date().toISOString()}
mixed-port: 7890
allow-lan: true
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
external-controller: 127.0.0.1:9090
dns:
  enable: true
  ipv6: true
  default-nameserver:
    - 223.5.5.5
    - 1.1.1.1
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query

proxies:
${proxyBlock}

proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
${groupProxies}
      - DIRECT
  - name: "auto"
    type: url-test
    tolerance: 50
    interval: 300
    url: "http://www.gstatic.com/generate_204"
    proxies:
${groupProxies}

rules:
  - MATCH,PROXY
`;
    }
}

// ========== HTTP SERVER ==========
// ========== PANEL (login, sessions, UI) ==========
const PANEL_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Console</title>
<style>
@font-face{font-family:"Mona Sans";font-style:normal;font-display:swap;font-weight:200 900;src:local("Mona Sans"),url(https://cdn.jsdelivr.net/fontsource/fonts/mona-sans:vf@latest/latin-wght-normal.woff2) format("woff2-variations");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
@font-face{font-family:"JetBrains Mono";font-style:normal;font-display:swap;font-weight:100 800;src:local("JetBrains Mono"),url(https://cdn.jsdelivr.net/fontsource/fonts/jetbrains-mono:vf@latest/latin-wght-normal.woff2) format("woff2-variations");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}

/* Tokens: names match the Figma variables (collection "Primer"). Dark is the default. */
:root{
  --canvas-default:#0d1117;--canvas-subtle:#151b23;--canvas-inset:#010409;
  --btn-bg:#212830;--btn-hover:#262c36;--btn-primary-bg:#238636;--btn-primary-hover:#2ea043;
  --neutral-muted:rgba(110,118,129,.4);
  --accent-emphasis:#1f6feb;--accent-subtle:rgba(65,132,228,.1);
  --success-emphasis:#238636;--success-subtle:rgba(46,160,67,.15);
  --danger-emphasis:#da3633;--danger-subtle:rgba(248,81,73,.1);
  --attention-subtle:rgba(187,128,9,.15);
  --border-default:#30363d;--border-muted:#21262d;
  --btn-border:rgba(240,246,252,.1);--btn-primary-border:rgba(240,246,252,.1);
  --fg-default:#e6edf3;--fg-muted:#9198a1;--fg-subtle:#6e7681;--fg-on-emphasis:#ffffff;
  --accent-fg:#4493f8;--success-fg:#3fb950;--danger-fg:#f85149;--attention-fg:#d29922;
  --space-1:4px;--space-2:8px;--space-3:12px;--space-4:16px;--space-5:24px;--space-6:32px;
  --radius-md:6px;--radius-lg:12px;--radius-full:999px;
  --shadow:0 8px 24px rgba(1,4,9,.45);
  --sans:"Mona Sans",ui-sans-serif,system-ui,-apple-system,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  color-scheme:dark;
}
@media (prefers-color-scheme:light){
  :root:not([data-theme=dark]){
    --canvas-default:#ffffff;--canvas-subtle:#f6f8fa;--canvas-inset:#f6f8fa;
    --btn-bg:#f6f8fa;--btn-hover:#eff2f5;--btn-primary-bg:#1f883d;--btn-primary-hover:#1a7f37;
    --neutral-muted:rgba(129,139,152,.2);
    --accent-emphasis:#0969da;--accent-subtle:#ddf4ff;
    --success-emphasis:#1f883d;--success-subtle:#dafbe1;
    --danger-emphasis:#cf222e;--danger-subtle:#ffebe9;
    --attention-subtle:#fff8c5;
    --border-default:#d1d9e0;--border-muted:#d8dee4;
    --btn-border:rgba(31,35,40,.15);--btn-primary-border:rgba(31,35,40,.15);
    --fg-default:#1f2328;--fg-muted:#59636e;--fg-subtle:#818b98;--fg-on-emphasis:#ffffff;
    --accent-fg:#0969da;--success-fg:#1a7f37;--danger-fg:#d1242f;--attention-fg:#9a6700;
    --shadow:0 8px 24px rgba(140,149,159,.3);
    color-scheme:light;
  }
}
:root[data-theme=light]{
  --canvas-default:#ffffff;--canvas-subtle:#f6f8fa;--canvas-inset:#f6f8fa;
  --btn-bg:#f6f8fa;--btn-hover:#eff2f5;--btn-primary-bg:#1f883d;--btn-primary-hover:#1a7f37;
  --neutral-muted:rgba(129,139,152,.2);
  --accent-emphasis:#0969da;--accent-subtle:#ddf4ff;
  --success-emphasis:#1f883d;--success-subtle:#dafbe1;
  --danger-emphasis:#cf222e;--danger-subtle:#ffebe9;
  --attention-subtle:#fff8c5;
  --border-default:#d1d9e0;--border-muted:#d8dee4;
  --btn-border:rgba(31,35,40,.15);--btn-primary-border:rgba(31,35,40,.15);
  --fg-default:#1f2328;--fg-muted:#59636e;--fg-subtle:#818b98;--fg-on-emphasis:#ffffff;
  --accent-fg:#0969da;--success-fg:#1a7f37;--danger-fg:#d1242f;--attention-fg:#9a6700;
  --shadow:0 8px 24px rgba(140,149,159,.3);
  color-scheme:light;
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--canvas-default);color:var(--fg-default);font-family:var(--sans);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
button,input,select{font:inherit;color:inherit}
svg{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.ico{display:inline-flex;align-items:center;justify-content:center;flex:none}
h1,h2,h3,p{margin:0}

/* ---- Button (Figma: Button, Variant x Size) ---- */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:var(--space-2);height:32px;padding:0 var(--space-4);border-radius:var(--radius-md);border:1px solid var(--btn-border);background:var(--btn-bg);color:var(--fg-default);font-weight:500;cursor:pointer;white-space:nowrap;transition:background .12s,border-color .12s}
.btn:hover{background:var(--btn-hover)}
.btn:focus-visible,.input:focus-visible,.nav:focus-visible,.icon-btn:focus-visible{outline:2px solid var(--accent-fg);outline-offset:-1px}
.btn.primary{background:var(--btn-primary-bg);border-color:var(--btn-primary-border);color:var(--fg-on-emphasis)}
.btn.primary:hover{background:var(--btn-primary-hover)}
.btn.danger{color:var(--danger-fg)}
.btn.danger:hover{background:var(--danger-subtle);border-color:var(--danger-emphasis)}
.btn.invisible{background:transparent;border-color:transparent}
.btn.invisible:hover{background:var(--btn-hover)}
.btn.sm{height:28px;padding:0 var(--space-3);font-size:12px}
.btn.block{width:100%}
.btn[disabled]{opacity:.5;cursor:not-allowed}
.btn svg{color:var(--fg-muted)}
.btn.primary svg{color:inherit}
.btn.danger svg{color:inherit}

/* ---- Field (Figma: Field, State x Size) ---- */
.field{display:flex;flex-direction:column;gap:var(--space-2)}
.field label{font-weight:500}
.input{width:100%;height:32px;padding:0 var(--space-3);border-radius:var(--radius-md);border:1px solid var(--border-default);background:var(--canvas-default);color:var(--fg-default)}
.input:focus{border-color:var(--accent-emphasis);outline:2px solid var(--accent-emphasis);outline-offset:-2px}
.input.code{height:52px;background:var(--canvas-inset);font-family:var(--mono);font-weight:500;font-size:22px;letter-spacing:.2em;text-align:center;text-transform:uppercase}
.input-wrap{position:relative}
.input-wrap .input{padding-right:40px}
.input-wrap .eye{position:absolute;right:2px;top:2px;width:28px;height:28px;border:0;background:transparent;border-radius:var(--radius-md);cursor:pointer;color:var(--fg-muted);display:flex;align-items:center;justify-content:center}
.hint{font-size:12px;color:var(--fg-muted)}
.err{font-size:12px;color:var(--danger-fg);min-height:18px}
.meter{display:flex;gap:var(--space-1);margin-top:var(--space-1)}
.meter i{flex:1;height:4px;border-radius:2px;background:var(--border-default);transition:background .15s}

/* ---- Label / StatusPill ---- */
.label{display:inline-flex;align-items:center;height:22px;padding:0 var(--space-2);border-radius:var(--radius-full);border:1px solid var(--border-default);font-size:12px;font-weight:500;color:var(--fg-muted);white-space:nowrap}
.label.accent{background:var(--accent-subtle);border-color:transparent;color:var(--accent-fg)}
.pill{display:inline-flex;align-items:center;gap:var(--space-2);height:24px;padding:0 var(--space-3);border-radius:var(--radius-full);font-size:12px;font-weight:500}
.pill i{width:6px;height:6px;border-radius:50%;background:currentColor}
.pill.ok{background:var(--success-subtle);color:var(--success-fg)}
.pill.bad{background:var(--danger-subtle);color:var(--danger-fg)}
.pill.off{background:var(--neutral-muted);color:var(--fg-muted)}

/* ---- Box ---- */
.box{border:1px solid var(--border-default);border-radius:var(--radius-md);background:var(--canvas-default);overflow:hidden;min-width:0}
.box-h{padding:var(--space-4);background:var(--canvas-subtle);border-bottom:1px solid var(--border-default)}
.box-h h3{font-size:16px;font-weight:600}
.box-h p{font-size:12px;color:var(--fg-muted);margin-top:2px}
.box-b{padding:var(--space-4);display:flex;flex-direction:column;gap:var(--space-3)}
.box-b.flush{padding:0 var(--space-4);gap:0}
.stack>*+*{margin-top:var(--space-4)}
.row{display:flex;align-items:center;gap:var(--space-2)}
.between{justify-content:space-between}
.grid{display:grid;gap:var(--space-4)}
.g4{grid-template-columns:repeat(4,minmax(0,1fr))}
.g2{grid-template-columns:repeat(2,minmax(0,1fr))}

/* ---- StatTile / ServiceRow ---- */
.tile{padding:var(--space-4);border:1px solid var(--border-default);border-radius:var(--radius-md);display:flex;flex-direction:column;gap:var(--space-1)}
.tile .k{font-size:12px;font-weight:500;color:var(--fg-muted)}
.tile .v{font-size:24px;line-height:32px;font-weight:600}
.svc{display:flex;align-items:center;justify-content:space-between;padding:var(--space-3) 0;border-top:1px solid var(--border-muted)}
.svc:first-child{border-top:0}

/* ---- CopyField ---- */
.copy{display:flex;align-items:center;gap:var(--space-2);min-height:36px;padding:3px 4px 3px var(--space-3);background:var(--canvas-inset);border:1px solid var(--border-default);border-radius:var(--radius-md)}
.copy code{flex:1;min-width:0;font-family:var(--mono);font-size:12px;line-height:18px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.copy.full code{white-space:normal;word-break:break-all;max-height:180px;overflow:auto}

/* ---- ProtocolCard / SubscriptionRow ---- */
.card{border:1px solid var(--border-default);border-radius:var(--radius-md);padding:var(--space-4);display:flex;flex-direction:column;gap:var(--space-3);min-width:0}
.card .head{display:flex;align-items:center;gap:var(--space-3)}
.avatar{width:36px;height:36px;border-radius:var(--radius-md);background:var(--accent-subtle);color:var(--accent-fg);display:flex;align-items:center;justify-content:center;font-weight:600;font-size:16px;flex:none}
.card .t{font-size:16px;font-weight:600;line-height:24px}
.card .s{font-size:12px;color:var(--fg-muted)}
.card .grow{flex:1;min-width:0}
.badges{display:flex;flex-wrap:wrap;gap:var(--space-2)}
.qr{display:none;justify-content:center;padding:var(--space-4);background:#fff;border-radius:var(--radius-md)}
.qr.open{display:flex}
.sub-t{font-weight:500}
.notice{padding:var(--space-4);border-radius:var(--radius-md);background:var(--attention-subtle);color:var(--attention-fg)}
.empty{padding:40px;text-align:center;color:var(--fg-muted)}

/* ---- Auth (Figma: Login / Setup) ---- */
.auth{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:var(--space-5)}
.auth-col{width:100%;max-width:340px;display:flex;flex-direction:column;align-items:center;gap:var(--space-4)}
.auth-col h1{font-size:24px;line-height:32px;font-weight:600;text-align:center}
.auth-col .lead{color:var(--fg-muted);text-align:center}
.auth-panel{width:100%;background:var(--canvas-subtle);border:1px solid var(--border-default);border-radius:var(--radius-lg);padding:var(--space-4);display:flex;flex-direction:column;gap:var(--space-4)}
.auth-foot{font-size:12px;color:var(--fg-muted);text-align:center}
.steps{display:flex;gap:var(--space-2);width:100%}
.steps i{flex:1;height:4px;border-radius:2px;background:var(--border-default)}
.steps i.on{background:var(--accent-emphasis)}
.logo{width:48px;height:48px;border-radius:50%;background:var(--fg-default);color:var(--canvas-default);display:flex;align-items:center;justify-content:center;flex:none}
.logo svg{width:26px;height:26px;color:inherit}
.logo.s{width:28px;height:28px}
.logo.s svg{width:16px;height:16px}

/* ---- App shell (Figma: Overview etc.) ---- */
.shell{display:grid;grid-template-columns:248px 1fr;min-height:100vh}
.side{position:sticky;top:0;height:100vh;padding:var(--space-4);border-right:1px solid var(--border-default);background:var(--canvas-subtle);display:flex;flex-direction:column;gap:var(--space-1)}
.brand{display:flex;align-items:center;gap:var(--space-3);padding:0 var(--space-2) var(--space-4);font-size:16px;font-weight:600}
.nav{position:relative;display:flex;align-items:center;gap:var(--space-3);height:32px;padding:0 var(--space-3);border:0;border-radius:var(--radius-md);background:transparent;color:var(--fg-muted);cursor:pointer;text-align:left;width:100%}
.nav:hover{background:var(--btn-hover);color:var(--fg-default)}
.nav.on{background:var(--btn-hover);color:var(--fg-default);font-weight:500}
.nav.on::before{content:"";position:absolute;left:0;top:7px;width:3px;height:18px;border-radius:2px;background:var(--accent-emphasis)}
.side .spacer{flex:1}
.main{min-width:0}
.top{display:flex;align-items:center;justify-content:space-between;gap:var(--space-2);padding:var(--space-3) var(--space-5);background:var(--canvas-subtle);border-bottom:1px solid var(--border-default);position:sticky;top:0;z-index:5}
.crumb{color:var(--fg-muted)}
.crumb b{color:var(--fg-default);font-weight:500}
.crumb .sep{margin:0 var(--space-2)}
.content{padding:var(--space-5);max-width:1120px}
.pagehead{margin-bottom:var(--space-5)}
.pagehead h1{font-size:24px;line-height:32px;font-weight:600}
.pagehead p{color:var(--fg-muted)}

/* ---- Modal / toast ---- */
.modal-bg{position:fixed;inset:0;background:rgba(1,4,9,.7);display:flex;align-items:center;justify-content:center;padding:var(--space-5);z-index:50}
.modal{width:100%;max-width:400px;background:var(--canvas-subtle);border:1px solid var(--border-default);border-radius:var(--radius-lg);padding:var(--space-5);box-shadow:var(--shadow)}
.modal h3{font-size:16px;font-weight:600}
.modal p{color:var(--fg-muted);margin-top:var(--space-3)}
.modal .row{justify-content:flex-end;margin-top:var(--space-5)}
#toast{position:fixed;left:50%;bottom:24px;transform:translate(-50%,20px);background:var(--fg-default);color:var(--canvas-default);padding:var(--space-2) var(--space-4);border-radius:var(--radius-md);font-weight:500;opacity:0;pointer-events:none;transition:all .2s;z-index:60}
#toast.show{opacity:1;transform:translate(-50%,0)}

@media (max-width:860px){
  .shell{grid-template-columns:1fr}
  .side{position:static;height:auto;flex-direction:row;overflow-x:auto;padding:var(--space-2);border-right:0;border-bottom:1px solid var(--border-default)}
  .brand,.side .spacer{display:none}
  .nav{width:auto;white-space:nowrap}
  .nav.on::before{display:none}
  .top{position:static;padding:var(--space-3) var(--space-4)}
  .content{padding:var(--space-4)}
  .g4{grid-template-columns:repeat(2,minmax(0,1fr))}
  .g2{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div id="app"></div>
<div id="toast"></div>
<script>
(function () {
  "use strict";
  var BASE = __BASE_JSON__;
  var API = BASE + "/api";
  var S = { tab: "overview", data: null, timer: null };

  /* ---------- DOM helpers ---------- */
  function $(s, r) { return (r || document).querySelector(s); }
  function add(el, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { add(el, x); }); return; }
    el.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
  }
  function h(tag, attrs) {
    var el = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "class") el.className = v;
      else if (k === "html") el.innerHTML = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2).toLowerCase(), v);
      else el.setAttribute(k, v === true ? "" : v);
    });
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  var ICONS = {
    shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    home: '<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3A4 4 0 0 0 11 18.7l1-1"/>',
    layers: '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7 7 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 21h4l.5-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
    qr: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h3M20 17v4"/>',
    eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    eyeoff: '<path d="M3 3l18 18"/><path d="M10.6 6.1A10 10 0 0 1 12 6c6.4 0 10 6 10 6a17 17 0 0 1-3.2 3.9M6.6 7.6C3.7 9.3 2 12 2 12s3.6 6 10 6c1.4 0 2.7-.3 3.9-.8"/>',
    out: '<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3"/><path d="M10 17l-5-5 5-5M5 12h11"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    refresh: '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v5h-5"/>'
  };
  function icon(name) { return h("span", { class: "ico", html: '<svg viewBox="0 0 24 24" aria-hidden="true">' + (ICONS[name] || "") + "</svg>" }); }

  /* ---------- utilities ---------- */
  function toast(msg) {
    var t = $("#toast"); t.textContent = msg; t.classList.add("show");
    clearTimeout(toast._t); toast._t = setTimeout(function () { t.classList.remove("show"); }, 1800);
  }
  function copy(text) {
    function ok() { toast("Copied to clipboard"); }
    function fallback() {
      var ta = h("textarea", { style: "position:fixed;opacity:0;left:-9999px" });
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); ok(); } catch (e) { toast("Copy failed"); }
      document.body.removeChild(ta);
    }
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(ok, fallback);
    else fallback();
  }
  function api(path, body) {
    var opt = { method: body === undefined ? "GET" : "POST", headers: {}, credentials: "same-origin" };
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    return fetch(API + path, opt).then(function (r) {
      return r.json().catch(function () { return { ok: false, error: "Unexpected response" }; })
        .then(function (j) { j.status = r.status; return j; });
    }).catch(function () { return { ok: false, error: "Network error", status: 0 }; });
  }
  function fmtUptime(s) {
    var d = Math.floor(s / 86400), hr = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return d ? d + "d " + hr + "h" : hr ? hr + "h " + m + "m" : m + "m";
  }
  function abbr(s) { return s.length > 64 ? s.slice(0, 44) + "..." + s.slice(-14) : s; }
  function getTheme() { try { return localStorage.getItem("theme") || "auto"; } catch (e) { return "auto"; } }
  function setTheme(t) {
    try { localStorage.setItem("theme", t); } catch (e) { /* ignore */ }
    if (t === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", t);
  }
  setTheme(getTheme());

  /* ---------- components (mirror the Figma component set) ---------- */
  function btn(label, opts) {
    opts = opts || {};
    var el = h("button", { class: "btn" + (opts.kind ? " " + opts.kind : "") + (opts.small ? " sm" : "") + (opts.block ? " block" : ""), type: "button", disabled: opts.disabled, onclick: opts.onclick },
      opts.icon ? icon(opts.icon) : null, label);
    return el;
  }
  function badge(text, accent) { return h("span", { class: "label" + (accent ? " accent" : "") }, text); }
  function copyfield(text, full) {
    return h("div", { class: "copy" + (full ? " full" : "") }, h("code", {}, full ? text : abbr(text)),
      btn("Copy", { small: true, icon: "copy", onclick: function () { copy(text); } }));
  }
  function box(title, sub, bodyNodes, flush) {
    return h("section", { class: "box" },
      h("div", { class: "box-h" }, h("h3", {}, title), sub ? h("p", {}, sub) : null),
      h("div", { class: "box-b" + (flush ? " flush" : "") }, bodyNodes));
  }
  function confirmDialog(title, text, okLabel, danger) {
    return new Promise(function (resolve) {
      var bg = h("div", { class: "modal-bg" });
      function close(v) { document.body.removeChild(bg); resolve(v); }
      bg.appendChild(h("div", { class: "modal" }, h("h3", {}, title), h("p", {}, text),
        h("div", { class: "row" },
          btn("Cancel", { onclick: function () { close(false); } }),
          btn(okLabel, { kind: danger ? "danger" : "primary", onclick: function () { close(true); } }))));
      document.body.appendChild(bg);
    });
  }
  function passwordField(label, id) {
    var input = h("input", { class: "input", type: "password", id: id, autocomplete: "off", spellcheck: "false" });
    var eye = h("button", { class: "eye", type: "button", "aria-label": "Show password" }, icon("eye"));
    eye.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      eye.innerHTML = ""; eye.appendChild(icon(show ? "eyeoff" : "eye"));
    });
    return { input: input, el: h("div", { class: "field" }, h("label", { for: id }, label), h("div", { class: "input-wrap" }, input, eye)) };
  }
  function strength(pw) {
    var s = 0;
    if (pw.length >= 8) s++;
    if (pw.length >= 12) s++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
    if (/\\d/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    return Math.min(s, 4);
  }
  function meter() {
    var segs = [h("i"), h("i"), h("i"), h("i")]; var wrap = h("div", { class: "meter" }, segs);
    wrap.update = function (pw) {
      var s = pw ? Math.max(strength(pw), 1) : 0;
      var color = s <= 1 ? "var(--danger-fg)" : s === 2 ? "var(--attention-fg)" : "var(--success-fg)";
      segs.forEach(function (el, i) { el.style.background = i < s ? color : ""; });
    };
    return wrap;
  }
  function busy(b, on, label) { b.disabled = on; b.textContent = on ? "Please wait..." : label; }

  /* ---------- auth screens ---------- */
  function authShell(title, lead, body, step) {
    var col = h("div", { class: "auth-col" },
      h("div", { class: "logo" }, icon("shield")),
      h("h1", {}, title), lead ? h("p", { class: "lead" }, lead) : null,
      step ? h("div", { class: "steps" }, h("i", { class: step >= 1 ? "on" : "" }), h("i", { class: step >= 2 ? "on" : "" })) : null,
      h("div", { class: "auth-panel" }, body.panel), body.foot ? h("p", { class: "auth-foot" }, body.foot) : null);
    var root = $("#app"); root.innerHTML = "";
    root.appendChild(h("div", { class: "auth" }, col));
  }

  function renderLogin() {
    var pw = passwordField("Password", "pw");
    var err = h("p", { class: "err" });
    var b = btn("Sign in", { kind: "primary", block: true });
    function go() {
      err.textContent = ""; busy(b, true, "Sign in");
      api("/login", { password: pw.input.value }).then(function (r) {
        busy(b, false, "Sign in");
        if (r.ok) return boot();
        err.textContent = r.error || "Sign-in failed";
        pw.input.select();
      });
    }
    b.addEventListener("click", go);
    pw.input.addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
    authShell("Sign in to Console", null, { panel: [pw.el, err, b], foot: "Locked out? Delete panel_auth.json on the server and restart." });
    pw.input.focus();
  }

  function renderSetup() {
    var code = "";
    function stepOne() {
      var input = h("input", { class: "input code", id: "code", maxlength: "9", autocomplete: "off", spellcheck: "false", placeholder: "XXXX-XXXX" });
      var err = h("p", { class: "err" });
      var b = btn("Continue", { kind: "primary", block: true });
      function go() {
        err.textContent = ""; busy(b, true, "Continue");
        api("/setup/verify", { code: input.value }).then(function (r) {
          busy(b, false, "Continue");
          if (r.ok) { code = input.value; stepTwo(); } else { err.textContent = r.error || "Invalid code"; input.select(); }
        });
      }
      b.addEventListener("click", go);
      input.addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
      authShell("Verify this server", "Copy the verification code printed in your server console log and paste it below.",
        { panel: [h("div", { class: "field" }, h("label", { for: "code" }, "Verification code"), input,
          h("span", { class: "hint" }, "Shown only in the server console. Valid until the password is created.")), err, b] }, 1);
      input.focus();
    }
    function stepTwo() {
      var p1 = passwordField("New password", "p1"), p2 = passwordField("Confirm password", "p2");
      var m = meter(); var err = h("p", { class: "err" });
      var b = btn("Create password", { kind: "primary", block: true });
      p1.input.addEventListener("input", function () { m.update(p1.input.value); });
      function go() {
        err.textContent = "";
        if (p1.input.value.length < 8) { err.textContent = "Use at least 8 characters."; return; }
        if (p1.input.value !== p2.input.value) { err.textContent = "Passwords do not match."; return; }
        busy(b, true, "Create password");
        api("/setup", { code: code, password: p1.input.value }).then(function (r) {
          busy(b, false, "Create password");
          if (r.ok) return boot();
          err.textContent = r.error || "Setup failed";
          if (r.status === 403) stepOne();
        });
      }
      b.addEventListener("click", go);
      p2.input.addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
      p1.el.appendChild(m);
      authShell("Choose a password", "This password protects the console. Use 12+ characters with mixed types.", { panel: [p1.el, p2.el, err, b] }, 2);
      p1.input.focus();
    }
    stepOne();
  }

  /* ---------- app shell ---------- */
  var TABS = [
    { id: "overview", label: "Overview", icon: "home", lead: "Status of the services and quick access to your subscription." },
    { id: "subs", label: "Subscriptions", icon: "link", lead: "Add one of these URLs to your client. Each one is private to this server." },
    { id: "protocols", label: "Protocols", icon: "layers", lead: "Every active inbound with its share link." },
    { id: "settings", label: "Settings", icon: "gear", lead: "Password, appearance and sessions." }
  ];

  function renderApp() {
    var root = $("#app"); root.innerHTML = "";
    var cur = TABS.filter(function (t) { return t.id === S.tab; })[0];
    var navs = TABS.map(function (t) {
      return h("button", { class: "nav" + (S.tab === t.id ? " on" : ""), type: "button", onclick: function () { S.tab = t.id; renderApp(); } }, icon(t.icon), t.label);
    });
    var side = h("aside", { class: "side" },
      h("div", { class: "brand" }, h("div", { class: "logo s" }, icon("shield")), "Console"),
      navs, h("div", { class: "spacer" }),
      h("button", { class: "nav", type: "button", onclick: logout }, icon("out"), "Sign out"));
    var top = h("div", { class: "top" },
      h("div", { class: "crumb" }, "Console", h("span", { class: "sep" }, "/"), h("b", {}, cur.label)),
      h("div", { class: "row" },
        btn("Refresh", { small: true, icon: "refresh", onclick: function () { loadState(true); } }),
        btn("Theme", { small: true, icon: "sun", onclick: cycleTheme })));
    var content = h("div", { class: "content" },
      h("div", { class: "pagehead" }, h("h1", {}, cur.label), h("p", {}, cur.lead)), VIEWS[S.tab]());
    root.appendChild(h("div", { class: "shell" }, side, h("main", { class: "main" }, top, content)));
  }
  function cycleTheme() {
    var order = ["auto", "light", "dark"]; var n = order[(order.indexOf(getTheme()) + 1) % 3];
    setTheme(n); toast("Theme: " + n);
  }
  function logout() { api("/logout", {}).then(function () { stopTimer(); boot(); }); }
  function stopTimer() { if (S.timer) { clearInterval(S.timer); S.timer = null; } }
  function loadState(manual) {
    return api("/state").then(function (r) {
      if (r.status === 401) { stopTimer(); return boot(); }
      if (r.ok) { S.data = r.data; renderApp(); if (manual) toast("Refreshed"); }
    });
  }

  /* ---------- views ---------- */
  function tile(k, v) { return h("div", { class: "tile" }, h("div", { class: "k" }, k), h("div", { class: "v" }, v)); }
  var VIEWS = {
    overview: function () {
      var d = S.data; if (!d) return h("div", { class: "empty" }, "Loading...");
      var linkCount = d.groups.reduce(function (n, g) { return n + g.links.length; }, 0);
      var rows = d.services.map(function (s) {
        var pill = !s.enabled ? h("span", { class: "pill off" }, h("i"), "Disabled")
          : s.up ? h("span", { class: "pill ok" }, h("i"), "Running")
          : h("span", { class: "pill bad" }, h("i"), "Down");
        return h("div", { class: "svc" }, h("span", {}, s.name), pill);
      });
      return h("div", { class: "stack" },
        h("div", { class: "grid g4" }, tile("Public port", String(d.publicPort)), tile("Uptime", fmtUptime(d.uptime)), tile("Protocols", String(d.groups.length)), tile("Links", String(linkCount))),
        h("div", { class: "grid g2", style: "align-items:start" },
          box("Services", "Engines running on this server.", rows, true),
          box("Universal subscription", "Paste this into your client's subscription field.",
            [copyfield(d.sub.all), h("p", { class: "hint" }, "The path is random and private. Rotate it from Subscriptions if it leaks.")])));
    },
    subs: function () {
      var d = S.data; if (!d) return h("div", { class: "empty" }, "Loading...");
      var items = [
        ["Universal (base64)", "v2rayN, NekoBox, Hiddify, Streisand, Shadowrocket", d.sub.all],
        ["sing-box core only", "Hysteria2, WS, HTTPUpgrade, SS, SOCKS, REALITY, gRPC, ShadowTLS, VMess, Trojan", d.sub.sb],
        ["Xray-core only", "Argo, XHTTP, XHTTP-REALITY, VMess and Trojan over Xray", d.sub.xray],
        ["Clash Meta / Mihomo", "Full YAML profile", d.sub.clash]
      ];
      var list = items.map(function (it) {
        var qrBox = h("div", { class: "qr" });
        return h("div", { class: "card" },
          h("div", { class: "head" }, h("div", { class: "grow" }, h("div", { class: "sub-t" }, it[0]), h("div", { class: "s" }, it[1])),
            btn("QR", { small: true, icon: "qr", onclick: function () { toggleQr(qrBox, it[2]); } })),
          copyfield(it[2]), qrBox);
      });
      var rot = box("Subscription path", d.subFixed ? "The base path is pinned by SUB_PATH. Rotating changes the last part of every URL." : "Generate new random paths. Old subscription URLs stop working immediately.",
        [btn("Rotate path", { kind: "danger", icon: "refresh", onclick: rotateSub })]);
      return h("div", { class: "stack" }, list, rot);
    },
    protocols: function () {
      var d = S.data; if (!d) return h("div", { class: "empty" }, "Loading...");
      if (!d.groups.length) return h("div", { class: "box empty" }, "No protocols are active yet.");
      return h("div", { class: "grid g2", style: "align-items:start" }, d.groups.map(protoCard));
    },
    settings: function () {
      var d = S.data;
      var cur = passwordField("Current password", "cp"), n1 = passwordField("New password", "np1"), n2 = passwordField("Confirm new password", "np2");
      var m = meter(); n1.input.addEventListener("input", function () { m.update(n1.input.value); }); n1.el.appendChild(m);
      var err = h("p", { class: "err" });
      var save = btn("Update password", { kind: "primary" });
      save.addEventListener("click", function () {
        err.textContent = "";
        if (n1.input.value.length < 8) { err.textContent = "Use at least 8 characters."; return; }
        if (n1.input.value !== n2.input.value) { err.textContent = "Passwords do not match."; return; }
        busy(save, true, "Update password");
        api("/password", { current: cur.input.value, next: n1.input.value }).then(function (r) {
          busy(save, false, "Update password");
          if (r.ok) { toast("Password updated"); cur.input.value = n1.input.value = n2.input.value = ""; m.update(""); } else err.textContent = r.error || "Failed";
        });
      });
      var themeBtns = ["auto", "light", "dark"].map(function (t) {
        return btn(t.charAt(0).toUpperCase() + t.slice(1), { small: true, kind: getTheme() === t ? "primary" : "", onclick: function () { setTheme(t); renderApp(); } });
      });
      return h("div", { class: "stack" },
        box("Change password", "Other signed-in sessions are closed when the password changes.",
          [h("div", { style: "max-width:360px;display:flex;flex-direction:column;gap:12px" }, cur.el, n1.el, n2.el, err), save]),
        box("Appearance", "Follows your system by default.", [h("div", { class: "row" }, themeBtns)]),
        box("Sessions", "Sign out every browser, including this one.",
          [btn("Sign out everywhere", { kind: "danger", icon: "out", onclick: function () { api("/logout-all", {}).then(function () { stopTimer(); boot(); }); } })]),
        h("div", { class: "notice" }, "Forgot the password? Stop the server, delete " + (d ? d.authFile : "panel_auth.json") + " from the data folder, and start again. A new verification code will appear in the console."));
    }
  };

  function protoCard(g) {
    var shown = false;
    var qrBox = h("div", { class: "qr" });
    var linkHost = h("div", { class: "stack", style: "display:flex;flex-direction:column;gap:8px" });
    function paint() { linkHost.innerHTML = ""; g.links.forEach(function (l) { linkHost.appendChild(copyfield(l, shown)); }); }
    paint();
    var showBtn = btn("Show full", { small: true, onclick: function () { shown = !shown; showBtn.textContent = shown ? "Collapse" : "Show full"; paint(); } });
    var qrBtn = btn("QR", { small: true, icon: "qr", onclick: function () { toggleQr(qrBox, g.links[0]); } });
    return h("div", { class: "card" },
      h("div", { class: "head" }, h("div", { class: "avatar" }, g.title.charAt(0)), h("div", { class: "grow" }, h("div", { class: "t" }, g.title), h("div", { class: "s" }, g.subtitle))),
      h("div", { class: "badges" }, g.badges.map(function (b, i) { return badge(b, i === 0); })),
      linkHost, h("div", { class: "row" }, showBtn, qrBtn), qrBox);
  }

  /* ---------- QR (loaded on demand) ---------- */
  function toggleQr(box, text) {
    var open = !box.classList.contains("open");
    box.classList.toggle("open", open);
    if (!open || box.dataset.done) return;
    if (text.length > 1800) { box.textContent = "This link is too long for a QR code. Use the subscription URL instead."; box.style.color = "#333"; box.dataset.done = "1"; return; }
    function draw() {
      try {
        new window.QRCode(box, { text: text, width: 190, height: 190, colorDark: "#0b0f19", colorLight: "#ffffff", correctLevel: window.QRCode.CorrectLevel.M });
        box.dataset.done = "1";
      } catch (e) { box.textContent = "QR generation failed"; }
    }
    if (window.QRCode) return draw();
    var s = document.createElement("script");
    s.src = "https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js";
    s.onload = draw;
    s.onerror = function () { box.textContent = "QR library could not be loaded (needs internet access in this browser)."; box.style.color = "#333"; };
    document.head.appendChild(s);
  }

  function rotateSub() {
    confirmDialog("Rotate subscription path?", "Every existing subscription URL will stop working. You will need to re-add the new URL in your clients.", "Rotate", true).then(function (yes) {
      if (!yes) return;
      api("/rotate-sub", {}).then(function (r) {
        if (r.ok) { toast("Path rotated"); loadState(); } else toast(r.error || "Failed");
      });
    });
  }

  /* ---------- boot ---------- */
  function boot() {
    return api("/session").then(function (r) {
      if (r.mode === "app") {
        stopTimer();
        return loadState().then(function () { S.timer = setInterval(function () { loadState(); }, 30000); });
      }
      if (r.mode === "setup") return renderSetup();
      renderLogin();
    });
  }
  boot();
})();
</script>
</body>
</html>
`;

const NOT_FOUND_HTML = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>";

class PanelUI {
    static render(base) {
        return PANEL_HTML.replace("__BASE_JSON__", JSON.stringify(base));
    }
}

class PanelAuth {
    static init() {
        if (this.ready) return;
        this.ready = true;
        this.file = path.join(CONFIG.FILE_PATH, "panel_auth.json");
        this.record = null;
        this.sessions = new Map();
        this.attempts = new Map();
        this.setupFailures = 0;
        this.setupCode = null;
        try {
            const j = JSON.parse(fs.readFileSync(this.file, "utf8"));
            if (j && typeof j.salt === "string" && typeof j.hash === "string") this.record = j;
        } catch { /* not configured yet */ }
        if (!this.record) this.rotateSetupCode(false);
        const t = setInterval(() => this.sweep(), 5 * 60 * 1000);
        if (t.unref) t.unref();
    }

    static isConfigured() { return !!this.record; }

    /* One-time verification code: printed in the server console only */
    static rotateSetupCode(announce) {
        const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        let c = "";
        for (let i = 0; i < 8; i++) c += alphabet[crypto.randomInt(alphabet.length)];
        this.setupCode = c;
        this.setupFailures = 0;
        if (announce) this.printSetupBanner();
    }

    static printSetupBanner() {
        if (this.record || !this.setupCode) return;
        const line = "=".repeat(56);
        const code = `${this.setupCode.slice(0, 4)}-${this.setupCode.slice(4)}`;
        console.log(`\n${COLORS.bright}${COLORS.yellow}${line}${COLORS.reset}`);
        console.log(`${COLORS.bright}  PANEL SETUP REQUIRED${COLORS.reset}`);
        console.log(`  Open path:          ${COLORS.cyan}/${CONFIG.PANEL_PATH}${COLORS.reset}  (public port ${CONFIG.PORT})`);
        console.log(`  Verification code:  ${COLORS.bright}${COLORS.green}${code}${COLORS.reset}`);
        console.log(`${COLORS.bright}${COLORS.yellow}${line}${COLORS.reset}\n`);
    }

    static normalizeCode(v) { return String(v || "").toUpperCase().replace(/[^A-Z0-9]/g, ""); }

    static checkCode(v) {
        if (!this.setupCode) return false;
        const a = Buffer.from(this.normalizeCode(v));
        const b = Buffer.from(this.setupCode);
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    }

    /* Wrong setup code: count globally and rotate the code after 10 misses */
    static setupMiss() {
        this.setupFailures++;
        if (this.setupFailures >= 10) {
            Logger.warning("Too many wrong setup codes - a new verification code was generated");
            this.rotateSetupCode(true);
        }
    }

    static clientKey(req) { return (req.socket && req.socket.remoteAddress) || "unknown"; }

    static lockedFor(req) {
        const k = this.clientKey(req);
        const e = this.attempts.get(k);
        if (!e) return 0;
        if (e.until && e.until <= Date.now()) { this.attempts.delete(k); return 0; }
        return e.until > Date.now() ? Math.ceil((e.until - Date.now()) / 1000) : 0;
    }

    static fail(req) {
        const k = this.clientKey(req);
        const now = Date.now();
        let e = this.attempts.get(k);
        if (!e || now - e.first > 10 * 60 * 1000) e = { count: 0, first: now, until: 0 };
        e.count++;
        if (e.count >= 5) e.until = now + 10 * 60 * 1000;
        this.attempts.set(k, e);
    }

    static succeed(req) { this.attempts.delete(this.clientKey(req)); }

    static derive(password, salt) {
        return new Promise((resolve, reject) => {
            crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? reject(e) : resolve(k)));
        });
    }

    static async setPassword(password) {
        const salt = crypto.randomBytes(16);
        const key = await this.derive(String(password), salt);
        this.record = { salt: salt.toString("hex"), hash: key.toString("hex") };
        fs.writeFileSync(this.file, JSON.stringify(this.record), { mode: 0o600 });
        this.setupCode = null;
    }

    static async verify(password) {
        if (!this.record) return false;
        const key = await this.derive(String(password || ""), Buffer.from(this.record.salt, "hex"));
        const want = Buffer.from(this.record.hash, "hex");
        return key.length === want.length && crypto.timingSafeEqual(key, want);
    }

    static parseCookies(req) {
        const out = {};
        String(req.headers.cookie || "").split(";").forEach((p) => {
            const i = p.indexOf("=");
            if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
        });
        return out;
    }

    static startSession(req, res) {
        const tok = crypto.randomBytes(32).toString("hex");
        this.sessions.set(tok, { exp: Date.now() + 12 * 3600 * 1000 });
        const secure = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https" || req.secure;
        res.setHeader("Set-Cookie", `cs=${tok}; Path=/${CONFIG.PANEL_PATH}; Max-Age=43200; HttpOnly; SameSite=Strict${secure ? "; Secure" : ""}`);
        return tok;
    }

    static currentToken(req) { return this.parseCookies(req).cs || ""; }

    static endSession(req, res) {
        this.sessions.delete(this.currentToken(req));
        res.setHeader("Set-Cookie", `cs=; Path=/${CONFIG.PANEL_PATH}; Max-Age=0; HttpOnly; SameSite=Strict`);
    }

    static revokeAll(exceptToken) {
        for (const k of Array.from(this.sessions.keys())) if (k !== exceptToken) this.sessions.delete(k);
    }

    static isAuthed(req) {
        const tok = this.currentToken(req);
        const s = tok && this.sessions.get(tok);
        if (!s) return false;
        if (s.exp < Date.now()) { this.sessions.delete(tok); return false; }
        return true;
    }

    static sweep() {
        const now = Date.now();
        for (const [k, s] of this.sessions) if (s.exp < now) this.sessions.delete(k);
        for (const [k, e] of this.attempts) if ((e.until && e.until < now) || now - e.first > 20 * 60 * 1000) this.attempts.delete(k);
    }
}

// ========== HOUSEKEEPING (keeps the data folder small) ==========
class Housekeeping {
    /* Keep only the last keepBytes of a log file */
    static trimLog(file, keepBytes) {
        try {
            const st = fs.statSync(file);
            if (st.size <= keepBytes * 2) return 0;
            const fd = fs.openSync(file, "r");
            const buf = Buffer.alloc(keepBytes);
            fs.readSync(fd, buf, 0, keepBytes, st.size - keepBytes);
            fs.closeSync(fd);
            fs.writeFileSync(file, buf);
            return st.size - keepBytes;
        } catch { return 0; }
    }

    static logFiles() {
        return [
            PATHS.SB_LOG_FILE,
            PATHS.XRAY_LOG_FILE,
            PATHS.BOOT_LOG,
            path.join(CONFIG.FILE_PATH, "xcore.log")
        ];
    }

    /* The Xray release zip includes geo databases and docs that this setup never reads, so they are removed to save disk space. */
    static pruneXrayExtras() {
        let freed = 0;
        for (const f of ["geoip.dat", "geosite.dat", "LICENSE", "README.md"]) {
            const p = path.join(PATHS.XRAY_BASE_DIR, f);
            try { const s = fs.statSync(p).size; fs.unlinkSync(p); freed += s; } catch { /* not present */ }
        }
        return freed;
    }

    static dirSize(p) {
        let total = 0;
        try {
            for (const e of fs.readdirSync(p, { withFileTypes: true })) {
                const full = path.join(p, e.name);
                total += e.isDirectory() ? this.dirSize(full) : fs.statSync(full).size;
            }
        } catch { /* ignore */ }
        return total;
    }

    /* Runs on every start: remove leftovers of interrupted downloads, trim old logs */
    static run() {
        let freed = 0;
        const junkFile = /\.(zip|tar\.gz|tgz|tar|tmp|part|download|crdownload)$/i;
        const junkDir = /^(sing-box-.*-linux-.*|xray-extract.*|tmp-extract.*)$/i;

        for (const dir of [CONFIG.FILE_PATH, PATHS.SB_BASE_DIR, PATHS.XRAY_BASE_DIR]) {
            let entries = [];
            try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
            for (const e of entries) {
                const full = path.join(dir, e.name);
                try {
                    if (e.isFile() && junkFile.test(e.name)) {
                        freed += fs.statSync(full).size;
                        fs.unlinkSync(full);
                    } else if (e.isDirectory() && junkDir.test(e.name)) {
                        freed += this.dirSize(full);
                        fs.rmSync(full, { recursive: true, force: true });
                    }
                } catch { /* ignore */ }
            }
        }

        freed += this.pruneXrayExtras();
        for (const f of this.logFiles()) freed += this.trimLog(f, 64 * 1024);

        if (freed > 0) Logger.info(`Housekeeping freed ${(freed / 1048576).toFixed(1)} MB in ${CONFIG.FILE_PATH}`);
    }

    /* While running: truncate any log file that grows beyond 5 MB (child processes keep appending to them). */
    static startPeriodic() {
        if (this.timer) return;
        this.timer = setInterval(() => {
            for (const f of this.logFiles()) {
                try { if (fs.statSync(f).size > 5 * 1024 * 1024) fs.truncateSync(f, 0); } catch { /* ignore */ }
            }
        }, 6 * 3600 * 1000);
        if (this.timer.unref) this.timer.unref();
    }
}

// ========== VMESS / TROJAN INBOUNDS ==========
const PROTO_LABEL = { vmess: "VMess", trojan: "Trojan", vless: "VLESS" };

class Extras {
    static active(engine) {
        return EXTRA_DEFS.filter((d) => d.enabled && (!engine || d.engine === engine));
    }
    static anyXray() { return this.active("xray").length > 0; }
    static needsRealityKeys() { return this.active("xray").some((d) => d.transport.includes("reality")); }
    static disableEngine(engine) { EXTRA_DEFS.forEach((d) => { if (d.engine === engine) d.enabled = false; }); }
    static disableReality() { EXTRA_DEFS.forEach((d) => { if (d.transport.includes("reality")) d.enabled = false; }); }
    static bySni(sni) { return sni ? this.active().find((d) => d.route === "sni" && d.sni === sni) || null : null; }
    static pathRoute(urlPath) {
        const norm = (p) => p.replace(/\/+$/, "") || "/";
        return this.active("sb").find((d) => d.route === "path" && norm(d.path) === urlPath) || null;
    }

    /* Resolve SNI collisions and pick free local ports (called once, before the engines start) */
    static async prepare() {
        if (this.prepared) return;
        this.prepared = true;
        const used = new Map();
        if (CONFIG.ENABLE_REALITY) used.set(CONFIG.REALITY_TARGET, "VLESS-REALITY");
        if (CONFIG.ENABLE_GRPC) used.set(CONFIG.GRPC_SNI, "VLESS-gRPC");
        if (CONFIG.ENABLE_SHADOWTLS_VLESS) used.set(CONFIG.SHADOWTLS_VLESS_SNI, "ShadowTLS");
        if (CONFIG.ENABLE_XHTTP_REALITY) used.set(CONFIG.XHTTP_REALITY_TARGET, "VLESS-XHTTP-REALITY");

        for (const d of this.active()) {
            if (d.route !== "sni") continue;
            if (used.has(d.sni)) {
                Logger.warning(`${d.label}: SNI ${d.sni} is already used by ${used.get(d.sni)} - disabled (set ${d.id.toUpperCase().replace(/-/g, "_")}_SNI to a different host)`);
                d.enabled = false;
            } else {
                used.set(d.sni, d.label);
            }
        }

        const taken = new Set([CONFIG.VLESS_LOCAL_PORT, CONFIG.VLESS_HTTPUPGRADE_LOCAL_PORT, CONFIG.SS_PORT, CONFIG.SOCKS_PORT,
            CONFIG.SHADOWTLS_VLESS_PORT, CONFIG.HTTP_PROXY_PORT, CONFIG.GRPC_PORT, CONFIG.REALITY_PORT, CONFIG.XRAY_LOCAL_PORT, CONFIG.XHTTP_REALITY_PORT]);
        for (const d of this.active()) {
            let p = await getFreePort();
            for (let i = 0; i < 20 && taken.has(p); i++) p = await getFreePort();
            taken.add(p);
            d.port = p;
        }
        const n = this.active().length;
        if (n) Logger.info(`VMess/Trojan inbounds enabled: ${n}`);
    }

    static sbInbounds(cert, key) {
        return this.active("sb").map((d) => {
            const inbound = {
                "type": d.proto,
                "tag": `${d.id}-in`,
                "listen": "127.0.0.1",
                "listen_port": d.port,
                "users": d.proto === "vmess"
                    ? [{ "name": "user", "uuid": CONFIG.SB_UUID }]
                    : [{ "name": "user", "password": CONFIG.TROJAN_PASSWORD }]
            };
            if (d.route === "sni") {
                inbound.tls = {
                    "enabled": true,
                    "server_name": d.sni,
                    "certificate_path": cert,
                    "key_path": key,
                    ...(d.transport === "tls" ? { "alpn": ["h2", "http/1.1"] } : { "alpn": [d.alpn] })
                };
            } else {
                inbound.tls = { "enabled": false };
            }
            if (d.transport === "ws") {
                inbound.transport = { "type": "ws", "path": d.path, "max_early_data": 2560, "early_data_header_name": "Sec-WebSocket-Protocol" };
            } else if (d.transport === "httpupgrade") {
                inbound.transport = { "type": "httpupgrade", "path": d.path };
            } else if (d.transport === "grpc") {
                inbound.transport = { "type": "grpc", "service_name": d.service };
            }
            return inbound;
        });
    }

    static xrayInbounds() {
        return this.active("xray").map((d) => {
            let settings;
            if (d.proto === "vmess") settings = { "clients": [{ "id": CONFIG.SB_UUID }] };
            else if (d.proto === "trojan") settings = { "clients": [{ "password": CONFIG.TROJAN_PASSWORD }] };
            else settings = { "clients": [{ "id": CONFIG.SB_UUID, "flow": "" }], "decryption": CONFIG.XHTTP_REALITY_DECRYPTION };
            const reality = {
                "show": false,
                "target": `${d.sni}:443`,
                "xver": 0,
                "serverNames": [d.sni],
                "privateKey": CONFIG.XHTTP_REALITY_PRIVATE_KEY,
                "shortIds": [CONFIG.XHTTP_REALITY_SHORT_ID],
                ...(CONFIG.XRAY_REALITY_MLDSA ? { "mldsa65Seed": CONFIG.XHTTP_REALITY_MLDSA_SEED } : {})
            };
            let stream;
            if (d.transport === "xhttp") {
                stream = { "network": "xhttp", "security": "none", "xhttpSettings": { "path": d.path, "mode": CONFIG.XHTTP_MODE } };
            } else if (d.transport === "reality") {
                stream = { "network": "raw", "security": "reality", "realitySettings": reality };
            } else {
                stream = { "network": "xhttp", "security": "reality", "realitySettings": reality, "xhttpSettings": { "path": d.path, "mode": CONFIG.XHTTP_MODE } };
            }
            return { "tag": `${d.id}-in`, "listen": "127.0.0.1", "port": d.port, "protocol": d.proto, "settings": settings, "streamSettings": stream };
        });
    }

    static buildLink(d, host, name) {
        const port = CONFIG.PORT; // same number as the Hysteria2 listener
        const frag = encodeURIComponent(name);
        const q = (o) => Object.entries(o)
            .filter(([, v]) => v !== undefined && v !== "")
            .map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");

        if (d.proto === "vmess" && ["ws", "httpupgrade", "grpc", "tls"].includes(d.transport)) {
            // v2rayN-style base64 JSON (works in the widest range of clients)
            const j = { v: "2", ps: name, add: host, port: String(port), id: CONFIG.SB_UUID, aid: "0", scy: CONFIG.VMESS_CIPHER, net: "tcp", type: "none", host: "", path: "", tls: "" };
            if (d.transport === "ws" || d.transport === "httpupgrade") { j.net = d.transport; j.path = d.path; }
            if (d.transport === "grpc") { j.net = "grpc"; j.path = d.service; j.type = "gun"; }
            if (d.route === "sni") { j.tls = "tls"; j.sni = d.sni; j.alpn = d.alpn; j.fp = "chrome"; j.insecure = "1"; }
            return "vmess://" + Buffer.from(JSON.stringify(j)).toString("base64");
        }

        let params;
        if (d.transport === "xhttp") {
            params = { security: "none", type: "xhttp", path: d.path, mode: CONFIG.XHTTP_MODE };
        } else if (d.transport === "reality" || d.transport === "xhttp-reality") {
            params = { security: "reality", sni: d.sni, fp: "chrome", pbk: CONFIG.XHTTP_REALITY_PUBLIC_KEY, sid: CONFIG.XHTTP_REALITY_SHORT_ID };
            if (CONFIG.XRAY_REALITY_MLDSA) params.pqv = CONFIG.XHTTP_REALITY_MLDSA_VERIFY;
            if (d.transport === "reality") { params.type = "tcp"; params.headerType = "none"; params.spx = "/"; }
            else { params.type = "xhttp"; params.path = d.path; params.mode = CONFIG.XHTTP_MODE; }
        } else {
            params = { security: "tls", sni: d.sni, fp: "chrome", alpn: d.alpn, allowInsecure: "1" };
            if (d.transport === "ws" || d.transport === "httpupgrade") { params.type = d.transport; params.path = d.path; params.host = d.sni; }
            else if (d.transport === "grpc") { params.type = "grpc"; params.serviceName = d.service; params.mode = "gun"; }
            else { params.type = "tcp"; params.headerType = "none"; }
        }

        if (d.proto === "vless") return `vless://${CONFIG.SB_UUID}@${host}:${port}?${q({ encryption: CONFIG.XHTTP_REALITY_ENCRYPTION, ...params })}#${frag}`;
        if (d.proto === "vmess") return `vmess://${CONFIG.SB_UUID}@${host}:${port}?${q({ encryption: CONFIG.VMESS_CIPHER, ...params })}#${frag}`;
        return `trojan://${encodeURIComponent(CONFIG.TROJAN_PASSWORD)}@${host}:${port}?${q(params)}#${frag}`;
    }

    static async generateLinks() {
        const host = await SbManager.getServerHost();
        const isp = await SystemUtils.getISPInfo();
        EXTRA_DEFS.forEach((d) => { d.links = []; });
        for (const d of this.active()) {
            if (d.engine === "sb" && !state.sbProcess) continue;
            if (d.engine === "xray" && !state.xrayProcess) continue;
            d.name = `${d.label}-${isp}`;
            d.host = host;
            d.links = [this.buildLink(d, host, d.name)];
        }
    }

    static links(engine) {
        return EXTRA_DEFS.filter((d) => d.engine === engine).flatMap((d) => d.links);
    }

    static linesForFile() {
        const out = [];
        for (const d of EXTRA_DEFS) {
            if (!d.links.length) continue;
            out.push(`=== ${d.label} ===`, ...d.links, "");
        }
        return out;
    }

    static groups() {
        return EXTRA_DEFS.filter((d) => d.links.length).map((d) => {
            const isReality = d.transport.includes("reality");
            const sec = isReality ? "REALITY" : d.route === "sni" ? "TLS (self-signed)" : "No TLS";
            const extras = [];
            if (d.proto === "vless") extras.push(`VLESS encryption (${CONFIG.XHTTP_REALITY_ENC_MODE})`);
            if (d.proto === "vmess") extras.push(`cipher ${CONFIG.VMESS_CIPHER}`);
            if (isReality && CONFIG.XRAY_REALITY_MLDSA) extras.push("ML-DSA-65");
            const badges = [PROTO_LABEL[d.proto], d.transport.toUpperCase(), isReality ? "REALITY" : d.route === "sni" ? "TLS" : "No TLS"];
            if (d.proto === "vless") badges.push("Post-Quantum");
            return {
                id: d.id,
                title: d.label,
                subtitle: `${d.engine === "xray" ? "Xray-core" : "sing-box"} | ${sec}${d.sni ? " | SNI " + d.sni : ""}${extras.length ? " | " + extras.join(" + ") : ""} | same public port`,
                badges,
                links: d.links.slice()
            };
        });
    }

    /* Clash Meta / Mihomo blocks (XHTTP is skipped, same as the VLESS XHTTP links) */
    static clashProxies() {
        const y = (s) => ClashConverter.yamlString(s);
        const out = [];
        for (const d of this.active()) {
            if (!d.links.length || d.transport.startsWith("xhttp") || d.proto === "vless") continue;
            const isReality = d.transport === "reality";
            const tls = d.route === "sni" || isReality;
            const lines = [
                `  - name: ${y(d.name)}`,
                `    type: ${d.proto}`,
                `    server: ${y(d.host)}`,
                `    port: ${CONFIG.PORT}`
            ];
            if (d.proto === "vmess") lines.push(`    uuid: ${y(CONFIG.SB_UUID)}`, `    alterId: 0`, `    cipher: ${CONFIG.VMESS_CIPHER}`);
            else lines.push(`    password: ${y(CONFIG.TROJAN_PASSWORD)}`);
            lines.push(`    udp: true`);
            if (d.proto === "vmess") lines.push(`    tls: ${tls ? "true" : "false"}`);
            if (tls) {
                lines.push(`    ${d.proto === "vmess" ? "servername" : "sni"}: ${y(d.sni)}`);
                lines.push(`    client-fingerprint: "chrome"`);
                lines.push(`    skip-cert-verify: ${isReality ? "false" : "true"}`);
            }
            if (isReality) {
                lines.push(`    reality-opts:`, `      public-key: ${y(CONFIG.XHTTP_REALITY_PUBLIC_KEY)}`, `      short-id: ${y(CONFIG.XHTTP_REALITY_SHORT_ID)}`);
            }
            if (d.transport === "ws" || d.transport === "httpupgrade") {
                lines.push(`    network: ws`, `    ws-opts:`, `      path: ${y(d.path)}`);
                if (d.transport === "httpupgrade") lines.push(`      v2ray-http-upgrade: true`);
                lines.push(`      headers:`, `        Host: ${y(d.sni || d.host)}`);
            } else if (d.transport === "grpc") {
                lines.push(`    network: grpc`, `    grpc-opts:`, `      grpc-service-name: ${y(d.service)}`);
            } else {
                lines.push(`    network: tcp`);
            }
            out.push({ name: d.name, uri: d.links[0], yaml: lines.join("\n") });
        }
        return out;
    }
}

class HttpServer {
    /**
     * Create Express application (plain HTTP panel)
     */
    static createApp() {
        const app = express();

        PanelAuth.init();
        app.disable("x-powered-by");

        // Subscription endpoints live under a random, persisted path
        app.use((req, res, next) => {
            const base = `/${CONFIG.SUB_PATH}`;
            const p = req.path;
            if (!p.startsWith(base + "/")) return next();
            const seg = p.slice(base.length + 1).replace(/\/+$/, "");
            const t = CONFIG.SUB_TOKENS;
            if (seg === t.all) return this.sendSubscriptionRaw(res, "all");
            if (seg === t.sb) return this.sendSubscriptionRaw(res, "sb");
            if (seg === t.xray) return this.sendSubscriptionRaw(res, "xray");
            if (seg === t.clash) return this.sendSubscriptionClash(req, res);
            return next();
        });

        // Console (login + dashboard) under its own path
        app.use(`/${CONFIG.PANEL_PATH}`, this.createPanelRouter());

        // Minimal liveness probe (no internal details)
        app.get("/health", (req, res) => res.json({ ok: true }));

        // ---------- VLESS + XHTTP: reverse-proxy to Xray-core ----------
        if (CONFIG.ENABLE_XHTTP) {
            const xhttpPrefix = CONFIG.XHTTP_PATH.startsWith('/') ? CONFIG.XHTTP_PATH : `/${CONFIG.XHTTP_PATH}`;
            app.use(xhttpPrefix, (req, res) => {
                const proxyReq = http.request({
                    hostname: "127.0.0.1",
                    port: CONFIG.XRAY_LOCAL_PORT,
                    path: req.originalUrl,
                    method: req.method,
                    headers: req.headers
                }, (proxyRes) => {
                    res.writeHead(proxyRes.statusCode, proxyRes.headers);
                    proxyRes.pipe(res);
                });
                proxyReq.on("error", () => { try { res.destroy(); } catch { /* ignore */ } });
                req.on("error", () => { try { proxyReq.destroy(); } catch { /* ignore */ } });
                req.pipe(proxyReq);
            });
        }

        // VMess-XHTTP (Xray-core): one reverse-proxy per path
        for (const d of Extras.active("xray")) {
            if (d.transport !== "xhttp") continue;
            app.use(d.path, (req, res) => {
                const proxyReq = http.request({
                    hostname: "127.0.0.1",
                    port: d.port,
                    path: req.originalUrl,
                    method: req.method,
                    headers: req.headers
                }, (proxyRes) => {
                    res.writeHead(proxyRes.statusCode, proxyRes.headers);
                    proxyRes.pipe(res);
                });
                proxyReq.on("error", () => { try { res.destroy(); } catch { /* ignore */ } });
                req.on("error", () => { try { proxyReq.destroy(); } catch { /* ignore */ } });
                req.pipe(proxyReq);
            });
        }

        // Anything else looks like an empty server
        app.use((req, res) => {
            res.status(404).set("Content-Type", "text/html; charset=utf-8").send(NOT_FOUND_HTML);
        });

        return app;
    }

    /**
     * Start public HTTP server + WebSocket proxy to local VLESS
     * + a raw-TCP multiplexer so Shadowsocks/SOCKS5 can share the
     * SAME public port (Katabump's free plan only grants 1 allocation).
     *
     * How the mux decides where a new connection goes, by peeking at
     * its first bytes before anything else touches the socket:
     *   - starts with 0x05                -> SOCKS5 handshake  -> 127.0.0.1:SOCKS_PORT
     *   - not an HTTP method line (ASCII)  -> Shadowsocks       -> 127.0.0.1:SS_PORT
     *   - otherwise                        -> hand off to the HTTP/WS server
     *                                          (panel + VLESS-WS), unchanged
     * This only multiplexes TCP; Hysteria2 keeps using the same port
     * number over UDP separately (already true before this change).
     */
    static startServer() {
        const app = this.createApp();
        const httpServer = http.createServer(app);

        const wsPathNorm = (CONFIG.WS_PATH.startsWith('/') ? CONFIG.WS_PATH : `/${CONFIG.WS_PATH}`).replace(/\/+$/, '') || '/';
        const huPathNorm = (CONFIG.HTTPUPGRADE_PATH.startsWith('/') ? CONFIG.HTTPUPGRADE_PATH : `/${CONFIG.HTTPUPGRADE_PATH}`).replace(/\/+$/, '') || '/';

        httpServer.on("upgrade", (req, socket, head) => {
            try {
                const urlPath = (req.url || "/").split("?")[0].replace(/\/+$/, '') || '/';
                const matches = (base) =>
                    urlPath === base || urlPath === base + '/' || decodeURIComponent(urlPath) === base;

                let backendPort;
                if (matches(wsPathNorm)) {
                    backendPort = CONFIG.VLESS_LOCAL_PORT;
                } else if (CONFIG.ENABLE_HTTPUPGRADE && matches(huPathNorm)) {
                    backendPort = CONFIG.VLESS_HTTPUPGRADE_LOCAL_PORT;
                } else {
                    const hit = Extras.pathRoute(urlPath) || Extras.pathRoute(decodeURIComponent(urlPath));
                    if (hit) backendPort = hit.port;
                }

                if (!backendPort) {
                    socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
                    socket.destroy();
                    return;
                }

                // Pipe client socket <-> local VLESS backend (WS or HTTPUpgrade)
                const target = net.connect(backendPort, "127.0.0.1", () => {
                    // Rebuild the HTTP upgrade request for the backend
                    let reqLines = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
                    for (let i = 0; i < req.rawHeaders.length; i += 2) {
                        reqLines += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
                    }
                    reqLines += "\r\n";
                    target.write(reqLines);
                    if (head && head.length) target.write(head);

                    socket.pipe(target);
                    target.pipe(socket);
                });

                target.on("error", () => {
                    try { socket.destroy(); } catch { /* ignore */ }
                });
                socket.on("error", () => {
                    try { target.destroy(); } catch { /* ignore */ }
                });
            } catch {
                try { socket.destroy(); } catch { /* ignore */ }
            }
        });

        // ---------- Raw TCP mux in front of everything ----------
        const bridge = (socket, firstChunk, port, label) => {
            const target = net.connect(port, "127.0.0.1", () => {
                target.write(firstChunk);
                socket.pipe(target);
                target.pipe(socket);
                socket.resume();
            });
            target.on("error", () => {
                Logger.error(`${label} backend unreachable on 127.0.0.1:${port}`);
                try { socket.destroy(); } catch { /* ignore */ }
            });
            socket.on("error", () => {
                try { target.destroy(); } catch { /* ignore */ }
            });
        };

        const frontServer = net.createServer((socket) => {
            socket.once("data", (chunk) => {
                socket.pause();

                if (CONFIG.ENABLE_SOCKS && chunk.length >= 2 && chunk[0] === 0x05) {
                    bridge(socket, chunk, CONFIG.SOCKS_PORT, "SOCKS5");
                    return;
                }

                // Raw TLS ClientHello (record type 0x16, any TLS 1.x record version): choose the backend by SNI.
                if (chunk.length >= 3 && chunk[0] === 0x16 && chunk[1] === 0x03) {
                    const sni = extractSNI(chunk);
                    let target = null;
                    if (CONFIG.ENABLE_SHADOWTLS_VLESS && sni === CONFIG.SHADOWTLS_VLESS_SNI) {
                        target = [CONFIG.SHADOWTLS_VLESS_PORT, "ShadowTLS-VLESS"];
                    } else if (CONFIG.ENABLE_XHTTP_REALITY && sni === CONFIG.XHTTP_REALITY_TARGET) {
                        target = [CONFIG.XHTTP_REALITY_PORT, "XHTTP-REALITY"];
                    } else if (Extras.bySni(sni)) {
                        const d = Extras.bySni(sni);
                        target = [d.port, d.label];
                    } else if (CONFIG.ENABLE_REALITY && sni === CONFIG.REALITY_TARGET) {
                        target = [CONFIG.REALITY_PORT, "REALITY"];
                    } else if (CONFIG.ENABLE_GRPC && sni === CONFIG.GRPC_SNI) {
                        target = [CONFIG.GRPC_PORT, "VLESS-gRPC"];
                    } else if (CONFIG.ENABLE_REALITY) {
                        // Unknown/no SNI match: REALITY itself safely falls back
                        target = [CONFIG.REALITY_PORT, "REALITY(fallback)"];
                    } else if (CONFIG.ENABLE_SHADOWTLS_VLESS) {
                        target = [CONFIG.SHADOWTLS_VLESS_PORT, "ShadowTLS-VLESS(fallback)"];
                    }
                    if (target) {
                        bridge(socket, chunk, target[0], target[1]);
                        return;
                    }
                }

                // Plain HTTP proxy request (CONNECT, or an absolute-form request line such as "GET http://host/").
                if (CONFIG.ENABLE_HTTP_PROXY) {
                    const head = chunk.toString("latin1", 0, Math.min(chunk.length, 2048));
                    const isConnect = /^CONNECT /.test(head);
                    const isAbsoluteForm = /^(GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH|TRACE) https?:\/\//.test(head);
                    if (isConnect || isAbsoluteForm) {
                        bridge(socket, chunk, CONFIG.HTTP_PROXY_PORT, "HTTP-proxy");
                        return;
                    }
                }

                const looksLikeHttp = /^(GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH|TRACE) /.test(
                    chunk.toString("latin1", 0, Math.min(chunk.length, 8))
                );

                if (!looksLikeHttp && CONFIG.ENABLE_SS) {
                    bridge(socket, chunk, CONFIG.SS_PORT, "Shadowsocks");
                    return;
                }

                // Not SOCKS5 or Shadowsocks (or they are disabled), so hand the connection over to the normal HTTP/WebSocket server.
                socket.unshift(chunk);
                httpServer.emit("connection", socket);
                socket.resume();
            });

            socket.on("error", () => { /* ignore - client disconnected before sending data */ });
        });

        return new Promise((resolve, reject) => {
            frontServer.listen(CONFIG.PORT, "0.0.0.0", () => {
                Logger.success(`HTTP panel + WS proxy on 0.0.0.0:${CONFIG.PORT}`);
                if (CONFIG.ENABLE_SS || CONFIG.ENABLE_SOCKS) {
                    Logger.success(`SS/SOCKS5 muxed onto the same port ${CONFIG.PORT} (TCP only)`);
                }
                if (CONFIG.ENABLE_REALITY || CONFIG.ENABLE_SHADOWTLS_VLESS) {
                    Logger.success(`REALITY/ShadowTLS muxed onto the same port ${CONFIG.PORT} (routed by SNI)`);
                }
                if (CONFIG.ENABLE_HTTP_PROXY) {
                    Logger.success(`HTTP proxy muxed onto the same port ${CONFIG.PORT}`);
                }
                Logger.info(`Console: http://YOUR_IP:${CONFIG.PORT}/${CONFIG.PANEL_PATH}`);
                resolve(frontServer);
            });
            frontServer.on("error", (err) => {
                Logger.error(`HTTP server error: ${err.message}`);
                reject(err);
            });
        });
    }

    /**
     * Collect currently-active links into a single newline-separated
     * subscription body. `scope` selects which engine's links to include:
     *   "all"  -> everything (default, backward compatible with /sub/base64)
     *   "sb"   -> native sing-box core only (Hysteria2, VLESS-WS/HTTPUpgrade,
     *             SS, SOCKS5, ShadowTLS-VLESS)
     *   "xray" -> Xray-core only (VLESS-Argo, VLESS-XHTTP)
     */
    static buildSubscriptionContent(scope = "all") {
        const sbLinks = [
            ...state.sboxLinks,
            ...state.vlessWsLinks,
            ...state.vlessHuLinks,
            ...state.ssLinks,
            ...state.socksLinks,
            ...state.realityLinks,
            ...state.grpcLinks,
            ...state.shadowtlsVlessLinks,
            ...state.httpProxyLinks,
            ...Extras.links("sb")
        ];
        const xrayLinks = [
            ...state.xLinks,
            ...state.vlessXhttpLinks,
            ...state.vlessXhttpRealityLinks,
            ...Extras.links("xray")
        ];

        let links;
        if (scope === "sb") links = sbLinks;
        else if (scope === "xray") links = xrayLinks;
        else links = [...sbLinks, ...xrayLinks];

        return links.filter(Boolean).join('\n');
    }

    /**
     * Serve the raw subscription content - a base64 blob of all active links,
     * one per line before encoding. This is the URL you paste into a client's
     * "Add subscription" field (v2rayN, NekoBox, sing-box, Hiddify, Shadowrocket,
     * Streisand, etc). Plain Clash needs a converter (e.g. subconverter) since
     * it doesn't parse vless:// / hysteria2:// URIs natively.
     */
    static sendSubscriptionRaw(res, scope = "all") {
        const content = this.buildSubscriptionContent(scope);
        const b64 = Buffer.from(content, 'utf8').toString('base64');
        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.set('Cache-Control', 'no-store');
        // Hint some clients (Shadowrocket/v2rayN) use to auto-refresh the sub
        res.set('Profile-Update-Interval', '12');
        res.set('Content-Disposition', `inline; filename="subscription-${scope}"`);
        res.send(b64);
    }

    /**
     * Serve the Clash Meta / Mihomo YAML config. Add ?download=1 to force a
     * file download instead of an inline response.
     */
    static sendSubscriptionClash(req, res) {
        const yaml = ClashConverter.buildYaml();
        res.set('Content-Type', 'text/yaml; charset=utf-8');
        res.set('Cache-Control', 'no-store');
        res.set('Profile-Update-Interval', '12');
        const disposition = (req.query && (req.query.download === '1' || req.query.download === 'true'))
            ? 'attachment'
            : 'inline';
        res.set('Content-Disposition', `${disposition}; filename="xray-sing-clash.yaml"`);
        res.send(yaml);
    }

    /* ---------- Console API ---------- */

    static getProtocolGroups() {
        const groups = [];
        const push = (g) => { if (g.links && g.links.length) groups.push(g); };
        push({ id: 'hy2', title: 'Hysteria2', subtitle: 'High-speed UDP | Brutal congestion control', badges: ['UDP', 'QUIC', 'Port ' + CONFIG.SB_PORT], links: state.sboxLinks.slice() });
        push({ id: 'vless', title: 'VLESS-WS', subtitle: 'WebSocket over TCP | same public port', badges: ['TCP', 'WebSocket', 'No TLS'], links: state.vlessWsLinks.slice() });
        push({ id: 'argo', title: 'VLESS Argo', subtitle: 'Cloudflare Tunnel | CDN edge', badges: ['TLS', 'CDN', 'Argo'], links: state.xLinks.slice() });
        push({ id: 'vless-hu', title: 'VLESS-HTTPUpgrade', subtitle: 'HTTPUpgrade over TCP | same public port', badges: ['TCP', 'HTTPUpgrade', 'No TLS'], links: state.vlessHuLinks.slice() });
        push({
            id: 'vless-xhttp-reality', title: 'VLESS-XHTTP-REALITY',
            subtitle: `Xray-core | REALITY + VLESS encryption (${CONFIG.XHTTP_REALITY_ENC_MODE})${CONFIG.XHTTP_REALITY_MLDSA ? ' + ML-DSA-65' : ''} | SNI ${CONFIG.XHTTP_REALITY_TARGET}`,
            badges: ['TLS', 'REALITY', 'XHTTP', 'Post-Quantum'], links: state.vlessXhttpRealityLinks.slice()
        });
        push({ id: 'vless-xhttp', title: 'VLESS-XHTTP', subtitle: 'Xray-core | reverse-proxied on the same public port', badges: ['TCP', 'XHTTP', CONFIG.XHTTP_MODE], links: state.vlessXhttpLinks.slice() });
        push({ id: 'ss', title: 'Shadowsocks', subtitle: `${CONFIG.SS_METHOD} | same public port`, badges: ['TCP', 'Shadowsocks'], links: state.ssLinks.slice() });
        push({ id: 'socks', title: 'SOCKS5', subtitle: 'Unencrypted | same public port | local/LAN use recommended', badges: ['TCP', 'SOCKS5', 'No encryption'], links: state.socksLinks.slice() });
        push({ id: 'reality', title: 'VLESS-REALITY', subtitle: `Real TLS handshake with ${CONFIG.REALITY_TARGET} | same public port`, badges: ['TLS', 'REALITY', 'Camouflaged'], links: state.realityLinks.slice() });
        push({ id: 'grpc', title: 'VLESS-gRPC', subtitle: 'Self-signed TLS | same public port | client must allow insecure', badges: ['TLS', 'gRPC', 'Insecure cert'], links: state.grpcLinks.slice() });
        push({ id: 'shadowtls-vless', title: 'ShadowTLS (pure)', subtitle: `Real TLS handshake with ${CONFIG.SHADOWTLS_VLESS_SNI} | works where REALITY is filtered`, badges: ['TLS', 'ShadowTLS v3', 'Camouflaged'], links: state.shadowtlsVlessLinks.slice(0, 1) });
        push({ id: 'http-proxy', title: 'HTTP Proxy', subtitle: 'Plain HTTP CONNECT proxy | same public port', badges: ['HTTP', 'CONNECT'], links: state.httpProxyLinks.slice() });
        Extras.groups().forEach(push);
        return groups;
    }

    static buildPanelState(req) {
        const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "http").split(",")[0].trim();
        const host = req.headers.host || `127.0.0.1:${CONFIG.PORT}`;
        const origin = `${proto}://${host}/${CONFIG.SUB_PATH}`;
        const alive = (p) => !!(p && p.exitCode === null && !p.killed);
        return {
            publicPort: CONFIG.PORT,
            uptime: Math.floor(process.uptime()),
            groups: this.getProtocolGroups(),
            services: [
                { name: "sing-box", enabled: true, up: alive(state.sbProcess) },
                { name: "Xray-core", enabled: !!(CONFIG.ENABLE_XHTTP || CONFIG.ENABLE_XHTTP_REALITY || Extras.anyXray()), up: alive(state.xrayProcess) },
                { name: "Argo tunnel", enabled: !!CONFIG.ENABLE_ARGO, up: state.xLinks.length > 0 }
            ],
            sub: {
                all: `${origin}/${CONFIG.SUB_TOKENS.all}`,
                sb: `${origin}/${CONFIG.SUB_TOKENS.sb}`,
                xray: `${origin}/${CONFIG.SUB_TOKENS.xray}`,
                clash: `${origin}/${CONFIG.SUB_TOKENS.clash}`
            },
            subFixed: !!CONFIG.SUB_PATH_FIXED,
            authFile: "panel_auth.json"
        };
    }

    static createPanelRouter() {
        const router = express.Router();
        const api = express.Router();
        const wrap = (fn) => (req, res) => {
            Promise.resolve(fn(req, res)).catch(() => {
                if (!res.headersSent) res.status(500).json({ ok: false, error: "Server error" });
            });
        };
        const needAuth = (req, res, next) => {
            if (!PanelAuth.isAuthed(req)) return res.status(401).json({ ok: false, error: "Not signed in" });
            next();
        };
        const delay = (ms) => new Promise((r) => setTimeout(r, ms));
        const validPassword = (p) => typeof p === "string" && p.length >= 8 && p.length <= 128;

        router.use((req, res, next) => {
            res.set({
                "Cache-Control": "no-store",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "X-Robots-Tag": "noindex, nofollow",
                "Content-Security-Policy": "default-src 'none'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'unsafe-inline'; font-src https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            });
            next();
        });

        router.get("/", (req, res) => {
            res.type("html").send(PanelUI.render(`/${CONFIG.PANEL_PATH}`));
        });

        api.use(express.json({ limit: "8kb" }));
        api.use((req, res, next) => {
            if (req.method === "POST") {
                if (!req.is("application/json")) return res.status(415).json({ ok: false, error: "Unsupported request" });
                const origin = req.headers.origin;
                if (origin) {
                    try {
                        if (new URL(origin).host !== req.headers.host) return res.status(403).json({ ok: false, error: "Cross-origin request blocked" });
                    } catch { return res.status(403).json({ ok: false, error: "Bad origin" }); }
                }
            }
            next();
        });

        api.get("/session", (req, res) => {
            if (!PanelAuth.isConfigured()) return res.json({ ok: true, mode: "setup" });
            res.json({ ok: true, mode: PanelAuth.isAuthed(req) ? "app" : "login" });
        });

        api.post("/setup/verify", wrap(async (req, res) => {
            if (PanelAuth.isConfigured()) return res.status(409).json({ ok: false, error: "Setup is already complete" });
            const wait = PanelAuth.lockedFor(req);
            if (wait) return res.status(429).json({ ok: false, error: `Too many attempts. Try again in ${wait}s.` });
            if (!PanelAuth.checkCode(req.body && req.body.code)) {
                PanelAuth.fail(req);
                PanelAuth.setupMiss();
                await delay(400);
                return res.status(403).json({ ok: false, error: "That code is not correct. Copy it from the server console." });
            }
            PanelAuth.succeed(req);
            res.json({ ok: true });
        }));

        api.post("/setup", wrap(async (req, res) => {
            if (PanelAuth.isConfigured()) return res.status(409).json({ ok: false, error: "Setup is already complete" });
            const wait = PanelAuth.lockedFor(req);
            if (wait) return res.status(429).json({ ok: false, error: `Too many attempts. Try again in ${wait}s.` });
            if (!PanelAuth.checkCode(req.body && req.body.code)) {
                PanelAuth.fail(req);
                PanelAuth.setupMiss();
                await delay(400);
                return res.status(403).json({ ok: false, error: "Verification code expired or wrong. Start again." });
            }
            if (!validPassword(req.body.password)) return res.status(400).json({ ok: false, error: "Use 8 to 128 characters." });
            await PanelAuth.setPassword(req.body.password);
            PanelAuth.startSession(req, res);
            Logger.success("Panel password created");
            res.json({ ok: true });
        }));

        api.post("/login", wrap(async (req, res) => {
            if (!PanelAuth.isConfigured()) return res.status(409).json({ ok: false, error: "Setup is not complete" });
            const wait = PanelAuth.lockedFor(req);
            if (wait) return res.status(429).json({ ok: false, error: `Too many attempts. Try again in ${wait}s.` });
            const ok = await PanelAuth.verify(req.body && req.body.password);
            if (!ok) {
                PanelAuth.fail(req);
                await delay(500);
                return res.status(401).json({ ok: false, error: "Incorrect password" });
            }
            PanelAuth.succeed(req);
            PanelAuth.startSession(req, res);
            res.json({ ok: true });
        }));

        api.post("/logout", (req, res) => {
            PanelAuth.endSession(req, res);
            res.json({ ok: true });
        });

        api.post("/logout-all", needAuth, (req, res) => {
            PanelAuth.revokeAll(null);
            PanelAuth.endSession(req, res);
            res.json({ ok: true });
        });

        api.get("/state", needAuth, (req, res) => {
            res.json({ ok: true, data: this.buildPanelState(req) });
        });

        api.post("/password", needAuth, wrap(async (req, res) => {
            const wait = PanelAuth.lockedFor(req);
            if (wait) return res.status(429).json({ ok: false, error: `Too many attempts. Try again in ${wait}s.` });
            if (!(await PanelAuth.verify(req.body && req.body.current))) {
                PanelAuth.fail(req);
                await delay(500);
                return res.status(401).json({ ok: false, error: "Current password is incorrect" });
            }
            if (!validPassword(req.body.next)) return res.status(400).json({ ok: false, error: "Use 8 to 128 characters." });
            PanelAuth.succeed(req);
            await PanelAuth.setPassword(req.body.next);
            PanelAuth.revokeAll(PanelAuth.currentToken(req));
            res.json({ ok: true });
        }));

        api.post("/rotate-sub", needAuth, (req, res) => {
            // A pinned SUB_PATH stays; only the last part of every URL is rotated in that case
            if (!CONFIG.SUB_PATH_FIXED) {
                CONFIG.SUB_PATH = randomToken(24);
                Secrets.set("subPath", CONFIG.SUB_PATH);
            }
            const keys = { all: "subTokenAll", sb: "subTokenSb", xray: "subTokenXray", clash: "subTokenClash" };
            for (const k of Object.keys(keys)) {
                CONFIG.SUB_TOKENS[k] = randomToken(16);
                Secrets.set(keys[k], CONFIG.SUB_TOKENS[k]);
            }
            res.json({ ok: true });
        });

        api.use((err, req, res, next) => {
            res.status(400).json({ ok: false, error: "Bad request" });
        });
        api.use((req, res) => res.status(404).json({ ok: false, error: "Not found" }));

        router.use("/api", api);
        return router;
    }
}

// ========== MAIN APPLICATION ==========
class Application {
    /**
     * Initialize application
     */
    static async initialize() {
        SystemUtils.ensureDirectory(CONFIG.FILE_PATH);
        SystemUtils.ensureDirectory(PATHS.SB_BASE_DIR);
        SystemUtils.ensureDirectory(PATHS.XRAY_BASE_DIR);
        Housekeeping.run();
        Housekeeping.startPeriodic();

        // Persist UUID so restarts keep the same node id when UUID env is unset
        const uuidFile = path.join(CONFIG.FILE_PATH, "uuid.txt");
        if (!process.env.UUID && !process.env.SB_UUID) {
            try {
                if (fs.existsSync(uuidFile)) {
                    const saved = fs.readFileSync(uuidFile, "utf8").trim();
                    if (saved) {
                        CONFIG.UUID = saved;
                        CONFIG.SB_UUID = saved;
                    }
                } else {
                    fs.writeFileSync(uuidFile, CONFIG.UUID);
                }
            } catch {
                // ignore
            }
        }

        // Persist OBFS password - critical: random each boot would break client links
        const obfsFile = path.join(CONFIG.FILE_PATH, "obfs.txt");
        if (CONFIG.SB_OBFS_PWD) {
            try { fs.writeFileSync(obfsFile, CONFIG.SB_OBFS_PWD); } catch { /* ignore */ }
        } else {
            try {
                if (fs.existsSync(obfsFile)) {
                    CONFIG.SB_OBFS_PWD = fs.readFileSync(obfsFile, "utf8").trim();
                }
            } catch { /* ignore */ }
            if (!CONFIG.SB_OBFS_PWD) {
                CONFIG.SB_OBFS_PWD = crypto.randomBytes(16).toString("hex");
                try { fs.writeFileSync(obfsFile, CONFIG.SB_OBFS_PWD); } catch { /* ignore */ }
            }
        }
    }

    /**
     * Start the application
     */
    static async start() {
        Logger.header("Xray-Sing starting");

        await this.initialize();
        Logger.success(`Data directory: ${CONFIG.FILE_PATH}`);
        Logger.info(`Public port: ${CONFIG.PORT}  |  Argo: ${CONFIG.ENABLE_ARGO ? "on" : "off"}`);
        if (CONFIG.CPU_LIMIT_PERCENT) {
            const viaCpulimit = SystemUtils.commandExists("cpulimit");
            Logger.info(`CPU cap: ${CONFIG.CPU_LIMIT_PERCENT}% per engine (${viaCpulimit ? "via cpulimit" : "via built-in watchdog"})`);
        }

        if (process.env.ENABLE_SYSCTL === "1" || process.env.ENABLE_SYSCTL === "true") {
            SystemUtils.applySystemOptimizations();
        }

        Logger.step("[1/4] Starting sing-box (Hysteria2 + VLESS-WS)...");
        state.sbProcess = await SbManager.initialize();
        if (state.sbProcess) {
            await SbManager.generateLinks();
            Logger.success("sing-box is running");
            await verifyMuxedBackends();
        } else {
            Logger.error("sing-box failed to start");
            Extras.disableEngine("sb");
        }

        if (CONFIG.ENABLE_XHTTP || CONFIG.ENABLE_XHTTP_REALITY || Extras.anyXray()) {
            Logger.step("[2/4] Starting Xray-core (XHTTP / XHTTP-REALITY / VMess / Trojan)...");
            state.xrayProcess = await XCoreManager.initialize();
            if (state.xrayProcess) {
                await XCoreManager.generateLink();
                Logger.success("xray-core is running");
            } else {
                Logger.error("xray-core failed to start (XHTTP link will be unavailable)");
            }
        } else {
            Logger.info("[2/4] XHTTP disabled (ENABLE_XHTTP=0)");
        }

        await Extras.generateLinks();

        Logger.step("[3/4] Starting HTTP panel + WS proxy...");
        await HttpServer.startServer();
        Logger.success(`Panel ready on port ${CONFIG.PORT}`);

        if (CONFIG.ENABLE_ARGO) {
            Logger.step("[4/4] Starting Xray + Cloudflare Argo...");
            try {
                XManager.createConfiguration();
                await XManager.downloadAndRun();
                await new Promise((resolve) => setTimeout(resolve, 3000));
                await XManager.extractDomains();
                if (state.xLinks.length > 0) {
                    Logger.success("Argo tunnel is ready");
                } else {
                    Logger.warning("Argo link not ready (check boot.log)");
                }
            } catch (error) {
                // Argo is optional. If it fails (for example the disk is full), the other protocols keep working.
                Logger.error(`Argo/X setup failed: ${error.message} - continuing without it`);
            }
        } else {
            Logger.info("[4/4] Argo disabled (ENABLE_ARGO=0)");
        }

        await this.printAllLinks();
    }

    /**
     * Final summary for the user, then clear console after 3 minutes
     */
    static async printAllLinks() {
        const host = await SbManager.getServerHost();
        const webUrl = `http://${host}:${CONFIG.PORT}/${CONFIG.SUB_PATH}`;
        const panelUrl = `http://${host}:${CONFIG.PORT}/${CONFIG.PANEL_PATH}`;

        console.log("");
        Logger.header("READY");
        console.log(`${COLORS.bright}${COLORS.green}  All services are running${COLORS.reset}`);
        console.log("");
        console.log(`${COLORS.bright}  Console (login)${COLORS.reset}`);
        console.log(`  ${COLORS.yellow}${panelUrl}${COLORS.reset}`);
        PanelAuth.printSetupBanner();
        console.log("");
        console.log(`${COLORS.bright}  Subscription (universal, base64)${COLORS.reset}`);
        console.log(`  ${COLORS.yellow}${webUrl}/${CONFIG.SUB_TOKENS.all}${COLORS.reset}`);
        console.log("");
        console.log(`${COLORS.bright}  Subscription (sing-box core only)${COLORS.reset}`);
        console.log(`  ${COLORS.yellow}${webUrl}/${CONFIG.SUB_TOKENS.sb}${COLORS.reset}`);
        console.log("");
        console.log(`${COLORS.bright}  Subscription (Xray-core / Argo only)${COLORS.reset}`);
        console.log(`  ${COLORS.yellow}${webUrl}/${CONFIG.SUB_TOKENS.xray}${COLORS.reset}`);
        console.log("");
        console.log(`${COLORS.bright}  Subscription (Clash Meta / Mihomo)${COLORS.reset}`);
        console.log(`  ${COLORS.yellow}${webUrl}/${CONFIG.SUB_TOKENS.clash}${COLORS.reset}`);
        console.log("");

        if (state.sboxLinks.length > 0) {
            console.log(`${COLORS.bright}  Hysteria2${COLORS.reset}`);
            state.sboxLinks.forEach((link) => {
                console.log(`  ${COLORS.white}${link}${COLORS.reset}`);
            });
            console.log("");
        }

        if (state.vlessWsLinks.length > 0) {
            console.log(`${COLORS.bright}  VLESS-WS${COLORS.reset}`);
            state.vlessWsLinks.forEach((link) => {
                console.log(`  ${COLORS.white}${link}${COLORS.reset}`);
            });
            console.log("");
        }

        if (state.realityLinks.length > 0) {
            console.log(`${COLORS.bright}  VLESS-REALITY${COLORS.reset}`);
            state.realityLinks.forEach((link) => console.log(`  ${COLORS.white}${link}${COLORS.reset}`));
            console.log("");
        }

        if (state.vlessXhttpRealityLinks.length > 0) {
            console.log(`${COLORS.bright}  VLESS-XHTTP-REALITY${COLORS.reset}`);
            state.vlessXhttpRealityLinks.forEach((link) => console.log(`  ${COLORS.white}${link}${COLORS.reset}`));
            console.log("");
        }

        for (const g of Extras.groups()) {
            console.log(`${COLORS.bright}  ${g.title}${COLORS.reset}`);
            g.links.forEach((link) => console.log(`  ${COLORS.white}${link}${COLORS.reset}`));
            console.log("");
        }

        if (state.grpcLinks.length > 0) {
            console.log(`${COLORS.bright}  VLESS-gRPC${COLORS.reset}`);
            state.grpcLinks.forEach((link) => console.log(`  ${COLORS.white}${link}${COLORS.reset}`));
            console.log("");
        }

        if (state.shadowtlsVlessLinks.length > 0) {
            console.log(`${COLORS.bright}  ShadowTLS (pure)${COLORS.reset}`);
            console.log(`  ${COLORS.white}${state.shadowtlsVlessLinks[0]}${COLORS.reset}`);
            console.log(`  ${COLORS.dim}(sing-box outbound JSON below for chained-detour clients)${COLORS.reset}`);
            console.log(`  ${COLORS.white}${state.shadowtlsVlessLinks[1]}${COLORS.reset}`);
            console.log("");
        }

        if (state.httpProxyLinks.length > 0) {
            console.log(`${COLORS.bright}  HTTP proxy${COLORS.reset}`);
            state.httpProxyLinks.forEach((link) => console.log(`  ${COLORS.white}${link}${COLORS.reset}`));
            console.log("");
        }

        if (CONFIG.ENABLE_ARGO && state.xLinks.length > 0) {
            console.log(`${COLORS.bright}  VLESS Argo${COLORS.reset}`);
            state.xLinks.forEach((link) => {
                console.log(`  ${COLORS.white}${link}${COLORS.reset}`);
            });
            console.log("");
        }

        console.log(`${COLORS.dim}  Links also saved to: ${path.join(CONFIG.FILE_PATH, "links.txt")}${COLORS.reset}`);
        console.log(`${COLORS.dim}  Console will clear in 3 minutes...${COLORS.reset}`);
        console.log(`${COLORS.bright}${COLORS.cyan}${"=".repeat(56)}${COLORS.reset}`);
        console.log("");

        try {
            const linksFile = path.join(CONFIG.FILE_PATH, "links.txt");
            const lines = [
                `Console: ${panelUrl}`,
                "",
                "=== Hysteria2 ===",
                ...state.sboxLinks,
                "",
                "=== VLESS-WS ===",
                ...state.vlessWsLinks,
                "",
                "=== VLESS-REALITY ===",
                ...state.realityLinks,
                "",
                "=== VLESS-XHTTP-REALITY ===",
                ...state.vlessXhttpRealityLinks,
                "",
                ...Extras.linesForFile(),
                "=== VLESS-gRPC ===",
                ...state.grpcLinks,
                "",
                "=== ShadowTLS (pure) ===",
                ...state.shadowtlsVlessLinks,
                "",
                "=== HTTP proxy ===",
                ...state.httpProxyLinks,
            ];
            if (CONFIG.ENABLE_ARGO && state.xLinks.length) {
                lines.push("", "=== X/Argo ===", ...state.xLinks);
            }
            fs.writeFileSync(linksFile, lines.join("\n") + "\n");
        } catch {
            // silent
        }

        // Keep this timer on the event loop. It clears the console after 3 minutes without printing anything else.
        const clearTimer = setTimeout(() => {
            Logger.clearConsole();
            PanelAuth.printSetupBanner();
        }, 3 * 60 * 1000);
        // Do NOT unref - must fire while the server keeps running
        if (clearTimer.ref) clearTimer.ref();
    }
}

// ========== ERROR HANDLING & SHUTDOWN ==========
function shutdown(signal) {
    try {
        if (state.sbProcess && !state.sbProcess.killed) {
            state.sbProcess.kill("SIGTERM");
        }
    } catch { /* ignore */ }
    process.exit(signal === "SIGINT" ? 130 : 0);
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

process.on("uncaughtException", (error) => {
    Logger.error(`Uncaught Exception: ${error.message}`);
});

process.on("unhandledRejection", (reason) => {
    Logger.error(`Unhandled Rejection: ${reason}`);
});

// ========== APPLICATION START ==========
Application.start().catch((error) => {
    Logger.error(`Application failed to start: ${error.message}`);
    process.exit(1);
});
