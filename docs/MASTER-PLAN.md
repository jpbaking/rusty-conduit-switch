# Rusty Conduit Switch — Master Plan

> **Status:** Approved Design Blueprint (v1)  
> **Target Platforms:** Linux, Windows, macOS (cross-platform single binary, pure-Rust TLS stack)  
> **Series Lineage:** Combines the proxy & MITM engine of [`rusty-conduit`](../rusty-conduit), the `UpstreamDialer` & remote-DNS architecture of [`rusty-conduit-ssh`](../rusty-conduit-ssh), and the Auto Switch profile/rule model of [`air-switch`](../air-switch).

---

## 1. Overview & Core Principles

`rusty-conduit-switch` is a lightweight, cross-platform Rust CLI proxy server that listens for **HTTP/HTTPS** and **SOCKS4/SOCKS4a/SOCKS5** clients and **dynamically routes each connection** to named upstream proxies (`direct`, `block`, `http`, `https`, `socks4a`, `socks5`) or failover chains using ordered Auto Switch rules — with **opt-in pure-Rust HTTPS MITM inspection**, **atomic config hot-reload**, and **AirSwitch `.bak` import**.

### Non-Negotiable Principles
1. **Zero Caching (Except Bounded MITM Leaf Certificates):**
   - **No** HTTP response caching.
   - **No** custom DNS caching (direct dials delegate directly to the OS/Tokio resolver).
   - **No** full-body request/response buffering (strictly streaming).
   - The **only** in-memory cache is for dynamically signed MITM leaf TLS certificates, strictly bounded by a configurable TTL, max-entry cap, lazy read-time expiry, and a periodic background reaper.
2. **No Local DNS Leaks by Default:**
   - When a connection routes to an upstream proxy (`socks5`, `socks4a`, `http`, `https`), hostnames are sent **unresolved** (`ATYP=0x03`, SOCKS4a domain, or HTTP `CONNECT host:port`) so DNS resolves on the upstream side.
   - IP/CIDR rules match IP literals immediately without DNS. Matching *hostnames* against IP/CIDR rules via local DNS lookup is **OFF by default** and requires explicit opt-in (`resolve_dns = true` on a rule or globally).
3. **MITM is Opt-In & Never Auto-Generates a CA:**
   - MITM mode is **OFF** by default (no private CA configured).
   - Never auto-generates a root CA keypair. Users supply their own PEM or PKCS#12 CA.
4. **Pure-Rust TLS & Zero Native C Dependencies:**
   - Pure-Rust TLS (`rustls` + `ring`, `rcgen`, `p12-keystore`, `rustls-platform-verifier`) with **zero OpenSSL / aws-lc dependencies**, ensuring identical single-binary builds on Linux (`gnu`/`musl`), macOS (`arm64`/`x64`), and Windows (`x64`/`arm64`).
5. **Long-Lived Tunnel Resilience:**
   - No idle timeout on established tunnels, plus configurable TCP keepalive on client and upstream sockets (default `60s` idle / `10s` × `5` probes) so NAT, firewalls, and VPNs do not drop silent long-running connections.
6. **Zero-Downtime Hot-Reload Safety:**
   - Reloading routing rules and upstream profiles never drops in-flight connections and never replaces a working configuration with an invalid one (strict validate-before-swap).

---

## 2. Locked-In Design Decisions (v1)

| Area | Decision |
| :--- | :--- |
| **Ports & Multiplexing** | Separate ports by default (`3128` HTTP/HTTPS, `1080` SOCKS4/5). If both are set to the same port (`> 0`), automatically enable single-port first-byte protocol multiplexing. Setting either port to `0` disables that listener. |
| **Unified vs. Split Routing** | **One unified `[routing]` config by default** shared by both HTTP and SOCKS. Split behavior is optionally supported in two ways: (1) per-rule `inbound = "http" \| "socks"` matchers, and/or (2) optional `[routing.http]` / `[routing.socks]` override sections (each with its own `default` and `rules`). |
| **Upstream Protocols** | `direct`, `block`, `http` (optional Basic auth), `https` (HTTP proxy over `rustls` TLS, optional Basic auth), `socks5` (RFC 1928 + optional RFC 1929 user/pass auth, remote DNS `ATYP=0x03`), `socks4a` (remote DNS). |
| **Plain HTTP → HTTP Upstream** | When a plain HTTP request (`http://...`) routes to an `http` or `https` upstream proxy, forward in **absolute-form** (`GET http://host/path HTTP/1.1` + `Proxy-Authorization`) rather than forcing `CONNECT` to port 80, ensuring compatibility with corporate HTTP proxies. All other combinations (`CONNECT`, SOCKS, or plain HTTP → SOCKS/direct) use the unified `UpstreamDialer` tunnel. |
| **Failover Chains** | Any rule or default target may be a single profile name (`"corp"`) or an ordered failover list (`["corp", "backup", "direct"]`). Failover triggers only on TCP connect / proxy handshake failure — never mid-stream after bytes have flowed. |
| **Loop Prevention** | At startup and on every hot-reload, validate that no upstream profile points to the server's own listening `(bind, port)` (including `127.0.0.1`/`::1` when bound to `0.0.0.0`/`::`). Fail fast on startup; reject reload on hot-reload. |
| **MITM Scope** | HTTP/HTTPS `CONNECT` tunnels only (works with **any** upstream profile, including tunneling upstream TLS through `socks5`, `socks4a`, `http`, or `https` proxies). SOCKS remains a transparent L4 tunnel with optional `--socks-block-web`. |
| **Hot-Reload** | Atomic `ArcSwap` of the compiled routing table, upstream profiles, and global allow/block filter. Triggered by `SIGHUP` (Unix) and/or `--watch-config` (cross-platform debounced file watcher). Listener bind/ports, MITM CA, and log file paths require a restart. |
| **AirSwitch Import** | Built-in `import-airswitch` subcommand converts AirSwitch / ZeroOmega / SwitchyOmega `.bak` JSON files directly into a valid, commented `rusty-conduit-switch` TOML config, printing clear warnings for browser-only constructs (`PacProfile`, `SystemProfile`, URL rules on opaque tunnels). |
| **Inbound Auth & SOCKS Scope** | TCP only: SOCKS4, SOCKS4a, SOCKS5 `CONNECT` (IPv4, IPv6, Domain). No inbound proxy auth in v1 (prominent startup notice when binding to a non-loopback address). Outbound upstream proxy auth **is** supported in v1. |
| **Configuration & Logging** | Precedence: **CLI > Env (`RUSTY_CONDUIT_SWITCH_*`) > TOML (`--config`) > Defaults**. 6 log levels (`QUIET`, `FATAL`, `ERROR`, `INFO`, `DEBUG`, `VERBOSE`), `text` (logfmt) or `json` (NDJSON), with `profile=`, `rule=`, and `upstream=` fields on every access/SOCKS log entry. |

---

## 3. CLI & Configuration Interface

### Subcommands

```text
rusty-conduit-switch [OPTIONS]                       # Run the proxy server (default)
rusty-conduit-switch validate --config <PATH>        # Validate config & rules, exit 0/1
rusty-conduit-switch test-route --config <PATH> \    # Dry-run routing decision for a target
    [--inbound http|socks] <HOST[:PORT] | URL>
rusty-conduit-switch import-airswitch <BAK_PATH> \   # Convert AirSwitch .bak JSON to TOML
    [-o <OUT.toml>] [--profile <SWITCH_PROFILE_NAME>]
```

### Configuration Precedence (Server Mode)
1. CLI flags (highest priority)
2. Environment variables (`RUSTY_CONDUIT_SWITCH_*`)
3. TOML config file (`--config <PATH>`) — required for multi-profile routing; optional if running in simple default-direct mode
4. Built-in defaults

### Server Flags & Settings

| CLI Flag | Env Var | TOML Key | Default | Hot-Reloadable? | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `--config <PATH>` | `RUSTY_CONDUIT_SWITCH_CONFIG` | — | *(none)* | *(source)* | Path to TOML configuration file |
| `--watch-config` | `RUSTY_CONDUIT_SWITCH_WATCH_CONFIG` | `watch_config` | `false` | No | Watch `--config` for changes and hot-reload automatically |
| `--watch-debounce <DURATION>` | `RUSTY_CONDUIT_SWITCH_WATCH_DEBOUNCE` | `watch_debounce` | `300ms` | No | Debounce window for config file change events |
| `--bind <IP>` | `RUSTY_CONDUIT_SWITCH_BIND` | `bind` | `127.0.0.1` | No | IPv4 or IPv6 bind address |
| `--http-port <PORT>` | `RUSTY_CONDUIT_SWITCH_HTTP_PORT` | `http_port` | `3128` | No | HTTP/HTTPS proxy port (`0` to disable) |
| `--socks-port <PORT>` | `RUSTY_CONDUIT_SWITCH_SOCKS_PORT` | `socks_port` | `1080` | No | SOCKS4/4a/5 proxy port (`0` to disable) |
| `--connect-timeout <DURATION>` | `RUSTY_CONDUIT_SWITCH_CONNECT_TIMEOUT` | `connect_timeout` | `10s` | Yes | Upstream TCP + proxy handshake timeout per attempt |
| `--max-connections <N>` | `RUSTY_CONDUIT_SWITCH_MAX_CONNECTIONS` | `max_connections` | `4096` | No | Maximum concurrent client connections |
| `--tcp-keepalive <DURATION>` | `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE` | `tcp_keepalive` | `60s` | Yes | TCP keepalive idle time (`0` disables) |
| `--tcp-keepalive-interval <DURATION>` | `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_INTERVAL` | `tcp_keepalive_interval` | `10s` | Yes | Time between unanswered TCP keepalive probes |
| `--tcp-keepalive-retries <N>` | `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_RETRIES` | `tcp_keepalive_retries` | `5` | Yes | Unanswered probes before dropping socket |
| `--allow <RULE>` | `RUSTY_CONDUIT_SWITCH_ALLOW` | `allow` | *(none)* | Yes | Global destination allowlist (IP/CIDR/FQDN/`*.domain`); exceptions when combined with `--block` |
| `--block <RULE>` | `RUSTY_CONDUIT_SWITCH_BLOCK` | `block` | *(none)* | Yes | Global destination blocklist (combine with `--allow` for exceptions) |
| `--mitm-ca-cert <PATH>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_CERT` | `mitm.ca_cert` | *(none)* | No | PEM CA cert (enables MITM with `--mitm-ca-key`) |
| `--mitm-ca-key <PATH>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_KEY` | `mitm.ca_key` | *(none)* | No | PEM CA private key |
| `--mitm-ca-p12 <PATH>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_P12` | `mitm.ca_p12` | *(none)* | No | PKCS#12 CA bundle (enables MITM) |
| `--mitm-ca-passphrase <STR>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE` | `mitm.ca_passphrase` | *(none)* | No | CA passphrase (prefer env var or file) |
| `--mitm-ca-passphrase-file <PATH>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE_FILE` | `mitm.ca_passphrase_file` | *(none)* | No | File containing CA passphrase |
| `--mitm-cert-ttl <DURATION>` | `RUSTY_CONDUIT_SWITCH_MITM_CERT_TTL` | `mitm.cert_ttl` | `1h` | No | In-memory TTL for signed MITM leaf certs |
| `--mitm-cert-cache-max-entries <N>` | `RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX_ENTRIES` | `mitm.cert_cache_max_entries` | `10240` | No | Max entries in MITM leaf cert cache |
| `--socks-block-web` | `RUSTY_CONDUIT_SWITCH_SOCKS_BLOCK_WEB` | `socks_block_web` | `false` | No | Reject HTTP/HTTPS over SOCKS4/4a/5 (with or without MITM) |
| `--log-level <LEVEL>` | `RUSTY_CONDUIT_SWITCH_LOG_LEVEL` | `logging.level` | `INFO` | No | `QUIET`, `FATAL`, `ERROR`, `INFO`, `DEBUG`, `VERBOSE` |
| `--log-format <FMT>` | `RUSTY_CONDUIT_SWITCH_LOG_FORMAT` | `logging.format` | `text` | No | `text` (logfmt) or `json` (NDJSON) |
| `--http-access-log <PATH>` | `RUSTY_CONDUIT_SWITCH_HTTP_ACCESS_LOG` | `logging.http_access_log` | *(none)* | No | Optional file path for HTTP/HTTPS access logs |
| `--socks-log <PATH>` | `RUSTY_CONDUIT_SWITCH_SOCKS_LOG` | `logging.socks_log` | *(none)* | No | Optional file path for SOCKS4/4a/5 logs |

> **Hot-Reloadable Config Sections:** `[profiles.*]`, `[routing]` (including `rules`, `default`, `[routing.http]`, `[routing.socks]`, `resolve_dns`), `allow`, `block`, `connect_timeout`, `tcp_keepalive`, `tcp_keepalive_interval`, and `tcp_keepalive_retries` all hot-reload live. If a reload detects changes to non-reloadable fields (`bind`, `http_port`, `socks_port`, `mitm.*`, `logging.*`, `max_connections`), it logs a clear `INFO` warning stating which fields were ignored until restart, while still applying the reloadable routing/profile changes.

### Annotated Example `config.toml`

```toml
bind = "127.0.0.1"
http_port = 3128
socks_port = 1080
watch_config = true
connect_timeout = "10s"

# Built-in profiles "direct" and "block" always exist and need not be declared
# unless you want to customize them.

[profiles.corp]
type = "http"
host = "10.0.0.2"
port = 3128
username = "alice"
password_env = "CORP_PROXY_PASS"   # Preferred over plaintext `password`
bypass = ["127.0.0.1", "::1", "localhost", "*.local"]

[profiles.bastion]
type = "socks5"
host = "127.0.0.1"
port = 1081                        # e.g. an ssh -D or rusty-conduit-ssh listener

[profiles.secure_gw]
type = "https"
host = "proxy.example.com"
port = 8443
# tls_insecure_skip_verify = false  # Default false; uses OS trust store (rustls-platform-verifier)

[profiles.legacy_socks]
type = "socks4a"
host = "10.0.0.5"
port = 1080

# Unified Auto Switch routing (shared by HTTP and SOCKS)
[routing]
default = "direct"
resolve_dns = false                # Default false: never leak DNS locally for CIDR rules

[[routing.rules]]
name = "rfc1918-to-corp"
cidr = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
target = "corp"

[[routing.rules]]
name = "internal-domains-with-failover"
host_wildcard = ["*.internal.example", "dev-*.corp.net"]
target = ["bastion", "corp"]       # Ordered failover chain

[[routing.rules]]
name = "block-telemetry"
host_regex = "^telemetry\\..*\\.example\\.com$"
target = "block"

[[routing.rules]]
name = "ssh-over-bastion"
port = [22, "2200-2299"]
target = "bastion"

[[routing.rules]]
name = "socks-only-override"
inbound = "socks"                  # Optional per-protocol filter within unified rules
host_wildcard = ["*.db.internal"]
target = "bastion"

[[routing.rules]]
name = "plain-http-or-mitm-path"
url_wildcard = ["http://downloads.example.com/private/*"]
target = "corp"                    # Only matches when full URL is visible (HTTP or MITM HTTPS)

# Optional split config overrides (completely omitted in unified mode):
# [routing.socks]
# default = "bastion"
# [[routing.socks.rules]]
# host_wildcard = ["*.local"]
# target = "direct"
```

---

## 4. Routing Engine (`src/router/`)

### Evaluation Model
1. **Global Egress Filter (`allow` / `block`):** If `allow` or `block` is configured, evaluate it first. Denied targets are immediately rejected with `status=denied_by_filter`.
2. **Active Rule Table Selection:**
   - If the inbound protocol is HTTP/HTTPS and `[routing.http]` is present, evaluate `[routing.http].rules` with fallback `[routing.http].default` (or fall back to unified `[routing]` if `inherit = true`).
   - If the inbound protocol is SOCKS and `[routing.socks]` is present, evaluate `[routing.socks].rules` with fallback `[routing.socks].default`.
   - Otherwise evaluate the unified `[routing].rules` in top-to-bottom order, falling back to `[routing].default` (default `"direct"`).
3. **Rule Matching (Logical AND across fields within a rule, Logical OR across values within a field):**
   A single `[[routing.rules]]` entry matches if **every** specified condition field matches (and within a list like `host_wildcard = ["a", "b"]`, matching *any* element satisfies that field).

### Supported Condition Types

| TOML Field | Semantics | Works on HTTP | Works on HTTPS `CONNECT` (no MITM) | Works on HTTPS (MITM) | Works on SOCKS |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `inbound` | `"http"` or `"socks"` | Yes | Yes | Yes | Yes |
| `host` | Exact case-insensitive FQDN (trailing dot stripped) | Yes | Yes | Yes | Yes |
| `host_wildcard` | AirSwitch-compatible wildcards: `*.example.com` (apex + subdomains), `**.example.com` (subdomains only), `*`, `?` | Yes | Yes | Yes | Yes |
| `host_regex` | Compiled Rust `regex::Regex` against normalized host | Yes | Yes | Yes | Yes |
| `cidr` / `ip` | IPv4/IPv6 literal or CIDR (canonicalizes IPv4-mapped IPv6 `::ffff:a.b.c.d`). Matches IP literals directly; matches hostnames only if `resolve_dns = true` | Yes | Yes | Yes | Yes |
| `port` | Single port (`443`), list (`[80, 443]`), or inclusive range (`"8000-8080"`) | Yes | Yes | Yes | Yes |
| `host_levels` | Dot-count / label-count range (`min`, `max`), matching AirSwitch `HostLevelsCondition` | Yes | Yes | Yes | Yes |
| `bypass` | Chromium/AirSwitch bypass syntax (`<local>`, `*.domain`, `10.0.0.0/8`, `host:port`) | Yes | Yes | Yes | Yes |
| `weekday` | Local day of week (`mon`..`sun`, range or list) | Yes | Yes | Yes | Yes |
| `time` | Local hour/time window (`"09:00-17:30"`, supports wrap-around midnight) | Yes | Yes | Yes | Yes |
| `url_wildcard` | Shell wildcard against full URL (`http://...` or `https://...`) | Yes | No *(never matches)* | Yes *(per-request)* | No *(never matches)* |
| `url_regex` | Regex against full URL | Yes | No *(never matches)* | Yes *(per-request)* | No *(never matches)* |
| `keyword` | Substring match against full URL (AirSwitch `KeywordCondition`) | Yes | No *(never matches)* | Yes *(per-request)* | No *(never matches)* |
| `disabled` | `true` skips the rule (preserves AirSwitch `FalseCondition` during import) | — | — | — | — |

> **Startup / Reload Warning for URL Rules:** If `url_wildcard`, `url_regex`, or `keyword` rules exist in a rule table used by SOCKS or non-MITM HTTPS `CONNECT`, log an `INFO` notice explaining that those rules will only evaluate on plain HTTP (and decrypted MITM HTTPS) requests.

### Profile-Level Bypass & Per-Scheme Proxy (AirSwitch Parity)
To preserve full fidelity with AirSwitch's `FixedProfile`:
- Any non-`direct`/non-`block` profile may declare an optional `bypass = [...]` list (using `bypass` condition syntax). If a routed target matches the selected profile's `bypass` list, it automatically resolves to `direct` (logged as `profile=<name>(bypass->direct)`).
- A profile may also be a `composite` / `fixed` profile with optional `http_proxy`, `https_proxy`, and `fallback_proxy` sub-targets (used when importing AirSwitch `FixedProfile`s that configure separate proxies per scheme).

### MITM + Per-Request URL Routing
When MITM is **ON** for an HTTPS `CONNECT` tunnel:
- If no URL-level rules (`url_wildcard`, `url_regex`, `keyword`) are configured, the upstream route is resolved once at `CONNECT` time (using SNI/authority + port), and the upstream TLS connection is reused across requests on that tunnel.
- If URL-level rules **are** configured, each decrypted HTTPS request evaluates the router with the full `https://host/path?query` URL; if consecutive requests on the same client connection resolve to different upstream profiles, the MITM handler dials the appropriate upstream profile for each request.

---

## 5. Upstream Dialer & Proxy Chaining Layer (`src/upstream/`)

### Core Abstraction
```rust
pub struct RouteRequest<'a> {
    pub inbound: InboundProto,          // Http | Socks
    pub host: &'a str,                  // Normalized hostname or IP literal (no brackets)
    pub port: u16,
    pub scheme: Option<&'a str>,        // Some("http") | Some("https") | None
    pub url: Option<&'a str>,           // Full URL when visible (plain HTTP or MITM HTTPS)
}

pub enum UpstreamStream {
    Tcp(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>), // Used when talking to an `https` proxy
}

pub trait UpstreamDialer: Send + Sync {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_>;
}
```

### Built-In Upstream Implementations
1. **`DirectDialer` (`direct`):**
   - Resolves `host:port` via OS/Tokio DNS (`lookup_host`), applies TCP keepalive and `TCP_NODELAY`, and connects directly.
2. **`BlockDialer` (`block`):**
   - Immediately returns a typed `RouteBlocked` error (`ErrorKind::PermissionDenied`) without touching DNS or the network.
   - HTTP returns `403 Forbidden`; SOCKS5 returns reply `0x02` (Connection not allowed by ruleset); SOCKS4 returns `0x5B` (Request rejected).
3. **`Socks5Dialer` (`socks5`):**
   - Connects TCP to upstream SOCKS5 proxy, negotiates `0x00` (No Auth) or `0x02` (RFC 1929 Username/Password), sends `CMD=CONNECT (0x01)` with `ATYP=0x03` for hostnames (remote DNS) or `0x01`/`0x04` for IP literals.
4. **`Socks4aDialer` (`socks4a`):**
   - Connects TCP to upstream SOCKS4a proxy, sends `0x04 0x01 <port> 0.0.0.1 <userid>\0 <hostname>\0` for hostnames (remote DNS) or IPv4 bytes for IPv4 literals. Rejects IPv6 literals cleanly (or falls over to next target in chain).
5. **`HttpConnectDialer` (`http`) & `HttpsConnectDialer` (`https`):**
   - Connects TCP (and wraps in `tokio-rustls` TLS using `rustls-platform-verifier` for `https` upstreams).
   - For tunnels (`CONNECT`, SOCKS, MITM): sends `CONNECT <host>:<port> HTTP/1.1` with `Host` and optional `Proxy-Authorization: Basic <base64>` header, parses the status line + headers, verifies `2xx`, and returns the raw tunnel stream (preserving any unread buffered bytes after `\r\n\r\n` via a `PrefixedStream` wrapper).
   - For **plain HTTP** requests forwarded to an `http`/`https` upstream: `http/forward.rs` detects that the resolved profile is an HTTP/HTTPS upstream and forwards the request in **absolute-form** (`GET http://host:port/path HTTP/1.1`) with `Proxy-Authorization` directly to the upstream proxy instead of issuing `CONNECT` to port 80.
6. **`FailoverDialer` (`target = ["a", "b", "direct"]`):**
   - Iterates through the configured target list in order.
   - Each attempt is bounded by `connect_timeout`.
   - If an attempt fails with a connection/handshake error (and not `RouteBlocked`), logs at `DEBUG` and advances to the next target.
   - Returns the first successful stream along with metadata (`chosen_profile`, `attempt_index`) for access logging.

### Credential Handling
- Upstream profiles support `username` + `password` OR `password_env = "ENV_VAR_NAME"` OR `password_file = "/path/to/secret"`.
- Startup/reload validation rejects ambiguous password sources (e.g., setting both `password` and `password_env`).
- Credentials are **never** printed in logs (`INFO`/`DEBUG`/`VERBOSE`) or error messages; URLs/profiles are redacted in diagnostics.

---

## 6. Hot-Reload Engine (`src/reload.rs`)

### Architecture
- All hot-reloadable state lives in an immutable `Arc<RuntimeConfig>` stored inside an `ArcSwap<RuntimeConfig>` (from the `arc-swap` crate — lock-free reads on every connection).
- Each accepted connection (or decrypted MITM request) calls `state.load()` once, holding an `Arc<RuntimeConfig>` snapshot for the lifetime of that connection/request.
- **Zero disruption:** In-flight tunnels keep using their existing `TcpStream` and `Arc<RuntimeConfig>` until they close naturally; new connections immediately see the new routing table.

### Reload Triggers
1. **`SIGHUP` (Unix — Linux & macOS):** Always enabled when `--config` is provided.
2. **File Watcher (`--watch-config`, all platforms):** Uses the `notify` crate watching the parent directory of `--config` (necessary to catch atomic rename-over-file saves by `vim`, `nano`, VS Code, etc.), filtering events to the target filename, with a configurable debounce timer (`--watch-debounce`, default `300ms`).

### Validate-Before-Swap Protocol
1. Read and parse the TOML file from disk.
2. Re-apply CLI/env overrides for reloadable fields.
3. Compile all regexes, wildcards, CIDRs, bypass lists, and upstream dialers; run full validation (missing profile refs, loop detection against active listener addresses, duplicate/invalid syntax).
4. **On failure:** Log a detailed `ERROR` message (with line/rule details) and **keep the previous `Arc<RuntimeConfig>` active**. Never crash the running server on a bad reload.
5. **On success:** Atomically `store(Arc::new(new_cfg))`, increment a `config_generation: u64` counter, and log an `INFO` summary (`config reloaded generation=N profiles=P rules=R`).

---

## 7. AirSwitch `.bak` Importer (`src/import/airswitch.rs`)

`rusty-conduit-switch import-airswitch <OmegaOptions.bak> [-o config.toml] [--profile <name>]` parses the JSON backup exported by AirSwitch (as well as legacy ZeroOmega / SwitchyOmega `.bak` files).

### Profile Mapping

| AirSwitch `profileType` | Conversion to `rusty-conduit-switch` TOML |
| :--- | :--- |
| `DirectProfile` (`+direct`) | Built-in `direct` profile |
| `FixedProfile` | `[profiles.<slug>]` with `type` (`http`, `https`, `socks4a`, `socks5`), `host`, `port`, optional `username`/`password` (from `auth.fallbackProxy` or `auth.all`), and `bypass` (from `bypassList`). If `proxyForHttp`/`proxyForHttps` differ from `fallbackProxy`, emits per-scheme sub-profiles or a composite profile. |
| `SwitchProfile` | Selected as `[routing]` (if `--profile` is given, use that SwitchProfile; otherwise auto-select the active/only `SwitchProfile`, or error listing available ones). Nested `SwitchProfile`s are flattened in evaluation order with cycle detection. |
| `VirtualProfile` | Resolved to its `defaultProfileName` target. |
| `SwitchyRuleListProfile` / `AutoProxyRuleListProfile` | If inline `ruleList` text is present in the `.bak`, parse supported host/wildcard/regex lines into `[[routing.rules]]` with comments; warn on unsupported AdBlock/AutoProxy modifiers. (AirSwitch is strictly offline, so remote `sourceUrl`s are ignored/warned.) |
| `SystemProfile` (`+system`) | Emit warning (`SystemProfile has no server-side equivalent; mapped to "direct"`). |
| `PacProfile` / `AutoDetectProfile` | Emit warning (`JavaScript PAC scripts are not executed; skipped — convert rules manually`). |

### Condition Mapping

| AirSwitch `conditionType` | TOML Rule Field | Notes |
| :--- | :--- | :--- |
| `HostWildcardCondition` | `host_wildcard = [...]` | Splits `\|`-delimited patterns; preserves `*.` (apex+subdomains) vs `**.` (subdomains only) semantics |
| `HostRegexCondition` | `host_regex = "..."` | Validated with Rust `regex` crate; warns if PCRE lookarounds are used |
| `IpCondition` | `cidr = ["<ip>/<prefixLength>"]` | First-class in AirSwitch; preserves IPv4 and IPv6 |
| `BypassCondition` | `bypass = ["..."]` | Preserves `<local>`, `host:port`, CIDR, and wildcard patterns |
| `UrlWildcardCondition` | `url_wildcard = [...]` | Emits comment + warning that URL rules only match plain HTTP or MITM HTTPS |
| `UrlRegexCondition` | `url_regex = "..."` | Same HTTP/MITM notice |
| `KeywordCondition` | `keyword = ["..."]` | Same HTTP/MITM notice |
| `HostLevelsCondition` | `host_levels = { min = M, max = N }` | Exact parity |
| `WeekdayCondition` | `weekday = [...]` | Exact parity |
| `TimeCondition` | `time = ["HH:00-HH:59"]` | Exact parity |
| `TrueCondition` | `match_all = true` | Matches unconditionally |
| `FalseCondition` | `disabled = true` | Preserved in output as disabled rule |

- Profile names are deterministically slugified to safe TOML keys (e.g., `"Work Proxy"` → `work_proxy`), with collision disambiguation and a `# Imported from AirSwitch profile "..."` header comment.
- Output goes to `stdout` by default or `-o <path>` (refusing to overwrite an existing file unless `--force` is passed).

---

## 8. System Architecture & Module Layout

```text
rusty-conduit-switch/
├── Cargo.toml
├── Dockerfile
├── README.md
├── LICENSE                          # BSD-3-Clause (matching rusty-conduit series)
├── docs/
│   ├── MASTER-PLAN.md               # This blueprint
│   ├── USER-GUIDE.md                # Full CLI/env/TOML, routing, hot-reload & AirSwitch import guide
│   └── MITM-CA-GUIDE.md             # Generating & trusting a PEM / PKCS#12 CA
├── src/
│   ├── main.rs                      # Entrypoint, subcommand dispatch, signal handling
│   ├── lib.rs                       # Library root & server bootstrap
│   ├── config.rs                    # CLI (clap) + env + TOML parsing & validation
│   ├── reload.rs                    # ArcSwap state, SIGHUP + debounced file watcher
│   ├── logging.rs                   # 6-level diagnostic logger + HTTP/SOCKS log sinks (with route fields)
│   ├── server.rs                    # Separate/mux listeners, connection cap, graceful shutdown
│   ├── mux.rs                       # Single-port first-byte protocol sniffer
│   ├── filter.rs                    # Global destination allowlist/blocklist (IP/CIDR/FQDN/wildcard)
│   ├── net.rs                       # TCP keepalive, PrefixedStream, bidirectional byte-counting relay
│   ├── router/
│   │   ├── mod.rs                   # Router, RouteDecision, unified & split rule tables
│   │   ├── condition.rs             # Compiled matchers (host wildcard/regex, CIDR, bypass, URL, port, time)
│   │   └── validate.rs              # Profile ref checks, cycle detection, self-loop detection
│   ├── upstream/
│   │   ├── mod.rs                   # UpstreamDialer trait, UpstreamStream, FailoverDialer
│   │   ├── direct.rs                # DirectDialer (OS DNS + keepalive)
│   │   ├── block.rs                 # BlockDialer (RouteBlocked)
│   │   ├── socks5.rs                # RFC 1928 + RFC 1929 SOCKS5 client dialer (remote DNS)
│   │   ├── socks4a.rs               # SOCKS4a client dialer (remote DNS)
│   │   └── http.rs                  # HTTP & HTTPS CONNECT client dialer + Basic auth
│   ├── import/
│   │   ├── mod.rs                   # Importer entry & TOML serializer
│   │   └── airswitch.rs             # AirSwitch / ZeroOmega / SwitchyOmega .bak JSON parser & mapper
│   ├── http/
│   │   ├── mod.rs                   # HTTP connection dispatcher
│   │   ├── forward.rs               # Plain HTTP forward proxy (direct/SOCKS tunnel + HTTP upstream absolute-form)
│   │   ├── tunnel.rs                # Non-MITM HTTPS CONNECT opaque tunnel via Router
│   │   └── mitm_tunnel.rs           # MITM HTTPS CONNECT (TLS termination, upstream TLS over any UpstreamDialer, per-request URL routing)
│   ├── socks/
│   │   ├── mod.rs                   # SOCKS4/4a/5 dispatcher
│   │   ├── v4.rs                    # SOCKS4 & SOCKS4a server handler
│   │   ├── v5.rs                    # SOCKS5 server handler (no-auth, CONNECT)
│   │   └── web_guard.rs             # First-chunk HTTP/TLS-ALPN detector for --socks-block-web-in-mitm
│   └── mitm/
│       ├── mod.rs                   # MITM context & rustls ServerConfig / ClientConfig builders
│       ├── ca.rs                    # PEM & PKCS#12 CA loader + startup validation
│       ├── signer.rs                # rcgen dynamic leaf cert generation (-5m / +TTL+5m)
│       └── cache.rs                 # DashMap TTL + max-entry CertCache, single-flight dedup, reaper
└── tests/
    ├── routing_rules.rs             # Unit & integration tests for all condition types, unified/split, failover
    ├── upstream_proxies.rs          # End-to-end forwarding through mock HTTP, HTTPS, SOCKS5 (auth & no-auth), SOCKS4a upstreams
    ├── hot_reload.rs                # Live config swap, invalid-reload preservation, active tunnel survival
    ├── airswitch_import.rs          # Real AirSwitch/SwitchyOmega .bak fixtures -> valid TOML -> live routing
    ├── mitm_proxy.rs                # MITM over direct, SOCKS5, and HTTP upstreams + URL-based MITM routing
    ├── socks_proxy.rs               # SOCKS4/4a/5 + --socks-block-web-in-mitm + cross-protocol routing
    └── mux_port.rs                  # Single-port multiplexing & port-disable tests
```

---

## 9. Logging Additions (`src/logging.rs`)

Retains the exact 6-level diagnostic hierarchy (`QUIET`, `FATAL`, `ERROR`, `INFO`, `DEBUG`, `VERBOSE`) and `text` (logfmt) / `json` (NDJSON) formats from `rusty-conduit`, adding routing visibility to every access/SOCKS record:

- **HTTP/HTTPS access log (`text`):**
  ```text
  ts=2026-11-25T11:30:01.123Z kind=http client=127.0.0.1:51234 proto=https mitm=false method=CONNECT target=api.internal.example:443 rule=internal-domains-with-failover profile=bastion upstream=socks5://127.0.0.1:1081 status=200 bytes_in=1024 bytes_out=8192 duration_ms=142
  ```
- **SOCKS connection log (`text`):**
  ```text
  ts=2026-11-25T11:30:02.456Z kind=socks client=127.0.0.1:51240 proto=socks5 cmd=CONNECT target=10.0.1.5:5432 rule=rfc1918-to-corp profile=corp upstream=http://10.0.0.2:3128 status=ok bytes_in=512 bytes_out=4096 duration_ms=89
  ```
- Credentials in `upstream=` are **always redacted** (`http://10.0.0.2:3128`, never `http://user:pass@...`).

---

## 10. Crate Stack

Inherits the `rusty-conduit` pure-Rust stack plus four focused additions:

| Concern | Crate(s) | Notes |
| :--- | :--- | :--- |
| Async Runtime & Signals | `tokio`, `tokio-util`, `bytes` | Same as `rusty-conduit` |
| HTTP/1.1 & HTTP/2 | `hyper` 1.x, `hyper-util`, `http`, `http-body-util` | Same as `rusty-conduit` |
| Pure-Rust TLS & MITM | `rustls` (`ring`), `tokio-rustls`, `rustls-platform-verifier`, `rcgen`, `p12-keystore`, `x509-parser` | Same as `rusty-conduit` |
| Sockets & Concurrency | `socket2`, `dashmap`, **`arc-swap`** | `arc-swap` for lock-free hot-reload snapshots |
| Rule Matching | **`regex`**, **`base64`** | `regex` for host/URL regex rules; `base64` for HTTP `Proxy-Authorization` |
| Hot-Reload Watcher | **`notify`** | Cross-platform file watching (`kqueue`, `inotify`, `ReadDirectoryChangesW`) |
| CLI, Config & Time | `clap` (`derive`, `env`), `serde`, `toml`, `serde_json`, `humantime`, `time` (`local-offset` for weekday/time rules) | Same as `rusty-conduit` |
| Errors | `thiserror` | Same as `rusty-conduit` |

---

## 11. Phased Implementation Roadmap

### Phase 1 — Scaffold, Config, Logging & Core Reusable Engine
- Initialize `rusty-conduit-switch` Cargo project (BSD-3-Clause, `.gitignore`, CI skeleton).
- Port/adapt proven `rusty-conduit` foundations: `logging.rs` (with `rule`/`profile`/`upstream` fields), `filter.rs`, `mux.rs`, `net.rs` (keepalive + `PrefixedStream` + byte-counting relay), `server.rs`.
- Implement `config.rs` with full CLI/env/TOML precedence, subcommands (`validate`, `test-route`, `import-airswitch`), and startup validation (including self-loop detection).

### Phase 2 — Routing Engine (`src/router/`)
- Implement all condition matchers (`condition.rs`): exact host, AirSwitch-compatible `host_wildcard`, `host_regex`, `cidr`/`ip` (with IPv4-mapped IPv6 canonicalization and opt-in `resolve_dns`), `port`, `host_levels`, `bypass` (including `<local>`), `weekday`, `time`, `url_wildcard`, `url_regex`, `keyword`, `inbound`, `disabled`.
- Implement unified + optional split `[routing.http]` / `[routing.socks]` tables, profile-level `bypass`, and `test-route` CLI output.
- Unit test every condition type and edge case.

### Phase 3 — Upstream Dialers & Failover (`src/upstream/`)
- Implement `DirectDialer`, `BlockDialer`, `Socks5Dialer` (no-auth + RFC 1929 user/pass, `ATYP=0x03`), `Socks4aDialer` (remote DNS), `HttpConnectDialer` (Basic auth), `HttpsConnectDialer` (`rustls`), and `FailoverDialer`.
- Integration tests against local mock HTTP, HTTPS, SOCKS5, and SOCKS4a proxy servers.

### Phase 4 — Inbound HTTP/HTTPS & SOCKS4/4a/5 Wired to Router
- Implement `http/forward.rs` (including the plain-HTTP-to-HTTP-upstream absolute-form path + `Proxy-Authorization`, and tunnel path for SOCKS/direct upstreams).
- Implement `http/tunnel.rs` (non-MITM `CONNECT` over `Router`).
- Implement `socks/v4.rs` and `socks/v5.rs` over `Router` (cross-protocol routing: SOCKS → HTTP/HTTPS/SOCKS5/SOCKS4a/direct/block).
- End-to-end tests verifying cross-protocol routing, failover, and zero local DNS lookups for proxied hosts.

### Phase 5 — MITM Over Routed Upstreams & SOCKS Web Guard
- Port/adapt `mitm/{ca,signer,cache,mod}.rs` (PEM & PKCS#12, TTL + max-entry cap, single-flight dedup, background reaper).
- Implement `http/mitm_tunnel.rs` so upstream TLS runs over **any** `UpstreamStream` returned by the `Router` (including SOCKS5 and HTTP `CONNECT` upstreams), with per-request URL rule evaluation when URL rules are configured.
- Implement `socks/web_guard.rs` (`--socks-block-web-in-mitm`).
- Integration tests for MITM through direct, SOCKS5, and HTTP upstreams + URL-rule routing under MITM.

### Phase 6 — Hot-Reload (`src/reload.rs`)
- Wire `ArcSwap<RuntimeConfig>` into listeners, HTTP, MITM, and SOCKS handlers.
- Implement `SIGHUP` handler (Unix) and debounced `notify` parent-directory file watcher (`--watch-config`).
- Implement validate-before-swap + non-reloadable-field notices.
- Integration tests: live route change, profile change, invalid TOML preservation, and in-flight tunnel survival across reload.

### Phase 7 — AirSwitch `.bak` Importer (`src/import/airswitch.rs`)
- Implement full AirSwitch / ZeroOmega / SwitchyOmega `.bak` JSON parser, profile slugifier, nested `SwitchProfile` flattener, condition mapper, warning reporter, and clean commented TOML emitter.
- Integration tests using realistic `.bak` fixtures (including AirSwitch IP/CIDR conditions, `FixedProfile` with `bypassList` & auth, `SwitchProfile`, `VirtualProfile`, `PacProfile` warning, and `SystemProfile` warning) verified by parsing the generated TOML back through `validate` and `test-route`.

### Phase 8 — Documentation, Polish & Cross-Platform Verification
- Write `README.md`, `docs/USER-GUIDE.md`, `docs/MITM-CA-GUIDE.md`, and `Dockerfile`.
- Run `cargo test`, `cargo clippy --all-targets`, `cargo fmt --check`, and verify cross-platform release builds.
