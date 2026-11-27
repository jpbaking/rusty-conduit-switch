# rusty-conduit-switch

**A lightweight HTTP/HTTPS and SOCKS4/4a/5 Auto Switch proxy server in a single Rust binary: route every connection to named upstream proxies or failover chains with ordered rules, with optional pure-Rust HTTPS MITM inspection, atomic hot-reload, and AirSwitch `.bak` import.**

[![Release](https://img.shields.io/github/v/release/jpbaking/rusty-conduit-switch)](https://github.com/jpbaking/rusty-conduit-switch/releases)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

---

## Why rusty-conduit-switch?

- **Auto Switch routing on the server:** Ordered `[[routing.rules]]` send each connection to `direct`, `block`, or a named `http`, `https`, `socks5`, or `socks4a` upstream. Rules match by host, wildcard, regex, IP/CIDR, port, host levels, bypass lists, weekday, time of day, and (for plain HTTP or MITM-decrypted HTTPS) the full URL.
- **Failover chains:** A target can be an ordered list (`["corp", "backup", "direct"]`). The next profile is tried only when a TCP connect or proxy handshake fails, never after bytes have flowed.
- **One binary, all inbound protocols:** Plain HTTP forwarding, HTTPS `CONNECT`, SOCKS4, SOCKS4a, and SOCKS5 on separate ports (`3128` / `1080`) or **auto-multiplexed on one port**. Both protocols share one routing table by default, with optional per-protocol overrides.
- **No local DNS leaks by default:** Hostnames routed to an upstream proxy are sent unresolved (SOCKS5 `ATYP=0x03`, SOCKS4a, or HTTP `CONNECT host:port`). IP/CIDR rules match hostnames through local DNS only if you opt in with `resolve_dns = true`.
- **Atomic hot-reload:** `SIGHUP` (Unix) or `--watch-config` re-validates the file and swaps profiles, rules, and filters without dropping in-flight tunnels. A bad edit is logged and the running configuration stays active.
- **AirSwitch / ZeroOmega / SwitchyOmega import:** `import-airswitch` turns a browser-extension `.bak` backup into a commented, ready-to-validate TOML config.
- **Opt-in HTTPS MITM:** OFF by default and **never auto-generates a CA**. Bring your own PEM or PKCS#12 CA. Upstream TLS runs over any routed upstream, including SOCKS5 and HTTP `CONNECT` proxies. Upstream certificates are verified strictly by default; for lab or self-signed origins, `--mitm-insecure-host <RULE>` (TOML `[mitm] insecure_hosts`) skips verification only for matching hosts, IPs, or CIDRs, and `--mitm-insecure` (TOML `[mitm] insecure = true`) blindly trusts every upstream — **unsafe**, and logged as a startup warning.
- **Your own error pages:** Swap the built-in HTML for proxy-generated errors (`400`, `403`, `502`, `504`, …) with `--error-page <PATH>` (`RUSTY_CONDUIT_SWITCH_ERROR_PAGE`, TOML `error_page`), using the `{{status}}`, `{{reason}}`, `{{message}}`, and `{{target}}` placeholders (HTML-escaped). Responses from upstream origins and proxies are never altered. Loaded at startup; a change needs a restart.
- **Zero caching, pure-Rust TLS:** No HTTP response or DNS caching and no full-body buffering. The only cache holds MITM leaf certificates, bounded by TTL and entry count. Built on `rustls` + `ring`, with no OpenSSL.
- **Survives long silent connections:** No idle timeout on established tunnels, plus TCP keepalive on client and upstream sockets (default `60s` idle / `10s` × `5` probes), so NAT, firewalls, and VPNs don't drop agents waiting on slow responses.
- **Built for operators:** `CLI > env > TOML` configuration, `validate` and `test-route` dry runs, six log levels, `text` (logfmt) or `json` (NDJSON) access logs that name the matched rule, profile, and upstream, and connection and cert-cache caps, with a small footprint: about 8 MB idle and 27 KB per open tunnel (Linux with `MALLOC_ARENA_MAX=2`, which the container image sets; see [sizing](docs/PERFORMANCE-AND-SIZING.md)).

---

## Quick Start

### 1. Download or install

Download a prebuilt package for Linux, macOS, or Windows (`amd64` / `arm64`) from **[Releases](https://github.com/jpbaking/rusty-conduit-switch/releases)**, run with Docker, or build from source with Rust:

```sh
# Docker (multi-arch: linux/amd64, linux/arm64); see the Docker Guide for Compose
docker run --rm -p 127.0.0.1:3128:3128 -p 127.0.0.1:1080:1080 \
  -v "$PWD/conf:/etc/rusty-conduit-switch:ro" ghcr.io/jpbaking/rusty-conduit-switch:2 \
  --config /etc/rusty-conduit-switch/config.toml --watch-config

# Or build from source
cargo install --path .
```

### 2. Write a config

```toml
# config.toml
[profiles.corp]
type = "http"
host = "10.0.0.2"
port = 3128
username = "alice"
password_env = "CORP_PROXY_PASS"
bypass = ["<local>", "*.local"]

[profiles.bastion]
type = "socks5"
host = "127.0.0.1"
port = 1081

[routing]
default = "direct"

[[routing.rules]]
name = "rfc1918-to-corp"
cidr = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
target = "corp"

[[routing.rules]]
name = "internal-with-failover"
host_wildcard = ["*.internal.example"]
target = ["bastion", "corp"]
```

Already using AirSwitch, ZeroOmega, or SwitchyOmega in your browser? Generate the config from a backup instead:

```sh
rusty-conduit-switch import-airswitch OmegaOptions.bak -o config.toml
```

### 3. Check it, then run

```sh
rusty-conduit-switch validate --config config.toml
rusty-conduit-switch test-route --config config.toml api.internal.example:443
# target=api.internal.example:443 inbound=http table=[routing] rule=internal-with-failover profile=bastion chain=bastion,corp upstream=socks5://127.0.0.1:1081

rusty-conduit-switch --config config.toml --watch-config
```

### 4. Point clients at it

```sh
curl -x http://127.0.0.1:3128 https://example.com/             # HTTP proxy (HTTPS via CONNECT)
curl --socks5-hostname 127.0.0.1:1080 https://example.com/     # SOCKS5 (remote DNS)
```

---

## Documentation

| Guide | What's inside |
| :--- | :--- |
| **[Basic User Guide](docs/USER-GUIDE-BASIC.md)** | Installing, connecting browsers and CLI tools, a first routing config, AirSwitch import, and everyday options |
| **[Advanced User Guide](docs/USER-GUIDE-ADVANCED.md)** | Every CLI flag, environment variable, and TOML key, upstream profiles, routing conditions, failover, hot-reload, HTTPS MITM, logging, and custom error pages |
| **[MITM CA Guide](docs/MITM-CA-GUIDE.md)** | Generating your own PEM or PKCS#12 CA with `openssl`, starting the proxy with it, and trusting it on Linux, macOS, Windows, and Firefox |
| **[Performance, Footprint & Sizing](docs/PERFORMANCE-AND-SIZING.md)** | Measured CPU/RAM footprint, `ulimit -n` and `somaxconn` limits, concurrent user sizing, and resource caps |
| **[Docker Guide](docs/DOCKER-GUIDE.md)** | Images, `docker run` and Compose examples, config hot-reload, reaching upstream proxies, secrets, limits, and health checks |

---

## License

BSD-3-Clause — see [LICENSE](LICENSE).
