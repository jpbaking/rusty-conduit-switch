# rusty-conduit-switch

**A lightweight HTTP/HTTPS and SOCKS4/4a/5 Auto Switch proxy server in a single Rust binary: route every connection to named upstream proxies or failover chains with ordered rules, with optional pure-Rust HTTPS MITM inspection, atomic hot-reload, and AirSwitch `.bak` import.**

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

---

## Why rusty-conduit-switch?

- **Auto Switch routing on the server:** Ordered `[[routing.rules]]` send each connection to `direct`, `block`, or a named `http`, `https`, `socks5`, or `socks4a` upstream. Rules match by host, wildcard, regex, IP/CIDR, port, host levels, bypass lists, weekday, time of day, and (for plain HTTP or MITM-decrypted HTTPS) the full URL.
- **Failover chains:** A target can be an ordered list (`["corp", "backup", "direct"]`). The next profile is tried only when a TCP connect or proxy handshake fails, never after bytes have flowed.
- **One binary, all inbound protocols:** Plain HTTP forwarding, HTTPS `CONNECT`, SOCKS4, SOCKS4a, and SOCKS5 on separate ports (`3128` / `1080`) or **auto-multiplexed on one port**. Both protocols share one routing table by default, with optional per-protocol overrides.
- **No local DNS leaks by default:** Hostnames routed to an upstream proxy are sent unresolved (SOCKS5 `ATYP=0x03`, SOCKS4a, or HTTP `CONNECT host:port`). IP/CIDR rules match hostnames through local DNS only if you opt in with `resolve_dns = true`.
- **Atomic hot-reload:** `SIGHUP` (Unix) or `--watch-config` re-validates the file and swaps profiles, rules, and filters without dropping in-flight tunnels. A bad edit is logged and the running configuration stays active.
- **AirSwitch / ZeroOmega / SwitchyOmega import:** `import-airswitch` turns a browser-extension `.bak` backup into a commented, ready-to-validate TOML config.
- **Opt-in HTTPS MITM:** OFF by default and **never auto-generates a CA**. Bring your own PEM or PKCS#12 CA. Upstream TLS runs over any routed upstream, including SOCKS5 and HTTP `CONNECT` proxies.
- **Zero caching, pure-Rust TLS:** No HTTP response or DNS caching and no full-body buffering. The only cache holds MITM leaf certificates, bounded by TTL and entry count. Built on `rustls` + `ring`, with no OpenSSL.

---

## Quick Start

### 1. Build or run in Docker

```sh
# Build from source (Rust stable)
cargo install --path .

# Or build and run the container image (binds 0.0.0.0 inside the container)
docker build -t rusty-conduit-switch .
docker run --rm -p 127.0.0.1:3128:3128 -p 127.0.0.1:1080:1080 rusty-conduit-switch
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
| **[User Guide](docs/USER-GUIDE.md)** | Every CLI flag and environment variable, the full TOML schema, routing rules and conditions, failover, hot-reload, AirSwitch import, logging, and Docker |
| **[MITM CA Guide](docs/MITM-CA-GUIDE.md)** | Generating your own PEM or PKCS#12 CA with `openssl`, starting the proxy with it, and trusting it on Linux, macOS, Windows, and Firefox |
| **[Master Plan](docs/MASTER-PLAN.md)** | v1 architecture and design specification |

---

## License

BSD-3-Clause — see [LICENSE](LICENSE).
