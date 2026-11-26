# Basic User Guide

This guide gets you from install to a working routing proxy: start the server, point clients at
it, write a first routing config, and use the everyday options.

- Looking for every flag and TOML key, routing conditions, failover, hot-reload, MITM, or
  logging details? See the **[Advanced User Guide](USER-GUIDE-ADVANCED.md)**.
- Curious about RAM, CPU, or `ulimit -n` sizing? See **[Performance, Footprint &
  Sizing](PERFORMANCE-AND-SIZING.md)**.
- Running in Docker or Compose? See the **[Docker Guide](DOCKER-GUIDE.md)**.

---

## 1. Install

### Option A: Download a prebuilt binary (recommended)

Grab the archive for your OS and CPU architecture from the [GitHub
Releases](https://github.com/jpbaking/rusty-conduit-switch/releases) page:

- **Linux:** `rusty-conduit-switch-<version>-linux-amd64.tar.gz` or `linux-arm64.tar.gz`
- **macOS:** `rusty-conduit-switch-<version>-macos-arm64.tar.gz` (Apple Silicon) or
  `macos-amd64.tar.gz` (Intel)
- **Windows:** `rusty-conduit-switch-<version>-windows-amd64.zip` or `windows-arm64.zip`

Extract it and place `rusty-conduit-switch` (or `rusty-conduit-switch.exe`) somewhere on your
`PATH`.

### Option B: Run with Docker

Multi-arch images (`linux/amd64` and `linux/arm64`, based on Ubuntu 26.04 LTS) are published to
GitHub Container Registry on each release:

```sh
# Publish to host loopback only (recommended: there is no inbound authentication)
docker run --rm \
  -p 127.0.0.1:3128:3128 \
  -p 127.0.0.1:1080:1080 \
  -v "$PWD/conf:/etc/rusty-conduit-switch:ro" \
  ghcr.io/jpbaking/rusty-conduit-switch:2 \
  --config /etc/rusty-conduit-switch/config.toml --watch-config
```

The **[Docker Guide](DOCKER-GUIDE.md)** covers config mounts, hot-reload, logs, MITM, resource
limits, and Compose examples.

### Option C: Build from source

Requires a stable Rust toolchain (<https://rustup.rs>):

```sh
git clone https://github.com/jpbaking/rusty-conduit-switch.git
cd rusty-conduit-switch
cargo install --path .
```

---

## 2. Start the Proxy

Run with no arguments to start with safe local defaults:

```sh
rusty-conduit-switch
```

Without a config file, every connection goes `direct`, so it behaves like a plain forward
proxy. The defaults:

- **HTTP/HTTPS proxy:** `127.0.0.1:3128`
- **SOCKS4 / SOCKS4a / SOCKS5 proxy:** `127.0.0.1:1080`
- **Routing:** everything `direct`
- **MITM mode:** `OFF` (HTTPS `CONNECT` and SOCKS act as pure encrypted tunnels)
- **Log level:** `INFO`

Press **`Ctrl+C`** (or send `SIGTERM` on Linux/macOS) to shut down cleanly. Active connections
drain before exit.

---

## 3. Connect Your Clients

### Test with `curl`

```sh
# Plain HTTP via HTTP proxy
curl -x http://127.0.0.1:3128 http://example.com/

# HTTPS via HTTP CONNECT tunnel (opaque, end-to-end encrypted)
curl -x http://127.0.0.1:3128 https://example.com/

# HTTPS via SOCKS5 (proxy resolves DNS)
curl --socks5-hostname 127.0.0.1:1080 https://example.com/

# HTTP via SOCKS4a (proxy resolves DNS)
curl --socks4a 127.0.0.1:1080 http://example.com/
```

### Standard CLI environment variables

Most CLI tools (`curl`, `git`, `python`, `npm`, `cargo`, etc.) respect:

```sh
# Linux / macOS
export HTTP_PROXY="http://127.0.0.1:3128"
export HTTPS_PROXY="http://127.0.0.1:3128"
# Or route everything through SOCKS5:
export ALL_PROXY="socks5h://127.0.0.1:1080"
```

```powershell
# Windows PowerShell
$env:HTTP_PROXY  = "http://127.0.0.1:3128"
$env:HTTPS_PROXY = "http://127.0.0.1:3128"
```

### Browsers (Firefox, Chrome, Edge, Safari)

- **HTTP / HTTPS Proxy:** host `127.0.0.1`, port `3128`
- **SOCKS5 Host:** host `127.0.0.1`, port `1080` (enable *"Proxy DNS when using SOCKS v5"* if
  available)

Point the browser at `rusty-conduit-switch` instead of a proxy-switching extension, and the
routing happens on the server for every app that uses it.

---

## 4. Your First Routing Config

A config file names **upstream profiles** and **routing rules**. Rules are checked top to
bottom; the first match picks the profile, and `default` applies when nothing matches:

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

- `direct` and `block` always exist; you never declare them.
- A `target` list is a **failover chain**: `bastion` is tried first, and `corp` only if
  connecting through `bastion` fails.
- `password_env` reads the password from an environment variable, so it never sits in the file.

Check the file, ask where a destination would go, then run it with hot-reload:

```sh
rusty-conduit-switch validate --config config.toml
# config OK: config.toml profiles=4 rules=2

rusty-conduit-switch test-route --config config.toml api.internal.example:443
# target=api.internal.example:443 inbound=http table=[routing] rule=internal-with-failover profile=bastion chain=bastion,corp upstream=socks5://127.0.0.1:1081

CORP_PROXY_PASS='...' rusty-conduit-switch --config config.toml --watch-config
```

With `--watch-config`, saving the file applies the new profiles and rules without dropping open
connections. A file that fails validation is logged and ignored, so the running config stays
active.

The [Advanced User Guide](USER-GUIDE-ADVANCED.md) lists every [profile
type](USER-GUIDE-ADVANCED.md#4-upstream-profiles) and [rule
condition](USER-GUIDE-ADVANCED.md#5-routing-rules): host wildcards and regexes, ports, weekdays
and times, URLs, split HTTP and SOCKS tables, and more.

---

## 5. Import from AirSwitch, ZeroOmega, or SwitchyOmega

Already using one of these browser extensions? Export a backup from its options page
(**Import/Export → Backup**) and turn it into a config:

```sh
rusty-conduit-switch import-airswitch OmegaOptions.bak -o config.toml
rusty-conduit-switch validate --config config.toml
```

Warnings about anything that could not be converted exactly are printed and also written into
the file's header comment. See
[Importing](USER-GUIDE-ADVANCED.md#8-importing-from-airswitch-zeroomega-or-switchyomega) for
what is converted.

---

## 6. Common Everyday Options

### Change ports or disable one listener

```sh
# Custom ports
rusty-conduit-switch --http-port 8080 --socks-port 1081

# HTTP/HTTPS only (disable SOCKS with 0)
rusty-conduit-switch --socks-port 0

# SOCKS4/4a/5 only (disable HTTP with 0)
rusty-conduit-switch --http-port 0
```

### Serve HTTP/HTTPS and SOCKS on one port

Set both ports to the same non-zero number. `rusty-conduit-switch` peeks at the first byte of
each connection to tell HTTP, SOCKS4/4a, and SOCKS5 apart:

```sh
rusty-conduit-switch --http-port 8888 --socks-port 8888
```

### Save traffic logs to files

```sh
rusty-conduit-switch --config config.toml \
  --http-access-log access.log \
  --socks-log socks.log
```

Each record shows the matched `rule`, the chosen `profile`, and the `upstream` it went through.

### Watch live traffic in your terminal

Set `--log-level DEBUG` to stream HTTP access and SOCKS connection records to `stdout`, while
server diagnostics stay on `stderr`:

```sh
rusty-conduit-switch --config config.toml --log-level DEBUG
```

### Block destinations (or allowlist specific hosts)

Use `--block` or `--allow` (repeatable or comma-separated; together, `--allow` entries are
exceptions to `--block`) with IPs, CIDRs, exact FQDNs, or `*.domain` wildcards. The filter runs
before any routing rule:

```sh
# Block ad domains and one network
rusty-conduit-switch --config config.toml --block "*.ads.example,10.99.0.0/16"

# Allow only specific domains
rusty-conduit-switch --config config.toml --allow example.com,*.example.org
```

### Listen on your LAN

```sh
rusty-conduit-switch --config config.toml --bind 0.0.0.0
```

> **Note:** There is **no inbound authentication**. Binding to a non-loopback address prints a security notice at startup. Restrict access with your firewall and keep `--max-connections` bounded (see [Performance, Footprint & Sizing](PERFORMANCE-AND-SIZING.md)).

### Reload without a restart

With `--watch-config`, saving the file reloads it. Without it, send `SIGHUP` on Linux and
macOS:

```sh
kill -HUP "$(pgrep -x rusty-conduit-switch)"
```

---

## 7. Where to Go Next

- **[Advanced User Guide](USER-GUIDE-ADVANCED.md):** Every CLI flag, environment variable, and
  TOML key, upstream profiles, routing conditions, failover, hot-reload, AirSwitch import,
  HTTPS MITM, and logging.
- **[MITM CA Guide](MITM-CA-GUIDE.md):** Step-by-step instructions to generate and trust your
  own private CA.
- **[Performance, Footprint & Sizing](PERFORMANCE-AND-SIZING.md):** Memory/CPU budgets, `ulimit
  -n` and `somaxconn` limits, and connection/cache caps.
- **[Docker Guide](DOCKER-GUIDE.md):** Running in containers, with `docker run` and Compose
  examples.
