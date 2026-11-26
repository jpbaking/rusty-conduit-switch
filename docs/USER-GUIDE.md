# rusty-conduit-switch User Guide

This guide covers everything you configure in `rusty-conduit-switch`:

1. [Running the server](#1-running-the-server)
2. [Subcommands](#2-subcommands): `validate`, `test-route`, `import-airswitch`
3. [CLI flags and environment variables](#3-cli-flags-and-environment-variables)
4. [The TOML configuration file](#4-the-toml-configuration-file)
5. [Upstream profiles](#5-upstream-profiles)
6. [Routing rules](#6-routing-rules)
7. [Failover chains](#7-failover-chains)
8. [Hot-reload](#8-hot-reload)
9. [Importing from AirSwitch, ZeroOmega, or SwitchyOmega](#9-importing-from-airswitch-zeroomega-or-switchyomega)
10. [HTTPS MITM inspection](#10-https-mitm-inspection)
11. [Logging](#11-logging)
12. [Docker](#12-docker)

---

## 1. Running the server

```sh
rusty-conduit-switch                               # 127.0.0.1:3128 (HTTP/HTTPS) + 127.0.0.1:1080 (SOCKS), everything direct
rusty-conduit-switch --config config.toml          # routing from a config file
rusty-conduit-switch --config config.toml --watch-config   # ... and hot-reload it on save
```

Without `--config`, every connection goes `direct`. Multi-profile routing needs a config
file.

**Listeners.** HTTP/HTTPS listens on `--http-port` (default `3128`) and SOCKS4/4a/5 on
`--socks-port` (default `1080`). A port of `0` disables that listener; at least one must stay
enabled. If both ports are the same (and not `0`), one listener serves both protocols and
tells them apart by the first byte of each connection.

**Inbound protocols.** Plain HTTP proxy requests (`GET http://...`), HTTPS `CONNECT`, SOCKS4,
SOCKS4a, and SOCKS5 `CONNECT` (IPv4, IPv6, and domain names). TCP only; there is no SOCKS
`BIND` or `UDP ASSOCIATE`.

**No inbound authentication in v1.** Anyone who can reach the listener can use it. Keep
`--bind` on loopback (the default) or restrict access with a firewall. The server prints a
`SECURITY NOTICE` at startup when it binds to a non-loopback address.

**Shutdown.** `Ctrl+C` or `SIGTERM` stops accepting connections and waits for active ones
to drain.

**Exit codes.** `0` on a clean shutdown or a successful subcommand, `1` on a fatal startup
error (invalid configuration, unreadable CA, port already in use) or a failed subcommand.

---

## 2. Subcommands

### `validate`

```sh
rusty-conduit-switch validate --config config.toml
# config OK: config.toml profiles=4 rules=2
```

Parses the file, applies CLI/env overrides, and runs the same checks as startup: unknown
fields, profile types and required fields, ambiguous password sources, unknown profile
references, composite-profile cycles, invalid rule syntax (regexes, CIDRs, wildcards,
ports, times), and self-loops (a profile pointing at this server's own listener). It exits
`0` when the file is valid and `1` with the error on stderr otherwise. Routing notices, such
as URL rules that cannot match some traffic, are printed too.

### `test-route`

```sh
rusty-conduit-switch test-route --config config.toml [--inbound http|socks] <HOST[:PORT] | URL>
```

Prints the routing decision for a target without connecting anywhere:

```text
target=10.1.2.3:443 inbound=http table=[routing] rule=rfc1918-to-corp profile=corp chain=corp upstream=http://10.0.0.2:3128
```

- The target is `HOST`, `HOST:PORT` (the port defaults to `80`), `[IPv6]:PORT`, or a full
  `http://` / `https://` URL.
- `--inbound` (default `http`) selects which table to evaluate: the HTTP or the SOCKS view
  of the routing configuration.
- The request is shaped the way the proxy would see it. SOCKS never sees a URL. An `https://`
  URL is visible over HTTP only when MITM is configured; otherwise it is an opaque `CONNECT`
  tunnel. In both cases URL rules are not evaluated and a `note:` line says so.
- `profile=` shows how the target was resolved: `corp`, `corp(bypass->direct)` when the
  profile's bypass list matched, or `split->split_http` for a composite profile.
- No DNS lookup happens unless a rule opts in with `resolve_dns = true`.
- A target rejected by the global filter prints `status=denied_by_filter`.

### `import-airswitch`

```sh
rusty-conduit-switch import-airswitch <BAK_PATH> [-o <OUT.toml>] [--profile <SWITCH_PROFILE_NAME>] [--force]
```

Converts a browser-extension backup into a config file. See
[section 9](#9-importing-from-airswitch-zeroomega-or-switchyomega).

---

## 3. CLI flags and environment variables

**Precedence: CLI flags > `RUSTY_CONDUIT_SWITCH_*` environment variables > `--config` TOML
file > built-in defaults.**

Durations use human-readable units: `300ms`, `10s`, `5m`, `1h`, `1h 30m`. Boolean
environment variables accept `true`/`false`, `yes`/`no`, `on`/`off`, and `1`/`0`.

| CLI flag | Environment variable | TOML key | Default | Hot-reload | Description |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `--config <PATH>` | `RUSTY_CONDUIT_SWITCH_CONFIG` | — | *(none)* | — | Optional TOML configuration file path |
| `--watch-config` | `RUSTY_CONDUIT_SWITCH_WATCH_CONFIG` | `watch_config` | `false` | No | Watch `--config` and hot-reload on change |
| `--watch-debounce <DURATION>` | `RUSTY_CONDUIT_SWITCH_WATCH_DEBOUNCE` | `watch_debounce` | `300ms` | No | Debounce window for file change events |
| `--bind <IP>` | `RUSTY_CONDUIT_SWITCH_BIND` | `bind` | `127.0.0.1` | No | IPv4 or IPv6 bind address |
| `--http-port <PORT>` | `RUSTY_CONDUIT_SWITCH_HTTP_PORT` | `http_port` | `3128` | No | HTTP/HTTPS proxy port (`0` disables) |
| `--socks-port <PORT>` | `RUSTY_CONDUIT_SWITCH_SOCKS_PORT` | `socks_port` | `1080` | No | SOCKS4/4a/5 port (`0` disables) |
| `--connect-timeout <DURATION>` | `RUSTY_CONDUIT_SWITCH_CONNECT_TIMEOUT` | `connect_timeout` | `10s` | Yes | Upstream TCP connect + proxy handshake timeout, per failover attempt |
| `--max-connections <N>` | `RUSTY_CONDUIT_SWITCH_MAX_CONNECTIONS` | `max_connections` | `4096` | No | Concurrent client connections; excess connections are closed immediately (`0` = unlimited) |
| `--tcp-keepalive <DURATION>` | `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE` | `tcp_keepalive` | `60s` | Yes | Idle time before TCP keepalive probes start on client and upstream sockets (`0` disables) |
| `--tcp-keepalive-interval <DURATION>` | `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_INTERVAL` | `tcp_keepalive_interval` | `10s` | Yes | Time between unanswered TCP keepalive probes |
| `--tcp-keepalive-retries <N>` | `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_RETRIES` | `tcp_keepalive_retries` | `5` | Yes | Unanswered TCP keepalive probes before the connection is closed |
| `--allow <RULE>` | `RUSTY_CONDUIT_SWITCH_ALLOW` | `allow` | *(none)* | Yes | Destination allowlist; when combined with `--block`, serves as exceptions to the blocklist |
| `--block <RULE>` | `RUSTY_CONDUIT_SWITCH_BLOCK` | `block` | *(none)* | Yes | Destination blocklist; combine with `--allow` to carve out exceptions |
| `--mitm-ca-cert <PATH>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_CERT` | `mitm.ca_cert` | *(none)* | No | Path to PEM-encoded CA certificate (enables MITM with `--mitm-ca-key`) |
| `--mitm-ca-key <PATH>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_KEY` | `mitm.ca_key` | *(none)* | No | Path to PEM-encoded CA private key |
| `--mitm-ca-p12 <PATH>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_P12` | `mitm.ca_p12` | *(none)* | No | Path to PKCS#12 (`.p12`/`.pfx`) CA bundle (enables MITM) |
| `--mitm-ca-passphrase <STR>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE` | `mitm.ca_passphrase` | *(none)* | No | CA passphrase (prefer the env var or a file) |
| `--mitm-ca-passphrase-file <PATH>` | `RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE_FILE` | `mitm.ca_passphrase_file` | *(none)* | No | File holding the CA passphrase (trailing newline trimmed) |
| `--mitm-cert-ttl <DURATION>` | `RUSTY_CONDUIT_SWITCH_MITM_CERT_TTL` | `mitm.cert_ttl` | `1h` | No | In-memory TTL for generated MITM leaf certificates (minimum `10s`) |
| `--mitm-cert-cache-max-entries <N>` | `RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX_ENTRIES` | `mitm.cert_cache_max_entries` | `10240` | No | Maximum cached MITM leaf certificates (`0` = unlimited) |
| `--socks-block-web` | `RUSTY_CONDUIT_SWITCH_SOCKS_BLOCK_WEB` | `socks_block_web` | `false` | No | Reject HTTP/HTTPS traffic over SOCKS4/4a/5 (works with or without MITM) |
| `--log-level <LEVEL>` | `RUSTY_CONDUIT_SWITCH_LOG_LEVEL` | `logging.level` | `INFO` | No | `QUIET`, `FATAL`, `ERROR`, `INFO`, `DEBUG`, `VERBOSE` |
| `--log-format <FMT>` | `RUSTY_CONDUIT_SWITCH_LOG_FORMAT` | `logging.format` | `text` | No | Access/SOCKS log format: `text` (logfmt) or `json` (NDJSON) |
| `--http-access-log <PATH>` | `RUSTY_CONDUIT_SWITCH_HTTP_ACCESS_LOG` | `logging.http_access_log` | *(none)* | No | Write HTTP/HTTPS access records to a file |
| `--socks-log <PATH>` | `RUSTY_CONDUIT_SWITCH_SOCKS_LOG` | `logging.socks_log` | *(none)* | No | Write SOCKS connection records to a file |

**Destination filter (`--allow` / `--block`).** Each entry is an IP address, a CIDR, an exact
FQDN, or a `*.domain` wildcard. Repeat the flag or separate entries with commas
(`--block "*.ads.example,10.0.0.0/8"`). The filter runs before any routing rule; a denied
target gets `403 Forbidden` (HTTP) or a SOCKS rejection, and the log shows
`status=denied_by_filter`. When both `--allow` and `--block` are set, `--block` denies matching
destinations while `--allow` carves out exceptions to the blocklist.

**Passphrases.** `--mitm-ca-passphrase` on the command line can show up in process listings
and shell history, and the server prints a `NOTICE` when you use it. Prefer
`RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE` or `--mitm-ca-passphrase-file`.

### Deprecated names

The older names below are still accepted for backwards compatibility and log a `NOTICE` at
startup. When both an old name and its replacement are set, the replacement wins.

| Old name | Replacement |
| :--- | :--- |
| `--tcp-keepalive-idle` (deprecated) | `--tcp-keepalive` |
| `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_IDLE` (deprecated) | `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE` |
| `--mitm-cert-cache-max` (deprecated) | `--mitm-cert-cache-max-entries` |
| `RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX` (deprecated) | `RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX_ENTRIES` |
| `[tcp_keepalive]` (deprecated) | `tcp_keepalive`, `tcp_keepalive_interval`, `tcp_keepalive_retries` |
| `[filter]` (deprecated) | `allow`, `block` |
| `mitm.cert_cache_max` (deprecated) | `mitm.cert_cache_max_entries` |

### Open-file limit

Every concurrent proxied connection uses 2 file descriptors (client + upstream), so
`--max-connections N` needs at least `2 × max_connections + 64` descriptors (`8256` at the
default `4096`). On Unix, `rusty-conduit-switch` automatically raises its soft open-file limit
(`RLIMIT_NOFILE`) toward the hard limit at startup whenever the current soft limit is below
that threshold. If the limit still cannot hold `--max-connections`, it logs:

```text
NOTICE: open-file limit is <limit> but --max-connections <N> needs at least <needed>; only about <M> concurrent connections will fit. Raise `ulimit -n` (LimitNOFILE= under systemd) or lower --max-connections
```

---

## 4. The TOML configuration file

Unknown keys are rejected, so typos fail validation instead of being ignored.

```toml
# Server settings (all optional; CLI flags and env vars override them)
bind = "127.0.0.1"
http_port = 3128
socks_port = 1080
watch_config = true
watch_debounce = "300ms"
connect_timeout = "10s"
max_connections = 4096
socks_block_web = false

tcp_keepalive = "60s"
tcp_keepalive_interval = "10s"
tcp_keepalive_retries = 5

# allow = ["*.example.com", "10.0.0.0/8"]   # allowlist, or exceptions when combined with block
block = ["*.ads.example"]

[mitm]                                     # MITM is on only when a CA is configured
# ca_cert = "/etc/rusty-conduit-switch/ca.pem"
# ca_key = "/etc/rusty-conduit-switch/ca.key"
# ca_p12 = "/etc/rusty-conduit-switch/ca.p12"
# ca_passphrase_file = "/etc/rusty-conduit-switch/ca.pass"
cert_ttl = "1h"
cert_cache_max_entries = 10240

[logging]
level = "INFO"
format = "text"
# http_access_log = "/var/log/rusty-conduit-switch/http.log"
# socks_log = "/var/log/rusty-conduit-switch/socks.log"

# Upstream profiles: see section 5
[profiles.corp]
type = "http"
host = "10.0.0.2"
port = 3128
username = "alice"
password_env = "CORP_PROXY_PASS"
bypass = ["127.0.0.1", "::1", "localhost", "*.local"]

[profiles.bastion]
type = "socks5"
host = "127.0.0.1"
port = 1081

# Routing: see section 6
[routing]
default = "direct"
resolve_dns = false

[[routing.rules]]
name = "rfc1918-to-corp"
cidr = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
target = "corp"

[[routing.rules]]
name = "internal-domains-with-failover"
host_wildcard = ["*.internal.example", "dev-*.corp.net"]
target = ["bastion", "corp"]
```

---

## 5. Upstream profiles

Each `[profiles.<name>]` table defines one upstream. Two profiles always exist without being
declared:

- **`direct`** connects to the destination itself, resolving hostnames through the OS
  resolver.
- **`block`** refuses the connection: `403 Forbidden` for HTTP, SOCKS5 reply `0x02`
  (connection not allowed by ruleset), or SOCKS4 reply `0x5B` (request rejected).

You may redeclare `direct` or `block`, but only with their own type.

| Key | Applies to | Description |
| :--- | :--- | :--- |
| `type` | all | `direct`, `block`, `http`, `https`, `socks5`, `socks4a`, or `composite` (alias `fixed`) |
| `host`, `port` | `http`, `https`, `socks5`, `socks4a` | Upstream proxy address (required, port must be non-zero) |
| `username` | proxies | User name for HTTP Basic (`Proxy-Authorization`) or SOCKS5 RFC 1929 auth; for `socks4a` it is sent as the user ID |
| `password` | proxies | Plaintext password |
| `password_env` | proxies | Name of an environment variable holding the password (preferred) |
| `password_file` | proxies | File holding the password (trailing newline trimmed) |
| `bypass` | any except `direct` / `block` | Targets matching this list go `direct` instead (see [bypass syntax](#bypass-syntax)) |
| `tls_insecure_skip_verify` | `https` | Skip verifying the proxy's TLS certificate (default `false`: the OS trust store is used) |
| `http_proxy`, `https_proxy`, `fallback_proxy` | `composite` | Profiles used for `http://` traffic, `https://` traffic, and everything else |

Rules for profiles:

- Use at most one of `password`, `password_env`, and `password_file`.
- Credentials never appear in logs or error messages; upstreams are logged as
  `scheme://host:port`.
- **No DNS leaks:** hostnames are sent to `socks5` upstreams as domain names
  (`ATYP=0x03`), to `socks4a` upstreams with the SOCKS4a domain extension, and to `http` /
  `https` upstreams as `CONNECT host:port`. `socks4a` cannot carry IPv6 literals; such a
  request fails over to the next profile in the chain.
- **Plain HTTP through an HTTP proxy:** when a plain `http://` request routes to an `http` or
  `https` profile, it is forwarded in absolute form (`GET http://host/path`) with
  `Proxy-Authorization`, which corporate proxies expect. Every other combination uses a
  tunnel.
- **Self-loops are rejected:** a profile may not point at one of this server's own listeners.
  `localhost` counts as `127.0.0.1` / `::1`, and a server bound to `0.0.0.0` / `::` also
  protects loopback addresses.

### Composite profiles

A `composite` profile picks another profile by URL scheme, like an AirSwitch `FixedProfile`
with per-scheme proxies:

```toml
[profiles.split]
type = "composite"
http_proxy = "web_proxy"        # http:// requests
https_proxy = "tls_proxy"       # https:// (CONNECT or MITM)
fallback_proxy = "socks_proxy"  # everything else, including SOCKS; omitted = direct
bypass = ["<local>"]
```

Sub-profiles may themselves be composite, but not in a cycle. `test-route` shows the
resolution as `profile=split->web_proxy`.

---

## 6. Routing rules

### How a connection is routed

1. **Global filter.** If top-level `allow` / `block` (or `--allow` / `--block`) is set, it is checked first.
2. **Table selection.** HTTP/HTTPS connections use `[routing.http]` if present, SOCKS
   connections use `[routing.socks]` if present, and everything else uses the unified
   `[routing]` table.
3. **Rules, top to bottom.** The first matching rule wins. Within one rule, **every** field
   must match (AND). Within one field, **any** listed value may match (OR).
4. **Default.** If no rule matches, the table's `default` applies (`"direct"` unless set).
5. **Profile resolution.** If the chosen profile has a `bypass` list that matches, the
   connection goes `direct`. Composite profiles pick a sub-profile by scheme.

### Conditions

| Field | Example | Matches |
| :--- | :--- | :--- |
| `name` | `"corp-hosts"` | *(label only)* shown as `rule=` in logs and `test-route` |
| `inbound` | `"socks"` | Inbound protocol: `"http"` or `"socks"` |
| `host` | `["example.com"]` | Exact host name, case-insensitive, trailing dot ignored |
| `host_wildcard` | `["*.example.com", "**.cdn.example", "dev-?.corp"]` | AirSwitch wildcards: `*.example.com` matches the apex **and** subdomains, `**.example.com` subdomains only; `*` and `?` work anywhere; `\|` separates alternatives in one string |
| `host_regex` | `"^telemetry\\..*\\.example\\.com$"` | Rust regex against the normalized host name |
| `cidr` / `ip` | `["10.0.0.0/8", "fd00::/8", "192.0.2.7"]` | IP literals in a network (IPv4-mapped IPv6 is canonicalized); host names only with `resolve_dns = true` |
| `port` | `443`, `[80, 443]`, `[22, "2200-2299"]` | Destination port, list, or inclusive range |
| `host_levels` | `{ min = 0, max = 1 }` | Number of dots in the host name (AirSwitch `HostLevelsCondition`) |
| `bypass` | `["<local>", "*.local", "10.0.0.0/8", "db:5432"]` | [Bypass syntax](#bypass-syntax) |
| `weekday` | `["mon-fri"]`, `["sat", "sun"]` | Local day of week: `mon`..`sun`, full names, or ranges |
| `time` | `["09:00-17:30"]`, `["22:00-06:00"]` | Local time windows; wrapping past midnight is allowed |
| `url_wildcard` | `["http://downloads.example.com/private/*"]` | Shell wildcard against the full URL |
| `url_regex` | `"^https://api\\.example\\.com/v2/"` | Regex against the full URL |
| `keyword` | `["/ads/"]` | Substring of the full URL |
| `match_all` | `true` | Matches everything (AirSwitch `TrueCondition`) |
| `disabled` | `true` | The rule never matches; kept for reference |
| `resolve_dns` | `true` | Per-rule override of `[routing].resolve_dns` for `cidr` / `ip` |
| `target` | `"corp"` or `["corp", "direct"]` | Profile or failover chain (required) |

A rule must have at least one condition, `match_all = true`, or `disabled = true`.

**URL rules** (`url_wildcard`, `url_regex`, `keyword`) see a URL only for plain HTTP requests
and for HTTPS requests decrypted by MITM. They never match SOCKS connections or opaque HTTPS
`CONNECT` tunnels, and the server prints an `INFO` notice at startup (and on reload) when
such rules sit in a table used by that traffic. With MITM on and URL rules present, every
decrypted request is routed separately, so requests on one tunnel can use different
upstreams.

### Bypass syntax

Used by the `bypass` rule field and by profile-level `bypass` lists (Chromium / AirSwitch
bypass-list syntax):

| Pattern | Matches |
| :--- | :--- |
| `<local>` | `127.0.0.1`, `::1`, and any host name without a dot |
| `localhost`, `*.local`, `.corp.example` | Host wildcards (a leading `.` means `*.`) |
| `127.0.0.1`, `[::1]` | One IP address |
| `10.0.0.0/8`, `fd00::/8` | A network (IP literals only) |
| `db.internal:5432` | A host on one port |
| `https://*.example.com` | A scheme plus a host |

### DNS and IP rules

`resolve_dns` is `false` by default: `cidr` / `ip` rules match only targets that are already
IP literals, and nothing is resolved locally. Set `resolve_dns = true` in `[routing]` or on
one rule to resolve host names through the OS resolver for those rules. That lookup happens
on this machine, so it reveals the host name to your local DNS server.

### Split HTTP and SOCKS tables

The unified `[routing]` table serves both protocols. To treat them differently, either add
`inbound = "http"` / `inbound = "socks"` to individual rules, or add an override table:

```toml
[routing.socks]
default = "bastion"            # fallback for SOCKS (without inherit: "direct" when omitted)
inherit = false                # true: fall back to the unified [routing] rules and default
[[routing.socks.rules]]
host_wildcard = ["*.local"]
target = "direct"
```

`[routing.http]` works the same way for HTTP/HTTPS.

---

## 7. Failover chains

Any `target` or `default` can be an ordered list:

```toml
[[routing.rules]]
host_wildcard = ["*.internal.example"]
target = ["bastion", "corp", "direct"]
```

- Profiles are tried in order. Each attempt is bounded by `connect_timeout`.
- The next profile is tried only if the TCP connect or proxy handshake fails. Once bytes have
  flowed, a broken connection is not retried.
- A `block` profile in a chain stops the chain: the request is refused.
- Logs show the profile that was used (`profile=corp`), and failed attempts are logged at
  `DEBUG`.

---

## 8. Hot-reload

With `--config`, the routing state can change without a restart:

- **`SIGHUP`** (Linux and macOS) always triggers a reload: `kill -HUP <pid>`.
- **`--watch-config`** (all platforms) watches the config file's directory and reloads after
  changes settle for `--watch-debounce` (default `300ms`). Watching the directory catches
  editors that save by writing a new file and renaming it over the old one.

Each reload re-reads the file, re-applies the CLI flags and environment variables the server
started with, and fully validates the result (including self-loops) before anything changes:

- **Success:** the new profiles, rules, and filter replace the old ones atomically and the
  log shows `config reloaded generation=N profiles=P rules=R`. New connections use the new
  configuration; connections already open keep the configuration they started with until
  they close.
- **Failure:** an `ERROR` explains the problem
  (`config reload (...) failed, keeping generation=N: ...`) and the running configuration
  stays active. A bad save never stops the server.

**Reloaded live:** `[profiles.*]`, `[routing]` (rules, defaults, split tables,
`resolve_dns`), `allow`, `block`, `connect_timeout`, `tcp_keepalive`,
`tcp_keepalive_interval`, and `tcp_keepalive_retries`.

**Need a restart:** `bind`, `http_port`, `socks_port`, `max_connections`, `watch_config`,
`watch_debounce`, `mitm.*`, and `logging.*`. If one of these changes, the reload still applies
the live sections and logs which fields were ignored until restart.

---

## 9. Importing from AirSwitch, ZeroOmega, or SwitchyOmega

Export a backup from the extension's options page (**Import/Export → Backup**), then:

```sh
rusty-conduit-switch import-airswitch OmegaOptions.bak                  # TOML to stdout
rusty-conduit-switch import-airswitch OmegaOptions.bak -o config.toml   # write a file
rusty-conduit-switch import-airswitch OmegaOptions.bak -o config.toml --force   # replace it
rusty-conduit-switch import-airswitch OmegaOptions.bak --profile "Work Switch"   # pick a SwitchProfile
rusty-conduit-switch validate --config config.toml
```

- **Output.** TOML goes to stdout unless `-o` / `--output` is given. `-o` refuses to replace
  an existing file unless you pass `--force`. Warnings go to stderr and are also listed in
  the file's header comment.
- **Which SwitchProfile.** `--profile` names the one to import as `[routing]`. Without it, the
  backup's startup profile is used if it is a SwitchProfile, otherwise the only
  SwitchProfile. If there are several, the command fails and lists them.
- **Input.** Plain JSON and base64-encoded JSON backups are both accepted.

### What is converted

| AirSwitch profile | Becomes |
| :--- | :--- |
| `DirectProfile` | The built-in `direct` profile |
| `FixedProfile` | `[profiles.<slug>]` of type `http`, `https`, `socks5`, or `socks4a` (SOCKS4 is imported as `socks4a`, with a warning) with `username` / `password` from `auth` and `bypass` from `bypassList`. If `proxyForHttp` / `proxyForHttps` differ from `fallbackProxy`, a `composite` profile with `<slug>_http`, `<slug>_https`, and `<slug>_fallback` sub-profiles |
| `SwitchProfile` | `[routing]` rules and `default`. Rules pointing at another SwitchProfile, VirtualProfile, or rule list are flattened in evaluation order: the outer condition is ANDed into each nested rule, followed by a rule for the nested profile's default. Cycles are an error |
| `VirtualProfile` | Its `defaultProfileName` target |
| `SwitchyRuleListProfile` / `AutoProxyRuleListProfile` | Rules parsed from the inline `ruleList` text (Switchy and AutoProxy formats). Remote `sourceUrl` lists are never downloaded; a warning says so |
| `SystemProfile` | `direct`, with a warning (no server-side equivalent) |
| `PacProfile` / `AutoDetectProfile` | Skipped with a warning: PAC scripts are not executed. Rules pointing at them are kept commented out |

| AirSwitch condition | Rule field |
| :--- | :--- |
| `HostWildcardCondition` | `host_wildcard` (`\|`-separated patterns split; `*.` and `**.` keep their meaning) |
| `HostRegexCondition` | `host_regex` |
| `IpCondition` | `cidr = ["<ip>/<prefixLength>"]` |
| `BypassCondition` | `bypass` |
| `UrlWildcardCondition` / `UrlRegexCondition` / `KeywordCondition` | `url_wildcard` / `url_regex` / `keyword`, with a comment that URL rules match only plain HTTP or MITM HTTPS |
| `HostLevelsCondition` | `host_levels = { min, max }` |
| `WeekdayCondition` | `weekday` |
| `TimeCondition` | `time = ["HH:00-HH:59"]` |
| `TrueCondition` | `match_all = true` |
| `FalseCondition` | `disabled = true` |

### Names, comments, and warnings

- Profile names become TOML keys: lowercase ASCII letters and digits joined by `_`
  (`"Work Proxy"` → `work_proxy`). Clashes, including with `direct` and `block`, get `_2`,
  `_3`, and so on. Each table carries a `# Imported from AirSwitch profile "..."` comment.
- Rule names come from the rule's note, or `<SwitchProfile name> #N`. Flattened rules are
  named `outer #N > inner #M`.
- Anything that cannot be converted exactly is written as a commented-out rule starting with
  `# SKIPPED: <reason>`, and reported as a warning. This covers regexes with PCRE lookarounds
  (`(?=`, `(?!`, `(?<=`, `(?<!`), which the Rust regex engine does not support, rules that
  point at PAC or unknown profiles, and nested conditions that would need the same field
  twice.
- Passwords are copied in plaintext from the backup, with a warning. Consider moving them to
  `password_env` or `password_file`.
- Server settings (ports, bind address, MITM, logging) are not part of a backup; the imported
  file uses the defaults.

---

## 10. HTTPS MITM inspection

MITM is **off** unless you configure a CA, and the server **never generates one for you**.
See the [MITM CA Guide](MITM-CA-GUIDE.md) to create one and trust it on your clients.

```sh
rusty-conduit-switch --config config.toml --mitm-ca-cert ca.pem --mitm-ca-key ca.key
```

- Applies to HTTPS `CONNECT` tunnels on the HTTP port. The upstream TLS connection runs over
  whichever profile the routing rules pick, including `socks5`, `socks4a`, `http`, and
  `https` proxies. Origin certificates are verified against the OS trust store.
- Leaf certificates are ECDSA P-256, valid from 5 minutes before signing until
  `--mitm-cert-ttl` + 5 minutes. They are cached in memory only, up to
  `--mitm-cert-cache-max-entries` entries.
- SOCKS stays a transparent TCP tunnel. With `--socks-block-web`, SOCKS connections
  that carry HTTP or TLS web traffic are rejected so that browsers cannot bypass inspection by
  switching to SOCKS.
- The access log marks decrypted requests with `mitm=true`.

---

## 11. Logging

Diagnostics go to stderr. Six levels, from quietest to loudest: `QUIET` (nothing), `FATAL`,
`ERROR`, `INFO` (default), `DEBUG`, `VERBOSE`.

Access records (HTTP) and connection records (SOCKS) are appended to the files given by
`--http-access-log` and `--socks-log`, and are also printed to stdout when the level is
`DEBUG` or `VERBOSE`. They include the matched rule, the chosen profile, and the redacted
upstream:

```text
ts=2026-11-25T11:30:01.123Z kind=http client=127.0.0.1:51234 proto=https mitm=false method=CONNECT target=api.internal.example:443 rule=internal-domains-with-failover profile=bastion upstream=socks5://127.0.0.1:1081 status=200 bytes_in=1024 bytes_out=8192 duration_ms=142
ts=2026-11-25T11:30:02.456Z kind=socks client=127.0.0.1:51240 proto=socks5 cmd=CONNECT target=10.0.1.5:5432 rule=rfc1918-to-corp profile=corp upstream=http://10.0.0.2:3128 status=ok bytes_in=512 bytes_out=4096 duration_ms=89
```

`--log-format json` writes the same fields as one JSON object per line (NDJSON). When no
rule matched, `rule=<default>`.

---

## 12. Docker

The repository's `Dockerfile` builds the binary (pure-Rust TLS, no OpenSSL) in a Rust builder
stage and runs it as an unprivileged user. Inside the container the server binds `0.0.0.0`
(`RUSTY_CONDUIT_SWITCH_BIND`), so publish the ports on loopback unless you mean to expose
them:

```sh
docker build -t rusty-conduit-switch .

docker run --rm \
  -p 127.0.0.1:3128:3128 -p 127.0.0.1:1080:1080 \
  -v "$PWD/conf:/etc/rusty-conduit-switch:ro" \
  rusty-conduit-switch --config /etc/rusty-conduit-switch/config.toml --watch-config

# Reload manually
docker kill --signal HUP <container>
```

Mount the config **directory**, not the single file. Editors that save by renaming a new file
over the old one would otherwise leave the container watching a stale copy.
