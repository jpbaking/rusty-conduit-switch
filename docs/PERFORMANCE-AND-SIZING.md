# Performance, Footprint & Sizing Guide

This guide documents `rusty-conduit-switch`'s memory, CPU, file-descriptor, and listen-backlog
characteristics, along with sizing rules of thumb and how its resource caps behave under load.

- Back to [README](../README.md) · [Basic User Guide](USER-GUIDE-BASIC.md) · [Advanced User
  Guide](USER-GUIDE-ADVANCED.md) · [Docker Guide](DOCKER-GUIDE.md)

---

## 1. Zero-Caching Architecture

`rusty-conduit-switch` is a streaming pass-through proxy. Keeping memory predictable starts
with what it **never** retains:

| Component | Cached / Buffered? |
| :--- | :--- |
| HTTP responses (plain or decrypted MITM) | **Never.** Every request reaches the origin through the chosen upstream, regardless of `Cache-Control` / `Expires`. |
| DNS lookups | **Never.** `direct` connections resolve through the OS resolver on every dial; names routed to an upstream proxy are not resolved locally at all. |
| Routing decisions | **Never.** Rules are evaluated for every connection (and for every request when MITM URL rules apply). |
| Upstream TCP/TLS connections | **Never pooled across clients.** Each client connection gets its own upstream connection or tunnel. |
| Request / response bodies | **Never buffered in full.** Streamed frame by frame. |
| MITM leaf certificates | **Yes — the only cache.** Bounded by `--mitm-cert-ttl` (default `1h`) and `--mitm-cert-cache-max-entries` (default `10240`). |

---

## 2. Memory & CPU Footprint

The **measured** figures come from the release container image (Linux arm64) with 1,000 idle
`CONNECT` tunnels routed `direct`, after 1 KiB of traffic each (process RSS; kernel socket
buffers excluded), with `MALLOC_ARENA_MAX=2` set ([see
below](#memory-on-many-core-linux-malloc_arena_max)). **Estimated** figures were not
benchmarked directly; validate them under your own traffic profile.

| Workload / Component | RAM | CPU | Basis |
| :--- | :--- | :--- | :--- |
| Idle process | ~8 MB RSS | ~0% (event-driven) | Measured (`7.6`–`7.9 MB` on 2 and 18 CPUs) |
| Opaque tunnel (`CONNECT` or SOCKS) | ~27 KB / connection | Low (streaming byte copy) | Measured for `CONNECT`; SOCKS uses the same relay |
| Tunnel through an upstream proxy | About the same as above, plus the upstream handshake | Low; `https` profiles add one TLS session to the upstream proxy | Estimated |
| HTTPS MITM tunnel | ~50–150 KB / tunnel | Moderate–High (**2× TLS** via `ring` assembly AES-GCM/ChaCha20 + HTTP/1.1 or HTTP/2 framing) | Estimated |
| Cached MITM leaf certificate | ~3–5 KB / host (~30–50 MB at default `10240` cap) | ~0.2–0.5 ms per cache miss (ECDSA P-256 via `rcgen`, offloaded to blocking pool with single-flight dedup) | Estimated |

- Routing rules run once per connection and never touch the network, unless a rule sets
  `resolve_dns = true`, which adds one local DNS lookup for that rule.
- A failed failover attempt costs up to `connect_timeout` (default `10s`) before the next
  profile is tried. Order chains so the usual upstream comes first.
- The Tokio async runtime spawns one worker thread per CPU core.
- Throughput is typically network-bound for opaque tunnels and plain HTTP, and CPU-bound
  (double TLS) in MITM mode.

### Memory on many-core Linux (`MALLOC_ARENA_MAX`)

On Linux, the prebuilt binaries and the container image use glibc's `malloc`, which gives each
worker thread its own memory arena. On a host with many CPUs, that multiplies both idle and
per-connection memory. Measured with the container image (Linux arm64, 1,000 idle `CONNECT`
tunnels after 1 KiB each):

| Setting | Idle RSS | Per open tunnel |
| :--- | :--- | :--- |
| glibc defaults, 2 CPUs | ~10 MB | 110–230 KB |
| glibc defaults, 18 CPUs | ~43 MB | ~220 KB |
| `MALLOC_ARENA_MAX=2`, 2 or 18 CPUs | ~8 MB | ~27 KB |

On Linux, the binary caps glibc at two arenas itself when `MALLOC_ARENA_MAX` is not set, so the prebuilt binaries and the container image (which also sets `MALLOC_ARENA_MAX=2`) get the low figures on any CPU count. Set `MALLOC_ARENA_MAX` to another value to override it. In a
bulk-transfer test with the same engine (64 parallel tunnels, 2.2–2.7 GB/s), throughput was the
same with or without it, within run-to-run noise. Fewer worker threads also lower the idle
figure: the runtime starts one per CPU it may use, so a Docker `--cpus` limit or
`TOKIO_WORKER_THREADS=<n>` reduces them.

---

## 3. File Descriptors (`ulimit -n`)

Every active proxied connection uses **2 file descriptors**: the client socket, and the socket
to the destination or to the upstream proxy. A MITM tunnel can briefly use extra descriptors
when re-dialing an upstream connection.

Size your process file-descriptor limit using:

```text
ulimit -n  >=  (2 × max_connections) + 64
```

On Unix, `rusty-conduit-switch` automatically raises its soft open-file limit (`RLIMIT_NOFILE`)
toward the hard limit at startup whenever the current soft limit is below that value. If the
limit still cannot hold `--max-connections`, it logs:

```text
NOTICE: open-file limit is <limit> but --max-connections <N> needs at least <needed>; only about <M> concurrent connections will fit. Raise `ulimit -n` (LimitNOFILE= under systemd) or lower --max-connections
```

The default `--max-connections 4096` requires at least **`8256`** file descriptors. Many Linux
shells default to `1024` (~480 concurrent connections), so if the hard limit is also too low,
either raise `ulimit -n` or lower `--max-connections`:

```sh
# Option A: raise FD limit to match default cap
ulimit -n 8256 && rusty-conduit-switch --config config.toml

# Option B: stay comfortably inside a 1024 FD limit
rusty-conduit-switch --config config.toml --max-connections 480
```

Under `systemd`, set `LimitNOFILE=8256` (or higher) in your service unit.

---

## 4. Listen Backlog (`somaxconn`)

Each listener (HTTP and SOCKS) asks the kernel for a listen backlog of `4096`: the queue of
connections that have finished the TCP handshake but that `rusty-conduit-switch` has not
accepted yet. The kernel caps the request at its own limit:

| OS | Limit | Default |
| :--- | :--- | :--- |
| Linux | `net.core.somaxconn` | `4096` (kernel 5.4 and later; `128` before) |
| macOS | `kern.ipc.somaxconn` | `128` |
| Windows | set by the OS | — |

The queue only matters during connection bursts, such as many clients reconnecting at once
after a network drop. When it is full, the kernel drops the new connection attempts and clients
retry about a second later, which shows up as slow connects rather than errors. If you expect
bursts larger than the limit, check it and raise it to `4096`:

```sh
# Linux (persist the setting in /etc/sysctl.d/)
sysctl net.core.somaxconn
sudo sysctl -w net.core.somaxconn=4096

# macOS (resets at reboot)
sysctl kern.ipc.somaxconn
sudo sysctl -w kern.ipc.somaxconn=4096
```

A value above `4096` has no effect, because `rusty-conduit-switch` requests `4096`. The backlog
is fixed when a listener opens, so restart `rusty-conduit-switch` after changing the limit; a
hot-reload does not reopen listeners. On Linux, a container has its own `net.core.somaxconn`
(normally `4096`) unless it uses the host network; set it with `docker run --sysctl
net.core.somaxconn=4096`.

---

## 5. Concurrency & Sizing Rules of Thumb

Assuming a typical active browser holds roughly **10 concurrent TCP connections** (varies
widely with HTTP/2 multiplexing and workload):

| Deployment Profile | `--max-connections` | Recommended `ulimit -n` | Approx. RAM (Opaque) | Approx. RAM (MITM) | Approx. Active Users |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Personal / single device | `256` | `1024` | ~15 MB | up to ~60 MB | 1–25 |
| Home / small team | `1024` | `2112` | ~36 MB | up to ~200 MB | 25–100 |
| Default | `4096` | `8256` | ~120 MB | up to ~700 MB | 100–400 |
| High concurrency (non-MITM) | `16384` | `32832` | ~450 MB | — | 1,000–2,500+ |

The RAM figures assume the measured ~27 KB per tunnel with `MALLOC_ARENA_MAX=2`. On many-core
Linux with glibc defaults, budget up to ~230 KB per open tunnel instead. The upstream proxies
you route to need their own capacity for the connections you send them.

---

## 6. How the Resource Caps Behave

### `--max-connections` (default `4096`, `0` = unlimited)
- Shared across all active listeners (HTTP, SOCKS, or multiplexed).
- When the cap is reached, new incoming connections are **accepted and closed immediately** (no
  reply, no queue, no slowloris buildup) and logged at `DEBUG`.
- Existing connections are unaffected, and a slot is freed immediately when any connection or
  tunnel ends.
- Changing it needs a restart; a hot-reload logs it as ignored.

### `--mitm-cert-cache-max-entries` (default `10240`, `0` = unlimited)
- Strictly bounds the number of in-memory MITM leaf certificates.
- When a new hostname is signed at the cap:
  1. Already-expired entries are reaped first so live certificates are not evicted
     unnecessarily.
  2. If the cache is still at the cap, the **oldest** entries (closest to expiry) are evicted
     and logged at `VERBOSE`.
- Cache hits are lock-free and unaffected; an evicted host is simply re-signed on its next
  connection.

### `--connect-timeout` (default `10s`)
- Bounds each upstream TCP connect plus proxy handshake, per failover attempt. A chain of three
  profiles can take up to three timeouts before the client gets an error.
- Reloaded live.

> **Security note:** Setting either cap to `0` disables the upper bound. Avoid `0` on untrusted networks where a client could exhaust file descriptors or flood random SNI hostnames.
