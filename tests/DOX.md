# tests

## Purpose
Cargo integration tests: end-to-end checks of the crate's public API and the built binary against real servers on loopback and local mock proxies.

## Ownership
Owns `tests/`. Behavior under test is owned by `../src/` (and the `rusty-conduit-engine` crate it re-exports); unit tests stay inline in their source modules.

## Local Contracts
- Hermetic: no external network. Bind listeners on ephemeral loopback ports (`127.0.0.1:0`); use mock proxies and local echo / HTTP origins as sinks.
- Hostnames under `.invalid` must never resolve; a successful dial to one proves the hostname was sent unresolved (remote DNS).
- Scratch files go under `std::env::temp_dir()` with unique per-process names.
- Binary-level tests run the built executable via `env!("CARGO_BIN_EXE_rusty-conduit-switch")`.
- Fixtures (origins, TLS clients, CA generation) use only `[dev-dependencies]`, pure-Rust TLS (`rustls` + `ring`), no OpenSSL.
- Each file is one test crate with its own helpers; there is no shared `tests/common` module.

## Verification
- `cargo test --locked` (CI runs it on Linux x86_64, macOS arm64, and Windows x86_64).

## Feature Map
- **Routing engine & subcommands** — every condition type, unified/split tables, bypass, composite profiles, failover, global filter, `validate` / `test-route`. Start: `routing_rules.rs`.
- **Routed inbound engines** — HTTP forward, HTTPS `CONNECT`, SOCKS4/4a/5 to mock upstreams, failover, filter denial, log route fields. Start: `socks_proxy.rs`.
- **Upstream dialers** — dialers against mock HTTP / SOCKS proxies, remote DNS. Start: `upstream_proxies.rs`.
- **Listener layout & multiplexing** — single-port mux, separate listeners, port `0` disabling. Start: `mux_port.rs`.
- **HTTPS MITM** — MITM over `direct`, SOCKS5, and HTTP `CONNECT` upstreams, access records. Start: `mitm_proxy.rs`.
- **Hot-reload** — live rule/profile swaps, invalid-config preservation, watcher, `SIGHUP`, tunnel survival. Start: `hot_reload.rs`.
- **AirSwitch import** — `.bak` fixtures to TOML, round-trip through `validate` / `test-route`, `-o` overwrite protection. Start: `airswitch_import.rs`.

## Child DOX Index
- (none)
