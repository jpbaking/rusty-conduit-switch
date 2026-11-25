# phase-0006 — Atomic hot-reload engine

- Status: done
- Owner: executor
- Depends on: phase-0005
- Goal: Implement lock-free `ArcSwap<RuntimeConfig>` hot-reload in `src/reload.rs` triggered by Unix `SIGHUP` and cross-platform debounced `--watch-config` parent-directory watching, with strict validate-before-swap and non-reloadable-field notices.
- Done when: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` exits 0 with `tests/hot_reload.rs` passing for live route changes, profile changes, invalid TOML preservation, non-reloadable field warnings, and in-flight tunnel survival across reload.
- Pattern to follow: docs/MASTER-PLAN.md:278

## Context
Read `docs/MASTER-PLAN.md` Section 3 (Hot-Reloadable Config Sections) and Section 6 (Hot-Reload Engine).
All hot-reloadable state (`Router`, `ProfileRegistry`, global `HostFilter`, `connect_timeout`, `KeepaliveSettings`, `config_generation: u64`) lives in an immutable `Arc<RuntimeConfig>` stored in `ArcSwap<RuntimeConfig>`.
Each accepted connection (and each decrypted MITM request when URL rules are present) calls `state.load()` once.
Reload triggers:
1. `SIGHUP` on Unix (`#[cfg(unix)]`) whenever `--config` is set.
2. `--watch-config` using `notify` watching the parent directory of `--config` (to catch atomic rename-over-file saves), filtering events to the target filename, debounced by `--watch-debounce` (default `300ms`).
Validate-before-swap: re-read TOML, re-apply CLI/env overrides for reloadable fields, compile and validate (including self-loop detection against active listener addresses), log `INFO` warning for changed non-reloadable fields (`bind`, `http_port`, `socks_port`, `mitm.*`, `logging.*`, `max_connections`), keep previous `Arc<RuntimeConfig>` on any error, or atomically swap and increment `config_generation` on success.

## Scope
- In: src/reload.rs, src/config.rs, src/server.rs, src/http/mod.rs, src/http/forward.rs, src/http/tunnel.rs, src/http/mitm_tunnel.rs, src/socks/mod.rs, src/socks/v4.rs, src/socks/v5.rs, src/lib.rs, tests/hot_reload.rs
- Out: docs/MASTER-PLAN.md, src/import/*

## Sub-tasks
1. [done] Implement `src/reload.rs` defining `RuntimeConfig`, `SharedRuntime` (`Arc<ArcSwap<RuntimeConfig>>`), `reload_once(...)` with validate-before-swap + CLI/env override re-application + non-reloadable-field diff warnings + `config_generation` increment, Unix `SIGHUP` task, and `notify` parent-directory debounced watcher task — done when: `cargo test --lib reload` exits 0.
2. [done] Wire `SharedRuntime` into `src/server.rs`, `src/lib.rs`, `src/http/*`, and `src/socks/*` so every new connection (and MITM URL-routed request) snapshots `Arc<RuntimeConfig>` lock-free while existing tunnels retain their snapshot — done when: `cargo test --lib` exits 0.
3. [done] Write integration tests in `tests/hot_reload.rs` verifying live routing rule swap, live upstream profile swap, invalid TOML reload preserving the prior working config, atomic rename-over-file save detection under `--watch-config`, Unix `SIGHUP` reload, non-reloadable field warning, and an established TCP tunnel surviving across a reload without dropping — done when: `cargo test --test hot_reload` exits 0.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Escalate when
- `notify` crate file-watcher events behave flakily on macOS `kqueue`/`FSEvents` in temp directories even after parent-dir watching + debounce → stop, set Status: needs-human — reason: <observed event trace>
- Re-applying CLI/env overrides during reload conflicts with how `config.rs` tracks explicit vs default CLI values → stop, set Status: needs-human — reason: <exact tracking gap>

## Log
- (append-only, one line per event)
- sub-task 1: added src/reload.rs (RuntimeConfig moved from server.rs with keepalive/filter/config_generation, SharedRuntime, Reloader::reload_once validate-before-swap re-merging startup CliInput, non_reloadable_changes/pin_non_reloadable, spawn_sighup, spawn_watcher); server.rs keeps RoutingState/SharedRouting/RoutingSetupError as aliases; lib.rs `pub mod reload`
- sub-task 2: HTTP RequestCtx snapshots the runtime once per accepted connection (forward/tunnel/MITM CONNECT use it); MitmConnect carries the live SharedRouting and Routing::PerRequest loads a fresh snapshot per decrypted request (upstream reuse key includes config_generation); SOCKS already loads once per connection; Server::with_runtime takes client keepalive from the live snapshot; lib::run(cfg, cli, logger) builds a Reloader and start_reload_triggers (SIGHUP when --config, watcher when --watch-config) stopped on shutdown
- sub-task 3: tests/hot_reload.rs (8 tests: rule swap over HTTP+SOCKS, profile swap, invalid TOML/config/missing file preservation, watch-config rename-over + in-place save via lib::start_reload_triggers, SIGHUP via `kill -HUP`, non-reloadable INFO notice, HTTP CONNECT + SOCKS5 tunnels surviving 2 reloads); watch test waits on routing outcome because macOS FSEvents also reports the pre-watch file creation (one benign no-op reload ~100ms after arming)
- phase Verify passed; phase closed

## Evidence
- (append-only: command → observed result)
- `cargo test --lib reload` → test result: ok. 8 passed; 0 failed
- `cargo test --lib` → test result: ok. 171 passed; 0 failed
- `cargo test --test hot_reload` → test result: ok. 8 passed; 0 failed (15 consecutive runs: 15/15 ok)
- `cargo fmt --check` → exit 0; `cargo clippy --all-targets -- -D warnings` → exit 0; `cargo test` → exit 0 (lib 171, hot_reload 8, mitm_proxy 8, mux_port 3, routing_rules 17, socks_proxy 10, upstream_proxies 14 = 231 passed)
- [planner Gate D] independently verified: `cargo fmt --check` exit 0, `cargo clippy --all-targets -- -D warnings` exit 0, `cargo test` hot_reload 8 (15/15 runs) pass. Close commit `5f9fc5b` scope-clean (src/reload.rs, src/server.rs, src/http/{mod,forward,tunnel}.rs, src/http/mitm_tunnel.rs, src/lib.rs, tests/hot_reload.rs + the two ledger files). Phase-0006 approved.
