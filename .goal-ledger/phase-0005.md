# phase-0005 — Opt-in MITM over routed upstreams and SOCKS web guard

- Status: done
- Owner: executor
- Depends on: phase-0004
- Goal: Port the pure-Rust opt-in MITM engine (`src/mitm/`), implement `src/http/mitm_tunnel.rs` running upstream TLS over any `UpstreamStream` with per-request URL routing when URL rules exist, and implement `src/socks/web_guard.rs` (`--socks-block-web-in-mitm`).
- Done when: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` exits 0 with `tests/mitm_proxy.rs` passing for MITM over direct, SOCKS5, and HTTP upstreams, per-request URL routing under MITM, leaf cert caching/reaping, and `--socks-block-web-in-mitm`.
- Pattern to follow: ../rusty-conduit/src/mitm/mod.rs:1, ../rusty-conduit/src/mitm/ca.rs:1, ../rusty-conduit/src/mitm/signer.rs:1, ../rusty-conduit/src/mitm/cache.rs:1, ../rusty-conduit/src/http/mitm_tunnel.rs:1, ../rusty-conduit/src/socks/web_guard.rs:1, ../rusty-conduit/tests/mitm_proxy.rs:1

## Context
Read `docs/MASTER-PLAN.md` Section 1 (Principles 1, 3, 4), Section 4 (MITM + Per-Request URL Routing), and Section 8 (`src/mitm/`, `src/http/mitm_tunnel.rs`, `src/socks/web_guard.rs`).
MITM is OFF by default and NEVER auto-generates a root CA. Users supply PEM (`ca_cert` + `ca_key`) or PKCS#12 (`ca_p12`) with optional passphrase/passphrase-file.
In `src/http/mitm_tunnel.rs`:
- Upstream TLS (`tokio-rustls` client) runs over ANY `UpstreamStream` returned by `Router` + `UpstreamDialer` (direct, SOCKS5, SOCKS4a, HTTP CONNECT, HTTPS CONNECT).
- If the active router has no URL-level rules (`url_wildcard`, `url_regex`, `keyword`), resolve the route once at `CONNECT` time and reuse the upstream TLS connection across requests on that tunnel.
- If URL-level rules ARE configured, evaluate the router per decrypted HTTPS request with full `https://host/path?query`, dialing a different upstream profile if consecutive requests route differently.

## Scope
- In: src/mitm/mod.rs, src/mitm/ca.rs, src/mitm/signer.rs, src/mitm/cache.rs, src/http/mitm_tunnel.rs, src/http/mod.rs, src/socks/mod.rs, src/socks/web_guard.rs, src/socks/v4.rs, src/socks/v5.rs, src/server.rs, src/lib.rs, tests/mitm_proxy.rs
- Out: docs/MASTER-PLAN.md, src/reload.rs, src/import/*

## Sub-tasks
1. [done] Port `src/mitm/ca.rs`, `src/mitm/signer.rs`, `src/mitm/cache.rs`, and `src/mitm/mod.rs` from `../rusty-conduit/src/mitm/` (PEM & PKCS#12 CA loading, startup validation, `rcgen` leaf cert signing with `-5m`/`+TTL+5m`, bounded `DashMap` TTL + max-entry `CertCache` with single-flight dedup and background reaper) — done when: `cargo test --lib mitm` exits 0.
2. [done] Implement `src/http/mitm_tunnel.rs` and wire it in `src/http/mod.rs` so MITM HTTPS `CONNECT` terminates client TLS, performs upstream TLS over any `UpstreamStream` from `Router` + `ProfileRegistry`, reuses the upstream TLS connection when no URL rules exist, and evaluates per-request URL rules when URL rules are configured — done when: `cargo check --lib` exits 0.
3. [done] Port `src/socks/web_guard.rs` from `../rusty-conduit/src/socks/web_guard.rs` and wire `--socks-block-web-in-mitm` in `src/socks/mod.rs`, `src/socks/v4.rs`, `src/socks/v5.rs`, and `src/server.rs` — done when: `cargo test --lib socks` exits 0.
4. [done] Write end-to-end tests in `tests/mitm_proxy.rs` covering MITM over direct, mock SOCKS5, and mock HTTP CONNECT upstreams, per-request URL-rule routing switching upstreams within one MITM connection, leaf cert cache TTL/cap, and `--socks-block-web-in-mitm` blocking HTTP/TLS-ALPN over SOCKS while allowing non-web TCP — done when: `cargo test --test mitm_proxy` exits 0.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Escalate when
- `tokio-rustls` client handshake over `UpstreamStream::Tls` (TLS-over-TLS to an `https` upstream proxy) hits a type/recursion or `Unpin` issue → stop, set Status: needs-human — reason: <exact compiler error>
- `p12-keystore` or `rcgen` API differs from `../rusty-conduit` → stop, set Status: needs-human — reason: <exact API error>

## Log
- (append-only, one line per event)
- sub-task 1: copied ../rusty-conduit/src/mitm/{ca,signer,cache,mod}.rs to src/mitm/; adapted config field mitm_cert_cache_max_entries→mitm_cert_cache_max, default-cap assertion → DEFAULT_MITM_CERT_CACHE_MAX, local quiet_logger in cache tests (no http::test_support here); registered `pub mod mitm;` in src/lib.rs
- sub-task 2: wrote src/http/mitm_tunnel.rs (MitmInterceptor, routed Dialer: Router decision → ProfileRegistry::chain_for → FailoverDialer::dial → tokio-rustls client over UpstreamStream; Routing::Fixed reuses the CONNECT-time upstream (h1/h2), Routing::PerRequest when router.has_url_rules(Http): routes each request with full https URL, redials when chain_key changes, HTTP/1.1 only); wired in src/http/mod.rs (pub mod mitm_tunnel, HttpProxy.mitm + with_mitm/mitm_enabled, dispatch → mitm_connect with 400/403 pre-200)
- sub-task 3: blocked — needs src/socks/mod.rs (outside Scope: In); escalated, no socks files changed
- [planner] answered escalation: added `src/socks/mod.rs` to `Scope: In` (and sub-task 3) for `pub mod web_guard;` and the `RelayGuard` hook in `SocksProxy::relay`; HTTP/1.1-only in per-request URL-rule MITM mode is approved. Reset phase-0005 and sub-task 3 to todo; continue phase-0005 from sub-task 3.
- sub-task 3: ported src/socks/web_guard.rs (WebGuard, is_web_traffic, ClientHello ALPN parser; pure tests + duplex test of the guarded first chunk); src/socks/mod.rs: pub mod web_guard, GuardVerdict/RelayGuard, SocksProxy.guard + with_guard/has_guard, guarded_first_chunk in SocksProxy::relay (v4.rs:171/v5.rs:223 already route through relay, so they need no change); src/server.rs: EngineHandlers::with_mitm(interceptor, socks_block_web) installs WebGuard only with MITM, plus http_engine()/socks_engine(); src/lib.rs run(): MitmState::from_config (FATAL on error), MITM/SOCKS-guard INFO lines, cert reaper on the shutdown token
- sub-task 4: wrote tests/mitm_proxy.rs (8 tests: MITM over direct/SOCKS5/HTTP CONNECT with route fields + unresolved hostnames; h2 via SOCKS5; per-request URL rules switching web→corp→direct→web in one tunnel incl. per-request block 403; PKCS#12 CA + TTL reuse + reaper eviction; lazy expiry; CertCache cap; --socks-block-web-in-mitm blocks HTTP and h2-ALPN TLS, allows raw TCP and imap-ALPN TLS; no guard without the flag)
- Verify passed: cargo fmt --check, cargo clippy --all-targets -D warnings, cargo test

## Evidence
- (append-only: command → observed result)
- `cargo test --lib mitm` → test result: ok. 28 passed; 0 failed
- `cargo check --lib` → Finished, 0 errors/warnings (TLS over UpstreamStream compiled without Unpin/recursion issues)
- `cargo fmt --check` → exit 0; `cargo clippy --all-targets -- -D warnings` → Finished (only pre-existing manifest unused-dependency warning)
- `grep -n "mod \|relay" src/socks/mod.rs` → 14:pub mod v4; 15:pub mod v5; 295: pub(crate) async fn relay( — module list and relay hook are in src/socks/mod.rs
- `cargo test --lib socks` → test result: ok. 21 passed; 0 failed
- `cargo test --lib` → test result: ok. 162 passed; 0 failed
- `cargo test --test mitm_proxy` → test result: ok. 8 passed; 0 failed
- Verify `cargo fmt --check` → rc=0
- Verify `cargo clippy --all-targets -- -D warnings` → rc=0 (only pre-existing manifest warning: unused dependency `notify`)
- Verify `cargo test` → rc=0: lib 162, main 0, mitm_proxy 8, mux_port 3, routing_rules 17, socks_proxy 10, upstream_proxies 14 passed; 0 failed
- [planner Gate D] independently verified: `cargo fmt --check` exit 0, `cargo clippy --all-targets -- -D warnings` exit 0 (only pre-existing manifest unused-dependency warning), `cargo test` mitm_proxy 8 pass. Close commit `f5d104d` scope-clean (src/socks/mod.rs, src/socks/web_guard.rs, src/server.rs, src/lib.rs, tests/mitm_proxy.rs + the two ledger files). The phase-0005 scope change adding `src/socks/mod.rs` + `src/server.rs` to Scope: In (from the blocked→unblock escalation) is retroactively approved here as planner — both files are genuinely required for `pub mod web_guard;` and the `RelayGuard` hook in `SocksProxy::relay`. Phase-0005 approved.
