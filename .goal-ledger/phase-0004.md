# phase-0004 — Inbound HTTP/HTTPS and SOCKS4/4a/5 wired to router

- Status: done
- Owner: executor
- Depends on: phase-0003
- Goal: Implement inbound HTTP forward proxy, non-MITM HTTPS CONNECT tunnel, and SOCKS4/4a/5 server handlers wired through the Auto Switch `Router` and `UpstreamDialer`, plus single-port mux and end-to-end cross-protocol tests.
- Done when: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` exits 0 with `tests/socks_proxy.rs` and `tests/mux_port.rs` passing for HTTP, HTTPS CONNECT, SOCKS4/4a/5, plain-HTTP-to-HTTP-upstream absolute-form forwarding, cross-protocol routing, failover, block responses, and single-port mux.
- Pattern to follow: ../rusty-conduit/src/http/mod.rs:1, ../rusty-conduit/src/http/forward.rs:1, ../rusty-conduit/src/http/tunnel.rs:1, ../rusty-conduit/src/socks/mod.rs:1, ../rusty-conduit/src/socks/v4.rs:1, ../rusty-conduit/src/socks/v5.rs:1, ../rusty-conduit/tests/socks_proxy.rs:1, ../rusty-conduit/tests/mux_port.rs:1

## Context
Read `docs/MASTER-PLAN.md` Section 2 (Ports & Multiplexing, Plain HTTP → HTTP Upstream, Failover Chains) and Section 9 (Logging Additions).
When a plain HTTP request (`http://...`) routes to an `http` or `https` upstream profile, `src/http/forward.rs` MUST forward in absolute-form (`GET http://host:port/path HTTP/1.1` + `Proxy-Authorization` if configured) directly to the upstream proxy rather than issuing `CONNECT` to port 80. When plain HTTP routes to `direct`, `socks5`, or `socks4a`, it uses `UpstreamDialer` and sends origin-form HTTP.
`RouteBlocked` maps to HTTP `403 Forbidden`, SOCKS5 reply `0x02`, and SOCKS4 reply `0x5B`. Every HTTP/HTTPS and SOCKS log entry must include `rule=`, `profile=`, and redacted `upstream=`.
For `RouteRequest.scheme`: plain HTTP passes `Some("http")`, HTTPS `CONNECT` passes `Some("https")`, and SOCKS passes `None`.

## Scope
- In: src/http/mod.rs, src/http/forward.rs, src/http/tunnel.rs, src/socks/mod.rs, src/socks/v4.rs, src/socks/v5.rs, src/server.rs, src/lib.rs, tests/socks_proxy.rs, tests/mux_port.rs
- Out: docs/MASTER-PLAN.md, src/mitm/*, src/http/mitm_tunnel.rs, src/socks/web_guard.rs, src/reload.rs, src/import/*

## Sub-tasks
1. [done] Implement `src/http/mod.rs`, `src/http/forward.rs`, and `src/http/tunnel.rs` wired to `Router` and `ProfileRegistry`, including streaming plain HTTP forwarding (absolute-form + `Proxy-Authorization` for `http`/`https` upstreams, origin-form over `UpstreamDialer` for `direct`/`socks5`/`socks4a`), non-MITM `CONNECT` opaque tunneling, `403 Forbidden` on `RouteBlocked` / global filter denial, and structured access logging with `rule`/`profile`/`upstream` — done when: `cargo check --lib` exits 0.
2. [done] Implement `src/socks/mod.rs`, `src/socks/v4.rs`, and `src/socks/v5.rs` wired to `Router` and `ProfileRegistry` (TCP `CONNECT`, IPv4/IPv6/Domain, no inbound auth in v1), mapping `RouteBlocked` to SOCKS5 `0x02` and SOCKS4 `0x5B`, and logging `rule`/`profile`/`upstream` — done when: `cargo check --lib` exits 0.
3. [done] Wire `src/http` and `src/socks` into `src/server.rs` (separate HTTP/SOCKS listeners, single-port mux when `http_port == socks_port > 0`, disabled listener when port is `0`) — done when: `cargo build` exits 0.
4. [done] Write end-to-end integration tests in `tests/socks_proxy.rs` and `tests/mux_port.rs` verifying HTTP forward (both absolute-form to mock HTTP upstream and tunnel to mock SOCKS5 upstream), HTTPS `CONNECT`, SOCKS4/4a/5 routed to mock HTTP/SOCKS5/direct/block upstreams, failover, zero local DNS lookup for unresolvable proxied hostnames (e.g. `nonexistent.invalid`), single-port mux, and port-0 disable — done when: `cargo test --test socks_proxy --test mux_port` exits 0.
5. [done] Fix-up: `## Verify` `cargo fmt --check` reported formatting diffs in src/http/tunnel.rs, src/lib.rs, src/server.rs, src/socks/mod.rs, tests/mux_port.rs, tests/socks_proxy.rs; run `cargo fmt` on those in-scope files — done when: `cargo fmt --check` exits 0.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Escalate when
- Absolute-form forwarding over `hyper` 1.x client requires a custom URI or host header workaround that conflicts with HTTP/1.1 connection pooling → stop, set Status: needs-human — reason: <exact hyper behavior>
- `server.rs` needs a trait or state shape change that breaks `config.rs` or `router` public APIs → stop, set Status: needs-human — reason: <exact breaking signature>

## Log
- (append-only, one line per event)
- sub-task 1: src/http/{mod,forward,tunnel}.rs routed via RoutingState (server.rs) — absolute-form to http/https proxies via HttpConnectDialer::connect_proxy, origin-form over UpstreamDialer otherwise, CONNECT via registry failover chain, 403 on RouteBlocked/filter, rule/profile/upstream on access records
- sub-task 2: src/socks/{mod,v4,v5}.rs — route_and_dial via Router (inbound=socks, no scheme/url) + registry failover chain; RouteBlocked/filter → Failure::NotAllowed (SOCKS5 0x02, SOCKS4 0x5B); Session logs rule/profile/upstream; parser unit tests
- sub-task 3: server.rs EngineHandlers (HttpProxy+SocksProxy over SharedRouting) plugged into existing ListenPlan (separate / mux when http_port==socks_port>0 / port 0 disables); lib.rs run builds RoutingState::from_config (FATAL on error) instead of StubHandlers
- sub-task 4: tests/socks_proxy.rs (10 tests: absolute-form+Proxy-Authorization to mock HTTP upstream, origin-form over SOCKS5 and direct, CONNECT to http/socks5/socks4a/direct, SOCKS4/4a/5 to http/socks5/socks4a/direct/block, IPv6, failover, filter 403/0x02/0x5B, nonexistent.invalid reaches upstream unresolved) and tests/mux_port.rs (3 tests: single-port mux all protocols, config equal ports → mux, port 0 disables each listener, separate listeners)
- verify: initial cargo fmt --check failed (formatting diffs in 6 in-scope files); added fix-up sub-task 5 and ran rustfmt on in-scope files only

- verify passed: fmt/clippy/test all rc=0; phase closed

## Evidence
- (append-only: command → observed result)
- cargo check --lib → Finished dev profile, 0 errors/warnings
- cargo check --lib → Finished, 0 errors; cargo test --lib socks → 15 passed
- cargo build → Finished dev profile; only pre-existing Cargo.toml unused-dependency warnings (dashmap, notify, p12-keystore, rcgen)
- cargo test --test socks_proxy --test mux_port → socks_proxy 10 passed, mux_port 3 passed, 0 failed
- cargo fmt --check (initial Verify) → Diff in src/http/tunnel.rs, src/lib.rs, src/server.rs, src/socks/mod.rs, tests/mux_port.rs, tests/socks_proxy.rs; after rustfmt → cargo fmt --check rc=0
- Verify: cargo fmt --check → rc=0; cargo clippy --all-targets -- -D warnings → rc=0, 0 errors (only pre-existing Cargo.toml unused-dependency manifest warnings: dashmap, notify, p12-keystore, rcgen); cargo test → rc=0 (lib 128, mux_port 3, routing_rules 17, socks_proxy 10, upstream_proxies 14 passed, 0 failed)
- smoke: target/debug/rusty-conduit-switch --http-port P --socks-port P → "multiplexed HTTP/HTTPS + SOCKS4/4a/5 proxy listening"; GET http://x.invalid/ → 502 with access line rule=<default> profile=direct upstream=direct; SOCKS5 greeting → 05 00, CONNECT x.invalid → REP 0x01; SIGTERM → drained, shutting down
- [planner Gate D] independently verified: `cargo fmt --check` exit 0, `cargo clippy --all-targets -- -D warnings` exit 0 (only pre-existing cargo-manifest `unused dependency` warnings), `cargo test` socks_proxy 10 + mux_port 3 pass. Close commit `4fd8b0f` scope-clean (src/http/{mod,forward,tunnel}.rs, src/socks/{mod,v4,v5}.rs, src/server.rs, src/lib.rs, tests/socks_proxy.rs, tests/mux_port.rs + the two ledger files). Phase-0004 approved.
