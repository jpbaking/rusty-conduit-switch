# phase-0003 — Upstream dialers and failover chains

- Status: done
- Owner: executor
- Depends on: phase-0002
- Goal: Implement the `UpstreamDialer` abstraction, `UpstreamStream` (`Tcp` / `Tls`), all 6 built-in upstream dialers (`direct`, `block`, `socks5`, `socks4a`, `http`, `https`), and `FailoverDialer`, verified against local mock proxy servers.
- Done when: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` exits 0 with `tests/upstream_proxies.rs` passing for direct, block, SOCKS5 (no-auth & RFC 1929 auth, remote DNS), SOCKS4a (remote DNS), HTTP CONNECT (with Basic auth), HTTPS CONNECT (`rustls`), and failover chains.
- Pattern to follow: ../rusty-conduit-ssh/src/net.rs:1, docs/MASTER-PLAN.md:229

## Context
Read `docs/MASTER-PLAN.md` Section 5 (Upstream Dialer & Proxy Chaining Layer).
Every outbound connection goes through `UpstreamDialer` returning `UpstreamStream` (`Tcp(TcpStream)` or `Tls(tokio_rustls::client::TlsStream<TcpStream>)`, plus preserving any unread bytes after HTTP `CONNECT` headers via `PrefixedStream`).
Hostnames routed to `socks5`, `socks4a`, `http`, or `https` MUST be sent unresolved (no local DNS lookup). `BlockDialer` returns typed `RouteBlocked` (`ErrorKind::PermissionDenied`) without touching DNS or network. `FailoverDialer` retries next target only on TCP connect / proxy handshake failure (never on `RouteBlocked` and never mid-stream). Credentials must never appear in logs or error strings.

## Scope
- In: src/upstream/mod.rs, src/upstream/direct.rs, src/upstream/block.rs, src/upstream/socks5.rs, src/upstream/socks4a.rs, src/upstream/http.rs, src/lib.rs, tests/upstream_proxies.rs
- Out: docs/MASTER-PLAN.md, src/http/*, src/socks/*, src/mitm/*, src/reload.rs, src/import/*

## Sub-tasks
1. [done] Implement `src/upstream/mod.rs` defining `UpstreamStream` (implementing `AsyncRead + AsyncWrite + Unpin + Send`), `DialOutcome` (stream, chosen profile name, redacted upstream URI, attempt index), `UpstreamDialer` trait, `RouteBlocked` error type, `ProfileRegistry`, and `FailoverDialer` — done when: `cargo check --lib` exits 0.
2. [done] Implement `src/upstream/direct.rs` (`DirectDialer` with OS/Tokio DNS, `TCP_NODELAY`, and `KeepaliveSettings`) and `src/upstream/block.rs` (`BlockDialer` returning `RouteBlocked`) — done when: `cargo test --lib upstream` exits 0.
3. [done] Implement `src/upstream/socks5.rs` (RFC 1928 `CONNECT` with `ATYP=0x03` remote DNS, IPv4/IPv6 literals, and optional RFC 1929 username/password auth) and `src/upstream/socks4a.rs` (SOCKS4a `0.0.0.1` remote DNS, IPv4 literal, clean error on IPv6) — done when: `cargo test --lib upstream` exits 0.
4. [done] Implement `src/upstream/http.rs` for both `HttpConnectDialer` (`http`) and `HttpsConnectDialer` (`https` over `tokio-rustls` using `rustls-platform-verifier` with optional `tls_insecure_skip_verify` and custom test root certs), supporting Basic `Proxy-Authorization` and preserving buffered trailing bytes via `PrefixedStream` — done when: `cargo test --lib upstream` exits 0.
5. [done] Write end-to-end integration tests in `tests/upstream_proxies.rs` spinning up local mock TCP echo, SOCKS5 (no-auth & user/pass), SOCKS4a, HTTP CONNECT (auth & no-auth), and HTTPS CONNECT servers, testing direct, block, remote DNS preservation, credential redaction, and failover chain behavior — done when: `cargo test --test upstream_proxies` exits 0.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Escalate when
- `rustls-platform-verifier` or `tokio-rustls` API version in `Cargo.toml` requires a different verifier construction for `tls_insecure_skip_verify` or test CAs → stop, set Status: needs-human — reason: <exact compiler error>
- A mock HTTPS upstream test cannot verify a self-signed cert without an explicit test-only `ClientConfig` hook → stop, set Status: needs-human — reason: <proposed hook API>

## Log
- (append-only, one line per event)
- began phase (ledger commit bd2d1b5)
- sub-task 1: src/upstream/mod.rs — UpstreamStream {Tcp, Tls(Box), Prefixed(Box<PrefixedStream<UpstreamStream>>)} with AsyncRead/AsyncWrite, DialFuture, UpstreamDialer (connect + redacted_upstream), RouteBlocked (PermissionDenied, is_route_blocked), DialOutcome {stream, profile, upstream, attempt}, DialerOptions, dialer_for_profile, ProfileRegistry (from_profiles/from_config/chain/chain_for), FailoverDialer (per-attempt timeout, stops on RouteBlocked, DEBUG log, aggregated redacted error); src/lib.rs registers `pub mod upstream`. Tls and Prefixed are boxed (clippy large_enum_variant / recursion); PrefixedStream reused from src/net.rs unchanged (net.rs is out of scope, so no inner-ref accessors)
- sub-task 2: direct.rs (DirectDialer over net::connect_upstream_filtered: OS DNS, TCP_NODELAY, KeepaliveSettings, optional HostFilter) and block.rs (BlockDialer -> RouteBlocked, no DNS/network)
- sub-task 3: socks5.rs (RFC 1928, ATYP 0x03/0x01/0x04, RFC 1929 auth offered only with credentials, creds never in errors/Debug) and socks4a.rs (0.0.0.1 + hostname, IPv4 literal, IPv6 -> ErrorKind::Unsupported before contacting the proxy)
- sub-task 4: http.rs — HttpConnectDialer::http / ::https (HttpsConnectDialer alias), TlsOptions {insecure_skip_verify, roots}; verifier: NoVerify (still checks handshake signatures) | RootCertStore of custom roots (replaces OS store) | rustls-platform-verifier BuilderVerifierExt; Basic Proxy-Authorization; trailing bytes after \r\n\r\n kept via UpstreamStream::with_prefix; also connect_proxy()/proxy_authorization() for phase 4 absolute-form forwarding. No escalation trigger hit: platform-verifier 0.6.2 API compiled as-is, and custom test roots use the TlsOptions.roots field named in this sub-task
- sub-task 5: tests/upstream_proxies.rs — mock echo, SOCKS5 (no-auth & user/pass), SOCKS4a, HTTP CONNECT (auth & no-auth, early bytes), HTTPS CONNECT (rcgen self-signed, tokio-rustls acceptor), closed-port and silent servers; 14 tests covering direct, block, remote DNS (`.invalid` targets recorded unresolved), IPv6 literals, credential redaction, registry, failover (refused/timeout/handshake advance, RouteBlocked stop, aggregated error)
- Verify passed on first run (cargo fmt applied once before the check to format the new files)
- noted: .goal-ledger/phase-0002.md has an uncommitted planner Gate D log line added after the begin commit; not staged by this phase

## Evidence
- (append-only: command → observed result)
- `cargo check --lib` → Finished, 0 errors (sub-task 1)
- `cargo test --lib upstream` → ok. 19 passed; 0 failed (upstream::{tests,direct,block,socks5,socks4a,http} + net tests matching filter) (sub-tasks 2-4)
- `cargo test --test upstream_proxies` → ok. 14 passed; 0 failed; finished in 0.61s (sub-task 5)
- Verify `cargo fmt --check` → exit 0
- Verify `cargo clippy --all-targets -- -D warnings` → exit 0 (only the pre-existing cargo-manifest `unused dependency` warnings, e.g. arc-swap, dashmap, notify, rcgen; Cargo.toml untouched)
- Verify `cargo test` → lib 116 passed; routing_rules 17 passed; upstream_proxies 14 passed; 0 failed
- [planner Gate D] independently verified: `cargo fmt --check` exit 0, `cargo clippy --all-targets -- -D warnings` exit 0 (only pre-existing cargo-manifest `unused dependency` warnings), `cargo test` upstream_proxies 14 pass. Close commit `2f89da5` scope-clean (src/upstream/{mod,direct,block,socks5,socks4a,http}.rs, src/lib.rs, tests/upstream_proxies.rs + the two ledger files). Phase-0003 approved.
