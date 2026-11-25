# phase-0001 — Scaffold, config, logging, and core engine

- Status: done
- Owner: executor
- Depends on: none
- Goal: Create the rusty-conduit-switch Cargo project with full CLI/env/TOML config parsing, 6-level logging with routing fields, global egress filter, protocol mux, socket keepalive/relay utilities, and listener skeleton.
- Done when: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` exits 0 and `cargo run -- --help` lists `validate`, `test-route`, and `import-airswitch`.
- Pattern to follow: ../rusty-conduit/Cargo.toml:1, ../rusty-conduit/src/config.rs:1, ../rusty-conduit/src/logging.rs:1, ../rusty-conduit/src/filter.rs:1, ../rusty-conduit/src/mux.rs:1, ../rusty-conduit/src/net.rs:1, ../rusty-conduit/src/server.rs:1

## Context
This is a greenfield Rust project implementing `docs/MASTER-PLAN.md` (read Sections 1–3 and 8–10 first).
The sibling repo `../rusty-conduit` contains the proven pure-Rust TLS stack (`rustls` + `ring`, zero OpenSSL/aws-lc), 6-level logging, global destination filter, single-port mux, TCP keepalive/PrefixedStream/relay utilities, and server listener harness.
In this phase, port and adapt those foundations to `rusty-conduit-switch` with `RUSTY_CONDUIT_SWITCH_*` env vars, full TOML schema for `[profiles.*]`, `[routing]`, `[routing.http]`, `[routing.socks]`, `[filter]`, `[tcp_keepalive]`, `[mitm]`, `[logging]`, and subcommand dispatch (`validate`, `test-route`, `import-airswitch`) returning clean placeholder/basic outputs to be wired in later phases.

## Scope
- In: Cargo.toml, LICENSE, .gitignore, .dockerignore, src/main.rs, src/lib.rs, src/config.rs, src/logging.rs, src/filter.rs, src/mux.rs, src/net.rs, src/server.rs
- Out: docs/MASTER-PLAN.md, src/router/*, src/upstream/*, src/http/*, src/socks/*, src/mitm/*, src/reload.rs, src/import/*, tests/*

## Sub-tasks
1. [done] Create `Cargo.toml`, `LICENSE` (copy BSD-3-Clause from `../rusty-conduit/LICENSE`), `.gitignore`, and `.dockerignore` using the pure-Rust crate stack in `docs/MASTER-PLAN.md` Section 10 (adding `arc-swap`, `regex`, `base64`, `notify`, and `time` with `local-offset` feature alongside `../rusty-conduit/Cargo.toml` deps) — done when: `cargo metadata --no-deps --format-version 1` exits 0 with package name `rusty-conduit-switch`.
2. [done] Port `src/logging.rs`, `src/filter.rs`, `src/mux.rs`, and `src/net.rs` from `../rusty-conduit/src/`, extending `logging.rs` access/SOCKS records with `rule`, `profile`, and redacted `upstream` fields per `docs/MASTER-PLAN.md` Section 9 and keeping `KeepaliveSettings`, `PrefixedStream`, and bidirectional byte-counting relay in `net.rs` — done when: `cargo test --lib logging` and `cargo test --lib filter` and `cargo test --lib mux` and `cargo test --lib net` exit 0.
3. [done] Implement `src/config.rs` with clap CLI flags, `RUSTY_CONDUIT_SWITCH_*` env vars, TOML file loading, precedence (`CLI > Env > TOML > Defaults`), subcommands (`validate`, `test-route`, `import-airswitch`), credential source exclusivity (`password` vs `password_env` vs `password_file`), built-in `direct`/`block` profiles, and startup validation including self-loop detection against active listener bind/ports — done when: `cargo test --lib config` exits 0 covering precedence, subcommand parsing, credential exclusivity, and self-loop rejection.
4. [done] Implement `src/server.rs`, `src/lib.rs`, and `src/main.rs` with separate/mux listener binding, `--max-connections` semaphore cap, non-loopback startup notice, graceful shutdown on Ctrl-C/SIGTERM, and subcommand dispatch — done when: `cargo build` and `cargo run -- --help` exit 0 and `cargo test --lib` exits 0.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- --help
```

## Escalate when
- Any dependency in `docs/MASTER-PLAN.md` Section 10 fails to resolve or pulls in OpenSSL or `aws-lc-sys` → stop, set Status: needs-human — reason: <exact crate conflict or native dep>
- A required CLI flag or TOML field in `docs/MASTER-PLAN.md` Section 3 conflicts with another field → stop, set Status: needs-human — reason: <exact conflict>

## Log
- opencode executor timed out at 1800s after completing sub-tasks 1 and 2 in the working tree; planner switched executor to claude (--model opus --effort medium) to verify sub-tasks 1-2 and finish sub-tasks 3-4 and close phase-0001
- claude executor re-verified sub-tasks 1-2 (checks pass, kept [done])
- sub-task 3: wrote src/config.rs (clap CLI + RUSTY_CONDUIT_SWITCH_* env + TOML incl. [profiles.*]/[routing]/[routing.http|socks]/[filter]/[tcp_keepalive]/[mitm]/[logging], subcommands, credential exclusivity, built-in direct/block, profile reference checks, self-loop detection) and registered it in src/lib.rs
- sub-task 4: ported src/server.rs from ../rusty-conduit (separate/mux listeners, max-connections semaphore, bounded drain; added connection_cap_closes_excess_connections test); wrote src/lib.rs (load_config, run with StubHandlers, non-loopback notice via Config::notices, Ctrl-C/SIGTERM shutdown, cmd_validate/cmd_test_route/cmd_import_airswitch placeholders) and src/main.rs
- phase verify passed; phase closed

## Evidence
- (append-only: command → observed result)
- [st1 re-verify] `cargo metadata --no-deps --format-version 1` → exit 0, packages ['rusty-conduit-switch']; `cargo tree -i openssl-sys` / `-i aws-lc-sys` → "did not match any packages"
- [st2 re-verify] `cargo test --lib logging` → 15 passed; `cargo test --lib filter` → 7 passed; `cargo test --lib mux` → 7 passed; `cargo test --lib net` → 7 passed
- [st3] `cargo test --lib config` → test result: ok. 24 passed; 0 failed (covers precedence toml/env/cli, subcommand_validate/test_route/import_airswitch, credential_sources_are_mutually_exclusive, self_loop_rejected / self_loop_uses_cli_overridden_listener)
- [st4] `cargo build` → exit 0 (only cargo `unused dependency` manifest warnings for crates reserved for later phases); `cargo run -- --help` → exit 0, Commands: validate, test-route, import-airswitch; `cargo test --lib` → test result: ok. 71 passed; 0 failed
- [st4 smoke] `rusty-conduit-switch validate --config loop.toml` (profile http 127.0.0.1:3128) → "config invalid: profile `me` points to this server's own listener 127.0.0.1:3128 (self-loop)", exit 1; `--http-port 3999 validate --config loop.toml` → "config OK ... profiles=3 rules=0", exit 0; `test-route --inbound socks example.com:443` → "rule=<default> profile=direct", exit 0; `import-airswitch x.bak` → "not available in this build yet", exit 1; server `--http-port 18128 --socks-port 18080` + SIGTERM → both listeners logged, "received SIGTERM", "shutting down", exit 0
- [verify] `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo run -- --help` → chain exit 0; cargo test: lib 71 passed, bin 0, doc 0; cargo tree -i openssl-sys / aws-lc-sys → no match
