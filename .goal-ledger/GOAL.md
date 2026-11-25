# GOAL — Build rusty-conduit-switch v1

## Goal
- Goal ID: 20261125-rusty-conduit-switch
- Outcome: Implement rusty-conduit-switch v1 per docs/MASTER-PLAN.md as a cross-platform pure-Rust HTTP/HTTPS and SOCKS4/4a/5 Auto Switch proxy server with multi-protocol upstream dialers, failover, opt-in MITM, atomic hot-reload, AirSwitch .bak import, tests, and documentation.
- Done when: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` exits 0 and all modules, subcommands, integration tests, docs, and Dockerfile specified in docs/MASTER-PLAN.md exist and pass.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0007

## Execution
- Execution mode: delegated
- Planner tier: Antigravity (Gemini 4 Neon, Medium)
- Executor tier: herdr-subagent (opencode default; fallback claude --dangerously-skip-permissions --model opus --effort medium)
- Full verification: cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261125-rusty-conduit-switch
- Baseline commit: 1abdf37657514f47b1fb64b56bf75ad9064763e4
- Starting upstream at start: none
- Work upstream at start: none

## Phases
- [done] phase-0001 — Scaffold, config, logging, and core engine
- [done] phase-0002 — Auto Switch routing engine and CLI route testing
- [done] phase-0003 — Upstream dialers and failover chains
- [done] phase-0004 — Inbound HTTP/HTTPS and SOCKS4/4a/5 wired to router
- [done] phase-0005 — Opt-in MITM over routed upstreams and SOCKS web guard
- [done] phase-0006 — Atomic hot-reload engine
- [done] phase-0007 — AirSwitch .bak importer, docs, and Dockerfile

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: Gate D full verification passed: cargo fmt --check, cargo clippy --all-targets -- -D warnings (0 warnings), cargo test (263 passed, 0 failed), cargo build --release, zero OpenSSL/aws-lc-sys
- Blockers: none

## Review
- Reviewed by: Antigravity (Gemini 4 Neon, Medium)
- Verification result: pass — cargo fmt --check exit 0; cargo clippy --all-targets -- -D warnings exit 0 (0 warnings); cargo test exit 0 (263 passed: lib 191, airswitch_import 12, hot_reload 8, mitm_proxy 8, mux_port 3, routing_rules 17, socks_proxy 10, upstream_proxies 14); cargo build --release exit 0; zero openssl-sys/aws-lc-sys
- Diff reviewed: 1abdf37657514f47b1fb64b56bf75ad9064763e4..ddfa55d (56 files, +27824 lines; audited per-phase diffs and full file list against every phase Scope: In)
- Findings: none

## Log
- created ledger with 7 phases
- user approved goal, Git baseline 1abdf37657514f47b1fb64b56bf75ad9064763e4 on main, isolated branch goal/20261125-rusty-conduit-switch
- switched executor from opencode to claude (--dangerously-skip-permissions --model opus --effort medium) after opencode timed out at 1800s during phase-0001
- phase-0001 done by claude executor: config/server/lib/main implemented, phase Verify passed
- phase-0002 done by claude executor: src/router/{mod,condition,validate}.rs, validate/test-route wired, tests/routing_rules.rs; phase Verify passed
- phase-0003 done by claude executor: src/upstream/{mod,direct,block,socks5,socks4a,http}.rs, lib.rs registers upstream, tests/upstream_proxies.rs (14 tests); phase Verify passed
- phase-0004 done by claude executor: src/http/{mod,forward,tunnel}.rs, src/socks/{mod,v4,v5}.rs, server.rs RoutingState/SharedRouting/EngineHandlers, lib.rs wires engines, tests/socks_proxy.rs (10) + tests/mux_port.rs (3); one fmt fix-up; phase Verify passed
- phase-0005 blocked by claude executor: sub-tasks 1-2 done (src/mitm/*, src/http/mitm_tunnel.rs, http/mod.rs, lib.rs); sub-task 3 needs src/socks/mod.rs outside Scope: In
- phase-0005 done by claude executor: src/mitm/*, src/http/mitm_tunnel.rs (routed upstream TLS, per-request URL routing), src/socks/{mod,web_guard}.rs, server.rs EngineHandlers::with_mitm, lib.rs MITM startup + reaper, tests/mitm_proxy.rs (8); phase Verify passed
- phase-0006 done by claude executor: src/reload.rs (RuntimeConfig/SharedRuntime/Reloader, SIGHUP + debounced parent-dir watcher), per-connection snapshots in HTTP/SOCKS, per-request live snapshot for MITM URL routing, Server::with_runtime keepalive, lib::run(cfg, cli, logger) + start_reload_triggers, tests/hot_reload.rs (8); phase Verify passed
- phase-0007 done by claude executor: src/import/{mod,airswitch}.rs, lib.rs import-airswitch wiring, tests/airswitch_import.rs (12), README.md, docs/USER-GUIDE.md, docs/MITM-CA-GUIDE.md, Dockerfile; phase Verify passed (Docker image build not exercised: daemon not running)
- Gate D planner review passed with 0 findings; goal status set to awaiting-acceptance
- user accepted goal and chose squash; soft-reset to baseline 1abdf37657514f47b1fb64b56bf75ad9064763e4 and created single squashed completion commit retaining .goal-ledger/
