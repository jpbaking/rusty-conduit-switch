# phase-0002 — Auto Switch routing engine and CLI route testing

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Implement the full Auto Switch routing engine (`src/router/`) supporting all condition types, unified and split HTTP/SOCKS tables, profile-level bypass, composite/per-scheme profiles, validation, and wired `validate` and `test-route` subcommands.
- Done when: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` exits 0 with `tests/routing_rules.rs` passing for every condition type, unified/split routing, bypass, failover resolution, and CLI `validate`/`test-route`.
- Pattern to follow: ../air-switch/omega-pac/src/conditions.coffee:1, docs/MASTER-PLAN.md:185

## Context
Read `docs/MASTER-PLAN.md` Section 4 (Routing Engine) and Section 3 (`validate` and `test-route` subcommands).
`src/config.rs` from phase-0001 defines the raw TOML config structures. This phase compiles those structures into an immutable `Router` in `src/router/`, evaluates `RouteRequest` in strict top-to-bottom order (AND across fields in a rule, OR across values in a field), enforces zero local DNS lookup for IP/CIDR rules unless `resolve_dns = true`, supports profile-level `bypass` (resolving to `direct` logged as `<name>(bypass->direct)`), and wires the `validate` and `test-route` subcommands in `src/lib.rs`/`src/main.rs`.

## Scope
- In: src/router/mod.rs, src/router/condition.rs, src/router/validate.rs, src/lib.rs, src/config.rs, tests/routing_rules.rs
- Out: docs/MASTER-PLAN.md, src/upstream/*, src/http/*, src/socks/*, src/mitm/*, src/reload.rs, src/import/*

## Sub-tasks
1. [done] Implement `src/router/condition.rs` with compiled matchers for `inbound`, `host`, `host_wildcard` (`*.example.com` apex+subdomains vs `**.example.com` subdomains-only, `*`, `?`), `host_regex`, `cidr`/`ip` (with IPv4-mapped IPv6 canonicalization and opt-in `resolve_dns`), `port` (single/list/range), `host_levels` (`min`/`max`), `bypass` (`<local>`, `*.domain`, CIDR, `host:port`), `weekday`, `time` (including midnight wrap-around), `url_wildcard`, `url_regex`, `keyword`, `match_all`, and `disabled` — done when: `cargo test --lib router::condition` exits 0 with unit tests for every condition type.
2. [done] Implement `src/router/validate.rs` checking profile references, failover target existence, composite/per-scheme profile cycle detection, regex/CIDR/port/time syntax validation, URL-rule-on-opaque-tunnel warnings, and self-loop detection against active listener bind/ports — done when: `cargo test --lib router::validate` exits 0 covering valid configs, missing profiles, cycles, and self-loops.
3. [done] Implement `src/router/mod.rs` with `RouteRequest`, `RouteDecision` (rule name, resolved target list, bypass annotation, `has_url_rules`), unified `[routing]` plus optional `[routing.http]` and `[routing.socks]` split tables (including `inherit = true`), profile-level `bypass` evaluation, and global `[filter]` pre-check — done when: `cargo test --lib router` exits 0.
4. [done] Wire `validate --config <PATH>` and `test-route --config <PATH> [--inbound http|socks] <HOST[:PORT] | URL>` in `src/lib.rs`, and add comprehensive integration tests in `tests/routing_rules.rs` — done when: `cargo test --test routing_rules` exits 0.
5. [done] Fix-up: `cargo fmt --check` failed on the new files src/router/{condition,mod,validate}.rs and tests/routing_rules.rs; run rustfmt on exactly those files — done when: `cargo fmt --check` exits 0.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Escalate when
- AirSwitch `HostWildcardCondition` or `BypassCondition` semantics in `../air-switch/omega-pac/src/conditions.coffee` contradict `docs/MASTER-PLAN.md` Section 4 → stop, set Status: needs-human — reason: <exact discrepancy>
- `time` crate local-offset lookup fails in multi-threaded Tokio tests on macOS → stop, set Status: needs-human — reason: <exact error and proposed injectable clock/offset signature>

## Log
- (append-only, one line per event)
- [resume] planner resumed interrupted phase: prior executor began (begin commit) and marked sub-task 1 `[ongoing]` but wrote no source (`src/router/` empty); reset sub-task 1 to `[todo]`, re-delegating fresh
- sub-task 1: added src/router/condition.rs (RuleMatcher/Condition for all condition types, BypassList, IpNet, AirSwitch shexp translation, injectable Clock/Resolver) and router module stub + `pub mod router` in src/lib.rs
- sub-task 2: added src/router/validate.rs (RouterError, target/failover checks, composite cycle DFS, self-loop vs explicit listeners, rule/bypass syntax compile, URL-rule notices); made config::host_targets_listener pub(crate); Router::from_config_with_listeners needed in mod.rs to back validate_config (first attempt: fixed a closure-lifetime compile error and one wrong test input `9:00-17`, which is a valid hour-only end)
- sub-task 3: src/router/mod.rs Router (unified + [routing.http]/[routing.socks] with inherit, [filter] pre-check, profile bypass -> `<name>(bypass->direct)`, composite per-scheme resolution with AirSwitch fallback->direct), RouteRequest, RouteDecision (rule, targets, has_url_rules), ParsedTarget for test-route
- sub-task 4: added ConfigError::Routing + router validation call at end of Config::validate (src/config.rs); lib.rs cmd_test_route now routes via Router (ParsedTarget, SOCKS/no-MITM URL dropping with notes, denied_by_filter, redacted upstream), cmd_validate/log_startup print router notices via all_notices; tests/routing_rules.rs with 17 integration tests incl. built-binary validate/test-route (first run: 1 test-input bug — 10.9.8.7 legitimately matched an earlier host_levels rule; adjusted the test range)
- Verify run 1 failed on fmt only; fix-up 5 ran rustfmt on the four new files
- Verify run 2 passed; phase done
- [planner Gate D] independently verified: `cargo fmt --check` exit 0, `cargo clippy --all-targets -- -D warnings` exit 0 (only 10 pre-existing manifest `unused dependency` warnings, cargo-level warn, not escalated); `cargo test` 102 lib + 17 routing_rules pass, 0 failed. Per-sub-task: condition 18, validate 6, router 31, routing_rules 17. Close commit `1d7d261` scope-clean (only in-scope src/router/{condition,mod,validate}.rs, src/lib.rs, src/config.rs, tests/routing_rules.rs + the two ledger files). Phase-0002 approved.

## Evidence
- (append-only: command → observed result)
- `cargo test --lib router::condition` → test result: ok. 18 passed; 0 failed (no warnings)
- `cargo test --lib router::validate` → test result: ok. 6 passed; 0 failed
- `cargo test --lib router` → test result: ok. 31 passed; 0 failed
- `cargo test --test routing_rules` → test result: ok. 17 passed; 0 failed
- Verify run 1: `cargo fmt --check` → exit 1 (diffs only in src/router/{condition,mod,validate}.rs, tests/routing_rules.rs); `cargo clippy --all-targets -- -D warnings` → see next line
- Verify run 1: `cargo clippy --all-targets -- -D warnings` → exit 0 (only pre-existing Cargo manifest `unused dependency` warnings, which -D warnings does not promote)
- fix-up 5: `rustfmt --edition 2021 src/router/condition.rs src/router/mod.rs src/router/validate.rs tests/routing_rules.rs; cargo fmt --check` → exit 0
- Verify run 2: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` → exit 0; lib 102 passed, main 0, routing_rules 17 passed, doc 0
