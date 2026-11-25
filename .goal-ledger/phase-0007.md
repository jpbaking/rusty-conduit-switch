# phase-0007 — AirSwitch .bak importer, docs, and Dockerfile

- Status: done
- Owner: executor
- Depends on: phase-0006
- Goal: Implement the `import-airswitch` `.bak` JSON importer (`src/import/`), integration tests round-tripping generated TOML through `validate` and `test-route`, and complete user documentation and `Dockerfile`.
- Done when: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` and `cargo build --release` exit 0, `tests/airswitch_import.rs` passes, and `README.md`, `docs/USER-GUIDE.md`, `docs/MITM-CA-GUIDE.md`, and `Dockerfile` are complete.
- Pattern to follow: ../air-switch/omega-pac/src/profiles.coffee:1, ../air-switch/omega-pac/src/conditions.coffee:1, ../rusty-conduit/README.md:1, ../rusty-conduit/Dockerfile:1, docs/MASTER-PLAN.md:298

## Context
Read `docs/MASTER-PLAN.md` Section 7 (AirSwitch `.bak` Importer), Section 8 (Module Layout), and Section 11 (Phases 7–8).
`import-airswitch <BAK_PATH> [-o <OUT.toml>] [--profile <SWITCH_PROFILE_NAME>] [--force]` parses AirSwitch / ZeroOmega / SwitchyOmega `.bak` JSON, maps `DirectProfile`, `FixedProfile` (including `bypassList`, auth, and per-scheme proxies), `SwitchProfile` (with nested `SwitchProfile` flattening and cycle detection), `VirtualProfile`, inline `SwitchyRuleListProfile`/`AutoProxyRuleListProfile`, and emits clear warnings for `SystemProfile`, `PacProfile`/`AutoDetectProfile`, remote `sourceUrl`, PCRE lookarounds, and URL rules on opaque tunnels.
Output goes to stdout by default or `-o <path>` (refusing to overwrite unless `--force` is passed), with deterministic profile slugification, collision disambiguation, and clean comments.
Documentation must cover all CLI flags, env vars, TOML schema, routing rules, failover, hot-reload, AirSwitch import, and MITM CA setup.

## Scope
- In: src/import/mod.rs, src/import/airswitch.rs, src/lib.rs, src/config.rs, tests/airswitch_import.rs, README.md, docs/USER-GUIDE.md, docs/MITM-CA-GUIDE.md, Dockerfile
- Out: docs/MASTER-PLAN.md, src/router/*, src/upstream/*, src/http/*, src/socks/*, src/mitm/*, src/reload.rs

## Sub-tasks
1. [done] Implement `src/import/airswitch.rs` and `src/import/mod.rs` parsing AirSwitch/ZeroOmega/SwitchyOmega `.bak` JSON, mapping all profile types and condition types per `docs/MASTER-PLAN.md` Section 7, slugifying profile names with collision disambiguation, flattening nested `SwitchProfile`s with cycle detection, reporting warnings to stderr, and serializing commented TOML (stdout or `-o` with `--force` guard) — done when: `cargo test --lib import` exits 0.
2. [done] Wire `import-airswitch` in `src/lib.rs`/`src/config.rs` and write `tests/airswitch_import.rs` testing realistic `.bak` fixtures (IP/CIDR, `FixedProfile` with `bypassList` & auth, `SwitchProfile`, nested `SwitchProfile`, `VirtualProfile`, `PacProfile`/`SystemProfile` warnings, `-o` overwrite protection) and verifying generated TOML parses cleanly through `validate` and `test-route` — done when: `cargo test --test airswitch_import` exits 0.
3. [done] Write `README.md`, `docs/USER-GUIDE.md`, `docs/MITM-CA-GUIDE.md`, and `Dockerfile` (multi-stage pure-Rust build matching `../rusty-conduit/Dockerfile`) — done when: all four files exist, are non-empty, and reference only accurate CLI flags/subcommands from `src/config.rs`.
4. [done] Run full verification suite (`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo build --release`) and confirm zero warnings or failures — done when: all four commands exit 0.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## Escalate when
- A real AirSwitch `.bak` JSON structure in `../air-switch` uses field names that differ from `docs/MASTER-PLAN.md` Section 7 → stop, set Status: needs-human — reason: <exact field name mismatch>
- `cargo build --release` fails or unexpectedly links OpenSSL / native C libraries → stop, set Status: needs-human — reason: <exact build error or dependency tree>

## Log
- (append-only, one line per event)
- sub-task 1: added src/import/airswitch.rs (JSON/base64 .bak parser, Fixed/composite/Switch/Virtual/RuleList/System/Pac mapping, condition mapper, nested flattening with cycle detection, Switchy/AutoProxy inline rule lists, slug allocator) and src/import/mod.rs (commented TOML renderer, run_import with -o/--force guard); registered `pub mod import` in src/lib.rs. Checked ../air-switch/omega-pac field names (profileType, fallbackProxy, proxyForHttp/Https, auth.<prop>/auth.all, bypassList, defaultProfileName, rules[].condition/profileName, ip/prefixLength, minValue/maxValue, days/startDay/endDay, startHour/endHour, ruleList, sourceUrl): consistent with MASTER-PLAN Section 7, no escalation
- sub-task 2: src/lib.rs cmd_import_airswitch(bak, output, profile, force, out, err) delegates to import::run_import; main_entry passes -o/--profile/--force; placeholder unit test replaced; src/config.rs needed no change (Command::ImportAirswitch already had all flags). Added tests/airswitch_import.rs (12 tests: full fixture with IP/CIDR, FixedProfile bypassList+auth, per-scheme composite, nested SwitchProfile, VirtualProfile, PacProfile/SystemProfile warnings, FalseCondition, --profile selection, cycle, ZeroOmega AutoProxy rule list + base64, binary stdout/validate/test-route, -o overwrite protection); one test-assertion fix (comment order)
- sub-task 3: wrote README.md, docs/USER-GUIDE.md (CLI/env/TOML reference, profiles, routing conditions, bypass syntax, split tables, failover, hot-reload, AirSwitch import, MITM, logging, Docker), docs/MITM-CA-GUIDE.md (adapted from ../rusty-conduit with RUSTY_CONDUIT_SWITCH_* names plus MITM-over-routed-upstreams section), Dockerfile (same multi-stage builder/base/prebuilt/runtime layout as ../rusty-conduit/Dockerfile). Corrected two doc claims after checking code: access records go to files and to stdout only at DEBUG/VERBOSE; test-route prints table=[routing]. Docker daemon not running, so the image itself was not built
- sub-task 4 / Verify: ran full suite; all four commands exit 0 with zero warnings or failures; Cargo.toml unchanged (no new dependencies)
- phase-0007 done

## Evidence
- (append-only: command → observed result)
- `cargo test --lib import` → test result: ok. 22 passed; 0 failed
- `cargo test --test airswitch_import` → test result: ok. 12 passed; 0 failed (first run: 1 failure in my own assertion about comment order, fixed in the test)
- flag/env audit script (regex over the four files vs `--help` of the binary and its 3 subcommands) → all four non-empty (README 4504 B, USER-GUIDE 27628 B, MITM-CA-GUIDE 14588 B, Dockerfile 1744 B); 0 unknown RUSTY_CONDUIT_SWITCH_* vars, 0 legacy RUSTY_CONDUIT_* vars; flags not in --help are only other tools' flags (cargo --path/--locked/--release, docker --rm/--signal/--chmod/--from, curl --socks5-hostname/--cacert, update-ca-certificates --fresh, git --global, trust --store/--remove, useradd/apt options); subcommands referenced: validate, test-route, import-airswitch
- `validate --config` on README example, USER-GUIDE section 4 example, and a snippet of USER-GUIDE composite/split/condition examples → `config OK` for all three; `test-route` outputs match the documented format (after correcting table=[routing])
- `docker info` → daemon not running; image build not exercised
- `cargo fmt --check` → exit 0
- `cargo clippy --all-targets -- -D warnings` → Finished, exit 0, no warnings
- `cargo test` → exit 0; lib 191 passed, airswitch_import 12, hot_reload 8, mitm_proxy 8, mux_port 3, routing_rules 17, socks_proxy 10, upstream_proxies 14; 0 failed
- `cargo build --release` → Finished `release` profile, exit 0
- `cargo tree -e normal` grep openssl|aws-lc|native-tls|-sys → only core-foundation-sys, fsevent-sys, security-framework-sys (macOS platform verifier / notify); no OpenSSL. `otool -L target/release/rusty-conduit-switch` → only CoreFoundation, CoreServices, Security frameworks, libiconv, libSystem
