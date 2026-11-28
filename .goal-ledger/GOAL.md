# GOAL — Optimization roadmap Phase 1 for rusty-conduit-switch

## Goal
- Goal ID: 20261128-optimization-phase1
- Outcome: rusty-conduit-switch release builds use thin LTO, one codegen unit, and stripped symbols; Linux glibc binaries cap malloc at two arenas unless `MALLOC_ARENA_MAX` is set; the startup banner reports `config::app_version()`; `--mitm-bypass-host` help matches the family; the contract test covers the four missing shared flags; and releases abort when the tag disagrees with `Cargo.toml`, with the pure-Rust crypto check in CI.
- Done when: `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && python3 scripts/check-pure-rust-crypto.py` exits 0, and every `## Verify` block of phase-0001 and phase-0002 passes.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0002

## Execution
- Execution mode: delegated
- Planner tier: Claude Code (claude-opus-5-5)
- Executor tier: agy --model gemini-4-neon-medium via the herdr-subagent skill (fallback: claude --model opus --effort medium via herdr-subagent while agy is rate-limited)
- Full verification: cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && python3 scripts/check-pure-rust-crypto.py

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261128-optimization-phase1
- Baseline commit: 8084dcba25d8c0f561cc18ff4f25fcabd6134299
- Starting upstream at start: origin/main@8084dcba25d8c0f561cc18ff4f25fcabd6134299
- Work upstream at start: none

## Phases
- [done] phase-0001 — Release profile and malloc arena cap
- [done] phase-0002 — Version banner, CLI contract rows, release tag guard, and pure-Rust crypto gate

## Handoff
- Current position: completed; accepted by the user 2026-11-28
- Next role: planner
- Next action: none
- Last verified evidence: Gate D → fmt/clippy clean, 164 tests passed, PURE_RUST_CRYPTO_OK, Linux Docker clippy exit 0
- Blockers: none

## Review
- Reviewed by: planner, Claude Code (claude-opus-5-5)
- Verification result: pass — cargo fmt --check, cargo clippy --all-targets --locked -D warnings, cargo test --locked (164 passed, 0 failed), python3 scripts/check-pure-rust-crypto.py → PURE_RUST_CRYPTO_OK; phase-0002 Verify block exit 0; rust:1-bookworm clippy --bins → exit 0
- Diff reviewed: 8084dcb..HEAD, read in full; non-ledger paths (Cargo.toml, src/main.rs, src/lib.rs log_startup, src/config.rs bypass doc comment, docs/PERFORMANCE-AND-SIZING.md, scripts/check-pure-rust-crypto.py, .github/workflows/ci.yml, .github/workflows/release.yml, tests/cli_contract.rs, DOX.md) all within phase Scope: In; removed phase-0003..0006 are the prior completed ledger replaced at approval
- Findings: 1 nit fixed — run-on DOX release sentence rewritten (phase-0002 planner sub-task); executor's rustfmt fix-up of the banner call (sub-task 7) accepted

## Log
- created ledger with 2 phases; replaces the completed ledger 20261126-cli-consistency (kept in Git history)
- source plan: rusty-conduit-series/docs/OPTIMIZATION.md, roadmap Phase 1 (items P-01, P-02, B-09, B-10, M-05)
- sibling ledgers with the same Goal ID: rusty-conduit (runs first; canonical contract rows and release steps), rusty-conduit-ssh, rusty-conduit-gui, and the rusty-conduit-series workspace
- user decisions: roadmap Phase 1 only; delegated to agy neon medium via herdr
- planner decisions: B-07 (RoutingCounters pruning and unnamed-rule keys) and P-11 (one Router compile per startup and reload) are deferred to the engine v0.7.0 goal — the engine v0.6.0 `RoutingCounters` has no prune API and `RoutingState` exposes neither its `Router` nor its notices, and this crate never reads the counters; Docker BuildKit cache mounts and builder/runtime distro alignment are deferred as low value
- user approved the goal (Gate A) on 2026-11-28
- Gate B: isolated branch goal/20261128-optimization-phase1 created from main at baseline 8084dcba25d8c0f561cc18ff4f25fcabd6134299; user asked to commit only and not start execution yet
- resumed 2026-11-28 by planner (claude-opus-5-5); evidence: branch and baseline consistent, HEAD = approve commit 56270b5, clean tree, validator OK; origin/goal/20261128-optimization-phase1 holds the approve commit, so automated squash is prohibited
- Gate C: user started execution; executor agy neon medium, fallback claude opus medium while agy is rate-limited
- planner fixed phase-0002 rusty-conduit line refs (77-100 → 78-101) after rusty-conduit fcc6cd4
- delegated phase-0001 to agy (herdr-subagent)
- executor completed phase-0001 (release profile, Linux glibc malloc arena cap, sizing guide update); all automated checks passed
- planner accepted phase-0001 (Verify re-run: 164 passed; diff in scope and verbatim; Linux Docker clippy exit 0); delegated phase-0002 to agy (herdr-subagent)
- executor completed phase-0002 (version banner via `config::app_version()`, `--mitm-bypass-host` help alignment, 4 shared CLI contract rows, release tag guard, pure-Rust crypto check in CI/release, and DOX.md updates); all `## Verify` checks passed
- planner accepted phase-0002 (Verify re-run, diff read, in scope); Gate D finding (DOX wording) fixed; Gate D passed; status awaiting-acceptance
- user accepted 2026-11-28; branch kept unsquashed (published on origin); user asked to squash-merge into main, delete the goal branch, and push
