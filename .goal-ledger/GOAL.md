# GOAL — Align rusty-conduit-switch with the rusty-conduit CLI family

## Goal
- Goal ID: 20261126-cli-consistency
- Outcome: rusty-conduit-switch uses the same flag, env, TOML, help-text, and default conventions as rusty-conduit and rusty-conduit-ssh (old names kept as deprecated aliases), raises its open-file limit at startup, and locks the conventions with a CLI contract test.
- Done when: `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked` exits 0; `rusty-conduit-switch --help` shows `--tcp-keepalive <DURATION>`, `--mitm-cert-cache-max-entries <N>` with `[default: 10240]`, and `--max-connections` with `[default: 4096]`; the old flags, env vars, and TOML tables still work and log a deprecation NOTICE; `tests/cli_contract.rs` passes; docs describe the new names.
- Goal status: completed
- Goal status meaning: drafting | approved | executing | blocked-on-human | in-review | awaiting-acceptance | completed | abandoned
- Last completed phase: phase-0006

## Execution
- Execution mode: delegated
- Planner tier: Claude Code (claude-opus-5-5)
- Executor tier: agy --model gemini-4-neon-medium via the herdr-subagent skill
- Full verification: cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked

## Git
- Repository: yes
- Strategy: isolated-branch
- Starting branch: main
- Work branch: goal/20261126-cli-consistency
- Baseline commit: fad20b7abaf2bb9fed82fa78961cff45afed8096
- Starting upstream at start: origin/main@fad20b7abaf2bb9fed82fa78961cff45afed8096
- Work upstream at start: none

## Phases
- [done] phase-0001 — Rename keepalive and MITM-cache flags with deprecated aliases; align help text and defaults
- [done] phase-0002 — Flat TOML keys with deprecated [tcp_keepalive] and [filter] tables
- [done] phase-0003 — Raise the open-file limit at startup
- [done] phase-0004 — CLI family contract test
- [done] phase-0005 — Update user docs and DOX Feature Map
- [done] phase-0006 — Fix stale filter comments in Config

## Handoff
- Current position: completed
- Next role: planner
- Next action: none
- Last verified evidence: Gate D re-run: fmt, clippy -D warnings, cargo test --locked (136 passed); no 'mutually exclusive' left in src, docs, README
- Blockers: none

## Review
- Reviewed by: Claude Code (claude-opus-5-5), planner
- Verification result: pass — cargo fmt --check exit 0; cargo clippy --all-targets --locked -- -D warnings exit 0; cargo test --locked 136 passed, 0 failed
- Diff reviewed: fad20b7abaf2bb9fed82fa78961cff45afed8096..HEAD read in full (per-phase diffs); every changed path is inside a phase Scope: In or the ledger; all commits carry Goal-ID; no merges
- Findings: two, fixed — untagged serde enum hid `unknown field` errors (phase-0002 fix-up sub-task 6); Config comments called allow/block mutually exclusive (remediation phase-0006)

## Log
- created ledger with 5 phases; replaces the completed ledger 20261125-rusty-conduit-switch (kept in Git history)
- sibling ledgers with the same Goal ID: rusty-conduit-ssh and rusty-conduit (run after this one)
- user decisions: one ledger per repo; goal/<id> branch per repo; defaults max_connections 4096 and MITM cache 10240 in all three CLIs; add an open-file limit raise; listen-backlog/somaxconn work is a separate follow-up goal in rusty-conduit-engine
- user approved goal, branches, and execution (Gates A-C); baseline fad20b7abaf2bb9fed82fa78961cff45afed8096 on main; isolated branch goal/20261126-cli-consistency
- execution started; phase-0001 delegated to agy (gemini-4-neon-medium) in herdr pane sub-switch-p1
- phase-0001 completed: renamed keepalive and MITM-cache flags with hidden deprecated aliases, aligned help text and defaults (4096 / 10240), updated summary/reload labels, added unit tests, and passed full verification.
- planner accepted phase-0001 after re-running Verify and reading the diff; phase-0002 delegated to the same agy session
- phase-0002 completed: added flat TOML keys (`tcp_keepalive`, `tcp_keepalive_interval`, `tcp_keepalive_retries`, `allow`, `block`, `mitm.cert_cache_max_entries`) with deprecated `[tcp_keepalive]`, `[filter]`, and `mitm.cert_cache_max` compatibility + NOTICEs, added unit tests, and passed full verification.
- planner reviewed phase-0002 (Verify re-run: 129 tests pass); reopened it for fix-up sub-task 6 (clear errors for typos in the deprecated [tcp_keepalive] table)
- phase-0002 sub-task 6 completed: replaced untagged derive on `FileKeepaliveField` with hand-written `Deserialize` impl, added error-message assertions, re-ran Verify, and closed phase-0002.
- planner accepted phase-0002 after fix-up; phase-0003 delegated to the same agy session
- phase-0003 completed: added `rlimit` Unix dependency, created `src/fdlimit.rs`, wired `fdlimit::apply` into `run()`, verified manual `ulimit -n 256` raise to 184320, and passed full verification.
- planner accepted phase-0003 (src/fdlimit.rs differs from the spec only by rustfmt wrapping; it is now the canonical copy for the sibling repos); phase-0004 delegated
- phase-0004 completed: added `tests/cli_contract.rs` locking shared flags, value names, env vars, help text, defaults, and binary exit codes; all 3 contract tests and full suite (136 tests) pass.
- planner accepted phase-0004; phase-0005 delegated
- phase-0005 completed: updated `docs/USER-GUIDE.md`, `docs/MITM-CA-GUIDE.md`, `docs/MASTER-PLAN.md`, and `DOX.md` Feature Map (`README.md` needed no changes); all Verify greps and `cargo test --locked` pass.
- planner accepted phase-0005; Gate D passed; goal awaiting user acceptance
- planner reopened the goal from awaiting-acceptance: remediation phase-0006 for stale "mutually exclusive" Config comments (found while reviewing rusty-conduit-ssh)
- planner completed phase-0006
- Gate D re-run passed after phase-0006; goal awaiting user acceptance
- user accepted the result ("proceed how you see best"); squash checks passed; squashed onto main as one commit with `git merge --squash`; goal/20261126-cli-consistency kept with the full phase history; nothing pushed
