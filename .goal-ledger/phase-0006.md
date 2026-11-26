# phase-0006 — Fix stale filter comments in Config

- Status: done
- Owner: planner
- Depends on: phase-0005
- Goal: Make the `Config` field comments describe the allow/block lists as block-with-exceptions instead of mutually exclusive.
- Done when: `grep -n 'mutually exclusive' src/config.rs` prints nothing and the full verification passes.
- Pattern to follow: `../rusty-conduit-ssh/src/config.rs` `Config` allow/block comments (fixed in that repo's phase-0006)

## Context
Planner review finding (found while reviewing rusty-conduit-ssh, after this goal's Gate D): `src/config.rs:645-647` documents the `Config` allow/block fields as mutually exclusive, but they combine as block-with-exceptions, which phase-0001 now documents in `--help` and phase-0005 in the user guide. Comment-only change; reopens this goal for one remediation phase and a fresh Gate D.

## Scope
- In: `src/config.rs`
- Out: everything else

## Sub-tasks
1. [done] Replace the doc comment on `Config::allow` with `/// Destination allowlist rules (exceptions to \`block\` when both are set).` — done when: `grep -n 'allowlist rules (exceptions' src/config.rs` prints one line.
2. [done] Replace the doc comment on `Config::block` with `/// Destination blocklist rules (combine with \`allow\` to carve out exceptions).` — done when: `grep -n 'mutually exclusive' src/config.rs` prints nothing.

## Verify
```sh
! grep -n 'mutually exclusive' src/config.rs
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

## Escalate when
- A test asserts on these comments → stop, set Status: needs-human — reason: name the test.

## Log
- (append-only, one line per event)
- planner reopened the goal after Gate D for this remediation phase

- sub-tasks 1-2: both Config doc comments now describe block-with-exceptions
- verify: all 4 commands passed; closing phase-0006

## Evidence
- (append-only: command → observed result)
- `! grep -n 'mutually exclusive' src/config.rs` → no output (pass)
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked` → exit 0; 136 passed, 0 failed
