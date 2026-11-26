# phase-0003 — Raise the open-file limit at startup

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: At server startup, raise the soft open-file limit when it cannot hold `--max-connections`, and log a NOTICE when it still cannot.
- Done when: `cargo test --locked` passes, including the `fdlimit` unit tests, and the manual check in sub-task 4 shows the limit raised without the NOTICE.
- Pattern to follow: `src/lib.rs:58-67` (`log_startup` and how notices go to `logger.info`)

## Context
Each proxied connection uses two file descriptors (client and upstream socket), so `--max-connections N` needs `2N + 64` descriptors; at the new default 4096 that is 8256. Many Linux shells default to a soft limit of 1024, so today the cap is unreachable. The `rlimit` crate's `increase_nofile_limit` raises the soft limit toward the hard limit and handles the macOS per-process maximum. On macOS it can LOWER a soft limit that is already above that maximum, so only call it when the current soft limit is below what is needed. This module is identical in rusty-conduit, rusty-conduit-ssh, and rusty-conduit-switch: copy it verbatim.
Create `src/fdlimit.rs` with exactly this content:
```rust
//! Open-file limit: raise the soft `RLIMIT_NOFILE` at startup and warn when it still
//! cannot hold the configured connection cap.

use crate::logging::Logger;

/// Descriptors kept free for listeners, log files, and the runtime.
const HEADROOM: u64 = 64;

/// Descriptors needed for `connections` concurrent proxied connections (client + upstream each).
pub fn required_fds(connections: usize) -> u64 {
    2 * connections as u64 + HEADROOM
}

/// Concurrent proxied connections that fit in `limit` descriptors.
pub fn connections_for(limit: u64) -> u64 {
    limit.saturating_sub(HEADROOM) / 2
}

/// The NOTICE to log when `limit` cannot hold `connections` (`0` = unlimited, never warns).
pub fn fd_limit_notice(limit: u64, connections: usize, flag: &str) -> Option<String> {
    if connections == 0 {
        return None;
    }
    let needed = required_fds(connections);
    if limit >= needed {
        return None;
    }
    Some(format!(
        "NOTICE: open-file limit is {limit} but {flag} {connections} needs at least {needed}; \
         only about {} concurrent connections will fit. Raise `ulimit -n` (LimitNOFILE= under \
         systemd) or lower {flag}",
        connections_for(limit)
    ))
}

/// Raise the soft open-file limit toward the hard limit when it is below `needed`.
/// Returns the soft limit before and after. Never lowers the limit.
#[cfg(unix)]
pub fn raise_nofile_limit(needed: u64) -> std::io::Result<(u64, u64)> {
    let (soft, _hard) = rlimit::getrlimit(rlimit::Resource::NOFILE)?;
    if soft >= needed {
        return Ok((soft, soft));
    }
    let after = rlimit::increase_nofile_limit(u64::MAX)?;
    Ok((soft, after))
}

/// Windows has no per-process socket descriptor limit to raise.
#[cfg(not(unix))]
pub fn raise_nofile_limit(_needed: u64) -> std::io::Result<(u64, u64)> {
    Ok((u64::MAX, u64::MAX))
}

/// Raise the limit for `connections` and log the outcome (`flag` names the setting).
pub fn apply(logger: &Logger, connections: usize, flag: &str) {
    if connections == 0 {
        return;
    }
    match raise_nofile_limit(required_fds(connections)) {
        Ok((before, after)) => {
            if after > before {
                logger.debug(format!("raised open-file limit from {before} to {after}"));
            }
            if let Some(notice) = fd_limit_notice(after, connections, flag) {
                logger.info(notice);
            }
        }
        Err(e) => logger.debug(format!("could not read or raise the open-file limit: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_fds_matches_sizing_rule() {
        assert_eq!(required_fds(4096), 8256);
        assert_eq!(required_fds(480), 1024);
    }

    #[test]
    fn connections_for_inverts_required_fds() {
        assert_eq!(connections_for(1024), 480);
        assert_eq!(connections_for(10), 0);
    }

    #[test]
    fn notice_only_when_limit_is_too_low() {
        assert_eq!(fd_limit_notice(8256, 4096, "--max-connections"), None);
        assert_eq!(fd_limit_notice(1024, 0, "--max-connections"), None);
        let n = fd_limit_notice(1024, 4096, "--max-connections").unwrap();
        assert!(n.starts_with("NOTICE: open-file limit is 1024"), "{n}");
        assert!(n.contains("--max-connections 4096 needs at least 8256"), "{n}");
        assert!(n.contains("about 480 concurrent connections"), "{n}");
    }

    #[cfg(unix)]
    #[test]
    fn raise_is_a_no_op_when_already_enough() {
        let (before, after) = raise_nofile_limit(0).unwrap();
        assert_eq!(before, after);
    }
}
```

## Scope
- In: `Cargo.toml`, `Cargo.lock`, `src/fdlimit.rs` (new), `src/lib.rs`
- Out: `src/config.rs`, `src/reload.rs`, `tests/`, `docs/`, `README.md`, `DOX.md`

## Sub-tasks
1. [done] Add the dependency: append to `Cargo.toml`, after the `[dependencies]` section and before `[dev-dependencies]`, the lines `[target.'cfg(unix)'.dependencies]` and `rlimit = "0.12"`; run `cargo build` (without `--locked`) once to update `Cargo.lock` — done when: `cargo build --locked` succeeds and `git diff --stat Cargo.lock` shows only `rlimit` added (plus `libc` only if it was not already present).
2. [done] Create `src/fdlimit.rs` with the exact content in `## Context`, and add `pub mod fdlimit;` to `src/lib.rs` next to the other `pub mod` lines (near `src/lib.rs:17`) — done when: `cargo test --locked --lib fdlimit` passes 4 tests on Unix.
3. [done] Call it: in `run` in `src/lib.rs`, on the line right after `log_startup(&cfg, &logger);` (near `src/lib.rs:82`), add `fdlimit::apply(&logger, cfg.max_connections, "--max-connections");` — done when: `cargo build --locked` succeeds.
4. [done] Manual check on this machine: run `cargo build --locked`, then `(ulimit -n 256; timeout 3 target/debug/rusty-conduit-switch --http-port 39129 --socks-port 0 --log-level DEBUG) 2>&1 | grep -i 'open-file'` and record the output in `## Evidence` — done when: the output contains `raised open-file limit from 256 to` and no `NOTICE: open-file limit`. If `timeout` is missing, use `gtimeout`, or start it in the background and `kill -INT` it after 2 s.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
grep -n 'fdlimit::apply(&logger, cfg.max_connections, "--max-connections");' src/lib.rs
```

## Escalate when
- `rlimit = "0.12"` does not resolve or does not provide `getrlimit`, `Resource::NOFILE`, or `increase_nofile_limit` → stop, set Status: needs-human — reason: paste the cargo or compiler error.
- `Cargo.lock` changes more than adding `rlimit` (and possibly `libc`) → stop, set Status: needs-human — reason: paste `git diff --stat Cargo.lock`.
- The manual check prints the NOTICE, or never prints `raised open-file limit` → stop, set Status: needs-human — reason: paste the output and `ulimit -Hn`.

## Log
- (append-only, one line per event)
- sub-task 1: added `[target.'cfg(unix)'.dependencies] rlimit = "0.12"` to `Cargo.toml` and updated `Cargo.lock`.
- sub-task 2: created `src/fdlimit.rs` verbatim and declared `pub mod fdlimit;` in `src/lib.rs`.
- sub-task 3: called `fdlimit::apply(&logger, cfg.max_connections, "--max-connections");` in `run()` in `src/lib.rs`.
- sub-task 4: ran manual `ulimit -n 256` startup check; observed soft limit raised from 256 to 184320 with no NOTICE.
- verify: formatted `src/fdlimit.rs` with `cargo fmt`; all 4 commands in `## Verify` passed; closing phase-0003.

## Evidence
- (append-only: command → observed result)
- `cargo build && cargo build --locked && git diff --stat Cargo.lock` → succeeded; `Cargo.lock | 10 ++++++++++` (only `rlimit v0.12.0` added).
- `cargo test --locked --lib fdlimit` → 4 passed, 0 failed.
- `cargo build --locked` → succeeded cleanly.
- `(ulimit -n 256; timeout 3 target/debug/rusty-conduit-switch --http-port 39129 --socks-port 0 --log-level DEBUG) 2>&1 | grep -i 'open-file'` → `2026-11-26T13:18:14.084Z DEBUG   raised open-file limit from 256 to 184320` (no NOTICE).
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && grep -n 'fdlimit::apply(&logger, cfg.max_connections, "--max-connections");' src/lib.rs` → exited 0 (61 unit tests + 72 integration tests passed; `84:    fdlimit::apply(&logger, cfg.max_connections, "--max-connections");`).
