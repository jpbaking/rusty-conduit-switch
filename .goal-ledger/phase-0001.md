# phase-0001 — Release profile and malloc arena cap

- Status: done
- Owner: executor
- Depends on: none
- Goal: Add an optimized `[profile.release]` and cap glibc malloc arenas at 2 on Linux when `MALLOC_ARENA_MAX` is unset, and say so in the sizing guide.
- Done when: `cargo test --locked` passes, `Cargo.toml` has the exact release profile from sub-task 1, `src/main.rs` matches sub-task 2, and the sizing guide sentence from sub-task 3 is in place.
- Pattern to follow: the `MALLOC_ARENA_MAX` comment in `Dockerfile` (around line 36) (the comment explaining why `MALLOC_ARENA_MAX=2` is set; reuse its reasoning in the code comment)

## Context
Release builds currently use Cargo defaults (`lto = false`, `codegen-units = 16`, no strip), so nothing is inlined across the `rusty-conduit-engine` crate boundary. The planner chose `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`; do not pick other values.
glibc gives every worker thread its own malloc arena; on many-core Linux that costs ~220 KB per open tunnel instead of ~26 KB. Only the Docker image sets `MALLOC_ARENA_MAX=2` today. glibc reads `MALLOC_ARENA_MAX` itself at startup, so when the variable is set the binary must leave it alone.
`libc` is already a `[target.'cfg(unix)'.dependencies]` entry in `Cargo.toml`, and the bin target can use it. `libc::mallopt` and `libc::M_ARENA_MAX` exist only for `target_os = "linux"` + `target_env = "gnu"`; that code is not compiled on macOS, so the planner checks it in a Linux container afterwards.

## Scope
- In: `Cargo.toml`, `src/main.rs`, `docs/PERFORMANCE-AND-SIZING.md`
- Out: `src/lib.rs`, `Dockerfile` (keep its `ENV MALLOC_ARENA_MAX=2`), `Cargo.lock`, `.github/`, every other doc

## Sub-tasks
1. [done] Append this block at the very end of `Cargo.toml`, after a blank line, exactly: (block 1 below) — done when: `grep -c '^\[profile.release\]' Cargo.toml` prints `1` and `cargo build --locked` succeeds.
   Block 1:
   ```toml
   # Thin LTO with one codegen unit inlines across the rusty-conduit-engine crate boundary;
   # stripped symbols keep the release binary and image small.
   [profile.release]
   lto = "thin"
   codegen-units = 1
   strip = "symbols"
   ```
2. [done] Replace the whole of `src/main.rs` with exactly: (block 1 below) — done when: `cargo build --locked` succeeds and `grep -c 'libc::mallopt(libc::M_ARENA_MAX, 2)' src/main.rs` prints `1`.
   Block 1:
   ```rust
   use std::process::ExitCode;

   fn main() -> ExitCode {
       cap_malloc_arenas();
       rusty_conduit_switch::main_entry()
   }

   /// glibc gives every worker thread its own malloc arena, which multiplies memory on hosts with
   /// many CPUs (about 8x per open connection); two arenas keep it low with no measurable
   /// throughput cost. glibc applies an explicit `MALLOC_ARENA_MAX` itself, so that one wins.
   #[cfg(all(target_os = "linux", target_env = "gnu"))]
   fn cap_malloc_arenas() {
       if std::env::var_os("MALLOC_ARENA_MAX").is_none() {
           // SAFETY: runs first in `main`, before any other thread exists; `mallopt` takes
           // integer arguments and touches no Rust-managed memory.
           unsafe {
               libc::mallopt(libc::M_ARENA_MAX, 2);
           }
       }
   }

   #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
   fn cap_malloc_arenas() {}
   ```
3. [done] In `docs/PERFORMANCE-AND-SIZING.md`, replace exactly this text: `The container image sets `MALLOC_ARENA_MAX=2`. For the prebuilt Linux binaries, set it in the environment (for example `Environment=MALLOC_ARENA_MAX=2` in a `systemd` unit) to get the low figures on any CPU count.` with exactly: `On Linux, the binary caps glibc at two arenas itself when `MALLOC_ARENA_MAX` is not set, so the prebuilt binaries and the container image (which also sets `MALLOC_ARENA_MAX=2`) get the low figures on any CPU count. Set `MALLOC_ARENA_MAX` to another value to override it.` Change nothing else in the file — done when: `grep -c 'caps glibc at two arenas itself' docs/PERFORMANCE-AND-SIZING.md` prints `1` and `grep -c 'For the prebuilt Linux binaries, set it' docs/PERFORMANCE-AND-SIZING.md` prints `0`.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
grep -c '^\[profile.release\]' Cargo.toml
grep -c 'caps glibc at two arenas itself' docs/PERFORMANCE-AND-SIZING.md
git diff --exit-code -- Cargo.lock src/lib.rs Dockerfile
```
- manual (planner only, needs Docker): `docker run --rm -v "$PWD":/src -w /src rust:1-bookworm cargo clippy --bins --locked -- -D warnings` exits 0, which compiles the Linux-only branch.

## Escalate when
- `cargo build --locked` fails because `Cargo.lock` would change → stop, set Status: needs-human — reason: paste the error (no new dependency should be needed).
- The sentence in sub-task 3 is not found verbatim → stop, set Status: needs-human — reason: paste the paragraph under "Memory on many-core Linux" as it is now.
- clippy reports a lint on the new code → stop, set Status: needs-human — reason: paste the lint; do not add `#[allow]`.

## Log
- (append-only, one line per event)
- sub-task 1: appended `[profile.release]` (`lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`) to `Cargo.toml`
- sub-task 2: replaced `src/main.rs` with `cap_malloc_arenas()` using `libc::mallopt(libc::M_ARENA_MAX, 2)` on Linux gnu when `MALLOC_ARENA_MAX` is unset
- sub-task 3: updated `docs/PERFORMANCE-AND-SIZING.md` line 64 to document built-in Linux glibc arena cap and `MALLOC_ARENA_MAX` override
- verify: all automated `## Verify` commands passed; manual Docker check left for planner

## Evidence
- (append-only: command → observed result)
- `grep -c '^\[profile.release\]' Cargo.toml && cargo build --locked` → `1` and `Finished dev profile [unoptimized + debuginfo] target(s) in 0.13s` (exit 0)
- `cargo build --locked && grep -c 'libc::mallopt(libc::M_ARENA_MAX, 2)' src/main.rs` → `Finished dev profile [unoptimized + debuginfo] target(s) in 0.48s` and `1` (exit 0)
- `grep -c 'caps glibc at two arenas itself' docs/PERFORMANCE-AND-SIZING.md` / `grep -c 'For the prebuilt Linux binaries, set it' docs/PERFORMANCE-AND-SIZING.md` → `1` / `0`
- `cargo fmt --check` → exit 0 (no formatting issues)
- `cargo clippy --all-targets --locked -- -D warnings` → exit 0 (`Finished dev profile in 0.64s`, 0 warnings)
- `cargo test --locked` → exit 0 (all unit, integration, and doc tests passed; 0 failed)
- `grep -c '^\[profile.release\]' Cargo.toml` → `1` (exit 0)
- `grep -c 'caps glibc at two arenas itself' docs/PERFORMANCE-AND-SIZING.md` → `1` (exit 0)
- `git diff --exit-code -- Cargo.lock src/lib.rs Dockerfile` → exit 0 (no diff)
- planner (claude-opus-5-5): rust:1-bookworm `rustup component add clippy && cargo clippy --bins --locked -- -D warnings` → exit 0 (Linux glibc branch compiles clean)
