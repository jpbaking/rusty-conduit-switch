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
