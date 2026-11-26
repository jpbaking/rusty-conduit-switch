# phase-0004 — CLI family contract test

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002, phase-0003
- Goal: Add `tests/cli_contract.rs`, which fails if any shared flag's name, value name, env var, help text, or default drifts from the family contract.
- Done when: `cargo test --locked --test cli_contract` passes 3 tests.
- Pattern to follow: `tests/routing_rules.rs:890-926` (running the built binary with `env!("CARGO_BIN_EXE_rusty-conduit-switch")` and capturing stdout, stderr, and exit code)

## Context
The same contract table, apart from the env prefix and a few tool-specific wording variants, goes into rusty-conduit and rusty-conduit-ssh, and a workspace script later compares the three. The table below is the specification: if a row fails, fix the doc comment in `src/config.rs`, never the table. `tests/DOX.md` applies: each test file has its own helpers, scratch files go under `std::env::temp_dir()`, no network.
Create `tests/cli_contract.rs` with exactly this content:
```rust
//! Family CLI contract: shared flags keep the same names, value names, env vars, help
//! text, and defaults across rusty-conduit, rusty-conduit-ssh, and rusty-conduit-switch.

use clap::CommandFactory;
use rusty_conduit_switch::config::{
    CliArgs, DEFAULT_MAX_CONNECTIONS, DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES,
};
use std::process::Command;

const ENV_PREFIX: &str = "RUSTY_CONDUIT_SWITCH_";

/// (long flag, value name, rendered help)
const SHARED_FLAGS: &[(&str, Option<&str>, &str)] = &[
    ("config", Some("PATH"), "Optional TOML configuration file path"),
    ("bind", Some("IP"), "IPv4 or IPv6 address to bind listeners to [default: 127.0.0.1]"),
    ("http-port", Some("PORT"), "HTTP/HTTPS proxy port, 0 to disable [default: 3128]"),
    ("socks-port", Some("PORT"), "SOCKS4/4a/5 proxy port, 0 to disable [default: 1080]"),
    ("max-connections", Some("N"), "Maximum concurrent client connections; excess connections are closed immediately, 0 = unlimited [default: 4096]"),
    ("tcp-keepalive", Some("DURATION"), "Idle time before TCP keepalive probes start on client and upstream sockets, 0 = disabled [default: 60s]"),
    ("tcp-keepalive-interval", Some("DURATION"), "Time between unanswered TCP keepalive probes [default: 10s]"),
    ("tcp-keepalive-retries", Some("N"), "Unanswered TCP keepalive probes before the connection is closed [default: 5]"),
    ("allow", Some("RULE"), "Allowlist of destinations (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated. When combined with --block, serves as exceptions to the blocklist"),
    ("block", Some("RULE"), "Blocklist of destinations (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated. Combine with --allow to carve out exceptions"),
    ("mitm-ca-cert", Some("PATH"), "Path to PEM-encoded CA certificate (enables MITM together with --mitm-ca-key)"),
    ("mitm-ca-key", Some("PATH"), "Path to PEM-encoded CA private key"),
    ("mitm-ca-p12", Some("PATH"), "Path to PKCS#12 (.p12/.pfx) CA bundle (enables MITM)"),
    ("mitm-ca-passphrase", Some("STR"), "Passphrase for the PKCS#12 bundle or encrypted PEM key (prefer the env var or a passphrase file)"),
    ("mitm-ca-passphrase-file", Some("PATH"), "File containing the CA passphrase (trailing newline is trimmed)"),
    ("mitm-cert-ttl", Some("DURATION"), "In-memory TTL for generated MITM leaf certs, e.g. 30m, 1h, 3600s [default: 1h]"),
    ("mitm-cert-cache-max-entries", Some("N"), "Maximum cached MITM leaf certificates; expired then oldest entries are evicted, 0 = unlimited [default: 10240]"),
    ("socks-block-web", None, "Reject HTTP/HTTPS traffic over SOCKS4/4a/5 (works with or without MITM)"),
    ("log-level", Some("LEVEL"), "Log level: QUIET, FATAL, ERROR, INFO, DEBUG, VERBOSE (case-insensitive) [default: INFO]"),
    ("log-format", Some("FMT"), "Access/SOCKS log format: text (logfmt) or json (NDJSON) [default: text]"),
    ("http-access-log", Some("PATH"), "Optional file path for HTTP/HTTPS access logs"),
    ("socks-log", Some("PATH"), "Optional file path for SOCKS4/4a/5 connection logs"),
];

#[test]
fn shared_flags_match_family_contract() {
    let cmd = CliArgs::command();
    for (long, value_name, help) in SHARED_FLAGS {
        let arg = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some(*long))
            .unwrap_or_else(|| panic!("missing --{long}"));
        assert!(!arg.is_hide_set(), "--{long} must be visible");
        if let Some(expected) = value_name {
            let names: Vec<String> = arg
                .get_value_names()
                .unwrap_or_default()
                .iter()
                .map(|n| n.to_string())
                .collect();
            assert_eq!(names, vec![expected.to_string()], "--{long} value name");
        }
        let env = arg.get_env().map(|e| e.to_string_lossy().into_owned());
        let expected_env = format!("{ENV_PREFIX}{}", long.to_uppercase().replace('-', "_"));
        assert_eq!(env.as_deref(), Some(expected_env.as_str()), "--{long} env var");
        let rendered = arg.get_help().map(|h| h.to_string());
        assert_eq!(rendered.as_deref(), Some(*help), "--{long} help text");
    }
}

#[test]
fn shared_defaults_match_family_contract() {
    assert_eq!(DEFAULT_MAX_CONNECTIONS, 4096);
    assert_eq!(DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES, 10_240);
}

#[test]
fn binary_help_and_exit_codes() {
    let bin = env!("CARGO_BIN_EXE_rusty-conduit-switch");
    let run = |args: &[&str]| {
        let out = Command::new(bin)
            .args(args)
            .env_remove("RUSTY_CONDUIT_SWITCH_CONFIG")
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (code, out, _) = run(&["--help"]);
    assert_eq!(code, Some(0));
    assert!(out.contains("--tcp-keepalive <DURATION>"), "{out}");
    assert!(!out.contains("--tcp-keepalive-idle"), "deprecated alias must stay hidden: {out}");
    assert!(!out.contains("--mitm-cert-cache-max <"), "deprecated alias must stay hidden: {out}");
    let (code, _, _) = run(&["--no-such-flag"]);
    assert_eq!(code, Some(2), "usage errors exit 2");
    let missing = std::env::temp_dir().join(format!("cli-contract-missing-{}.toml", std::process::id()));
    let (code, _, err) = run(&["--config", missing.to_str().unwrap(), "--http-port", "0", "--socks-port", "0"]);
    assert_eq!(code, Some(1), "config errors exit 1: {err}");
}
```

## Scope
- In: `tests/cli_contract.rs` (new)
- Out: `src/`, every other file under `tests/`, `docs/`, `README.md`, `DOX.md`, `tests/DOX.md`

## Sub-tasks
1. [done] Create `tests/cli_contract.rs` with the exact content in `## Context` and run `cargo fmt` — done when: `cargo test --locked --test cli_contract` compiles.
2. [done] Run `cargo test --locked --test cli_contract`; record each failing assertion in `## Log` — done when: all 3 tests pass. A failure here means an earlier phase missed a doc comment; that is an escalation, not a fix-up (see `## Escalate when`).

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked --test cli_contract
cargo test --locked
```

## Escalate when
- Any row of `SHARED_FLAGS` fails → stop, set Status: needs-human — reason: paste the assertion message (fixing it requires `src/config.rs`, which is outside this phase's scope).
- `DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES` or `DEFAULT_MAX_CONNECTIONS` is not public in `rusty_conduit_switch::config` → stop, set Status: needs-human — reason: paste the compiler error.
- The missing-config run exits with something other than 1 → stop, set Status: needs-human — reason: paste the exit code and stderr.

## Log
- (append-only, one line per event)
- sub-task 1: created `tests/cli_contract.rs` verbatim from `## Context` and ran `cargo fmt`.
- sub-task 2: ran `cargo test --locked --test cli_contract`; all 3 tests passed with 0 failures.
- verify: all 4 commands in `## Verify` passed; closing phase-0004.

## Evidence
- (append-only: command → observed result)
- `cargo fmt && cargo test --locked --test cli_contract` → compiled and passed 3/3 tests (`shared_defaults_match_family_contract`, `shared_flags_match_family_contract`, `binary_help_and_exit_codes`).
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked --test cli_contract && cargo test --locked` → exited 0 (3 contract tests, 61 unit tests + 75 integration tests passed).
