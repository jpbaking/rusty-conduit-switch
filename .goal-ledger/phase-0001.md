# phase-0001 — Rename keepalive and MITM-cache flags with deprecated aliases; align help text and defaults

- Status: done
- Owner: executor
- Depends on: none
- Goal: Make every shared CLI flag in `src/config.rs` match the family's names, value names, help text, and defaults, keeping the two renamed flags as hidden deprecated aliases.
- Done when: `cargo test --locked` passes and `cargo run -q -- --help` shows the help lines listed in sub-task 3.
- Pattern to follow: `src/config.rs:360-368` and `src/config.rs:430-437` (the hidden `--socks-block-web-in-mitm` alias and how `from_matches` picks primary vs legacy by `ValueSource`)

## Context
rusty-conduit and rusty-conduit-ssh are the reference. The switch differs in two flag names, its value names, several help strings, and two defaults. The user has decided the new defaults: `max_connections` 4096 (was 1024) and MITM cert cache 10240 (was 4096). Renamed flags must keep working: old CLI flag and old env var stay as hidden aliases, and using them adds a NOTICE line at startup.
Precedence between new and old names: new CLI > old CLI > new env > old env (the same order as the socks-block-web alias).
Do NOT rename internal `Config` fields (`tcp_keepalive_idle`, `mitm_cert_cache_max`); only user-visible names change. TOML changes are phase-0002, not this phase.
clap strips a trailing period from a one-paragraph doc comment, so the help strings below have no final period.

Help text table (flag and value name → rendered help):
- `--config <PATH>`: `Optional TOML configuration file path` (keep `global = true`)
- `--socks-port <PORT>`: `SOCKS4/4a/5 proxy port, 0 to disable [default: 1080]`
- `--max-connections <N>`: `Maximum concurrent client connections; excess connections are closed immediately, 0 = unlimited [default: 4096]`
- `--tcp-keepalive <DURATION>`: `Idle time before TCP keepalive probes start on client and upstream sockets, 0 = disabled [default: 60s]`
- `--tcp-keepalive-interval <DURATION>`: `Time between unanswered TCP keepalive probes [default: 10s]`
- `--tcp-keepalive-retries <N>`: `Unanswered TCP keepalive probes before the connection is closed [default: 5]`
- `--allow <RULE>`: two doc lines `Allowlist of destinations (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated.` / `When combined with --block, serves as exceptions to the blocklist.`
- `--block <RULE>`: two doc lines `Blocklist of destinations (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated.` / `Combine with --allow to carve out exceptions.`
- `--mitm-ca-cert <PATH>`: `Path to PEM-encoded CA certificate (enables MITM together with --mitm-ca-key)`
- `--mitm-ca-key <PATH>`: `Path to PEM-encoded CA private key`
- `--mitm-ca-p12 <PATH>`: `Path to PKCS#12 (.p12/.pfx) CA bundle (enables MITM)`
- `--mitm-ca-passphrase <STR>`: `Passphrase for the PKCS#12 bundle or encrypted PEM key (prefer the env var or a passphrase file)`
- `--mitm-cert-ttl <DURATION>`: `In-memory TTL for generated MITM leaf certs, e.g. 30m, 1h, 3600s [default: 1h]`
- `--mitm-cert-cache-max-entries <N>`: `Maximum cached MITM leaf certificates; expired then oldest entries are evicted, 0 = unlimited [default: 10240]`
- `--socks-block-web`: `Reject HTTP/HTTPS traffic over SOCKS4/4a/5 (works with or without MITM)`
- `--watch-debounce` and `--connect-timeout`: change `value_name` from `DUR` to `DURATION`; keep their help text.

## Scope
- In: `src/config.rs`, `src/reload.rs`
- Out: `src/lib.rs`, `tests/`, `docs/`, `README.md`, `DOX.md`, the TOML structs (`FileKeepaliveConfig`, `FileFilterConfig`, `FileMitmConfig`, `FileConfig`) and their merge code

## Sub-tasks
1. [done] Defaults: in `src/config.rs` set `DEFAULT_MAX_CONNECTIONS` to `4096`; rename `DEFAULT_MITM_CERT_CACHE_MAX` to `DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES` with value `10_240` and update its uses (find them with `grep -n DEFAULT_MITM_CERT_CACHE_MAX src/*.rs`); in the unit test near `src/config.rs:1155` change the expected values to `4096` and `10_240` — done when: `grep -n 'DEFAULT_MITM_CERT_CACHE_MAX\b' src/*.rs` prints nothing and `grep -n '10_240' src/config.rs` prints the constant.
2. [done] Renames in `CliArgs`: rename field `tcp_keepalive_idle` to `tcp_keepalive` (long `--tcp-keepalive`, env `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE`); rename field `mitm_cert_cache_max` to `mitm_cert_cache_max_entries` (long `--mitm-cert-cache-max-entries`, env `RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX_ENTRIES`). Add two hidden legacy fields shaped like `socks_block_web_in_mitm`: `tcp_keepalive_idle: Option<Duration>` (long `tcp-keepalive-idle`, env `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_IDLE`, `hide = true`, `value_parser = humantime::parse_duration`, doc `/// Deprecated alias for --tcp-keepalive`) and `mitm_cert_cache_max: Option<usize>` (long `mitm-cert-cache-max`, env `RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX`, `hide = true`, doc `/// Deprecated alias for --mitm-cert-cache-max-entries`). In `CliInput` add `pub deprecated: Vec<String>`. In `from_matches`, make `args` mutable and, for each pair (primary id, legacy id): if the legacy `value_source` is `Some(_)`, push the notice text below; if the primary source is `None`, or the primary is `EnvVariable` and the legacy is `CommandLine`, copy the legacy value into the primary field. Notice texts, exactly: `NOTICE: --tcp-keepalive-idle / RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_IDLE is deprecated; use --tcp-keepalive / RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE` and `NOTICE: --mitm-cert-cache-max / RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX is deprecated; use --mitm-cert-cache-max-entries / RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX_ENTRIES`. Add `pub deprecations: Vec<String>` to `Config` (default `Vec::new()`), set it from `cli.deprecated` in `Config::merge`, and append its entries at the end of `Config::notices()`. Update the merge code that read `a.tcp_keepalive_idle` / `a.mitm_cert_cache_max` to read the new field names, and change the validation message `--tcp-keepalive-idle must be` to `--tcp-keepalive must be` — done when: `cargo build` succeeds and `cargo run -q -- --tcp-keepalive-idle 0s validate 2>&1 | head -1` fails only because `--config` is missing (not because of an unknown flag).
3. [done] Help text and value names: set every doc comment and `value_name` listed under "Help text table" in `## Context` exactly as written — done when: `cargo run -q -- --help | grep -c 'DUR>'` prints `0` and `cargo run -q -- --help | grep -F 'mutually exclusive'` prints nothing.
4. [done] Startup summary and reload label: in `Config::summary()` (near `src/config.rs:1015`) rename the key `mitm_cert_cache_max=` to `mitm_cert_cache_max_entries=`; in `src/reload.rs:84` change the label `"mitm.cert_cache_max"` to `"mitm.cert_cache_max_entries"` — done when: `grep -n 'mitm_cert_cache_max=' src/config.rs` prints nothing.
5. [done] Unit tests for the aliases: in the `mod tests` of `src/config.rs`, next to the existing env test near line 1246, add tests that (a) `--tcp-keepalive-idle 0s` sets `cfg.tcp_keepalive_idle` to zero and `cfg.notices()` contains the keepalive deprecation NOTICE, (b) `--mitm-cert-cache-max 7` sets `cfg.mitm_cert_cache_max == 7` with its NOTICE, (c) `--tcp-keepalive 30s --tcp-keepalive-idle 5s` keeps 30s, (d) the new `--tcp-keepalive 0s` produces no deprecation NOTICE. Reuse the `load(&[...])` helper used at `src/config.rs:1820` — done when: `cargo test --locked --lib config` passes.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run -q -- --help | grep -F -- '--tcp-keepalive <DURATION>'
cargo run -q -- --help | grep -F '[default: 10240]'
cargo run -q -- --help | grep -F 'closed immediately, 0 = unlimited [default: 4096]'
! cargo run -q -- --help | grep -F -- '--tcp-keepalive-idle'
```

## Escalate when
- An existing test outside `src/config.rs` fails because it uses an old flag or env name in a way the alias does not cover → stop, set Status: needs-human — reason: name the test and the failure.
- `Config` cannot hold `deprecations` without breaking `reload.rs` field-by-field comparisons or the manual `Debug` impl → stop, set Status: needs-human — reason: paste the compiler error.
- clap rejects two args sharing a prefix (`--mitm-cert-cache-max` vs `--mitm-cert-cache-max-entries`) → stop, set Status: needs-human — reason: paste the clap error.

## Log
- (append-only, one line per event)
- sub-task 1: updated `DEFAULT_MAX_CONNECTIONS` to 4096, renamed `DEFAULT_MITM_CERT_CACHE_MAX` to `DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES` = 10_240, and updated `defaults_when_nothing_is_set` assertions in `src/config.rs`.
- sub-task 2: renamed CLI flags/env vars to `--tcp-keepalive` and `--mitm-cert-cache-max-entries`, added hidden deprecated aliases with precedence and deprecation notices in `CliInput`/`Config`, and updated validation message in `src/config.rs`.
- sub-task 3: updated all CLI doc comments and `value_name` attributes in `src/config.rs` to match the Help text table.
- sub-task 4: renamed `mitm_cert_cache_max=` to `mitm_cert_cache_max_entries=` in `Config::summary()` (`src/config.rs`) and `"mitm.cert_cache_max"` to `"mitm.cert_cache_max_entries"` in `non_reloadable_changes()` (`src/reload.rs`).
- sub-task 5: added `deprecated_cli_aliases_and_precedence` unit test in `src/config.rs` covering `--tcp-keepalive-idle`, `--mitm-cert-cache-max`, precedence, and new `--tcp-keepalive`.
- verify: all 7 commands in `## Verify` passed; closing phase-0001.

## Evidence
- (append-only: command → observed result)
- `grep -nE 'DEFAULT_MITM_CERT_CACHE_MAX\b' src/*.rs; grep -n '10_240' src/config.rs` → first printed nothing (exit 1); second printed `64:pub const DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES: usize = 10_240;` and `1157: assert_eq!(cfg.mitm_cert_cache_max, 10_240);`.
- `cargo build && cargo run -q -- --tcp-keepalive-idle 0s validate 2>&1 | head -1` → build succeeded; printed `config invalid: the \`validate\` subcommand requires --config <PATH>`.
- `cargo run -q -- --help | grep -c 'DUR>'` and `cargo run -q -- --help | grep -F 'mutually exclusive'` → printed `0` and nothing (exit 1); full `--help` matches Help text table.
- `grep -n 'mitm_cert_cache_max=' src/config.rs` → printed nothing (exit 1).
- `cargo test --locked --lib config` → 25 passed, 0 failed.
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && cargo run -q -- --help | grep -F -- '--tcp-keepalive <DURATION>' && cargo run -q -- --help | grep -F '[default: 10240]' && cargo run -q -- --help | grep -F 'closed immediately, 0 = unlimited [default: 4096]' && ! cargo run -q -- --help | grep -F -- '--tcp-keepalive-idle'` → exited 0 (all unit + integration tests passed; help assertions matched).
