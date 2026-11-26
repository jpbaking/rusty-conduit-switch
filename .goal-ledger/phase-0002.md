# phase-0002 — Flat TOML keys with deprecated [tcp_keepalive] and [filter] tables

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Accept the family's flat TOML keys (`tcp_keepalive = "60s"`, `tcp_keepalive_interval`, `tcp_keepalive_retries`, `allow`, `block`, `mitm.cert_cache_max_entries`) while still accepting the old tables and key, which add a deprecation NOTICE.
- Done when: `cargo test --locked` passes, including every existing test that still uses `[tcp_keepalive]`, `[filter]`, or `cert_cache_max`, plus the new tests from sub-task 5.
- Pattern to follow: `src/config.rs:706-707` (`file_filter_rules` with a key name for error messages) and `src/config.rs:683-686` (`file_duration` with a key name)

## Context
rusty-conduit and rusty-conduit-ssh put `tcp_keepalive`, `tcp_keepalive_interval`, `tcp_keepalive_retries`, `allow`, and `block` at the top level of the TOML file, and call the cache key `mitm.cert_cache_max_entries`. The switch uses a `[tcp_keepalive]` table (`idle`, `interval`, `retries`), a `[filter]` table (`allow`, `block`), and `mitm.cert_cache_max`. The key `tcp_keepalive` therefore has to accept either a string (new) or a table (old); use an untagged serde enum.
When both a new key and its old equivalent are set, the new key wins. Error messages keep the key the user actually wrote: `tcp_keepalive.idle` / `filter.allow` for the old forms, `tcp_keepalive` / `allow` for the new ones. Existing tests that use the old forms must pass unchanged; they are the compatibility proof.
Hot reload (`src/reload.rs`) works on the merged `Config`, so it needs no change.

## Scope
- In: `src/config.rs`
- Out: `src/reload.rs`, `src/lib.rs`, `tests/`, `docs/`, `README.md`, `DOX.md`, the CLI structs changed in phase-0001

## Sub-tasks
1. [done] Add the untagged enum next to `FileKeepaliveConfig` (near `src/config.rs:459`), exactly: `#[derive(Debug, Clone, PartialEq, Eq, Deserialize)] #[serde(untagged)] pub enum FileKeepaliveField { Idle(String), Table(FileKeepaliveConfig) }` with doc `/// \`tcp_keepalive\`: a duration string (canonical) or the deprecated \`[tcp_keepalive]\` table.` Change the doc of `FileKeepaliveConfig` to `/// Deprecated \`[tcp_keepalive]\` table; use the top-level keys.` and of `FileFilterConfig` to `/// Deprecated \`[filter]\` table; use top-level \`allow\` / \`block\`.` — done when: `cargo build` succeeds.
2. [done] In `FileConfig` replace `#[serde(default)] pub tcp_keepalive: FileKeepaliveConfig` with `pub tcp_keepalive: Option<FileKeepaliveField>`, and add `pub tcp_keepalive_interval: Option<String>`, `pub tcp_keepalive_retries: Option<u32>`, `pub allow: Option<Vec<String>>`, `pub block: Option<Vec<String>>`; keep `#[serde(default)] pub filter: FileFilterConfig`. In `FileMitmConfig` add `pub cert_cache_max_entries: Option<usize>` above the existing `cert_cache_max` — done when: `cargo build` succeeds (merge code may still need sub-task 3).
3. [done] In `Config::merge`: resolve keepalive as `(idle, interval, retries, used_table)`: `Some(Idle(s))` gives idle from `s` with key `"tcp_keepalive"`; `Some(Table(t))` gives `t.idle` with key `"tcp_keepalive.idle"` and sets `used_table`; then interval = `file.tcp_keepalive_interval` (key `"tcp_keepalive_interval"`) or else the table's `interval` (key `"tcp_keepalive.interval"`); retries = `file.tcp_keepalive_retries` or else the table's `retries`. Filters: `allow` = `file.allow` parsed with key `"allow"`, else `file.filter.allow` with key `"filter.allow"`; the same for `block`. Cache: `file.mitm.cert_cache_max_entries.or(file.mitm.cert_cache_max)`. CLI values still win over every file value, as today — done when: `cargo build` succeeds and `cargo test --locked --lib` passes.
4. [done] Deprecation notices: push onto `Config.deprecations` (added in phase-0001), each at most once, exactly: when the table form was used `NOTICE: TOML [tcp_keepalive] table is deprecated; use top-level tcp_keepalive, tcp_keepalive_interval, tcp_keepalive_retries`; when `file.filter.allow` or `file.filter.block` is `Some` `NOTICE: TOML [filter] table is deprecated; use top-level allow and block`; when `file.mitm.cert_cache_max` is `Some` `NOTICE: TOML mitm.cert_cache_max is deprecated; use mitm.cert_cache_max_entries` — done when: the tests in sub-task 5 pass.
5. [done] Unit tests in `src/config.rs` `mod tests` (next to the TOML test near line 1181): (a) flat form `tcp_keepalive = "30s"\ntcp_keepalive_interval = "5s"\ntcp_keepalive_retries = 2\nallow = ["*.ok.example"]\n[mitm]\ncert_cache_max_entries = 11\n` merges to idle 30s, interval 5s, retries 2, an allow filter, cache 11, and no deprecation NOTICE; (b) the old table form yields the same values plus the three NOTICEs; (c) when both `tcp_keepalive = "30s"` and `tcp_keepalive_interval = "7s"` and a `[filter]`-free file are given, values are 30s/7s; (d) `tcp_keepalive = "x"` errors with a message naming `tcp_keepalive` — done when: `cargo test --locked --lib config` passes.
6. [done] Planner fix-up (Gate review finding): replace `#[derive(Debug, Clone, PartialEq, Eq, Deserialize)] #[serde(untagged)]` on `FileKeepaliveField` with `#[derive(Debug, Clone, PartialEq, Eq)]` plus a hand-written impl, so a typo inside the deprecated table reports `unknown field` instead of `data did not match any variant of untagged enum FileKeepaliveField`. Use exactly: `impl<'de> Deserialize<'de> for FileKeepaliveField { fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> { use serde::de::Error as _; match toml::Value::deserialize(deserializer)? { toml::Value::String(s) => Ok(Self::Idle(s)), v @ toml::Value::Table(_) => v.try_into::<FileKeepaliveConfig>().map(Self::Table).map_err(D::Error::custom), other => Err(D::Error::custom(format!("expected a duration string such as \"60s\", found {}", other.type_str()))), } } }` (the planner prototyped this against toml 1.2.3). Then add two assertions to `flat_and_deprecated_toml_keys`: `FileConfig::from_toml_str("[tcp_keepalive]\nidle = \"1m\"\nbogus = 1\n", Path::new("x.toml"))` is an `Err` whose text contains `unknown field`, and the same call with `tcp_keepalive = 5\n` is an `Err` whose text contains `expected a duration string` — done when: `cargo test --locked --lib config` passes and `grep -n 'serde(untagged)' src/config.rs` prints nothing.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
git diff --exit-code -- tests/ src/reload.rs
```

## Escalate when
- An existing test that uses `[tcp_keepalive]` or `[filter]` fails, or its expected error text changes → stop, set Status: needs-human — reason: name the test and paste the failure (the old forms must keep working unchanged).
- serde's untagged enum produces an unusable error for a malformed `[tcp_keepalive]` table and an existing test asserts the old message → stop, set Status: needs-human — reason: paste the old and new message.
- Reaching the merged values needs a change in `src/reload.rs` → stop, set Status: needs-human — reason: explain what reload reads from `FileConfig`.

## Log
- (append-only, one line per event)
- sub-task 1: added `FileKeepaliveField` untagged enum and updated doc comments on `FileKeepaliveConfig` and `FileFilterConfig` in `src/config.rs`.
- sub-task 2: updated `FileConfig` and `FileMitmConfig` with flat keepalive/filter fields and `cert_cache_max_entries`.
- sub-task 3: updated `Config::merge` to resolve flat and legacy TOML keepalive, filter, and MITM cert cache keys with flat-over-legacy and CLI-over-file precedence.
- sub-task 4: added exact deprecation NOTICE pushes for `[tcp_keepalive]`, `[filter]`, and `mitm.cert_cache_max` onto `Config.deprecations`.
- sub-task 5: added `flat_and_deprecated_toml_keys` unit test in `src/config.rs` covering flat keys, legacy tables + 3 NOTICEs, flat keepalive without `[filter]`, and invalid `tcp_keepalive` error key.
- verify: all 4 commands in `## Verify` passed; closing phase-0002.

- planner review reopened phase-0002: the untagged enum hides `unknown field` errors inside the deprecated [tcp_keepalive] table (observed: `data did not match any variant of untagged enum FileKeepaliveField`); added fix-up sub-task 6 with a prototyped custom deserializer
- sub-task 6: replaced `#[serde(untagged)]` on `FileKeepaliveField` with hand-written `Deserialize` impl and added `unknown field` / `expected a duration string` assertions to `flat_and_deprecated_toml_keys`; re-ran Verify and closed phase-0002.

## Evidence
- (append-only: command → observed result)
- `cargo build` → succeeded cleanly.
- `cargo build && cargo test --locked --lib` → build succeeded; 56 passed, 0 failed.
- `cargo test --locked --lib config` → 26 passed, 0 failed.
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && git diff --exit-code -- tests/ src/reload.rs` → exited 0 (57 unit tests + 72 integration tests passed; `tests/` and `src/reload.rs` untouched).
- `cargo test --locked --lib config && ! grep -n 'serde(untagged)' src/config.rs && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && git diff --exit-code -- tests/ src/reload.rs` → exited 0 (26 config tests, 57 unit tests + 72 integration tests passed; no `serde(untagged)` in `src/config.rs`).
