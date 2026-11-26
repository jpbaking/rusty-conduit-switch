# src/import

## Purpose
The `import-airswitch` subcommand: converts an AirSwitch / ZeroOmega / SwitchyOmega browser-extension `.bak` backup into a commented, ready-to-validate `rusty-conduit-switch` TOML config.

## Ownership
Owns `src/import/`. The TOML schema it targets (`ProfileConfig`, `RuleConfig`, `OneOrMany`, `PortSpec`, `HostLevels`) is owned by `../config.rs`; rule matching semantics come from the engine `router` (re-exported via `../lib.rs`). CLI wiring (`Command::ImportAirswitch`, `cmd_import_airswitch`) lives in `../config.rs` and `../lib.rs`.

## Local Contracts
- Offline only: inline `ruleList` text is parsed; remote `sourceUrl`s are never fetched (reported as a warning).
- Accept both plain JSON and legacy base64-encoded JSON backups.
- Lossy input never fails silently: anything that cannot be represented faithfully becomes a commented-out rule with its reason and an entry in `Imported::warnings`. Only `ImportError` stops an import.
- Output goes to stdout by default; `-o <path>` refuses to overwrite an existing file unless `--force`. Warnings and errors go to stderr.
- Generated TOML must parse and pass `validate` / `test-route`; URL-level rules carry the `URL_RULE_NOTE` comment.
- Nested SwitchProfile / VirtualProfile / rule-list references are flattened in evaluation order with cycle detection; `PacProfile` / `AutoDetectProfile` are skipped with a warning.

## Verification
- Unit tests in `mod.rs` and `airswitch.rs` (`#[cfg(test)]`) and `../../tests/airswitch_import.rs`: `cargo test --locked`.

## Feature Map
- **`.bak` parsing & mapping** — decodes the backup and maps profiles and the selected SwitchProfile onto profiles and one `[routing]` table. Start: `airswitch.rs` (`convert`). Files: `airswitch.rs` (`parse_options`, `slugify`).
- **Commented TOML rendering** — writes the import with header, per-item comments, and TOML quoting. Start: `mod.rs` (`render_toml`). Files: `mod.rs` (`toml_string`, `toml_key`).
- **Subcommand runner** — reads the file, writes stdout or `-o` with overwrite protection, prints warnings, returns the exit code. Start: `mod.rs` (`run_import`).

## Child DOX Index
- (none)
