# phase-0002 — Version banner, CLI contract rows, release tag guard, and pure-Rust crypto gate

- Status: done
- Owner: executor
- Depends on: phase-0001
- Goal: Log the tag-driven version at startup, align `--mitm-bypass-host` help with the family, lock four shared flags in the contract test, guard releases against a tag that disagrees with `Cargo.toml`, and run the pure-Rust crypto check in CI.
- Done when: every command in `## Verify` exits 0.
- Pattern to follow: `../rusty-conduit/src/lib.rs:48` (startup banner using `config::app_version()`), `../rusty-conduit/.github/workflows/release.yml:78-101` (the "Derive release version" and "Build release binary" steps), `../rusty-conduit-engine/.github/workflows/ci.yml:26` (crypto check step)

## Context
The banner uses `env!("CARGO_PKG_VERSION")`, so it drops the `-dev` and pre-release suffixes that `--version` (via `config::app_version()`) reports. rusty-conduit already does this correctly.
`--mitm-bypass-host` help reads differently here than in rusty-conduit and rusty-conduit-ssh; rusty-conduit's wording is canonical. The planner checked that the old wording ("Never intercept TLS ...") appears only in `src/config.rs`.
Only rusty-conduit's `release.yml` aborts when the `vX.Y.Z` tag does not match the `Cargo.toml` version. Its two steps (derive the version and check it, then one bash build step that works on every runner, Git Bash included on Windows) replace this repo's separate Unix and Windows build steps. Nothing else in `release.yml` changes.
The crypto check script is generic; copy it unchanged from the engine. If a new contract row's help assertion fails, stop and escalate: the strings below are the family's canonical text and were copied from rusty-conduit.

## Scope
- In: `src/lib.rs` (`log_startup` only), `src/config.rs` (the `--mitm-bypass-host` doc comment only), `tests/cli_contract.rs`, `.github/workflows/release.yml`, `.github/workflows/ci.yml`, `scripts/check-pure-rust-crypto.py` (new), `DOX.md` (Verification and release text only)
- Out: `src/reload.rs`, `src/import/`, every other part of `src/config.rs`, `Cargo.toml`, `Cargo.lock`, `Dockerfile`, `docs/`

## Sub-tasks
1. [done] In `src/lib.rs` `log_startup` (lines 61-65), replace the multi-line `logger.info(format!("rusty-conduit-switch v{} starting", env!("CARGO_PKG_VERSION")));` call with exactly `logger.info(format!("rusty-conduit-switch v{} starting", config::app_version()));` — done when: `grep -c 'CARGO_PKG_VERSION' src/lib.rs` prints `0` and `cargo build --locked` succeeds.
2. [done] In `src/config.rs`, replace the two doc-comment lines above `long = "mitm-bypass-host"` (lines 401-402, starting `/// Never intercept TLS for matching destinations`) with exactly these two lines, same indentation: (block 1 below) — done when: `grep -c 'Never intercept TLS' src/config.rs` prints `0` and `cargo build --locked` succeeds.
   Block 1:
   ```rust
       /// Exclude matching destinations (IP, CIDR, FQDN, or *.domain) from MITM interception: they
       /// get an opaque CONNECT tunnel instead; repeatable or comma-separated
   ```
3. [done] In `tests/cli_contract.rs` `SHARED_FLAGS`, insert these three rows directly after the `("mitm-cert-cache-max-entries", ...)` row, exactly: (block 1 below) and this row directly after the `("socks-block-web", ...)` row, exactly: (block 2 below) — done when: `cargo test --locked --test cli_contract` passes.
   Block 1:
   ```rust
       ("mitm-insecure-host", Some("RULE"), "Accept invalid/self-signed upstream TLS certificates under MITM for matching destinations (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated"),
       ("mitm-bypass-host", Some("RULE"), "Exclude matching destinations (IP, CIDR, FQDN, or *.domain) from MITM interception: they get an opaque CONNECT tunnel instead; repeatable or comma-separated"),
       ("mitm-insecure", None, "UNSAFE blind trust: skip upstream TLS certificate verification for ALL MITM targets"),
   ```
   Block 2:
   ```rust
       ("error-page", Some("PATH"), "HTML template file for proxy-generated HTTP error pages (placeholders: {{status}}, {{reason}}, {{message}}, {{target}}) [default: built-in page]"),
   ```
4. [done] In `.github/workflows/release.yml`, delete every line from the comment line containing ``--version` reports the tag`` (line 77) up to, but not including, the line `      - name: Package archive (Unix)`. In their place paste lines 78-101 of `../rusty-conduit/.github/workflows/release.yml` (its comment, the `Derive release version` step, the `Build release binary` step, and the blank line after it) unchanged — done when: `diff <(awk '/reports the tag/,/Package archive \(Unix\)/' ../rusty-conduit/.github/workflows/release.yml) <(awk '/reports the tag/,/Package archive \(Unix\)/' .github/workflows/release.yml)` prints nothing and exits 0, and `grep -c 'does not match Cargo.toml version' .github/workflows/release.yml` prints `1`.
5. [done] Run `mkdir -p scripts && cp ../rusty-conduit-engine/scripts/check-pure-rust-crypto.py scripts/ && chmod 755 scripts/check-pure-rust-crypto.py`. Then insert `      - run: python3 scripts/check-pure-rust-crypto.py` directly after `      - run: cargo clippy --all-targets --locked -- -D warnings` in `.github/workflows/ci.yml` (`lint` job), and directly after `      - run: cargo test --locked` in `.github/workflows/release.yml` (`verify` job) — done when: `python3 scripts/check-pure-rust-crypto.py` prints `PURE_RUST_CRYPTO_OK` and `grep -c 'check-pure-rust-crypto.py'` prints `1` for each workflow file.
6. [done] In `DOX.md`, wherever the Verification commands are listed (`cargo fmt --check`, `cargo clippy ...`, `cargo test --locked`), add `python3 scripts/check-pure-rust-crypto.py` after `cargo test --locked`; and where `DOX.md` describes `release.yml`, add that the tag's `X.Y.Z` base must equal the `Cargo.toml` version or the build fails (wording as in `../rusty-conduit/DOX.md`, which says "the tag's `X.Y.Z` base must equal the `Cargo.toml` version (the build fails otherwise)") — done when: `grep -c 'check-pure-rust-crypto.py' DOX.md` and `grep -c 'base must equal the' DOX.md` each print at least `1`.
7. [done] Fix-up: format `src/lib.rs` `log_startup` to satisfy `cargo fmt --check` — done when: `cargo fmt --check` exits 0.
8. [done] (planner, Gate D finding) In `DOX.md` Verification bullet, rewrite the run-on release sentence into a colon-led list (tag base must equal `Cargo.toml` version; `CONDUIT_RELEASE_VERSION` = tag minus `v`; `-` suffix → pre-release) — done when: `grep -c 'base must equal the' DOX.md` prints `1` and `grep -c 'otherwise), which builds' DOX.md` prints `0`.

## Verify
```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
python3 scripts/check-pure-rust-crypto.py
test "$(grep -c 'CARGO_PKG_VERSION' src/lib.rs)" = 0
test "$(grep -c 'Never intercept TLS' src/config.rs)" = 0
diff <(awk '/reports the tag/,/Package archive \(Unix\)/' ../rusty-conduit/.github/workflows/release.yml) <(awk '/reports the tag/,/Package archive \(Unix\)/' .github/workflows/release.yml)
test "$(grep -c 'check-pure-rust-crypto.py' .github/workflows/ci.yml)" = 1
test "$(grep -c 'check-pure-rust-crypto.py' .github/workflows/release.yml)" = 1
ruby -ryaml -e 'ARGV.each { |f| YAML.load_file(f) }' .github/workflows/ci.yml .github/workflows/release.yml
git diff --exit-code -- src/reload.rs src/import Cargo.toml Cargo.lock Dockerfile docs
```

## Escalate when
- A contract row fails (help text, value name, env var, or visibility) → stop, set Status: needs-human — reason: paste the failing assertion.
- An existing test asserts the old `--mitm-bypass-host` wording or the old banner text → stop, set Status: needs-human — reason: name the test and paste its assertion.
- `python3 scripts/check-pure-rust-crypto.py` reports a banned crate → stop, set Status: needs-human — reason: paste its output.

## Log
- (append-only, one line per event)
- planner: before delegation, shifted the rusty-conduit release.yml line refs from 77-100 to 78-101 (rusty-conduit gained the crypto-check step in its verify job at fcc6cd4); the awk-based done-when check is unchanged
- sub-task 1: replaced `env!("CARGO_PKG_VERSION")` with `config::app_version()` in `src/lib.rs` `log_startup`
- sub-task 2: updated `--mitm-bypass-host` doc comment in `src/config.rs` to match family wording
- sub-task 3: added 4 shared flag rows (`mitm-insecure-host`, `mitm-bypass-host`, `mitm-insecure`, `error-page`) to `SHARED_FLAGS` in `tests/cli_contract.rs`
- sub-task 4: replaced Unix/Windows build steps in `.github/workflows/release.yml` with `Derive release version` (tag vs `Cargo.toml` guard) and unified `Build release binary` steps from `../rusty-conduit/.github/workflows/release.yml`
- sub-task 5: copied `scripts/check-pure-rust-crypto.py` from `rusty-conduit-engine` (chmod 755) and wired it into `.github/workflows/ci.yml` (`lint`) and `.github/workflows/release.yml` (`verify`)
- sub-task 6: updated `DOX.md` verification commands and `release.yml` tag-matching rule
- verify attempt 1: `cargo fmt --check` failed on single-line `logger.info(format!(...))` in `src/lib.rs`; added fix-up sub-task 7
- sub-task 7: formatted `logger.info(format!(...))` in `src/lib.rs` `log_startup` to match rustfmt
- verify: all commands in `## Verify` passed

- planner Gate D finding: DOX release sentence was a run-on after sub-task 6; rewrote it (sub-task 8)

## Evidence
- (append-only: command → observed result)
- `grep -c 'CARGO_PKG_VERSION' src/lib.rs` → `0`; `cargo build --locked` → exit 0
- `grep -c 'Never intercept TLS' src/config.rs` → `0`; `cargo build --locked` → exit 0
- `cargo test --locked --test cli_contract` → 3 passed, 0 failed
- `diff <(awk '/reports the tag/,/Package archive \(Unix\)/' ../rusty-conduit/.github/workflows/release.yml) <(awk '/reports the tag/,/Package archive \(Unix\)/' .github/workflows/release.yml)` → empty, exit 0; `grep -c 'does not match Cargo.toml version' .github/workflows/release.yml` → `1`
- `python3 scripts/check-pure-rust-crypto.py` → `PURE_RUST_CRYPTO_OK`; `grep -c 'check-pure-rust-crypto.py'` → `1` in both `.github/workflows/ci.yml` and `.github/workflows/release.yml`
- `grep -c 'check-pure-rust-crypto.py' DOX.md` → `1`; `grep -c 'base must equal the' DOX.md` → `1`
- `cargo fmt --check` (attempt 1) → exit 1 (diff in `src/lib.rs` `log_startup`)
- `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked && python3 scripts/check-pure-rust-crypto.py && test "$(grep -c 'CARGO_PKG_VERSION' src/lib.rs)" = 0 && test "$(grep -c 'Never intercept TLS' src/config.rs)" = 0 && diff <(awk '/reports the tag/,/Package archive \(Unix\)/' ../rusty-conduit/.github/workflows/release.yml) <(awk '/reports the tag/,/Package archive \(Unix\)/' .github/workflows/release.yml) && test "$(grep -c 'check-pure-rust-crypto.py' .github/workflows/ci.yml)" = 1 && test "$(grep -c 'check-pure-rust-crypto.py' .github/workflows/release.yml)" = 1 && ruby -ryaml -e 'ARGV.each { |f| YAML.load_file(f) }' .github/workflows/ci.yml .github/workflows/release.yml && git diff --exit-code -- src/reload.rs src/import Cargo.toml Cargo.lock Dockerfile docs` → exit 0 (`PURE_RUST_CRYPTO_OK`, all tests passed, `ALL_VERIFY_PASSED`)
- planner Gate D: `grep -c 'base must equal the' DOX.md` → 1; `grep -c 'otherwise), which builds' DOX.md` → 0
