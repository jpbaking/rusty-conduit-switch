# phase-0005 — Update user docs and DOX Feature Map

- Status: done
- Owner: executor
- Depends on: phase-0001, phase-0002, phase-0003, phase-0004
- Goal: Make every user-facing doc describe the new flag, env, and TOML names and defaults, list the deprecated names in one place, and document the open-file limit behaviour.
- Done when: every command in `## Verify` exits 0.
- Pattern to follow: the flag reference table in `docs/USER-GUIDE.md` (around line 120) for row format; `../rusty-conduit/docs/PERFORMANCE-AND-SIZING.md` section 3 for the open-file limit wording (read only; do not edit that repo)

## Context
Phases 0001–0004 changed: `--tcp-keepalive-idle` → `--tcp-keepalive` (env `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE`); `--mitm-cert-cache-max` → `--mitm-cert-cache-max-entries` (env `..._MITM_CERT_CACHE_MAX_ENTRIES`); TOML `[tcp_keepalive]` table → top-level `tcp_keepalive`, `tcp_keepalive_interval`, `tcp_keepalive_retries`; `[filter]` table → top-level `allow`, `block`; `mitm.cert_cache_max` → `mitm.cert_cache_max_entries`; defaults `max_connections` 1024 → 4096 and MITM cache 4096 → 10240; `--allow` + `--block` together act as block-with-exceptions; startup raises the soft open-file limit and logs `NOTICE: open-file limit is …` if it still cannot hold `--max-connections` (needs `2 × max_connections + 64`). Old names still work and log a deprecation NOTICE.
Rule for old names: they may appear only in rows or lines that also contain the word `deprecated`, so the Verify greps can find stray ones. The hot-reload docs must use the new key names.
In `DOX.md`, edit only the `## Project Rules` and `## Feature Map` sections; the rest of that file is framework text.

## Scope
- In: `docs/USER-GUIDE.md`, `docs/MITM-CA-GUIDE.md`, `docs/MASTER-PLAN.md`, `README.md`, `DOX.md`
- Out: `src/`, `tests/`, `tests/DOX.md`, `src/import/DOX.md`, `Dockerfile`, every file outside this repository

## Sub-tasks
1. [done] `docs/USER-GUIDE.md`: update the flag/env/TOML reference rows for the renamed flags and the two defaults; rewrite the TOML example (around lines 160–185) to the flat keys; change any `--block` text that says it is mutually exclusive with `--allow` to describe block-with-exceptions; add a `### Deprecated names` subsection after the reference table with one row per old name, formatted `| \`<old>\` (deprecated) | \`<new>\` |`, covering both flags, both env vars, the two TOML tables, and `mitm.cert_cache_max`; add a short `### Open-file limit` subsection stating the `2 × max_connections + 64` rule, that the switch raises its soft limit at startup, and the NOTICE text it logs otherwise — done when: `grep -n 'Deprecated names' docs/USER-GUIDE.md` and `grep -n 'Open-file limit' docs/USER-GUIDE.md` both print a line.
2. [done] `docs/MITM-CA-GUIDE.md`: change `cert_cache_max = 4096` (around line 157) to `cert_cache_max_entries = 10240` and update any flag or default mentioned nearby — done when: `grep -n 'cert_cache_max\b' docs/MITM-CA-GUIDE.md | grep -vi deprecated` prints nothing.
3. [done] `docs/MASTER-PLAN.md`: update the option table rows (around lines 82 and 94) and the hot-reload sentence (around line 101) to the new names and defaults — done when: `grep -nE '\[filter\]|\[tcp_keepalive\]' docs/MASTER-PLAN.md | grep -vi deprecated` prints nothing.
4. [done] `README.md`: if its quick-start config uses `[filter]`, `[tcp_keepalive]`, or `cert_cache_max`, switch it to the new keys — done when: the README grep in `## Verify` passes.
5. [done] `DOX.md` `## Feature Map`: add `- **Open-file limit** — raises the soft \`RLIMIT_NOFILE\` at startup and logs a NOTICE when it cannot hold \`--max-connections\`. Start: \`src/fdlimit.rs\`. Files: \`src/lib.rs\` (\`run\`), \`Cargo.toml\` (\`rlimit\`).` and `- **CLI family contract** — test that shared flags keep the family's names, value names, env vars, help text, and defaults. Start: \`tests/cli_contract.rs\`.`; extend the existing **Configuration loading & validation** bullet with `; deprecated aliases (\`--tcp-keepalive-idle\`, \`--mitm-cert-cache-max\`, \`[tcp_keepalive]\`, \`[filter]\`, \`mitm.cert_cache_max\`) log a NOTICE` — done when: `grep -c 'fdlimit.rs\|cli_contract.rs' DOX.md` prints at least `2`.

## Verify
```sh
! grep -rnE 'tcp-keepalive-idle|TCP_KEEPALIVE_IDLE|mitm-cert-cache-max([^-]|$)|MITM_CERT_CACHE_MAX([^_]|$)|cert_cache_max([^_]|$)|\[filter\]|\[tcp_keepalive\]' docs README.md | grep -vi deprecated
! grep -rnE 'max_connections = 1024|cert_cache_max_entries = 4096|mutually exclusive with --allow' docs README.md
grep -n 'Deprecated names' docs/USER-GUIDE.md
grep -n 'Open-file limit' docs/USER-GUIDE.md
grep -n '10240' docs/USER-GUIDE.md
grep -n 'fdlimit.rs' DOX.md
grep -n 'cli_contract.rs' DOX.md
cargo test --locked
```

## Escalate when
- A doc describes behaviour that the code from phases 0001–0004 contradicts (for example a default or key that the code does not have) → stop, set Status: needs-human — reason: quote the doc line and what the code does.
- An old name appears in a code sample that cannot carry the word `deprecated` on the same line → stop, set Status: needs-human — reason: quote the sample and file:line.

## Log
- (append-only, one line per event)
- sub-task 1: updated `docs/USER-GUIDE.md` reference table, block-with-exceptions wording, flat TOML example, hot-reload/MITM references, and added `### Deprecated names` and `### Open-file limit` subsections.
- sub-task 2: updated `docs/MITM-CA-GUIDE.md` (`cert_cache_max_entries = 10240`, `--mitm-cert-cache-max-entries`, `--socks-block-web`).
- sub-task 3: updated `docs/MASTER-PLAN.md` option table, hot-reload sentence, and global filter note to new names and defaults.
- sub-task 4: checked `README.md` — already had no legacy keys/tables.
- sub-task 5: updated `DOX.md` `## Feature Map` with **Open-file limit**, **CLI family contract**, and deprecated-aliases note on **Configuration loading & validation**.
- verify: all 8 commands in `## Verify` passed; closing phase-0005.

## Evidence
- (append-only: command → observed result)
- `(! grep -rnE 'tcp-keepalive-idle|TCP_KEEPALIVE_IDLE|mitm-cert-cache-max([^-]|$)|MITM_CERT_CACHE_MAX([^_]|$)|cert_cache_max([^_]|$)|\[filter\]|\[tcp_keepalive\]' docs README.md | grep -vi deprecated) && (! grep -rnE 'max_connections = 1024|cert_cache_max_entries = 4096|mutually exclusive with --allow' docs README.md)` → exited 0 (no stray legacy names or old defaults).
- `grep -n 'Deprecated names' docs/USER-GUIDE.md && grep -n 'Open-file limit' docs/USER-GUIDE.md && grep -n '10240' docs/USER-GUIDE.md && grep -n 'fdlimit.rs' DOX.md && grep -n 'cli_contract.rs' DOX.md && grep -c 'fdlimit.rs\|cli_contract.rs' DOX.md` → matched lines 150, 165, 132, 207 in `docs/USER-GUIDE.md`, lines 234, 235 (count `2`) in `DOX.md`.
- `cargo test --locked` → 61 unit tests + 75 integration tests passed, 0 failed.
