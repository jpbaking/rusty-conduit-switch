# TODO

- **`v3.0.0` deprecated config alias removal:** Remove the deprecated aliases currently emitting
  `NOTICE:` warnings in `src/config.rs` (can be paired with the next breaking `rusty-conduit-engine`
  cleanup):
  - `--tcp-keepalive-idle` / `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_IDLE` (replaced by `--tcp-keepalive` / `RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE`)
  - `--mitm-cert-cache-max` / `RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX` (replaced by `--mitm-cert-cache-max-entries` / `RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX_ENTRIES`)
  - TOML `[tcp_keepalive]` table (replaced by top-level `tcp_keepalive`, `tcp_keepalive_interval`, `tcp_keepalive_retries`)
  - TOML `[filter]` table (replaced by top-level `allow` and `block`)
  - TOML `[mitm] cert_cache_max` (replaced by `[mitm] cert_cache_max_entries`)
