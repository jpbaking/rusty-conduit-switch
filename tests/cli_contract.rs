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
        assert_eq!(
            env.as_deref(),
            Some(expected_env.as_str()),
            "--{long} env var"
        );
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
    assert!(
        !out.contains("--tcp-keepalive-idle"),
        "deprecated alias must stay hidden: {out}"
    );
    assert!(
        !out.contains("--mitm-cert-cache-max <"),
        "deprecated alias must stay hidden: {out}"
    );
    let (code, _, _) = run(&["--no-such-flag"]);
    assert_eq!(code, Some(2), "usage errors exit 2");
    let missing =
        std::env::temp_dir().join(format!("cli-contract-missing-{}.toml", std::process::id()));
    let (code, _, err) = run(&[
        "--config",
        missing.to_str().unwrap(),
        "--http-port",
        "0",
        "--socks-port",
        "0",
    ]);
    assert_eq!(code, Some(1), "config errors exit 1: {err}");
}
