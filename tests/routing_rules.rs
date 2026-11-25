//! Integration tests for the Auto Switch routing engine: every condition type, unified and
//! split tables, profile-level bypass, composite profiles, failover chain resolution, the
//! global filter, validation errors, and the `validate` / `test-route` subcommands (both
//! through the library entry points and the built binary).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusty_conduit_switch::config::{CliInput, Config, FileConfig, Inbound, ProfileType};
use rusty_conduit_switch::router::{
    FixedClock, LocalTime, Resolver, RouteDecision, RouteRequest, Router, RouterError,
    SystemResolver, TableKind,
};
use rusty_conduit_switch::{cmd_test_route, cmd_validate, EXIT_FATAL};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn config(text: &str) -> Config {
    let file = FileConfig::from_toml_str(text, Path::new("routing_rules.toml")).unwrap();
    Config::merge(CliInput::default(), Some(file)).unwrap()
}

fn router(text: &str) -> Router {
    let cfg = config(text);
    cfg.validate().unwrap();
    Router::from_input(&cfg.routing_input()).unwrap()
}

/// Monday 12:00 local.
const MON_NOON: FixedClock = FixedClock(LocalTime {
    weekday: 0,
    minute_of_day: 12 * 60,
});

/// A resolver that records every lookup (and must not be called unless opted in).
struct SpyResolver {
    calls: AtomicUsize,
    answer: Vec<IpAddr>,
}

impl SpyResolver {
    fn new(answer: &[&str]) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            answer: answer.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Resolver for SpyResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Vec<IpAddr> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answer.clone()
    }
}

fn route_at(r: &Router, req: RouteRequest<'_>, clock: &FixedClock) -> RouteDecision {
    r.route_with(&req, clock, &SystemResolver).unwrap()
}

fn rule_for(r: &Router, inbound: Inbound, host: &str, port: u16) -> String {
    route_at(r, RouteRequest::new(inbound, host, port), &MON_NOON)
        .rule_label()
        .to_string()
}

fn url_rule(r: &Router, host: &str, url: &str) -> String {
    let req = RouteRequest {
        url: Some(url),
        ..RouteRequest::new(Inbound::Http, host, 80)
    };
    route_at(r, req, &MON_NOON).rule_label().to_string()
}

const PROFILES: &str = r#"
[profiles.corp]
type = "http"
host = "10.0.0.2"
port = 3128
username = "alice"
password = "s3cret"
bypass = ["127.0.0.1", "::1", "localhost", "*.local"]

[profiles.bastion]
type = "socks5"
host = "127.0.0.1"
port = 1081

[profiles.secure_gw]
type = "https"
host = "proxy.example.com"
port = 8443

[profiles.legacy_socks]
type = "socks4a"
host = "10.0.0.5"
port = 1080
"#;

/// The annotated example from docs/MASTER-PLAN.md Section 3 (minus `watch_config`).
fn master_plan_example() -> String {
    format!(
        r#"
bind = "127.0.0.1"
http_port = 3128
socks_port = 1080
connect_timeout = "10s"
{PROFILES}
[routing]
default = "direct"
resolve_dns = false

[[routing.rules]]
name = "rfc1918-to-corp"
cidr = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
target = "corp"

[[routing.rules]]
name = "internal-domains-with-failover"
host_wildcard = ["*.internal.example", "dev-*.corp.net"]
target = ["bastion", "corp"]

[[routing.rules]]
name = "block-telemetry"
host_regex = "^telemetry\\..*\\.example\\.com$"
target = "block"

[[routing.rules]]
name = "ssh-over-bastion"
port = [22, "2200-2299"]
target = "bastion"

[[routing.rules]]
name = "socks-only-override"
inbound = "socks"
host_wildcard = ["*.db.internal"]
target = "bastion"

[[routing.rules]]
name = "plain-http-or-mitm-path"
url_wildcard = ["http://downloads.example.com/private/*"]
target = "corp"
"#
    )
}

// ---------------------------------------------------------------------------
// Condition types through the full router
// ---------------------------------------------------------------------------

#[test]
fn master_plan_example_routes_as_documented() {
    let r = router(&master_plan_example());
    assert_eq!(r.rule_count(), 6);

    let d = route_at(
        &r,
        RouteRequest::new(Inbound::Http, "10.1.2.3", 443),
        &MON_NOON,
    );
    assert_eq!(d.rule_label(), "rfc1918-to-corp");
    assert_eq!(d.profile_label(), "corp");

    let d = route_at(
        &r,
        RouteRequest::new(Inbound::Http, "api.internal.example", 443),
        &MON_NOON,
    );
    assert_eq!(d.rule_label(), "internal-domains-with-failover");
    assert_eq!(d.chain_label(), "bastion,corp");
    assert_eq!(d.targets[0].kind, ProfileType::Socks5);
    assert_eq!(d.targets[1].kind, ProfileType::Http);
    // `*.internal.example` covers the apex too.
    assert_eq!(
        rule_for(&r, Inbound::Http, "internal.example", 443),
        "internal-domains-with-failover"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "dev-42.corp.net", 443),
        "internal-domains-with-failover"
    );

    assert_eq!(
        rule_for(&r, Inbound::Http, "telemetry.eu.example.com", 443),
        "block-telemetry"
    );
    assert_eq!(
        rule_for(&r, Inbound::Socks, "git.example", 22),
        "ssh-over-bastion"
    );
    assert_eq!(
        rule_for(&r, Inbound::Socks, "git.example", 2222),
        "ssh-over-bastion"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "git.example", 2300),
        "<default>"
    );

    // inbound = "socks" only applies to SOCKS.
    assert_eq!(
        rule_for(&r, Inbound::Socks, "pg.db.internal", 5432),
        "socks-only-override"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "pg.db.internal", 5432),
        "<default>"
    );

    // URL rule: only with a visible URL.
    assert_eq!(
        url_rule(
            &r,
            "downloads.example.com",
            "http://downloads.example.com/private/file.iso"
        ),
        "plain-http-or-mitm-path"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "downloads.example.com", 80),
        "<default>"
    );
    assert_eq!(
        rule_for(&r, Inbound::Socks, "downloads.example.com", 80),
        "<default>"
    );
    let d = route_at(
        &r,
        RouteRequest::new(Inbound::Http, "x.test", 443),
        &MON_NOON,
    );
    assert!(d.has_url_rules);
    assert_eq!(d.profile_label(), "direct");
    // URL rules in a SOCKS-used table (and no MITM) produce both notices.
    assert_eq!(r.notices().len(), 2, "{:?}", r.notices());
}

#[test]
fn host_exact_and_host_regex() {
    let r = router(
        r#"
[[routing.rules]]
name = "exact"
host = ["Exact.Example.", "other.example"]
target = "block"
[[routing.rules]]
name = "regex"
host_regex = ["^cdn[0-9]+\\.example$", "^static\\."]
target = "block"
"#,
    );
    assert_eq!(rule_for(&r, Inbound::Http, "EXACT.example", 443), "exact");
    assert_eq!(rule_for(&r, Inbound::Http, "exact.example.", 443), "exact");
    assert_eq!(
        rule_for(&r, Inbound::Http, "www.exact.example", 443),
        "<default>"
    );
    assert_eq!(rule_for(&r, Inbound::Http, "cdn12.example", 443), "regex");
    assert_eq!(rule_for(&r, Inbound::Http, "static.foo.bar", 443), "regex");
    assert_eq!(
        rule_for(&r, Inbound::Http, "cdnx.example", 443),
        "<default>"
    );
}

#[test]
fn host_wildcard_airswitch_semantics() {
    let r = router(
        r#"
[[routing.rules]]
name = "apex-and-subs"
host_wildcard = "*.apex.example"
target = "block"
[[routing.rules]]
name = "subs-only"
host_wildcard = "**.subs.example"
target = "block"
[[routing.rules]]
name = "pipes-and-qmark"
host_wildcard = "n?de.example|.lan"
target = "block"
"#,
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "apex.example", 443),
        "apex-and-subs"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "a.b.apex.example", 443),
        "apex-and-subs"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "notapex.example", 443),
        "<default>"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "subs.example", 443),
        "<default>"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "x.subs.example", 443),
        "subs-only"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "node.example", 443),
        "pipes-and-qmark"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "nooode.example", 443),
        "<default>"
    );
    assert_eq!(
        rule_for(&r, Inbound::Http, "nas.lan", 443),
        "pipes-and-qmark"
    );
}

#[test]
fn cidr_ip_literals_mapped_ipv6_and_no_dns_by_default() {
    let text = r#"
[[routing.rules]]
name = "v4"
cidr = "192.168.0.0/16"
target = "block"
[[routing.rules]]
name = "v6"
ip = ["fd00::/8", "2001:db8::1"]
target = "block"
"#;
    let r = router(text);
    assert_eq!(rule_for(&r, Inbound::Socks, "192.168.4.4", 80), "v4");
    assert_eq!(rule_for(&r, Inbound::Socks, "::ffff:192.168.4.4", 80), "v4");
    assert_eq!(rule_for(&r, Inbound::Socks, "[fd00::5]", 80), "v6");
    assert_eq!(rule_for(&r, Inbound::Socks, "2001:db8::1", 80), "v6");
    assert_eq!(rule_for(&r, Inbound::Socks, "2001:db8::2", 80), "<default>");

    // Hostnames never trigger a lookup unless resolve_dns is enabled.
    let spy = SpyResolver::new(&["192.168.1.1"]);
    let d = r
        .route_with(
            &RouteRequest::new(Inbound::Socks, "nas.home.example", 80),
            &MON_NOON,
            &spy,
        )
        .unwrap();
    assert_eq!(d.rule_label(), "<default>");
    assert_eq!(spy.calls(), 0);

    let resolving = router(&format!("[routing]\nresolve_dns = true\n{text}"));
    let d = resolving
        .route_with(
            &RouteRequest::new(Inbound::Socks, "nas.home.example", 80),
            &MON_NOON,
            &spy,
        )
        .unwrap();
    assert_eq!(d.rule_label(), "v4");
    // One lookup per decision, shared by both CIDR rules.
    assert_eq!(spy.calls(), 1);
}

#[test]
fn port_host_levels_and_bypass_conditions() {
    let r = router(
        r#"
[[routing.rules]]
name = "web"
port = [80, 443, "8000-8080"]
host_levels = { max = 0 }
target = "block"
[[routing.rules]]
name = "deep"
host_levels = { min = 4, max = 5 }
target = "block"
[[routing.rules]]
name = "bypass-like"
bypass = ["<local>", "10.0.0.0/8", "db.example:5432", "https://*.secure.example"]
target = "block"
"#,
    );
    assert_eq!(rule_for(&r, Inbound::Http, "intranet", 8080), "web");
    assert_eq!(rule_for(&r, Inbound::Http, "intranet", 8081), "bypass-like"); // <local>
    assert_eq!(rule_for(&r, Inbound::Http, "a.b.c.d.example", 1), "deep");
    assert_eq!(
        rule_for(&r, Inbound::Http, "a.b.c.d.e.f.example", 1),
        "<default>"
    );
    assert_eq!(rule_for(&r, Inbound::Http, "10.9.8.7", 1), "bypass-like");
    assert_eq!(
        rule_for(&r, Inbound::Http, "db.example", 5432),
        "bypass-like"
    );
    assert_eq!(rule_for(&r, Inbound::Http, "db.example", 5433), "<default>");
    let https = RouteRequest {
        scheme: Some("https"),
        ..RouteRequest::new(Inbound::Http, "www.secure.example", 443)
    };
    assert_eq!(route_at(&r, https, &MON_NOON).rule_label(), "bypass-like");
    assert_eq!(
        rule_for(&r, Inbound::Http, "www.secure.example", 443),
        "<default>"
    );
}

#[test]
fn weekday_and_time_conditions_with_injected_clock() {
    let r = router(
        r#"
[[routing.rules]]
name = "office"
weekday = "mon-fri"
time = "09:00-17:30"
target = "block"
[[routing.rules]]
name = "night"
time = "22:00-06:00"
target = "block"
"#,
    );
    let at = |day: u8, h: u8, m: u8| {
        route_at(
            &r,
            RouteRequest::new(Inbound::Http, "h.example", 443),
            &FixedClock(LocalTime::new(day, h, m)),
        )
        .rule_label()
        .to_string()
    };
    assert_eq!(at(0, 9, 0), "office");
    assert_eq!(at(4, 17, 30), "office");
    assert_eq!(at(5, 12, 0), "<default>"); // Saturday
    assert_eq!(at(2, 17, 31), "<default>");
    assert_eq!(at(6, 23, 15), "night");
    assert_eq!(at(1, 3, 0), "night");
    assert_eq!(at(1, 6, 1), "<default>");
    // The system clock works too (no panic, some decision).
    assert!(r
        .route(&RouteRequest::new(Inbound::Http, "h.example", 443))
        .is_ok());
}

#[test]
fn url_wildcard_url_regex_and_keyword() {
    let r = router(
        r#"
[[routing.rules]]
name = "wild"
url_wildcard = "*://dl.example/*.iso"
target = "block"
[[routing.rules]]
name = "regex"
url_regex = "^https://api\\.example/v[0-9]+/"
target = "block"
[[routing.rules]]
name = "kw"
keyword = ["utm_source", "tracker"]
target = "block"
"#,
    );
    assert_eq!(
        url_rule(&r, "dl.example", "http://dl.example/os/x.iso"),
        "wild"
    );
    assert_eq!(
        url_rule(&r, "dl.example", "http://dl.example/os/x.img"),
        "<default>"
    );
    assert_eq!(
        url_rule(&r, "api.example", "https://api.example/v3/me"),
        "regex"
    );
    assert_eq!(
        url_rule(&r, "s.example", "http://s.example/?utm_source=x"),
        "kw"
    );
    // Opaque tunnels never match URL rules.
    assert_eq!(rule_for(&r, Inbound::Socks, "dl.example", 80), "<default>");
    assert_eq!(rule_for(&r, Inbound::Http, "api.example", 443), "<default>");
}

#[test]
fn match_all_disabled_and_rule_order() {
    let r = router(
        r#"
[[routing.rules]]
name = "off"
match_all = true
disabled = true
target = "block"
[[routing.rules]]
name = "and"
host = "a.example"
port = 22
target = "block"
[[routing.rules]]
name = "catch-all"
match_all = true
target = "block"
[[routing.rules]]
name = "never-reached"
host = "a.example"
target = "direct"
"#,
    );
    assert_eq!(rule_for(&r, Inbound::Http, "a.example", 22), "and");
    assert_eq!(rule_for(&r, Inbound::Http, "a.example", 443), "catch-all");
    let d = route_at(&r, RouteRequest::new(Inbound::Http, "z", 1), &MON_NOON);
    assert_eq!(
        (d.rule_index, d.profile_label().as_str()),
        (Some(2), "block")
    );
}

#[test]
fn unnamed_rules_get_positional_labels() {
    let r = router("[[routing.socks.rules]]\nhost = \"a\"\ntarget = \"block\"\n");
    assert_eq!(
        rule_for(&r, Inbound::Socks, "a", 1),
        "[routing.socks] rule #1"
    );
}

// ---------------------------------------------------------------------------
// Tables, bypass, composites, failover, filter
// ---------------------------------------------------------------------------

#[test]
fn unified_and_split_tables() {
    let r = router(&format!(
        r#"{PROFILES}
[routing]
default = "corp"
[[routing.rules]]
name = "u"
host = "shared.example"
target = "secure_gw"

[routing.http]
inherit = true
[[routing.http.rules]]
name = "h"
host = "web.example"
target = "block"

[routing.socks]
default = "bastion"
[[routing.socks.rules]]
name = "s"
host_wildcard = "*.local"
target = "direct"
"#
    ));
    let d = route_at(
        &r,
        RouteRequest::new(Inbound::Http, "web.example", 443),
        &MON_NOON,
    );
    assert_eq!((d.table, d.rule_label()), (TableKind::Http, "h"));
    let d = route_at(
        &r,
        RouteRequest::new(Inbound::Http, "shared.example", 443),
        &MON_NOON,
    );
    assert_eq!((d.table, d.rule_label()), (TableKind::Unified, "u"));
    let d = route_at(
        &r,
        RouteRequest::new(Inbound::Http, "else.example", 443),
        &MON_NOON,
    );
    assert_eq!(
        (d.rule_label(), d.profile_label().as_str()),
        ("<default>", "corp")
    );

    let d = route_at(
        &r,
        RouteRequest::new(Inbound::Socks, "nas.local", 445),
        &MON_NOON,
    );
    assert_eq!((d.table, d.rule_label()), (TableKind::Socks, "s"));
    // SOCKS does not inherit: the unified rule is skipped and the SOCKS default applies.
    let d = route_at(
        &r,
        RouteRequest::new(Inbound::Socks, "shared.example", 1),
        &MON_NOON,
    );
    assert_eq!(
        (d.table, d.profile_label().as_str()),
        (TableKind::Socks, "bastion")
    );
}

#[test]
fn profile_bypass_resolves_to_direct() {
    let r = router(&format!(
        "{PROFILES}\n[routing]\ndefault = [\"corp\", \"legacy_socks\"]\n"
    ));
    for host in ["127.0.0.1", "::1", "localhost", "printer.local"] {
        let d = route_at(&r, RouteRequest::new(Inbound::Http, host, 631), &MON_NOON);
        assert_eq!(d.profile_label(), "corp(bypass->direct)", "{host}");
        assert_eq!(d.targets[0].profile, "direct");
        assert_eq!(d.targets[0].kind, ProfileType::Direct);
        // legacy_socks has no bypass list.
        assert_eq!(d.targets[1].label(), "legacy_socks");
    }
    let d = route_at(
        &r,
        RouteRequest::new(Inbound::Http, "www.example", 443),
        &MON_NOON,
    );
    assert_eq!(d.chain_label(), "corp,legacy_socks");
    assert!(!d.targets[0].bypassed);
}

#[test]
fn failover_chains_and_composite_profiles_resolve_in_order() {
    let r = router(&format!(
        r#"{PROFILES}
[profiles.per_scheme]
type = "fixed"
http_proxy = "corp"
https_proxy = "secure_gw"
fallback_proxy = "bastion"

[[routing.rules]]
name = "chain"
match_all = true
target = ["per_scheme", "legacy_socks", "block", "direct"]
"#
    ));
    let chain = |scheme: Option<&str>, url: Option<&str>| {
        let req = RouteRequest {
            scheme,
            url,
            ..RouteRequest::new(Inbound::Http, "www.example", 443)
        };
        route_at(&r, req, &MON_NOON).chain_label()
    };
    assert_eq!(
        chain(Some("https"), None),
        "per_scheme->secure_gw,legacy_socks,block,direct"
    );
    assert_eq!(
        chain(None, Some("http://www.example/")),
        "per_scheme->corp,legacy_socks,block,direct"
    );
    assert_eq!(
        chain(None, None),
        "per_scheme->bastion,legacy_socks,block,direct"
    );
}

#[test]
fn global_filter_denies_before_routing() {
    let r = router("[filter]\nallow = [\"*.allowed.example\", \"10.0.0.0/8\"]\n");
    assert!(r
        .route(&RouteRequest::new(Inbound::Http, "a.allowed.example", 443))
        .is_ok());
    assert!(r
        .route(&RouteRequest::new(Inbound::Socks, "10.1.1.1", 22))
        .is_ok());
    let denied = r
        .route(&RouteRequest::new(Inbound::Http, "evil.example", 443))
        .unwrap_err();
    assert!(denied.0.contains("not in allowlist"), "{}", denied.0);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_bad_configs() {
    let cases: &[(&str, &str)] = &[
        (
            "[[routing.rules]]\nhost_regex = \"(\"\ntarget = \"direct\"\n",
            "`host_regex`",
        ),
        (
            "[[routing.rules]]\ncidr = \"300.0.0.0/8\"\ntarget = \"direct\"\n",
            "`cidr`",
        ),
        (
            "[[routing.rules]]\nport = \"1-0\"\ntarget = \"direct\"\n",
            "`port`",
        ),
        (
            "[[routing.rules]]\ntime = \"24:00-01:00\"\ntarget = \"direct\"\n",
            "`time`",
        ),
        (
            "[[routing.rules]]\nweekday = \"someday\"\ntarget = \"direct\"\n",
            "`weekday`",
        ),
        (
            "[[routing.rules]]\nname = \"empty\"\ntarget = \"direct\"\n",
            "match_all",
        ),
        (
            "[profiles.a]\ntype = \"composite\"\nfallback_proxy = \"b\"\n\
             [profiles.b]\ntype = \"composite\"\nfallback_proxy = \"a\"\n",
            "composite profile cycle: a -> b -> a",
        ),
        (
            "[profiles.p]\ntype = \"http\"\nhost = \"h\"\nport = 1\nbypass = [\"h:x\"]\n",
            "profile `p`: invalid `bypass`",
        ),
        (
            "[[routing.rules]]\nhost = \"a\"\ntarget = [\"direct\", \"ghost\"]\n",
            "unknown profile `ghost`",
        ),
        (
            "[profiles.me]\ntype = \"socks5\"\nhost = \"127.0.0.1\"\nport = 1080\n",
            "self-loop",
        ),
    ];
    for (text, needle) in cases {
        let cfg = config(text);
        let msg = cfg.validate().unwrap_err().to_string();
        assert!(msg.contains(needle), "{text}\n=> {msg}");
    }
    // The router-level error type is available for hot-reload callers.
    let cfg = config("[profiles.x]\ntype = \"composite\"\nhttp_proxy = \"x\"\n");
    assert!(matches!(
        Router::from_input(&cfg.routing_input()),
        Err(RouterError::CompositeCycle { .. })
    ));
}

// ---------------------------------------------------------------------------
// CLI: validate / test-route
// ---------------------------------------------------------------------------

struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str, text: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("rcs-routing-{name}-{}.toml", std::process::id()));
        std::fs::write(&path, text).unwrap();
        Self(path)
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn cli(args: &[&str]) -> CliInput {
    let mut full = vec!["rusty-conduit-switch"];
    full.extend_from_slice(args);
    CliInput::try_parse_from(full).unwrap()
}

fn test_route(path: &str, inbound: Inbound, target: &str) -> (u8, String, String) {
    let inbound_arg = inbound.to_string();
    let c = cli(&[
        "test-route",
        "--config",
        path,
        "--inbound",
        &inbound_arg,
        target,
    ]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cmd_test_route(c, inbound, target, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn cmd_validate_reports_ok_notices_and_errors() {
    let good = TempFile::new("validate-good", &master_plan_example());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cmd_validate(
        cli(&["validate", "--config", good.path()]),
        &mut out,
        &mut err,
    );
    let out = String::from_utf8(out).unwrap();
    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
    assert!(
        out.contains("config OK") && out.contains("profiles=6 rules=6"),
        "{out}"
    );
    assert!(out.contains("plain-http-or-mitm-path"), "{out}");

    let bad = TempFile::new(
        "validate-bad",
        "[[routing.rules]]\nname = \"broken\"\nhost_regex = \"[\"\ntarget = \"direct\"\n",
    );
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cmd_validate(
        cli(&["validate", "--config", bad.path()]),
        &mut out,
        &mut err,
    );
    assert_eq!(code, EXIT_FATAL);
    let err = String::from_utf8(err).unwrap();
    assert!(
        err.contains("[routing] rule #1 (\"broken\")") && err.contains("`host_regex`"),
        "{err}"
    );
}

#[test]
fn cmd_test_route_prints_decisions() {
    let f = TempFile::new("test-route", &master_plan_example());
    let (code, out, _) = test_route(f.path(), Inbound::Http, "api.internal.example:443");
    assert_eq!(code, 0);
    assert!(
        out.contains(
            "target=api.internal.example:443 inbound=http table=[routing] \
             rule=internal-domains-with-failover profile=bastion chain=bastion,corp \
             upstream=socks5://127.0.0.1:1081"
        ),
        "{out}"
    );

    let (_, out, _) = test_route(f.path(), Inbound::Socks, "10.1.5.5:5432");
    assert!(out.contains("rule=rfc1918-to-corp profile=corp"), "{out}");
    assert!(out.contains("upstream=http://10.0.0.2:3128"), "{out}");
    assert!(!out.contains("s3cret") && !out.contains("alice"), "{out}");

    let (_, out, _) = test_route(f.path(), Inbound::Http, "[::1]:8080");
    assert!(out.contains("target=[::1]:8080"), "{out}");
    assert!(out.contains("rule=<default> profile=direct"), "{out}");

    // Plain-HTTP URL: URL rule evaluates.
    let url = "http://downloads.example.com/private/x.zip";
    let (_, out, _) = test_route(f.path(), Inbound::Http, url);
    assert!(
        out.contains("rule=plain-http-or-mitm-path profile=corp"),
        "{out}"
    );
    // Same URL over SOCKS: no URL visible.
    let (_, out, _) = test_route(f.path(), Inbound::Socks, url);
    assert!(out.contains("rule=<default>"), "{out}");
    assert!(
        out.contains("note: SOCKS connections carry no URL"),
        "{out}"
    );
    // HTTPS without MITM: opaque CONNECT.
    let (_, out, _) = test_route(
        f.path(),
        Inbound::Http,
        "https://downloads.example.com/private/x",
    );
    assert!(out.contains("target=downloads.example.com:443"), "{out}");
    assert!(out.contains("note: HTTPS without MITM"), "{out}");

    // Bypass annotation.
    let bypass = TempFile::new(
        "test-route-bypass",
        &format!("{PROFILES}\n[routing]\ndefault = \"corp\"\n"),
    );
    let (_, out, _) = test_route(bypass.path(), Inbound::Http, "nas.local:445");
    assert!(out.contains("profile=corp(bypass->direct)"), "{out}");
    assert!(out.contains("upstream=direct"), "{out}");

    // Filter denial and invalid target.
    let filtered = TempFile::new(
        "test-route-filter",
        "[filter]\nblock = [\"*.ads.example\"]\n",
    );
    let (code, out, _) = test_route(filtered.path(), Inbound::Http, "x.ads.example:443");
    assert_eq!(code, 0);
    assert!(out.contains("status=denied_by_filter"), "{out}");
    let (code, _, err) = test_route(filtered.path(), Inbound::Http, "host:notaport");
    assert_eq!(code, EXIT_FATAL);
    assert!(err.contains("invalid target"), "{err}");
}

#[test]
fn binary_validate_and_test_route() {
    let f = TempFile::new("binary", &master_plan_example());
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
    let (code, out, err) = run(&["validate", "--config", f.path()]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("config OK"), "{out}");

    let (code, out, _) = run(&[
        "test-route",
        "--config",
        f.path(),
        "--inbound",
        "socks",
        "pg.db.internal:5432",
    ]);
    assert_eq!(code, Some(0));
    assert!(
        out.contains("rule=socks-only-override profile=bastion"),
        "{out}"
    );

    let bad = TempFile::new("binary-bad", "[routing]\ndefault = \"nowhere\"\n");
    let (code, _, err) = run(&["validate", "--config", bad.path()]);
    assert_eq!(code, Some(1));
    assert!(err.contains("unknown profile `nowhere`"), "{err}");
}
