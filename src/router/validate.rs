//! Routing validation: profile references, failover targets, composite-profile cycles,
//! rule syntax (regex / CIDR / port / time / bypass), self-loop detection, and the
//! URL-rules-on-opaque-tunnel notices.
//!
//! Everything here runs at startup, in `validate`, and before a hot-reload swap; any error
//! rejects the candidate configuration.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use crate::config::{
    host_targets_listener, Config, Inbound, ProfileConfig, ProfileType, RoutingConfig,
    RoutingTableConfig, RuleConfig, Target, PROFILE_BLOCK, PROFILE_DIRECT,
};

use super::condition::{BypassList, ConditionError, RuleMatcher};

/// A routing configuration that cannot be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouterError {
    #[error("{location}: invalid condition {source}")]
    InvalidRule {
        location: String,
        #[source]
        source: ConditionError,
    },
    #[error("profile `{profile}`: invalid {source}")]
    InvalidProfileBypass {
        profile: String,
        #[source]
        source: ConditionError,
    },
    #[error("{location} references unknown profile `{target}`")]
    UnknownProfile { location: String, target: String },
    #[error("{location} has an empty failover chain")]
    EmptyTarget { location: String },
    #[error("composite profile cycle: {}", .cycle.join(" -> "))]
    CompositeCycle { cycle: Vec<String> },
    #[error("profile `{profile}` points to this server's own listener {listener} (self-loop)")]
    SelfLoop { profile: String, listener: String },
}

/// Human-readable location of rule `index` (0-based) in `table` (e.g. `[routing.socks]`).
pub fn rule_location(table: &str, index: usize, rule: &RuleConfig) -> String {
    match &rule.name {
        Some(n) => format!("{table} rule #{} ({n:?})", index + 1),
        None => format!("{table} rule #{}", index + 1),
    }
}

fn has_profile(profiles: &BTreeMap<String, ProfileConfig>, name: &str) -> bool {
    name == PROFILE_DIRECT || name == PROFILE_BLOCK || profiles.contains_key(name)
}

/// Every name in a target (single profile or failover chain) must exist.
pub fn check_target(
    profiles: &BTreeMap<String, ProfileConfig>,
    location: &str,
    target: &Target,
) -> Result<(), RouterError> {
    let names = target.as_slice();
    if names.is_empty() {
        return Err(RouterError::EmptyTarget {
            location: location.to_string(),
        });
    }
    match names.iter().find(|n| !has_profile(profiles, n)) {
        Some(missing) => Err(RouterError::UnknownProfile {
            location: location.to_string(),
            target: missing.clone(),
        }),
        None => Ok(()),
    }
}

/// Sub-targets of a composite profile, in `http_proxy`, `https_proxy`, `fallback_proxy` order.
pub fn composite_parts(p: &ProfileConfig) -> impl Iterator<Item = (&'static str, &String)> {
    [
        ("http_proxy", p.http_proxy.as_ref()),
        ("https_proxy", p.https_proxy.as_ref()),
        ("fallback_proxy", p.fallback_proxy.as_ref()),
    ]
    .into_iter()
    .filter_map(|(f, v)| v.map(|v| (f, v)))
}

/// Composite sub-targets must exist and must not form a cycle (including self-reference).
pub fn check_composites(profiles: &BTreeMap<String, ProfileConfig>) -> Result<(), RouterError> {
    for (name, p) in profiles {
        for (field, sub) in composite_parts(p) {
            if !has_profile(profiles, sub) {
                return Err(RouterError::UnknownProfile {
                    location: format!("profile `{name}` {field}"),
                    target: sub.clone(),
                });
            }
        }
    }
    // Iterative DFS with colouring: 0 = unvisited, 1 = on stack, 2 = done.
    let mut state: BTreeMap<&str, u8> = BTreeMap::new();
    for start in profiles.keys() {
        if state.get(start.as_str()).copied().unwrap_or(0) != 0 {
            continue;
        }
        let mut path: Vec<&str> = Vec::new();
        visit(profiles, start, &mut state, &mut path)?;
    }
    Ok(())
}

fn visit<'p>(
    profiles: &'p BTreeMap<String, ProfileConfig>,
    name: &'p str,
    state: &mut BTreeMap<&'p str, u8>,
    path: &mut Vec<&'p str>,
) -> Result<(), RouterError> {
    match state.get(name).copied().unwrap_or(0) {
        2 => return Ok(()),
        1 => {
            let start = path.iter().position(|n| *n == name).unwrap_or(0);
            let mut cycle: Vec<String> = path[start..].iter().map(|s| s.to_string()).collect();
            cycle.push(name.to_string());
            return Err(RouterError::CompositeCycle { cycle });
        }
        _ => {}
    }
    let Some(p) = profiles.get(name) else {
        return Ok(());
    };
    if p.kind != ProfileType::Composite {
        state.insert(name, 2);
        return Ok(());
    }
    state.insert(name, 1);
    path.push(name);
    for (_, sub) in composite_parts(p) {
        visit(profiles, sub.as_str(), state, path)?;
    }
    path.pop();
    state.insert(name, 2);
    Ok(())
}

/// No proxy profile may point at one of `listeners` (the active `(bind, port)` pairs).
///
/// `localhost` counts as `127.0.0.1` / `::1`; a listener on `0.0.0.0` / `::` also catches
/// loopback and unspecified upstream addresses. Other hostnames are never resolved.
pub fn check_self_loop(
    profiles: &BTreeMap<String, ProfileConfig>,
    listeners: &[SocketAddr],
) -> Result<(), RouterError> {
    for (name, p) in profiles {
        let (true, Some(host), Some(port)) = (p.kind.is_proxy(), &p.host, p.port) else {
            continue;
        };
        if let Some(l) = listeners
            .iter()
            .find(|l| l.port() == port && host_targets_listener(host, l.ip()))
        {
            return Err(RouterError::SelfLoop {
                profile: name.clone(),
                listener: l.to_string(),
            });
        }
    }
    Ok(())
}

/// The `(bind, port)` pairs of the listeners `cfg` enables.
pub fn configured_listeners(cfg: &Config) -> Vec<SocketAddr> {
    cfg.active_ports()
        .into_iter()
        .map(|p| SocketAddr::new(cfg.bind, p))
        .collect()
}

/// Compile every rule of one table (syntax validation + target check).
pub fn compile_rules(
    profiles: &BTreeMap<String, ProfileConfig>,
    table: &str,
    rules: &[RuleConfig],
    global_resolve_dns: bool,
) -> Result<Vec<RuleMatcher>, RouterError> {
    rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let location = rule_location(table, i, rule);
            check_target(profiles, &location, &rule.target)?;
            RuleMatcher::compile(rule, global_resolve_dns)
                .map_err(|source| RouterError::InvalidRule { location, source })
        })
        .collect()
}

/// Compile every profile-level `bypass` list.
pub fn compile_profile_bypass(
    profiles: &BTreeMap<String, ProfileConfig>,
) -> Result<BTreeMap<String, BypassList>, RouterError> {
    profiles
        .iter()
        .filter(|(_, p)| !p.bypass.is_empty())
        .map(|(name, p)| {
            BypassList::compile(&p.bypass)
                .map(|list| (name.clone(), list))
                .map_err(|source| RouterError::InvalidProfileBypass {
                    profile: name.clone(),
                    source,
                })
        })
        .collect()
}

fn url_rule_names(table: &str, rules: &[RuleConfig]) -> Vec<String> {
    rules
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            !r.disabled
                && (r.url_wildcard.is_some() || r.url_regex.is_some() || r.keyword.is_some())
        })
        .map(|(i, r)| match &r.name {
            Some(n) => n.clone(),
            None => format!("{table} rule #{}", i + 1),
        })
        .collect()
}

/// Which inbound protocols evaluate the unified `[routing]` rules.
fn unified_users(routing: &RoutingConfig) -> Vec<Inbound> {
    let uses = |t: &Option<RoutingTableConfig>| t.as_ref().is_none_or(|t| t.inherit);
    let mut out = Vec::new();
    if uses(&routing.http) {
        out.push(Inbound::Http);
    }
    if uses(&routing.socks) {
        out.push(Inbound::Socks);
    }
    out
}

/// `INFO` notices for URL rules (`url_wildcard`, `url_regex`, `keyword`) in tables used by
/// SOCKS or by HTTPS `CONNECT` without MITM, where the full URL is never visible.
pub fn url_rule_notices(routing: &RoutingConfig, mitm_enabled: bool) -> Vec<String> {
    let mut tables: Vec<(String, Vec<String>, Vec<Inbound>)> = vec![(
        "[routing]".into(),
        url_rule_names("[routing]", &routing.rules),
        unified_users(routing),
    )];
    if let Some(t) = &routing.http {
        tables.push((
            "[routing.http]".into(),
            url_rule_names("[routing.http]", &t.rules),
            vec![Inbound::Http],
        ));
    }
    if let Some(t) = &routing.socks {
        tables.push((
            "[routing.socks]".into(),
            url_rule_names("[routing.socks]", &t.rules),
            vec![Inbound::Socks],
        ));
    }
    let mut out = Vec::new();
    for (table, names, users) in tables {
        if names.is_empty() {
            continue;
        }
        let list = names.join(", ");
        if users.contains(&Inbound::Socks) {
            out.push(format!(
                "NOTICE: {table} URL rules ({list}) never match SOCKS connections (the full URL \
                 is not visible on an opaque L4 tunnel)"
            ));
        }
        if users.contains(&Inbound::Http) && !mitm_enabled {
            out.push(format!(
                "NOTICE: {table} URL rules ({list}) only evaluate on plain HTTP requests; HTTPS \
                 CONNECT tunnels never match them because MITM is disabled"
            ));
        }
    }
    out
}

/// Full routing validation of a merged configuration against its own listeners.
///
/// Returns the `INFO` notices to log on success.
pub fn validate_config(cfg: &Config) -> Result<Vec<String>, RouterError> {
    validate_with_listeners(cfg, &configured_listeners(cfg))
}

/// Full routing validation against explicit active `listeners` (used by hot-reload, where
/// the running listeners — not the candidate file's — are what must not be looped back to).
pub fn validate_with_listeners(
    cfg: &Config,
    listeners: &[SocketAddr],
) -> Result<Vec<String>, RouterError> {
    super::Router::from_config_with_listeners(cfg, listeners).map(|r| r.notices().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CliInput, FileConfig};
    use std::path::Path;

    fn cfg(text: &str) -> Config {
        let file = FileConfig::from_toml_str(text, Path::new("test.toml")).unwrap();
        Config::merge(CliInput::default(), Some(file)).unwrap()
    }

    #[test]
    fn valid_config_passes_with_no_notices() {
        let c = cfg(r#"
            [profiles.corp]
            type = "http"
            host = "10.0.0.2"
            port = 3128
            bypass = ["<local>", "*.local", "10.0.0.0/8", "db:5432"]
            [profiles.bastion]
            type = "socks5"
            host = "127.0.0.1"
            port = 1081
            [profiles.split]
            type = "composite"
            http_proxy = "corp"
            fallback_proxy = "bastion"
            [routing]
            default = ["corp", "direct"]
            [[routing.rules]]
            cidr = ["10.0.0.0/8"]
            target = "corp"
            [[routing.rules]]
            host_wildcard = ["*.internal.example"]
            port = [22, "2200-2299"]
            time = "09:00-17:30"
            weekday = "mon-fri"
            target = ["bastion", "split"]
        "#);
        assert_eq!(validate_config(&c).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn missing_profiles_are_reported_with_location() {
        let mut c = cfg(
            "[[routing.rules]]\nname = \"r\"\nhost = \"a\"\ntarget = [\"direct\", \"ghost\"]\n",
        );
        let e = validate_config(&c).unwrap_err();
        assert_eq!(
            e,
            RouterError::UnknownProfile {
                location: "[routing] rule #1 (\"r\")".into(),
                target: "ghost".into()
            }
        );
        c.routing.rules.clear();
        c.routing.default = Target::One("nope".into());
        assert!(validate_config(&c)
            .unwrap_err()
            .to_string()
            .contains("[routing].default references unknown profile `nope`"));
        c.routing.default = Target::Many(vec![]);
        assert!(matches!(
            validate_config(&c),
            Err(RouterError::EmptyTarget { .. })
        ));

        let c = cfg("[routing.socks]\ndefault = \"x\"\n");
        assert!(validate_config(&c)
            .unwrap_err()
            .to_string()
            .contains("[routing.socks].default"));
        let c = cfg("[profiles.c]\ntype = \"composite\"\nhttps_proxy = \"missing\"\n");
        assert!(validate_config(&c)
            .unwrap_err()
            .to_string()
            .contains("profile `c` https_proxy references unknown profile `missing`"));
    }

    #[test]
    fn composite_cycles_are_detected() {
        let c = cfg(r#"
            [profiles.a]
            type = "composite"
            http_proxy = "b"
            [profiles.b]
            type = "composite"
            fallback_proxy = "c"
            [profiles.c]
            type = "fixed"
            https_proxy = "a"
        "#);
        let e = validate_config(&c).unwrap_err();
        assert_eq!(
            e,
            RouterError::CompositeCycle {
                cycle: vec!["a".into(), "b".into(), "c".into(), "a".into()]
            }
        );
        let selfref = cfg("[profiles.me]\ntype = \"composite\"\nfallback_proxy = \"me\"\n");
        assert!(validate_config(&selfref)
            .unwrap_err()
            .to_string()
            .contains("me -> me"));
        // A diamond (shared sub-targets) is not a cycle.
        let diamond = cfg(r#"
            [profiles.p]
            type = "socks5"
            host = "10.0.0.9"
            port = 1080
            [profiles.x]
            type = "composite"
            http_proxy = "p"
            https_proxy = "y"
            [profiles.y]
            type = "composite"
            fallback_proxy = "p"
        "#);
        assert!(validate_config(&diamond).is_ok());
    }

    #[test]
    fn self_loops_against_active_listeners() {
        let profiles = cfg(r#"
            [profiles.loop]
            type = "socks5"
            host = "localhost"
            port = 1080
        "#)
        .profiles;
        let local: Vec<SocketAddr> = vec!["127.0.0.1:1080".parse().unwrap()];
        assert!(matches!(
            check_self_loop(&profiles, &local),
            Err(RouterError::SelfLoop { .. })
        ));
        let any: Vec<SocketAddr> = vec!["0.0.0.0:1080".parse().unwrap()];
        assert!(check_self_loop(&profiles, &any).is_err());
        let other_port: Vec<SocketAddr> = vec!["127.0.0.1:1081".parse().unwrap()];
        assert!(check_self_loop(&profiles, &other_port).is_ok());
        let other_ip: Vec<SocketAddr> = vec!["10.1.1.1:1080".parse().unwrap()];
        assert!(check_self_loop(&profiles, &other_ip).is_ok());

        // Hot-reload style: candidate config validated against explicit running listeners.
        let c = cfg("http_port = 9000\nsocks_port = 9001\n[profiles.p]\ntype = \"http\"\nhost = \"::1\"\nport = 3128\n");
        assert!(validate_config(&c).is_ok());
        let running: Vec<SocketAddr> = vec!["[::]:3128".parse().unwrap()];
        assert!(validate_with_listeners(&c, &running)
            .unwrap_err()
            .to_string()
            .contains("self-loop"));
    }

    #[test]
    fn syntax_errors_name_rule_and_field() {
        for (body, field) in [
            ("host_regex = \"(\"", "host_regex"),
            ("cidr = \"10.0.0.0/40\"", "cidr"),
            ("port = \"9-1\"", "port"),
            ("time = \"9:0-17:00\"", "time"),
            ("url_regex = \"[\"", "url_regex"),
            ("bypass = \"a:b\"", "bypass"),
        ] {
            let c = cfg(&format!(
                "[[routing.http.rules]]\n{body}\ntarget = \"direct\"\n"
            ));
            let msg = validate_config(&c).unwrap_err().to_string();
            assert!(msg.starts_with("[routing.http] rule #1"), "{msg}");
            assert!(msg.contains(&format!("`{field}`")), "{msg}");
        }
        let c = cfg("[profiles.p]\ntype = \"http\"\nhost = \"h\"\nport = 1\nbypass = [\"x:y\"]\n");
        assert!(validate_config(&c)
            .unwrap_err()
            .to_string()
            .starts_with("profile `p`: invalid `bypass`"));
    }

    #[test]
    fn url_rules_on_opaque_tunnels_produce_notices() {
        let c = cfg(r#"
            [[routing.rules]]
            name = "dl"
            url_wildcard = "http://dl.example/*"
            target = "direct"
            [[routing.rules]]
            keyword = "x"
            disabled = true
            target = "direct"
        "#);
        let notices = validate_config(&c).unwrap();
        assert_eq!(notices.len(), 2, "{notices:?}");
        assert!(notices[0].contains("[routing] URL rules (dl) never match SOCKS"));
        assert!(notices[1].contains("MITM is disabled"));
        assert_eq!(url_rule_notices(&c.routing, true).len(), 1);

        // SOCKS has its own table: unified URL rules only concern HTTP.
        let split = cfg(r#"
            [[routing.rules]]
            url_regex = "^http://"
            target = "direct"
            [routing.socks]
            default = "direct"
        "#);
        let n = url_rule_notices(&split.routing, false);
        assert_eq!(n.len(), 1);
        assert!(n[0].contains("[routing] rule #1") && n[0].contains("plain HTTP"));
        assert!(url_rule_notices(&split.routing, true).is_empty());

        let socks_url = cfg("[[routing.socks.rules]]\nkeyword = \"k\"\ntarget = \"direct\"\n");
        let n = url_rule_notices(&socks_url.routing, true);
        assert_eq!(n.len(), 1);
        assert!(n[0].starts_with("NOTICE: [routing.socks] URL rules"));
    }
}
