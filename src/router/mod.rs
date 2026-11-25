//! Auto Switch routing engine.
//!
//! A [`Router`] is compiled once from a validated [`Config`] (at startup and on every
//! hot-reload) and is immutable afterwards. Each connection (or decrypted MITM request)
//! builds a [`RouteRequest`] and calls [`Router::route`], which:
//!
//! 1. applies the global `[filter]` allow/block list (denials return [`AccessDenied`],
//!    logged as `status=denied_by_filter`);
//! 2. selects the rule table: `[routing.http]` / `[routing.socks]` when present for the
//!    inbound protocol, otherwise the unified `[routing]` table;
//! 3. evaluates rules strictly top to bottom (AND across fields, OR within a field), falling
//!    back to the table default;
//! 4. resolves each name of the target (single profile or failover chain) through composite
//!    per-scheme profiles and profile-level `bypass` lists.
//!
//! Split-table fallback order: the split table's rules; then, with `inherit = true`, the
//! unified `[routing]` rules; then the split table's `default` if set, else (`inherit`) the
//! unified default, else `direct`.

pub mod condition;
pub mod validate;

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;

use crate::config::{
    Config, Inbound, ProfileConfig, ProfileType, RuleConfig, Target, PROFILE_DIRECT,
};
use crate::filter::{AccessDenied, HostFilter};

pub use condition::{
    normalize_host, BypassList, Clock, FixedClock, LocalTime, MatchContext, Resolver, RuleMatcher,
    SystemClock, SystemResolver,
};
pub use validate::RouterError;

/// One routing query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRequest<'a> {
    pub inbound: Inbound,
    /// Hostname or IP literal (brackets and a trailing dot are tolerated).
    pub host: &'a str,
    pub port: u16,
    /// `Some("http")` / `Some("https")` when the scheme is known; selects the sub-target of
    /// composite profiles. Derived from `url` when absent.
    pub scheme: Option<&'a str>,
    /// Full URL when visible (plain HTTP or decrypted MITM HTTPS); URL rules need it.
    pub url: Option<&'a str>,
}

impl<'a> RouteRequest<'a> {
    /// A request without scheme or URL (SOCKS connection, opaque `CONNECT` tunnel).
    pub fn new(inbound: Inbound, host: &'a str, port: u16) -> Self {
        Self {
            inbound,
            host,
            port,
            scheme: None,
            url: None,
        }
    }
}

/// Which rule table produced a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    Unified,
    Http,
    Socks,
}

impl TableKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unified => "[routing]",
            Self::Http => "[routing.http]",
            Self::Socks => "[routing.socks]",
        }
    }
}

impl fmt::Display for TableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One element of a resolved failover chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// The profile name as written in the rule / default target.
    pub name: String,
    /// The concrete profile to dial (after composite resolution and bypass).
    pub profile: String,
    pub kind: ProfileType,
    /// The target matched a profile-level `bypass` list and resolves to `direct`.
    pub bypassed: bool,
}

impl ResolvedTarget {
    /// Label for `profile=` log fields: `corp`, `corp(bypass->direct)`, or `split->corp`.
    pub fn label(&self) -> String {
        if self.bypassed {
            format!("{}(bypass->direct)", self.name)
        } else if self.name != self.profile {
            format!("{}->{}", self.name, self.profile)
        } else {
            self.name.clone()
        }
    }
}

/// Label used for the `rule=` field when the table default applied.
pub const DEFAULT_RULE_LABEL: &str = "<default>";

/// The outcome of routing one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub table: TableKind,
    /// Name of the matched rule (`name`, or `<table> rule #N`); `None` = table default.
    pub rule: Option<String>,
    /// 0-based index of the matched rule within `table`.
    pub rule_index: Option<usize>,
    /// Ordered failover chain (never empty).
    pub targets: Vec<ResolvedTarget>,
    /// The table(s) consulted for this inbound protocol contain URL rules, so a MITM tunnel
    /// must re-route each decrypted request.
    pub has_url_rules: bool,
}

impl RouteDecision {
    /// `rule=` log value.
    pub fn rule_label(&self) -> &str {
        self.rule.as_deref().unwrap_or(DEFAULT_RULE_LABEL)
    }

    /// `profile=` log value of the first target.
    pub fn profile_label(&self) -> String {
        self.targets
            .first()
            .map(ResolvedTarget::label)
            .unwrap_or_default()
    }

    /// Comma-separated labels of the whole chain.
    pub fn chain_label(&self) -> String {
        self.targets
            .iter()
            .map(ResolvedTarget::label)
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    label: String,
    matcher: RuleMatcher,
    target: Vec<String>,
}

#[derive(Debug, Clone)]
struct Table {
    kind: TableKind,
    rules: Vec<CompiledRule>,
    default: Option<Vec<String>>,
    inherit: bool,
    has_url_rules: bool,
}

impl Table {
    fn compile(
        cfg: &Config,
        kind: TableKind,
        rules: &[RuleConfig],
        default: Option<&Target>,
        inherit: bool,
    ) -> Result<Self, RouterError> {
        let table = kind.as_str();
        if let Some(d) = default {
            validate::check_target(&cfg.profiles, &format!("{table}.default"), d)?;
        }
        let matchers =
            validate::compile_rules(&cfg.profiles, table, rules, cfg.routing.resolve_dns)?;
        let rules: Vec<CompiledRule> = rules
            .iter()
            .zip(matchers)
            .enumerate()
            .map(|(i, (r, matcher))| CompiledRule {
                label: r
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("{table} rule #{}", i + 1)),
                matcher,
                target: r.target.as_slice().to_vec(),
            })
            .collect();
        Ok(Self {
            kind,
            has_url_rules: rules.iter().any(|r| r.matcher.has_url_conditions()),
            rules,
            default: default.map(|d| d.as_slice().to_vec()),
            inherit,
        })
    }

    fn first_match(&self, ctx: &MatchContext<'_>) -> Option<(usize, &CompiledRule)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, r)| r.matcher.matches(ctx))
    }
}

/// The compiled, immutable routing engine.
#[derive(Debug, Clone)]
pub struct Router {
    unified: Table,
    http: Option<Table>,
    socks: Option<Table>,
    profiles: BTreeMap<String, ProfileConfig>,
    bypass: BTreeMap<String, BypassList>,
    filter: Option<HostFilter>,
    notices: Vec<String>,
}

impl Router {
    /// Compile and fully validate the routing configuration of `cfg`, checking self-loops
    /// against the listeners `cfg` itself enables.
    pub fn from_config(cfg: &Config) -> Result<Self, RouterError> {
        Self::from_config_with_listeners(cfg, &validate::configured_listeners(cfg))
    }

    /// Compile and validate against explicit active `listeners` (hot-reload).
    pub fn from_config_with_listeners(
        cfg: &Config,
        listeners: &[SocketAddr],
    ) -> Result<Self, RouterError> {
        let r = &cfg.routing;
        validate::check_composites(&cfg.profiles)?;
        validate::check_self_loop(&cfg.profiles, listeners)?;
        for (name, p) in &cfg.profiles {
            if !p.bypass.is_empty() && matches!(p.kind, ProfileType::Direct | ProfileType::Block) {
                return Err(RouterError::InvalidProfileBypass {
                    profile: name.clone(),
                    source: condition::ConditionError {
                        field: "bypass",
                        message: format!("is not supported on `{}` profiles", p.kind),
                    },
                });
            }
        }
        let bypass = validate::compile_profile_bypass(&cfg.profiles)?;
        let unified = Table::compile(cfg, TableKind::Unified, &r.rules, Some(&r.default), false)?;
        let split = |kind, t: &Option<crate::config::RoutingTableConfig>| {
            t.as_ref()
                .map(|t| Table::compile(cfg, kind, &t.rules, t.default.as_ref(), t.inherit))
                .transpose()
        };
        let http = split(TableKind::Http, &r.http)?;
        let socks = split(TableKind::Socks, &r.socks)?;
        Ok(Self {
            unified,
            http,
            socks,
            profiles: cfg.profiles_with_builtins(),
            bypass,
            filter: cfg.host_filter(),
            notices: validate::url_rule_notices(r, cfg.mitm_enabled()),
        })
    }

    /// `INFO` notices to log at startup / reload (URL rules on opaque tunnels).
    pub fn notices(&self) -> &[String] {
        &self.notices
    }

    /// A profile by name (built-ins included).
    pub fn profile(&self, name: &str) -> Option<&ProfileConfig> {
        self.profiles.get(name)
    }

    /// Number of profiles, built-ins included.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Total number of compiled rules across all tables.
    pub fn rule_count(&self) -> usize {
        self.unified.rules.len()
            + self.http.as_ref().map_or(0, |t| t.rules.len())
            + self.socks.as_ref().map_or(0, |t| t.rules.len())
    }

    /// Whether any table consulted for `inbound` traffic has URL rules.
    pub fn has_url_rules(&self, inbound: Inbound) -> bool {
        match self.split_for(inbound) {
            Some(t) => t.has_url_rules || (t.inherit && self.unified.has_url_rules),
            None => self.unified.has_url_rules,
        }
    }

    fn split_for(&self, inbound: Inbound) -> Option<&Table> {
        match inbound {
            Inbound::Http => self.http.as_ref(),
            Inbound::Socks => self.socks.as_ref(),
        }
    }

    /// Route with the system clock and (opt-in only) the OS resolver.
    pub fn route(&self, req: &RouteRequest<'_>) -> Result<RouteDecision, AccessDenied> {
        self.route_with(req, &SystemClock, &SystemResolver)
    }

    /// Route with an injected clock and resolver (deterministic tests, dry runs).
    pub fn route_with(
        &self,
        req: &RouteRequest<'_>,
        clock: &dyn Clock,
        resolver: &dyn Resolver,
    ) -> Result<RouteDecision, AccessDenied> {
        let host = normalize_host(req.host);
        if let Some(f) = &self.filter {
            f.check_host(&host)?;
        }
        let url_scheme = req
            .url
            .and_then(|u| u.split_once("://"))
            .map(|(s, _)| s.to_ascii_lowercase());
        let scheme = req.scheme.map(str::to_ascii_lowercase).or(url_scheme);
        let ctx = MatchContext::new(
            req.inbound,
            &host,
            req.port,
            scheme.as_deref(),
            req.url,
            clock,
            resolver,
        );

        let has_url_rules = self.has_url_rules(req.inbound);
        fn hit<'t>(
            t: &'t Table,
            ctx: &MatchContext<'_>,
        ) -> Option<(TableKind, usize, &'t CompiledRule)> {
            t.first_match(ctx).map(|(i, r)| (t.kind, i, r))
        }
        let (table, matched, default) = match self.split_for(req.inbound) {
            Some(t) => {
                let matched =
                    hit(t, &ctx).or_else(|| t.inherit.then(|| hit(&self.unified, &ctx)).flatten());
                let default = match (&t.default, t.inherit) {
                    (Some(d), _) => d.clone(),
                    (None, true) => self.unified.default.clone().unwrap_or_default(),
                    (None, false) => vec![PROFILE_DIRECT.to_string()],
                };
                (t.kind, matched, default)
            }
            None => (
                TableKind::Unified,
                hit(&self.unified, &ctx),
                self.unified.default.clone().unwrap_or_default(),
            ),
        };

        let (table, rule, rule_index, names) = match matched {
            Some((kind, i, r)) => (kind, Some(r.label.clone()), Some(i), r.target.clone()),
            None => (table, None, None, default),
        };
        let names = if names.is_empty() {
            vec![PROFILE_DIRECT.to_string()]
        } else {
            names
        };
        Ok(RouteDecision {
            table,
            rule,
            rule_index,
            targets: names.iter().map(|n| self.resolve_target(n, &ctx)).collect(),
            has_url_rules,
        })
    }

    /// Resolve a chain element through profile-level bypass and composite profiles.
    fn resolve_target(&self, name: &str, ctx: &MatchContext<'_>) -> ResolvedTarget {
        let direct = |bypassed| ResolvedTarget {
            name: name.to_string(),
            profile: PROFILE_DIRECT.to_string(),
            kind: ProfileType::Direct,
            bypassed,
        };
        let mut current = name.to_string();
        // Validation rejects composite cycles; the bound is a belt-and-braces guard.
        for _ in 0..=self.profiles.len() {
            if self.bypass.get(&current).is_some_and(|b| b.matches(ctx)) {
                return direct(true);
            }
            let Some(p) = self.profiles.get(&current) else {
                return direct(false);
            };
            if p.kind != ProfileType::Composite {
                return ResolvedTarget {
                    name: name.to_string(),
                    profile: current,
                    kind: p.kind,
                    bypassed: false,
                };
            }
            // AirSwitch FixedProfile: per-scheme proxy, else fallback, else DIRECT.
            let sub = match ctx.scheme {
                Some("http") => p.http_proxy.as_ref(),
                Some("https") => p.https_proxy.as_ref(),
                _ => None,
            }
            .or(p.fallback_proxy.as_ref());
            match sub {
                Some(s) => current = s.clone(),
                None => return direct(false),
            }
        }
        direct(false)
    }
}

// ---------------------------------------------------------------------------
// test-route target parsing
// ---------------------------------------------------------------------------

/// A `test-route` target: `HOST`, `HOST:PORT`, `[V6]:PORT`, bare IPv6, or a full URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTarget {
    pub host: String,
    pub port: u16,
    /// Lowercase scheme for URL targets.
    pub scheme: Option<String>,
    /// The URL as given, for URL targets.
    pub url: Option<String>,
}

/// Default port for a `HOST` target without `:PORT`.
pub const DEFAULT_TARGET_PORT: u16 = 80;

impl ParsedTarget {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("empty target".into());
        }
        if let Some((scheme, rest)) = raw.split_once("://") {
            let scheme = scheme.to_ascii_lowercase();
            let default_port = match scheme.as_str() {
                "http" => 80,
                "https" => 443,
                other => {
                    return Err(format!(
                        "unsupported URL scheme {other:?} (use http or https)"
                    ))
                }
            };
            let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
            let authority = authority.rsplit('@').next().unwrap_or(authority);
            let (host, port) = split_host_port(authority, default_port)?;
            return Ok(Self {
                host,
                port,
                scheme: Some(scheme),
                url: Some(raw.to_string()),
            });
        }
        let (host, port) = split_host_port(raw, DEFAULT_TARGET_PORT)?;
        Ok(Self {
            host,
            port,
            scheme: None,
            url: None,
        })
    }
}

fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    let parse_port = |p: &str| {
        p.parse::<u16>()
            .map_err(|_| format!("invalid port {p:?} in target {s:?}"))
    };
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated `[` in target {s:?}"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => parse_port(p)?,
            None if after.is_empty() => default_port,
            None => return Err(format!("unexpected {after:?} after `]` in target {s:?}")),
        };
        (h.to_string(), port)
    } else if s.matches(':').count() > 1 {
        // Bare IPv6 literal without a port.
        (s.to_string(), default_port)
    } else if let Some((h, p)) = s.rsplit_once(':') {
        (h.to_string(), parse_port(p)?)
    } else {
        (s.to_string(), default_port)
    };
    if host.is_empty() {
        return Err(format!("target {s:?} has no host"));
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CliInput, FileConfig};
    use std::path::Path;

    fn router(text: &str) -> Router {
        let file = FileConfig::from_toml_str(text, Path::new("t.toml")).unwrap();
        let cfg = Config::merge(CliInput::default(), Some(file)).unwrap();
        Router::from_config(&cfg).unwrap()
    }

    const NOON: FixedClock = FixedClock(LocalTime {
        weekday: 0,
        minute_of_day: 720,
    });

    fn route(r: &Router, inbound: Inbound, host: &str, port: u16) -> RouteDecision {
        r.route_with(
            &RouteRequest::new(inbound, host, port),
            &NOON,
            &SystemResolver,
        )
        .unwrap()
    }

    const PROFILES: &str = r#"
        [profiles.corp]
        type = "http"
        host = "10.0.0.2"
        port = 3128
        bypass = ["127.0.0.1", "*.local"]
        [profiles.bastion]
        type = "socks5"
        host = "127.0.0.1"
        port = 1081
        [profiles.secure]
        type = "https"
        host = "proxy.example"
        port = 8443
    "#;

    #[test]
    fn unified_top_to_bottom_with_default() {
        let r = router(&format!(
            "{PROFILES}
            [routing]
            default = [\"corp\", \"direct\"]
            [[routing.rules]]
            name = \"first\"
            host_wildcard = \"*.example.com\"
            target = \"bastion\"
            [[routing.rules]]
            name = \"second\"
            host = \"www.example.com\"
            target = \"block\"
            "
        ));
        let d = route(&r, Inbound::Http, "www.example.com", 443);
        assert_eq!(d.table, TableKind::Unified);
        assert_eq!(d.rule_label(), "first");
        assert_eq!(d.rule_index, Some(0));
        assert_eq!(d.profile_label(), "bastion");
        let d = route(&r, Inbound::Socks, "other.test", 22);
        assert_eq!(d.rule_label(), "<default>");
        assert_eq!(d.chain_label(), "corp,direct");
        assert!(!d.has_url_rules);
        assert_eq!(r.rule_count(), 2);
        assert_eq!(r.profile_count(), 5);
    }

    #[test]
    fn split_tables_with_and_without_inherit() {
        let base = format!(
            "{PROFILES}
            [routing]
            default = \"corp\"
            [[routing.rules]]
            name = \"unified-db\"
            host = \"db.internal\"
            target = \"bastion\"
            "
        );
        let r = router(&format!(
            "{base}
            [routing.socks]
            default = \"secure\"
            [[routing.socks.rules]]
            name = \"socks-local\"
            host_wildcard = \"*.local\"
            target = \"direct\"
            "
        ));
        let d = route(&r, Inbound::Socks, "nas.local", 445);
        assert_eq!((d.table, d.rule_label()), (TableKind::Socks, "socks-local"));
        // No inherit: unified rules are not consulted for SOCKS.
        let d = route(&r, Inbound::Socks, "db.internal", 5432);
        assert_eq!((d.table, d.rule_label()), (TableKind::Socks, "<default>"));
        assert_eq!(d.profile_label(), "secure");
        // HTTP has no split table: unified.
        let d = route(&r, Inbound::Http, "db.internal", 443);
        assert_eq!(
            (d.table, d.profile_label().as_str()),
            (TableKind::Unified, "bastion")
        );

        let r = router(&format!(
            "{base}
            [routing.http]
            inherit = true
            [[routing.http.rules]]
            name = \"http-only\"
            port = 80
            target = \"block\"
            "
        ));
        let d = route(&r, Inbound::Http, "db.internal", 80);
        assert_eq!(d.rule_label(), "http-only");
        let d = route(&r, Inbound::Http, "db.internal", 443);
        assert_eq!(
            (d.table, d.rule_label()),
            (TableKind::Unified, "unified-db")
        );
        let d = route(&r, Inbound::Http, "x.test", 443);
        assert_eq!(
            (d.table, d.profile_label().as_str()),
            (TableKind::Http, "corp")
        );

        // Split table without default and without inherit falls back to direct.
        let r = router(&format!("{base}\n[routing.http]\n"));
        assert_eq!(
            route(&r, Inbound::Http, "x.test", 443).profile_label(),
            "direct"
        );
    }

    #[test]
    fn profile_bypass_and_composites() {
        let r = router(&format!(
            "{PROFILES}
            [profiles.split]
            type = \"composite\"
            http_proxy = \"corp\"
            https_proxy = \"secure\"
            [profiles.fb]
            type = \"composite\"
            fallback_proxy = \"bastion\"
            bypass = [\"<local>\"]
            [routing]
            default = [\"corp\", \"split\", \"fb\"]
            "
        ));
        let d = route(&r, Inbound::Http, "printer.local", 631);
        assert_eq!(d.targets[0].label(), "corp(bypass->direct)");
        assert_eq!(d.targets[0].kind, ProfileType::Direct);
        assert!(d.targets[0].bypassed);
        // No scheme: composite without fallback goes direct; fb uses its fallback.
        assert_eq!(d.targets[1].profile, "direct");
        assert_eq!(d.targets[2].label(), "fb->bastion");

        let req = RouteRequest {
            scheme: None,
            url: Some("http://site.example/x"),
            ..RouteRequest::new(Inbound::Http, "site.example", 80)
        };
        let d = r.route_with(&req, &NOON, &SystemResolver).unwrap();
        assert_eq!(d.targets[1].label(), "split->corp");
        let req = RouteRequest {
            scheme: Some("HTTPS"),
            ..RouteRequest::new(Inbound::Http, "site.example", 443)
        };
        let d = r.route_with(&req, &NOON, &SystemResolver).unwrap();
        assert_eq!(d.targets[1].label(), "split->secure");
        // fb's own bypass list: dot-less host.
        let d = route(&r, Inbound::Socks, "intranet", 80);
        assert_eq!(d.targets[2].label(), "fb(bypass->direct)");
    }

    #[test]
    fn global_filter_runs_first() {
        let r = router("[filter]\nblock = [\"*.ads.example\"]\n");
        let e = r
            .route_with(
                &RouteRequest::new(Inbound::Http, "x.ads.example", 443),
                &NOON,
                &SystemResolver,
            )
            .unwrap_err();
        assert!(e.0.contains("blocklisted"));
        assert!(r
            .route_with(
                &RouteRequest::new(Inbound::Http, "ok.example", 443),
                &NOON,
                &SystemResolver
            )
            .is_ok());
    }

    #[test]
    fn has_url_rules_follows_active_tables() {
        let r = router(
            "[[routing.rules]]\nkeyword = \"k\"\ntarget = \"direct\"\n\
             [routing.socks]\n[routing.http]\ninherit = true\n",
        );
        assert!(r.has_url_rules(Inbound::Http));
        assert!(!r.has_url_rules(Inbound::Socks));
        assert!(route(&r, Inbound::Http, "h", 1).has_url_rules);
    }

    #[test]
    fn invalid_bypass_on_builtin_kinds() {
        let file = FileConfig::from_toml_str(
            "[profiles.direct]\ntype = \"direct\"\nbypass = [\"x\"]\n",
            Path::new("t.toml"),
        )
        .unwrap();
        let cfg = Config::merge(CliInput::default(), Some(file)).unwrap();
        assert!(Router::from_config(&cfg)
            .unwrap_err()
            .to_string()
            .contains("not supported on `direct`"));
    }

    #[test]
    fn parse_targets() {
        let t = |s: &str| ParsedTarget::parse(s).unwrap();
        assert_eq!((t("db:5432").host, t("db:5432").port), ("db".into(), 5432));
        assert_eq!(t("example.com").port, DEFAULT_TARGET_PORT);
        assert_eq!(t("[::1]:22").host, "::1");
        assert_eq!(t("[::1]:22").port, 22);
        assert_eq!(t("fd00::1").host, "fd00::1");
        let u = t("https://user@API.example:8443/v1?q#f");
        assert_eq!(
            (u.host.as_str(), u.port, u.scheme.as_deref()),
            ("API.example", 8443, Some("https"))
        );
        assert_eq!(t("http://h/").port, 80);
        assert_eq!(t("https://[fd00::2]/").host, "fd00::2");
        assert!(ParsedTarget::parse("ftp://h").is_err());
        assert!(ParsedTarget::parse("h:99999").is_err());
        assert!(ParsedTarget::parse("").is_err());
        assert!(ParsedTarget::parse(":80").is_err());
    }
}
