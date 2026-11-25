//! AirSwitch / ZeroOmega / SwitchyOmega `.bak` JSON parser and mapper.
//!
//! A `.bak` file is the options object exported by the browser extension: every key that
//! starts with `+` is a profile (`"+Work Proxy": { "profileType": "FixedProfile", ... }`),
//! and `-startupProfileName` names the profile that was active. Legacy backups may be
//! base64-encoded JSON; both forms are accepted.
//!
//! [`convert`] maps that model onto `rusty-conduit-switch` profiles and one `[routing]`
//! table:
//!
//! - `DirectProfile` → built-in `direct`; `SystemProfile` → `direct` with a warning.
//! - `FixedProfile` → a `[profiles.<slug>]` proxy (`http`, `https`, `socks5`, `socks4a`)
//!   with credentials and `bypass`, or a `composite` profile with per-scheme sub-profiles
//!   when `proxyForHttp` / `proxyForHttps` differ from `fallbackProxy`.
//! - The selected `SwitchProfile` becomes `[routing]`. Rules that point at another
//!   `SwitchProfile`, `VirtualProfile`, or inline rule list are flattened in evaluation
//!   order (nested conditions are ANDed into the outer rule) with cycle detection.
//! - `SwitchyRuleListProfile` / `AutoProxyRuleListProfile` inline `ruleList` text is parsed;
//!   remote `sourceUrl`s are never fetched.
//! - `PacProfile` / `AutoDetectProfile` are skipped with a warning.
//!
//! Anything that cannot be represented faithfully is kept as a commented-out rule with
//! the reason, and reported in [`Imported::warnings`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::Engine;
use serde_json::{json, Map, Value};

use crate::config::{
    HostLevels, OneOrMany, ProfileConfig, ProfileType, RuleConfig, PROFILE_BLOCK, PROFILE_DIRECT,
};
use crate::router::{BypassList, RuleMatcher};

/// Comment attached to every URL-level rule (`url_wildcard`, `url_regex`, `keyword`).
pub const URL_RULE_NOTE: &str =
    "URL rule: only matches plain HTTP or MITM-decrypted HTTPS (never SOCKS or opaque CONNECT)";

/// Errors that stop an import (everything else is a warning).
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("not an AirSwitch backup: {0}")]
    Parse(String),
    #[error("not an AirSwitch backup: the top-level JSON value must be an object")]
    NotObject,
    #[error("SwitchProfile {name:?} not found; available SwitchProfiles: {}", list(.available))]
    ProfileNotFound {
        name: String,
        available: Vec<String>,
    },
    #[error(
        "profile {name:?} is a {kind}, not a SwitchProfile; available SwitchProfiles: {}",
        list(.available)
    )]
    NotSwitchProfile {
        name: String,
        kind: String,
        available: Vec<String>,
    },
    #[error(
        "the backup has several SwitchProfiles and none is the startup profile; \
         choose one with --profile: {}",
        list(.available)
    )]
    AmbiguousSwitch { available: Vec<String> },
    #[error("SwitchProfile cycle detected: {}", .cycle.join(" -> "))]
    Cycle { cycle: Vec<String> },
}

fn list(names: &[String]) -> String {
    if names.is_empty() {
        "(none)".to_string()
    } else {
        names
            .iter()
            .map(|n| format!("{n:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Import options.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    /// SwitchProfile to import as `[routing]` (`--profile`).
    pub profile: Option<String>,
}

/// One emitted `[profiles.<key>]` table.
#[derive(Debug, Clone)]
pub struct ImportedProfile {
    /// TOML key (slug).
    pub key: String,
    /// Comment lines written above the table.
    pub comments: Vec<String>,
    pub config: ProfileConfig,
}

/// One emitted `[[routing.rules]]` entry.
#[derive(Debug, Clone)]
pub struct ImportedRule {
    pub rule: RuleConfig,
    /// Comment lines written above the rule.
    pub comments: Vec<String>,
    /// `Some(reason)`: the rule cannot be represented and is written commented out.
    pub skipped: Option<String>,
}

/// The result of an import, ready to be rendered as TOML.
#[derive(Debug, Clone, Default)]
pub struct Imported {
    pub profiles: Vec<ImportedProfile>,
    pub rules: Vec<ImportedRule>,
    /// `[routing].default` failover chain.
    pub default: Vec<String>,
    /// AirSwitch name of the SwitchProfile imported as `[routing]`, if any.
    pub switch_profile: Option<String>,
    pub warnings: Vec<String>,
}

impl Imported {
    /// Number of active (not commented-out) rules.
    pub fn active_rule_count(&self) -> usize {
        self.rules.iter().filter(|r| r.skipped.is_none()).count()
    }
}

/// Deterministic TOML-safe slug: lowercase ASCII alphanumerics joined by `_`
/// (`"Work Proxy"` → `work_proxy`). Names with no ASCII alphanumerics become `profile`.
pub fn slugify(name: &str) -> String {
    let mut out = String::new();
    let mut sep = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if sep && !out.is_empty() {
                out.push('_');
            }
            sep = false;
            out.push(c.to_ascii_lowercase());
        } else {
            sep = true;
        }
    }
    if out.is_empty() {
        "profile".to_string()
    } else {
        out
    }
}

/// Parse the `.bak` text (JSON, or base64-encoded JSON) into the options object.
pub fn parse_options(text: &str) -> Result<Map<String, Value>, ImportError> {
    let text = text.trim().trim_start_matches('\u{feff}').trim();
    let value: Value = if text.starts_with('{') {
        serde_json::from_str(text).map_err(|e| ImportError::Parse(format!("invalid JSON: {e}")))?
    } else {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|_| ImportError::Parse("neither JSON nor base64-encoded JSON".into()))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| ImportError::Parse(format!("invalid base64-encoded JSON: {e}")))?
    };
    match value {
        Value::Object(m) => Ok(m),
        _ => Err(ImportError::NotObject),
    }
}

/// Convert `.bak` text into an [`Imported`] configuration.
pub fn convert(text: &str, opts: &ImportOptions) -> Result<Imported, ImportError> {
    let options = parse_options(text)?;
    Converter::new(&options).run(&options, opts)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Direct,
    System,
    Fixed,
    Switch,
    Virtual,
    RuleList,
    Pac,
    Other,
}

impl Kind {
    fn of(type_name: &str) -> Self {
        match type_name {
            "DirectProfile" => Self::Direct,
            "SystemProfile" => Self::System,
            "FixedProfile" => Self::Fixed,
            "SwitchProfile" => Self::Switch,
            "VirtualProfile" => Self::Virtual,
            "RuleListProfile" | "SwitchyRuleListProfile" | "AutoProxyRuleListProfile" => {
                Self::RuleList
            }
            "PacProfile" | "AutoDetectProfile" => Self::Pac,
            _ => Self::Other,
        }
    }

    /// Profiles whose rules are flattened into the routing table.
    fn is_nested(self) -> bool {
        matches!(self, Self::Switch | Self::Virtual | Self::RuleList)
    }
}

struct Source<'a> {
    kind: Kind,
    type_name: String,
    value: &'a Value,
}

/// What a profile reference resolves to.
enum Ref {
    /// A concrete target profile (TOML key).
    Leaf(String),
    /// A profile whose rules are flattened.
    Nested(String),
    /// Cannot be represented; reason.
    Unsupported(String),
}

#[derive(Clone)]
enum Leaf {
    Target(String),
    Unsupported(String),
}

/// A mapped condition: a rule with every matcher set and a placeholder target.
#[derive(Clone)]
struct Cond {
    rule: RuleConfig,
    comments: Vec<String>,
}

type CondResult = Result<Cond, String>;

/// A rule as read from a SwitchProfile or rule list, before target resolution.
struct RawRule {
    cond: CondResult,
    profile: String,
    label: String,
    comments: Vec<String>,
}

/// A flattened rule: condition plus resolved target chain.
struct FlatRule {
    cond: CondResult,
    target: Vec<String>,
    label: String,
    comments: Vec<String>,
    unsupported: Option<String>,
}

#[derive(Default)]
struct Warnings(Vec<String>);

impl Warnings {
    fn push(&mut self, w: impl Into<String>) {
        let w = w.into();
        if !self.0.contains(&w) {
            self.0.push(w);
        }
    }
}

#[derive(Default)]
struct SlugAllocator(BTreeSet<String>);

impl SlugAllocator {
    fn new() -> Self {
        Self(
            [PROFILE_DIRECT, PROFILE_BLOCK]
                .into_iter()
                .map(str::to_string)
                .collect(),
        )
    }

    fn alloc(&mut self, base: &str) -> String {
        if self.0.insert(base.to_string()) {
            return base.to_string();
        }
        let mut n = 2;
        loop {
            let candidate = format!("{base}_{n}");
            if self.0.insert(candidate.clone()) {
                return candidate;
            }
            n += 1;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Proxy {
    scheme: String,
    host: String,
    port: u16,
}

struct Converter<'a> {
    profiles: BTreeMap<String, Source<'a>>,
    leaves: BTreeMap<String, Leaf>,
    out_profiles: Vec<ImportedProfile>,
    slugs: SlugAllocator,
    warnings: Warnings,
}

fn empty_rule() -> RuleConfig {
    RuleConfig {
        name: None,
        inbound: None,
        host: None,
        host_wildcard: None,
        host_regex: None,
        cidr: None,
        ip: None,
        port: None,
        host_levels: None,
        bypass: None,
        weekday: None,
        time: None,
        url_wildcard: None,
        url_regex: None,
        keyword: None,
        match_all: false,
        disabled: false,
        resolve_dns: None,
        target: OneOrMany::One(PROFILE_DIRECT.to_string()),
    }
}

fn str_field<'v>(v: &'v Value, key: &str) -> Option<&'v str> {
    v.get(key).and_then(Value::as_str)
}

/// An integer field written as a JSON number or a numeric string.
fn int_field(v: &Value, key: &str) -> Option<i64> {
    match v.get(key)? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

impl<'a> Converter<'a> {
    fn new(options: &'a Map<String, Value>) -> Self {
        let mut profiles = BTreeMap::new();
        for (key, value) in options {
            let Some(key_name) = key.strip_prefix('+') else {
                continue;
            };
            if !value.is_object() {
                continue;
            }
            let name = str_field(value, "name").unwrap_or(key_name).to_string();
            let type_name = str_field(value, "profileType").unwrap_or("").to_string();
            profiles.insert(
                name,
                Source {
                    kind: Kind::of(&type_name),
                    type_name,
                    value,
                },
            );
        }
        static DIRECT: Value = Value::Null;
        for (name, type_name) in [("direct", "DirectProfile"), ("system", "SystemProfile")] {
            profiles.entry(name.to_string()).or_insert(Source {
                kind: Kind::of(type_name),
                type_name: type_name.to_string(),
                value: &DIRECT,
            });
        }
        Self {
            profiles,
            leaves: BTreeMap::new(),
            out_profiles: Vec::new(),
            slugs: SlugAllocator::new(),
            warnings: Warnings::default(),
        }
    }

    fn run(
        mut self,
        options: &Map<String, Value>,
        opts: &ImportOptions,
    ) -> Result<Imported, ImportError> {
        // Report profile types that cannot be imported at all.
        for (name, src) in &self.profiles {
            match src.kind {
                Kind::Pac => self.warnings.push(format!(
                    "profile {name:?} ({}): JavaScript PAC scripts are not executed; \
                     skipped — convert rules manually",
                    src.type_name
                )),
                Kind::Other => self.warnings.push(format!(
                    "profile {name:?} has unsupported profileType {:?}; skipped",
                    src.type_name
                )),
                _ => {}
            }
        }

        // FixedProfiles: allocate every main slug first (name order), then convert.
        let fixed: Vec<String> = self
            .profiles
            .iter()
            .filter(|(_, s)| s.kind == Kind::Fixed)
            .map(|(n, _)| n.clone())
            .collect();
        let main_slugs: Vec<String> = fixed
            .iter()
            .map(|n| self.slugs.alloc(&slugify(n)))
            .collect();
        for (name, slug) in fixed.iter().zip(main_slugs) {
            let value = self.profiles[name].value;
            let leaf = self.convert_fixed(name, value, &slug);
            self.leaves.insert(name.clone(), leaf);
        }

        let switch = self.select_switch(options, opts)?;
        let (flat, default) = match &switch {
            Some(name) => {
                let mut stack = vec![name.clone()];
                self.flatten(name, &mut stack)?
            }
            None => {
                let startup = options
                    .get("-startupProfileName")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let default = match self.resolve_ref(&startup) {
                    Ref::Leaf(t) if !startup.is_empty() => vec![t],
                    _ => vec![PROFILE_DIRECT.to_string()],
                };
                self.warnings.push(format!(
                    "the backup has no SwitchProfile; [routing] has no rules and defaults to {:?}",
                    default.join(", ")
                ));
                (Vec::new(), default)
            }
        };

        let mut rules = Vec::new();
        let mut url_rules = 0;
        for f in flat {
            let mut comments = f.comments;
            let (mut rule, skipped) = match (f.cond, f.unsupported) {
                (_, Some(reason)) => (empty_rule(), Some(reason)),
                (Err(reason), None) => (empty_rule(), Some(reason)),
                (Ok(c), None) => {
                    comments.extend(c.comments);
                    (c.rule, None)
                }
            };
            rule.name = Some(f.label.clone());
            rule.target = if f.target.len() == 1 {
                OneOrMany::One(f.target[0].clone())
            } else {
                OneOrMany::Many(f.target)
            };
            let skipped = skipped.or_else(|| {
                RuleMatcher::compile(&rule, false)
                    .err()
                    .map(|e| e.to_string())
            });
            match &skipped {
                Some(reason) => self.warnings.push(format!(
                    "rule {:?} cannot be imported ({reason}); written commented out",
                    f.label
                )),
                None => {
                    if rule.url_wildcard.is_some()
                        || rule.url_regex.is_some()
                        || rule.keyword.is_some()
                    {
                        url_rules += 1;
                    }
                }
            }
            dedup(&mut comments);
            rules.push(ImportedRule {
                rule,
                comments,
                skipped,
            });
        }
        if url_rules > 0 {
            self.warnings.push(format!(
                "{url_rules} URL rule(s) (url_wildcard/url_regex/keyword) only match plain HTTP \
                 or MITM-decrypted HTTPS; they never match SOCKS or opaque HTTPS CONNECT tunnels"
            ));
        }

        Ok(Imported {
            profiles: self.out_profiles,
            rules,
            default,
            switch_profile: switch,
            warnings: self.warnings.0,
        })
    }

    // -- profile selection --------------------------------------------------

    fn switch_names(&self) -> Vec<String> {
        self.profiles
            .iter()
            .filter(|(_, s)| s.kind == Kind::Switch)
            .map(|(n, _)| n.clone())
            .collect()
    }

    fn select_switch(
        &self,
        options: &Map<String, Value>,
        opts: &ImportOptions,
    ) -> Result<Option<String>, ImportError> {
        let available = self.switch_names();
        if let Some(name) = &opts.profile {
            return match self.profiles.get(name) {
                None => Err(ImportError::ProfileNotFound {
                    name: name.clone(),
                    available,
                }),
                Some(s) if s.kind.is_nested() => Ok(Some(name.clone())),
                Some(s) => Err(ImportError::NotSwitchProfile {
                    name: name.clone(),
                    kind: if s.type_name.is_empty() {
                        "profile without profileType".into()
                    } else {
                        s.type_name.clone()
                    },
                    available,
                }),
            };
        }
        let startup = options
            .get("-startupProfileName")
            .and_then(Value::as_str)
            .unwrap_or("");
        if self
            .profiles
            .get(startup)
            .is_some_and(|s| s.kind.is_nested())
        {
            return Ok(Some(startup.to_string()));
        }
        match available.len() {
            0 => Ok(None),
            1 => Ok(available.into_iter().next()),
            _ => Err(ImportError::AmbiguousSwitch { available }),
        }
    }

    // -- FixedProfile ---------------------------------------------------------

    fn proxy_of(&mut self, profile: &str, v: &Value, prop: &str) -> Option<Proxy> {
        let p = v.get(prop)?;
        if p.is_null() {
            return None;
        }
        let host = str_field(p, "host").map(str::trim).unwrap_or("");
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let port = int_field(p, "port").and_then(|n| u16::try_from(n).ok());
        match (host.is_empty(), port) {
            (false, Some(port)) if port > 0 => Some(Proxy {
                scheme: str_field(p, "scheme")
                    .unwrap_or("http")
                    .to_ascii_lowercase(),
                host: host.to_string(),
                port,
            }),
            _ => {
                self.warnings.push(format!(
                    "profile {profile:?}: {prop} has no valid host/port; ignored"
                ));
                None
            }
        }
    }

    fn proxy_profile(
        &mut self,
        profile: &str,
        v: &Value,
        proxy: &Proxy,
        auth_prop: &str,
    ) -> Result<(ProfileConfig, bool), String> {
        let kind = match proxy.scheme.as_str() {
            "http" => ProfileType::Http,
            "https" => ProfileType::Https,
            "socks5" => ProfileType::Socks5,
            "socks4" | "socks4a" => {
                if proxy.scheme == "socks4" {
                    self.warnings.push(format!(
                        "profile {profile:?}: SOCKS4 proxy imported as socks4a (remote DNS); \
                         the upstream server must support SOCKS4a"
                    ));
                }
                ProfileType::Socks4a
            }
            other => {
                return Err(format!(
                    "profile {profile:?} uses unsupported proxy scheme {other:?}"
                ))
            }
        };
        let mut cfg = ProfileConfig::of_kind(kind);
        cfg.host = Some(proxy.host.clone());
        cfg.port = Some(proxy.port);
        let auth = v.get("auth");
        let creds = auth
            .and_then(|a| a.get(auth_prop))
            .filter(|c| c.is_object())
            .or_else(|| auth.and_then(|a| a.get("all")).filter(|c| c.is_object()));
        let mut has_password = false;
        if let Some(c) = creds {
            if let Some(user) = str_field(c, "username").filter(|u| !u.is_empty()) {
                cfg.username = Some(user.to_string());
                if let Some(pass) = str_field(c, "password").filter(|p| !p.is_empty()) {
                    cfg.password = Some(pass.to_string());
                    has_password = true;
                }
            }
        }
        Ok((cfg, has_password))
    }

    fn convert_fixed(&mut self, name: &str, v: &Value, slug: &str) -> Leaf {
        let header = format!("Imported from AirSwitch profile {name:?}");
        let fallback = self.proxy_of(name, v, "fallbackProxy");
        let http = self.proxy_of(name, v, "proxyForHttp");
        let https = self.proxy_of(name, v, "proxyForHttps");
        if v.get("proxyForFtp").is_some_and(|p| !p.is_null()) {
            self.warnings.push(format!(
                "profile {name:?}: proxyForFtp is ignored (FTP is not proxied)"
            ));
        }

        let mut bypass = Vec::new();
        if let Some(list) = v.get("bypassList").and_then(Value::as_array) {
            for c in list {
                let pattern = str_field(c, "pattern").map(str::trim).unwrap_or("");
                let ty = str_field(c, "conditionType").unwrap_or("");
                if ty != "BypassCondition" || pattern.is_empty() {
                    self.warnings.push(format!(
                        "profile {name:?}: bypassList entry {ty:?} {pattern:?} is not a \
                         BypassCondition pattern; ignored"
                    ));
                    continue;
                }
                match BypassList::compile(&[pattern.to_string()]) {
                    Ok(_) => bypass.push(pattern.to_string()),
                    Err(e) => self.warnings.push(format!(
                        "profile {name:?}: bypassList entry {pattern:?} ignored ({e})"
                    )),
                }
            }
        }

        let per_http = http.filter(|p| Some(p) != fallback.as_ref());
        let per_https = https.filter(|p| Some(p) != fallback.as_ref());

        let password_note = |w: &mut Warnings| {
            w.push(format!(
                "profile {name:?}: password imported in plaintext from the backup; \
                 consider password_env or password_file"
            ));
        };
        const PLAINTEXT: &str =
            "Password imported in plaintext; prefer password_env or password_file";

        if per_http.is_none() && per_https.is_none() {
            let Some(proxy) = fallback else {
                self.warnings.push(format!(
                    "profile {name:?} has no proxy server configured; mapped to \"direct\""
                ));
                return Leaf::Target(PROFILE_DIRECT.to_string());
            };
            return match self.proxy_profile(name, v, &proxy, "fallbackProxy") {
                Ok((mut cfg, has_password)) => {
                    cfg.bypass = bypass;
                    let mut comments = vec![header];
                    if has_password {
                        comments.push(PLAINTEXT.to_string());
                        password_note(&mut self.warnings);
                    }
                    self.out_profiles.push(ImportedProfile {
                        key: slug.to_string(),
                        comments,
                        config: cfg,
                    });
                    Leaf::Target(slug.to_string())
                }
                Err(reason) => {
                    self.warnings.push(format!("{reason}; profile skipped"));
                    Leaf::Unsupported(reason)
                }
            };
        }

        // Per-scheme proxies: a composite profile over sub-profiles.
        let mut composite = ProfileConfig::of_kind(ProfileType::Composite);
        composite.bypass = bypass;
        let mut subs = Vec::new();
        let mut any_password = false;
        for (part, proxy, prop) in [
            ("http", per_http, "proxyForHttp"),
            ("https", per_https, "proxyForHttps"),
            ("fallback", fallback, "fallbackProxy"),
        ] {
            let Some(proxy) = proxy else { continue };
            match self.proxy_profile(name, v, &proxy, prop) {
                Ok((cfg, has_password)) => {
                    let key = self.slugs.alloc(&format!("{slug}_{part}"));
                    let mut comments = vec![format!(
                        "{part} proxy of AirSwitch profile {name:?} (used by [profiles.{slug}])"
                    )];
                    if has_password {
                        comments.push(PLAINTEXT.to_string());
                        any_password = true;
                    }
                    match part {
                        "http" => composite.http_proxy = Some(key.clone()),
                        "https" => composite.https_proxy = Some(key.clone()),
                        _ => composite.fallback_proxy = Some(key.clone()),
                    }
                    subs.push(ImportedProfile {
                        key,
                        comments,
                        config: cfg,
                    });
                }
                Err(reason) => self
                    .warnings
                    .push(format!("{reason}; {part} proxy skipped")),
            }
        }
        if any_password {
            password_note(&mut self.warnings);
        }
        if subs.is_empty() {
            self.warnings.push(format!(
                "profile {name:?} has no usable proxy server; mapped to \"direct\""
            ));
            return Leaf::Target(PROFILE_DIRECT.to_string());
        }
        let mut comments = vec![header];
        comments.push(
            "Per-scheme proxies: http_proxy for http://, https_proxy for https://, \
             fallback_proxy otherwise (none = direct)"
                .to_string(),
        );
        self.out_profiles.push(ImportedProfile {
            key: slug.to_string(),
            comments,
            config: composite,
        });
        self.out_profiles.extend(subs);
        Leaf::Target(slug.to_string())
    }

    // -- references & flattening ----------------------------------------------

    fn resolve_ref(&mut self, name: &str) -> Ref {
        let Some(src) = self.profiles.get(name) else {
            return Ref::Unsupported(format!("references unknown profile {name:?}"));
        };
        match src.kind {
            Kind::Direct => Ref::Leaf(PROFILE_DIRECT.to_string()),
            Kind::System => {
                self.warnings.push(
                    "SystemProfile has no server-side equivalent; mapped to \"direct\"".to_string(),
                );
                Ref::Leaf(PROFILE_DIRECT.to_string())
            }
            Kind::Fixed => match self.leaves.get(name) {
                Some(Leaf::Target(t)) => Ref::Leaf(t.clone()),
                Some(Leaf::Unsupported(r)) => Ref::Unsupported(r.clone()),
                None => Ref::Unsupported(format!("profile {name:?} was not imported")),
            },
            Kind::Switch | Kind::Virtual | Kind::RuleList => Ref::Nested(name.to_string()),
            Kind::Pac => Ref::Unsupported(format!(
                "profile {name:?} is a {}: JavaScript PAC scripts are not executed",
                src.type_name
            )),
            Kind::Other => Ref::Unsupported(format!(
                "profile {name:?} has unsupported profileType {:?}",
                src.type_name
            )),
        }
    }

    fn nested(&mut self, name: &str, stack: &mut Vec<String>) -> Result<FlatTable, ImportError> {
        if stack.iter().any(|s| s == name) {
            let mut cycle = stack.clone();
            cycle.push(name.to_string());
            return Err(ImportError::Cycle { cycle });
        }
        stack.push(name.to_string());
        let out = self.flatten(name, stack);
        stack.pop();
        out
    }

    /// Flatten the rules of a SwitchProfile / VirtualProfile / rule list into evaluation
    /// order. `stack` holds the profiles being flattened (including `name`).
    fn flatten(&mut self, name: &str, stack: &mut Vec<String>) -> Result<FlatTable, ImportError> {
        let (raw, default_name) = self.raw_rules(name);
        let mut out = Vec::new();
        for r in raw {
            match self.resolve_ref(&r.profile) {
                Ref::Leaf(t) => out.push(FlatRule {
                    cond: r.cond,
                    target: vec![t],
                    label: r.label,
                    comments: r.comments,
                    unsupported: None,
                }),
                Ref::Unsupported(reason) => out.push(FlatRule {
                    cond: r.cond,
                    target: vec![PROFILE_DIRECT.to_string()],
                    label: r.label,
                    comments: r.comments,
                    unsupported: Some(reason),
                }),
                Ref::Nested(n) => {
                    let (sub, sub_default) = self.nested(&n, stack)?;
                    for s in sub {
                        let mut comments = r.comments.clone();
                        comments.extend(s.comments);
                        out.push(FlatRule {
                            cond: merge(&r.cond, &s.cond),
                            target: s.target,
                            label: format!("{} > {}", r.label, s.label),
                            comments,
                            unsupported: s.unsupported,
                        });
                    }
                    let mut comments = r.comments.clone();
                    comments.push(format!("Fallback of nested profile {n:?}"));
                    out.push(FlatRule {
                        cond: r.cond,
                        target: sub_default,
                        label: format!("{} > default", r.label),
                        comments,
                        unsupported: None,
                    });
                }
            }
        }
        let default = match self.resolve_ref(&default_name) {
            Ref::Leaf(t) => vec![t],
            Ref::Unsupported(reason) => {
                self.warnings.push(format!(
                    "default of profile {name:?} {reason}; using \"direct\" instead"
                ));
                vec![PROFILE_DIRECT.to_string()]
            }
            Ref::Nested(n) => {
                let (sub, sub_default) = self.nested(&n, stack)?;
                out.extend(sub);
                sub_default
            }
        };
        Ok((out, default))
    }

    /// The rules and default profile name of a nested-kind profile.
    fn raw_rules(&mut self, name: &str) -> (Vec<RawRule>, String) {
        let src = &self.profiles[name];
        let (kind, type_name, v) = (src.kind, src.type_name.clone(), src.value);
        let default = str_field(v, "defaultProfileName")
            .unwrap_or(PROFILE_DIRECT)
            .to_string();
        match kind {
            Kind::Switch => {
                let mut out = Vec::new();
                for (i, r) in v
                    .get("rules")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or_default()
                    .iter()
                    .enumerate()
                {
                    let label = str_field(r, "note")
                        .map(str::trim)
                        .filter(|n| !n.is_empty())
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{name} #{}", i + 1));
                    let cond = match r.get("condition") {
                        Some(c) => map_condition(c, &mut self.warnings),
                        None => Err("rule has no condition".to_string()),
                    };
                    out.push(RawRule {
                        cond,
                        profile: str_field(r, "profileName")
                            .unwrap_or(PROFILE_DIRECT)
                            .to_string(),
                        label,
                        comments: Vec::new(),
                    });
                }
                (out, default)
            }
            Kind::RuleList => {
                let matched = str_field(v, "matchProfileName")
                    .unwrap_or(PROFILE_DIRECT)
                    .to_string();
                let text = str_field(v, "ruleList").unwrap_or("").trim().to_string();
                if text.is_empty() {
                    if let Some(url) = str_field(v, "sourceUrl").filter(|u| !u.is_empty()) {
                        self.warnings.push(format!(
                            "rule list {name:?}: remote sourceUrl {url:?} is not fetched \
                             (offline import); its rules are skipped"
                        ));
                    }
                    return (Vec::new(), default);
                }
                let format = str_field(v, "format")
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        if type_name == "AutoProxyRuleListProfile" {
                            "AutoProxy".into()
                        } else {
                            "Switchy".into()
                        }
                    });
                let rules =
                    parse_rule_list(name, &format, &text, &matched, &default, &mut self.warnings);
                (rules, default)
            }
            // VirtualProfile: no rules, resolves to its defaultProfileName.
            _ => (Vec::new(), default),
        }
    }
}

type FlatTable = (Vec<FlatRule>, Vec<String>);

fn dedup(v: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    v.retain(|s| seen.insert(s.clone()));
}

/// AND two conditions into one rule. Fails when both set the same field (a field is an OR
/// of its values, so two independent constraints on one field cannot be expressed).
fn merge(a: &CondResult, b: &CondResult) -> CondResult {
    let (a, b) = match (a, b) {
        (Err(e), _) | (_, Err(e)) => return Err(e.clone()),
        (Ok(a), Ok(b)) => (a, b),
    };
    let mut out = empty_rule();
    macro_rules! take {
        ($($f:ident),*) => {$(
            out.$f = match (&a.rule.$f, &b.rule.$f) {
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "nested SwitchProfile conditions both use `{}`, which cannot be ANDed",
                        stringify!($f)
                    ))
                }
                (x, y) => x.clone().or_else(|| y.clone()),
            };
        )*};
    }
    take!(
        inbound,
        host,
        host_wildcard,
        host_regex,
        cidr,
        ip,
        port,
        host_levels,
        bypass,
        weekday,
        time,
        url_wildcard,
        url_regex,
        keyword,
        resolve_dns
    );
    out.disabled = a.rule.disabled || b.rule.disabled;
    out.match_all = a.rule.match_all && b.rule.match_all;
    let mut comments = a.comments.clone();
    comments.extend(b.comments.iter().cloned());
    Ok(Cond {
        rule: out,
        comments,
    })
}

fn split_pipes(p: &str) -> Vec<String> {
    p.split('|')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Validate a JavaScript regex for the Rust `regex` engine.
fn check_regex(p: &str, warnings: &mut Warnings) -> Result<(), String> {
    if ["(?=", "(?!", "(?<=", "(?<!"].iter().any(|l| p.contains(l)) {
        warnings.push(format!(
            "regex {p:?} uses PCRE lookarounds, which the Rust regex engine does not support"
        ));
        return Err(format!("regex {p:?} uses unsupported PCRE lookarounds"));
    }
    regex::Regex::new(p)
        .map(|_| ())
        .map_err(|e| format!("invalid regex {p:?}: {e}"))
}

const WEEKDAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// Map one AirSwitch condition object onto rule fields.
fn map_condition(c: &Value, warnings: &mut Warnings) -> CondResult {
    let ty = str_field(c, "conditionType").unwrap_or("");
    let pattern = || {
        str_field(c, "pattern")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("{ty} has no pattern"))
    };
    let mut r = empty_rule();
    let mut comments = Vec::new();
    match ty {
        "HostWildcardCondition" => {
            let parts = split_pipes(&pattern()?);
            if parts.is_empty() {
                return Err(format!("{ty} has no pattern"));
            }
            r.host_wildcard = Some(OneOrMany::Many(parts));
        }
        "HostRegexCondition" => {
            let p = pattern()?;
            check_regex(&p, warnings)?;
            r.host_regex = Some(OneOrMany::One(p));
        }
        "UrlWildcardCondition" => {
            let parts = split_pipes(&pattern()?);
            if parts.is_empty() {
                return Err(format!("{ty} has no pattern"));
            }
            r.url_wildcard = Some(OneOrMany::Many(parts));
            comments.push(URL_RULE_NOTE.to_string());
        }
        "UrlRegexCondition" => {
            let p = pattern()?;
            check_regex(&p, warnings)?;
            r.url_regex = Some(OneOrMany::One(p));
            comments.push(URL_RULE_NOTE.to_string());
        }
        "KeywordCondition" => {
            r.keyword = Some(OneOrMany::Many(vec![pattern()?]));
            comments.push(URL_RULE_NOTE.to_string());
            comments.push(
                "AirSwitch matched keywords on http:// URLs only; here they also match \
                 MITM-decrypted https:// URLs"
                    .to_string(),
            );
        }
        "IpCondition" => {
            let ip = str_field(c, "ip").map(str::trim).unwrap_or("");
            let ip = ip
                .strip_prefix('[')
                .and_then(|i| i.strip_suffix(']'))
                .unwrap_or(ip);
            let prefix = int_field(c, "prefixLength");
            match (ip.is_empty(), prefix) {
                (false, Some(p)) => r.cidr = Some(OneOrMany::Many(vec![format!("{ip}/{p}")])),
                (false, None) => r.cidr = Some(OneOrMany::Many(vec![ip.to_string()])),
                (true, _) => return Err(format!("{ty} has no ip")),
            }
        }
        "BypassCondition" => r.bypass = Some(OneOrMany::Many(vec![pattern()?])),
        "HostLevelsCondition" => {
            let min = int_field(c, "minValue").unwrap_or(1).max(0);
            let max = int_field(c, "maxValue").unwrap_or(1).max(0);
            if min > max {
                r.disabled = true;
                comments.push(format!(
                    "AirSwitch HostLevelsCondition {min}~{max} never matches; rule disabled"
                ));
            } else {
                r.host_levels = Some(HostLevels {
                    min: u32::try_from(min).ok(),
                    max: u32::try_from(max).ok(),
                });
            }
        }
        "WeekdayCondition" => {
            let mut sel = [false; 7];
            match str_field(c, "days").filter(|d| !d.is_empty()) {
                Some(days) => {
                    for (i, ch) in days.chars().take(7).enumerate() {
                        sel[i] = u32::from(ch) > 64;
                    }
                }
                None => {
                    let start = int_field(c, "startDay").unwrap_or(0);
                    let end = int_field(c, "endDay").unwrap_or(0);
                    for (i, s) in sel.iter_mut().enumerate() {
                        *s = (start..=end).contains(&(i as i64));
                    }
                }
            }
            let days: Vec<String> = WEEKDAYS
                .iter()
                .zip(sel)
                .filter(|(_, on)| *on)
                .map(|(d, _)| d.to_string())
                .collect();
            if days.is_empty() {
                r.disabled = true;
                comments.push("AirSwitch WeekdayCondition selects no day; rule disabled".into());
            } else {
                r.weekday = Some(OneOrMany::Many(days));
            }
        }
        "TimeCondition" => {
            let start = int_field(c, "startHour").unwrap_or(0);
            let end = int_field(c, "endHour").unwrap_or(0);
            let valid = |h: i64| (0..24).contains(&h);
            if !valid(start) || !valid(end) {
                return Err(format!("{ty} has invalid hours {start}~{end}"));
            }
            if start > end {
                r.disabled = true;
                comments.push(format!(
                    "AirSwitch TimeCondition {start}~{end} never matches; rule disabled"
                ));
            } else {
                r.time = Some(OneOrMany::Many(vec![format!("{start:02}:00-{end:02}:59")]));
            }
        }
        "TrueCondition" => r.match_all = true,
        "FalseCondition" => {
            r.disabled = true;
            comments.push("AirSwitch FalseCondition: rule preserved but disabled".into());
        }
        other => return Err(format!("unsupported conditionType {other:?}")),
    }
    Ok(Cond { rule: r, comments })
}

// ---------------------------------------------------------------------------
// Inline rule lists (Switchy / AutoProxy)
// ---------------------------------------------------------------------------

/// Condition type for a Switchy condition-type abbreviation (case-insensitive).
fn type_from_abbr(abbr: &str) -> Option<&'static str> {
    const TABLE: &[(&str, &[&str])] = &[
        ("TrueCondition", &["True"]),
        ("FalseCondition", &["False", "Disabled"]),
        ("UrlRegexCondition", &["UR", "URegex", "UrlR", "UrlRegex"]),
        (
            "UrlWildcardCondition",
            &[
                "U",
                "UW",
                "Url",
                "UrlW",
                "UWild",
                "UWildcard",
                "UrlWild",
                "UrlWildcard",
            ],
        ),
        (
            "HostRegexCondition",
            &["R", "HR", "Regex", "HostR", "HRegex", "HostRegex"],
        ),
        (
            "HostWildcardCondition",
            &[
                "",
                "H",
                "W",
                "HW",
                "Wild",
                "Wildcard",
                "Host",
                "HostW",
                "HWild",
                "HWildcard",
                "HostWild",
                "HostWildcard",
            ],
        ),
        ("BypassCondition", &["B", "Bypass"]),
        ("KeywordCondition", &["K", "KW", "Keyword"]),
        ("IpCondition", &["Ip"]),
        (
            "HostLevelsCondition",
            &[
                "Lv",
                "Level",
                "Levels",
                "HL",
                "HLv",
                "HLevel",
                "HLevels",
                "HostL",
                "HostLv",
                "HostLevel",
                "HostLevels",
            ],
        ),
        ("WeekdayCondition", &["WD", "Week", "Day", "Weekday"]),
        ("TimeCondition", &["T", "Time", "Hour"]),
    ];
    TABLE.iter().find_map(|(ty, abbrs)| {
        (ty.eq_ignore_ascii_case(abbr) || abbrs.iter().any(|a| a.eq_ignore_ascii_case(abbr)))
            .then_some(*ty)
    })
}

/// Parse one Switchy condition line (`"Type: pattern"` or a bare host wildcard).
fn condition_from_str(s: &str) -> Option<Value> {
    let s = s.trim();
    let i = s.find(' ').unwrap_or(s.len());
    let (abbr, rest) = match s[..i].strip_suffix(':') {
        Some(abbr) => (abbr, s[i..].trim()),
        None => ("", s),
    };
    let ty = type_from_abbr(abbr)?;
    let int = |x: &str| x.trim().parse::<i64>().ok();
    Some(match ty {
        "IpCondition" => {
            let (ip, prefix) = match rest.rsplit_once('/') {
                Some((ip, p)) => (ip, int(p)),
                None => (rest, None),
            };
            let prefix = prefix.unwrap_or(if ip.contains(':') { 128 } else { 32 });
            json!({"conditionType": ty, "ip": ip.trim(), "prefixLength": prefix})
        }
        "HostLevelsCondition" => {
            let (a, b) = rest.split_once('~').unwrap_or((rest, ""));
            let norm = |v: Option<i64>| v.filter(|v| *v > 0).unwrap_or(1);
            json!({"conditionType": ty, "minValue": norm(int(a)), "maxValue": norm(int(b))})
        }
        "WeekdayCondition" if !rest.contains('~') && rest.chars().count() == 7 => {
            json!({"conditionType": ty, "days": rest})
        }
        "WeekdayCondition" => {
            let (a, b) = rest.split_once('~').unwrap_or((rest, ""));
            let norm = |v: Option<i64>| v.filter(|v| (0..=6).contains(v)).unwrap_or(0);
            json!({"conditionType": ty, "startDay": norm(int(a)), "endDay": norm(int(b))})
        }
        "TimeCondition" => {
            let (a, b) = rest.split_once('~').unwrap_or((rest, ""));
            let norm = |v: Option<i64>| v.filter(|v| (0..24).contains(v)).unwrap_or(0);
            json!({"conditionType": ty, "startHour": norm(int(a)), "endHour": norm(int(b))})
        }
        "TrueCondition" | "FalseCondition" => json!({"conditionType": ty}),
        _ => json!({"conditionType": ty, "pattern": rest}),
    })
}

struct ListRule {
    cond: Value,
    profile: Option<String>,
    source: String,
}

fn parse_rule_list(
    list_name: &str,
    format: &str,
    text: &str,
    matched: &str,
    default: &str,
    warnings: &mut Warnings,
) -> Vec<RawRule> {
    let rules = match format {
        "AutoProxy" => parse_autoproxy(list_name, text, matched, default, warnings),
        "Switchy" => {
            if !text.starts_with("[SwitchyOmega Conditions")
                && (text.starts_with('#') || text.contains("\n#"))
            {
                parse_switchy_legacy(text, matched, default)
            } else {
                parse_switchy_omega(list_name, text, matched, default, warnings)
            }
        }
        other => {
            warnings.push(format!(
                "rule list {list_name:?}: unsupported format {other:?}; its rules are skipped"
            ));
            Vec::new()
        }
    };
    rules
        .into_iter()
        .enumerate()
        .map(|(i, r)| RawRule {
            cond: map_condition(&r.cond, warnings),
            profile: r.profile.unwrap_or_else(|| default.to_string()),
            label: format!("{list_name} #{}", i + 1),
            comments: vec![format!("Rule list line: {}", r.source)],
        })
        .collect()
}

fn parse_switchy_omega(
    list_name: &str,
    text: &str,
    matched: &str,
    default: &str,
    warnings: &mut Warnings,
) -> Vec<ListRule> {
    let mut rules = Vec::new();
    let mut with_result = false;
    let mut exclusive: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('[') || line.starts_with(';') {
            continue;
        }
        if let Some(d) = line.strip_prefix('@') {
            let (directive, arg) = d.split_once(' ').unwrap_or((d, ""));
            if directive.eq_ignore_ascii_case("with")
                && matches!(
                    arg.trim().to_ascii_uppercase().as_str(),
                    "RESULT" | "RESULTS"
                )
            {
                with_result = true;
            }
            continue;
        }
        let source = line.to_string();
        let (body, profile) = if let Some(rest) = line.strip_prefix('!') {
            (
                rest.to_string(),
                (!with_result).then(|| default.to_string()),
            )
        } else if with_result {
            let Some(idx) = line.rfind(" +") else {
                warnings.push(format!(
                    "rule list {list_name:?}: line {line:?} has no result profile; skipped"
                ));
                continue;
            };
            let profile = line[idx + 2..].trim().to_string();
            let body = line[..idx].trim().to_string();
            if body == "*" {
                exclusive = Some(profile.clone());
            }
            (body, Some(profile))
        } else {
            (line.to_string(), Some(matched.to_string()))
        };
        match condition_from_str(&body) {
            Some(cond) => rules.push(ListRule {
                cond,
                profile,
                source,
            }),
            None => warnings.push(format!(
                "rule list {list_name:?}: invalid rule {line:?}; skipped"
            )),
        }
    }
    if with_result {
        let fill = exclusive.unwrap_or_else(|| default.to_string());
        for r in &mut rules {
            r.profile.get_or_insert_with(|| fill.clone());
        }
    }
    rules
}

/// `*://host/*` → `host` (AirSwitch `urlWildcard2HostWildcard`).
fn url_wildcard_to_host(p: &str) -> Option<&str> {
    let host = p.strip_prefix("*://")?.strip_suffix("/*")?;
    (!host.is_empty()
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || "_?*.-".contains(c)))
    .then_some(host)
}

fn parse_switchy_legacy(text: &str, matched: &str, default: &str) -> Vec<ListRule> {
    let (mut normal, mut exclusive) = (Vec::new(), Vec::new());
    let mut begin = false;
    let mut section = "WILDCARD".to_string();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if !begin {
            begin = line.eq_ignore_ascii_case("#BEGIN");
            continue;
        }
        if line.eq_ignore_ascii_case("#END") {
            break;
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            section = line[1..line.len() - 1].to_ascii_uppercase();
            continue;
        }
        let source = line.to_string();
        let (body, profile, is_excl) = match line.strip_prefix('!') {
            Some(rest) => (rest, default, true),
            None => (line, matched, false),
        };
        let cond = match section.as_str() {
            "WILDCARD" => {
                let mut p = match body.strip_prefix('@') {
                    Some(rest) => rest.to_string(),
                    None => {
                        let mut p = body.to_string();
                        if p.find("://").is_none_or(|i| i == 0) && !p.starts_with('*') {
                            p.insert(0, '*');
                        }
                        p
                    }
                };
                if !body.starts_with('@') && !p.ends_with('*') {
                    p.push('*');
                }
                match url_wildcard_to_host(&p) {
                    Some(h) => json!({"conditionType": "HostWildcardCondition", "pattern": h}),
                    None => json!({"conditionType": "UrlWildcardCondition", "pattern": p}),
                }
            }
            "REGEXP" => json!({"conditionType": "UrlRegexCondition", "pattern": body}),
            _ => continue,
        };
        let r = ListRule {
            cond,
            profile: Some(profile.to_string()),
            source,
        };
        if is_excl {
            exclusive.push(r);
        } else {
            normal.push(r);
        }
    }
    exclusive.extend(normal);
    exclusive
}

fn parse_autoproxy(
    list_name: &str,
    text: &str,
    matched: &str,
    default: &str,
    warnings: &mut Warnings,
) -> Vec<ListRule> {
    let decoded;
    let text = if text.starts_with("W0F1dG9Qcm94") {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        match base64::engine::general_purpose::STANDARD
            .decode(compact)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        {
            Some(t) => {
                decoded = t;
                decoded.as_str()
            }
            None => {
                warnings.push(format!(
                    "rule list {list_name:?}: invalid base64 AutoProxy list; skipped"
                ));
                return Vec::new();
            }
        }
    } else {
        text
    };
    let (mut normal, mut exclusive) = (Vec::new(), Vec::new());
    let mut modifiers = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        if line.contains('$') || line.contains("##") || line.contains("#@#") {
            modifiers += 1;
            continue;
        }
        let source = line.to_string();
        let (body, profile, is_excl) = match line.strip_prefix("@@") {
            Some(rest) => (rest, default, true),
            None => (line, matched, false),
        };
        let cond = if body.len() >= 2 && body.starts_with('/') && body.ends_with('/') {
            json!({"conditionType": "UrlRegexCondition", "pattern": &body[1..body.len() - 1]})
        } else if let Some(host) = body.strip_prefix("||") {
            let host = host.trim_end_matches('^').trim_end_matches('/');
            if host.is_empty() || host.contains(['/', '^', '|']) {
                warnings.push(format!(
                    "rule list {list_name:?}: AutoProxy rule {line:?} is not a plain host rule; \
                     skipped"
                ));
                continue;
            }
            json!({"conditionType": "HostWildcardCondition", "pattern": format!("*.{host}")})
        } else if let Some(url) = body.strip_prefix('|') {
            json!({"conditionType": "UrlWildcardCondition", "pattern": format!("{url}*")})
        } else if !body.contains('*') {
            json!({"conditionType": "KeywordCondition", "pattern": body})
        } else {
            json!({"conditionType": "UrlWildcardCondition", "pattern": format!("http://*{body}*")})
        };
        let r = ListRule {
            cond,
            profile: Some(profile.to_string()),
            source,
        };
        if is_excl {
            exclusive.push(r);
        } else {
            normal.push(r);
        }
    }
    if modifiers > 0 {
        warnings.push(format!(
            "rule list {list_name:?}: {modifiers} line(s) with unsupported AdBlock/AutoProxy \
             modifiers ($options, element hiding) skipped"
        ));
    }
    exclusive.extend(normal);
    exclusive
}

impl fmt::Display for Imported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "profiles={} rules={} warnings={}",
            self.profiles.len(),
            self.active_rule_count(),
            self.warnings.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv(json: &str) -> Imported {
        convert(json, &ImportOptions::default()).unwrap()
    }

    #[test]
    fn slugify_is_deterministic() {
        assert_eq!(slugify("Work Proxy"), "work_proxy");
        assert_eq!(slugify("  --Dev__Box 2-- "), "dev_box_2");
        assert_eq!(slugify("代理"), "profile");
    }

    #[test]
    fn slug_collisions_are_disambiguated() {
        let imp = conv(
            r#"{"+Work Proxy":{"name":"Work Proxy","profileType":"FixedProfile",
                "fallbackProxy":{"scheme":"http","host":"a","port":1}},
               "+work-proxy":{"name":"work-proxy","profileType":"FixedProfile",
                "fallbackProxy":{"scheme":"http","host":"b","port":2}},
               "+Direct":{"name":"Direct","profileType":"FixedProfile",
                "fallbackProxy":{"scheme":"socks5","host":"c","port":3}}}"#,
        );
        let keys: Vec<_> = imp.profiles.iter().map(|p| p.key.as_str()).collect();
        assert_eq!(keys, ["direct_2", "work_proxy", "work_proxy_2"]);
    }

    #[test]
    fn base64_backup_is_accepted() {
        let json = r#"{"+p":{"name":"p","profileType":"FixedProfile",
            "fallbackProxy":{"scheme":"socks5","host":"h","port":1080}}}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json);
        let imp = conv(&b64);
        assert_eq!(imp.profiles[0].config.kind, ProfileType::Socks5);
    }

    #[test]
    fn fixed_profile_maps_auth_and_bypass() {
        let imp = conv(
            r#"{"+Corp":{"name":"Corp","profileType":"FixedProfile",
                "fallbackProxy":{"scheme":"http","host":"10.0.0.2","port":3128},
                "auth":{"fallbackProxy":{"username":"alice","password":"s3cret"}},
                "bypassList":[{"conditionType":"BypassCondition","pattern":"127.0.0.1"},
                              {"conditionType":"BypassCondition","pattern":"[::1]"},
                              {"conditionType":"BypassCondition","pattern":"<local>"}]}}"#,
        );
        let p = &imp.profiles[0];
        assert_eq!(p.key, "corp");
        assert_eq!(p.config.kind, ProfileType::Http);
        assert_eq!(p.config.username.as_deref(), Some("alice"));
        assert_eq!(p.config.password.as_deref(), Some("s3cret"));
        assert_eq!(p.config.bypass, ["127.0.0.1", "[::1]", "<local>"]);
        assert!(imp.warnings.iter().any(|w| w.contains("plaintext")));
        assert!(!imp.warnings.iter().any(|w| w.contains("s3cret")));
    }

    #[test]
    fn per_scheme_fixed_profile_becomes_composite() {
        let imp = conv(
            r#"{"+Split":{"name":"Split","profileType":"FixedProfile",
                "proxyForHttp":{"scheme":"http","host":"h","port":8080},
                "proxyForHttps":{"scheme":"https","host":"s","port":8443},
                "fallbackProxy":{"scheme":"socks5","host":"f","port":1080},
                "auth":{"all":{"username":"u","password":"p"}}}}"#,
        );
        let keys: Vec<_> = imp.profiles.iter().map(|p| p.key.as_str()).collect();
        assert_eq!(
            keys,
            ["split", "split_http", "split_https", "split_fallback"]
        );
        let c = &imp.profiles[0].config;
        assert_eq!(c.kind, ProfileType::Composite);
        assert_eq!(c.http_proxy.as_deref(), Some("split_http"));
        assert_eq!(c.https_proxy.as_deref(), Some("split_https"));
        assert_eq!(c.fallback_proxy.as_deref(), Some("split_fallback"));
        assert_eq!(imp.profiles[2].config.kind, ProfileType::Https);
        assert_eq!(imp.profiles[3].config.username.as_deref(), Some("u"));
    }

    #[test]
    fn conditions_map_to_rule_fields() {
        let imp = conv(
            r#"{"-startupProfileName":"auto",
               "+P":{"name":"P","profileType":"FixedProfile",
                 "fallbackProxy":{"scheme":"socks5","host":"h","port":1}},
               "+auto":{"name":"auto","profileType":"SwitchProfile","defaultProfileName":"direct",
                 "rules":[
                  {"condition":{"conditionType":"HostWildcardCondition","pattern":"*.a.com|**.b.com"},"profileName":"P"},
                  {"condition":{"conditionType":"IpCondition","ip":"10.0.0.0","prefixLength":8},"profileName":"P"},
                  {"condition":{"conditionType":"IpCondition","ip":"[fd00::]","prefixLength":8},"profileName":"P"},
                  {"condition":{"conditionType":"HostLevelsCondition","minValue":0,"maxValue":0},"profileName":"P"},
                  {"condition":{"conditionType":"WeekdayCondition","days":"-MTWTF-"},"profileName":"P"},
                  {"condition":{"conditionType":"WeekdayCondition","startDay":5,"endDay":6},"profileName":"P"},
                  {"condition":{"conditionType":"TimeCondition","startHour":9,"endHour":17},"profileName":"P"},
                  {"condition":{"conditionType":"KeywordCondition","pattern":"ads"},"profileName":"P"},
                  {"condition":{"conditionType":"UrlWildcardCondition","pattern":"http://x/*"},"profileName":"P"},
                  {"condition":{"conditionType":"BypassCondition","pattern":"<local>"},"profileName":"P"},
                  {"condition":{"conditionType":"FalseCondition"},"profileName":"P"},
                  {"condition":{"conditionType":"TrueCondition"},"profileName":"direct","note":"catch all"}
                 ]}}"#,
        );
        assert_eq!(imp.switch_profile.as_deref(), Some("auto"));
        let r: Vec<_> = imp.rules.iter().map(|r| &r.rule).collect();
        assert!(imp.rules.iter().all(|r| r.skipped.is_none()));
        assert_eq!(
            r[0].host_wildcard,
            Some(OneOrMany::Many(vec!["*.a.com".into(), "**.b.com".into()]))
        );
        assert_eq!(r[1].cidr, Some(OneOrMany::Many(vec!["10.0.0.0/8".into()])));
        assert_eq!(r[2].cidr, Some(OneOrMany::Many(vec!["fd00::/8".into()])));
        assert_eq!(
            r[3].host_levels,
            Some(HostLevels {
                min: Some(0),
                max: Some(0)
            })
        );
        let days = |v: &[&str]| Some(OneOrMany::Many(v.iter().map(|s| s.to_string()).collect()));
        assert_eq!(r[4].weekday, days(&["mon", "tue", "wed", "thu", "fri"]));
        assert_eq!(r[5].weekday, days(&["fri", "sat"]));
        assert_eq!(r[6].time, days(&["09:00-17:59"]));
        assert!(r[7].keyword.is_some());
        assert!(r[8].url_wildcard.is_some());
        assert_eq!(r[9].bypass, days(&["<local>"]));
        assert!(r[10].disabled);
        assert!(r[11].match_all);
        assert_eq!(r[11].name.as_deref(), Some("catch all"));
        assert_eq!(r[0].name.as_deref(), Some("auto #1"));
        assert_eq!(r[0].target, OneOrMany::One("p".into()));
        assert!(imp.warnings.iter().any(|w| w.contains("URL rule")));
    }

    #[test]
    fn lookaround_regex_is_skipped_with_warning() {
        let imp = conv(
            r#"{"+s":{"name":"s","profileType":"SwitchProfile","rules":[
                {"condition":{"conditionType":"HostRegexCondition","pattern":"^(?!www\\.)x"},"profileName":"direct"}]}}"#,
        );
        assert!(imp.rules[0].skipped.is_some());
        assert!(imp.warnings.iter().any(|w| w.contains("lookaround")));
    }

    #[test]
    fn nested_switch_profiles_are_flattened() {
        let imp = conv(
            r#"{"-startupProfileName":"outer",
               "+P":{"name":"P","profileType":"FixedProfile",
                 "fallbackProxy":{"scheme":"http","host":"h","port":1}},
               "+outer":{"name":"outer","profileType":"SwitchProfile","defaultProfileName":"inner",
                 "rules":[{"condition":{"conditionType":"HostWildcardCondition","pattern":"*.corp"},
                           "profileName":"inner"}]},
               "+inner":{"name":"inner","profileType":"SwitchProfile","defaultProfileName":"virt",
                 "rules":[{"condition":{"conditionType":"IpCondition","ip":"10.0.0.0","prefixLength":8},
                           "profileName":"P"}]},
               "+virt":{"name":"virt","profileType":"VirtualProfile","defaultProfileName":"P"}}"#,
        );
        let labels: Vec<_> = imp
            .rules
            .iter()
            .map(|r| r.rule.name.clone().unwrap())
            .collect();
        assert_eq!(
            labels,
            ["outer #1 > inner #1", "outer #1 > default", "inner #1"]
        );
        let first = &imp.rules[0].rule;
        assert!(first.host_wildcard.is_some() && first.cidr.is_some());
        assert_eq!(imp.rules[1].rule.target, OneOrMany::One("p".into()));
        assert_eq!(imp.default, ["p"]);
    }

    #[test]
    fn switch_cycles_are_rejected() {
        let err = convert(
            r#"{"+a":{"name":"a","profileType":"SwitchProfile","defaultProfileName":"b","rules":[]},
               "+b":{"name":"b","profileType":"SwitchProfile","defaultProfileName":"a","rules":[]}}"#,
            &ImportOptions {
                profile: Some("a".into()),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ImportError::Cycle { .. }), "{err}");
        assert!(err.to_string().contains("a -> b -> a"), "{err}");
    }

    #[test]
    fn switch_selection_errors_list_available() {
        let json = r#"{"+a":{"name":"a","profileType":"SwitchProfile"},
                       "+b":{"name":"b","profileType":"SwitchProfile"}}"#;
        let err = convert(json, &ImportOptions::default()).unwrap_err();
        assert!(matches!(err, ImportError::AmbiguousSwitch { .. }));
        assert!(err.to_string().contains("\"a\", \"b\""));
        let err = convert(
            json,
            &ImportOptions {
                profile: Some("zzz".into()),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ImportError::ProfileNotFound { .. }));
        let ok = convert(
            json,
            &ImportOptions {
                profile: Some("b".into()),
            },
        )
        .unwrap();
        assert_eq!(ok.switch_profile.as_deref(), Some("b"));
    }

    #[test]
    fn pac_and_system_profiles_warn() {
        let imp = conv(
            r#"{"+pac":{"name":"pac","profileType":"PacProfile","pacScript":"x"},
               "+s":{"name":"s","profileType":"SwitchProfile","defaultProfileName":"system","rules":[
                 {"condition":{"conditionType":"HostWildcardCondition","pattern":"*.x"},"profileName":"pac"}]}}"#,
        );
        assert!(imp
            .warnings
            .iter()
            .any(|w| w.contains("SystemProfile has no server-side equivalent")));
        assert!(imp
            .warnings
            .iter()
            .any(|w| w.contains("JavaScript PAC scripts are not executed")));
        assert!(imp.rules[0].skipped.is_some());
        assert_eq!(imp.default, ["direct"]);
    }

    #[test]
    fn inline_rule_lists_are_parsed() {
        let imp = conv(
            r#"{"-startupProfileName":"s",
               "+P":{"name":"P","profileType":"FixedProfile",
                 "fallbackProxy":{"scheme":"http","host":"h","port":1}},
               "+s":{"name":"s","profileType":"SwitchProfile","defaultProfileName":"list","rules":[]},
               "+list":{"name":"list","profileType":"SwitchyRuleListProfile",
                 "matchProfileName":"P","defaultProfileName":"direct",
                 "ruleList":"[SwitchyOmega Conditions]\n; comment\n*.google.com\nIp: 10.0.0.0/8\n!*.local\n"},
               "+ap":{"name":"ap","profileType":"AutoProxyRuleListProfile",
                 "ruleList":"[AutoProxy 0.2.9]\n||example.com\n@@||ok.example.com\n|http://x.com/\nkw\n/re.x/\nads$third-party\n"},
               "+remote":{"name":"remote","profileType":"SwitchyRuleListProfile","sourceUrl":"https://x/list.txt"}}"#,
        );
        let r = &imp.rules;
        assert_eq!(r.len(), 3);
        assert_eq!(
            r[0].rule.host_wildcard,
            Some(OneOrMany::Many(vec!["*.google.com".into()]))
        );
        assert_eq!(r[0].rule.target, OneOrMany::One("p".into()));
        assert_eq!(
            r[1].rule.cidr,
            Some(OneOrMany::Many(vec!["10.0.0.0/8".into()]))
        );
        assert_eq!(r[2].rule.target, OneOrMany::One("direct".into()));

        let imp = convert(
            r#"{"+ap":{"name":"ap","profileType":"AutoProxyRuleListProfile","matchProfileName":"direct",
                 "ruleList":"[AutoProxy 0.2.9]\n||example.com\n@@||ok.example.com\n|http://x.com/\nkw\n/re.x/\nads$third-party\n"}}"#,
            &ImportOptions { profile: Some("ap".into()) },
        )
        .unwrap();
        let kinds: Vec<_> = imp
            .rules
            .iter()
            .map(|r| {
                let r = &r.rule;
                if r.host_wildcard.is_some() {
                    "host"
                } else if r.url_wildcard.is_some() {
                    "url"
                } else if r.keyword.is_some() {
                    "kw"
                } else {
                    "re"
                }
            })
            .collect();
        // Exclusive (@@) rules come first.
        assert_eq!(kinds, ["host", "host", "url", "kw", "re"]);
        assert!(imp.warnings.iter().any(|w| w.contains("modifiers")));
    }

    #[test]
    fn remote_rule_list_warns() {
        let imp = convert(
            r#"{"+r":{"name":"r","profileType":"SwitchyRuleListProfile","sourceUrl":"https://x/list.txt"}}"#,
            &ImportOptions {
                profile: Some("r".into()),
            },
        )
        .unwrap();
        assert!(imp.rules.is_empty());
        assert!(imp.warnings.iter().any(|w| w.contains("sourceUrl")));
    }

    #[test]
    fn legacy_switchy_list_is_parsed() {
        let rules = parse_switchy_legacy(
            "#BEGIN\n[Wildcard]\n*://*.example.com/*\n!*.local*\n[RegExp]\n^https?://x\n#END\n",
            "m",
            "d",
        );
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].profile.as_deref(), Some("d"));
        assert_eq!(rules[1].cond["conditionType"], "HostWildcardCondition");
        assert_eq!(rules[1].cond["pattern"], "*.example.com");
        assert_eq!(rules[2].cond["conditionType"], "UrlRegexCondition");
    }

    #[test]
    fn merge_rejects_same_field() {
        let mut w = Warnings::default();
        let a = map_condition(
            &json!({"conditionType":"HostWildcardCondition","pattern":"*.a"}),
            &mut w,
        );
        let b = map_condition(
            &json!({"conditionType":"HostWildcardCondition","pattern":"*.b"}),
            &mut w,
        );
        assert!(merge(&a, &b).is_err());
        let t = map_condition(&json!({"conditionType":"TrueCondition"}), &mut w);
        let m = merge(&t, &a).unwrap();
        assert!(!m.rule.match_all && m.rule.host_wildcard.is_some());
    }
}
