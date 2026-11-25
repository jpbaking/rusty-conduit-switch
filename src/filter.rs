//! Destination allowlist / blocklist filtering for IP, CIDR, and FQDN (with `*.` wildcards).
//!
//! A [`HostFilter`] is either an allowlist ([`HostFilter::Allow`]) or a blocklist
//! ([`HostFilter::Block`]) — never both.
//!
//! Because `rusty-conduit` dials destinations directly through the OS resolver
//! ([`crate::net::connect_upstream_filtered`]), both domain rules and resolved-IP IP/CIDR rules
//! are enforced before connecting (blocking DNS-to-loopback / DNS-rebinding bypasses).

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Error carried inside an [`io::Error`] (`ErrorKind::PermissionDenied`) when a destination is
/// rejected by a [`HostFilter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDenied(pub String);

impl fmt::Display for AccessDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AccessDenied {}

/// Wrap an [`AccessDenied`] in an [`io::Error`] with [`io::ErrorKind::PermissionDenied`].
pub fn access_denied_error(denied: AccessDenied) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, denied)
}

/// Whether `err` was produced by a [`HostFilter`] rejection (as opposed to an unrelated
/// `PermissionDenied` from the OS).
pub fn is_access_denied(err: &io::Error) -> bool {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<AccessDenied>())
        .is_some()
}

/// One destination match rule: an IP address, a CIDR subnet, an exact FQDN, or a `*.` wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FilterRule {
    Ip(IpAddr),
    Cidr {
        addr: IpAddr,
        prefix: u8,
    },
    /// Normalized lowercase domain without a trailing dot.
    DomainExact(String),
    /// Normalized lowercase suffix of a `*.<suffix>` rule (matches subdomains, not the apex).
    DomainWildcard(String),
}

impl FilterRule {
    /// Whether this rule matches IP addresses (IP literal or CIDR).
    pub fn is_ip_rule(&self) -> bool {
        matches!(self, Self::Ip(_) | Self::Cidr { .. })
    }

    /// Whether this rule matches `ip`. IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are also
    /// checked in their canonical IPv4 form so IPv4 rules cover them.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        let canonical = canonical_ip(ip);
        match *self {
            Self::Ip(rule_ip) => {
                let rule_canonical = canonical_ip(rule_ip);
                ip == rule_ip || canonical == rule_canonical
            }
            Self::Cidr { addr, prefix } => {
                cidr_contains(addr, prefix, ip) || cidr_contains(addr, prefix, canonical)
            }
            Self::DomainExact(_) | Self::DomainWildcard(_) => false,
        }
    }

    /// Whether this rule matches a normalized lowercase domain (without trailing dot).
    pub fn matches_domain(&self, domain: &str) -> bool {
        match self {
            Self::DomainExact(exact) => domain == exact,
            Self::DomainWildcard(suffix) => {
                domain.len() > suffix.len() + 1
                    && domain.ends_with(suffix.as_str())
                    && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            }
            Self::Ip(_) | Self::Cidr { .. } => false,
        }
    }
}

impl fmt::Display for FilterRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Cidr { addr, prefix } => write!(f, "{addr}/{prefix}"),
            Self::DomainExact(d) => f.write_str(d),
            Self::DomainWildcard(s) => write!(f, "*.{s}"),
        }
    }
}

impl FromStr for FilterRule {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let s = raw.trim();
        if s.is_empty() {
            return Err("filter rule cannot be empty".into());
        }

        // CIDR: `<ip>/<prefix>`
        if let Some((addr_part, prefix_part)) = s.split_once('/') {
            let bare = strip_brackets(addr_part);
            let addr: IpAddr = bare
                .parse()
                .map_err(|_| format!("invalid CIDR address in {raw:?}"))?;
            let prefix: u8 = prefix_part
                .parse()
                .map_err(|_| format!("invalid CIDR prefix length in {raw:?}"))?;
            let max_prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max_prefix {
                return Err(format!(
                    "CIDR prefix /{prefix} exceeds /{max_prefix} in {raw:?}"
                ));
            }
            let masked = mask_ip(addr, prefix);
            return Ok(Self::Cidr {
                addr: masked,
                prefix,
            });
        }

        // Literal IP (with optional `[...]` brackets for IPv6)
        let bare = strip_brackets(s);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(Self::Ip(canonical_ip(ip)));
        }

        // Reject malformed bracketed inputs that didn't parse as an IP.
        if s.contains('[') || s.contains(']') {
            return Err(format!("invalid IP address in filter rule {raw:?}"));
        }

        // FQDN or `*.<domain>` wildcard
        let lowered = s.to_ascii_lowercase();
        let trimmed = lowered.strip_suffix('.').unwrap_or(&lowered);
        if let Some(suffix) = trimmed.strip_prefix("*.") {
            validate_domain(suffix, raw)?;
            return Ok(Self::DomainWildcard(suffix.to_string()));
        }
        if trimmed.contains('*') {
            return Err(format!(
                "invalid wildcard in filter rule {raw:?}: only a leading `*.` prefix is supported"
            ));
        }
        validate_domain(trimmed, raw)?;
        Ok(Self::DomainExact(trimmed.to_string()))
    }
}

/// Mutually exclusive destination filter policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFilter {
    Allow(Vec<FilterRule>),
    Block(Vec<FilterRule>),
}

impl HostFilter {
    /// Policy mode label for summaries and logs (`allow` or `block`).
    pub fn mode_str(&self) -> &'static str {
        match self {
            Self::Allow(_) => "allow",
            Self::Block(_) => "block",
        }
    }

    /// Number of rules in this filter.
    pub fn len(&self) -> usize {
        self.rules().len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules().is_empty()
    }

    pub fn rules(&self) -> &[FilterRule] {
        match self {
            Self::Allow(rules) | Self::Block(rules) => rules,
        }
    }

    /// Whether any rule in this filter can match an IP address.
    pub fn has_ip_rules(&self) -> bool {
        self.rules().iter().any(FilterRule::is_ip_rule)
    }

    /// Whether any rule in this filter matches `ip`.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        self.rules().iter().any(|r| r.matches_ip(ip))
    }

    /// Whether any rule in this filter matches `domain` (case-insensitive, trailing dot ignored).
    pub fn matches_domain(&self, domain: &str) -> bool {
        let normalized = normalize_domain(domain);
        self.rules().iter().any(|r| r.matches_domain(&normalized))
    }

    /// Check a destination host string (literal IP or domain) without resolving DNS.
    pub fn check_host(&self, host: &str) -> Result<(), AccessDenied> {
        let bare = strip_brackets(host);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return self.check_ip(ip);
        }
        let domain = normalize_domain(bare);
        match self {
            Self::Allow(rules) => {
                if rules.iter().any(|r| r.matches_domain(&domain)) {
                    Ok(())
                } else {
                    Err(AccessDenied(format!(
                        "destination {host} is not in allowlist"
                    )))
                }
            }
            Self::Block(rules) => {
                if rules.iter().any(|r| r.matches_domain(&domain)) {
                    Err(AccessDenied(format!("destination {host} is blocklisted")))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Check a single IP address against this policy's IP/CIDR rules.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), AccessDenied> {
        match self {
            Self::Allow(rules) => {
                if rules.iter().any(|r| r.matches_ip(ip)) {
                    Ok(())
                } else {
                    Err(AccessDenied(format!(
                        "destination {ip} is not in allowlist"
                    )))
                }
            }
            Self::Block(rules) => {
                if rules.iter().any(|r| r.matches_ip(ip)) {
                    Err(AccessDenied(format!("destination {ip} is blocklisted")))
                } else {
                    Ok(())
                }
            }
        }
    }
}

pub(crate) fn normalize_domain(host: &str) -> String {
    let lowered = host.trim().to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
}

fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

fn mask_ip(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

fn cidr_contains(network: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(candidate)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(candidate) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(candidate)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(candidate) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

fn validate_domain(domain: &str, raw: &str) -> Result<(), String> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(format!("invalid domain in filter rule {raw:?}"));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid domain label in filter rule {raw:?}"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(format!("invalid character in domain filter rule {raw:?}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str) -> FilterRule {
        s.parse().unwrap()
    }

    #[test]
    fn parses_ip_cidr_and_domain_rules() {
        assert_eq!(
            rule("127.0.0.1"),
            FilterRule::Ip("127.0.0.1".parse().unwrap())
        );
        assert_eq!(rule("[::1]"), FilterRule::Ip("::1".parse().unwrap()));
        assert_eq!(
            rule("10.1.2.3/8"),
            FilterRule::Cidr {
                addr: "10.0.0.0".parse().unwrap(),
                prefix: 8,
            }
        );
        assert_eq!(
            rule("fe80::1/10"),
            FilterRule::Cidr {
                addr: "fe80::".parse().unwrap(),
                prefix: 10,
            }
        );
        assert_eq!(
            rule("Example.COM."),
            FilterRule::DomainExact("example.com".into())
        );
        assert_eq!(
            rule("*.Example.COM"),
            FilterRule::DomainWildcard("example.com".into())
        );
    }

    #[test]
    fn rejects_invalid_rules() {
        for bad in [
            "",
            "   ",
            "*",
            "*.",
            "foo.*.example.com",
            "a*b.example.com",
            "127.0.0.1/33",
            "::1/129",
            "not-an-ip/24",
            "10.0.0.0/abc",
            "example.com:443",
            "http://example.com",
            "bad..example.com",
            "[not-ipv6]",
        ] {
            assert!(
                bad.parse::<FilterRule>().is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn ip_and_cidr_matching_handles_ipv4_mapped_ipv6_and_edge_prefixes() {
        let loopback = rule("127.0.0.0/8");
        assert!(loopback.matches_ip("127.0.0.1".parse().unwrap()));
        assert!(loopback.matches_ip("127.255.255.254".parse().unwrap()));
        assert!(loopback.matches_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!loopback.matches_ip("128.0.0.1".parse().unwrap()));
        assert!(!loopback.matches_ip("::1".parse().unwrap()));

        let all_v4 = rule("0.0.0.0/0");
        assert!(all_v4.matches_ip("1.2.3.4".parse().unwrap()));
        assert!(!all_v4.matches_ip("::1".parse().unwrap()));

        let host_v4 = rule("192.168.1.5/32");
        assert!(host_v4.matches_ip("192.168.1.5".parse().unwrap()));
        assert!(!host_v4.matches_ip("192.168.1.6".parse().unwrap()));

        let all_v6 = rule("::/0");
        assert!(all_v6.matches_ip("2001:db8::1".parse().unwrap()));
        assert!(!all_v6.matches_ip("1.2.3.4".parse().unwrap()));

        let exact_ip = rule("127.0.0.1");
        assert!(exact_ip.matches_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn wildcard_and_exact_domain_matching() {
        let wild = rule("*.example.com");
        assert!(wild.matches_domain("a.example.com"));
        assert!(wild.matches_domain("a.b.example.com"));
        assert!(!wild.matches_domain("example.com"));
        assert!(!wild.matches_domain("notexample.com"));

        let exact = rule("example.com");
        assert!(exact.matches_domain("example.com"));
        assert!(!exact.matches_domain("a.example.com"));
    }

    #[test]
    fn allowlist_and_blocklist_check_host() {
        let allow = HostFilter::Allow(vec![rule("*.example.com"), rule("10.0.0.0/8")]);
        assert!(allow.check_host("api.example.com").is_ok());
        assert!(allow.check_host("API.EXAMPLE.COM.").is_ok());
        assert!(allow.check_host("example.com").is_err());
        assert!(allow.check_host("10.1.2.3").is_ok());
        assert!(allow.check_host("192.168.1.1").is_err());

        let block = HostFilter::Block(vec![rule("127.0.0.0/8"), rule("::1"), rule("*.internal")]);
        assert!(block.check_host("127.0.0.1").is_err());
        assert!(block.check_host("[::1]").is_err());
        assert!(block.check_host("db.internal").is_err());
        assert!(block.check_host("example.com").is_ok());
        assert!(block.check_host("1.1.1.1").is_ok());
    }

    #[test]
    fn access_denied_io_error_is_detected() {
        let err = access_denied_error(AccessDenied("blocked".into()));
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(is_access_denied(&err));

        let other = io::Error::new(io::ErrorKind::PermissionDenied, "plain");
        assert!(!is_access_denied(&other));
    }
}
