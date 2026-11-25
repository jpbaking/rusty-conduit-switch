//! Upstream dialer and proxy chaining layer.
//!
//! Every outbound connection goes through an [`UpstreamDialer`], which returns an
//! [`UpstreamStream`]: a plain TCP socket, a TLS session (when talking to an `https` proxy),
//! or a [`PrefixedStream`] that first replays bytes read past an HTTP `CONNECT` response.
//!
//! Built-in dialers:
//! - [`DirectDialer`] (`direct`): OS/Tokio DNS, `TCP_NODELAY`, TCP keepalive.
//! - [`BlockDialer`] (`block`): typed [`RouteBlocked`] error without DNS or network I/O.
//! - [`Socks5Dialer`] (`socks5`): RFC 1928 + optional RFC 1929 auth, remote DNS (`ATYP=0x03`).
//! - [`Socks4aDialer`] (`socks4a`): SOCKS4a remote DNS (`0.0.0.1` + hostname).
//! - [`HttpConnectDialer`] (`http` and `https`): `CONNECT host:port` + optional Basic auth.
//!
//! Hostnames routed to a proxy are always sent **unresolved**. [`FailoverDialer`] walks an
//! ordered chain of dialers, advancing only on TCP connect / proxy handshake failure (never
//! on [`RouteBlocked`]). Credentials never appear in `Debug` output, logs, or error strings.

pub mod block;
pub mod direct;
pub mod http;
pub mod socks4a;
pub mod socks5;

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::config::{Config, ConfigError, ProfileConfig, ProfileType};
use crate::filter::HostFilter;
use crate::logging::Logger;
use crate::net::{KeepaliveSettings, PrefixedStream};
use crate::router::ResolvedTarget;

pub use block::BlockDialer;
pub use direct::DirectDialer;
pub use http::{HttpConnectDialer, TlsOptions};
pub use socks4a::Socks4aDialer;
pub use socks5::Socks5Dialer;

/// A connected upstream byte stream.
pub enum UpstreamStream {
    /// Plain TCP (direct dials, SOCKS proxies, `http` proxies).
    Tcp(TcpStream),
    /// TLS to an `https` proxy (boxed: the session state is large).
    Tls(Box<TlsStream<TcpStream>>),
    /// A stream with bytes read past a framing header (HTTP `CONNECT` response) to replay
    /// before the inner stream.
    Prefixed(Box<PrefixedStream<UpstreamStream>>),
}

impl UpstreamStream {
    /// Wrap `self` so `buffered` bytes are read first; returns `self` unchanged when empty.
    pub fn with_prefix(self, buffered: Vec<u8>) -> Self {
        if buffered.is_empty() {
            self
        } else {
            Self::Prefixed(Box::new(PrefixedStream::new(self, buffered)))
        }
    }
}

impl fmt::Debug for UpstreamStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(s) => f.debug_tuple("Tcp").field(s).finish(),
            Self::Tls(s) => f.debug_tuple("Tls").field(s.get_ref().0).finish(),
            Self::Prefixed(p) => f
                .debug_struct("Prefixed")
                .field("buffered", &p.buffered())
                .finish_non_exhaustive(),
        }
    }
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Self::Prefixed(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Self::Prefixed(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Self::Prefixed(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Self::Prefixed(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Boxed future returned by [`UpstreamDialer::connect`].
pub type DialFuture<'a> = Pin<Box<dyn Future<Output = io::Result<UpstreamStream>> + Send + 'a>>;

/// Opens upstream connections to `host:port`.
pub trait UpstreamDialer: Send + Sync {
    /// Connect to `host:port` (a DNS name or IP literal; IPv6 with or without brackets),
    /// bounding the whole operation — TCP connect plus any proxy handshake — by `timeout`.
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_>;

    /// Redacted description of the upstream (`socks5://127.0.0.1:1081`, `direct`, `block`)
    /// for logs; never carries credentials.
    fn redacted_upstream(&self) -> String;
}

/// Typed error returned by [`BlockDialer`]: the route resolved to a `block` profile.
///
/// Carried inside an [`io::Error`] of kind [`io::ErrorKind::PermissionDenied`]; detect it
/// with [`is_route_blocked`] / [`RouteBlocked::from_io`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("route blocked by profile `{profile}`")]
pub struct RouteBlocked {
    pub profile: String,
}

impl RouteBlocked {
    /// Wrap as an [`io::Error`] of kind `PermissionDenied`.
    pub fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, self)
    }

    /// The [`RouteBlocked`] carried by `err`, if any.
    pub fn from_io(err: &io::Error) -> Option<&RouteBlocked> {
        err.get_ref().and_then(|e| e.downcast_ref::<RouteBlocked>())
    }
}

/// Whether `err` is a [`RouteBlocked`] error.
pub fn is_route_blocked(err: &io::Error) -> bool {
    RouteBlocked::from_io(err).is_some()
}

/// Bounds a dial future by `timeout`, mapping expiry to [`io::ErrorKind::TimedOut`].
pub(crate) async fn with_timeout<F, T>(what: &str, timeout: Duration, fut: F) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    tokio::time::timeout(timeout, fut).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{what} timed out after {}",
                humantime::format_duration(timeout)
            ),
        )
    })?
}

/// Strip `[...]` from a bracketed IPv6 literal.
pub(crate) fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// `host:port`, bracketing IPv6 literals.
pub(crate) fn host_port(host: &str, port: u16) -> String {
    let bare = strip_brackets(host);
    if bare.contains(':') {
        format!("[{bare}]:{port}")
    } else {
        format!("{bare}:{port}")
    }
}

/// A successful dial: the stream plus metadata for access logging.
#[derive(Debug)]
pub struct DialOutcome {
    pub stream: UpstreamStream,
    /// Name of the profile that connected.
    pub profile: String,
    /// Redacted upstream URI of that profile (no credentials).
    pub upstream: String,
    /// 0-based position of the successful attempt within the chain.
    pub attempt: usize,
}

/// Error building a dialer from a profile.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("profile `{profile}`: {message}")]
    Profile { profile: String, message: String },
    #[error("unknown profile `{0}`")]
    UnknownProfile(String),
}

/// Settings shared by every dialer built from configuration.
#[derive(Debug, Clone, Default)]
pub struct DialerOptions {
    /// TCP keepalive on upstream sockets (`None` disables).
    pub keepalive: Option<KeepaliveSettings>,
    /// Destination filter enforced by `direct` dials (domain and resolved IP).
    pub filter: Option<Arc<HostFilter>>,
    /// Extra trust anchors for `https` proxies (when non-empty they replace the OS store).
    pub tls_roots: Vec<CertificateDer<'static>>,
}

/// Build the dialer for one profile. `composite` profiles have no dialer of their own (the
/// router resolves them to a concrete profile first).
pub fn dialer_for_profile(
    name: &str,
    profile: &ProfileConfig,
    opts: &DialerOptions,
) -> Result<Option<Arc<dyn UpstreamDialer>>, UpstreamError> {
    let endpoint = || -> Result<(String, u16), UpstreamError> {
        match (&profile.host, profile.port) {
            (Some(h), Some(p)) => Ok((h.clone(), p)),
            _ => Err(UpstreamError::Profile {
                profile: name.to_string(),
                message: format!("type `{}` requires host and port", profile.kind),
            }),
        }
    };
    let credentials = || -> Result<Option<(String, String)>, UpstreamError> {
        let password = profile.resolve_password(name)?;
        Ok(match (&profile.username, password) {
            (Some(u), p) => Some((u.clone(), p.unwrap_or_default())),
            (None, Some(p)) => Some((String::new(), p)),
            (None, None) => None,
        })
    };
    let dialer: Arc<dyn UpstreamDialer> = match profile.kind {
        ProfileType::Direct => {
            let mut d = DirectDialer::new().with_tcp_keepalive(opts.keepalive);
            if let Some(f) = &opts.filter {
                d = d.with_filter(f.clone());
            }
            Arc::new(d)
        }
        ProfileType::Block => Arc::new(BlockDialer::new(name)),
        ProfileType::Socks5 => {
            let (h, p) = endpoint()?;
            Arc::new(
                Socks5Dialer::new(h, p)
                    .with_credentials(credentials()?)
                    .with_tcp_keepalive(opts.keepalive),
            )
        }
        ProfileType::Socks4a => {
            let (h, p) = endpoint()?;
            Arc::new(
                Socks4aDialer::new(h, p)
                    .with_user_id(profile.username.clone().unwrap_or_default())
                    .with_tcp_keepalive(opts.keepalive),
            )
        }
        ProfileType::Http => {
            let (h, p) = endpoint()?;
            Arc::new(
                HttpConnectDialer::http(h, p)
                    .with_credentials(credentials()?)
                    .with_tcp_keepalive(opts.keepalive),
            )
        }
        ProfileType::Https => {
            let (h, p) = endpoint()?;
            let tls = TlsOptions {
                insecure_skip_verify: profile.tls_insecure_skip_verify,
                roots: opts.tls_roots.clone(),
            };
            let d = HttpConnectDialer::https(h, p, &tls).map_err(|e| UpstreamError::Profile {
                profile: name.to_string(),
                message: format!("TLS setup failed: {e}"),
            })?;
            Arc::new(
                d.with_credentials(credentials()?)
                    .with_tcp_keepalive(opts.keepalive),
            )
        }
        ProfileType::Composite => return Ok(None),
    };
    Ok(Some(dialer))
}

/// Dialers for every concrete profile, keyed by profile name.
#[derive(Clone, Default)]
pub struct ProfileRegistry {
    dialers: BTreeMap<String, Arc<dyn UpstreamDialer>>,
}

impl fmt::Debug for ProfileRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.dialers.iter().map(|(k, d)| (k, d.redacted_upstream())))
            .finish()
    }
}

impl ProfileRegistry {
    /// Build dialers for `profiles` (resolving password sources once, up front).
    pub fn from_profiles(
        profiles: &BTreeMap<String, ProfileConfig>,
        opts: &DialerOptions,
    ) -> Result<Self, UpstreamError> {
        let mut dialers = BTreeMap::new();
        for (name, profile) in profiles {
            if let Some(d) = dialer_for_profile(name, profile, opts)? {
                dialers.insert(name.clone(), d);
            }
        }
        Ok(Self { dialers })
    }

    /// Build from a validated [`Config`] (declared plus built-in profiles), using its
    /// TCP keepalive settings.
    pub fn from_config(cfg: &Config, opts: DialerOptions) -> Result<Self, UpstreamError> {
        let opts = DialerOptions {
            keepalive: cfg.tcp_keepalive_settings(),
            ..opts
        };
        Self::from_profiles(&cfg.profiles_with_builtins(), &opts)
    }

    /// Register (or replace) a dialer under `name`.
    pub fn insert(&mut self, name: impl Into<String>, dialer: Arc<dyn UpstreamDialer>) {
        self.dialers.insert(name.into(), dialer);
    }

    /// The dialer for `name`.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn UpstreamDialer>> {
        self.dialers.get(name)
    }

    /// Number of registered dialers.
    pub fn len(&self) -> usize {
        self.dialers.len()
    }

    /// Whether no dialer is registered.
    pub fn is_empty(&self) -> bool {
        self.dialers.is_empty()
    }

    /// A [`FailoverDialer`] over profile `names`, in order.
    pub fn chain<S: AsRef<str>>(&self, names: &[S]) -> Result<FailoverDialer, UpstreamError> {
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            let name = name.as_ref();
            let dialer = self
                .get(name)
                .ok_or_else(|| UpstreamError::UnknownProfile(name.to_string()))?;
            entries.push((name.to_string(), dialer.clone()));
        }
        Ok(FailoverDialer::new(entries))
    }

    /// A [`FailoverDialer`] over a router decision's resolved targets (`profile` names).
    pub fn chain_for(&self, targets: &[ResolvedTarget]) -> Result<FailoverDialer, UpstreamError> {
        let names: Vec<&str> = targets.iter().map(|t| t.profile.as_str()).collect();
        self.chain(&names)
    }
}

/// Tries an ordered chain of dialers until one connects.
///
/// Each attempt is bounded by the dial timeout. A failure advances to the next entry
/// (logged at `DEBUG`), except [`RouteBlocked`], which stops the chain immediately. Failover
/// happens only while connecting: once a stream is returned the chain is done.
#[derive(Clone)]
pub struct FailoverDialer {
    entries: Vec<(String, Arc<dyn UpstreamDialer>)>,
    logger: Option<Logger>,
}

impl fmt::Debug for FailoverDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                self.entries
                    .iter()
                    .map(|(n, d)| format!("{n}={}", d.redacted_upstream())),
            )
            .finish()
    }
}

impl FailoverDialer {
    /// A chain of `(profile name, dialer)` entries, tried in order.
    pub fn new(entries: Vec<(String, Arc<dyn UpstreamDialer>)>) -> Self {
        Self {
            entries,
            logger: None,
        }
    }

    /// Log failed attempts at `DEBUG` through `logger`.
    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Number of entries in the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Dial `host:port` through the chain, returning the first successful stream plus which
    /// profile connected. When every entry fails, returns the last error with a summary.
    pub async fn dial(&self, host: &str, port: u16, timeout: Duration) -> io::Result<DialOutcome> {
        let target = host_port(host, port);
        let mut failures = Vec::new();
        let mut last_err: Option<io::Error> = None;
        for (attempt, (name, dialer)) in self.entries.iter().enumerate() {
            let upstream = dialer.redacted_upstream();
            let result = with_timeout(
                &format!("dial {target} via {upstream}"),
                timeout,
                dialer.connect(host, port, timeout),
            )
            .await;
            match result {
                Ok(stream) => {
                    return Ok(DialOutcome {
                        stream,
                        profile: name.clone(),
                        upstream,
                        attempt,
                    })
                }
                Err(e) if is_route_blocked(&e) => return Err(e),
                Err(e) => {
                    if let Some(logger) = &self.logger {
                        logger.debug(format!(
                            "failover: profile={name} upstream={upstream} target={target} \
                             attempt={attempt} error={e}"
                        ));
                    }
                    failures.push(format!("{name}: {e}"));
                    last_err = Some(e);
                }
            }
        }
        Err(match last_err {
            None => io::Error::new(io::ErrorKind::InvalidInput, "failover chain has no targets"),
            Some(e) if failures.len() == 1 => e,
            Some(e) => io::Error::new(
                e.kind(),
                format!(
                    "all {} upstream targets failed for {target}: {}",
                    failures.len(),
                    failures.join("; ")
                ),
            ),
        })
    }
}

impl UpstreamDialer for FailoverDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = host.to_string();
        Box::pin(async move { self.dial(&host, port, timeout).await.map(|o| o.stream) })
    }

    fn redacted_upstream(&self) -> String {
        self.entries
            .iter()
            .map(|(_, d)| d.redacted_upstream())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_blocked_round_trips_through_io_error() {
        let err = RouteBlocked {
            profile: "block".into(),
        }
        .into_io();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(is_route_blocked(&err));
        assert_eq!(RouteBlocked::from_io(&err).unwrap().profile, "block");
        assert!(!is_route_blocked(&io::Error::other("x")));
    }

    #[test]
    fn host_port_brackets_ipv6() {
        assert_eq!(host_port("::1", 80), "[::1]:80");
        assert_eq!(host_port("[::1]", 80), "[::1]:80");
        assert_eq!(host_port("a.example", 443), "a.example:443");
    }

    #[tokio::test]
    async fn empty_chain_errors() {
        let err = FailoverDialer::new(Vec::new())
            .dial("a", 1, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
