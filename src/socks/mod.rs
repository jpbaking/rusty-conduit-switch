//! SOCKS4/4a/5 server engine wired to the Auto Switch [`Router`](crate::router::Router).
//!
//! Only TCP `CONNECT` is supported (IPv4, IPv6, and domain targets); there is no inbound
//! authentication in v1. Every request is routed with `inbound = socks`, no scheme, and no
//! URL (SOCKS never sees one), then dialed through the decision's failover chain from the
//! [`ProfileRegistry`](crate::upstream::ProfileRegistry) — so a SOCKS client can be routed to
//! `direct`, `block`, or an `http` / `https` / `socks5` / `socks4a` upstream proxy.
//! Hostnames routed to a proxy are forwarded unresolved (no local DNS lookup).
//!
//! A `block` route or a global filter denial is answered with SOCKS5 reply `0x02`
//! (connection not allowed by ruleset) or SOCKS4 reply `0x5B`. Every session emits one
//! [`SocksLogRecord`] carrying `rule`, `profile`, and the redacted `upstream`.
//!
//! # Relay guard hook
//!
//! An optional [`RelayGuard`] can be installed with [`SocksProxy::with_guard`]. After the
//! SOCKS handshake succeeds and the upstream is connected, upstream → client bytes flow
//! immediately (server-speaks-first protocols are never delayed), but the **first**
//! client → upstream chunk is passed to [`RelayGuard::inspect`] before being forwarded. A
//! [`GuardVerdict::Block`] closes both sockets without forwarding it and records the
//! verdict's status label. Afterwards the relay switches to plain bidirectional copying.
//!
//! [`web_guard::WebGuard`] is the guard used for `--socks-block-web-in-mitm`.

pub mod v4;
pub mod v5;
pub mod web_guard;

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::config::Inbound;
use crate::http::tunnel::CountingStream;
use crate::logging::{AccessLogger, Logger, SocksLogRecord};
use crate::mux::{self, DetectedProtocol};
use crate::net::relay_bidirectional;
use crate::router::RouteRequest;
use crate::server::{Connection, RoutingState, SharedRouting};
use crate::upstream::{is_route_blocked, UpstreamStream};

/// Default bound on the SOCKS greeting + request exchange.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum length of SOCKS4 user IDs and SOCKS4a domain names.
pub(crate) const MAX_CSTRING_LEN: usize = 255;

/// Size of the buffers used while waiting for the first client chunk under a guard.
const GUARD_BUF_SIZE: usize = 16 * 1024;

/// Decision returned by a [`RelayGuard`] for the first client → upstream chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardVerdict {
    /// Forward the chunk and continue relaying.
    Allow,
    /// Drop the chunk, close both sockets, and log `status` (e.g. `blocked_web_in_mitm`).
    Block { status: String },
}

/// Inspector for the first client → upstream payload chunk of a SOCKS session.
pub trait RelayGuard: Send + Sync + 'static {
    fn inspect(&self, target: &SocksTarget, first_chunk: &[u8]) -> GuardVerdict;
}

/// Destination host of a SOCKS request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetHost {
    Ip(IpAddr),
    Domain(String),
}

/// Destination of a SOCKS `CONNECT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksTarget {
    pub host: TargetHost,
    pub port: u16,
}

impl SocksTarget {
    /// The host as passed to the router and dialers (IP literal or unresolved domain).
    pub fn dial_host(&self) -> String {
        match &self.host {
            TargetHost::Ip(ip) => ip.to_string(),
            TargetHost::Domain(d) => d.clone(),
        }
    }
}

impl fmt::Display for SocksTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            TargetHost::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            TargetHost::Ip(IpAddr::V4(ip)) => write!(f, "{ip}:{}", self.port),
            TargetHost::Domain(d) => write!(f, "{d}:{}", self.port),
        }
    }
}

/// Why a SOCKS request failed; maps to SOCKS5 reply codes and log `status=` labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    General,
    /// Route blocked (`block` profile) or destination denied by the global filter.
    NotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Failure {
    /// Classify an upstream dial error.
    pub fn from_dial_error(e: &io::Error) -> Self {
        if is_route_blocked(e) || crate::filter::is_access_denied(e) {
            return Self::NotAllowed;
        }
        match e.kind() {
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::TimedOut | io::ErrorKind::HostUnreachable => Self::HostUnreachable,
            io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            _ => Self::General,
        }
    }

    /// SOCKS5 `REP` byte.
    pub fn socks5_reply(self) -> u8 {
        match self {
            Self::General => 0x01,
            Self::NotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }

    /// `status=` value in the SOCKS log.
    pub fn label(self) -> &'static str {
        match self {
            Self::General => "general_failure",
            Self::NotAllowed => "not_allowed",
            Self::NetworkUnreachable => "network_unreachable",
            Self::HostUnreachable => "host_unreachable",
            Self::ConnectionRefused => "connection_refused",
            Self::CommandNotSupported => "command_not_supported",
            Self::AddressTypeNotSupported => "address_type_not_supported",
        }
    }
}

/// The SOCKS4/4a/5 engine. Cheap to clone.
#[derive(Clone)]
pub struct SocksProxy {
    pub(crate) access: AccessLogger,
    pub(crate) logger: Logger,
    pub(crate) routing: SharedRouting,
    pub(crate) handshake_timeout: Duration,
    pub(crate) guard: Option<Arc<dyn RelayGuard>>,
}

impl fmt::Debug for SocksProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksProxy")
            .field("routing", &*self.routing.load())
            .field("handshake_timeout", &self.handshake_timeout)
            .field("guard", &self.guard.is_some())
            .finish_non_exhaustive()
    }
}

impl SocksProxy {
    pub fn new(routing: SharedRouting, access: AccessLogger, logger: Logger) -> Self {
        Self {
            access,
            logger,
            routing,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            guard: None,
        }
    }

    /// Install a first-chunk relay guard (used by `--socks-block-web-in-mitm`).
    pub fn with_guard(mut self, guard: Arc<dyn RelayGuard>) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Whether a relay guard is installed.
    pub fn has_guard(&self) -> bool {
        self.guard.is_some()
    }

    /// Override the handshake timeout (default [`DEFAULT_HANDSHAKE_TIMEOUT`]).
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Serve a connection whose version byte has not been sniffed yet.
    pub async fn serve(&self, conn: Connection) {
        let sniffed = tokio::select! {
            () = conn.shutdown.cancelled() => return,
            res = mux::sniff_protocol(&conn.stream, self.handshake_timeout) => res,
        };
        match sniffed {
            Ok(DetectedProtocol::Socks4) => self.serve_v4(conn).await,
            Ok(DetectedProtocol::Socks5) => self.serve_v5(conn).await,
            Ok(DetectedProtocol::Http) => self.logger.debug(format!(
                "rejected SOCKS connection from {}: HTTP request on SOCKS port",
                conn.peer
            )),
            Ok(DetectedProtocol::Unknown(b)) => self.logger.debug(format!(
                "rejected SOCKS connection from {}: unknown version byte 0x{b:02x}",
                conn.peer
            )),
            Err(e) => self
                .logger
                .debug(format!("rejected SOCKS connection from {}: {e}", conn.peer)),
        }
    }

    /// Serve a SOCKS4/4a connection (first byte `0x04`, unread).
    pub async fn serve_v4(&self, conn: Connection) {
        v4::serve(self, conn).await;
    }

    /// Serve a SOCKS5 connection (first byte `0x05`, unread).
    pub async fn serve_v5(&self, conn: Connection) {
        v5::serve(self, conn).await;
    }

    /// Run `fut` bounded by the handshake timeout and server shutdown.
    pub(crate) async fn bounded<T>(
        &self,
        shutdown: &CancellationToken,
        peer: SocketAddr,
        what: &str,
        fut: impl std::future::Future<Output = T>,
    ) -> Option<T> {
        tokio::select! {
            () = shutdown.cancelled() => {
                self.logger.debug(format!("{what} from {peer} aborted by shutdown"));
                None
            }
            res = tokio::time::timeout(self.handshake_timeout, fut) => match res {
                Ok(v) => Some(v),
                Err(_) => {
                    self.logger.debug(format!(
                        "{what} from {peer} timed out after {}",
                        humantime::format_duration(self.handshake_timeout)
                    ));
                    None
                }
            },
        }
    }

    /// Route `target` and dial the decision's failover chain, recording `rule` / `profile`
    /// / `upstream` on `session`. Returns `None` if the server shut down meanwhile.
    pub(crate) async fn route_and_dial(
        &self,
        session: &mut Session,
        target: &SocksTarget,
        shutdown: &CancellationToken,
    ) -> Option<Result<UpstreamStream, Failure>> {
        let state: Arc<RoutingState> = self.routing.load_full();
        let host = target.dial_host();
        let proto = session.proto;
        let decision =
            match state
                .router
                .route(&RouteRequest::new(Inbound::Socks, &host, target.port))
            {
                Ok(d) => d,
                Err(denied) => {
                    self.logger.info(format!(
                        "{proto} {target} from {} denied by filter: {denied}",
                        session.client
                    ));
                    return Some(Err(Failure::NotAllowed));
                }
            };
        session.rule = decision.rule_label().to_string();
        session.profile = decision.profile_label();
        session.upstream = state.first_upstream(&decision);
        let chain = match state.registry.chain_for(&decision.targets) {
            Ok(c) => c.with_logger(self.logger.clone()),
            Err(e) => {
                self.logger.error(format!("{proto} {target}: {e}"));
                return Some(Err(Failure::General));
            }
        };
        let dial = chain.dial(&host, target.port, state.connect_timeout);
        let res = tokio::select! {
            () = shutdown.cancelled() => return None,
            res = dial => res,
        };
        Some(match res {
            Ok(outcome) => {
                session.profile = decision
                    .targets
                    .get(outcome.attempt)
                    .map(|t| t.label())
                    .unwrap_or(outcome.profile);
                session.upstream = outcome.upstream;
                self.logger.debug(format!(
                    "{proto} {target} from {}: rule={} profile={} upstream={}",
                    session.client, session.rule, session.profile, session.upstream
                ));
                Ok(outcome.stream)
            }
            Err(e) => {
                let failure = Failure::from_dial_error(&e);
                let msg = format!(
                    "{proto} {target}: rule={} profile={} upstream={}",
                    session.rule, session.profile, session.upstream
                );
                if failure == Failure::NotAllowed {
                    self.logger.info(format!("{msg} blocked"));
                } else {
                    self.logger.error(format!("{msg} failed: {e}"));
                }
                Err(failure)
            }
        })
    }

    /// Relay the client and upstream until both close (or shutdown), first passing the
    /// initial client chunk through the [`RelayGuard`] when one is installed. Returns
    /// `(status, bytes_in, bytes_out)`.
    pub(crate) async fn relay(
        &self,
        conn: &mut Connection,
        mut upstream: UpstreamStream,
        target: &SocksTarget,
    ) -> (String, u64, u64) {
        let bytes_in = Arc::new(AtomicU64::new(0));
        let bytes_out = Arc::new(AtomicU64::new(0));
        let peer = conn.peer;
        let shutdown = conn.shutdown.clone();
        let mut client = CountingStream::new(&mut conn.stream, bytes_in.clone(), bytes_out.clone());
        let guard = self.guard.clone();
        let work = async {
            if let Some(guard) = guard {
                if let GuardVerdict::Block { status } =
                    guarded_first_chunk(&mut client, &mut upstream, guard.as_ref(), target).await?
                {
                    return Ok(Some(status));
                }
            }
            relay_bidirectional(&mut client, &mut upstream).await?;
            Ok::<_, io::Error>(None)
        };
        let status = tokio::select! {
            res = work => match res {
                Ok(Some(blocked)) => {
                    self.logger.info(format!(
                        "SOCKS session {peer} -> {target} blocked: {blocked}"
                    ));
                    blocked
                }
                Ok(None) => "ok".to_string(),
                Err(e) => {
                    self.logger.debug(format!("SOCKS session {peer} -> {target} ended: {e}"));
                    "ok".to_string()
                }
            },
            () = shutdown.cancelled() => {
                self.logger.debug(format!("SOCKS session {peer} -> {target} closed by shutdown"));
                "ok".to_string()
            }
        };
        (
            status,
            bytes_in.load(Ordering::Relaxed),
            bytes_out.load(Ordering::Relaxed),
        )
    }
}

/// Forward upstream → client data while waiting for the first client chunk, then ask the
/// guard about it. Allowed chunks are written upstream before returning.
async fn guarded_first_chunk<C, U>(
    client: &mut C,
    upstream: &mut U,
    guard: &dyn RelayGuard,
    target: &SocksTarget,
) -> io::Result<GuardVerdict>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut cbuf = vec![0u8; GUARD_BUF_SIZE];
    let mut ubuf = vec![0u8; GUARD_BUF_SIZE];
    let mut upstream_eof = false;
    loop {
        tokio::select! {
            n = client.read(&mut cbuf) => {
                let n = n?;
                if n == 0 {
                    // Client half-closed without sending data: nothing to inspect.
                    return Ok(GuardVerdict::Allow);
                }
                let chunk = &cbuf[..n];
                let verdict = guard.inspect(target, chunk);
                if verdict == GuardVerdict::Allow {
                    upstream.write_all(chunk).await?;
                }
                return Ok(verdict);
            }
            n = upstream.read(&mut ubuf), if !upstream_eof => {
                let n = n?;
                if n == 0 {
                    upstream_eof = true;
                    client.shutdown().await?;
                } else {
                    client.write_all(&ubuf[..n]).await?;
                }
            }
        }
    }
}

/// Local address of the upstream socket, for the `BND.ADDR` reply field (only known for a
/// plain TCP upstream).
pub(crate) fn bound_addr(stream: &UpstreamStream) -> Option<SocketAddr> {
    match stream {
        UpstreamStream::Tcp(s) => s.local_addr().ok(),
        _ => None,
    }
}

/// One SOCKS session being logged.
pub(crate) struct Session {
    ts: OffsetDateTime,
    start: Instant,
    pub(crate) client: SocketAddr,
    pub(crate) proto: &'static str,
    pub(crate) cmd: String,
    pub(crate) target: String,
    pub(crate) rule: String,
    pub(crate) profile: String,
    pub(crate) upstream: String,
}

impl Session {
    pub(crate) fn new(client: SocketAddr, proto: &'static str) -> Self {
        Self {
            ts: OffsetDateTime::now_utc(),
            start: Instant::now(),
            client,
            proto,
            cmd: "-".into(),
            target: "-".into(),
            rule: String::new(),
            profile: String::new(),
            upstream: String::new(),
        }
    }

    pub(crate) async fn finish(self, access: &AccessLogger, status: &str, bin: u64, bout: u64) {
        let record = SocksLogRecord {
            ts: self.ts,
            client: self.client,
            proto: self.proto.into(),
            cmd: self.cmd,
            target: self.target,
            rule: self.rule,
            profile: self.profile,
            upstream: self.upstream,
            status: status.into(),
            bytes_in: bin,
            bytes_out: bout,
            duration_ms: u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        access.log_socks(&record).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_blocked_maps_to_not_allowed() {
        let blocked = crate::upstream::RouteBlocked {
            profile: "block".into(),
        }
        .into_io();
        let f = Failure::from_dial_error(&blocked);
        assert_eq!(f, Failure::NotAllowed);
        assert_eq!(f.socks5_reply(), 0x02);
        let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "x");
        assert_eq!(Failure::from_dial_error(&refused).socks5_reply(), 0x05);
    }

    #[test]
    fn target_display_brackets_ipv6() {
        let t = SocksTarget {
            host: TargetHost::Ip("::1".parse().unwrap()),
            port: 80,
        };
        assert_eq!(t.to_string(), "[::1]:80");
        let t = SocksTarget {
            host: TargetHost::Domain("nonexistent.invalid".into()),
            port: 443,
        };
        assert_eq!(t.dial_host(), "nonexistent.invalid");
    }
}
