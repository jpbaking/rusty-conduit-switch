//! HTTP/HTTPS proxy connection dispatcher wired to the Auto Switch [`Router`].
//!
//! Every accepted HTTP connection is served by `hyper` 1.x (`http1` server, upgrades
//! enabled). Each request is routed and dispatched by method:
//!
//! * `CONNECT host:port` → [`tunnel`]: routed with `scheme = "https"` (no URL), dialed
//!   through the decision's failover chain, then relayed as an opaque TCP tunnel.
//! * anything else → [`forward`]: routed with `scheme = "http"` and the full URL, then
//!   forwarded in absolute-form to an `http` / `https` upstream proxy, or in origin-form over
//!   an [`UpstreamDialer`](crate::upstream::UpstreamDialer) tunnel (`direct`, `socks5`,
//!   `socks4a`).
//!
//! When MITM is enabled ([`HttpProxy::with_mitm`]), every valid `CONNECT` is answered with
//! `200` and handed to [`mitm_tunnel::MitmInterceptor`] instead of the opaque tunnel: TLS is
//! terminated with a leaf signed by the user-supplied CA and upstream TLS runs over the
//! routed [`UpstreamStream`](crate::upstream::UpstreamStream).
//!
//! Hot-reload: each client connection takes one lock-free snapshot of the shared
//! [`RuntimeConfig`](crate::reload::RuntimeConfig) when it is accepted and routes every
//! request on it with that snapshot, so tunnels opened before a reload keep the routing they
//! started with while new connections see the new tables. MITM tunnels with URL rules
//! re-load the live state for every decrypted request.
//!
//! A route that resolves to `block`, or a target denied by the global filter, gets
//! `403 Forbidden`. Nothing is cached: every request/tunnel opens a fresh upstream
//! connection, bodies are streamed frame by frame, and every access record carries the
//! `rule`, `profile`, and redacted `upstream` of the routing decision.
//!
//! [`Router`]: crate::router::Router

pub mod forward;
pub mod mitm_tunnel;
pub mod tunnel;

use std::convert::Infallible;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::Inbound;
use crate::logging::{AccessLogger, HttpAccessRecord, Logger};
use crate::router::{RouteDecision, RouteRequest};
use crate::server::{Connection, RoutingState, SharedRouting};
use mitm_tunnel::{MitmConnect, MitmInterceptor};

/// Boxed error type used by proxied bodies.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Response body type produced by the proxy (streamed, never buffered in full).
pub type ProxyBody = BoxBody<Bytes, BoxError>;

/// A validated `CONNECT` target (`host:port`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    /// Hostname or IP literal (IPv6 without brackets).
    pub host: String,
    pub port: u16,
}

impl ConnectTarget {
    /// Parse a `CONNECT` authority (`host:port`, `[v6]:port`). The port is mandatory and
    /// must be non-zero; userinfo, paths, and whitespace are rejected.
    pub fn parse(authority: &str) -> Option<Self> {
        let (host, port) = authority.rsplit_once(':')?;
        let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
        let host = match host.strip_prefix('[') {
            Some(rest) => rest.strip_suffix(']')?,
            None if host.contains(':') => return None,
            None => host,
        };
        let invalid = |c: char| c.is_whitespace() || matches!(c, '/' | '@' | '[' | ']');
        if host.is_empty() || host.chars().any(invalid) {
            return None;
        }
        Some(Self {
            host: host.to_string(),
            port,
        })
    }

    /// `host:port`, bracketing IPv6 literals.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for ConnectTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.authority())
    }
}

/// The HTTP/HTTPS proxy engine. Cheap to clone.
#[derive(Clone)]
pub struct HttpProxy {
    pub(crate) access: AccessLogger,
    pub(crate) logger: Logger,
    pub(crate) routing: SharedRouting,
    pub(crate) mitm: Option<Arc<MitmInterceptor>>,
}

impl fmt::Debug for HttpProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpProxy")
            .field("routing", &*self.routing.load())
            .field("mitm", &self.mitm.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpProxy {
    pub fn new(routing: SharedRouting, access: AccessLogger, logger: Logger) -> Self {
        Self {
            access,
            logger,
            routing,
            mitm: None,
        }
    }

    /// Enable HTTPS interception: every `CONNECT` is handled by `interceptor`.
    pub fn with_mitm(mut self, interceptor: Arc<MitmInterceptor>) -> Self {
        self.mitm = Some(interceptor);
        self
    }

    /// Whether HTTPS interception is enabled.
    pub fn mitm_enabled(&self) -> bool {
        self.mitm.is_some()
    }

    /// The current routing snapshot.
    pub fn routing(&self) -> Arc<RoutingState> {
        self.routing.load_full()
    }

    /// Serve one client connection until it closes or the server shuts down. Tunnels and
    /// upstream connection drivers spawned for this connection are awaited before returning,
    /// so the server's drain accounting covers them.
    pub async fn serve(&self, conn: Connection) {
        let Connection {
            stream,
            peer,
            shutdown,
            ..
        } = conn;
        let tasks = TaskTracker::new();
        let ctx = RequestCtx {
            state: self.routing(),
            proxy: self.clone(),
            peer,
            shutdown: shutdown.clone(),
            tasks: tasks.clone(),
        };
        let service = service_fn(move |req| {
            let ctx = ctx.clone();
            async move { Ok::<_, Infallible>(ctx.dispatch(req).await) }
        });
        let conn = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades();
        let mut conn = std::pin::pin!(conn);
        let result = tokio::select! {
            res = conn.as_mut() => res,
            () = shutdown.cancelled() => {
                conn.as_mut().graceful_shutdown();
                conn.as_mut().await
            }
        };
        if let Err(e) = result {
            self.logger
                .debug(format!("HTTP connection from {peer} ended with error: {e}"));
        }
        tasks.close();
        tasks.wait().await;
    }
}

/// Per-connection request context shared by [`forward`] and [`tunnel`].
#[derive(Clone)]
pub(crate) struct RequestCtx {
    pub(crate) proxy: HttpProxy,
    /// Runtime snapshot taken when the connection was accepted.
    pub(crate) state: Arc<RoutingState>,
    pub(crate) peer: SocketAddr,
    pub(crate) shutdown: CancellationToken,
    pub(crate) tasks: TaskTracker,
}

impl RequestCtx {
    async fn dispatch(&self, req: Request<Incoming>) -> Response<ProxyBody> {
        if req.method() != Method::CONNECT {
            return forward::handle(self, req).await;
        }
        match self.proxy.mitm.clone() {
            Some(mitm) => self.mitm_connect(mitm, req),
            None => tunnel::handle(self, req).await,
        }
    }

    /// Answer a MITM `CONNECT` with `200` and intercept the upgraded stream. Invalid targets
    /// get `400` and filter-denied destinations `403` before the tunnel is established.
    fn mitm_connect(
        &self,
        mitm: Arc<MitmInterceptor>,
        req: Request<Incoming>,
    ) -> Response<ProxyBody> {
        let authority = req.uri().authority().map(|a| a.as_str().to_string());
        let Some(target) = authority.as_deref().and_then(ConnectTarget::parse) else {
            let mut guard =
                self.access_guard("https", true, "CONNECT", authority.unwrap_or_default());
            guard.set_status(StatusCode::BAD_REQUEST);
            return error_response(StatusCode::BAD_REQUEST, "CONNECT target must be host:port");
        };
        let state = Arc::clone(&self.state);
        let live = Arc::clone(&self.proxy.routing);
        let route_req = RouteRequest {
            inbound: Inbound::Http,
            host: &target.host,
            port: target.port,
            scheme: Some("https"),
            url: None,
        };
        if let Err(denied) = state.router.route(&route_req) {
            let mut guard = self.access_guard("https", true, "CONNECT", target.authority());
            guard.set_status(StatusCode::FORBIDDEN);
            self.proxy.logger.info(format!(
                "CONNECT {target} from {} denied by filter: {denied}",
                self.peer
            ));
            return error_response(StatusCode::FORBIDDEN, "destination not allowed");
        }
        let (client, shutdown) = (self.peer, self.shutdown.clone());
        let (access, logger) = (self.proxy.access.clone(), self.proxy.logger.clone());
        self.tasks.spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    mitm.intercept(MitmConnect {
                        upgraded: TokioIo::new(upgraded),
                        target,
                        client,
                        shutdown,
                        access,
                        logger,
                        state,
                        live,
                    })
                    .await
                }
                Err(e) => logger.debug(format!("CONNECT upgrade from {client} failed: {e}")),
            }
        });
        connect_established()
    }

    /// Start an access record for this request; it is emitted when the guard drops.
    pub(crate) fn access_guard(
        &self,
        proto: &str,
        mitm: bool,
        method: &str,
        target: String,
    ) -> AccessGuard {
        AccessGuard::new(
            self.proxy.access.clone(),
            self.tasks.clone(),
            HttpAccessRecord {
                ts: OffsetDateTime::now_utc(),
                client: self.peer,
                proto: proto.to_string(),
                mitm,
                method: method.to_string(),
                target,
                rule: String::new(),
                profile: String::new(),
                upstream: String::new(),
                status: 0,
                bytes_in: 0,
                bytes_out: 0,
                duration_ms: 0,
            },
        )
    }
}

/// Emits one [`HttpAccessRecord`] when dropped, filling in byte counters and duration.
///
/// The guard travels with the streamed response body, so the record is written once the
/// body has been fully delivered (or abandoned by the client).
pub struct AccessGuard {
    access: AccessLogger,
    tasks: TaskTracker,
    record: Option<HttpAccessRecord>,
    started: Instant,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
}

impl AccessGuard {
    pub fn new(access: AccessLogger, tasks: TaskTracker, record: HttpAccessRecord) -> Self {
        Self {
            access,
            tasks,
            record: Some(record),
            started: Instant::now(),
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn set_status(&mut self, status: StatusCode) {
        if let Some(r) = self.record.as_mut() {
            r.status = status.as_u16();
        }
    }

    /// Record the routing decision (`rule`, `profile`) and the redacted `upstream`.
    pub fn set_route(&mut self, rule: &str, profile: String, upstream: String) {
        if let Some(r) = self.record.as_mut() {
            r.rule = rule.to_string();
            r.profile = profile;
            r.upstream = upstream;
        }
    }

    /// Counter for bytes received from the client.
    pub fn bytes_in(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.bytes_in)
    }

    /// Counter for bytes sent to the client.
    pub fn bytes_out(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.bytes_out)
    }
}

impl Drop for AccessGuard {
    fn drop(&mut self) {
        let Some(mut record) = self.record.take() else {
            return;
        };
        record.bytes_in = self.bytes_in.load(Ordering::Relaxed);
        record.bytes_out = self.bytes_out.load(Ordering::Relaxed);
        record.duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        if !self.access.http_enabled() || tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let access = self.access.clone();
        self.tasks
            .spawn(async move { access.log_http(&record).await });
    }
}

/// Streams an inner body unchanged while counting data bytes; optionally owns an
/// [`AccessGuard`] so the access record is emitted when the body finishes.
pub struct CountingBody<B> {
    inner: B,
    counter: Arc<AtomicU64>,
    _guard: Option<AccessGuard>,
}

impl<B> CountingBody<B> {
    pub fn new(inner: B, counter: Arc<AtomicU64>, guard: Option<AccessGuard>) -> Self {
        Self {
            inner,
            counter,
            _guard: guard,
        }
    }
}

impl<B> Body for CountingBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    self.counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// `200 Connection Established` with an empty body.
pub fn connect_established() -> Response<ProxyBody> {
    let mut resp = Response::new(empty_body());
    resp.extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(
            b"Connection Established",
        ));
    resp
}

/// A short `text/plain` error response generated by the proxy itself.
pub fn error_response(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from(format!("{msg}\n")))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn empty_body() -> ProxyBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

/// Map an upstream dial error to the proxy status code (`403` when the route is blocked or
/// the destination filtered, `504` on timeout, else `502`).
pub(crate) fn dial_error_status(e: &std::io::Error) -> StatusCode {
    if crate::upstream::is_route_blocked(e) || crate::filter::is_access_denied(e) {
        StatusCode::FORBIDDEN
    } else if e.kind() == std::io::ErrorKind::TimedOut {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::BAD_GATEWAY
    }
}

/// `rule=` / `profile=` / `upstream=` values for a dial that failed or was refused: the
/// decision's first target and its redacted upstream.
pub(crate) fn failed_route(state: &RoutingState, d: &RouteDecision) -> (String, String) {
    (d.profile_label(), state.first_upstream(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_target_parsing() {
        assert_eq!(
            ConnectTarget::parse("example.com:443"),
            Some(ConnectTarget {
                host: "example.com".into(),
                port: 443
            })
        );
        let v6 = ConnectTarget::parse("[::1]:8443").unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("::1", 8443));
        assert_eq!(v6.authority(), "[::1]:8443");
        for bad in [
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:99999",
            ":443",
            "::1:443",
            "[::1:443",
            "user@host:443",
            "host/path:443",
        ] {
            assert_eq!(ConnectTarget::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn connect_established_has_reason_phrase() {
        let resp = connect_established();
        assert_eq!(resp.status(), StatusCode::OK);
        let reason = resp.extensions().get::<hyper::ext::ReasonPhrase>().unwrap();
        assert_eq!(reason.as_bytes(), b"Connection Established");
    }

    #[test]
    fn route_blocked_and_filter_denials_map_to_403() {
        let blocked = crate::upstream::RouteBlocked {
            profile: "block".into(),
        }
        .into_io();
        assert_eq!(dial_error_status(&blocked), StatusCode::FORBIDDEN);
        let denied = crate::filter::access_denied_error(crate::filter::AccessDenied("x".into()));
        assert_eq!(dial_error_status(&denied), StatusCode::FORBIDDEN);
        let timeout = std::io::Error::new(std::io::ErrorKind::TimedOut, "t");
        assert_eq!(dial_error_status(&timeout), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            dial_error_status(&std::io::Error::other("x")),
            StatusCode::BAD_GATEWAY
        );
    }
}
