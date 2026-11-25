//! HTTPS `CONNECT` interception (MITM ON) over Auto Switch routed upstreams.
//!
//! After the client received `200 Connection Established` ([`super::RequestCtx`] hands the
//! upgraded stream to [`MitmInterceptor`]):
//!
//! 1. `tokio_rustls::LazyConfigAcceptor` reads the client's `ClientHello` (SNI + ALPN).
//!    The leaf host is the SNI, falling back to the `CONNECT` host/IP.
//! 2. Upstream connections are dialed through the routing snapshot taken at `CONNECT` time:
//!    [`Router`](crate::router::Router) decision → failover chain from the
//!    [`ProfileRegistry`](crate::upstream::ProfileRegistry) → an
//!    [`UpstreamStream`] (`direct`, `socks5`, `socks4a`, `http` / `https` `CONNECT`). Upstream
//!    TLS (`tokio-rustls` client, SNI = leaf host, verified with the platform verifier or an
//!    injected root store) then runs **over that stream**, so TLS-over-TLS to an `https`
//!    proxy works the same way as a plain TCP tunnel.
//! 3. The leaf certificate comes from the [`CertCache`] (signed on a miss) and the client
//!    TLS handshake is completed.
//! 4. Decrypted requests are served with `hyper` and forwarded upstream, streaming bodies
//!    frame by frame — **nothing is cached**.
//!
//! Two routing modes:
//!
//! * **No URL-level rules** (`url_wildcard`, `url_regex`, `keyword`) in the tables active for
//!   HTTP: the route is resolved **once** at `CONNECT` time, the upstream is dialed before the
//!   client handshake (so the client sees exactly the ALPN protocol, `h2` or `http/1.1`, the
//!   origin chose), and that upstream TLS connection is reused for every request on the
//!   tunnel (an HTTP/1.1 connection that closes is redialed through the same decision).
//! * **URL-level rules present**: every decrypted request is routed with its full
//!   `https://host/path?query` URL. The tunnel speaks HTTP/1.1 to the client and upstream
//!   connections are dialed lazily; a request whose decision resolves to a different
//!   failover chain than the current upstream connection dials a fresh connection through
//!   the new chain. A request routed to `block` gets `403 Forbidden`.
//!
//! HTTP/1.1 upgrades (`101 Switching Protocols`, e.g. WebSocket) are forwarded and then
//! relayed as raw bytes. One access record per decrypted request: `proto=https mitm=true`,
//! method, `https://authority/path`, `rule`, `profile`, redacted `upstream`, status, bytes,
//! duration. Upstream failures before any request are logged as one `method=CONNECT`
//! record.

use std::convert::Infallible;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::client::conn::{http1 as client_http1, http2 as client_http2};
use hyper::header::{self, HeaderValue};
use hyper::server::conn::{http1 as server_http1, http2 as server_http2};
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_platform_verifier::BuilderVerifierExt;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio_rustls::{client::TlsStream as ClientTlsStream, LazyConfigAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::forward::strip_hop_by_hop;
use super::tunnel::CountingStream;
use super::{
    dial_error_status, error_response, AccessGuard, ConnectTarget, CountingBody, ProxyBody,
};
use crate::config::Inbound;
use crate::logging::{AccessLogger, HttpAccessRecord, Logger};
use crate::mitm::cache::CertCache;
use crate::net::relay_bidirectional;
use crate::router::{RouteDecision, RouteRequest};
use crate::server::{RoutingState, SharedRouting};
use crate::upstream::UpstreamStream;

/// Bound on the client and upstream TLS handshakes.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Upstream TLS session over a routed upstream stream.
type UpstreamTls = ClientTlsStream<UpstreamStream>;
type ClientTls = tokio_rustls::server::TlsStream<TokioIo<Upgraded>>;
type H1Sender = client_http1::SendRequest<ProxyBody>;

/// Upstream TLS client config using the OS / platform certificate verifier.
pub fn platform_client_config(
    provider: Arc<CryptoProvider>,
) -> Result<ClientConfig, rustls::Error> {
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_platform_verifier()?
        .with_no_client_auth())
}

/// Upstream TLS client config trusting only `roots` (local integration tests, private PKI).
pub fn client_config_with_roots(
    provider: Arc<CryptoProvider>,
    roots: RootCertStore,
) -> Result<ClientConfig, rustls::Error> {
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// An intercepted `CONNECT`, handed to [`MitmInterceptor::intercept`] after the client
/// received `200 Connection Established`.
pub(crate) struct MitmConnect {
    /// The upgraded client stream (raw bytes after the `CONNECT` response).
    pub(crate) upgraded: TokioIo<Upgraded>,
    pub(crate) target: ConnectTarget,
    pub(crate) client: SocketAddr,
    /// Cancelled on server shutdown.
    pub(crate) shutdown: CancellationToken,
    pub(crate) access: AccessLogger,
    pub(crate) logger: Logger,
    /// Routing snapshot of the client connection; used for the whole tunnel unless URL
    /// rules are configured.
    pub(crate) state: Arc<RoutingState>,
    /// The live runtime handle: with URL rules every decrypted request loads a fresh
    /// snapshot from it (hot-reload).
    pub(crate) live: SharedRouting,
}

/// The MITM `CONNECT` handler. Cheap to clone.
#[derive(Clone)]
pub struct MitmInterceptor {
    cache: Arc<CertCache>,
    upstream_tls: Arc<ClientConfig>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for MitmInterceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmInterceptor")
            .field("cache", &self.cache)
            .finish_non_exhaustive()
    }
}

/// Serves one fixed leaf certificate (chosen before the handshake from the `ClientHello`).
#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// `rule=` / `profile=` / `upstream=` of one upstream connection (or failed attempt).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RouteInfo {
    rule: String,
    profile: String,
    upstream: String,
}

/// A failed route / dial: the status to report and the route fields to log.
#[derive(Debug)]
struct DialFailure {
    status: StatusCode,
    info: RouteInfo,
}

/// Opens upstream TLS connections to the `CONNECT` target through routed upstream chains.
#[derive(Clone)]
struct Dialer {
    tls: Arc<ClientConfig>,
    target: ConnectTarget,
    server_name: ServerName<'static>,
    state: Arc<RoutingState>,
    logger: Logger,
}

/// Identity of a decision's failover chain: requests whose chains are equal share an
/// upstream connection.
fn chain_key(d: &RouteDecision) -> String {
    d.targets
        .iter()
        .map(|t| t.profile.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

impl Dialer {
    /// Route the target, optionally with the full decrypted request URL.
    fn route(&self, url: Option<&str>) -> Result<RouteDecision, DialFailure> {
        let req = RouteRequest {
            inbound: Inbound::Http,
            host: &self.target.host,
            port: self.target.port,
            scheme: Some("https"),
            url,
        };
        self.state.router.route(&req).map_err(|denied| {
            self.logger.info(format!(
                "MITM {} denied by filter: {denied}",
                url.unwrap_or(&self.target.authority())
            ));
            DialFailure {
                status: StatusCode::FORBIDDEN,
                info: RouteInfo::default(),
            }
        })
    }

    /// Dial `decision`'s failover chain to the target and run upstream TLS over the stream.
    async fn connect(
        &self,
        decision: &RouteDecision,
        alpn: Vec<Vec<u8>>,
    ) -> Result<(UpstreamTls, RouteInfo), DialFailure> {
        let rule = decision.rule_label().to_string();
        let failed = |status: StatusCode| {
            let (profile, upstream) = super::failed_route(&self.state, decision);
            DialFailure {
                status,
                info: RouteInfo {
                    rule: rule.clone(),
                    profile,
                    upstream,
                },
            }
        };
        let target = &self.target;
        let chain = match self.state.registry.chain_for(&decision.targets) {
            Ok(c) => c.with_logger(self.logger.clone()),
            Err(e) => {
                self.logger.error(format!("MITM {target}: {e}"));
                return Err(failed(StatusCode::BAD_GATEWAY));
            }
        };
        let outcome = match chain
            .dial(&target.host, target.port, self.state.connect_timeout)
            .await
        {
            Ok(o) => o,
            Err(e) => {
                let status = dial_error_status(&e);
                let f = failed(status);
                if status == StatusCode::FORBIDDEN {
                    self.logger.info(format!(
                        "MITM {target} blocked: rule={rule} profile={} upstream={}",
                        f.info.profile, f.info.upstream
                    ));
                } else {
                    self.logger.error(format!(
                        "MITM upstream {target} failed: rule={rule} profile={} upstream={} \
                         error={e}",
                        f.info.profile, f.info.upstream
                    ));
                }
                return Err(f);
            }
        };
        let profile = decision
            .targets
            .get(outcome.attempt)
            .map(|t| t.label())
            .unwrap_or_else(|| outcome.profile.clone());
        let info = RouteInfo {
            rule,
            profile,
            upstream: outcome.upstream,
        };
        let mut cfg = (*self.tls).clone();
        cfg.alpn_protocols = alpn;
        let connector = TlsConnector::from(Arc::new(cfg));
        let tls = tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT,
            connector.connect(self.server_name.clone(), outcome.stream),
        )
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "upstream TLS handshake timed out",
            ))
        });
        match tls {
            Ok(tls) => {
                self.logger.debug(format!(
                    "MITM upstream {target}: rule={} profile={} upstream={}",
                    info.rule, info.profile, info.upstream
                ));
                Ok((tls, info))
            }
            Err(e) => {
                self.logger.error(format!(
                    "MITM upstream TLS to {target} (SNI {:?}) via profile={} failed: {e}",
                    self.server_name, info.profile
                ));
                Err(DialFailure {
                    status: dial_error_status(&e),
                    info,
                })
            }
        }
    }
}

/// The upstream HTTP/1.1 connection currently attached to a tunnel.
struct H1Upstream {
    sender: H1Sender,
    key: String,
    info: RouteInfo,
}

/// How a tunnel picks the upstream for each request.
#[derive(Clone)]
enum Routing {
    /// Resolved once at `CONNECT` time.
    Fixed {
        decision: Arc<RouteDecision>,
        info: RouteInfo,
    },
    /// Re-evaluated for every decrypted request (URL rules configured) against a fresh
    /// snapshot of the live runtime state.
    PerRequest(SharedRouting),
}

/// Per-tunnel state shared by every decrypted request.
#[derive(Clone)]
struct Session {
    access: AccessLogger,
    logger: Logger,
    tasks: TaskTracker,
    shutdown: CancellationToken,
    client: SocketAddr,
    /// Authority used when a request carries neither an absolute URI nor `Host`.
    default_authority: String,
    dialer: Dialer,
    routing: Routing,
}

impl MitmInterceptor {
    pub fn new(
        cache: Arc<CertCache>,
        upstream_tls: Arc<ClientConfig>,
        provider: Arc<CryptoProvider>,
    ) -> Self {
        Self {
            cache,
            upstream_tls,
            provider,
        }
    }

    pub fn cache(&self) -> &Arc<CertCache> {
        &self.cache
    }

    pub(crate) async fn intercept(&self, connect: MitmConnect) {
        let MitmConnect {
            upgraded,
            target,
            client,
            shutdown,
            access,
            logger,
            state,
            live,
        } = connect;
        let tasks = TaskTracker::new();
        let connect_guard = |status: StatusCode, info: &RouteInfo| {
            let mut g = new_guard(&access, &tasks, client, "CONNECT", target.authority());
            g.set_route(&info.rule, info.profile.clone(), info.upstream.clone());
            g.set_status(status);
            g
        };

        // 1. ClientHello: SNI + ALPN.
        let acceptor = LazyConfigAcceptor::new(Acceptor::default(), upgraded);
        let start = tokio::select! {
            () = shutdown.cancelled() => return,
            res = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor) => match res {
                Ok(Ok(start)) => start,
                Ok(Err(e)) => {
                    logger.debug(format!("MITM {client} -> {target}: invalid ClientHello: {e}"));
                    return;
                }
                Err(_) => {
                    logger.debug(format!("MITM {client} -> {target}: ClientHello timed out"));
                    return;
                }
            },
        };
        let hello = start.client_hello();
        let sni = hello.server_name().map(str::to_string);
        let offered: Vec<Vec<u8>> = hello
            .alpn()
            .map(|it| {
                it.filter(|p| *p == ALPN_H2 || *p == ALPN_HTTP11)
                    .map(<[u8]>::to_vec)
                    .collect()
            })
            .unwrap_or_default();
        let offers_h11 = offered.iter().any(|p| p == ALPN_HTTP11);
        let leaf_host = sni.unwrap_or_else(|| target.host.clone());

        let Ok(server_name) = ServerName::try_from(leaf_host.clone()) else {
            logger.debug(format!(
                "MITM {client} -> {target}: invalid server name {leaf_host:?}"
            ));
            drop(connect_guard(
                StatusCode::BAD_REQUEST,
                &RouteInfo::default(),
            ));
            return;
        };
        let per_request = state.router.has_url_rules(Inbound::Http);
        let dialer = Dialer {
            tls: Arc::clone(&self.upstream_tls),
            target: target.clone(),
            server_name,
            state,
            logger: logger.clone(),
        };

        // 2. Upstream. Without URL rules: route once and dial now (learn the ALPN choice).
        let (routing, upstream, negotiated) = if per_request {
            let alpn = offers_h11.then(|| ALPN_HTTP11.to_vec());
            (Routing::PerRequest(live), None, alpn)
        } else {
            let dialed = async {
                let decision = dialer.route(None)?;
                let (tls, info) = dialer.connect(&decision, offered.clone()).await?;
                Ok::<_, DialFailure>((decision, tls, info))
            };
            let dialed = tokio::select! {
                () = shutdown.cancelled() => return,
                res = dialed => res,
            };
            match dialed {
                Ok((decision, tls, info)) => {
                    let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                    let negotiated =
                        negotiated.or_else(|| offers_h11.then(|| ALPN_HTTP11.to_vec()));
                    let routing = Routing::Fixed {
                        decision: Arc::new(decision),
                        info,
                    };
                    (routing, Some(tls), negotiated)
                }
                Err(f) => {
                    drop(connect_guard(f.status, &f.info));
                    return;
                }
            }
        };

        // 3. Leaf certificate + client handshake.
        let leaf = match self.cache.get_or_create(&leaf_host).await {
            Ok(k) => k,
            Err(e) => {
                logger.error(format!("MITM {client} -> {target}: {e}"));
                drop(connect_guard(
                    StatusCode::BAD_GATEWAY,
                    &RouteInfo::default(),
                ));
                return;
            }
        };
        let mut server_cfg = match ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
        {
            Ok(b) => b
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedCert(leaf))),
            Err(e) => {
                logger.error(format!("MITM TLS server config failed: {e}"));
                return;
            }
        };
        server_cfg.alpn_protocols = negotiated.iter().cloned().collect();
        let client_tls = tokio::select! {
            () = shutdown.cancelled() => return,
            res = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, start.into_stream(Arc::new(server_cfg))) => res,
        };
        let client_tls = match client_tls {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                logger.debug(format!(
                    "MITM client TLS handshake with {client} for {leaf_host} failed: {e}"
                ));
                return;
            }
            Err(_) => {
                logger.debug(format!("MITM client TLS handshake with {client} timed out"));
                return;
            }
        };

        let default_authority = if target.port == 443 {
            authority_host(&leaf_host)
        } else {
            format!("{}:{}", authority_host(&leaf_host), target.port)
        };
        let session = Session {
            access,
            logger: logger.clone(),
            tasks: tasks.clone(),
            shutdown: shutdown.clone(),
            client,
            default_authority,
            dialer,
            routing,
        };

        // 4. Serve decrypted HTTP.
        let result = match upstream {
            Some(up) if negotiated.as_deref() == Some(ALPN_H2) => {
                session.serve_h2(client_tls, up).await
            }
            up => session.serve_h1(client_tls, up).await,
        };
        if let Err(e) = result {
            logger.debug(format!("MITM session {client} -> {target} ended: {e}"));
        }
        tasks.close();
        tasks.wait().await;
    }
}

fn authority_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn new_guard(
    access: &AccessLogger,
    tasks: &TaskTracker,
    client: SocketAddr,
    method: &str,
    target: String,
) -> AccessGuard {
    AccessGuard::new(
        access.clone(),
        tasks.clone(),
        HttpAccessRecord {
            ts: OffsetDateTime::now_utc(),
            client,
            proto: "https".into(),
            mitm: true,
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

fn is_upgrade_request<B>(req: &Request<B>) -> bool {
    req.headers().contains_key(header::UPGRADE)
        && req
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
}

fn set_route(guard: &mut AccessGuard, info: &RouteInfo) {
    guard.set_route(&info.rule, info.profile.clone(), info.upstream.clone());
}

impl Session {
    fn guard(&self, method: &str, target: String) -> AccessGuard {
        new_guard(&self.access, &self.tasks, self.client, method, target)
    }

    /// `(authority, https:// URL)` for a decrypted request.
    fn request_target<B>(&self, req: &Request<B>) -> (String, String) {
        let authority = req
            .uri()
            .authority()
            .map(|a| a.as_str().to_string())
            .or_else(|| {
                req.headers()
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| self.default_authority.clone());
        let pq = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
        let url = format!("https://{authority}{pq}");
        (authority, url)
    }

    fn spawn_driver<F>(&self, what: &'static str, conn: F)
    where
        F: std::future::Future<Output = Result<(), hyper::Error>> + Send + 'static,
    {
        let shutdown = self.shutdown.clone();
        let logger = self.logger.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                res = conn => {
                    if let Err(e) = res {
                        logger.debug(format!("MITM upstream {what} connection error: {e}"));
                    }
                }
                () = shutdown.cancelled() => {}
            }
        });
    }

    async fn h1_handshake(&self, tls: UpstreamTls) -> Result<H1Sender, hyper::Error> {
        let (sender, conn) = client_http1::handshake(TokioIo::new(tls)).await?;
        self.spawn_driver("HTTP/1.1", conn.with_upgrades());
        Ok(sender)
    }

    /// The decision for one decrypted request (`url` is its full `https://` URL) and the
    /// dialer bound to the snapshot it was made with.
    fn decide(&self, url: &str) -> Result<(Arc<RouteDecision>, Dialer), DialFailure> {
        match &self.routing {
            Routing::Fixed { decision, .. } => Ok((Arc::clone(decision), self.dialer.clone())),
            Routing::PerRequest(live) => {
                let dialer = Dialer {
                    state: live.load_full(),
                    ..self.dialer.clone()
                };
                let decision = dialer.route(Some(url))?;
                Ok((Arc::new(decision), dialer))
            }
        }
    }

    /// The upstream HTTP/1.1 sender for `decision`: the attached one if it serves the same
    /// chain and is still open, otherwise a freshly dialed one.
    async fn h1_upstream(
        &self,
        slot: &Mutex<Option<H1Upstream>>,
        decision: &RouteDecision,
        dialer: &Dialer,
    ) -> Result<H1Upstream, DialFailure> {
        // Same chain under the same config generation: a reload may redefine profiles.
        let key = format!("{}@{}", chain_key(decision), dialer.state.config_generation);
        if let Some(mut up) = slot.lock().await.take() {
            if up.key == key && up.sender.ready().await.is_ok() {
                return Ok(up);
            }
        }
        let (tls, info) = dialer.connect(decision, vec![ALPN_HTTP11.to_vec()]).await?;
        match self.h1_handshake(tls).await {
            Ok(sender) => Ok(H1Upstream { sender, key, info }),
            Err(e) => {
                self.logger.error(format!(
                    "MITM upstream {} handshake failed: {e}",
                    self.dialer.target
                ));
                Err(DialFailure {
                    status: StatusCode::BAD_GATEWAY,
                    info,
                })
            }
        }
    }

    async fn serve_h1(
        &self,
        client_tls: ClientTls,
        upstream: Option<UpstreamTls>,
    ) -> Result<(), hyper::Error> {
        let first = match (upstream, &self.routing) {
            (Some(tls), Routing::Fixed { decision, info }) => Some(H1Upstream {
                sender: self.h1_handshake(tls).await?,
                key: format!(
                    "{}@{}",
                    chain_key(decision),
                    self.dialer.state.config_generation
                ),
                info: info.clone(),
            }),
            _ => None,
        };
        let slot = Arc::new(Mutex::new(first));
        let session = self.clone();
        let service = service_fn(move |req| {
            let session = session.clone();
            let slot = Arc::clone(&slot);
            async move { Ok::<_, Infallible>(session.forward_h1(req, &slot).await) }
        });
        let conn = server_http1::Builder::new()
            .serve_connection(TokioIo::new(client_tls), service)
            .with_upgrades();
        let mut conn = std::pin::pin!(conn);
        tokio::select! {
            res = conn.as_mut() => res,
            () = self.shutdown.cancelled() => {
                conn.as_mut().graceful_shutdown();
                conn.as_mut().await
            }
        }
    }

    async fn forward_h1(
        &self,
        mut req: Request<Incoming>,
        slot: &Mutex<Option<H1Upstream>>,
    ) -> Response<ProxyBody> {
        let (authority, url) = self.request_target(&req);
        let mut guard = self.guard(req.method().as_str(), url.clone());
        let (decision, dialer) = match self.decide(&url) {
            Ok(d) => d,
            Err(f) => {
                guard.set_status(f.status);
                return error_response(f.status, "destination not allowed");
            }
        };
        let upgrade = is_upgrade_request(&req).then(|| {
            let proto = req.headers().get(header::UPGRADE).cloned();
            (hyper::upgrade::on(&mut req), proto)
        });

        let (mut parts, body) = req.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        if let Some((_, Some(proto))) = &upgrade {
            parts.headers.insert(header::UPGRADE, proto.clone());
            parts
                .headers
                .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        }
        let origin = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
        parts.uri = origin
            .parse::<Uri>()
            .unwrap_or_else(|_| Uri::from_static("/"));
        parts.version = Version::HTTP_11;
        if !parts.headers.contains_key(header::HOST) {
            match HeaderValue::from_str(&authority) {
                Ok(v) => {
                    parts.headers.insert(header::HOST, v);
                }
                Err(_) => {
                    guard.set_status(StatusCode::BAD_REQUEST);
                    return error_response(StatusCode::BAD_REQUEST, "invalid host");
                }
            }
        }

        let mut up = match self.h1_upstream(slot, &decision, &dialer).await {
            Ok(up) => up,
            Err(f) => {
                set_route(&mut guard, &f.info);
                guard.set_status(f.status);
                let msg = if f.status == StatusCode::FORBIDDEN {
                    "destination blocked"
                } else {
                    "upstream connection failed"
                };
                return error_response(f.status, msg);
            }
        };
        set_route(&mut guard, &up.info);
        let body = CountingBody::new(body, guard.bytes_in(), None).boxed();
        let upstream_req = Request::from_parts(parts, body);
        let mut resp = match up.sender.send_request(upstream_req).await {
            Ok(r) => r,
            Err(e) => {
                self.logger
                    .error(format!("MITM upstream request to {authority} failed: {e}"));
                guard.set_status(StatusCode::BAD_GATEWAY);
                return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
            }
        };
        guard.set_status(resp.status());

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            if let Some((client_upgrade, _)) = upgrade {
                // The upstream connection now belongs to the upgraded stream.
                drop(up);
                let upstream_upgrade = hyper::upgrade::on(&mut resp);
                self.spawn_upgrade_relay(client_upgrade, upstream_upgrade, guard);
                let (parts, _) = resp.into_parts();
                return Response::from_parts(parts, empty_body());
            }
        }
        *slot.lock().await = Some(up);

        let (mut parts, body) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        let bytes_out = guard.bytes_out();
        Response::from_parts(
            parts,
            CountingBody::new(body, bytes_out, Some(guard)).boxed(),
        )
    }

    fn spawn_upgrade_relay(
        &self,
        client: hyper::upgrade::OnUpgrade,
        upstream: hyper::upgrade::OnUpgrade,
        guard: AccessGuard,
    ) {
        let shutdown = self.shutdown.clone();
        let logger = self.logger.clone();
        let peer = self.client;
        self.tasks.spawn(async move {
            let (client, upstream) = match tokio::try_join!(client, upstream) {
                Ok(pair) => pair,
                Err(e) => {
                    logger.debug(format!("MITM upgrade for {peer} failed: {e}"));
                    return;
                }
            };
            let mut client =
                CountingStream::new(TokioIo::new(client), guard.bytes_in(), guard.bytes_out());
            let mut upstream = TokioIo::new(upstream);
            tokio::select! {
                res = relay_bidirectional(&mut client, &mut upstream) => {
                    if let Err(e) = res {
                        logger.debug(format!("MITM upgraded stream for {peer} ended: {e}"));
                    }
                }
                () = shutdown.cancelled() => {}
            }
            drop(guard);
        });
    }

    /// HTTP/2 to client and upstream (fixed routing only: one multiplexed upstream).
    async fn serve_h2(
        &self,
        client_tls: ClientTls,
        upstream: UpstreamTls,
    ) -> Result<(), hyper::Error> {
        let info = match &self.routing {
            Routing::Fixed { info, .. } => info.clone(),
            Routing::PerRequest(_) => RouteInfo::default(),
        };
        let (sender, conn) =
            client_http2::handshake(TokioExecutor::new(), TokioIo::new(upstream)).await?;
        self.spawn_driver("HTTP/2", conn);
        let session = self.clone();
        let service = service_fn(move |req| {
            let session = session.clone();
            let sender = sender.clone();
            let info = info.clone();
            async move { Ok::<_, Infallible>(session.forward_h2(req, sender, &info).await) }
        });
        let conn = server_http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(client_tls), service);
        let mut conn = std::pin::pin!(conn);
        tokio::select! {
            res = conn.as_mut() => res,
            () = self.shutdown.cancelled() => {
                conn.as_mut().graceful_shutdown();
                conn.as_mut().await
            }
        }
    }

    async fn forward_h2(
        &self,
        req: Request<Incoming>,
        mut sender: client_http2::SendRequest<ProxyBody>,
        info: &RouteInfo,
    ) -> Response<ProxyBody> {
        let (authority, url) = self.request_target(&req);
        let mut guard = self.guard(req.method().as_str(), url.clone());
        set_route(&mut guard, info);
        let (mut parts, body) = req.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        parts.headers.remove(header::HOST);
        parts.version = Version::HTTP_2;
        parts.uri = match url.parse::<Uri>() {
            Ok(u) => u,
            Err(_) => {
                guard.set_status(StatusCode::BAD_REQUEST);
                return error_response(StatusCode::BAD_REQUEST, "invalid request target");
            }
        };
        let body = CountingBody::new(body, guard.bytes_in(), None).boxed();
        let resp = match sender.send_request(Request::from_parts(parts, body)).await {
            Ok(r) => r,
            Err(e) => {
                self.logger.error(format!(
                    "MITM upstream HTTP/2 request to {authority} failed: {e}"
                ));
                guard.set_status(StatusCode::BAD_GATEWAY);
                return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
            }
        };
        guard.set_status(resp.status());
        let (mut parts, body) = resp.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        let bytes_out = guard.bytes_out();
        Response::from_parts(
            parts,
            CountingBody::new(body, bytes_out, Some(guard)).boxed(),
        )
    }
}

fn empty_body() -> ProxyBody {
    Empty::new().map_err(|never| match never {}).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::ResolvedTarget;

    fn target(profile: &str) -> ResolvedTarget {
        ResolvedTarget {
            name: profile.into(),
            profile: profile.into(),
            kind: crate::config::ProfileType::Direct,
            bypassed: false,
        }
    }

    #[test]
    fn chain_key_identifies_failover_chains() {
        let decision = |targets: Vec<ResolvedTarget>| RouteDecision {
            table: crate::router::TableKind::Unified,
            rule: None,
            rule_index: None,
            targets,
            has_url_rules: true,
        };
        let a = decision(vec![target("corp"), target("direct")]);
        let b = decision(vec![target("corp"), target("direct")]);
        let c = decision(vec![target("direct")]);
        assert_eq!(chain_key(&a), "corp,direct");
        assert_eq!(chain_key(&a), chain_key(&b));
        assert_ne!(chain_key(&a), chain_key(&c));
    }

    #[test]
    fn authority_host_brackets_ipv6() {
        assert_eq!(authority_host("::1"), "[::1]");
        assert_eq!(authority_host("example.com"), "example.com");
    }
}
