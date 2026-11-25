//! Listener lifecycle: separate vs. single-port multiplexed listeners, connection dispatch,
//! and graceful shutdown.
//!
//! * `http_port != socks_port` (both `> 0`): two listeners. The HTTP listener hands every
//!   connection to [`ProtocolHandlers::http`]; the SOCKS listener sniffs the version byte and
//!   dispatches to [`ProtocolHandlers::socks4`] or [`ProtocolHandlers::socks5`].
//! * `http_port == socks_port > 0`: one listener; every connection is classified by
//!   [`crate::mux::sniff_protocol`] and dispatched accordingly.
//! * A port of `0` in [`Config`] disables that listener.
//!
//! Shutdown cancels a shared [`CancellationToken`]: accept loops stop immediately, every
//! connection task receives a child token, and in-flight connections are drained for at
//! most [`Server::drain_timeout`].
//!
//! An optional connection cap ([`Server::with_max_connections`]) is shared by all listeners.
//! When it is full, a newly accepted connection is closed at once rather than queued, so
//! idle clients cannot build up a backlog. Each connection task owns its permit, which is
//! released when the task ends.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::Config;
use crate::http::mitm_tunnel::MitmInterceptor;
use crate::http::HttpProxy;
use crate::logging::{AccessLogger, Logger};
use crate::mux::{self, DetectedProtocol, DEFAULT_SNIFF_TIMEOUT};
use crate::net::KeepaliveSettings;
use crate::socks::web_guard::WebGuard;
use crate::socks::SocksProxy;

/// Default bound on how long in-flight connections may drain after shutdown starts.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Pause after a failed `accept()` (e.g. file-descriptor exhaustion) to avoid a hot loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Boxed future returned by protocol handlers.
pub type HandlerFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// An accepted client connection handed to a protocol handler.
///
/// For sniffed connections the first byte has only been peeked, so it is still unread.
#[derive(Debug)]
pub struct Connection {
    pub stream: TcpStream,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    /// Cancelled when the server shuts down; long-lived relays should stop on it.
    pub shutdown: CancellationToken,
}

/// Protocol engines plugged into the server ([`EngineHandlers`] in production; mocks in
/// tests); the server itself never changes.
pub trait ProtocolHandlers: Send + Sync + 'static {
    /// Handle an HTTP/HTTPS proxy connection (plain forward or `CONNECT`).
    fn http(&self, conn: Connection) -> HandlerFuture;
    /// Handle a SOCKS4/4a connection (first byte `0x04`, unread).
    fn socks4(&self, conn: Connection) -> HandlerFuture;
    /// Handle a SOCKS5 connection (first byte `0x05`, unread).
    fn socks5(&self, conn: Connection) -> HandlerFuture;
}

/// Placeholder handlers that log and close every connection.
#[derive(Debug, Clone)]
pub struct StubHandlers {
    logger: Logger,
}

impl StubHandlers {
    pub fn new(logger: Logger) -> Self {
        Self { logger }
    }

    fn reject(&self, proto: &'static str, conn: Connection) -> HandlerFuture {
        let logger = self.logger.clone();
        Box::pin(async move {
            logger.debug(format!(
                "{proto} connection from {} closed: protocol engine not available",
                conn.peer
            ));
            drop(conn);
        })
    }
}

impl ProtocolHandlers for StubHandlers {
    fn http(&self, conn: Connection) -> HandlerFuture {
        self.reject("HTTP", conn)
    }
    fn socks4(&self, conn: Connection) -> HandlerFuture {
        self.reject("SOCKS4", conn)
    }
    fn socks5(&self, conn: Connection) -> HandlerFuture {
        self.reject("SOCKS5", conn)
    }
}

/// The real protocol engines: the routed HTTP/HTTPS proxy for HTTP connections and the
/// routed SOCKS4/4a/5 engine for SOCKS connections (dedicated and multiplexed listeners).
#[derive(Debug, Clone)]
pub struct EngineHandlers {
    http: HttpProxy,
    socks: SocksProxy,
}

impl EngineHandlers {
    pub fn new(http: HttpProxy, socks: SocksProxy) -> Self {
        Self { http, socks }
    }

    /// Build both engines over one shared routing state.
    pub fn from_routing(routing: SharedRouting, access: AccessLogger, logger: Logger) -> Self {
        Self::new(
            HttpProxy::new(Arc::clone(&routing), access.clone(), logger.clone()),
            SocksProxy::new(routing, access, logger),
        )
    }

    /// Enable HTTPS interception on the HTTP engine; with `socks_block_web`
    /// (`--socks-block-web-in-mitm`) also install the SOCKS [`WebGuard`], so web traffic
    /// cannot bypass MITM logging by tunnelling over SOCKS. The guard is only ever installed
    /// together with MITM.
    pub fn with_mitm(mut self, interceptor: Arc<MitmInterceptor>, socks_block_web: bool) -> Self {
        self.http = self.http.with_mitm(interceptor);
        if socks_block_web {
            self.socks = self.socks.with_guard(Arc::new(WebGuard));
        }
        self
    }

    /// The HTTP/HTTPS engine.
    pub fn http_engine(&self) -> &HttpProxy {
        &self.http
    }

    /// The SOCKS4/4a/5 engine.
    pub fn socks_engine(&self) -> &SocksProxy {
        &self.socks
    }
}

impl ProtocolHandlers for EngineHandlers {
    fn http(&self, conn: Connection) -> HandlerFuture {
        let proxy = self.http.clone();
        Box::pin(async move { proxy.serve(conn).await })
    }
    fn socks4(&self, conn: Connection) -> HandlerFuture {
        let proxy = self.socks.clone();
        Box::pin(async move { proxy.serve_v4(conn).await })
    }
    fn socks5(&self, conn: Connection) -> HandlerFuture {
        let proxy = self.socks.clone();
        Box::pin(async move { proxy.serve_v5(conn).await })
    }
}

/// Compiled hot-reloadable state; see [`crate::reload::RuntimeConfig`].
pub use crate::reload::RoutingSetupError;
/// Historical name of [`crate::reload::RuntimeConfig`] (one immutable routing snapshot).
pub type RoutingState = crate::reload::RuntimeConfig;
/// Historical name of [`crate::reload::SharedRuntime`].
pub type SharedRouting = crate::reload::SharedRuntime;

/// What a listener accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerRole {
    /// HTTP/HTTPS only.
    Http,
    /// SOCKS4/4a/5 only (version byte sniffed).
    Socks,
    /// HTTP/HTTPS and SOCKS on one port (first byte sniffed).
    Multiplexed,
}

impl fmt::Display for ListenerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http => "HTTP/HTTPS",
            Self::Socks => "SOCKS4/4a/5",
            Self::Multiplexed => "multiplexed HTTP/HTTPS + SOCKS4/4a/5",
        })
    }
}

/// Which socket addresses to bind. Unlike [`Config`] ports, a socket address with port `0`
/// here means "OS-assigned ephemeral port" (useful in tests); disabled listeners are `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenPlan {
    Separate {
        http: Option<SocketAddr>,
        socks: Option<SocketAddr>,
    },
    Multiplexed(SocketAddr),
}

impl ListenPlan {
    /// Derive the plan from configuration: port `0` disables a listener, equal non-zero
    /// ports enable single-port multiplexing.
    pub fn from_config(cfg: &Config) -> Self {
        if cfg.is_multiplexed() {
            return Self::Multiplexed(SocketAddr::new(cfg.bind, cfg.http_port));
        }
        let addr = |port: u16| (port > 0).then(|| SocketAddr::new(cfg.bind, port));
        Self::Separate {
            http: addr(cfg.http_port),
            socks: addr(cfg.socks_port),
        }
    }
}

/// Errors raised while starting the server. All are `FATAL`.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("failed to bind {role} listener on {addr}: {source}")]
    Bind {
        role: ListenerRole,
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("no listeners enabled: at least one of http_port / socks_port must be non-zero")]
    NoListeners,
}

/// Outcome of a completed [`Server::run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    /// `true` if every in-flight connection finished within the drain timeout.
    pub drained: bool,
}

/// Bound proxy server, ready to [`run`](Server::run).
pub struct Server {
    listeners: Vec<(ListenerRole, SocketAddr, TcpListener)>,
    handlers: Arc<dyn ProtocolHandlers>,
    logger: Logger,
    shutdown: CancellationToken,
    tracker: TaskTracker,
    sniff_timeout: Duration,
    drain_timeout: Duration,
    /// `None` means unlimited.
    connection_limit: Option<Arc<Semaphore>>,
    /// TCP keepalive for accepted client sockets (`None` = disabled).
    keepalive: Option<KeepaliveSettings>,
    /// Hot-reloadable runtime state; when set, its keepalive overrides `keepalive`.
    runtime: Option<SharedRouting>,
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("http_addr", &self.local_http_addr())
            .field("socks_addr", &self.local_socks_addr())
            .field("sniff_timeout", &self.sniff_timeout)
            .field("drain_timeout", &self.drain_timeout)
            .field("keepalive", &self.keepalive)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Bind every listener in `plan`.
    pub async fn bind(
        plan: ListenPlan,
        handlers: Arc<dyn ProtocolHandlers>,
        logger: Logger,
    ) -> Result<Self, ServerError> {
        let wanted: Vec<(ListenerRole, SocketAddr)> = match plan {
            ListenPlan::Multiplexed(addr) => vec![(ListenerRole::Multiplexed, addr)],
            ListenPlan::Separate { http, socks } => http
                .map(|a| (ListenerRole::Http, a))
                .into_iter()
                .chain(socks.map(|a| (ListenerRole::Socks, a)))
                .collect(),
        };
        if wanted.is_empty() {
            return Err(ServerError::NoListeners);
        }
        let mut listeners = Vec::with_capacity(wanted.len());
        for (role, addr) in wanted {
            let bind_err = |source| ServerError::Bind { role, addr, source };
            let listener = TcpListener::bind(addr).await.map_err(bind_err)?;
            let local = listener.local_addr().map_err(bind_err)?;
            listeners.push((role, local, listener));
        }
        Ok(Self {
            listeners,
            handlers,
            logger,
            shutdown: CancellationToken::new(),
            tracker: TaskTracker::new(),
            sniff_timeout: DEFAULT_SNIFF_TIMEOUT,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
            connection_limit: None,
            keepalive: Some(KeepaliveSettings::DEFAULT),
            runtime: None,
        })
    }

    /// Bind according to the validated configuration.
    pub async fn from_config(
        cfg: &Config,
        handlers: Arc<dyn ProtocolHandlers>,
        logger: Logger,
    ) -> Result<Self, ServerError> {
        Ok(Self::bind(ListenPlan::from_config(cfg), handlers, logger)
            .await?
            .with_max_connections(cfg.max_connections)
            .with_tcp_keepalive(cfg.tcp_keepalive_settings()))
    }

    /// Cap concurrent connections across all listeners (`0` = unlimited). Values above
    /// [`Semaphore::MAX_PERMITS`] are clamped to it.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.connection_limit =
            (max > 0).then(|| Arc::new(Semaphore::new(max.min(Semaphore::MAX_PERMITS))));
        self
    }

    /// Set TCP keepalive for accepted client sockets (`None` disables; default
    /// [`KeepaliveSettings::DEFAULT`]).
    pub fn with_tcp_keepalive(mut self, keepalive: Option<KeepaliveSettings>) -> Self {
        self.keepalive = keepalive;
        self
    }

    /// Take client-socket TCP keepalive from the hot-reloadable runtime state: every
    /// accepted connection uses the keepalive of the snapshot current at accept time.
    pub fn with_runtime(mut self, runtime: SharedRouting) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Override how long to wait for a client's first byte (default 5s).
    pub fn with_sniff_timeout(mut self, timeout: Duration) -> Self {
        self.sniff_timeout = timeout;
        self
    }

    /// Override the bounded drain timeout applied on shutdown (default 5s).
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    pub fn drain_timeout(&self) -> Duration {
        self.drain_timeout
    }

    /// Address accepting HTTP/HTTPS connections (the shared address when multiplexed).
    pub fn local_http_addr(&self) -> Option<SocketAddr> {
        self.addr_for(|r| matches!(r, ListenerRole::Http | ListenerRole::Multiplexed))
    }

    /// Address accepting SOCKS connections (the shared address when multiplexed).
    pub fn local_socks_addr(&self) -> Option<SocketAddr> {
        self.addr_for(|r| matches!(r, ListenerRole::Socks | ListenerRole::Multiplexed))
    }

    /// Whether a single multiplexed listener is in use.
    pub fn is_multiplexed(&self) -> bool {
        self.listeners
            .iter()
            .any(|(r, _, _)| *r == ListenerRole::Multiplexed)
    }

    /// Bound listeners as `(role, address)` pairs.
    pub fn listeners(&self) -> Vec<(ListenerRole, SocketAddr)> {
        self.listeners.iter().map(|(r, a, _)| (*r, *a)).collect()
    }

    /// Token that triggers graceful shutdown when cancelled.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    fn addr_for(&self, pred: impl Fn(ListenerRole) -> bool) -> Option<SocketAddr> {
        self.listeners
            .iter()
            .find(|(r, _, _)| pred(*r))
            .map(|(_, a, _)| *a)
    }

    /// Accept and dispatch connections until the shutdown token is cancelled, then drain
    /// in-flight connections for at most the drain timeout.
    pub async fn run(self) -> ShutdownReport {
        let Self {
            listeners,
            handlers,
            logger,
            shutdown,
            tracker,
            sniff_timeout,
            drain_timeout,
            connection_limit,
            keepalive,
            runtime,
        } = self;

        let mut accept_loops = tokio::task::JoinSet::new();
        for (role, addr, listener) in listeners {
            accept_loops.spawn(accept_loop(AcceptCtx {
                role,
                addr,
                listener,
                handlers: Arc::clone(&handlers),
                logger: logger.clone(),
                shutdown: shutdown.clone(),
                tracker: tracker.clone(),
                sniff_timeout,
                connection_limit: connection_limit.clone(),
                keepalive,
                runtime: runtime.clone(),
            }));
        }
        while accept_loops.join_next().await.is_some() {}

        tracker.close();
        let active = tracker.len();
        if active > 0 {
            logger.debug(format!(
                "draining {active} active connection(s) (timeout {})",
                humantime::format_duration(drain_timeout)
            ));
        }
        let drained = tokio::time::timeout(drain_timeout, tracker.wait())
            .await
            .is_ok();
        if !drained {
            logger.error(format!(
                "shutdown drain timed out after {}; {} connection(s) aborted",
                humantime::format_duration(drain_timeout),
                tracker.len()
            ));
        }
        ShutdownReport { drained }
    }
}

struct AcceptCtx {
    role: ListenerRole,
    addr: SocketAddr,
    listener: TcpListener,
    handlers: Arc<dyn ProtocolHandlers>,
    logger: Logger,
    shutdown: CancellationToken,
    tracker: TaskTracker,
    sniff_timeout: Duration,
    connection_limit: Option<Arc<Semaphore>>,
    keepalive: Option<KeepaliveSettings>,
    runtime: Option<SharedRouting>,
}

async fn accept_loop(ctx: AcceptCtx) {
    loop {
        let accepted = tokio::select! {
            biased;
            () = ctx.shutdown.cancelled() => break,
            res = ctx.listener.accept() => res,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                ctx.logger.error(format!(
                    "{} listener {}: accept failed: {e}",
                    ctx.role, ctx.addr
                ));
                tokio::select! {
                    () = ctx.shutdown.cancelled() => break,
                    () = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => continue,
                }
            }
        };
        let permit = match &ctx.connection_limit {
            Some(limit) => match Arc::clone(limit).try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    ctx.logger.debug(format!(
                        "dropped connection from {peer} on {} listener {}: connection limit reached",
                        ctx.role, ctx.addr
                    ));
                    drop(stream);
                    continue;
                }
            },
            None => None,
        };
        let keepalive = match &ctx.runtime {
            Some(rt) => rt.load().keepalive,
            None => ctx.keepalive,
        };
        if let Some(ka) = &keepalive {
            if let Err(e) = ka.apply(&stream) {
                ctx.logger
                    .debug(format!("failed to enable TCP keepalive for {peer}: {e}"));
            }
        }
        ctx.logger.verbose(format!(
            "accepted connection from {peer} on {} listener {}",
            ctx.role, ctx.addr
        ));
        let conn = Connection {
            stream,
            peer,
            local: ctx.addr,
            shutdown: ctx.shutdown.child_token(),
        };
        let connection = dispatch(
            ctx.role,
            conn,
            Arc::clone(&ctx.handlers),
            ctx.logger.clone(),
            ctx.sniff_timeout,
        );
        ctx.tracker.spawn(async move {
            let _permit = permit;
            connection.await;
        });
    }
    ctx.logger
        .debug(format!("{} listener {} stopped", ctx.role, ctx.addr));
}

async fn dispatch(
    role: ListenerRole,
    conn: Connection,
    handlers: Arc<dyn ProtocolHandlers>,
    logger: Logger,
    sniff_timeout: Duration,
) {
    if role == ListenerRole::Http {
        return handlers.http(conn).await;
    }
    let sniffed = tokio::select! {
        () = conn.shutdown.cancelled() => return,
        res = mux::sniff_protocol(&conn.stream, sniff_timeout) => res,
    };
    let peer = conn.peer;
    match sniffed {
        Ok(DetectedProtocol::Socks4) => handlers.socks4(conn).await,
        Ok(DetectedProtocol::Socks5) => handlers.socks5(conn).await,
        Ok(DetectedProtocol::Http) if role == ListenerRole::Multiplexed => {
            handlers.http(conn).await
        }
        Ok(DetectedProtocol::Http) => {
            logger.debug(format!(
                "rejected connection from {peer} on {role} listener: HTTP request on SOCKS port"
            ));
        }
        Ok(DetectedProtocol::Unknown(byte)) => {
            logger.debug(format!(
                "rejected connection from {peer} on {role} listener: unknown first byte 0x{byte:02x}"
            ));
        }
        Err(e) => {
            logger.debug(format!(
                "rejected connection from {peer} on {role} listener: {e}"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::LogLevel;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn quiet() -> Logger {
        Logger::with_writer(LogLevel::Quiet, Box::new(io::sink()))
    }

    /// Mock handlers: record the protocol, read the first byte, and reply with a tag.
    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<(&'static str, u8)>>,
        /// Whether `SO_KEEPALIVE` was set on each accepted client socket.
        keepalive: Mutex<Vec<bool>>,
    }

    impl Recorder {
        fn handle(self: &Arc<Self>, tag: &'static str, mut conn: Connection) -> HandlerFuture {
            let me = Arc::clone(self);
            Box::pin(async move {
                let ka = socket2::SockRef::from(&conn.stream).keepalive().unwrap();
                me.keepalive.lock().unwrap().push(ka);
                let mut first = [0u8; 1];
                conn.stream.read_exact(&mut first).await.unwrap();
                me.seen.lock().unwrap().push((tag, first[0]));
                conn.stream.write_all(tag.as_bytes()).await.unwrap();
                conn.stream.shutdown().await.unwrap();
            })
        }
        fn seen(&self) -> Vec<(&'static str, u8)> {
            let mut v = self.seen.lock().unwrap().clone();
            v.sort();
            v
        }
    }

    struct Handlers(Arc<Recorder>);
    impl ProtocolHandlers for Handlers {
        fn http(&self, conn: Connection) -> HandlerFuture {
            self.0.handle("http", conn)
        }
        fn socks4(&self, conn: Connection) -> HandlerFuture {
            self.0.handle("socks4", conn)
        }
        fn socks5(&self, conn: Connection) -> HandlerFuture {
            self.0.handle("socks5", conn)
        }
    }

    async fn roundtrip(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(payload).await.unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out).await;
        out
    }

    async fn start(plan: ListenPlan) -> (Server, Arc<Recorder>) {
        let rec = Arc::new(Recorder::default());
        let server = Server::bind(plan, Arc::new(Handlers(Arc::clone(&rec))), quiet())
            .await
            .unwrap()
            .with_sniff_timeout(Duration::from_millis(200));
        (server, rec)
    }

    #[test]
    fn plan_from_config() {
        let mut cfg = Config {
            http_port: 3128,
            socks_port: 1080,
            ..Config::default()
        };
        assert_eq!(
            ListenPlan::from_config(&cfg),
            ListenPlan::Separate {
                http: Some(SocketAddr::new(cfg.bind, 3128)),
                socks: Some(SocketAddr::new(cfg.bind, 1080)),
            }
        );
        cfg.socks_port = 0;
        assert_eq!(
            ListenPlan::from_config(&cfg),
            ListenPlan::Separate {
                http: Some(SocketAddr::new(cfg.bind, 3128)),
                socks: None,
            }
        );
        cfg.http_port = 0;
        cfg.socks_port = 1080;
        assert_eq!(
            ListenPlan::from_config(&cfg),
            ListenPlan::Separate {
                http: None,
                socks: Some(SocketAddr::new(cfg.bind, 1080)),
            }
        );
        cfg.http_port = 8080;
        cfg.socks_port = 8080;
        assert_eq!(
            ListenPlan::from_config(&cfg),
            ListenPlan::Multiplexed(SocketAddr::new(cfg.bind, 8080))
        );
    }

    #[tokio::test]
    async fn no_listeners_is_an_error() {
        let plan = ListenPlan::Separate {
            http: None,
            socks: None,
        };
        let err = Server::bind(plan, Arc::new(StubHandlers::new(quiet())), quiet())
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::NoListeners));
    }

    #[tokio::test]
    async fn bind_conflict_reports_role_and_addr() {
        let taken = TcpListener::bind(loopback(0)).await.unwrap();
        let addr = taken.local_addr().unwrap();
        let plan = ListenPlan::Separate {
            http: Some(addr),
            socks: None,
        };
        let err = Server::bind(plan, Arc::new(StubHandlers::new(quiet())), quiet())
            .await
            .unwrap_err();
        match err {
            ServerError::Bind { role, addr: a, .. } => {
                assert_eq!(role, ListenerRole::Http);
                assert_eq!(a, addr);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn accepted_client_sockets_get_tcp_keepalive() {
        for (keepalive, expected) in [(Some(KeepaliveSettings::DEFAULT), true), (None, false)] {
            let (server, rec) = start(ListenPlan::Separate {
                http: Some(loopback(0)),
                socks: Some(loopback(0)),
            })
            .await;
            let server = server.with_tcp_keepalive(keepalive);
            let http = server.local_http_addr().unwrap();
            let socks = server.local_socks_addr().unwrap();
            let token = server.shutdown_token();
            let run = tokio::spawn(server.run());

            assert_eq!(roundtrip(http, b"GET / HTTP/1.1\r\n\r\n").await, b"http");
            assert_eq!(roundtrip(socks, &[0x05, 0x01, 0x00]).await, b"socks5");
            assert_eq!(*rec.keepalive.lock().unwrap(), vec![expected; 2]);

            token.cancel();
            run.await.unwrap();
        }
    }

    #[tokio::test]
    async fn client_keepalive_follows_the_live_runtime_snapshot() {
        let cfg = Config::default();
        let state =
            RoutingState::from_config(&cfg, crate::upstream::DialerOptions::default()).unwrap();
        let runtime = state.clone().shared();
        let (server, rec) = start(ListenPlan::Multiplexed(loopback(0))).await;
        // The static setting is overridden by the runtime snapshot.
        let server = server
            .with_tcp_keepalive(None)
            .with_runtime(Arc::clone(&runtime));
        let addr = server.local_http_addr().unwrap();
        let token = server.shutdown_token();
        let run = tokio::spawn(server.run());

        assert_eq!(roundtrip(addr, b"GET / HTTP/1.1\r\n\r\n").await, b"http");
        let mut off = state;
        off.keepalive = None;
        runtime.store(Arc::new(off));
        assert_eq!(roundtrip(addr, b"GET / HTTP/1.1\r\n\r\n").await, b"http");
        assert_eq!(*rec.keepalive.lock().unwrap(), vec![true, false]);

        token.cancel();
        run.await.unwrap();
    }

    #[tokio::test]
    async fn separate_listeners_dispatch_and_shut_down() {
        let (server, rec) = start(ListenPlan::Separate {
            http: Some(loopback(0)),
            socks: Some(loopback(0)),
        })
        .await;
        assert!(!server.is_multiplexed());
        let http = server.local_http_addr().unwrap();
        let socks = server.local_socks_addr().unwrap();
        assert_ne!(http, socks);
        let token = server.shutdown_token();
        let run = tokio::spawn(server.run());

        assert_eq!(roundtrip(http, b"GET / HTTP/1.1\r\n\r\n").await, b"http");
        // HTTP listener does not sniff: even a SOCKS-looking byte goes to the HTTP handler.
        assert_eq!(roundtrip(http, &[0x05, 0x01, 0x00]).await, b"http");
        assert_eq!(roundtrip(socks, &[0x04, 0x01]).await, b"socks4");
        assert_eq!(roundtrip(socks, &[0x05, 0x01, 0x00]).await, b"socks5");
        // SOCKS listener rejects HTTP and unknown first bytes by closing.
        assert!(roundtrip(socks, b"GET / HTTP/1.1\r\n").await.is_empty());
        assert!(roundtrip(socks, &[0x00]).await.is_empty());

        token.cancel();
        let report = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
        assert!(report.drained);
        assert_eq!(
            rec.seen(),
            vec![
                ("http", 0x05),
                ("http", b'G'),
                ("socks4", 0x04),
                ("socks5", 0x05)
            ]
        );
        // Listeners are closed after shutdown.
        assert!(TcpStream::connect(http).await.is_err());
        assert!(TcpStream::connect(socks).await.is_err());
    }

    #[tokio::test]
    async fn disabled_port_binds_single_listener() {
        let (server, _rec) = start(ListenPlan::Separate {
            http: None,
            socks: Some(loopback(0)),
        })
        .await;
        assert_eq!(server.local_http_addr(), None);
        assert!(server.local_socks_addr().is_some());
        assert_eq!(server.listeners().len(), 1);
        assert_eq!(server.listeners()[0].0, ListenerRole::Socks);

        let (server, _rec) = start(ListenPlan::Separate {
            http: Some(loopback(0)),
            socks: None,
        })
        .await;
        assert!(server.local_http_addr().is_some());
        assert_eq!(server.local_socks_addr(), None);
        assert_eq!(server.listeners().len(), 1);
    }

    #[tokio::test]
    async fn multiplexed_listener_sniffs_and_dispatches() {
        let (server, rec) = start(ListenPlan::Multiplexed(loopback(0))).await;
        assert!(server.is_multiplexed());
        let addr = server.local_http_addr().unwrap();
        assert_eq!(server.local_socks_addr(), Some(addr));
        assert_eq!(server.listeners().len(), 1);
        let token = server.shutdown_token();
        let run = tokio::spawn(server.run());

        assert_eq!(
            roundtrip(addr, b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").await,
            b"http"
        );
        assert_eq!(roundtrip(addr, &[0x04, 0x01]).await, b"socks4");
        assert_eq!(roundtrip(addr, &[0x05, 0x01, 0x00]).await, b"socks5");
        assert!(roundtrip(addr, &[0x16, 0x03, 0x01]).await.is_empty());
        // A silent client is rejected after the sniff timeout.
        let mut silent = TcpStream::connect(addr).await.unwrap();
        let mut buf = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), silent.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0);

        token.cancel();
        let report = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
        assert!(report.drained);
        assert_eq!(
            rec.seen(),
            vec![("http", b'C'), ("socks4", 0x04), ("socks5", 0x05)]
        );
    }

    /// Handler that holds the connection until shutdown (or forever if `ignore_shutdown`).
    struct Holding {
        ignore_shutdown: bool,
        started: Arc<tokio::sync::Notify>,
    }
    impl Holding {
        fn hold(&self, conn: Connection) -> HandlerFuture {
            let ignore = self.ignore_shutdown;
            let started = Arc::clone(&self.started);
            Box::pin(async move {
                started.notify_one();
                if ignore {
                    std::future::pending::<()>().await;
                }
                conn.shutdown.cancelled().await;
            })
        }
    }
    impl ProtocolHandlers for Holding {
        fn http(&self, conn: Connection) -> HandlerFuture {
            self.hold(conn)
        }
        fn socks4(&self, conn: Connection) -> HandlerFuture {
            self.hold(conn)
        }
        fn socks5(&self, conn: Connection) -> HandlerFuture {
            self.hold(conn)
        }
    }

    async fn run_holding(ignore_shutdown: bool) -> ShutdownReport {
        let started = Arc::new(tokio::sync::Notify::new());
        let handlers = Holding {
            ignore_shutdown,
            started: Arc::clone(&started),
        };
        let server = Server::bind(
            ListenPlan::Separate {
                http: Some(loopback(0)),
                socks: None,
            },
            Arc::new(handlers),
            quiet(),
        )
        .await
        .unwrap()
        .with_drain_timeout(Duration::from_millis(200));
        let addr = server.local_http_addr().unwrap();
        let token = server.shutdown_token();
        let run = tokio::spawn(server.run());
        let _client = TcpStream::connect(addr).await.unwrap();
        started.notified().await;
        token.cancel();
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn shutdown_drains_connections_that_honour_cancellation() {
        assert!(run_holding(false).await.drained);
    }

    #[tokio::test]
    async fn shutdown_drain_is_bounded() {
        assert!(!run_holding(true).await.drained);
    }

    #[tokio::test]
    async fn connection_cap_closes_excess_connections() {
        let started = Arc::new(tokio::sync::Notify::new());
        let handlers = Holding {
            ignore_shutdown: false,
            started: Arc::clone(&started),
        };
        let server = Server::bind(
            ListenPlan::Separate {
                http: Some(loopback(0)),
                socks: None,
            },
            Arc::new(handlers),
            quiet(),
        )
        .await
        .unwrap()
        .with_max_connections(1);
        let addr = server.local_http_addr().unwrap();
        let token = server.shutdown_token();
        let run = tokio::spawn(server.run());

        // First connection takes the only permit and is held open.
        let _held = TcpStream::connect(addr).await.unwrap();
        started.notified().await;
        // Second connection is closed immediately instead of being queued.
        let mut excess = TcpStream::connect(addr).await.unwrap();
        let mut buf = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), excess.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap_or(0);
        assert_eq!(n, 0);

        token.cancel();
        assert!(run.await.unwrap().drained);
    }
}
