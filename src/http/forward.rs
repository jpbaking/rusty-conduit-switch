//! Plain HTTP forward proxy (RFC 9110) over the Auto Switch router, streaming with zero
//! caching.
//!
//! For each absolute-form request (`GET http://host[:port]/path HTTP/1.1`):
//! 1. the target is routed with `scheme = Some("http")` and the full URL,
//! 2. hop-by-hop headers are stripped (see [`strip_hop_by_hop`]),
//! 3. the decision's failover chain is dialed (fresh connection, no pooling, no DNS cache):
//!    * an `http` / `https` upstream proxy is connected to **itself** (TCP, plus TLS for
//!      `https`) and the request is forwarded in **absolute-form**
//!      (`GET http://host:port/path HTTP/1.1`) with `Proxy-Authorization` when configured —
//!      never `CONNECT host:80`;
//!    * `direct`, `socks5`, and `socks4a` dial a tunnel to the target through their
//!      [`UpstreamDialer`] and the request is sent in **origin-form** (`GET /path`);
//!    * `block` (or a filter denial) answers `403 Forbidden`,
//! 4. request and response bodies are streamed frame by frame (never buffered in full),
//! 5. one access record (`proto=http`, `mitm=false`, `rule`, `profile`, `upstream`) is
//!    emitted when the response body ends.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;

use super::{dial_error_status, error_response, failed_route, CountingBody, ProxyBody, RequestCtx};
use crate::config::Inbound;
use crate::router::{ResolvedTarget, RouteRequest};
use crate::server::RoutingState;
use crate::upstream::{
    DialFuture, FailoverDialer, HttpConnectDialer, UpstreamDialer, UpstreamError,
};

/// Fixed hop-by-hop headers removed in both directions (RFC 9110 §7.6.1 plus the legacy
/// `Proxy-Connection`, `Keep-Alive`, and `Upgrade`, which plain forwarding does not support).
const HOP_BY_HOP: [&str; 10] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Remove hop-by-hop headers: every header named in `Connection` / `Proxy-Connection`,
/// then the fixed [`HOP_BY_HOP`] set.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = [
        header::CONNECTION,
        HeaderName::from_static("proxy-connection"),
    ]
    .iter()
    .flat_map(|h| headers.get_all(h))
    .filter_map(|v| v.to_str().ok())
    .flat_map(|v| v.split(','))
    .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
    .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// Upstream target derived from an absolute-form request URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardTarget {
    pub host: String,
    pub port: u16,
    /// Value for the upstream `Host` header (authority without userinfo).
    pub host_header: String,
    /// Origin-form URI (`/path?query`).
    pub origin: Uri,
}

impl ForwardTarget {
    /// Absolute-form URI without userinfo (`http://host[:port]/path?query`), used both as
    /// the routing URL and as the request target sent to `http` / `https` upstream proxies.
    pub fn absolute(&self) -> String {
        format!("http://{}{}", self.host_header, self.origin)
    }
}

/// Validate an absolute-form `http://` URI and derive the upstream target.
pub fn parse_target(uri: &Uri) -> Result<ForwardTarget, &'static str> {
    match uri.scheme_str() {
        Some(s) if s.eq_ignore_ascii_case("http") => {}
        Some(_) => return Err("only http:// URIs can be forwarded (use CONNECT for https)"),
        None => return Err("proxy requests must use an absolute-form http:// URI"),
    }
    let authority = uri.authority().ok_or("missing host in request URI")?;
    let host = authority.host();
    if host.is_empty() {
        return Err("missing host in request URI");
    }
    let port = authority.port_u16().unwrap_or(80);
    if port == 0 {
        return Err("invalid port in request URI");
    }
    let host_header = authority
        .as_str()
        .rsplit_once('@')
        .map_or(authority.as_str(), |(_, h)| h)
        .to_string();
    let origin = uri
        .path_and_query()
        .map_or("/", |pq| pq.as_str())
        .parse::<Uri>()
        .map_err(|_| "invalid request path")?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    Ok(ForwardTarget {
        host,
        port,
        host_header,
        origin,
    })
}

/// Connects to an `http` / `https` upstream proxy itself (no `CONNECT`), so the request can
/// be forwarded to it in absolute-form. The target host/port are carried by the request.
struct ProxyEndpointDialer(HttpConnectDialer);

impl UpstreamDialer for ProxyEndpointDialer {
    fn connect(&self, _host: &str, _port: u16, timeout: Duration) -> DialFuture<'_> {
        Box::pin(self.0.connect_proxy(timeout))
    }

    fn redacted_upstream(&self) -> String {
        self.0.redacted_upstream()
    }
}

/// Build the failover chain for a plain HTTP request: `http` / `https` profiles registered
/// as forward proxies connect to the proxy itself; everything else uses its tunnel dialer.
pub fn forward_chain(
    state: &RoutingState,
    targets: &[ResolvedTarget],
) -> Result<FailoverDialer, UpstreamError> {
    let mut entries: Vec<(String, Arc<dyn UpstreamDialer>)> = Vec::with_capacity(targets.len());
    for t in targets {
        let dialer: Arc<dyn UpstreamDialer> = match state.forward_proxies.get(&t.profile) {
            Some(proxy) => Arc::new(ProxyEndpointDialer(proxy.clone())),
            None => state
                .registry
                .get(&t.profile)
                .cloned()
                .ok_or_else(|| UpstreamError::UnknownProfile(t.profile.clone()))?,
        };
        entries.push((t.profile.clone(), dialer));
    }
    Ok(FailoverDialer::new(entries))
}

/// Forward one plain HTTP request upstream and stream the response back.
pub(crate) async fn handle(ctx: &RequestCtx, req: Request<Incoming>) -> Response<ProxyBody> {
    let mut guard = ctx.access_guard("http", false, req.method().as_str(), req.uri().to_string());
    let logger = &ctx.proxy.logger;

    let target = match parse_target(req.uri()) {
        Ok(t) => t,
        Err(msg) => {
            guard.set_status(StatusCode::BAD_REQUEST);
            logger.debug(format!("rejected request from {}: {msg}", ctx.peer));
            return error_response(StatusCode::BAD_REQUEST, msg);
        }
    };
    let absolute = target.absolute();

    let state = Arc::clone(&ctx.state);
    let route_req = RouteRequest {
        inbound: Inbound::Http,
        host: &target.host,
        port: target.port,
        scheme: Some("http"),
        url: Some(&absolute),
    };
    let decision = match state.router.route(&route_req) {
        Ok(d) => d,
        Err(denied) => {
            guard.set_status(StatusCode::FORBIDDEN);
            logger.info(format!(
                "request {absolute} from {} denied by filter: {denied}",
                ctx.peer
            ));
            return error_response(StatusCode::FORBIDDEN, "destination not allowed");
        }
    };
    let rule = decision.rule_label().to_string();
    let chain = match forward_chain(&state, &decision.targets) {
        Ok(c) => c.with_logger(logger.clone()),
        Err(e) => {
            let (profile, upstream) = failed_route(&state, &decision);
            guard.set_route(&rule, profile, upstream);
            guard.set_status(StatusCode::BAD_GATEWAY);
            logger.error(format!("request {absolute}: {e}"));
            return error_response(StatusCode::BAD_GATEWAY, "upstream not configured");
        }
    };

    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    parts.version = Version::HTTP_11;
    match HeaderValue::from_str(&target.host_header) {
        Ok(v) => {
            parts.headers.insert(header::HOST, v);
        }
        Err(_) => {
            guard.set_status(StatusCode::BAD_REQUEST);
            return error_response(StatusCode::BAD_REQUEST, "invalid host");
        }
    }

    let outcome = match chain
        .dial(&target.host, target.port, state.connect_timeout)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            let status = dial_error_status(&e);
            let (profile, upstream) = failed_route(&state, &decision);
            if status == StatusCode::FORBIDDEN {
                logger.info(format!(
                    "request {absolute} blocked: rule={rule} profile={profile} upstream={upstream}"
                ));
            } else {
                logger.error(format!(
                    "request {absolute} failed: rule={rule} profile={profile} \
                     upstream={upstream} error={e}"
                ));
            }
            guard.set_route(&rule, profile, upstream);
            guard.set_status(status);
            return error_response(status, "upstream connection failed");
        }
    };
    let profile = decision
        .targets
        .get(outcome.attempt)
        .map(|t| t.label())
        .unwrap_or_else(|| outcome.profile.clone());
    let upstream = outcome.upstream.clone();

    // Absolute-form to an HTTP(S) upstream proxy; origin-form over a tunnel otherwise.
    match state.forward_proxies.get(&outcome.profile) {
        Some(proxy) => {
            parts.uri = match absolute.parse::<Uri>() {
                Ok(u) => u,
                Err(_) => {
                    guard.set_status(StatusCode::BAD_REQUEST);
                    return error_response(StatusCode::BAD_REQUEST, "invalid request URI");
                }
            };
            if let Some(auth) = proxy
                .proxy_authorization()
                .and_then(|a| HeaderValue::from_str(a).ok())
            {
                parts.headers.insert(header::PROXY_AUTHORIZATION, auth);
            }
        }
        None => parts.uri = target.origin.clone(),
    }
    logger.debug(format!(
        "{} {absolute} from {}: rule={rule} profile={profile} upstream={upstream}",
        parts.method, ctx.peer
    ));
    guard.set_route(&rule, profile, upstream.clone());
    let upstream_req = Request::from_parts(parts, CountingBody::new(body, guard.bytes_in(), None));

    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(outcome.stream)).await {
            Ok(pair) => pair,
            Err(e) => {
                guard.set_status(StatusCode::BAD_GATEWAY);
                logger.error(format!(
                    "upstream handshake for {absolute} via {upstream} failed: {e}"
                ));
                return error_response(StatusCode::BAD_GATEWAY, "upstream handshake failed");
            }
        };
    let shutdown = ctx.shutdown.clone();
    let conn_logger = logger.clone();
    ctx.tasks.spawn(async move {
        tokio::select! {
            res = conn => {
                if let Err(e) = res {
                    conn_logger.debug(format!("upstream connection error: {e}"));
                }
            }
            () = shutdown.cancelled() => {}
        }
    });

    let resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            guard.set_status(StatusCode::BAD_GATEWAY);
            logger.error(format!(
                "upstream request {absolute} via {upstream} failed: {e}"
            ));
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };
    // One request per upstream connection: dropping the sender lets the driver finish.
    drop(sender);

    let (mut parts, body) = resp.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    guard.set_status(parts.status);
    let bytes_out = guard.bytes_out();
    let body = CountingBody::new(body, Arc::clone(&bytes_out), Some(guard)).boxed();
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_rewrites_to_origin_form() {
        let t = parse_target(&"http://user:pw@example.com:8080/a/b?q=1".parse().unwrap()).unwrap();
        assert_eq!(
            (
                t.host.as_str(),
                t.port,
                t.host_header.as_str(),
                t.origin.to_string().as_str()
            ),
            ("example.com", 8080, "example.com:8080", "/a/b?q=1")
        );
        assert_eq!(t.absolute(), "http://example.com:8080/a/b?q=1");
        let t = parse_target(&"http://example.com".parse().unwrap()).unwrap();
        assert_eq!((t.port, t.origin.to_string().as_str()), (80, "/"));
        assert_eq!(t.absolute(), "http://example.com/");
        let t = parse_target(&"http://[::1]:81/x".parse().unwrap()).unwrap();
        assert_eq!(
            (t.host.as_str(), t.host_header.as_str()),
            ("::1", "[::1]:81")
        );
        assert!(parse_target(&"/relative".parse().unwrap()).is_err());
        assert!(parse_target(&"https://example.com/".parse().unwrap()).is_err());
    }

    #[test]
    fn strips_connection_listed_and_fixed_hop_by_hop_headers() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("connection", "keep-alive, X-Custom-Hop"),
            ("proxy-connection", "x-legacy"),
            ("x-custom-hop", "1"),
            ("x-legacy", "1"),
            ("keep-alive", "timeout=5"),
            ("proxy-authorization", "Basic abc"),
            ("proxy-authenticate", "Basic"),
            ("te", "trailers"),
            ("trailer", "x-t"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("x-keep", "1"),
            ("content-length", "3"),
        ] {
            h.append(k, HeaderValue::from_static(v));
        }
        strip_hop_by_hop(&mut h);
        let mut left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["content-length", "x-keep"]);
    }
}
