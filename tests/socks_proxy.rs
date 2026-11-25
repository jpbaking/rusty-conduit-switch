//! End-to-end tests for the routed inbound engines: HTTP forward (absolute-form to an HTTP
//! upstream proxy, origin-form over a SOCKS5 tunnel and `direct`), HTTPS `CONNECT`, and
//! SOCKS4 / SOCKS4a / SOCKS5 routed to mock HTTP / SOCKS5 / SOCKS4a / `direct` / `block`
//! upstreams, failover, global filter denial, and access/SOCKS log route fields.
//!
//! Every test runs a real [`Server`] with [`EngineHandlers`] on ephemeral loopback ports.
//! Mock proxies record the destination exactly as received and then splice to a local
//! "sink" (echo or HTTP origin) regardless of it. Hostnames under `.invalid` can never
//! resolve, so a successful exchange proves the name reached the upstream unresolved (zero
//! local DNS lookups).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use rusty_conduit_switch::config::{CliInput, Config, FileConfig};
use rusty_conduit_switch::logging::{AccessLogConfig, AccessLogger, LogFormat, LogLevel, Logger};
use rusty_conduit_switch::server::{
    EngineHandlers, ListenPlan, RoutingState, Server, ShutdownReport,
};
use rusty_conduit_switch::upstream::DialerOptions;

type Seen = Arc<Mutex<Vec<String>>>;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Mock servers
// ---------------------------------------------------------------------------

/// TCP echo server.
async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

/// A loopback port with nothing listening.
async fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Read an HTTP request/response head (through the blank line).
async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    while !buf.ends_with(b"\r\n\r\n") {
        match s.read_u8().await {
            Ok(b) => buf.push(b),
            Err(_) => break,
        }
    }
    String::from_utf8(buf).unwrap()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Minimal HTTP origin: records `request-line|host=<Host>` and answers
/// `200` with body `origin:<request-line>`.
async fn origin_server() -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let rec = seen.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(serve_origin(s, rec.clone()));
        }
    });
    (addr, seen)
}

async fn serve_origin<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, rec: Seen) {
    let head = read_head(&mut s).await;
    let line = head.lines().next().unwrap_or_default().to_string();
    let host = header(&head, "host").unwrap_or_default().to_string();
    rec.lock().unwrap().push(format!("{line}|host={host}"));
    let body = format!("origin:{line}");
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.shutdown().await;
}

async fn splice<S: AsyncRead + AsyncWrite + Unpin>(mut client: S, sink: SocketAddr) {
    let mut up = TcpStream::connect(sink).await.unwrap();
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
}

/// Mock HTTP upstream proxy. `CONNECT` → records the request line, `200`, then splices to
/// `sink`. Any other method (absolute-form forwarding) → records
/// `request-line|auth=<Proxy-Authorization>|host=<Host>` and answers `200` itself with
/// body `proxy:<request-line>`.
async fn http_proxy_server(sink: SocketAddr) -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let rec = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let rec = rec.clone();
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let line = head.lines().next().unwrap_or_default().to_string();
                if line.starts_with("CONNECT ") {
                    rec.lock().unwrap().push(line);
                    s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .unwrap();
                    splice(s, sink).await;
                    return;
                }
                let auth = header(&head, "proxy-authorization").unwrap_or("-");
                let host = header(&head, "host").unwrap_or("-");
                rec.lock()
                    .unwrap()
                    .push(format!("{line}|auth={auth}|host={host}"));
                let body = format!("proxy:{line}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (addr, seen)
}

/// Mock no-auth SOCKS5 upstream: records `domain:<host>:<port>` / `ipv4:..` / `ipv6:..`
/// and splices to `sink`.
async fn socks5_server(sink: SocketAddr) -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let rec = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let rec = rec.clone();
            tokio::spawn(async move {
                let mut g = [0u8; 2];
                s.read_exact(&mut g).await.unwrap();
                let mut methods = vec![0u8; usize::from(g[1])];
                s.read_exact(&mut methods).await.unwrap();
                s.write_all(&[5, 0]).await.unwrap();
                let mut head = [0u8; 4];
                s.read_exact(&mut head).await.unwrap();
                let host = match head[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        s.read_exact(&mut a).await.unwrap();
                        format!("ipv4:{}", std::net::Ipv4Addr::from(a))
                    }
                    4 => {
                        let mut a = [0u8; 16];
                        s.read_exact(&mut a).await.unwrap();
                        format!("ipv6:{}", std::net::Ipv6Addr::from(a))
                    }
                    _ => {
                        let n = s.read_u8().await.unwrap();
                        let mut d = vec![0u8; usize::from(n)];
                        s.read_exact(&mut d).await.unwrap();
                        format!("domain:{}", String::from_utf8(d).unwrap())
                    }
                };
                let port = s.read_u16().await.unwrap();
                rec.lock().unwrap().push(format!("{host}:{port}"));
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                splice(s, sink).await;
            });
        }
    });
    (addr, seen)
}

/// Mock SOCKS4a upstream: records `domain:<host>:<port>` / `ipv4:..` and splices to `sink`.
async fn socks4a_server(sink: SocketAddr) -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let rec = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let rec = rec.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 8];
                s.read_exact(&mut head).await.unwrap();
                let port = u16::from_be_bytes([head[2], head[3]]);
                read_cstr(&mut s).await;
                let host = if head[4..7] == [0, 0, 0] && head[7] != 0 {
                    format!("domain:{}", read_cstr(&mut s).await)
                } else {
                    format!(
                        "ipv4:{}",
                        std::net::Ipv4Addr::new(head[4], head[5], head[6], head[7])
                    )
                };
                rec.lock().unwrap().push(format!("{host}:{port}"));
                s.write_all(&[0, 0x5a, 0, 0, 0, 0, 0, 0]).await.unwrap();
                splice(s, sink).await;
            });
        }
    });
    (addr, seen)
}

async fn read_cstr(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    loop {
        let b = s.read_u8().await.unwrap();
        if b == 0 {
            return String::from_utf8(out).unwrap();
        }
        out.push(b);
    }
}

fn seen(s: &Seen) -> Vec<String> {
    s.lock().unwrap().clone()
}

// ---------------------------------------------------------------------------
// Proxy under test
// ---------------------------------------------------------------------------

fn quiet_logger() -> Logger {
    Logger::with_writer(LogLevel::Quiet, Box::new(std::io::sink()))
}

fn temp_dir(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rcs-it-socks-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn config(text: &str) -> Config {
    let file = FileConfig::from_toml_str(text, Path::new("socks_proxy.toml")).unwrap();
    let cfg = Config::merge(CliInput::default(), Some(file)).unwrap();
    cfg.validate().unwrap();
    cfg
}

struct Proxy {
    http: SocketAddr,
    socks: SocketAddr,
    token: CancellationToken,
    run: JoinHandle<ShutdownReport>,
    access: AccessLogger,
    http_log: PathBuf,
    socks_log: PathBuf,
    dir: PathBuf,
}

impl Proxy {
    async fn start(name: &str, toml: &str) -> Self {
        let cfg = config(toml);
        let dir = temp_dir(name);
        let (http_log, socks_log) = (dir.join("access.log"), dir.join("socks.log"));
        let logger = quiet_logger();
        let access = AccessLogger::start(
            AccessLogConfig::new(
                LogLevel::Info,
                LogFormat::Text,
                Some(http_log.clone()),
                Some(socks_log.clone()),
            ),
            logger.clone(),
        )
        .await
        .unwrap();
        let routing = RoutingState::from_input(&cfg.routing_input(), DialerOptions::default())
            .unwrap()
            .with_connect_timeout(Duration::from_secs(3))
            .shared();
        let handlers = EngineHandlers::from_routing(routing, access.clone(), logger.clone());
        let server = Server::bind(
            ListenPlan::Separate {
                http: Some("127.0.0.1:0".parse().unwrap()),
                socks: Some("127.0.0.1:0".parse().unwrap()),
            },
            Arc::new(handlers),
            logger,
        )
        .await
        .unwrap();
        Self {
            http: server.local_http_addr().unwrap(),
            socks: server.local_socks_addr().unwrap(),
            token: server.shutdown_token(),
            run: tokio::spawn(server.run()),
            access,
            http_log,
            socks_log,
            dir,
        }
    }

    /// Wait until `path` has at least `n` lines (flushing the access logger).
    async fn lines(&self, path: &Path, n: usize) -> Vec<String> {
        for _ in 0..500 {
            self.access.flush().await.unwrap();
            let lines = read_lines(path);
            if lines.len() >= n {
                return lines;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "expected {n} lines in {}, got {:?}",
            path.display(),
            read_lines(path)
        );
    }

    async fn http_lines(&self, n: usize) -> Vec<String> {
        self.lines(&self.http_log.clone(), n).await
    }

    async fn socks_lines(&self, n: usize) -> Vec<String> {
        self.lines(&self.socks_log.clone(), n).await
    }

    async fn stop(self) {
        self.token.cancel();
        let report = tokio::time::timeout(IO_TIMEOUT, self.run)
            .await
            .unwrap()
            .unwrap();
        assert!(report.drained);
        self.access.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Find the single log line containing `needle`.
fn line_with<'a>(lines: &'a [String], needle: &str) -> &'a str {
    let found: Vec<&String> = lines.iter().filter(|l| l.contains(needle)).collect();
    assert_eq!(
        found.len(),
        1,
        "expected one line with {needle:?}: {lines:?}"
    );
    found[0]
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

/// Plain HTTP request through the proxy (`Connection: close`); returns the whole response.
async fn http_get(proxy: SocketAddr, url: &str, host: &str) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let req = format!(
        "GET {url} HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: Basic Y2xpZW50OnNlY3JldA==\r\n\
         Connection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(out).unwrap()
}

/// `CONNECT target`; returns the stream positioned after the response head and the head.
async fn http_connect(proxy: SocketAddr, target: &str) -> (TcpStream, String) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = tokio::time::timeout(IO_TIMEOUT, read_head(&mut s))
        .await
        .unwrap();
    (s, head)
}

/// SOCKS5 `CONNECT` to a domain target; returns the stream and the `REP` byte.
async fn socks5_domain(proxy: SocketAddr, host: &str, port: u16) -> (TcpStream, u8) {
    let mut req = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    socks5_request(proxy, &req).await
}

/// SOCKS5 `CONNECT` to an IP target.
async fn socks5_ip(proxy: SocketAddr, target: SocketAddr) -> (TcpStream, u8) {
    let mut req = vec![5, 1, 0];
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    socks5_request(proxy, &req).await
}

async fn socks5_request(proxy: SocketAddr, req: &[u8]) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    s.write_all(req).await.unwrap();
    let mut rep = [0u8; 4];
    tokio::time::timeout(IO_TIMEOUT, s.read_exact(&mut rep))
        .await
        .unwrap()
        .unwrap();
    let rest = match rep[3] {
        4 => 16 + 2,
        _ => 4 + 2,
    };
    let mut tail = vec![0u8; rest];
    s.read_exact(&mut tail).await.unwrap();
    (s, rep[1])
}

/// SOCKS4 (`domain = None`) or SOCKS4a `CONNECT`; returns the stream and the `CD` byte.
async fn socks4(
    proxy: SocketAddr,
    ip: [u8; 4],
    domain: Option<&str>,
    port: u16,
) -> (TcpStream, u8) {
    let mut req = vec![4, 1];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&ip);
    req.extend_from_slice(b"user\0");
    if let Some(d) = domain {
        req.extend_from_slice(d.as_bytes());
        req.push(0);
    }
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 8];
    tokio::time::timeout(IO_TIMEOUT, s.read_exact(&mut rep))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rep[0], 0);
    (s, rep[1])
}

/// Write `payload`, half-close, and read everything back.
async fn echo_roundtrip(mut s: TcpStream, payload: &[u8]) -> Vec<u8> {
    s.write_all(payload).await.unwrap();
    s.shutdown().await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    out
}

// ---------------------------------------------------------------------------
// Shared topology
// ---------------------------------------------------------------------------

struct Upstreams {
    echo: SocketAddr,
    origin: SocketAddr,
    origin_seen: Seen,
    /// HTTP proxy for absolute-form forwarding (answers itself) and CONNECT (→ echo).
    corp: SocketAddr,
    corp_seen: Seen,
    /// SOCKS5 proxy splicing to the HTTP origin.
    web: SocketAddr,
    web_seen: Seen,
    /// SOCKS5 proxy splicing to the echo server.
    bastion: SocketAddr,
    bastion_seen: Seen,
    /// SOCKS4a proxy splicing to the echo server.
    legacy: SocketAddr,
    legacy_seen: Seen,
    dead: u16,
}

impl Upstreams {
    async fn start() -> Self {
        let echo = echo_server().await;
        let (origin, origin_seen) = origin_server().await;
        let (corp, corp_seen) = http_proxy_server(echo).await;
        let (web, web_seen) = socks5_server(origin).await;
        let (bastion, bastion_seen) = socks5_server(echo).await;
        let (legacy, legacy_seen) = socks4a_server(echo).await;
        Self {
            echo,
            origin,
            origin_seen,
            corp,
            corp_seen,
            web,
            web_seen,
            bastion,
            bastion_seen,
            legacy,
            legacy_seen,
            dead: closed_port().await,
        }
    }

    fn toml(&self, extra: &str) -> String {
        format!(
            r#"{extra}
[profiles.corp]
type = "http"
host = "127.0.0.1"
port = {corp}
username = "proxyuser"
password = "hunter2"

[profiles.web]
type = "socks5"
host = "127.0.0.1"
port = {web}

[profiles.bastion]
type = "socks5"
host = "127.0.0.1"
port = {bastion}

[profiles.legacy]
type = "socks4a"
host = "127.0.0.1"
port = {legacy}

[profiles.dead]
type = "socks5"
host = "127.0.0.1"
port = {dead}

[routing]
default = "direct"

[[routing.rules]]
name = "corp-net"
host_wildcard = "*.corp.invalid"
target = "corp"

[[routing.rules]]
name = "web-tunnel"
host_wildcard = "*.web.invalid"
target = "web"

[[routing.rules]]
name = "bastion-hosts"
host = ["nonexistent.invalid", "db.bastion.invalid"]
target = "bastion"

[[routing.rules]]
name = "legacy-hosts"
host_wildcard = "*.legacy.invalid"
target = "legacy"

[[routing.rules]]
name = "with-failover"
host_wildcard = "*.failover.invalid"
target = ["dead", "bastion"]

[[routing.rules]]
name = "web-failover"
host_wildcard = "*.webfail.invalid"
target = ["dead", "web"]

[[routing.rules]]
name = "blackhole"
host_wildcard = "*.blocked.invalid"
target = "block"
"#,
            corp = self.corp.port(),
            web = self.web.port(),
            bastion = self.bastion.port(),
            legacy = self.legacy.port(),
            dead = self.dead,
        )
    }
}

fn upstream(addr: SocketAddr, scheme: &str) -> String {
    format!("upstream={scheme}://127.0.0.1:{}", addr.port())
}

// ---------------------------------------------------------------------------
// HTTP / HTTPS inbound
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plain_http_to_http_upstream_uses_absolute_form_with_proxy_auth() {
    let up = Upstreams::start().await;
    let proxy = Proxy::start("abs-form", &up.toml("")).await;

    let resp = http_get(
        proxy.http,
        "http://www.corp.invalid:8080/a/b?q=1",
        "www.corp.invalid:8080",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(
        resp.ends_with("proxy:GET http://www.corp.invalid:8080/a/b?q=1 HTTP/1.1"),
        "{resp}"
    );
    // Absolute-form, never `CONNECT host:80`; the client's own Proxy-Authorization is
    // replaced by the profile's credentials (proxyuser:hunter2).
    assert_eq!(
        seen(&up.corp_seen),
        [
            "GET http://www.corp.invalid:8080/a/b?q=1 HTTP/1.1|auth=Basic cHJveHl1c2VyOmh1bnRlcjI=|host=www.corp.invalid:8080"
        ]
    );
    assert!(seen(&up.origin_seen).is_empty());

    let lines = proxy.http_lines(1).await;
    let line = line_with(&lines, "method=GET");
    assert!(line.contains("kind=http"), "{line}");
    assert!(line.contains("proto=http mitm=false"), "{line}");
    assert!(
        line.contains(&format!(
            "rule=corp-net profile=corp {} status=200",
            upstream(up.corp, "http")
        )),
        "{line}"
    );
    assert!(
        !line.contains("hunter2") && !line.contains("proxyuser"),
        "{line}"
    );
    proxy.stop().await;
}

#[tokio::test]
async fn plain_http_over_socks5_and_direct_uses_origin_form() {
    let up = Upstreams::start().await;
    let proxy = Proxy::start("origin-form", &up.toml("")).await;

    // Routed to the SOCKS5 `web` profile: tunnel, then origin-form to the origin.
    let resp = http_get(
        proxy.http,
        "http://app.web.invalid/x?y=2",
        "app.web.invalid",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.ends_with("origin:GET /x?y=2 HTTP/1.1"), "{resp}");
    assert_eq!(seen(&up.web_seen), ["domain:app.web.invalid:80"]);

    // Default route: direct to the origin.
    let url = format!("http://{}/direct", up.origin);
    let resp = http_get(proxy.http, &url, &up.origin.to_string()).await;
    assert!(resp.ends_with("origin:GET /direct HTTP/1.1"), "{resp}");

    let origin = seen(&up.origin_seen);
    assert_eq!(
        origin,
        [
            "GET /x?y=2 HTTP/1.1|host=app.web.invalid".to_string(),
            format!("GET /direct HTTP/1.1|host={}", up.origin),
        ]
    );
    assert!(seen(&up.corp_seen).is_empty());

    let lines = proxy.http_lines(2).await;
    let web = line_with(&lines, "app.web.invalid");
    assert!(
        web.contains(&format!(
            "rule=web-tunnel profile=web {} status=200",
            upstream(up.web, "socks5")
        )),
        "{web}"
    );
    let direct = line_with(&lines, "/direct");
    assert!(
        direct.contains("rule=<default> profile=direct upstream=direct status=200"),
        "{direct}"
    );
    proxy.stop().await;
}

#[tokio::test]
async fn https_connect_is_routed_to_every_upstream_type() {
    let up = Upstreams::start().await;
    let proxy = Proxy::start("connect", &up.toml("")).await;

    let cases = [
        (
            "secure.corp.invalid:443",
            "corp-net",
            "corp",
            upstream(up.corp, "http"),
        ),
        (
            "db.bastion.invalid:443",
            "bastion-hosts",
            "bastion",
            upstream(up.bastion, "socks5"),
        ),
        (
            "old.legacy.invalid:443",
            "legacy-hosts",
            "legacy",
            upstream(up.legacy, "socks4a"),
        ),
    ];
    for (target, ..) in &cases {
        let (s, head) = http_connect(proxy.http, target).await;
        assert!(
            head.starts_with("HTTP/1.1 200 Connection Established"),
            "{target}: {head}"
        );
        assert_eq!(echo_roundtrip(s, b"tls-bytes").await, b"tls-bytes");
    }
    // Direct by default.
    let (s, head) = http_connect(proxy.http, &up.echo.to_string()).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(echo_roundtrip(s, b"direct").await, b"direct");

    assert_eq!(
        seen(&up.corp_seen),
        ["CONNECT secure.corp.invalid:443 HTTP/1.1"]
    );
    assert_eq!(seen(&up.bastion_seen), ["domain:db.bastion.invalid:443"]);
    assert_eq!(seen(&up.legacy_seen), ["domain:old.legacy.invalid:443"]);

    let lines = proxy.http_lines(4).await;
    for (target, rule, profile, upstream) in &cases {
        let line = line_with(&lines, &format!("target={target}"));
        assert!(
            line.contains(&format!(
                "proto=https mitm=false method=CONNECT target={target} rule={rule} \
                 profile={profile} {upstream} status=200 bytes_in=9 bytes_out=9"
            )),
            "{line}"
        );
    }
    let direct = line_with(&lines, &format!("target={}", up.echo));
    assert!(
        direct.contains("profile=direct upstream=direct status=200"),
        "{direct}"
    );
    proxy.stop().await;
}

#[tokio::test]
async fn block_route_and_filter_denial_answer_403() {
    let up = Upstreams::start().await;
    let proxy = Proxy::start(
        "http-block",
        &up.toml("[filter]\nblock = [\"*.denied.invalid\"]\n"),
    )
    .await;

    let resp = http_get(proxy.http, "http://x.blocked.invalid/", "x.blocked.invalid").await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    let (_, head) = http_connect(proxy.http, "x.blocked.invalid:443").await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    let resp = http_get(proxy.http, "http://x.denied.invalid/", "x.denied.invalid").await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    let (_, head) = http_connect(proxy.http, "x.denied.invalid:443").await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");

    let lines = proxy.http_lines(4).await;
    for method in ["GET", "CONNECT"] {
        let blocked: Vec<&String> = lines
            .iter()
            .filter(|l| l.contains("x.blocked.invalid") && l.contains(&format!("method={method}")))
            .collect();
        assert_eq!(blocked.len(), 1, "{lines:?}");
        assert!(
            blocked[0].contains("rule=blackhole profile=block upstream=block status=403"),
            "{}",
            blocked[0]
        );
    }
    let denied: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("x.denied.invalid"))
        .collect();
    assert_eq!(denied.len(), 2, "{lines:?}");
    assert!(
        denied.iter().all(|l| l.contains("status=403")),
        "{denied:?}"
    );
    // Nothing reached any upstream.
    assert!(seen(&up.corp_seen).is_empty() && seen(&up.origin_seen).is_empty());
    proxy.stop().await;
}

#[tokio::test]
async fn http_failover_skips_dead_upstream() {
    let up = Upstreams::start().await;
    let proxy = Proxy::start("http-failover", &up.toml("")).await;

    let resp = http_get(
        proxy.http,
        "http://a.webfail.invalid/f",
        "a.webfail.invalid",
    )
    .await;
    assert!(resp.ends_with("origin:GET /f HTTP/1.1"), "{resp}");
    let (s, head) = http_connect(proxy.http, "b.failover.invalid:22").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(echo_roundtrip(s, b"ssh").await, b"ssh");

    assert_eq!(seen(&up.web_seen), ["domain:a.webfail.invalid:80"]);
    assert_eq!(seen(&up.bastion_seen), ["domain:b.failover.invalid:22"]);
    let lines = proxy.http_lines(2).await;
    let get = line_with(&lines, "method=GET");
    assert!(
        get.contains(&format!(
            "rule=web-failover profile=web {}",
            upstream(up.web, "socks5")
        )),
        "{get}"
    );
    let connect = line_with(&lines, "method=CONNECT");
    assert!(
        connect.contains(&format!(
            "rule=with-failover profile=bastion {}",
            upstream(up.bastion, "socks5")
        )),
        "{connect}"
    );
    proxy.stop().await;
}

// ---------------------------------------------------------------------------
// SOCKS inbound
// ---------------------------------------------------------------------------

#[tokio::test]
async fn socks5_is_routed_across_protocols() {
    let up = Upstreams::start().await;
    let proxy = Proxy::start("socks5-cross", &up.toml("")).await;

    // SOCKS5 → HTTP upstream (CONNECT).
    let (s, rep) = socks5_domain(proxy.socks, "git.corp.invalid", 22).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"to-http").await, b"to-http");
    // SOCKS5 → SOCKS5 upstream.
    let (s, rep) = socks5_domain(proxy.socks, "db.bastion.invalid", 5432).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"to-socks5").await, b"to-socks5");
    // SOCKS5 → SOCKS4a upstream.
    let (s, rep) = socks5_domain(proxy.socks, "mf.legacy.invalid", 23).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"to-socks4a").await, b"to-socks4a");
    // SOCKS5 IPv4 → direct.
    let (s, rep) = socks5_ip(proxy.socks, up.echo).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"direct-v4").await, b"direct-v4");
    // SOCKS5 → block: 0x02 (connection not allowed by ruleset).
    let (_, rep) = socks5_domain(proxy.socks, "ads.blocked.invalid", 443).await;
    assert_eq!(rep, 0x02);

    assert_eq!(
        seen(&up.corp_seen),
        ["CONNECT git.corp.invalid:22 HTTP/1.1"]
    );
    assert_eq!(seen(&up.bastion_seen), ["domain:db.bastion.invalid:5432"]);
    assert_eq!(seen(&up.legacy_seen), ["domain:mf.legacy.invalid:23"]);

    let lines = proxy.socks_lines(5).await;
    let expect = [
        (
            "target=git.corp.invalid:22".to_string(),
            format!(
                "rule=corp-net profile=corp {} status=ok",
                upstream(up.corp, "http")
            ),
        ),
        (
            "target=db.bastion.invalid:5432".to_string(),
            format!(
                "rule=bastion-hosts profile=bastion {} status=ok",
                upstream(up.bastion, "socks5")
            ),
        ),
        (
            "target=mf.legacy.invalid:23".to_string(),
            format!(
                "rule=legacy-hosts profile=legacy {} status=ok",
                upstream(up.legacy, "socks4a")
            ),
        ),
        (
            format!("target={}", up.echo),
            "rule=<default> profile=direct upstream=direct status=ok".to_string(),
        ),
        (
            "target=ads.blocked.invalid:443".to_string(),
            "rule=blackhole profile=block upstream=block status=not_allowed".to_string(),
        ),
    ];
    for (needle, fields) in &expect {
        let line = line_with(&lines, needle.as_str());
        assert!(
            line.contains("kind=socks") && line.contains("proto=socks5 cmd=CONNECT"),
            "{line}"
        );
        assert!(line.contains(fields.as_str()), "{line}");
        assert!(!line.contains("hunter2"), "{line}");
    }
    proxy.stop().await;
}

#[tokio::test]
async fn socks5_ipv6_target_is_routed_direct() {
    let Ok(l) = TcpListener::bind("[::1]:0").await else {
        eprintln!("IPv6 loopback unavailable; skipping");
        return;
    };
    let echo6 = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    let up = Upstreams::start().await;
    let proxy = Proxy::start("socks5-v6", &up.toml("")).await;
    let (s, rep) = socks5_ip(proxy.socks, echo6).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"v6").await, b"v6");
    let lines = proxy.socks_lines(1).await;
    assert!(
        lines[0].contains(&format!("target={echo6}")) && lines[0].contains("profile=direct"),
        "{lines:?}"
    );
    proxy.stop().await;
}

#[tokio::test]
async fn socks4_and_socks4a_are_routed_across_protocols() {
    let up = Upstreams::start().await;
    let proxy = Proxy::start("socks4-cross", &up.toml("")).await;

    // SOCKS4 IPv4 → direct.
    let (s, rep) = socks4(proxy.socks, [127, 0, 0, 1], None, up.echo.port()).await;
    assert_eq!(rep, 0x5A);
    assert_eq!(echo_roundtrip(s, b"v4-direct").await, b"v4-direct");
    // SOCKS4a → SOCKS5 upstream, HTTP upstream, SOCKS4a upstream.
    for (host, payload) in [
        ("db.bastion.invalid", &b"4a-socks5"[..]),
        ("svn.corp.invalid", b"4a-http"),
        ("tn.legacy.invalid", b"4a-socks4a"),
    ] {
        let (s, rep) = socks4(proxy.socks, [0, 0, 0, 1], Some(host), 3690).await;
        assert_eq!(rep, 0x5A, "{host}");
        assert_eq!(echo_roundtrip(s, payload).await, payload);
    }
    // Block → 0x5B.
    let (_, rep) = socks4(proxy.socks, [0, 0, 0, 1], Some("x.blocked.invalid"), 80).await;
    assert_eq!(rep, 0x5B);

    assert_eq!(seen(&up.bastion_seen), ["domain:db.bastion.invalid:3690"]);
    assert_eq!(
        seen(&up.corp_seen),
        ["CONNECT svn.corp.invalid:3690 HTTP/1.1"]
    );
    assert_eq!(seen(&up.legacy_seen), ["domain:tn.legacy.invalid:3690"]);

    let lines = proxy.socks_lines(5).await;
    let direct = line_with(&lines, "proto=socks4 ");
    assert!(
        direct.contains("rule=<default> profile=direct upstream=direct status=ok"),
        "{direct}"
    );
    let corp = line_with(&lines, "svn.corp.invalid");
    assert!(
        corp.contains(&format!(
            "proto=socks4a cmd=CONNECT target=svn.corp.invalid:3690 rule=corp-net profile=corp {} status=ok",
            upstream(up.corp, "http")
        )),
        "{corp}"
    );
    let blocked = line_with(&lines, "x.blocked.invalid");
    assert!(
        blocked.contains("profile=block upstream=block status=not_allowed"),
        "{blocked}"
    );
    proxy.stop().await;
}

#[tokio::test]
async fn socks_failover_and_filter_denial() {
    let up = Upstreams::start().await;
    let proxy = Proxy::start(
        "socks-failover",
        &up.toml("[filter]\nblock = [\"*.denied.invalid\"]\n"),
    )
    .await;

    let (s, rep) = socks5_domain(proxy.socks, "a.failover.invalid", 9000).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"fo5").await, b"fo5");
    let (s, rep) = socks4(proxy.socks, [0, 0, 0, 1], Some("b.failover.invalid"), 9001).await;
    assert_eq!(rep, 0x5A);
    assert_eq!(echo_roundtrip(s, b"fo4").await, b"fo4");
    assert_eq!(
        seen(&up.bastion_seen),
        [
            "domain:a.failover.invalid:9000",
            "domain:b.failover.invalid:9001"
        ]
    );

    let (_, rep) = socks5_domain(proxy.socks, "x.denied.invalid", 443).await;
    assert_eq!(rep, 0x02);
    let (_, rep) = socks4(proxy.socks, [0, 0, 0, 1], Some("x.denied.invalid"), 443).await;
    assert_eq!(rep, 0x5B);

    // Every target in the chain fails → general/refused failure, not "not allowed".
    let toml = up.toml("").replace(
        "target = [\"dead\", \"bastion\"]",
        "target = [\"dead\", \"dead\"]",
    );
    let all_dead = Proxy::start("socks-all-dead", &toml).await;
    let (_, rep) = socks5_domain(all_dead.socks, "c.failover.invalid", 1).await;
    assert!(rep != 0x00 && rep != 0x02, "rep=0x{rep:02x}");
    all_dead.stop().await;

    let lines = proxy.socks_lines(4).await;
    let fo = line_with(&lines, "a.failover.invalid");
    assert!(
        fo.contains(&format!(
            "rule=with-failover profile=bastion {} status=ok",
            upstream(up.bastion, "socks5")
        )),
        "{fo}"
    );
    let denied: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("x.denied.invalid"))
        .collect();
    assert_eq!(denied.len(), 2, "{lines:?}");
    assert!(
        denied.iter().all(|l| l.contains("status=not_allowed")),
        "{denied:?}"
    );
    proxy.stop().await;
}

#[tokio::test]
async fn proxied_hostnames_are_never_resolved_locally() {
    let up = Upstreams::start().await;
    let proxy = Proxy::start("no-local-dns", &up.toml("")).await;
    const HOST: &str = "nonexistent.invalid";

    let (s, rep) = socks5_domain(proxy.socks, HOST, 7001).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"a").await, b"a");
    let (s, rep) = socks4(proxy.socks, [0, 0, 0, 1], Some(HOST), 7002).await;
    assert_eq!(rep, 0x5A);
    assert_eq!(echo_roundtrip(s, b"b").await, b"b");
    let (s, head) = http_connect(proxy.http, &format!("{HOST}:7003")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(echo_roundtrip(s, b"c").await, b"c");

    assert_eq!(
        seen(&up.bastion_seen),
        [
            format!("domain:{HOST}:7001"),
            format!("domain:{HOST}:7002"),
            format!("domain:{HOST}:7003"),
        ]
    );

    // Sanity: `direct` to the same name does need DNS and fails.
    let (_, rep) = socks5_domain(proxy.socks, "other.nonexistent.invalid", 80).await;
    assert_ne!(rep, 0x00);
    proxy.stop().await;
}
