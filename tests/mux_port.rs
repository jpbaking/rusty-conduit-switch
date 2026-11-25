//! End-to-end tests for listener layout with the routed engines: single-port multiplexing
//! (`http_port == socks_port > 0`) serving plain HTTP, HTTPS `CONNECT`, SOCKS4, SOCKS4a,
//! and SOCKS5 on one port through the Auto Switch router; separate listeners; and disabling
//! a listener with port `0`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rusty_conduit_switch::config::{CliInput, Config, FileConfig};
use rusty_conduit_switch::logging::{AccessLogConfig, AccessLogger, LogFormat, LogLevel, Logger};
use rusty_conduit_switch::server::{
    EngineHandlers, ListenPlan, ListenerRole, RoutingState, Server,
};
use rusty_conduit_switch::upstream::DialerOptions;

type Seen = Arc<Mutex<Vec<String>>>;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Mock upstreams
// ---------------------------------------------------------------------------

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

async fn respond<S: AsyncWrite + Unpin>(s: &mut S, body: &str) {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.shutdown().await;
}

/// HTTP origin answering `origin:<request-line>`.
async fn origin_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let line = head.lines().next().unwrap_or_default().to_string();
                respond(&mut s, &format!("origin:{line}")).await;
            });
        }
    });
    addr
}

/// HTTP upstream proxy: absolute-form requests are answered with `proxy:<request-line>`;
/// `CONNECT` is spliced to `sink`. Records every request line.
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
                rec.lock().unwrap().push(line.clone());
                if line.starts_with("CONNECT ") {
                    s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .unwrap();
                    let mut up = TcpStream::connect(sink).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                } else {
                    respond(&mut s, &format!("proxy:{line}")).await;
                }
            });
        }
    });
    (addr, seen)
}

/// A free loopback port (bound and released).
async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn quiet_logger() -> Logger {
    Logger::with_writer(LogLevel::Quiet, Box::new(std::io::sink()))
}

fn config(text: &str) -> Config {
    let file = FileConfig::from_toml_str(text, Path::new("mux_port.toml")).unwrap();
    let cfg = Config::merge(CliInput::default(), Some(file)).unwrap();
    cfg.validate().unwrap();
    cfg
}

fn routing_toml(listen: &str, corp: SocketAddr) -> String {
    format!(
        r#"{listen}
[profiles.corp]
type = "http"
host = "127.0.0.1"
port = {}

[routing]
default = "direct"

[[routing.rules]]
name = "corp-net"
host_wildcard = "*.corp.invalid"
target = "corp"

[[routing.rules]]
name = "blackhole"
host_wildcard = "*.blocked.invalid"
target = "block"
"#,
        corp.port()
    )
}

async fn access_logger(dir: &Path) -> AccessLogger {
    AccessLogger::start(
        AccessLogConfig::new(
            LogLevel::Info,
            LogFormat::Text,
            Some(dir.join("access.log")),
            Some(dir.join("socks.log")),
        ),
        quiet_logger(),
    )
    .await
    .unwrap()
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rcs-it-mux-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn wait_lines(access: &AccessLogger, path: &Path, n: usize) -> Vec<String> {
    for _ in 0..500 {
        access.flush().await.unwrap();
        let lines: Vec<String> = std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect();
        if lines.len() >= n {
            return lines;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {n} lines in {}", path.display());
}

fn engines(cfg: &Config, access: &AccessLogger) -> Arc<EngineHandlers> {
    let routing = RoutingState::from_input(&cfg.routing_input(), DialerOptions::default())
        .unwrap()
        .shared();
    Arc::new(EngineHandlers::from_routing(
        routing,
        access.clone(),
        quiet_logger(),
    ))
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

async fn http_get(proxy: SocketAddr, url: &str) -> String {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("GET {url} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(out).unwrap()
}

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

async fn socks5_domain(proxy: SocketAddr, host: &str, port: u16) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(IO_TIMEOUT, s.read_exact(&mut rep))
        .await
        .unwrap()
        .unwrap();
    (s, rep[1])
}

async fn socks4(
    proxy: SocketAddr,
    ip: [u8; 4],
    domain: Option<&str>,
    port: u16,
) -> (TcpStream, u8) {
    let mut req = vec![4, 1];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&ip);
    req.push(0);
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
    (s, rep[1])
}

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

/// Bytes the server sends back before closing (empty when the connection is rejected).
async fn send_and_read(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let _ = s.write_all(payload).await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut out)).await;
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn single_port_mux_serves_every_protocol_through_the_router() {
    let echo = echo_server().await;
    let origin = origin_server().await;
    let (corp, corp_seen) = http_proxy_server(echo).await;
    let dir = temp_dir("all");
    let access = access_logger(&dir).await;
    let cfg = config(&routing_toml("", corp));
    let server = Server::bind(
        ListenPlan::Multiplexed("127.0.0.1:0".parse().unwrap()),
        engines(&cfg, &access),
        quiet_logger(),
    )
    .await
    .unwrap();
    assert!(server.is_multiplexed());
    let addr = server.local_http_addr().unwrap();
    assert_eq!(server.local_socks_addr(), Some(addr));
    let token = server.shutdown_token();
    let run = tokio::spawn(server.run());

    // Plain HTTP: direct (origin-form) and routed to the HTTP upstream (absolute-form).
    let resp = http_get(addr, &format!("http://{origin}/plain")).await;
    assert!(resp.ends_with("origin:GET /plain HTTP/1.1"), "{resp}");
    let resp = http_get(addr, "http://intra.corp.invalid/abs").await;
    assert!(
        resp.ends_with("proxy:GET http://intra.corp.invalid/abs HTTP/1.1"),
        "{resp}"
    );
    // HTTPS CONNECT direct and via the HTTP upstream.
    let (s, head) = http_connect(addr, &echo.to_string()).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(echo_roundtrip(s, b"connect").await, b"connect");
    let (s, head) = http_connect(addr, "vault.corp.invalid:443").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(echo_roundtrip(s, b"connect-corp").await, b"connect-corp");
    // SOCKS4 / SOCKS4a / SOCKS5 on the same port.
    let (s, rep) = socks4(addr, [127, 0, 0, 1], None, echo.port()).await;
    assert_eq!(rep, 0x5A);
    assert_eq!(echo_roundtrip(s, b"s4").await, b"s4");
    let (s, rep) = socks4(addr, [0, 0, 0, 1], Some("git.corp.invalid"), 22).await;
    assert_eq!(rep, 0x5A);
    assert_eq!(echo_roundtrip(s, b"s4a").await, b"s4a");
    let (s, rep) = socks5_domain(addr, "wiki.corp.invalid", 80).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"s5").await, b"s5");
    // Block over both protocol families.
    let resp = http_get(addr, "http://x.blocked.invalid/").await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    let (_, rep) = socks5_domain(addr, "x.blocked.invalid", 80).await;
    assert_eq!(rep, 0x02);
    // Unknown first byte is rejected without a response.
    assert!(send_and_read(addr, &[0x16, 0x03, 0x01]).await.is_empty());

    assert_eq!(
        *corp_seen.lock().unwrap(),
        [
            "GET http://intra.corp.invalid/abs HTTP/1.1",
            "CONNECT vault.corp.invalid:443 HTTP/1.1",
            "CONNECT git.corp.invalid:22 HTTP/1.1",
            "CONNECT wiki.corp.invalid:80 HTTP/1.1",
        ]
    );

    let http = wait_lines(&access, &dir.join("access.log"), 5).await;
    assert!(
        http.iter().all(|l| l.contains("kind=http")
            && l.contains(" rule=")
            && l.contains(" profile=")
            && l.contains(" upstream=")),
        "{http:?}"
    );
    let socks = wait_lines(&access, &dir.join("socks.log"), 4).await;
    assert!(
        socks.iter().all(|l| l.contains("kind=socks")
            && l.contains(" rule=")
            && l.contains(" profile=")
            && l.contains(" upstream=")),
        "{socks:?}"
    );
    assert!(socks.iter().any(|l| l.contains("proto=socks4 ")));
    assert!(socks.iter().any(|l| l.contains("proto=socks4a ")));
    assert!(socks
        .iter()
        .any(|l| l.contains("proto=socks5 ") && l.contains("profile=corp")));

    token.cancel();
    assert!(
        tokio::time::timeout(IO_TIMEOUT, run)
            .await
            .unwrap()
            .unwrap()
            .drained
    );
    access.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn equal_config_ports_enable_mux_and_zero_disables_a_listener() {
    let echo = echo_server().await;
    let (corp, _) = http_proxy_server(echo).await;
    let dir = temp_dir("ports");
    let access = access_logger(&dir).await;

    // http_port == socks_port > 0: one multiplexed listener.
    let port = free_port().await;
    let listen = format!("bind = \"127.0.0.1\"\nhttp_port = {port}\nsocks_port = {port}\n");
    let cfg = config(&routing_toml(&listen, corp));
    assert!(cfg.is_multiplexed());
    let server = Server::from_options(
        &cfg.server_options(),
        engines(&cfg, &access),
        quiet_logger(),
    )
    .await
    .unwrap();
    assert_eq!(server.listeners().len(), 1);
    assert_eq!(server.listeners()[0].0, ListenerRole::Multiplexed);
    let addr = server.local_http_addr().unwrap();
    assert_eq!(addr.port(), port);
    let token = server.shutdown_token();
    let run = tokio::spawn(server.run());
    let (s, rep) = socks5_domain(addr, "a.corp.invalid", 1).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"mux").await, b"mux");
    let (s, head) = http_connect(addr, &echo.to_string()).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(echo_roundtrip(s, b"mux-http").await, b"mux-http");
    token.cancel();
    run.await.unwrap();

    // socks_port = 0: only the HTTP listener exists.
    let port = free_port().await;
    let listen = format!("bind = \"127.0.0.1\"\nhttp_port = {port}\nsocks_port = 0\n");
    let cfg = config(&routing_toml(&listen, corp));
    assert_eq!(
        ListenPlan::from_options(&cfg.server_options()),
        ListenPlan::Separate {
            http: Some(SocketAddr::from(([127, 0, 0, 1], port))),
            socks: None,
        }
    );
    let server = Server::from_options(
        &cfg.server_options(),
        engines(&cfg, &access),
        quiet_logger(),
    )
    .await
    .unwrap();
    assert_eq!(server.listeners().len(), 1);
    assert_eq!(server.local_socks_addr(), None);
    let http = server.local_http_addr().unwrap();
    let token = server.shutdown_token();
    let run = tokio::spawn(server.run());
    let (s, head) = http_connect(http, &echo.to_string()).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(echo_roundtrip(s, b"http-only").await, b"http-only");
    // A SOCKS greeting on the HTTP-only port gets no SOCKS method selection.
    let reply = send_and_read(http, &[5, 1, 0]).await;
    assert!(!reply.starts_with(&[5, 0]), "{reply:?}");
    token.cancel();
    run.await.unwrap();

    // http_port = 0: only the SOCKS listener exists, and it refuses HTTP.
    let port = free_port().await;
    let listen = format!("bind = \"127.0.0.1\"\nhttp_port = 0\nsocks_port = {port}\n");
    let cfg = config(&routing_toml(&listen, corp));
    let server = Server::from_options(
        &cfg.server_options(),
        engines(&cfg, &access),
        quiet_logger(),
    )
    .await
    .unwrap();
    assert_eq!(server.listeners().len(), 1);
    assert_eq!(server.local_http_addr(), None);
    let socks = server.local_socks_addr().unwrap();
    let token = server.shutdown_token();
    let run = tokio::spawn(server.run());
    let (s, rep) = socks4(socks, [127, 0, 0, 1], None, echo.port()).await;
    assert_eq!(rep, 0x5A);
    assert_eq!(echo_roundtrip(s, b"socks-only").await, b"socks-only");
    let reply = send_and_read(socks, b"GET http://a.corp.invalid/ HTTP/1.1\r\n\r\n").await;
    assert!(reply.is_empty(), "{}", String::from_utf8_lossy(&reply));
    token.cancel();
    run.await.unwrap();

    // Both ports 0: configuration is rejected.
    let file = FileConfig::from_toml_str(
        "http_port = 0\nsocks_port = 0\n",
        Path::new("mux_port.toml"),
    )
    .unwrap();
    let cfg = Config::merge(CliInput::default(), Some(file)).unwrap();
    assert!(cfg.validate().is_err());

    access.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn separate_listeners_route_independently() {
    let echo = echo_server().await;
    let (corp, corp_seen) = http_proxy_server(echo).await;
    let dir = temp_dir("separate");
    let access = access_logger(&dir).await;
    let cfg = config(&routing_toml("", corp));
    let server = Server::bind(
        ListenPlan::Separate {
            http: Some("127.0.0.1:0".parse().unwrap()),
            socks: Some("127.0.0.1:0".parse().unwrap()),
        },
        engines(&cfg, &access),
        quiet_logger(),
    )
    .await
    .unwrap();
    assert!(!server.is_multiplexed());
    let http = server.local_http_addr().unwrap();
    let socks = server.local_socks_addr().unwrap();
    assert_ne!(http, socks);
    let token = server.shutdown_token();
    let run = tokio::spawn(server.run());

    let resp = http_get(http, "http://h.corp.invalid/").await;
    assert!(
        resp.ends_with("proxy:GET http://h.corp.invalid/ HTTP/1.1"),
        "{resp}"
    );
    let (s, rep) = socks5_domain(socks, "s.corp.invalid", 9).await;
    assert_eq!(rep, 0x00);
    assert_eq!(echo_roundtrip(s, b"sep").await, b"sep");
    // The SOCKS port does not speak HTTP.
    assert!(send_and_read(socks, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .is_empty());
    assert_eq!(
        *corp_seen.lock().unwrap(),
        [
            "GET http://h.corp.invalid/ HTTP/1.1",
            "CONNECT s.corp.invalid:9 HTTP/1.1"
        ]
    );

    token.cancel();
    assert!(run.await.unwrap().drained);
    access.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
