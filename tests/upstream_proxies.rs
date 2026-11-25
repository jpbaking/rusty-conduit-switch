//! End-to-end tests for the upstream dialers against local mock proxy servers.
//!
//! Every mock proxy records the destination exactly as the client sent it and then tunnels
//! to a local echo server regardless of that destination. Targets under `.invalid` cannot
//! resolve, so a successful dial proves the hostname was sent unresolved (remote DNS).

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rusty_conduit_switch::config::{ProfileConfig, ProfileType};
use rusty_conduit_switch::upstream::{
    is_route_blocked, BlockDialer, DialerOptions, DirectDialer, FailoverDialer, HttpConnectDialer,
    ProfileRegistry, Socks4aDialer, Socks5Dialer, TlsOptions, UpstreamDialer, UpstreamStream,
};

const T: Duration = Duration::from_secs(5);
const REMOTE_ONLY: &str = "remote-dns-only.invalid";

type Seen = Arc<Mutex<Vec<String>>>;

// ---------------------------------------------------------------------------
// Mock servers
// ---------------------------------------------------------------------------

/// TCP echo server.
async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// A port with nothing listening.
async fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Accepts connections and never answers.
async fn silent_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    addr
}

async fn splice<S: AsyncRead + AsyncWrite + Unpin>(mut client: S, echo: SocketAddr) {
    let mut up = TcpStream::connect(echo).await.unwrap();
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
}

/// SOCKS5 proxy; when `auth` is set, only RFC 1929 with those credentials is accepted.
async fn socks5_server(
    echo: SocketAddr,
    auth: Option<(&'static str, &'static str)>,
) -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let rec = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let rec = rec.clone();
            tokio::spawn(async move {
                let ver = s.read_u8().await.unwrap();
                assert_eq!(ver, 5);
                let n = s.read_u8().await.unwrap();
                let mut methods = vec![0u8; n.into()];
                s.read_exact(&mut methods).await.unwrap();
                if let Some((user, pass)) = auth {
                    if !methods.contains(&2) {
                        s.write_all(&[5, 0xff]).await.unwrap();
                        return;
                    }
                    s.write_all(&[5, 2]).await.unwrap();
                    assert_eq!(s.read_u8().await.unwrap(), 1);
                    let ul = s.read_u8().await.unwrap();
                    let mut u = vec![0u8; ul.into()];
                    s.read_exact(&mut u).await.unwrap();
                    let pl = s.read_u8().await.unwrap();
                    let mut p = vec![0u8; pl.into()];
                    s.read_exact(&mut p).await.unwrap();
                    if u != user.as_bytes() || p != pass.as_bytes() {
                        s.write_all(&[1, 1]).await.unwrap();
                        return;
                    }
                    s.write_all(&[1, 0]).await.unwrap();
                } else {
                    assert!(methods.contains(&0));
                    s.write_all(&[5, 0]).await.unwrap();
                }
                let mut head = [0u8; 4];
                s.read_exact(&mut head).await.unwrap();
                assert_eq!(&head[..3], &[5, 1, 0]);
                let host = match head[3] {
                    1 => {
                        let mut b = [0u8; 4];
                        s.read_exact(&mut b).await.unwrap();
                        format!("ipv4:{}", std::net::Ipv4Addr::from(b))
                    }
                    4 => {
                        let mut b = [0u8; 16];
                        s.read_exact(&mut b).await.unwrap();
                        format!("ipv6:{}", std::net::Ipv6Addr::from(b))
                    }
                    3 => {
                        let len = s.read_u8().await.unwrap();
                        let mut b = vec![0u8; len.into()];
                        s.read_exact(&mut b).await.unwrap();
                        format!("domain:{}", String::from_utf8(b).unwrap())
                    }
                    other => panic!("bad atyp {other}"),
                };
                let port = s.read_u16().await.unwrap();
                rec.lock().unwrap().push(format!("{host}:{port}"));
                s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                splice(s, echo).await;
            });
        }
    });
    (addr, seen)
}

/// SOCKS4a proxy recording `user_id|host:port` (host is `ipv4:` or `domain:`).
async fn socks4a_server(echo: SocketAddr) -> (SocketAddr, Seen) {
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
                assert_eq!(&head[..2], &[4, 1]);
                let port = u16::from_be_bytes([head[2], head[3]]);
                let user = read_cstr(&mut s).await;
                let host = if head[4..7] == [0, 0, 0] && head[7] != 0 {
                    format!("domain:{}", read_cstr(&mut s).await)
                } else {
                    format!(
                        "ipv4:{}",
                        std::net::Ipv4Addr::new(head[4], head[5], head[6], head[7])
                    )
                };
                rec.lock().unwrap().push(format!("{user}|{host}:{port}"));
                s.write_all(&[0, 0x5a, 0, 0, 0, 0, 0, 0]).await.unwrap();
                splice(s, echo).await;
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

/// Reads an HTTP request head; returns it as text.
async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    while !buf.ends_with(b"\r\n\r\n") {
        buf.push(s.read_u8().await.unwrap());
    }
    String::from_utf8(buf).unwrap()
}

/// HTTP CONNECT handler: records the request line, enforces `auth` (exact
/// `Proxy-Authorization` value), replies `200` plus an early `EARLY` payload, then tunnels.
async fn serve_connect<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    echo: SocketAddr,
    auth: Option<String>,
    rec: Seen,
) {
    let head = read_head(&mut s).await;
    let line = head.lines().next().unwrap().to_string();
    rec.lock().unwrap().push(line);
    if let Some(want) = auth {
        if !head.contains(&format!("Proxy-Authorization: {want}\r\n")) {
            s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
            let _ = s.shutdown().await;
            return;
        }
    }
    s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nEARLY")
        .await
        .unwrap();
    splice(s, echo).await;
}

async fn http_server(echo: SocketAddr, auth: Option<String>) -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let rec = seen.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(serve_connect(s, echo, auth.clone(), rec.clone()));
        }
    });
    (addr, seen)
}

/// HTTPS (TLS) CONNECT proxy with a self-signed certificate for `localhost` / 127.0.0.1.
async fn https_server(
    echo: SocketAddr,
    auth: Option<String>,
) -> (SocketAddr, Seen, CertificateDer<'static>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let rec = seen.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let (acceptor, auth, rec) = (acceptor.clone(), auth.clone(), rec.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    serve_connect(tls, echo, auth, rec).await;
                }
            });
        }
    });
    (addr, seen, cert)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn assert_echo(stream: &mut UpstreamStream) {
    stream.write_all(b"ping-123").await.unwrap();
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping-123");
}

async fn assert_early_then_echo(stream: &mut UpstreamStream) {
    let mut early = [0u8; 5];
    stream.read_exact(&mut early).await.unwrap();
    assert_eq!(
        &early, b"EARLY",
        "bytes after CONNECT headers must be preserved"
    );
    assert_echo(stream).await;
}

fn seen(s: &Seen) -> Vec<String> {
    s.lock().unwrap().clone()
}

fn basic(user: &str, pass: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    )
}

fn proxy_profile(kind: ProfileType, addr: SocketAddr) -> ProfileConfig {
    let mut p = ProfileConfig::of_kind(kind);
    p.host = Some(addr.ip().to_string());
    p.port = Some(addr.port());
    p
}

// ---------------------------------------------------------------------------
// direct / block
// ---------------------------------------------------------------------------

#[tokio::test]
async fn direct_dials_target() {
    let echo = echo_server().await;
    let mut s = DirectDialer::new()
        .connect("127.0.0.1", echo.port(), T)
        .await
        .unwrap();
    assert_echo(&mut s).await;
    let mut s = DirectDialer::new()
        .connect("localhost", echo.port(), T)
        .await
        .unwrap();
    assert_echo(&mut s).await;
}

#[tokio::test]
async fn block_refuses_without_network() {
    let err = BlockDialer::new("block")
        .connect(REMOTE_ONLY, 443, T)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert!(is_route_blocked(&err));
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

#[tokio::test]
async fn socks5_no_auth_remote_dns_and_literals() {
    let echo = echo_server().await;
    let (proxy, seen_by) = socks5_server(echo, None).await;
    let d = Socks5Dialer::new(proxy.ip().to_string(), proxy.port());
    for (host, port) in [
        (REMOTE_ONLY, 5432),
        ("10.1.2.3", 22),
        ("[2001:db8::1]", 443),
    ] {
        let mut s = d.connect(host, port, T).await.unwrap();
        assert_echo(&mut s).await;
    }
    assert_eq!(
        seen(&seen_by),
        [
            format!("domain:{REMOTE_ONLY}:5432"),
            "ipv4:10.1.2.3:22".to_string(),
            "ipv6:2001:db8::1:443".to_string(),
        ]
    );
}

#[tokio::test]
async fn socks5_username_password_auth() {
    let echo = echo_server().await;
    let (proxy, seen_by) = socks5_server(echo, Some(("alice", "s3cret"))).await;
    let ok = Socks5Dialer::new(proxy.ip().to_string(), proxy.port())
        .with_credentials(Some(("alice".into(), "s3cret".into())));
    let mut s = ok.connect(REMOTE_ONLY, 80, T).await.unwrap();
    assert_echo(&mut s).await;
    assert_eq!(seen(&seen_by), [format!("domain:{REMOTE_ONLY}:80")]);

    let bad = Socks5Dialer::new(proxy.ip().to_string(), proxy.port())
        .with_credentials(Some(("alice".into(), "wrong-pw".into())));
    let err = bad.connect(REMOTE_ONLY, 80, T).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    let msg = err.to_string();
    assert!(!msg.contains("alice") && !msg.contains("wrong-pw"), "{msg}");

    let none = Socks5Dialer::new(proxy.ip().to_string(), proxy.port());
    let err = none.connect(REMOTE_ONLY, 80, T).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
}

// ---------------------------------------------------------------------------
// SOCKS4a
// ---------------------------------------------------------------------------

#[tokio::test]
async fn socks4a_remote_dns_ipv4_and_ipv6_rejection() {
    let echo = echo_server().await;
    let (proxy, seen_by) = socks4a_server(echo).await;
    let d = Socks4aDialer::new(proxy.ip().to_string(), proxy.port()).with_user_id("bob");
    let mut s = d.connect(REMOTE_ONLY, 8080, T).await.unwrap();
    assert_echo(&mut s).await;
    let mut s = d.connect("10.0.0.9", 80, T).await.unwrap();
    assert_echo(&mut s).await;
    assert_eq!(
        seen(&seen_by),
        [
            format!("bob|domain:{REMOTE_ONLY}:8080"),
            "bob|ipv4:10.0.0.9:80".to_string()
        ]
    );
    let err = d.connect("::1", 80, T).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert_eq!(
        seen(&seen_by).len(),
        2,
        "IPv6 must fail before contacting the proxy"
    );
}

// ---------------------------------------------------------------------------
// HTTP / HTTPS CONNECT
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_connect_no_auth_preserves_early_bytes() {
    let echo = echo_server().await;
    let (proxy, seen_by) = http_server(echo, None).await;
    let d = HttpConnectDialer::http(proxy.ip().to_string(), proxy.port());
    let mut s = d.connect(REMOTE_ONLY, 443, T).await.unwrap();
    assert!(matches!(s, UpstreamStream::Prefixed(_)));
    assert_early_then_echo(&mut s).await;
    let mut s = d.connect("2001:db8::5", 22, T).await.unwrap();
    assert_early_then_echo(&mut s).await;
    assert_eq!(
        seen(&seen_by),
        [
            format!("CONNECT {REMOTE_ONLY}:443 HTTP/1.1"),
            "CONNECT [2001:db8::5]:22 HTTP/1.1".to_string()
        ]
    );
}

#[tokio::test]
async fn http_connect_basic_auth() {
    let echo = echo_server().await;
    let (proxy, _) = http_server(echo, Some(basic("alice", "s3cret"))).await;
    let ok = HttpConnectDialer::http(proxy.ip().to_string(), proxy.port())
        .with_credentials(Some(("alice".into(), "s3cret".into())));
    let mut s = ok.connect(REMOTE_ONLY, 443, T).await.unwrap();
    assert_early_then_echo(&mut s).await;

    let bad = HttpConnectDialer::http(proxy.ip().to_string(), proxy.port())
        .with_credentials(Some(("alice".into(), "wrong-pw".into())));
    let err = bad.connect(REMOTE_ONLY, 443, T).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    let msg = err.to_string();
    assert!(msg.contains("407"), "{msg}");
    for secret in ["alice", "wrong-pw", &basic("alice", "wrong-pw")] {
        assert!(!msg.contains(secret), "{msg}");
    }
}

#[tokio::test]
async fn https_connect_with_custom_root_and_auth() {
    let echo = echo_server().await;
    let (proxy, seen_by, cert) = https_server(echo, Some(basic("u", "p"))).await;
    let tls = TlsOptions {
        insecure_skip_verify: false,
        roots: vec![cert],
    };
    let d = HttpConnectDialer::https("localhost", proxy.port(), &tls)
        .unwrap()
        .with_credentials(Some(("u".into(), "p".into())));
    let mut s = d.connect(REMOTE_ONLY, 443, T).await.unwrap();
    assert_early_then_echo(&mut s).await;
    assert_eq!(
        seen(&seen_by),
        [format!("CONNECT {REMOTE_ONLY}:443 HTTP/1.1")]
    );
    assert_eq!(
        d.redacted_upstream(),
        format!("https://localhost:{}", proxy.port())
    );
}

#[tokio::test]
async fn https_connect_verification() {
    let echo = echo_server().await;
    let (proxy, seen_by, _cert) = https_server(echo, None).await;

    // Untrusted self-signed certificate: rejected by the OS trust store.
    let strict =
        HttpConnectDialer::https("localhost", proxy.port(), &TlsOptions::default()).unwrap();
    assert!(strict.connect(REMOTE_ONLY, 443, T).await.is_err());

    // A pinned root that did not issue the proxy certificate: rejected.
    let other_root = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .unwrap()
        .cert
        .der()
        .clone();
    let wrong = HttpConnectDialer::https(
        "localhost",
        proxy.port(),
        &TlsOptions {
            insecure_skip_verify: false,
            roots: vec![other_root],
        },
    )
    .unwrap();
    assert!(wrong.connect(REMOTE_ONLY, 443, T).await.is_err());

    // tls_insecure_skip_verify accepts it.
    let insecure = HttpConnectDialer::https(
        proxy.ip().to_string(),
        proxy.port(),
        &TlsOptions {
            insecure_skip_verify: true,
            roots: Vec::new(),
        },
    )
    .unwrap();
    let mut s = insecure.connect(REMOTE_ONLY, 443, T).await.unwrap();
    assert_early_then_echo(&mut s).await;
    assert_eq!(
        seen(&seen_by),
        [format!("CONNECT {REMOTE_ONLY}:443 HTTP/1.1")]
    );
}

// ---------------------------------------------------------------------------
// Registry & failover
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_builds_every_profile_type_and_redacts() {
    let echo = echo_server().await;
    let (s5, _) = socks5_server(echo, Some(("alice", "s3cret"))).await;
    let mut profiles = BTreeMap::new();
    profiles.insert(
        "direct".to_string(),
        ProfileConfig::of_kind(ProfileType::Direct),
    );
    profiles.insert(
        "block".to_string(),
        ProfileConfig::of_kind(ProfileType::Block),
    );
    let mut bastion = proxy_profile(ProfileType::Socks5, s5);
    bastion.username = Some("alice".into());
    bastion.password = Some("s3cret".into());
    profiles.insert("bastion".to_string(), bastion);
    profiles.insert(
        "legacy".to_string(),
        proxy_profile(ProfileType::Socks4a, "127.0.0.1:1".parse().unwrap()),
    );
    profiles.insert(
        "corp".to_string(),
        proxy_profile(ProfileType::Http, "127.0.0.1:2".parse().unwrap()),
    );
    let mut gw = proxy_profile(ProfileType::Https, "127.0.0.1:3".parse().unwrap());
    gw.tls_insecure_skip_verify = true;
    profiles.insert("gw".to_string(), gw);
    let mut split = ProfileConfig::of_kind(ProfileType::Composite);
    split.fallback_proxy = Some("corp".into());
    profiles.insert("split".to_string(), split);

    let reg = ProfileRegistry::from_profiles(&profiles, &DialerOptions::default()).unwrap();
    assert_eq!(reg.len(), 6, "composite profiles have no dialer");
    assert_eq!(
        reg.get("bastion").unwrap().redacted_upstream(),
        format!("socks5://{s5}")
    );
    assert_eq!(
        reg.get("gw").unwrap().redacted_upstream(),
        "https://127.0.0.1:3"
    );
    let dbg = format!("{reg:?}");
    assert!(!dbg.contains("s3cret") && !dbg.contains("alice"), "{dbg}");

    let outcome = reg
        .chain(&["bastion"])
        .unwrap()
        .dial(REMOTE_ONLY, 80, T)
        .await
        .unwrap();
    assert_eq!(outcome.profile, "bastion");
    assert!(!outcome.upstream.contains("s3cret"));
    assert!(reg.chain(&["missing"]).is_err());
}

#[tokio::test]
async fn failover_advances_on_connect_and_handshake_failures() {
    let echo = echo_server().await;
    let (http, _) = http_server(echo, None).await;
    let (s4, _) = socks4a_server(echo).await;
    let dead = closed_port().await;
    let silent = silent_server().await;

    let chain = FailoverDialer::new(vec![
        (
            "dead".into(),
            Arc::new(Socks5Dialer::new("127.0.0.1", dead)) as Arc<dyn UpstreamDialer>,
        ),
        (
            "silent".into(),
            Arc::new(Socks5Dialer::new("127.0.0.1", silent.port())),
        ),
        (
            "legacy".into(),
            Arc::new(Socks4aDialer::new("127.0.0.1", s4.port())),
        ),
        (
            "corp".into(),
            Arc::new(HttpConnectDialer::http("127.0.0.1", http.port())),
        ),
    ]);
    // IPv6 target: dead (refused) -> silent (timeout) -> legacy (SOCKS4a can't carry IPv6)
    // -> corp succeeds.
    let mut out = chain
        .dial("2001:db8::7", 443, Duration::from_millis(300))
        .await
        .unwrap();
    assert_eq!(out.profile, "corp");
    assert_eq!(out.attempt, 3);
    assert_eq!(out.upstream, format!("http://{http}"));
    assert_early_then_echo(&mut out.stream).await;

    // IPv4 target: legacy is reached first after the two failures.
    let mut out = chain
        .dial("10.0.0.1", 80, Duration::from_millis(300))
        .await
        .unwrap();
    assert_eq!((out.profile.as_str(), out.attempt), ("legacy", 2));
    assert_echo(&mut out.stream).await;
}

#[tokio::test]
async fn failover_stops_on_route_blocked() {
    let echo = echo_server().await;
    let chain = FailoverDialer::new(vec![
        (
            "block".into(),
            Arc::new(BlockDialer::new("block")) as Arc<dyn UpstreamDialer>,
        ),
        ("direct".into(), Arc::new(DirectDialer::new())),
    ]);
    let err = chain.dial("127.0.0.1", echo.port(), T).await.unwrap_err();
    assert!(is_route_blocked(&err));
}

#[tokio::test]
async fn failover_reports_all_failures_without_credentials() {
    let echo = echo_server().await;
    let (http, _) = http_server(echo, Some(basic("alice", "right"))).await;
    let dead = closed_port().await;
    let chain = FailoverDialer::new(vec![
        (
            "bastion".into(),
            Arc::new(
                Socks5Dialer::new("127.0.0.1", dead)
                    .with_credentials(Some(("alice".into(), "s3cret".into()))),
            ) as Arc<dyn UpstreamDialer>,
        ),
        (
            "corp".into(),
            Arc::new(
                HttpConnectDialer::http("127.0.0.1", http.port())
                    .with_credentials(Some(("alice".into(), "s3cret".into()))),
            ),
        ),
    ]);
    let err = chain.dial(REMOTE_ONLY, 443, T).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("all 2 upstream targets failed"), "{msg}");
    assert!(msg.contains("bastion:") && msg.contains("corp:"), "{msg}");
    for secret in ["alice", "s3cret", &basic("alice", "s3cret")] {
        assert!(!msg.contains(secret), "{msg}");
    }
    assert_eq!(
        chain.redacted_upstream(),
        format!("socks5://127.0.0.1:{dead},http://{http}")
    );
}

#[tokio::test]
async fn failover_as_dialer_returns_stream() {
    let echo = echo_server().await;
    let chain: Arc<dyn UpstreamDialer> = Arc::new(FailoverDialer::new(vec![(
        "direct".into(),
        Arc::new(DirectDialer::new()) as Arc<dyn UpstreamDialer>,
    )]));
    let mut s = chain.connect("127.0.0.1", echo.port(), T).await.unwrap();
    assert_echo(&mut s).await;
}
