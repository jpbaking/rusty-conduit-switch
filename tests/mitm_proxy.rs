//! End-to-end tests for opt-in HTTPS MITM over Auto Switch routed upstreams.
//!
//! Each test runs a real [`Server`] with [`EngineHandlers`] (MITM installed through
//! [`EngineHandlers::with_mitm`]) on ephemeral loopback ports. Covered here:
//!
//! * MITM over `direct`, a mock SOCKS5 upstream, and a mock HTTP `CONNECT` upstream. Upstream
//!   TLS runs over the routed stream, and the route fields appear in `mitm=true` access
//!   records.
//! * Per-request URL-rule routing that switches upstreams inside one MITM connection, plus
//!   `block` per request.
//! * PKCS#12 CA loading, leaf caching within the TTL, lazy expiry, the background reaper,
//!   and the entry cap.
//! * `--socks-block-web-in-mitm` blocking plaintext HTTP and HTTP-ALPN TLS over SOCKS while
//!   allowing non-web TCP.
//!
//! Every CA is ephemeral and generated in-process. The TLS origin is local and presents a
//! leaf for `localhost`. Mock proxies record the destination exactly as received and then
//! splice to the origin.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

use rusty_conduit_switch::config::{CliInput, Config, FileConfig};
use rusty_conduit_switch::http::mitm_tunnel::client_config_with_roots;
use rusty_conduit_switch::logging::{AccessLogConfig, AccessLogger, LogFormat, LogLevel, Logger};
use rusty_conduit_switch::mitm::ca::CaMaterial;
use rusty_conduit_switch::mitm::cache::CertCache;
use rusty_conduit_switch::mitm::signer::LeafSigner;
use rusty_conduit_switch::mitm::{crypto_provider, MitmState};
use rusty_conduit_switch::server::{
    EngineHandlers, ListenPlan, RoutingState, Server, ShutdownReport,
};
use rusty_conduit_switch::upstream::DialerOptions;

type Seen = Arc<Mutex<Vec<String>>>;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Ephemeral CAs and helpers
// ---------------------------------------------------------------------------

struct TestCa {
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn test_ca(cn: &str) -> TestCa {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365);
    let cert = params.self_signed(&key).unwrap();
    TestCa {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    }
}

/// Encrypted PKCS#12 bundle holding the CA key and certificate.
fn p12_bytes(ca: &TestCa, password: &str) -> Vec<u8> {
    use p12_keystore::{
        Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain,
    };
    let mut ks = KeyStore::new();
    let chain = PrivateKeyChain::new(
        b"ca-key".to_vec(),
        PrivateKey::from_der(&ca.key_der).unwrap(),
        [Certificate::from_der(&ca.cert_der).unwrap()],
    );
    ks.add_entry("ca", KeyStoreEntry::PrivateKeyChain(chain));
    ks.writer(password)
        .encryption_algorithm(EncryptionAlgorithm::PbeWithHmacSha256AndAes256)
        .write()
        .unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rcs-it-mitm-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn quiet_logger() -> Logger {
    Logger::with_writer(LogLevel::Quiet, Box::new(std::io::sink()))
}

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn seen(s: &Seen) -> Vec<String> {
    s.lock().unwrap().clone()
}

// ---------------------------------------------------------------------------
// Local TLS origin
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// HTTPS origin on 127.0.0.1 (leaf for `localhost`, own private CA, `h2` + `http/1.1`)
/// answering `hit <n> <method> <path>` with an hour-long `Cache-Control`. `conns` counts
/// accepted TLS connections.
struct Origin {
    addr: SocketAddr,
    ca_der: CertificateDer<'static>,
    hits: Arc<AtomicUsize>,
    conns: Arc<AtomicUsize>,
}

async fn spawn_origin() -> Origin {
    let ca = test_ca("Switch Origin CA");
    let material =
        CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None).unwrap();
    let signer = LeafSigner::new(&material, Duration::from_secs(3600), crypto_provider()).unwrap();
    let leaf = signer
        .sign_at("localhost", OffsetDateTime::now_utc())
        .unwrap();
    let mut cfg = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(leaf.certified)));
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let conns = Arc::new(AtomicUsize::new(0));
    let (counter, conn_counter) = (Arc::clone(&hits), Arc::clone(&conns));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let counter = Arc::clone(&counter);
            let conn_counter = Arc::clone(&conn_counter);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                conn_counter.fetch_add(1, Ordering::SeqCst);
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let service = service_fn(move |req: Request<Incoming>| {
                    let counter = Arc::clone(&counter);
                    async move {
                        let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                        let body = format!("hit {n} {} {}", req.method(), req.uri().path());
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("cache-control", "public, max-age=3600")
                                .body(http_body_util::Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                });
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                }
            });
        }
    });
    Origin {
        addr,
        ca_der: CertificateDer::from(ca.cert_der),
        hits,
        conns,
    }
}

// ---------------------------------------------------------------------------
// Mock upstream proxies (record the destination, then splice to `sink`)
// ---------------------------------------------------------------------------

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

async fn splice<S: AsyncRead + AsyncWrite + Unpin>(mut client: S, sink: SocketAddr) {
    let mut up = TcpStream::connect(sink).await.unwrap();
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
}

/// Mock HTTP `CONNECT` proxy: records the request line, answers `200`, splices.
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
                rec.lock().unwrap().push(line);
                s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                splice(s, sink).await;
            });
        }
    });
    (addr, seen)
}

/// Mock no-auth SOCKS5 proxy: records `domain:<host>:<port>` (or `ip:<..>`), splices.
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
                    3 => {
                        let n = s.read_u8().await.unwrap();
                        let mut d = vec![0u8; usize::from(n)];
                        s.read_exact(&mut d).await.unwrap();
                        format!("domain:{}", String::from_utf8(d).unwrap())
                    }
                    1 => {
                        let mut a = [0u8; 4];
                        s.read_exact(&mut a).await.unwrap();
                        format!("ip:{}", std::net::Ipv4Addr::from(a))
                    }
                    _ => {
                        let mut a = [0u8; 16];
                        s.read_exact(&mut a).await.unwrap();
                        format!("ip:{}", std::net::Ipv6Addr::from(a))
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

// ---------------------------------------------------------------------------
// Proxy harness
// ---------------------------------------------------------------------------

enum CaKind {
    Pem,
    Pkcs12,
}

struct Opts {
    ca: CaKind,
    ttl: Duration,
    reap_every: Option<Duration>,
    socks_block_web: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            ca: CaKind::Pem,
            ttl: Duration::from_secs(3600),
            reap_every: None,
            socks_block_web: false,
        }
    }
}

struct MitmProxy {
    http: SocketAddr,
    socks: SocketAddr,
    ca: TestCa,
    state: MitmState,
    socks_guard: bool,
    token: CancellationToken,
    run: JoinHandle<ShutdownReport>,
    reaper: Option<JoinHandle<()>>,
    access: AccessLogger,
    http_log: PathBuf,
    socks_log: PathBuf,
    dir: PathBuf,
}

impl MitmProxy {
    /// Start a MITM proxy from `toml` routing config that trusts `origin_ca` upstream.
    /// The TTL is set directly, bypassing the CLI's 10s minimum, so expiry shows up fast.
    async fn start(name: &str, toml: &str, origin_ca: &CertificateDer<'static>, o: Opts) -> Self {
        let dir = temp_dir(name);
        let file = FileConfig::from_toml_str(toml, Path::new("mitm_proxy.toml")).unwrap();
        let mut cfg = Config::merge(CliInput::default(), Some(file)).unwrap();
        cfg.validate().unwrap();
        let ca = test_ca("Switch Integration MITM CA");
        cfg.mitm_cert_ttl = o.ttl;
        cfg.socks_block_web_in_mitm = o.socks_block_web;
        match o.ca {
            CaKind::Pem => {
                let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
                std::fs::write(&cert, &ca.cert_pem).unwrap();
                std::fs::write(&key, &ca.key_pem).unwrap();
                cfg.mitm_ca_cert = Some(cert);
                cfg.mitm_ca_key = Some(key);
            }
            CaKind::Pkcs12 => {
                let (p12, pass) = (dir.join("ca.p12"), dir.join("ca.pass"));
                std::fs::write(&p12, p12_bytes(&ca, "integration-pass")).unwrap();
                std::fs::write(&pass, "integration-pass\n").unwrap();
                cfg.mitm_ca_p12 = Some(p12);
                cfg.mitm_ca_passphrase_file = Some(pass);
            }
        }
        assert!(cfg.mitm_enabled());

        let provider = crypto_provider();
        let mut roots = RootCertStore::empty();
        roots.add(origin_ca.clone()).unwrap();
        let upstream = client_config_with_roots(Arc::clone(&provider), roots).unwrap();
        let state = MitmState::build(
            &cfg.mitm_options(),
            &cfg.ca_source().unwrap(),
            provider,
            upstream,
        )
        .unwrap();

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
        let handlers = EngineHandlers::from_routing(routing, access.clone(), logger.clone())
            .with_mitm(
                Arc::new(state.interceptor.clone()),
                cfg.socks_block_web_in_mitm,
            );
        assert!(handlers.http_engine().mitm_enabled());
        let socks_guard = handlers.socks_engine().has_guard();
        let server = Server::bind(
            ListenPlan::Separate {
                http: Some("127.0.0.1:0".parse().unwrap()),
                socks: Some("127.0.0.1:0".parse().unwrap()),
            },
            Arc::new(handlers),
            logger.clone(),
        )
        .await
        .unwrap();
        let token = server.shutdown_token();
        let reaper = o
            .reap_every
            .map(|every| state.cache.spawn_reaper_every(every, token.clone(), logger));
        Self {
            http: server.local_http_addr().unwrap(),
            socks: server.local_socks_addr().unwrap(),
            ca,
            state,
            socks_guard,
            token,
            run: tokio::spawn(server.run()),
            reaper,
            access,
            http_log,
            socks_log,
            dir,
        }
    }

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

    /// `CONNECT target` and complete a TLS handshake that trusts only the MITM CA.
    async fn tunnel(&self, target: &str, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
        let tcp = connect_through(self.http, target).await;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.ca.cert_der.clone()))
            .unwrap();
        let mut cfg = client_config_with_roots(crypto_provider(), roots).unwrap();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        tokio::time::timeout(
            IO_TIMEOUT,
            TlsConnector::from(Arc::new(cfg))
                .connect(ServerName::try_from("localhost").unwrap(), tcp),
        )
        .await
        .unwrap()
        .expect("client must trust the MITM leaf")
    }

    async fn stop(self) {
        self.token.cancel();
        let report = tokio::time::timeout(IO_TIMEOUT, self.run)
            .await
            .unwrap()
            .unwrap();
        assert!(report.drained);
        if let Some(r) = self.reaper {
            r.await.unwrap();
        }
        self.access.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn connect_through(proxy: SocketAddr, target: &str) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = tokio::time::timeout(IO_TIMEOUT, read_head(&mut s))
        .await
        .unwrap();
    assert!(
        head.starts_with("HTTP/1.1 200 Connection Established\r\n"),
        "{head}"
    );
    s
}

type Sender = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

async fn http1(tls: TlsStream<TcpStream>) -> Sender {
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    sender
}

/// `GET path` on an HTTP/1.1 MITM tunnel; returns `(status, body)`.
async fn get(sender: &mut Sender, authority: &str, path: &str) -> (u16, String) {
    sender.ready().await.unwrap();
    let req = Request::get(path)
        .header(hyper::header::HOST, authority)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = tokio::time::timeout(IO_TIMEOUT, sender.send_request(req))
        .await
        .unwrap()
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn presented_serial(tls: &TlsStream<TcpStream>) -> Vec<u8> {
    let certs = tls.get_ref().1.peer_certificates().unwrap();
    let (_, x) = x509_parser::parse_x509_certificate(&certs[0]).unwrap();
    x.raw_serial().to_vec()
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

fn upstream(addr: SocketAddr, scheme: &str) -> String {
    format!("upstream={scheme}://127.0.0.1:{}", addr.port())
}

/// Profiles `web` (SOCKS5 → origin) and `corp` (HTTP CONNECT → origin) plus `routing`.
fn routed_toml(socks: SocketAddr, http: SocketAddr, routing: &str) -> String {
    format!(
        r#"
[profiles.web]
type = "socks5"
host = "127.0.0.1"
port = {}

[profiles.corp]
type = "http"
host = "127.0.0.1"
port = {}

{routing}
"#,
        socks.port(),
        http.port()
    )
}

// ---------------------------------------------------------------------------
// MITM over every upstream type
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mitm_over_direct_socks5_and_http_upstreams() {
    let origin = spawn_origin().await;
    let (socks, socks_seen) = socks5_server(origin.addr).await;
    let (corp, corp_seen) = http_proxy_server(origin.addr).await;
    // No URL rules: the route is fixed per CONNECT (one proxy per default profile).
    let port = origin.addr.port();
    let toml = routed_toml(socks, corp, "[routing]\ndefault = \"direct\"\n");
    let direct = MitmProxy::start("direct", &toml, &origin.ca_der, Opts::default()).await;
    let socks_toml = routed_toml(socks, corp, "[routing]\ndefault = \"web\"\n");
    let via_socks = MitmProxy::start("socks5", &socks_toml, &origin.ca_der, Opts::default()).await;
    let http_toml = routed_toml(socks, corp, "[routing]\ndefault = \"corp\"\n");
    let via_http = MitmProxy::start("http", &http_toml, &origin.ca_der, Opts::default()).await;

    let target = format!("localhost:{port}");
    let cases: [(&MitmProxy, &str, String); 3] = [
        (&direct, "direct", "upstream=direct".to_string()),
        (&via_socks, "web", upstream(socks, "socks5")),
        (&via_http, "corp", upstream(corp, "http")),
    ];
    for (i, (proxy, profile, up)) in cases.iter().enumerate() {
        let mut sender = http1(proxy.tunnel(&target, &[b"http/1.1"]).await).await;
        let (s1, b1) = get(&mut sender, &target, "/one").await;
        let (s2, b2) = get(&mut sender, &target, "/two").await;
        assert_eq!((s1, s2), (200, 200));
        assert_eq!(b1, format!("hit {} GET /one", 2 * i + 1));
        assert_eq!(b2, format!("hit {} GET /two", 2 * i + 2));
        drop(sender);
        let lines = proxy.http_lines(2).await;
        for path in ["/one", "/two"] {
            let line = line_with(&lines, &format!("target=https://{target}{path}"));
            assert!(line.contains("proto=https mitm=true method=GET"), "{line}");
            assert!(
                line.contains(&format!("profile={profile} {up} status=200")),
                "{line}"
            );
        }
    }
    // Hostnames reach proxy upstreams unresolved; one upstream TLS connection per tunnel.
    assert_eq!(seen(&socks_seen), [format!("domain:localhost:{port}")]);
    assert_eq!(
        seen(&corp_seen),
        [format!("CONNECT localhost:{port} HTTP/1.1")]
    );
    assert_eq!(origin.conns.load(Ordering::SeqCst), 3);
    assert_eq!(origin.hits.load(Ordering::SeqCst), 6);
    for p in [direct, via_socks, via_http] {
        p.stop().await;
    }
}

#[tokio::test]
async fn mitm_negotiates_h2_through_socks5_upstream() {
    let origin = spawn_origin().await;
    let (socks, socks_seen) = socks5_server(origin.addr).await;
    let (corp, _) = http_proxy_server(origin.addr).await;
    let toml = routed_toml(socks, corp, "[routing]\ndefault = \"web\"\n");
    let proxy = MitmProxy::start("h2", &toml, &origin.ca_der, Opts::default()).await;
    let target = format!("localhost:{}", origin.addr.port());

    let tls = proxy.tunnel(&target, &[b"h2", b"http/1.1"]).await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let req = Request::get(format!("https://{target}/h2"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.version(), hyper::Version::HTTP_2);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hit 1 GET /h2");
    drop(sender);

    let lines = proxy.http_lines(1).await;
    assert!(
        lines[0].contains(&format!(
            "mitm=true method=GET target=https://{target}/h2 rule=<default> profile=web {} \
             status=200",
            upstream(socks, "socks5")
        )),
        "{lines:?}"
    );
    assert_eq!(seen(&socks_seen).len(), 1);
    proxy.stop().await;
}

// ---------------------------------------------------------------------------
// Per-request URL routing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn url_rules_route_each_request_and_switch_upstreams_in_one_tunnel() {
    let origin = spawn_origin().await;
    let (socks, socks_seen) = socks5_server(origin.addr).await;
    let (corp, corp_seen) = http_proxy_server(origin.addr).await;
    let toml = routed_toml(
        socks,
        corp,
        r#"
[routing]
default = "direct"

[[routing.rules]]
name = "socks-paths"
keyword = ["via-socks"]
target = "web"

[[routing.rules]]
name = "http-paths"
url_regex = "^https://localhost:[0-9]+/via-http/"
target = "corp"

[[routing.rules]]
name = "no-ads"
keyword = ["ads"]
target = "block"
"#,
    );
    let proxy = MitmProxy::start("per-request", &toml, &origin.ca_der, Opts::default()).await;
    let port = origin.addr.port();
    let target = format!("localhost:{port}");

    // One client TLS connection; requests alternate between routes.
    let tls = proxy.tunnel(&target, &[b"h2", b"http/1.1"]).await;
    // URL-rule mode speaks HTTP/1.1 to the client.
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let mut sender = http1(tls).await;
    let mut bodies = Vec::new();
    for path in [
        "/via-socks/1",
        "/via-socks/2",
        "/via-http/1",
        "/plain",
        "/ads/banner",
        "/via-socks/3",
    ] {
        bodies.push(get(&mut sender, &target, path).await);
    }
    drop(sender);
    assert_eq!(
        bodies,
        [
            (200, "hit 1 GET /via-socks/1".to_string()),
            (200, "hit 2 GET /via-socks/2".to_string()),
            (200, "hit 3 GET /via-http/1".to_string()),
            (200, "hit 4 GET /plain".to_string()),
            (403, "destination blocked\n".to_string()),
            (200, "hit 5 GET /via-socks/3".to_string()),
        ]
    );
    // Consecutive same-route requests share one upstream connection; a route change dials
    // a fresh connection through the new chain (socks → http → direct → socks).
    let socks_dest = format!("domain:localhost:{port}");
    assert_eq!(seen(&socks_seen), [socks_dest.clone(), socks_dest]);
    assert_eq!(
        seen(&corp_seen),
        [format!("CONNECT localhost:{port} HTTP/1.1")]
    );
    assert_eq!(origin.conns.load(Ordering::SeqCst), 4);

    let lines = proxy.http_lines(6).await;
    let socks_up = upstream(socks, "socks5");
    let corp_up = upstream(corp, "http");
    for (path, rule, profile, up, status) in [
        ("/via-socks/1", "socks-paths", "web", socks_up.as_str(), 200),
        ("/via-socks/2", "socks-paths", "web", socks_up.as_str(), 200),
        ("/via-http/1", "http-paths", "corp", corp_up.as_str(), 200),
        ("/plain", "<default>", "direct", "upstream=direct", 200),
        ("/ads/banner", "no-ads", "block", "upstream=block", 403),
        ("/via-socks/3", "socks-paths", "web", socks_up.as_str(), 200),
    ] {
        let line = line_with(&lines, &format!("target=https://{target}{path} "));
        assert!(
            line.contains(&format!(
                "mitm=true method=GET target=https://{target}{path} rule={rule} \
                 profile={profile} {up} status={status}"
            )),
            "{line}"
        );
    }
    proxy.stop().await;
}

// ---------------------------------------------------------------------------
// Leaf certificate cache: PKCS#12, TTL, reaper, cap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pkcs12_ca_leaf_cached_within_ttl_and_reaped_after() {
    let origin = spawn_origin().await;
    let toml = "[routing]\ndefault = \"direct\"\n";
    let proxy = MitmProxy::start(
        "reaper",
        toml,
        &origin.ca_der,
        Opts {
            ca: CaKind::Pkcs12,
            ttl: Duration::from_secs(3),
            reap_every: Some(Duration::from_millis(100)),
            ..Opts::default()
        },
    )
    .await;
    assert!(
        proxy
            .state
            .ca_subject
            .contains("Switch Integration MITM CA"),
        "{}",
        proxy.state.ca_subject
    );
    let target = format!("localhost:{}", origin.addr.port());

    let first = presented_serial(&proxy.tunnel(&target, &[b"http/1.1"]).await);
    let again = presented_serial(&proxy.tunnel(&target, &[b"http/1.1"]).await);
    assert_eq!(first, again, "leaf reused within the TTL");
    assert_eq!(proxy.state.cache.len(), 1);

    let mut evicted = false;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if proxy.state.cache.is_empty() {
            evicted = true;
            break;
        }
    }
    assert!(evicted, "reaper did not evict the expired leaf");

    let tls = proxy.tunnel(&target, &[b"http/1.1"]).await;
    assert_ne!(first, presented_serial(&tls), "fresh leaf after expiry");
    let mut sender = http1(tls).await;
    assert_eq!(
        get(&mut sender, &target, "/fresh").await.1,
        "hit 1 GET /fresh"
    );
    drop(sender);
    proxy.stop().await;
}

#[tokio::test]
async fn expired_leaf_is_never_served_between_reaper_ticks() {
    let origin = spawn_origin().await;
    let ttl = Duration::from_millis(800);
    let proxy = MitmProxy::start(
        "lazy",
        "[routing]\ndefault = \"direct\"\n",
        &origin.ca_der,
        Opts {
            ttl,
            ..Opts::default()
        },
    )
    .await;
    let target = format!("localhost:{}", origin.addr.port());
    let first = presented_serial(&proxy.tunnel(&target, &[b"http/1.1"]).await);
    tokio::time::sleep(ttl + Duration::from_millis(300)).await;
    assert_eq!(proxy.state.cache.len(), 1, "nothing reaped it");
    let second = presented_serial(&proxy.tunnel(&target, &[b"http/1.1"]).await);
    assert_ne!(first, second);
    proxy.stop().await;
}

#[tokio::test]
async fn cert_cache_enforces_entry_cap_and_ttl() {
    let ca = test_ca("Switch Cap CA");
    let material =
        CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None).unwrap();
    let ttl = Duration::from_secs(600);
    let signer = LeafSigner::new(&material, ttl, crypto_provider()).unwrap();
    let cache = CertCache::new(Arc::new(signer), ttl).with_max_entries(2);
    assert_eq!((cache.ttl(), cache.max_entries()), (ttl, 2));
    for host in ["a.example", "b.example", "c.example", "C.EXAMPLE"] {
        cache.get_or_create(host).await.unwrap();
        assert!(cache.len() <= 2, "cap exceeded after {host}");
    }
    assert_eq!(cache.len(), 2);
    // Same host (normalized) twice in a row returns the cached key.
    let k1 = cache.get_or_create("c.example").await.unwrap();
    let k2 = cache.get_or_create("C.Example").await.unwrap();
    assert!(Arc::ptr_eq(&k1, &k2));
}

// ---------------------------------------------------------------------------
// --socks-block-web-in-mitm
// ---------------------------------------------------------------------------

/// TLS record carrying a `ClientHello` with SNI and optional ALPN.
fn client_hello(sni: &str, alpn: Option<&[&[u8]]>) -> Vec<u8> {
    let mut exts = Vec::new();
    let mut entry = vec![0u8];
    entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    entry.extend_from_slice(sni.as_bytes());
    let mut list = (entry.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&entry);
    exts.extend_from_slice(&0u16.to_be_bytes());
    exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
    exts.extend_from_slice(&list);
    if let Some(protos) = alpn {
        let mut list = Vec::new();
        for p in protos {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(&data);
    }
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[7u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut hs = vec![0x01];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// SOCKS5 `CONNECT` to an IPv4 target; asserts success.
async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await.unwrap();
    let SocketAddr::V4(t) = target else {
        panic!("ipv4 only")
    };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&t.ip().octets());
    req.extend_from_slice(&t.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00);
    s
}

/// Send `payload`, half-close, and collect everything echoed back.
async fn echo_roundtrip(mut s: TcpStream, payload: &[u8]) -> Vec<u8> {
    s.write_all(payload).await.unwrap();
    s.shutdown().await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut out))
        .await
        .unwrap();
    out
}

#[tokio::test]
async fn socks_block_web_in_mitm_blocks_web_and_allows_other_tcp() {
    let origin = spawn_origin().await;
    let echo = echo_server().await;
    let toml = "[routing]\ndefault = \"direct\"\n";
    let proxy = MitmProxy::start(
        "web-guard",
        toml,
        &origin.ca_der,
        Opts {
            socks_block_web: true,
            ..Opts::default()
        },
    )
    .await;
    assert!(proxy.socks_guard);

    // Plaintext HTTP: dropped, nothing echoed.
    let s = socks5_connect(proxy.socks, echo).await;
    assert!(echo_roundtrip(s, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .is_empty());
    // TLS ClientHello advertising h2 (non-443 port): dropped.
    let s = socks5_connect(proxy.socks, echo).await;
    let hello = client_hello("a.example", Some(&[b"h2", b"http/1.1"]));
    assert!(echo_roundtrip(s, &hello).await.is_empty());
    // Raw TCP: echoed unchanged.
    let raw: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let s = socks5_connect(proxy.socks, echo).await;
    assert_eq!(echo_roundtrip(s, &raw).await, raw);
    // TLS with a non-HTTP ALPN to a non-443 port: echoed unchanged.
    let imap = client_hello("mail.example", Some(&[b"imap"]));
    let s = socks5_connect(proxy.socks, echo).await;
    assert_eq!(echo_roundtrip(s, &imap).await, imap);

    let lines = proxy.socks_lines(4).await;
    let blocked = lines
        .iter()
        .filter(|l| l.contains("status=blocked_web_in_mitm"))
        .count();
    let ok = lines.iter().filter(|l| l.contains("status=ok")).count();
    assert_eq!((blocked, ok), (2, 2), "{lines:?}");
    proxy.stop().await;
}

#[tokio::test]
async fn socks_web_traffic_passes_without_the_flag() {
    let origin = spawn_origin().await;
    let echo = echo_server().await;
    let proxy = MitmProxy::start(
        "no-guard",
        "[routing]\ndefault = \"direct\"\n",
        &origin.ca_der,
        Opts::default(),
    )
    .await;
    assert!(!proxy.socks_guard);
    let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let s = socks5_connect(proxy.socks, echo).await;
    assert_eq!(echo_roundtrip(s, req).await, req);
    let lines = proxy.socks_lines(1).await;
    assert!(lines[0].contains("status=ok"), "{lines:?}");
    proxy.stop().await;
}
