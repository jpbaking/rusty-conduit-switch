//! End-to-end hot-reload tests: a real [`Server`] with [`EngineHandlers`] over a
//! [`SharedRuntime`] swapped by a [`Reloader`].
//!
//! Covered: live routing-rule swap, live upstream-profile swap, invalid TOML (and invalid
//! config) preserving the previous working snapshot, atomic rename-over-file saves seen by
//! `--watch-config`, Unix `SIGHUP` reload, the non-reloadable-field `INFO` notice, and an
//! established tunnel (HTTP `CONNECT` and SOCKS5) surviving a reload that would now block it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use rusty_conduit_switch::config::{CliInput, Config, Inbound};
use rusty_conduit_switch::logging::{AccessLogConfig, AccessLogger, LogFormat, LogLevel, Logger};
use rusty_conduit_switch::reload::{ReloadTrigger, Reloader, RuntimeConfig, SharedRuntime};
use rusty_conduit_switch::router::RouteRequest;
use rusty_conduit_switch::server::{EngineHandlers, ListenPlan, Server, ShutdownReport};
use rusty_conduit_switch::upstream::DialerOptions;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

type Seen = Arc<Mutex<Vec<String>>>;

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

/// Read an HTTP head (through the blank line).
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

/// Mock HTTP `CONNECT` upstream proxy: records each request line, answers `200`, then
/// splices the tunnel to `sink` regardless of the requested target.
async fn connect_proxy(sink: SocketAddr) -> (SocketAddr, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let rec = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let rec = Arc::clone(&rec);
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let line = head.lines().next().unwrap_or_default().to_string();
                rec.lock().unwrap().push(line);
                if s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let Ok(mut up) = TcpStream::connect(sink).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
            });
        }
    });
    (addr, seen)
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A `Write` sink that can be read back (captures diagnostic log lines).
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn temp_dir(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rcs-it-reload-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Proxy {
    addr: SocketAddr,
    token: CancellationToken,
    run: JoinHandle<ShutdownReport>,
    access: AccessLogger,
    runtime: SharedRuntime,
    reloader: Arc<Reloader>,
    cfg: Config,
    logs: Captured,
    path: PathBuf,
    dir: PathBuf,
}

impl Proxy {
    /// Write `toml` to `<tmp>/config.toml` and start a multiplexed proxy from it.
    async fn start(name: &str, toml: &str) -> Self {
        let dir = temp_dir(name);
        let path = dir.join("config.toml");
        std::fs::write(&path, toml).unwrap();
        let cli = CliInput::try_parse_from([
            "rusty-conduit-switch",
            "--config",
            path.to_str().unwrap(),
            "--connect-timeout",
            "3s",
        ])
        .unwrap();
        let cfg = Config::from_cli(cli.clone()).unwrap();
        cfg.validate().unwrap();

        let logs = Captured::default();
        let logger = Logger::with_writer(LogLevel::Info, Box::new(logs.clone()));
        let access = AccessLogger::start(
            AccessLogConfig::new(LogLevel::Info, LogFormat::Text, None, None),
            logger.clone(),
        )
        .await
        .unwrap();
        let runtime = RuntimeConfig::from_input(&cfg.routing_input(), DialerOptions::default())
            .unwrap()
            .shared();
        let handlers =
            EngineHandlers::from_routing(Arc::clone(&runtime), access.clone(), logger.clone());
        let server = Server::bind(
            ListenPlan::Multiplexed("127.0.0.1:0".parse().unwrap()),
            Arc::new(handlers),
            logger.clone(),
        )
        .await
        .unwrap()
        .with_runtime(Arc::clone(&runtime));
        let reloader = Arc::new(Reloader::new(
            Arc::clone(&runtime),
            cli,
            cfg.clone(),
            DialerOptions::default(),
            logger,
        ));
        Self {
            addr: server.local_http_addr().unwrap(),
            token: server.shutdown_token(),
            run: tokio::spawn(server.run()),
            access,
            runtime,
            reloader,
            cfg,
            logs,
            path,
            dir,
        }
    }

    /// Overwrite the config file in place.
    fn write(&self, toml: &str) {
        std::fs::write(&self.path, toml).unwrap();
    }

    /// Save like an editor: write a sibling temp file, then rename it over the config.
    fn save_atomically(&self, toml: &str) {
        let tmp = self.dir.join(".config.toml.swp");
        std::fs::write(&tmp, toml).unwrap();
        std::fs::rename(&tmp, &self.path).unwrap();
    }

    fn generation(&self) -> u64 {
        self.runtime.load().config_generation
    }

    /// Wait (bounded) until the active generation reaches `want`.
    async fn wait_generation(&self, want: u64) {
        for _ in 0..1000 {
            if self.generation() >= want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "generation {} never reached {want}; log:\n{}",
            self.generation(),
            self.logs.text()
        );
    }

    /// The profile the active snapshot routes `target` (an HTTP `CONNECT`) to.
    fn profile_for(&self, target: SocketAddr) -> String {
        let host = target.ip().to_string();
        let mut req = RouteRequest::new(Inbound::Http, &host, target.port());
        req.scheme = Some("https");
        let state = self.runtime.load_full();
        state
            .router
            .route(&req)
            .unwrap()
            .profile_label()
            .to_string()
    }

    /// Wait (bounded) until the active snapshot routes `target` to `profile`.
    async fn wait_profile(&self, target: SocketAddr, profile: &str) {
        for _ in 0..1000 {
            if self.profile_for(target) == profile {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "{target} never routed to {profile} (generation {}); log:\n{}",
            self.generation(),
            self.logs.text()
        );
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

/// HTTP `CONNECT` through the proxy; returns the stream and the status code.
async fn http_connect(proxy: SocketAddr, target: &str) -> (TcpStream, u16) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = tokio::time::timeout(IO_TIMEOUT, read_head(&mut s))
        .await
        .unwrap();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("bad response head {head:?}"));
    (s, status)
}

/// SOCKS5 `CONNECT` to an IPv4 target; returns the stream and the `REP` byte.
async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> (TcpStream, u8) {
    let std::net::IpAddr::V4(ip) = target.ip() else {
        panic!("IPv4 only");
    };
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(IO_TIMEOUT, s.read_exact(&mut rep))
        .await
        .unwrap()
        .unwrap();
    (s, rep[1])
}

/// Send `payload` and expect it echoed back.
async fn assert_echo(s: &mut TcpStream, payload: &[u8]) {
    s.write_all(payload).await.unwrap();
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(IO_TIMEOUT, s.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .expect("tunnel dropped");
    assert_eq!(buf, payload);
}

/// Routes the echo server's port to `target`.
fn port_rule(echo: SocketAddr, target: &str) -> String {
    format!(
        "[[routing.rules]]\nname = \"echo\"\nport = {}\ntarget = \"{target}\"\n",
        echo.port()
    )
}

fn upstream_profile(name: &str, addr: SocketAddr) -> String {
    format!(
        "[profiles.{name}]\ntype = \"http\"\nhost = \"127.0.0.1\"\nport = {}\n",
        addr.port()
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_routing_rule_swap_applies_to_new_connections() {
    let echo = echo_server().await;
    let proxy = Proxy::start("rules", &port_rule(echo, "block")).await;
    let target = echo.to_string();

    let (_s, status) = http_connect(proxy.addr, &target).await;
    assert_eq!(status, 403);
    let (_s, rep) = socks5_connect(proxy.addr, echo).await;
    assert_ne!(rep, 0, "blocked over SOCKS too");

    proxy.write(&port_rule(echo, "direct"));
    let summary = proxy.reloader.reload_once(ReloadTrigger::Manual).unwrap();
    assert_eq!((summary.generation, summary.rules), (1, 1));
    assert_eq!(proxy.generation(), 1);

    let (mut s, status) = http_connect(proxy.addr, &target).await;
    assert_eq!(status, 200);
    assert_echo(&mut s, b"after reload").await;
    let (mut s, rep) = socks5_connect(proxy.addr, echo).await;
    assert_eq!(rep, 0);
    assert_echo(&mut s, b"socks after reload").await;
    assert!(
        proxy
            .logs
            .text()
            .contains("config reloaded generation=1 profiles=2 rules=1"),
        "{}",
        proxy.logs.text()
    );
    proxy.stop().await;
}

#[tokio::test]
async fn live_upstream_profile_swap() {
    let echo = echo_server().await;
    let (first, first_seen) = connect_proxy(echo).await;
    let (second, second_seen) = connect_proxy(echo).await;
    let routing = "[routing]\ndefault = \"corp\"\n";
    let proxy = Proxy::start(
        "profiles",
        &format!("{}{routing}", upstream_profile("corp", first)),
    )
    .await;

    let (mut s, status) = http_connect(proxy.addr, "one.invalid:443").await;
    assert_eq!(status, 200);
    assert_echo(&mut s, b"via first").await;
    drop(s);

    // Same profile name, new upstream address.
    proxy.write(&format!("{}{routing}", upstream_profile("corp", second)));
    proxy.reloader.reload_once(ReloadTrigger::Manual).unwrap();

    let (mut s, status) = http_connect(proxy.addr, "two.invalid:443").await;
    assert_eq!(status, 200);
    assert_echo(&mut s, b"via second").await;

    assert_eq!(
        *first_seen.lock().unwrap(),
        vec!["CONNECT one.invalid:443 HTTP/1.1".to_string()]
    );
    assert_eq!(
        *second_seen.lock().unwrap(),
        vec!["CONNECT two.invalid:443 HTTP/1.1".to_string()]
    );
    proxy.stop().await;
}

#[tokio::test]
async fn invalid_reload_preserves_the_working_config() {
    let echo = echo_server().await;
    let proxy = Proxy::start("invalid", &port_rule(echo, "direct")).await;
    let before = proxy.runtime.load_full();

    // Broken TOML.
    proxy.write("[[routing.rules]\nport = ");
    assert!(proxy.reloader.reload_once(ReloadTrigger::Manual).is_err());
    // Valid TOML, invalid config (unknown profile reference).
    proxy.write(&port_rule(echo, "nowhere"));
    assert!(proxy.reloader.reload_once(ReloadTrigger::Manual).is_err());
    // Missing file.
    std::fs::remove_file(&proxy.path).unwrap();
    assert!(proxy.reloader.reload_once(ReloadTrigger::Manual).is_err());

    assert!(Arc::ptr_eq(&before, &proxy.runtime.load_full()));
    assert_eq!(proxy.generation(), 0);
    let (mut s, status) = http_connect(proxy.addr, &echo.to_string()).await;
    assert_eq!(status, 200, "previous routing still active");
    assert_echo(&mut s, b"still working").await;

    let log = proxy.logs.text();
    assert_eq!(log.matches("keeping generation=0").count(), 3, "{log}");
    assert!(log.contains("TOML parse error"), "{log}");
    assert!(log.contains("nowhere"), "{log}");
    proxy.stop().await;
}

#[tokio::test]
async fn watch_config_sees_atomic_rename_over_save() {
    let echo = echo_server().await;
    let header = "watch_config = true\nwatch_debounce = \"100ms\"\n";
    let proxy = Proxy::start("watch", &format!("{header}{}", port_rule(echo, "block"))).await;
    assert!(proxy.cfg.watch_config);
    let tasks = rusty_conduit_switch::start_reload_triggers(
        Arc::clone(&proxy.reloader),
        &proxy.cfg,
        proxy.token.clone(),
        &Logger::with_writer(LogLevel::Quiet, Box::new(std::io::sink())),
    );
    assert!(!tasks.is_empty());
    // Give the platform watcher a moment to arm. Some backends (macOS FSEvents) also
    // report the file's creation just before the watch started, which yields one harmless
    // reload of unchanged content; so wait on the routing outcome, not on a generation count.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let base = proxy.generation();
    assert_eq!(proxy.profile_for(echo), "block");

    proxy.save_atomically(&format!("{header}{}", port_rule(echo, "direct")));
    proxy.wait_profile(echo, "direct").await;
    assert!(proxy.generation() > base);
    let (mut s, status) = http_connect(proxy.addr, &echo.to_string()).await;
    assert_eq!(status, 200);
    assert_echo(&mut s, b"watched").await;

    // A second save (in-place write this time) is picked up too.
    tokio::time::sleep(Duration::from_millis(200)).await;
    proxy.write(&format!("{header}{}", port_rule(echo, "block")));
    proxy.wait_profile(echo, "block").await;
    let (_s, status) = http_connect(proxy.addr, &echo.to_string()).await;
    assert_eq!(status, 403);

    proxy.stop().await;
    for t in tasks {
        tokio::time::timeout(IO_TIMEOUT, t).await.unwrap().unwrap();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_triggers_reload() {
    let echo = echo_server().await;
    let proxy = Proxy::start("sighup", &port_rule(echo, "block")).await;
    let task = proxy
        .reloader
        .spawn_sighup(proxy.token.clone())
        .expect("SIGHUP handler");

    proxy.write(&port_rule(echo, "direct"));
    let status = std::process::Command::new("kill")
        .args(["-HUP", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    proxy.wait_generation(1).await;
    assert!(proxy.logs.text().contains("received SIGHUP"));
    let (mut s, status) = http_connect(proxy.addr, &echo.to_string()).await;
    assert_eq!(status, 200);
    assert_echo(&mut s, b"hup").await;

    proxy.stop().await;
    tokio::time::timeout(IO_TIMEOUT, task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn non_reloadable_changes_are_warned_and_ignored() {
    let echo = echo_server().await;
    let proxy = Proxy::start("nonreload", &port_rule(echo, "block")).await;

    let changed = format!(
        "bind = \"0.0.0.0\"\nhttp_port = 3999\nmax_connections = 5\n\
         [mitm]\ncert_ttl = \"2h\"\n[logging]\nformat = \"json\"\n{}",
        port_rule(echo, "direct")
    );
    proxy.write(&changed);
    let summary = proxy.reloader.reload_once(ReloadTrigger::Manual).unwrap();
    assert_eq!(
        summary.ignored,
        vec![
            "bind",
            "http_port",
            "max_connections",
            "mitm.cert_ttl",
            "logging.format"
        ]
    );
    let log = proxy.logs.text();
    let notice = log
        .lines()
        .find(|l| l.contains("ignored until restart"))
        .unwrap_or_else(|| panic!("no notice in {log}"));
    assert!(notice.contains("INFO"), "{notice}");
    assert!(
        notice.contains("bind, http_port, max_connections, mitm.cert_ttl, logging.format"),
        "{notice}"
    );
    // The reloadable routing change still applied.
    let (mut s, status) = http_connect(proxy.addr, &echo.to_string()).await;
    assert_eq!(status, 200);
    assert_echo(&mut s, b"routing applied").await;
    proxy.stop().await;
}

#[tokio::test]
async fn established_tunnels_survive_reload() {
    let echo = echo_server().await;
    let proxy = Proxy::start("tunnel", &port_rule(echo, "direct")).await;

    let (mut http_tunnel, status) = http_connect(proxy.addr, &echo.to_string()).await;
    assert_eq!(status, 200);
    assert_echo(&mut http_tunnel, b"before").await;
    let (mut socks_tunnel, rep) = socks5_connect(proxy.addr, echo).await;
    assert_eq!(rep, 0);
    assert_echo(&mut socks_tunnel, b"socks before").await;

    // New rules block the destination and shorten every timeout.
    proxy.write(&format!(
        "connect_timeout = \"1s\"\n{}",
        port_rule(echo, "block")
    ));
    proxy.reloader.reload_once(ReloadTrigger::Manual).unwrap();
    proxy.reloader.reload_once(ReloadTrigger::Manual).unwrap();
    assert_eq!(proxy.generation(), 2);

    // In-flight tunnels keep working on their original snapshot ...
    assert_echo(&mut http_tunnel, b"after reload").await;
    assert_echo(&mut socks_tunnel, b"socks after reload").await;
    // ... while new connections see the new table.
    let (_s, status) = http_connect(proxy.addr, &echo.to_string()).await;
    assert_eq!(status, 403);
    let (_s, rep) = socks5_connect(proxy.addr, echo).await;
    assert_ne!(rep, 0);

    // Both old tunnels are still intact and close cleanly.
    assert_echo(&mut http_tunnel, b"still here").await;
    assert_echo(&mut socks_tunnel, b"socks still here").await;
    drop(http_tunnel);
    drop(socks_tunnel);
    proxy.stop().await;
}

/// Not a test of the reload engine itself: the config file used by the harness must be the
/// one the reloader reads.
#[tokio::test]
async fn reloader_reads_the_configured_path() {
    let proxy = Proxy::start("path", "").await;
    assert_eq!(proxy.reloader.path(), Some(Path::new(&proxy.path)));
    proxy.stop().await;
}
