//! Atomic hot-reload engine.
//!
//! All hot-reloadable state — the compiled [`Router`], the [`ProfileRegistry`] of upstream
//! dialers, the global [`HostFilter`], `connect_timeout`, [`KeepaliveSettings`], and a
//! `config_generation` counter — lives in one immutable [`RuntimeConfig`] stored inside an
//! [`ArcSwap`] ([`SharedRuntime`]). Every accepted connection (and every decrypted MITM
//! request when URL rules are configured) takes one lock-free snapshot with `load()` and
//! keeps it for its lifetime, so in-flight tunnels are never disturbed by a reload while new
//! connections immediately see the new tables.
//!
//! Reload triggers ([`Reloader`]):
//! 1. `SIGHUP` on Unix whenever `--config` is set ([`Reloader::spawn_sighup`]).
//! 2. `--watch-config` ([`Reloader::spawn_watcher`]): the `notify` crate watches the
//!    *parent directory* of `--config` (so atomic rename-over-file saves are seen), events
//!    are filtered to the target file name and debounced by `--watch-debounce`.
//!
//! Validate-before-swap ([`Reloader::reload_once`]): the TOML file is re-read, the startup
//! CLI/env overrides are re-applied ([`Config::merge`] with the original [`CliInput`]),
//! non-reloadable fields are pinned to their running values (and reported once with an
//! `INFO` notice), and the result is fully validated — including self-loop detection
//! against the active listener addresses — and compiled. Any error is logged at `ERROR` and
//! the previous snapshot stays active; on success the new snapshot is stored atomically with
//! `config_generation + 1`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{CliInput, Config, ConfigError, FileConfig, ProfileConfig, ProfileType};
use crate::filter::HostFilter;
use crate::logging::Logger;
use crate::net::KeepaliveSettings;
use crate::router::{RouteDecision, Router, RouterError};
use crate::upstream::{
    DialerOptions, HttpConnectDialer, ProfileRegistry, TlsOptions, UpstreamError,
};

/// Errors raised while compiling the routing / upstream state from configuration.
#[derive(Debug, thiserror::Error)]
pub enum RoutingSetupError {
    #[error(transparent)]
    Router(#[from] RouterError),
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
}

/// One immutable snapshot of everything needed to route and dial a request: the compiled
/// [`Router`], the [`ProfileRegistry`] of tunnel dialers, the `http` / `https` proxy
/// profiles usable for absolute-form plain HTTP forwarding, the global destination filter,
/// timeouts, keepalive, and the generation that produced it. Cheap to clone.
#[derive(Clone)]
pub struct RuntimeConfig {
    pub router: Arc<Router>,
    pub registry: Arc<ProfileRegistry>,
    /// `http` / `https` profiles by name, for absolute-form plain HTTP forwarding.
    pub forward_proxies: Arc<BTreeMap<String, HttpConnectDialer>>,
    /// Per-attempt upstream connect timeout.
    pub connect_timeout: Duration,
    /// TCP keepalive for accepted client sockets and upstream sockets (`None` = disabled).
    pub keepalive: Option<KeepaliveSettings>,
    /// Global destination filter (also compiled into the router and `direct` dialers).
    pub filter: Option<Arc<HostFilter>>,
    /// `0` for the startup configuration, incremented by every successful reload.
    pub config_generation: u64,
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeConfig")
            .field("config_generation", &self.config_generation)
            .field("registry", &self.registry)
            .field(
                "forward_proxies",
                &self.forward_proxies.keys().collect::<Vec<_>>(),
            )
            .field("connect_timeout", &self.connect_timeout)
            .field("keepalive", &self.keepalive)
            .field("filter", &self.filter)
            .finish_non_exhaustive()
    }
}

/// Runtime state shared by the listeners and every protocol engine; swapped atomically on
/// reload.
pub type SharedRuntime = Arc<ArcSwap<RuntimeConfig>>;

impl RuntimeConfig {
    /// A state with no absolute-form forward proxies, the default connect timeout, default
    /// keepalive, and no filter.
    pub fn new(router: Router, registry: ProfileRegistry) -> Self {
        Self {
            router: Arc::new(router),
            registry: Arc::new(registry),
            forward_proxies: Arc::new(BTreeMap::new()),
            connect_timeout: crate::config::DEFAULT_CONNECT_TIMEOUT,
            keepalive: Some(KeepaliveSettings::DEFAULT),
            filter: None,
            config_generation: 0,
        }
    }

    /// Compile the router and every upstream dialer from validated configuration. The
    /// global destination filter (if any) is enforced by the router on the target name and
    /// by `direct` dials on every resolved IP.
    pub fn from_config(cfg: &Config, opts: DialerOptions) -> Result<Self, RoutingSetupError> {
        let router = Router::from_config(cfg)?;
        let opts = DialerOptions {
            keepalive: cfg.tcp_keepalive_settings(),
            filter: opts.filter.or_else(|| cfg.host_filter().map(Arc::new)),
            ..opts
        };
        let profiles = cfg.profiles_with_builtins();
        let registry = ProfileRegistry::from_profiles(&profiles, &opts)?;
        let mut forward = BTreeMap::new();
        for (name, profile) in &profiles {
            if let Some(d) = forward_proxy_for_profile(name, profile, &opts)? {
                forward.insert(name.clone(), d);
            }
        }
        Ok(Self {
            router: Arc::new(router),
            registry: Arc::new(registry),
            forward_proxies: Arc::new(forward),
            connect_timeout: cfg.connect_timeout,
            keepalive: opts.keepalive,
            filter: opts.filter,
            config_generation: 0,
        })
    }

    /// Register `dialer` as the absolute-form forward proxy for profile `name`.
    pub fn with_forward_proxy(
        mut self,
        name: impl Into<String>,
        dialer: HttpConnectDialer,
    ) -> Self {
        Arc::make_mut(&mut self.forward_proxies).insert(name.into(), dialer);
        self
    }

    /// Override the per-attempt upstream connect timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the generation number of this snapshot.
    pub fn with_generation(mut self, generation: u64) -> Self {
        self.config_generation = generation;
        self
    }

    /// Wrap into a [`SharedRuntime`] handle.
    pub fn shared(self) -> SharedRuntime {
        Arc::new(ArcSwap::from_pointee(self))
    }

    /// Redacted upstream of the first target of `decision` (for logs when every dial
    /// failed or the route was refused).
    pub fn first_upstream(&self, decision: &RouteDecision) -> String {
        decision
            .targets
            .first()
            .and_then(|t| self.registry.get(&t.profile))
            .map(|d| d.redacted_upstream())
            .unwrap_or_default()
    }
}

/// Build the absolute-form forward proxy dialer for an `http` / `https` profile (`None` for
/// every other type). Mirrors [`crate::upstream::dialer_for_profile`].
fn forward_proxy_for_profile(
    name: &str,
    profile: &ProfileConfig,
    opts: &DialerOptions,
) -> Result<Option<HttpConnectDialer>, UpstreamError> {
    if !matches!(profile.kind, ProfileType::Http | ProfileType::Https) {
        return Ok(None);
    }
    let (Some(host), Some(port)) = (&profile.host, profile.port) else {
        return Err(UpstreamError::Profile {
            profile: name.to_string(),
            message: format!("type `{}` requires host and port", profile.kind),
        });
    };
    let password = profile.resolve_password(name)?;
    let credentials = match (&profile.username, password) {
        (Some(u), p) => Some((u.clone(), p.unwrap_or_default())),
        (None, Some(p)) => Some((String::new(), p)),
        (None, None) => None,
    };
    let dialer = if profile.kind == ProfileType::Https {
        let tls = TlsOptions {
            insecure_skip_verify: profile.tls_insecure_skip_verify,
            roots: opts.tls_roots.clone(),
        };
        HttpConnectDialer::https(host.clone(), port, &tls).map_err(|e| UpstreamError::Profile {
            profile: name.to_string(),
            message: format!("TLS setup failed: {e}"),
        })?
    } else {
        HttpConnectDialer::http(host.clone(), port)
    };
    Ok(Some(
        dialer
            .with_credentials(credentials)
            .with_tcp_keepalive(opts.keepalive),
    ))
}

// ---------------------------------------------------------------------------
// Non-reloadable fields
// ---------------------------------------------------------------------------

/// Names of the non-reloadable fields whose values differ between `active` and `new`
/// (`bind`, `http_port`, `socks_port`, `max_connections`, `watch_*`, `mitm.*`, `logging.*`).
pub fn non_reloadable_changes(active: &Config, new: &Config) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut check = |changed: bool, name: &'static str| {
        if changed {
            out.push(name);
        }
    };
    check(active.bind != new.bind, "bind");
    check(active.http_port != new.http_port, "http_port");
    check(active.socks_port != new.socks_port, "socks_port");
    check(
        active.max_connections != new.max_connections,
        "max_connections",
    );
    check(active.watch_config != new.watch_config, "watch_config");
    check(
        active.watch_debounce != new.watch_debounce,
        "watch_debounce",
    );
    check(active.mitm_ca_cert != new.mitm_ca_cert, "mitm.ca_cert");
    check(active.mitm_ca_key != new.mitm_ca_key, "mitm.ca_key");
    check(active.mitm_ca_p12 != new.mitm_ca_p12, "mitm.ca_p12");
    check(
        active.mitm_ca_passphrase != new.mitm_ca_passphrase,
        "mitm.ca_passphrase",
    );
    check(
        active.mitm_ca_passphrase_file != new.mitm_ca_passphrase_file,
        "mitm.ca_passphrase_file",
    );
    check(active.mitm_cert_ttl != new.mitm_cert_ttl, "mitm.cert_ttl");
    check(
        active.mitm_cert_cache_max != new.mitm_cert_cache_max,
        "mitm.cert_cache_max",
    );
    check(
        active.socks_block_web_in_mitm != new.socks_block_web_in_mitm,
        "mitm.socks_block_web",
    );
    check(active.log_level != new.log_level, "logging.level");
    check(active.log_format != new.log_format, "logging.format");
    check(
        active.http_access_log != new.http_access_log,
        "logging.http_access_log",
    );
    check(active.socks_log != new.socks_log, "logging.socks_log");
    out
}

/// `new` with every non-reloadable field pinned to its running value in `active`, so that
/// validation (including self-loop detection) runs against the listeners actually bound.
pub fn pin_non_reloadable(active: &Config, new: Config) -> Config {
    Config {
        config_path: active.config_path.clone(),
        watch_config: active.watch_config,
        watch_debounce: active.watch_debounce,
        bind: active.bind,
        http_port: active.http_port,
        socks_port: active.socks_port,
        max_connections: active.max_connections,
        mitm_ca_cert: active.mitm_ca_cert.clone(),
        mitm_ca_key: active.mitm_ca_key.clone(),
        mitm_ca_p12: active.mitm_ca_p12.clone(),
        mitm_ca_passphrase: active.mitm_ca_passphrase.clone(),
        mitm_ca_passphrase_file: active.mitm_ca_passphrase_file.clone(),
        mitm_cert_ttl: active.mitm_cert_ttl,
        mitm_cert_cache_max: active.mitm_cert_cache_max,
        socks_block_web_in_mitm: active.socks_block_web_in_mitm,
        log_level: active.log_level,
        log_format: active.log_format,
        http_access_log: active.http_access_log.clone(),
        socks_log: active.socks_log.clone(),
        passphrase_from_cli: active.passphrase_from_cli,
        ..new
    }
}

// ---------------------------------------------------------------------------
// Reloader
// ---------------------------------------------------------------------------

/// What caused a reload attempt (shown in log messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadTrigger {
    /// `SIGHUP` (Unix).
    Signal,
    /// `--watch-config` file watcher.
    Watch,
    /// Explicit API call.
    Manual,
}

impl fmt::Display for ReloadTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Signal => "SIGHUP",
            Self::Watch => "file watcher",
            Self::Manual => "request",
        })
    }
}

/// Why a reload was rejected (the previous snapshot stays active).
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("no --config file to reload")]
    NoConfigPath,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Routing(#[from] RoutingSetupError),
}

/// Result of a successful reload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadSummary {
    /// Generation of the newly stored snapshot.
    pub generation: u64,
    /// Profiles in the new configuration (built-ins included).
    pub profiles: usize,
    /// Routing rules in the new configuration.
    pub rules: usize,
    /// Non-reloadable fields that changed on disk and were ignored until restart.
    pub ignored: Vec<&'static str>,
}

/// Re-reads `--config`, validates, and atomically swaps the [`SharedRuntime`].
pub struct Reloader {
    shared: SharedRuntime,
    path: Option<PathBuf>,
    cli: CliInput,
    opts: DialerOptions,
    logger: Logger,
    /// The configuration behind the active snapshot; the lock also serialises reloads.
    active: Mutex<Config>,
}

impl fmt::Debug for Reloader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reloader")
            .field("path", &self.path)
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl Reloader {
    /// A reloader for the running `active` configuration (which produced the current
    /// snapshot in `shared`). `cli` is the startup CLI/env input, re-applied over the file
    /// on every reload; `opts` are the base dialer options used at startup.
    pub fn new(
        shared: SharedRuntime,
        cli: CliInput,
        active: Config,
        opts: DialerOptions,
        logger: Logger,
    ) -> Self {
        Self {
            shared,
            path: active.config_path.clone(),
            cli,
            opts,
            logger,
            active: Mutex::new(active),
        }
    }

    /// The shared runtime handle this reloader swaps.
    pub fn shared(&self) -> &SharedRuntime {
        &self.shared
    }

    /// The config file being reloaded, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Generation of the active snapshot.
    pub fn generation(&self) -> u64 {
        self.shared.load().config_generation
    }

    /// Re-read, validate, compile, and (only on success) atomically swap the runtime
    /// configuration. Logs an `INFO` summary (and an `INFO` notice for ignored
    /// non-reloadable changes) on success, or an `ERROR` on failure, in which case the
    /// previous snapshot stays active.
    pub fn reload_once(&self, trigger: ReloadTrigger) -> Result<ReloadSummary, ReloadError> {
        let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        match self.prepare(&active) {
            Ok((cfg, runtime, ignored)) => {
                let generation = self.shared.load().config_generation + 1;
                let summary = ReloadSummary {
                    generation,
                    profiles: cfg.profiles_with_builtins().len(),
                    rules: cfg.routing.rule_count(),
                    ignored,
                };
                self.shared
                    .store(Arc::new(runtime.with_generation(generation)));
                *active = cfg;
                if !summary.ignored.is_empty() {
                    self.logger.info(format!(
                        "config reload: changes to non-reloadable fields ignored until restart: {}",
                        summary.ignored.join(", ")
                    ));
                }
                self.logger.info(format!(
                    "config reloaded generation={} profiles={} rules={} ({trigger})",
                    summary.generation, summary.profiles, summary.rules
                ));
                Ok(summary)
            }
            Err(e) => {
                self.logger.error(format!(
                    "config reload ({trigger}) failed, keeping generation={}: {e}",
                    self.shared.load().config_generation
                ));
                Err(e)
            }
        }
    }

    /// Steps 1-3 of validate-before-swap: everything except the store.
    fn prepare(
        &self,
        active: &Config,
    ) -> Result<(Config, RuntimeConfig, Vec<&'static str>), ReloadError> {
        let path = self.path.as_ref().ok_or(ReloadError::NoConfigPath)?;
        let file = FileConfig::load(path)?;
        let merged = Config::merge(self.cli.clone(), Some(file))?;
        let ignored = non_reloadable_changes(active, &merged);
        let cfg = pin_non_reloadable(active, merged);
        cfg.validate()?;
        let runtime = RuntimeConfig::from_config(&cfg, self.opts.clone())?;
        Ok((cfg, runtime, ignored))
    }

    /// Run [`Reloader::reload_once`] on the blocking pool (it reads files and compiles).
    async fn reload_blocking(self: &Arc<Self>, trigger: ReloadTrigger) {
        let this = Arc::clone(self);
        if let Err(e) =
            tokio::task::spawn_blocking(move || this.reload_once(trigger).map(|_| ())).await
        {
            self.logger.error(format!("config reload task failed: {e}"));
        }
    }

    /// Reload on every `SIGHUP` until `shutdown` is cancelled. Returns `None` (after
    /// logging) when there is no `--config` or the handler cannot be installed.
    #[cfg(unix)]
    pub fn spawn_sighup(self: &Arc<Self>, shutdown: CancellationToken) -> Option<JoinHandle<()>> {
        use tokio::signal::unix::{signal, SignalKind};
        self.path.as_ref()?;
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                self.logger
                    .error(format!("failed to listen for SIGHUP: {e}"));
                return None;
            }
        };
        let this = Arc::clone(self);
        Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    got = sig.recv() => {
                        if got.is_none() {
                            break;
                        }
                        this.logger.info("received SIGHUP: reloading configuration");
                        this.reload_blocking(ReloadTrigger::Signal).await;
                    }
                }
            }
        }))
    }

    /// Watch the parent directory of `--config` and reload `debounce` after the last change
    /// to the config file, until `shutdown` is cancelled.
    pub fn spawn_watcher(
        self: &Arc<Self>,
        debounce: Duration,
        shutdown: CancellationToken,
    ) -> Result<JoinHandle<()>, WatchError> {
        use notify::{RecursiveMode, Watcher};

        let path = self.path.clone().ok_or(WatchError::NoConfigPath)?;
        let name = path
            .file_name()
            .map(OsString::from)
            .ok_or_else(|| WatchError::BadPath(path.clone()))?;
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let (tx, mut rx) = mpsc::unbounded_channel::<()>();
        let filter_name = name.clone();
        let mut watcher =
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    if is_relevant(&event, &filter_name) {
                        let _ = tx.send(());
                    }
                }
            })?;
        watcher.watch(&dir, RecursiveMode::NonRecursive)?;
        self.logger.info(format!(
            "watching {} for changes (debounce {})",
            path.display(),
            humantime::format_duration(debounce)
        ));
        let this = Arc::clone(self);
        Ok(tokio::spawn(async move {
            // Keep the watcher alive for as long as the task runs.
            let _watcher = watcher;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    ev = rx.recv() => if ev.is_none() { return },
                }
                // Debounce: wait until no further event arrives for `debounce`.
                loop {
                    tokio::select! {
                        () = shutdown.cancelled() => return,
                        () = tokio::time::sleep(debounce) => break,
                        ev = rx.recv() => if ev.is_none() { return },
                    }
                }
                this.logger
                    .debug("config file changed: reloading configuration");
                this.reload_blocking(ReloadTrigger::Watch).await;
            }
        }))
    }
}

/// Errors starting the `--watch-config` watcher.
#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("--watch-config requires --config")]
    NoConfigPath,
    #[error("cannot watch config path {0}")]
    BadPath(PathBuf),
    #[error("file watcher failed: {0}")]
    Notify(#[from] notify::Error),
}

/// Whether a watcher event concerns the config file (by file name: the parent directory is
/// watched, and platforms may report canonicalised paths). Pure access events (e.g. our own
/// reads) are ignored.
fn is_relevant(event: &notify::Event, name: &OsString) -> bool {
    if matches!(event.kind, notify::EventKind::Access(_)) {
        return false;
    }
    event
        .paths
        .iter()
        .any(|p| p.file_name().is_some_and(|n| n == name.as_os_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TEST_ENV_LOCK;
    use crate::logging::LogLevel;

    /// A `Write` sink that can be read back.
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

    fn temp_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rcs-reload-unit-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("config.toml")
    }

    const BASE: &str = "http_port = 18080\nsocks_port = 18081\n\
        [profiles.corp]\ntype = \"http\"\nhost = \"10.0.0.2\"\nport = 3128\n\
        [[routing.rules]]\nhost = \"a.example\"\ntarget = \"corp\"\n";

    fn reloader(name: &str, text: &str, args: &[&str]) -> (Reloader, PathBuf, Captured) {
        let path = temp_path(name);
        std::fs::write(&path, text).unwrap();
        let mut full = vec!["rusty-conduit-switch", "--config", path.to_str().unwrap()];
        full.extend_from_slice(args);
        let cli = {
            let _lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            CliInput::try_parse_from(full).unwrap()
        };
        let cfg = Config::from_cli(cli.clone()).unwrap();
        cfg.validate().unwrap();
        let shared = RuntimeConfig::from_config(&cfg, DialerOptions::default())
            .unwrap()
            .shared();
        let cap = Captured::default();
        let logger = Logger::with_writer(LogLevel::Info, Box::new(cap.clone()));
        (
            Reloader::new(shared, cli, cfg, DialerOptions::default(), logger),
            path,
            cap,
        )
    }

    fn route_profile(r: &Reloader, host: &str) -> String {
        let state = r.shared().load_full();
        let req = crate::router::RouteRequest {
            inbound: crate::config::Inbound::Http,
            host,
            port: 80,
            scheme: Some("http"),
            url: None,
        };
        state
            .router
            .route(&req)
            .unwrap()
            .profile_label()
            .to_string()
    }

    #[test]
    fn reload_swaps_routes_and_increments_generation() {
        let (r, path, cap) = reloader("swap", BASE, &[]);
        assert_eq!(r.generation(), 0);
        assert_eq!(route_profile(&r, "a.example"), "corp");
        std::fs::write(&path, BASE.replace("a.example", "b.example")).unwrap();
        let s = r.reload_once(ReloadTrigger::Manual).unwrap();
        assert_eq!(s.generation, 1);
        assert_eq!((s.profiles, s.rules), (3, 1));
        assert!(s.ignored.is_empty());
        assert_eq!(r.generation(), 1);
        assert_eq!(route_profile(&r, "a.example"), "direct");
        assert_eq!(route_profile(&r, "b.example"), "corp");
        assert!(
            cap.text()
                .contains("config reloaded generation=1 profiles=3 rules=1"),
            "{}",
            cap.text()
        );
    }

    #[test]
    fn invalid_reload_keeps_previous_snapshot() {
        let (r, path, cap) = reloader("invalid", BASE, &[]);
        let before = r.shared().load_full();
        std::fs::write(&path, "[[routing.rules]\nnot toml").unwrap();
        assert!(matches!(
            r.reload_once(ReloadTrigger::Manual),
            Err(ReloadError::Config(_))
        ));
        std::fs::write(&path, "[routing]\ndefault = \"missing\"\n").unwrap();
        assert!(r.reload_once(ReloadTrigger::Manual).is_err());
        assert!(Arc::ptr_eq(&before, &r.shared().load_full()));
        assert_eq!(r.generation(), 0);
        assert!(
            cap.text().contains("keeping generation=0"),
            "{}",
            cap.text()
        );
        // A later valid file still reloads.
        std::fs::write(&path, BASE).unwrap();
        assert_eq!(r.reload_once(ReloadTrigger::Manual).unwrap().generation, 1);
    }

    #[test]
    fn non_reloadable_changes_are_reported_and_ignored() {
        let (r, path, cap) = reloader("nonreload", BASE, &[]);
        let text = "max_connections = 7\n".to_string()
            + &BASE.replace("http_port = 18080", "http_port = 18090")
            + "[logging]\nlevel = \"DEBUG\"\n";
        std::fs::write(&path, text).unwrap();
        let s = r.reload_once(ReloadTrigger::Manual).unwrap();
        assert_eq!(
            s.ignored,
            vec!["http_port", "max_connections", "logging.level"]
        );
        assert!(
            cap.text()
                .contains("ignored until restart: http_port, max_connections, logging.level"),
            "{}",
            cap.text()
        );
        // Still pinned: the same change is reported again on the next reload.
        assert_eq!(
            r.reload_once(ReloadTrigger::Manual).unwrap().ignored.len(),
            3
        );
    }

    #[test]
    fn cli_overrides_are_reapplied_on_reload() {
        let (r, path, _cap) = reloader("cli", BASE, &["--connect-timeout", "3s"]);
        assert_eq!(r.shared().load().connect_timeout, Duration::from_secs(3));
        std::fs::write(&path, format!("connect_timeout = \"7s\"\n{BASE}")).unwrap();
        r.reload_once(ReloadTrigger::Manual).unwrap();
        assert_eq!(r.shared().load().connect_timeout, Duration::from_secs(3));
    }

    #[test]
    fn reloadable_scalars_follow_the_file() {
        let (r, path, _cap) = reloader("scalars", BASE, &[]);
        std::fs::write(
            &path,
            format!(
                "connect_timeout = \"4s\"\n[tcp_keepalive]\nidle = \"0s\"\n\
                 [filter]\nblock = [\"bad.example\"]\n{}",
                BASE.replace("http_port = 18080\nsocks_port = 18081\n", "")
            ),
        )
        .unwrap();
        // Ports come back as defaults in the file: reported, not applied.
        let s = r.reload_once(ReloadTrigger::Manual).unwrap();
        assert_eq!(s.ignored, vec!["http_port", "socks_port"]);
        let state = r.shared().load_full();
        assert_eq!(state.connect_timeout, Duration::from_secs(4));
        assert_eq!(state.keepalive, None);
        assert!(state.filter.is_some());
    }

    #[test]
    fn self_loop_is_rejected_against_active_listeners() {
        let (r, path, _cap) = reloader("selfloop", BASE, &[]);
        std::fs::write(
            &path,
            BASE.replace(
                "host = \"10.0.0.2\"\nport = 3128",
                "host = \"127.0.0.1\"\nport = 18081",
            ),
        )
        .unwrap();
        assert!(r.reload_once(ReloadTrigger::Manual).is_err());
        assert_eq!(r.generation(), 0);
    }

    #[test]
    fn watcher_relevance_filters_by_file_name() {
        use notify::event::{AccessKind, CreateKind, ModifyKind};
        let name = OsString::from("config.toml");
        let ev = |kind, p: &str| notify::Event::new(kind).add_path(PathBuf::from(p));
        assert!(is_relevant(
            &ev(notify::EventKind::Modify(ModifyKind::Any), "/x/config.toml"),
            &name
        ));
        assert!(is_relevant(
            &ev(
                notify::EventKind::Create(CreateKind::File),
                "/private/x/config.toml"
            ),
            &name
        ));
        assert!(!is_relevant(
            &ev(notify::EventKind::Modify(ModifyKind::Any), "/x/other.toml"),
            &name
        ));
        assert!(!is_relevant(
            &ev(notify::EventKind::Access(AccessKind::Any), "/x/config.toml"),
            &name
        ));
    }

    #[tokio::test]
    async fn watcher_requires_config_path() {
        let cfg = Config::default();
        let shared = RuntimeConfig::from_config(&cfg, DialerOptions::default())
            .unwrap()
            .shared();
        let r = Arc::new(Reloader::new(
            shared,
            CliInput::default(),
            cfg,
            DialerOptions::default(),
            Logger::with_writer(LogLevel::Quiet, Box::new(std::io::sink())),
        ));
        assert!(matches!(
            r.spawn_watcher(Duration::from_millis(10), CancellationToken::new()),
            Err(WatchError::NoConfigPath)
        ));
        assert!(matches!(
            r.reload_once(ReloadTrigger::Manual),
            Err(ReloadError::NoConfigPath)
        ));
    }
}
