//! rusty-conduit-switch: lightweight cross-platform HTTP/HTTPS and SOCKS4/4a/5 Auto Switch
//! proxy server with optional HTTPS MITM inspection.
//!
//! Library root and server bootstrap: configuration loading, subcommand dispatch
//! (`validate`, `test-route`, `import-airswitch`), listener startup, and graceful shutdown on
//! `Ctrl+C` / `SIGTERM`. The server runs the routed HTTP/HTTPS ([`http`]) and SOCKS4/4a/5
//! ([`socks`]) engines ([`server::EngineHandlers`]) over one shared
//! [`server::RoutingState`] (compiled [`router`] + [`upstream`] dialers). The routing engine
//! also backs `validate` and `test-route`. When a CA is configured, HTTPS `CONNECT`s are
//! intercepted ([`mitm`], [`http::mitm_tunnel`]) and `--socks-block-web` installs
//! the SOCKS web guard ([`socks::web_guard`]). With `--config`, the routing state is
//! hot-reloadable ([`reload`]): `SIGHUP` on Unix and, with `--watch-config`, a debounced
//! file watcher re-validate the file and atomically swap the shared runtime snapshot.
//! `import-airswitch` converts AirSwitch / ZeroOmega / SwitchyOmega `.bak` backups into a
//! commented TOML config ([`import`]).

pub mod config;
pub mod fdlimit;
pub mod import;
pub mod preflight;
pub mod reload;

// Extracted proxy engine (E1b): the routing/profile model and compiled snapshots
// ([`routing`]), rule matching ([`router`]), upstream dialers ([`upstream`]), the
// HTTP/HTTPS ([`http`]) and SOCKS4/4a/5 ([`socks`]) engines, HTTPS MITM ([`mitm`]),
// listeners and multiplexing ([`server`], [`mux`]), destination filtering ([`filter`]),
// socket helpers ([`net`]), and logging ([`logging`]) now live in `rusty-conduit-engine`
// and are re-exported here so the integration tests keep using `rusty_conduit_switch::...`.
pub use rusty_conduit_engine::{
    filter, http, logging, mitm, mux, net, router, routing, server, socks, upstream,
};

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use config::{CliInput, Command, Config, ConfigError, Inbound};
use logging::{AccessLogConfig, AccessLogger, LogLevel, Logger};
use router::{ParsedTarget, RouteRequest, Router};
#[cfg(test)]
use server::StubHandlers;
use server::{EngineHandlers, ProtocolHandlers, RoutingState, Server};

/// Exit code used for `FATAL` startup errors and failed subcommands.
pub const EXIT_FATAL: u8 = 1;

/// Merge and validate configuration from parsed CLI/env input.
///
/// On failure returns the error together with the best-known log level (the merged level if
/// merging succeeded, otherwise the CLI/env level, otherwise the default `INFO`), so the
/// `FATAL` message can still honour `--log-level QUIET`.
pub fn load_config(cli: CliInput) -> Result<Config, (ConfigError, LogLevel)> {
    let fallback_level = cli.args.log_level.unwrap_or(LogLevel::Info);
    let cfg = Config::from_cli(cli).map_err(|e| (e, fallback_level))?;
    cfg.validate().map_err(|e| (e, cfg.log_level))?;
    Ok(cfg)
}

/// Emit the startup banner, configuration summary, and any `INFO` notices.
pub fn log_startup(cfg: &Config, logger: &Logger) {
    logger.info(format!(
        "rusty-conduit-switch v{} starting",
        env!("CARGO_PKG_VERSION")
    ));
    logger.info(format!("config: {}", cfg.summary()));
    for notice in all_notices(cfg) {
        logger.info(notice);
    }
}

/// Configuration notices followed by routing notices (URL rules on opaque tunnels).
pub fn all_notices(cfg: &Config) -> Vec<String> {
    let mut out = cfg.notices();
    if let Ok(router) = Router::from_input(&cfg.routing_input()) {
        out.extend_from_slice(router.notices());
    }
    out
}

/// Run the proxy server with an already-validated configuration. `cli` is the CLI/env
/// input `cfg` was merged from; it is re-applied over the file on every hot-reload. Returns
/// the process exit code. Must be called inside a Tokio runtime.
pub async fn run(cfg: Config, cli: CliInput, logger: Logger) -> ExitCode {
    log_startup(&cfg, &logger);
    fdlimit::apply(&logger, cfg.max_connections, "--max-connections");

    let access = match AccessLogger::start(
        AccessLogConfig::new(
            cfg.log_level,
            cfg.log_format,
            cfg.http_access_log.clone(),
            cfg.socks_log.clone(),
        ),
        logger.clone(),
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            logger.fatal(format!("failed to open access log: {e}"));
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };

    let dialer_opts = upstream::DialerOptions::default();
    let routing = match RoutingState::from_input(&cfg.routing_input(), dialer_opts.clone()) {
        Ok(r) => r.shared(),
        Err(e) => {
            logger.fatal(format!("config invalid: {e}"));
            let _ = access.shutdown().await;
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let mitm_state = match mitm::MitmState::from_options(&cfg.mitm_options()) {
        Ok(m) => m,
        Err(e) => {
            logger.fatal(format!("MITM setup failed: {e}"));
            let _ = access.shutdown().await;
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let mut engines =
        EngineHandlers::from_routing(Arc::clone(&routing), access.clone(), logger.clone());
    if let Some(m) = &mitm_state {
        m.cache.set_logger(logger.clone());
        logger.info(format!(
            "MITM enabled: CA \"{}\" valid until {}; leaf certificate TTL {}",
            m.ca_subject,
            logging::format_timestamp(m.ca_not_after),
            humantime::format_duration(cfg.mitm_cert_ttl)
        ));
        engines = engines.with_mitm(Arc::new(m.interceptor.clone()), false);
    }
    if cfg.socks_block_web {
        logger.info("SOCKS web blocking enabled: HTTP/HTTPS over SOCKS is rejected");
        engines = engines.with_socks_block_web();
    }
    let handlers: Arc<dyn ProtocolHandlers> = Arc::new(engines);
    let server = match Server::from_options(&cfg.server_options(), handlers, logger.clone()).await {
        Ok(s) => s.with_runtime(Arc::clone(&routing)),
        Err(e) => {
            logger.fatal(e);
            let _ = access.shutdown().await;
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };
    // The leaf-certificate reaper runs only when MITM is enabled and stops on shutdown.
    let reaper = mitm_state.as_ref().map(|m| {
        m.cache
            .spawn_reaper(server.shutdown_token(), logger.clone())
    });
    for (role, addr) in server.listeners() {
        logger.info(format!("{role} proxy listening on {addr}"));
    }
    let reload_tasks = start_reload_triggers(
        Arc::new(reload::Reloader::new(
            routing,
            cli,
            cfg.clone(),
            dialer_opts,
            logger.clone(),
        )),
        &cfg,
        server.shutdown_token(),
        &logger,
    );

    let token = server.shutdown_token();
    let signal_logger = logger.clone();
    tokio::spawn(async move {
        tokio::select! {
            () = shutdown_signal(&signal_logger) => token.cancel(),
            () = token.cancelled() => {}
        }
    });
    let report = server.run().await;
    if report.drained {
        logger.debug("all connections drained");
    }
    if let Some(reaper) = reaper {
        let _ = reaper.await;
    }
    for task in reload_tasks {
        let _ = task.await;
    }

    logger.info("shutting down");
    let code = match access.shutdown().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            logger.error(format!("failed to flush access logs: {e}"));
            ExitCode::from(EXIT_FATAL)
        }
    };
    logger.flush();
    code
}

/// Start the hot-reload triggers for a server run from `cfg`: `SIGHUP` (Unix) whenever
/// `--config` is set, plus the debounced file watcher with `--watch-config`. A trigger that
/// cannot start is logged and skipped. The returned tasks end when `shutdown` is cancelled.
pub fn start_reload_triggers(
    reloader: Arc<reload::Reloader>,
    cfg: &Config,
    shutdown: tokio_util::sync::CancellationToken,
    logger: &Logger,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut tasks = Vec::new();
    let Some(path) = cfg.config_path.as_ref() else {
        return tasks;
    };
    #[cfg(unix)]
    if let Some(task) = reloader.spawn_sighup(shutdown.clone()) {
        logger.debug(format!("SIGHUP reloads {}", path.display()));
        tasks.push(task);
    }
    if cfg.watch_config {
        match reloader.spawn_watcher(cfg.watch_debounce, shutdown) {
            Ok(task) => tasks.push(task),
            Err(e) => logger.error(format!(
                "cannot watch {} for changes: {e}; hot-reload by file watching is disabled",
                path.display()
            )),
        }
    }
    tasks
}

/// Resolve when the process receives `Ctrl+C` (all platforms) or `SIGTERM` (Unix).
///
/// If a signal handler cannot be installed the error is logged and that source is ignored.
pub async fn shutdown_signal(logger: &Logger) {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => logger.info("received Ctrl+C"),
            Err(e) => {
                logger.error(format!("failed to listen for Ctrl+C: {e}"));
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
                logger.info("received SIGTERM");
            }
            Err(e) => {
                logger.error(format!("failed to listen for SIGTERM: {e}"));
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// Load and validate configuration for a subcommand that requires `--config`.
fn load_subcommand_config(name: &'static str, cli: CliInput) -> Result<Config, ConfigError> {
    if cli.args.config.is_none() {
        return Err(ConfigError::MissingConfig(name));
    }
    load_config(cli).map_err(|(e, _)| e)
}

/// `validate --config <PATH>`: exit 0 when the configuration is valid, 1 otherwise.
/// The offline checks startup would fail on (see [`preflight`]), in startup order: the
/// access logs, the routing state (which resolves every upstream password), and the MITM CA.
pub fn preflight_checks(cfg: &Config) -> Result<(), String> {
    if let Some(path) = &cfg.http_access_log {
        preflight::check_log_path("--http-access-log", path)?;
    }
    if let Some(path) = &cfg.socks_log {
        preflight::check_log_path("--socks-log", path)?;
    }
    RoutingState::from_input(&cfg.routing_input(), upstream::DialerOptions::default())
        .map_err(|e| e.to_string())?;
    preflight::check_mitm(&cfg.mitm_options())
}

pub fn cmd_validate(cli: CliInput, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let settings_only = matches!(
        cli.args.command,
        Some(Command::Validate {
            settings_only: true
        })
    );
    match load_subcommand_config("validate", cli) {
        Ok(cfg) => {
            if !settings_only {
                if let Err(e) = preflight_checks(&cfg) {
                    let _ = writeln!(err, "config invalid: {e}");
                    return EXIT_FATAL;
                }
            }
            let path = cfg
                .config_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "config OK: {path} profiles={} rules={}",
                cfg.profiles_with_builtins().len(),
                cfg.routing.rule_count()
            );
            for notice in all_notices(&cfg) {
                let _ = writeln!(out, "{notice}");
            }
            if !settings_only {
                if let Some(notice) =
                    preflight::fd_limit_notice(cfg.max_connections, "--max-connections")
                {
                    let _ = writeln!(out, "{notice}");
                }
            }
            0
        }
        Err(e) => {
            let _ = writeln!(err, "config invalid: {e}");
            EXIT_FATAL
        }
    }
}

/// `test-route [--inbound http|socks] <TARGET>`: dry-run the routing decision.
///
/// The target is `HOST`, `HOST:PORT` (port defaults to 80), `[V6]:PORT`, or a full
/// `http://` / `https://` URL. The request is shaped the way the proxy would see it: SOCKS
/// never sees a URL, and an `https://` URL is only visible over HTTP when MITM is enabled
/// (otherwise it is an opaque `CONNECT` tunnel). No DNS lookup happens unless a rule opts
/// in with `resolve_dns = true`.
pub fn cmd_test_route(
    cli: CliInput,
    inbound: Inbound,
    target: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let cfg = match load_subcommand_config("test-route", cli) {
        Ok(cfg) => cfg,
        Err(e) => {
            let _ = writeln!(err, "config invalid: {e}");
            return EXIT_FATAL;
        }
    };
    let router = match Router::from_input(&cfg.routing_input()) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err, "config invalid: {e}");
            return EXIT_FATAL;
        }
    };
    let parsed = match ParsedTarget::parse(target) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(err, "invalid target: {e}");
            return EXIT_FATAL;
        }
    };

    let mut notes = Vec::new();
    let (scheme, url) = match (inbound, parsed.scheme.as_deref(), parsed.url.as_deref()) {
        (Inbound::Socks, _, Some(_)) => {
            notes.push("SOCKS connections carry no URL: URL rules are not evaluated");
            (None, None)
        }
        (Inbound::Http, Some("https"), Some(_)) if !cfg.mitm_enabled() => {
            notes.push(
                "HTTPS without MITM is an opaque CONNECT tunnel: URL rules are not evaluated",
            );
            (Some("https"), None)
        }
        (_, scheme, url) => (scheme, url),
    };
    let req = RouteRequest {
        inbound,
        host: &parsed.host,
        port: parsed.port,
        scheme,
        url,
    };
    let shown = if parsed.host.contains(':') {
        format!("[{}]:{}", parsed.host, parsed.port)
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };
    match router.route(&req) {
        Ok(d) => {
            let upstream = d
                .targets
                .first()
                .and_then(|t| router.profile(&t.profile))
                .map(|p| p.redacted_upstream())
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "target={shown} inbound={inbound} table={} rule={} profile={} chain={} upstream={upstream}",
                d.table,
                quote_if_needed(d.rule_label()),
                d.profile_label(),
                d.chain_label(),
            );
        }
        Err(denied) => {
            let _ = writeln!(
                out,
                "target={shown} inbound={inbound} status=denied_by_filter reason={:?}",
                denied.0
            );
        }
    }
    for note in notes {
        let _ = writeln!(out, "note: {note}");
    }
    0
}

/// logfmt-style quoting for values containing spaces or quotes.
fn quote_if_needed(v: &str) -> String {
    if v.contains([' ', '"', '=']) {
        format!("{v:?}")
    } else {
        v.to_string()
    }
}

/// `import-airswitch <BAK_PATH> [-o OUT.toml] [--profile NAME] [--force]`: convert an
/// AirSwitch / ZeroOmega / SwitchyOmega `.bak` backup into TOML on `out` (or `output`,
/// refusing to overwrite an existing file unless `force`). Warnings go to `err`.
pub fn cmd_import_airswitch(
    bak_path: &std::path::Path,
    output: Option<&std::path::Path>,
    profile: Option<&str>,
    force: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    import::run_import(bak_path, output, profile, force, out, err)
}

/// Full CLI entrypoint: parse args/env (help/version/usage errors exit inside `clap`),
/// dispatch subcommands, or load and validate config and run the server on a
/// multi-threaded Tokio runtime.
pub fn main_entry() -> ExitCode {
    let cli = CliInput::parse();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    match cli.args.command.clone() {
        Some(Command::Validate { .. }) => {
            return ExitCode::from(cmd_validate(cli, &mut out, &mut err))
        }
        Some(Command::TestRoute { inbound, target }) => {
            return ExitCode::from(cmd_test_route(cli, inbound, &target, &mut out, &mut err))
        }
        Some(Command::ImportAirswitch {
            bak_path,
            output,
            profile,
            force,
        }) => {
            return ExitCode::from(cmd_import_airswitch(
                &bak_path,
                output.as_deref(),
                profile.as_deref(),
                force,
                &mut out,
                &mut err,
            ))
        }
        None => {}
    }

    let cfg = match load_config(cli.clone()) {
        Ok(cfg) => cfg,
        Err((e, level)) => {
            let logger = Logger::stderr(level);
            logger.fatal(e);
            logger.flush();
            return ExitCode::from(EXIT_FATAL);
        }
    };
    let logger = Logger::stderr(cfg.log_level);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            logger.fatal(format!("failed to start async runtime: {e}"));
            return ExitCode::from(EXIT_FATAL);
        }
    };
    runtime.block_on(run(cfg, cli, logger))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TEST_ENV_LOCK as ENV_LOCK;

    fn cli(args: &[&str]) -> CliInput {
        let mut full = vec!["rusty-conduit-switch"];
        full.extend_from_slice(args);
        CliInput::try_parse_from(full).unwrap()
    }

    fn temp_toml(name: &str, text: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("rcs-lib-{name}-{}.toml", std::process::id()));
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn validate_reports_ok_and_errors() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let good = temp_toml(
            "good",
            "[profiles.corp]\ntype = \"http\"\nhost = \"10.0.0.2\"\nport = 3128\n\
             [[routing.rules]]\nhost = \"a.example\"\ntarget = \"corp\"\n",
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cmd_validate(
            cli(&["validate", "--config", good.to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("config OK") && out.contains("profiles=3 rules=1"),
            "{out}"
        );

        let bad = temp_toml("bad", "[routing]\ndefault = \"missing\"\n");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cmd_validate(
            cli(&["validate", "--config", bad.to_str().unwrap()]),
            &mut out,
            &mut err,
        );
        assert_eq!(code, EXIT_FATAL);
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("unknown profile `missing`"));

        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            cmd_validate(cli(&["validate"]), &mut out, &mut err),
            EXIT_FATAL
        );
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("requires --config"));
        std::fs::remove_file(good).ok();
        std::fs::remove_file(bad).ok();
    }

    #[test]
    fn test_route_reports_routing_decision() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path = temp_toml(
            "route",
            "[profiles.bastion]\ntype = \"socks5\"\nhost = \"127.0.0.1\"\nport = 1081\n\
             [routing.socks]\ndefault = \"bastion\"\n",
        );
        let p = path.to_str().unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let c = cli(&["test-route", "--config", p, "--inbound", "socks", "db:5432"]);
        assert_eq!(
            cmd_test_route(c, Inbound::Socks, "db:5432", &mut out, &mut err),
            0
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("target=db:5432 inbound=socks"), "{out}");
        assert!(out.contains("profile=bastion"), "{out}");

        let (mut out, mut err) = (Vec::new(), Vec::new());
        let c = cli(&["test-route", "--config", p, "db:5432"]);
        assert_eq!(
            cmd_test_route(c, Inbound::Http, "db:5432", &mut out, &mut err),
            0
        );
        assert!(String::from_utf8(out).unwrap().contains("profile=direct"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn import_airswitch_reports_unreadable_input() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            cmd_import_airswitch(
                std::path::Path::new("/nonexistent/x.bak"),
                None,
                None,
                false,
                &mut out,
                &mut err
            ),
            EXIT_FATAL
        );
        assert!(out.is_empty());
        assert!(String::from_utf8(err).unwrap().contains("cannot read"));
    }

    #[tokio::test]
    async fn server_binds_from_config_and_shuts_down() {
        let cfg = Config {
            http_port: 0,
            socks_port: 0,
            ..Config::default()
        };
        // Port 0 in Config disables listeners; bind via an explicit ephemeral plan instead.
        assert!(cfg.validate().is_err());
        let quiet = Logger::with_writer(LogLevel::Quiet, Box::new(std::io::sink()));
        let handlers: Arc<dyn ProtocolHandlers> = Arc::new(StubHandlers::new(quiet.clone()));
        let server = Server::bind(
            server::ListenPlan::Multiplexed("127.0.0.1:0".parse().unwrap()),
            handlers,
            quiet,
        )
        .await
        .unwrap()
        .with_max_connections(Config::default().max_connections);
        let addr = server.local_http_addr().unwrap();
        let token = server.shutdown_token();
        let run = tokio::spawn(server.run());
        // Stub handlers accept and close.
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut s, b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut s, &mut buf).await;
        assert!(buf.is_empty());
        token.cancel();
        assert!(run.await.unwrap().drained);
    }
}
