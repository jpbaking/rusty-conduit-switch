//! Configuration loading and validation.
//!
//! Sources are merged with strict precedence:
//! **CLI flags > `RUSTY_CONDUIT_SWITCH_*` environment variables > `--config` TOML file > defaults**.
//!
//! CLI flags and environment variables are both handled by `clap` (each flag declares its
//! `env` fallback, and `clap` itself prefers the flag over the variable). The resulting
//! [`CliInput`] is layered over an optional [`FileConfig`] and the built-in defaults by
//! [`Config::merge`], and checked by [`Config::validate`].
//!
//! Besides the server settings, the TOML file carries the Auto Switch model: named upstream
//! `[profiles.*]` and the `[routing]` table (with optional `[routing.http]` /
//! `[routing.socks]` overrides). This module only parses and sanity-checks that model
//! (credential sources, profile references, self-loops); compiling rules into matchers is
//! the router's job.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::builder::{PossibleValuesParser, TypedValueParser};
use clap::parser::ValueSource;
use clap::{ArgAction, ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::Deserialize;

use crate::filter::{FilterRule, HostFilter};
use crate::logging::{LogFormat, LogLevel};
use crate::net::KeepaliveSettings;
use rusty_conduit_engine::mitm::MitmOptions;
use rusty_conduit_engine::server::ServerOptions;

// E1b: the routing/profile model, the MITM CA source, and the routing-model errors
// now live in `rusty-conduit-engine` and are re-exported here so the CLI/TOML layer and the
// integration tests keep referring to them as `crate::config::...`. The switch keeps its own
// [`ConfigError`] (config-level checks) but maps the engine's `RoutingError` onto it 1:1 so the
// reported strings are unchanged.
pub use rusty_conduit_engine::mitm::CaSource;
pub use rusty_conduit_engine::routing::{
    HostLevels, Inbound, OneOrMany, PortSpec, ProfileConfig, ProfileType, RoutingConfig,
    RoutingError, RoutingInput, RoutingTableConfig, RuleConfig, Target,
};
// Engine defaults and built-in profile names, shared with the CLI/TOML layer.
pub use rusty_conduit_engine::routing::{DEFAULT_CONNECT_TIMEOUT, PROFILE_BLOCK, PROFILE_DIRECT};

/// Default bind address.
pub const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default HTTP/HTTPS proxy port.
pub const DEFAULT_HTTP_PORT: u16 = 3128;
/// Default SOCKS4/4a/5 proxy port.
pub const DEFAULT_SOCKS_PORT: u16 = 1080;
/// Default debounce window for config file change events.
pub const DEFAULT_WATCH_DEBOUNCE: Duration = Duration::from_millis(300);
/// Default cap on concurrent client connections (`0` = unlimited).
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;
/// Default in-memory TTL for generated MITM leaf certificates.
pub const DEFAULT_MITM_CERT_TTL: Duration = Duration::from_secs(60 * 60);
/// Smallest accepted MITM leaf certificate TTL.
pub const MIN_MITM_CERT_TTL: Duration = Duration::from_secs(10);
/// Default cap on cached MITM leaf certificates (`0` = unlimited).
pub const DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES: usize = 10_240;
/// Largest accepted TCP keepalive idle time / probe interval (Linux caps both at 32767s).
pub const MAX_TCP_KEEPALIVE_DURATION: Duration = Duration::from_secs(32_767);
/// Largest accepted TCP keepalive probe count (Linux caps `TCP_KEEPCNT` at 127).
pub const MAX_TCP_KEEPALIVE_RETRIES: u32 = 127;

/// Errors raised while loading or validating configuration. Every variant is `FATAL` at
/// startup (and rejects the candidate configuration on hot-reload).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {message}")]
    ParseFile { path: PathBuf, message: String },
    #[error("invalid value for `{key}` in config file: {message}")]
    InvalidFileValue { key: &'static str, message: String },
    #[error("both http_port and socks_port are 0: at least one listener must be enabled")]
    NoListeners,
    #[error(
        "ambiguous MITM CA source: --mitm-ca-p12 cannot be combined with --mitm-ca-cert or --mitm-ca-key"
    )]
    AmbiguousCaSource,
    #[error("incomplete PEM MITM CA: --mitm-ca-cert and --mitm-ca-key must be provided together")]
    IncompletePemCa,
    #[error(
        "conflicting passphrase sources: use only one of --mitm-ca-passphrase and --mitm-ca-passphrase-file"
    )]
    ConflictingPassphrase,
    #[error("--mitm-cert-ttl must be at least 10s (got {})", humantime::format_duration(*.0))]
    CertTtlTooShort(Duration),
    #[error("invalid TCP keepalive setting: {0}")]
    InvalidKeepalive(String),
    #[error("--connect-timeout must be greater than 0")]
    ZeroConnectTimeout,
    #[error("invalid profile `{profile}`: {message}")]
    InvalidProfile { profile: String, message: String },
    #[error(
        "ambiguous password source for profile `{profile}`: use only one of password, password_env, password_file"
    )]
    AmbiguousPassword { profile: String },
    #[error("profile `{profile}`: failed to resolve password: {message}")]
    ResolvePassword { profile: String, message: String },
    #[error("{location} references unknown profile `{target}`")]
    UnknownProfile { location: String, target: String },
    #[error("{location} has an empty failover chain")]
    EmptyTarget { location: String },
    #[error(
        "profile `{profile}` points to this server's own listener {listener} (self-loop); \
         refusing to start"
    )]
    SelfLoop { profile: String, listener: String },
    #[error("the `{0}` subcommand requires --config <PATH>")]
    MissingConfig(&'static str),
    #[error("invalid routing configuration: {0}")]
    Routing(#[from] rusty_conduit_engine::router::RouterError),
}

/// Map the engine's routing-model errors onto [`ConfigError`] with identical `Display` strings,
/// so delegating validation to `RoutingInput::validate()` reports exactly the same messages as
/// the switch's own checks did.
impl From<rusty_conduit_engine::routing::RoutingError> for ConfigError {
    fn from(err: rusty_conduit_engine::routing::RoutingError) -> Self {
        match err {
            rusty_conduit_engine::routing::RoutingError::InvalidProfile { profile, message } => {
                ConfigError::InvalidProfile { profile, message }
            }
            rusty_conduit_engine::routing::RoutingError::AmbiguousPassword { profile } => {
                ConfigError::AmbiguousPassword { profile }
            }
            rusty_conduit_engine::routing::RoutingError::ResolvePassword { profile, message } => {
                ConfigError::ResolvePassword { profile, message }
            }
            rusty_conduit_engine::routing::RoutingError::UnknownProfile { location, target } => {
                ConfigError::UnknownProfile { location, target }
            }
            rusty_conduit_engine::routing::RoutingError::EmptyTarget { location } => {
                ConfigError::EmptyTarget { location }
            }
            rusty_conduit_engine::routing::RoutingError::SelfLoop { profile, listener } => {
                ConfigError::SelfLoop { profile, listener }
            }
            rusty_conduit_engine::routing::RoutingError::Routing(source) => {
                ConfigError::Routing(source)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

/// Subcommands. Without one, the proxy server runs.
#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Validate the configuration file (profiles, routing, self-loops) and exit 0/1
    Validate,
    /// Dry-run the routing decision for a target and print it
    TestRoute {
        /// Inbound protocol to evaluate the routing table for
        #[arg(
            long,
            value_parser = PossibleValuesParser::new(["http", "socks"])
                .map(|s| s.parse::<Inbound>().expect("restricted to the possible values")),
            default_value_t = Inbound::Http
        )]
        inbound: Inbound,
        /// Target as HOST[:PORT] or a full URL
        #[arg(value_name = "HOST[:PORT] | URL")]
        target: String,
    },
    /// Convert an AirSwitch / ZeroOmega / SwitchyOmega .bak JSON backup into TOML
    ImportAirswitch {
        /// Path to the .bak JSON backup
        #[arg(value_name = "BAK_PATH")]
        bak_path: PathBuf,
        /// Output TOML path (default: stdout)
        #[arg(short = 'o', long = "output", value_name = "OUT.toml")]
        output: Option<PathBuf>,
        /// SwitchProfile to import as [routing]
        #[arg(long, value_name = "SWITCH_PROFILE_NAME")]
        profile: Option<String>,
        /// Overwrite the output file if it already exists
        #[arg(long)]
        force: bool,
    },
}

/// Raw command-line / environment input (`clap` derive with `env` fallbacks).
#[derive(Debug, Clone, Default, Parser)]
#[command(
    name = "rusty-conduit-switch",
    version,
    about = "Lightweight HTTP/HTTPS and SOCKS4/4a/5 Auto Switch proxy server with optional HTTPS MITM inspection",
    long_about = "Lightweight HTTP/HTTPS and SOCKS4/4a/5 Auto Switch proxy server with optional HTTPS MITM inspection.\n\n\
                  Precedence: CLI flags > RUSTY_CONDUIT_SWITCH_* environment variables > --config TOML file > defaults."
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Optional TOML configuration file path
    #[arg(
        long,
        value_name = "PATH",
        env = "RUSTY_CONDUIT_SWITCH_CONFIG",
        global = true
    )]
    pub config: Option<PathBuf>,

    /// Watch --config for changes and hot-reload automatically
    #[arg(
        long,
        env = "RUSTY_CONDUIT_SWITCH_WATCH_CONFIG",
        action = ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub watch_config: bool,

    /// Debounce window for config file change events [default: 300ms]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SWITCH_WATCH_DEBOUNCE",
        value_parser = humantime::parse_duration
    )]
    pub watch_debounce: Option<Duration>,

    /// IPv4 or IPv6 address to bind listeners to [default: 127.0.0.1]
    #[arg(long, value_name = "IP", env = "RUSTY_CONDUIT_SWITCH_BIND")]
    pub bind: Option<IpAddr>,

    /// HTTP/HTTPS proxy port, 0 to disable [default: 3128]
    #[arg(long, value_name = "PORT", env = "RUSTY_CONDUIT_SWITCH_HTTP_PORT")]
    pub http_port: Option<u16>,

    /// SOCKS4/4a/5 proxy port, 0 to disable [default: 1080]
    #[arg(long, value_name = "PORT", env = "RUSTY_CONDUIT_SWITCH_SOCKS_PORT")]
    pub socks_port: Option<u16>,

    /// Upstream TCP + proxy handshake timeout per attempt [default: 10s]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SWITCH_CONNECT_TIMEOUT",
        value_parser = humantime::parse_duration
    )]
    pub connect_timeout: Option<Duration>,

    /// Maximum concurrent client connections; excess connections are closed immediately, 0 = unlimited [default: 4096]
    #[arg(long, value_name = "N", env = "RUSTY_CONDUIT_SWITCH_MAX_CONNECTIONS")]
    pub max_connections: Option<usize>,

    /// Idle time before TCP keepalive probes start on client and upstream sockets, 0 = disabled [default: 60s]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE",
        value_parser = humantime::parse_duration
    )]
    pub tcp_keepalive: Option<Duration>,

    /// Deprecated alias for --tcp-keepalive
    #[arg(
        long = "tcp-keepalive-idle",
        hide = true,
        env = "RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_IDLE",
        value_parser = humantime::parse_duration
    )]
    pub tcp_keepalive_idle: Option<Duration>,

    /// Time between unanswered TCP keepalive probes [default: 10s]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_INTERVAL",
        value_parser = humantime::parse_duration
    )]
    pub tcp_keepalive_interval: Option<Duration>,

    /// Unanswered TCP keepalive probes before the connection is closed [default: 5]
    #[arg(
        long,
        value_name = "N",
        env = "RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_RETRIES"
    )]
    pub tcp_keepalive_retries: Option<u32>,

    /// Allowlist of destinations (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated.
    /// When combined with --block, serves as exceptions to the blocklist.
    #[arg(
        long,
        value_name = "RULE",
        value_delimiter = ',',
        env = "RUSTY_CONDUIT_SWITCH_ALLOW"
    )]
    pub allow: Vec<FilterRule>,

    /// Blocklist of destinations (IP, CIDR, FQDN, or *.domain); repeatable or comma-separated.
    /// Combine with --allow to carve out exceptions.
    #[arg(
        long,
        value_name = "RULE",
        value_delimiter = ',',
        env = "RUSTY_CONDUIT_SWITCH_BLOCK"
    )]
    pub block: Vec<FilterRule>,

    /// Path to PEM-encoded CA certificate (enables MITM together with --mitm-ca-key)
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SWITCH_MITM_CA_CERT")]
    pub mitm_ca_cert: Option<PathBuf>,

    /// Path to PEM-encoded CA private key
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SWITCH_MITM_CA_KEY")]
    pub mitm_ca_key: Option<PathBuf>,

    /// Path to PKCS#12 (.p12/.pfx) CA bundle (enables MITM)
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SWITCH_MITM_CA_P12")]
    pub mitm_ca_p12: Option<PathBuf>,

    /// Passphrase for the PKCS#12 bundle or encrypted PEM key (prefer the env var or a passphrase file)
    #[arg(
        long,
        value_name = "STR",
        env = "RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE",
        hide_env_values = true
    )]
    pub mitm_ca_passphrase: Option<String>,

    /// File containing the CA passphrase (trailing newline is trimmed)
    #[arg(
        long,
        value_name = "PATH",
        env = "RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE_FILE"
    )]
    pub mitm_ca_passphrase_file: Option<PathBuf>,

    /// In-memory TTL for generated MITM leaf certs, e.g. 30m, 1h, 3600s [default: 1h]
    #[arg(
        long,
        value_name = "DURATION",
        env = "RUSTY_CONDUIT_SWITCH_MITM_CERT_TTL",
        value_parser = humantime::parse_duration
    )]
    pub mitm_cert_ttl: Option<Duration>,

    /// Maximum cached MITM leaf certificates; expired then oldest entries are evicted, 0 = unlimited [default: 10240]
    #[arg(
        long,
        value_name = "N",
        env = "RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX_ENTRIES"
    )]
    pub mitm_cert_cache_max_entries: Option<usize>,

    /// Deprecated alias for --mitm-cert-cache-max-entries
    #[arg(
        long = "mitm-cert-cache-max",
        hide = true,
        env = "RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX"
    )]
    pub mitm_cert_cache_max: Option<usize>,

    /// Reject HTTP/HTTPS traffic over SOCKS4/4a/5 (works with or without MITM)
    #[arg(
        long,
        env = "RUSTY_CONDUIT_SWITCH_SOCKS_BLOCK_WEB",
        action = ArgAction::SetTrue,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    pub socks_block_web: bool,

    /// Log level: QUIET, FATAL, ERROR, INFO, DEBUG, VERBOSE (case-insensitive) [default: INFO]
    #[arg(long, value_name = "LEVEL", env = "RUSTY_CONDUIT_SWITCH_LOG_LEVEL")]
    pub log_level: Option<LogLevel>,

    /// Access/SOCKS log format: text (logfmt) or json (NDJSON) [default: text]
    #[arg(long, value_name = "FMT", env = "RUSTY_CONDUIT_SWITCH_LOG_FORMAT")]
    pub log_format: Option<LogFormat>,

    /// Optional file path for HTTP/HTTPS access logs
    #[arg(
        long,
        value_name = "PATH",
        env = "RUSTY_CONDUIT_SWITCH_HTTP_ACCESS_LOG"
    )]
    pub http_access_log: Option<PathBuf>,

    /// Optional file path for SOCKS4/4a/5 connection logs
    #[arg(long, value_name = "PATH", env = "RUSTY_CONDUIT_SWITCH_SOCKS_LOG")]
    pub socks_log: Option<PathBuf>,
}

/// Parsed CLI/env input plus the provenance details that `clap` alone does not expose.
#[derive(Debug, Clone, Default)]
pub struct CliInput {
    pub args: CliArgs,
    /// `--mitm-ca-passphrase` came from an actual command-line argument (not the env var).
    pub passphrase_from_cli: bool,
    /// `--socks-block-web` was explicitly provided (CLI or env).
    pub socks_block_web_explicit: bool,
    /// Resolved CLI/env value for `--socks-block-web` when `socks_block_web_explicit` is true.
    pub socks_block_web_value: bool,
    /// `--watch-config` was explicitly provided (CLI or env), so it overrides TOML.
    pub watch_config_explicit: bool,
    /// Deprecation notices produced by legacy CLI flags or environment variables.
    pub deprecated: Vec<String>,
}

impl CliInput {
    /// Parse the process arguments and environment; prints help/version or usage errors and exits.
    pub fn parse() -> Self {
        let matches = CliArgs::command().get_matches();
        Self::from_matches(&matches).unwrap_or_else(|e| e.exit())
    }

    /// Parse an explicit argument list (the environment is still consulted for `env` fallbacks).
    pub fn try_parse_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = CliArgs::command().try_get_matches_from(args)?;
        Self::from_matches(&matches)
    }

    fn from_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let mut args = CliArgs::from_arg_matches(matches)?;
        let mut deprecated = Vec::new();
        if let Some(legacy_src) = matches.value_source("tcp_keepalive_idle") {
            deprecated.push(
                "NOTICE: --tcp-keepalive-idle / RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_IDLE is deprecated; use --tcp-keepalive / RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE"
                    .to_string(),
            );
            let primary_src = matches.value_source("tcp_keepalive");
            if primary_src.is_none()
                || (primary_src == Some(ValueSource::EnvVariable)
                    && legacy_src == ValueSource::CommandLine)
            {
                args.tcp_keepalive = args.tcp_keepalive_idle;
            }
        }
        if let Some(legacy_src) = matches.value_source("mitm_cert_cache_max") {
            deprecated.push(
                "NOTICE: --mitm-cert-cache-max / RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX is deprecated; use --mitm-cert-cache-max-entries / RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX_ENTRIES"
                    .to_string(),
            );
            let primary_src = matches.value_source("mitm_cert_cache_max_entries");
            if primary_src.is_none()
                || (primary_src == Some(ValueSource::EnvVariable)
                    && legacy_src == ValueSource::CommandLine)
            {
                args.mitm_cert_cache_max_entries = args.mitm_cert_cache_max;
            }
        }
        let explicit = |id: &str| {
            matches!(
                matches.value_source(id),
                Some(ValueSource::CommandLine | ValueSource::EnvVariable)
            )
        };
        let socks_block_web_explicit = matches!(
            matches.value_source("socks_block_web"),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        );
        let socks_block_web_value = args.socks_block_web;
        Ok(Self {
            passphrase_from_cli: matches.value_source("mitm_ca_passphrase")
                == Some(ValueSource::CommandLine),
            socks_block_web_explicit,
            socks_block_web_value,
            watch_config_explicit: explicit("watch_config"),
            deprecated,
            args,
        })
    }
}

// ---------------------------------------------------------------------------
// TOML file layout
// ---------------------------------------------------------------------------

// The routing/profile model (`OneOrMany`, `Target`, `PortSpec`, `HostLevels`, `RuleConfig`,
// `RoutingTableConfig`, `RoutingConfig`, `ProfileType`, `ProfileConfig`) and the inbound
// family (`Inbound`) are defined in `rusty-conduit-engine` and re-exported at the top of this
// file, so the TOML structs below (`FileConfig` etc.) reference them unchanged.

/// Deprecated `[tcp_keepalive]` table; use the top-level keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileKeepaliveConfig {
    /// Human-readable duration such as `60s`; `"0s"` disables keepalive.
    pub idle: Option<String>,
    pub interval: Option<String>,
    pub retries: Option<u32>,
}

/// `tcp_keepalive`: a duration string (canonical) or the deprecated `[tcp_keepalive]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKeepaliveField {
    Idle(String),
    Table(FileKeepaliveConfig),
}

impl<'de> Deserialize<'de> for FileKeepaliveField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        match toml::Value::deserialize(deserializer)? {
            toml::Value::String(s) => Ok(Self::Idle(s)),
            v @ toml::Value::Table(_) => v
                .try_into::<FileKeepaliveConfig>()
                .map(Self::Table)
                .map_err(D::Error::custom),
            other => Err(D::Error::custom(format!(
                "expected a duration string such as \"60s\", found {}",
                other.type_str()
            ))),
        }
    }
}

/// Deprecated `[filter]` table; use top-level `allow` / `block`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileFilterConfig {
    pub allow: Option<Vec<String>>,
    pub block: Option<Vec<String>>,
}

/// `[mitm]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileMitmConfig {
    pub ca_cert: Option<PathBuf>,
    pub ca_key: Option<PathBuf>,
    pub ca_p12: Option<PathBuf>,
    pub ca_passphrase: Option<String>,
    pub ca_passphrase_file: Option<PathBuf>,
    /// Human-readable duration such as `30m`, `1h`, or `3600s`.
    pub cert_ttl: Option<String>,
    pub cert_cache_max_entries: Option<usize>,
    pub cert_cache_max: Option<usize>,
}

/// `[logging]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileLoggingConfig {
    pub level: Option<String>,
    pub format: Option<String>,
    pub http_access_log: Option<PathBuf>,
    pub socks_log: Option<PathBuf>,
}

/// Top-level TOML configuration file layout.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub bind: Option<IpAddr>,
    pub http_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub watch_config: Option<bool>,
    pub watch_debounce: Option<String>,
    pub connect_timeout: Option<String>,
    pub max_connections: Option<usize>,
    /// Reject HTTP/HTTPS traffic over SOCKS4/4a/5 (works with or without MITM).
    pub socks_block_web: Option<bool>,
    pub tcp_keepalive: Option<FileKeepaliveField>,
    pub tcp_keepalive_interval: Option<String>,
    pub tcp_keepalive_retries: Option<u32>,
    pub allow: Option<Vec<String>>,
    pub block: Option<Vec<String>>,
    #[serde(default)]
    pub filter: FileFilterConfig,
    #[serde(default)]
    pub mitm: FileMitmConfig,
    #[serde(default)]
    pub logging: FileLoggingConfig,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
}

impl FileConfig {
    /// Parse TOML text.
    pub fn from_toml_str(text: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::ParseFile {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
    }

    /// Read and parse a TOML file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&text, path)
    }
}

// ---------------------------------------------------------------------------
// Merged configuration
// ---------------------------------------------------------------------------

/// Fully merged configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    pub config_path: Option<PathBuf>,
    pub watch_config: bool,
    pub watch_debounce: Duration,
    pub bind: IpAddr,
    pub http_port: u16,
    pub socks_port: u16,
    pub connect_timeout: Duration,
    /// Maximum concurrent client connections (`0` = unlimited).
    pub max_connections: usize,
    /// Idle time before TCP keepalive probes start (`0` = keepalive disabled).
    pub tcp_keepalive_idle: Duration,
    pub tcp_keepalive_interval: Duration,
    pub tcp_keepalive_retries: u32,
    /// Destination allowlist rules (exceptions to `block` when both are set).
    pub allow: Vec<FilterRule>,
    /// Destination blocklist rules (combine with `allow` to carve out exceptions).
    pub block: Vec<FilterRule>,
    pub mitm_ca_cert: Option<PathBuf>,
    pub mitm_ca_key: Option<PathBuf>,
    pub mitm_ca_p12: Option<PathBuf>,
    pub mitm_ca_passphrase: Option<String>,
    pub mitm_ca_passphrase_file: Option<PathBuf>,
    pub mitm_cert_ttl: Duration,
    /// Maximum cached MITM leaf certificates (`0` = unlimited).
    pub mitm_cert_cache_max: usize,
    pub socks_block_web: bool,
    pub log_level: LogLevel,
    pub log_format: LogFormat,
    pub http_access_log: Option<PathBuf>,
    pub socks_log: Option<PathBuf>,
    /// Declared upstream profiles (built-ins are added by [`Config::profiles_with_builtins`]).
    pub profiles: BTreeMap<String, ProfileConfig>,
    pub routing: RoutingConfig,
    /// The passphrase was supplied as a CLI argument (triggers an `INFO` notice).
    pub passphrase_from_cli: bool,
    /// Deprecation notices triggered by legacy flags or env vars.
    pub deprecations: Vec<String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("config_path", &self.config_path)
            .field("watch_config", &self.watch_config)
            .field("watch_debounce", &self.watch_debounce)
            .field("bind", &self.bind)
            .field("http_port", &self.http_port)
            .field("socks_port", &self.socks_port)
            .field("connect_timeout", &self.connect_timeout)
            .field("max_connections", &self.max_connections)
            .field("tcp_keepalive_idle", &self.tcp_keepalive_idle)
            .field("tcp_keepalive_interval", &self.tcp_keepalive_interval)
            .field("tcp_keepalive_retries", &self.tcp_keepalive_retries)
            .field("allow", &self.allow)
            .field("block", &self.block)
            .field("mitm_ca_cert", &self.mitm_ca_cert)
            .field("mitm_ca_key", &self.mitm_ca_key)
            .field("mitm_ca_p12", &self.mitm_ca_p12)
            .field(
                "mitm_ca_passphrase",
                &self.mitm_ca_passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("mitm_ca_passphrase_file", &self.mitm_ca_passphrase_file)
            .field("mitm_cert_ttl", &self.mitm_cert_ttl)
            .field("mitm_cert_cache_max", &self.mitm_cert_cache_max)
            .field("socks_block_web", &self.socks_block_web)
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("http_access_log", &self.http_access_log)
            .field("socks_log", &self.socks_log)
            .field("profiles", &self.profiles)
            .field("routing", &self.routing)
            .field("passphrase_from_cli", &self.passphrase_from_cli)
            .field("deprecations", &self.deprecations)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_path: None,
            watch_config: false,
            watch_debounce: DEFAULT_WATCH_DEBOUNCE,
            bind: DEFAULT_BIND,
            http_port: DEFAULT_HTTP_PORT,
            socks_port: DEFAULT_SOCKS_PORT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            tcp_keepalive_idle: KeepaliveSettings::DEFAULT.idle,
            tcp_keepalive_interval: KeepaliveSettings::DEFAULT.interval,
            tcp_keepalive_retries: KeepaliveSettings::DEFAULT.retries,
            allow: Vec::new(),
            block: Vec::new(),
            mitm_ca_cert: None,
            mitm_ca_key: None,
            mitm_ca_p12: None,
            mitm_ca_passphrase: None,
            mitm_ca_passphrase_file: None,
            mitm_cert_ttl: DEFAULT_MITM_CERT_TTL,
            mitm_cert_cache_max: DEFAULT_MITM_CERT_CACHE_MAX_ENTRIES,
            socks_block_web: false,
            log_level: LogLevel::Info,
            log_format: LogFormat::Text,
            http_access_log: None,
            socks_log: None,
            profiles: BTreeMap::new(),
            routing: RoutingConfig::default(),
            passphrase_from_cli: false,
            deprecations: Vec::new(),
        }
    }
}

impl Config {
    /// Load the TOML file named by `--config` (if any) and merge it under the CLI/env input.
    /// Does not validate; call [`Config::validate`] afterwards.
    pub fn from_cli(cli: CliInput) -> Result<Self, ConfigError> {
        let file = match &cli.args.config {
            Some(path) => Some(FileConfig::load(path)?),
            None => None,
        };
        Self::merge(cli, file)
    }

    /// Merge CLI/env input over an optional file config over defaults. Does not validate.
    pub fn merge(cli: CliInput, file: Option<FileConfig>) -> Result<Self, ConfigError> {
        let file = file.unwrap_or_default();
        let d = Config::default();
        let a = cli.args;

        let file_ttl = file_duration("mitm.cert_ttl", file.mitm.cert_ttl.as_deref())?;
        let (file_idle, table_interval, table_retries, used_keepalive_table) =
            match file.tcp_keepalive {
                Some(FileKeepaliveField::Idle(s)) => {
                    (file_duration("tcp_keepalive", Some(&s))?, None, None, false)
                }
                Some(FileKeepaliveField::Table(t)) => (
                    file_duration("tcp_keepalive.idle", t.idle.as_deref())?,
                    t.interval,
                    t.retries,
                    true,
                ),
                None => (None, None, None, false),
            };
        let file_interval = match file.tcp_keepalive_interval.as_deref() {
            Some(s) => file_duration("tcp_keepalive_interval", Some(s))?,
            None => file_duration("tcp_keepalive.interval", table_interval.as_deref())?,
        };
        let file_retries = file.tcp_keepalive_retries.or(table_retries);
        let file_connect = file_duration("connect_timeout", file.connect_timeout.as_deref())?;
        let file_debounce = file_duration("watch_debounce", file.watch_debounce.as_deref())?;
        let file_level = file_parsed::<LogLevel>("logging.level", file.logging.level.as_deref())?;
        let file_format =
            file_parsed::<LogFormat>("logging.format", file.logging.format.as_deref())?;

        let socks_block_web = if cli.socks_block_web_explicit {
            cli.socks_block_web_value
        } else {
            file.socks_block_web.unwrap_or(d.socks_block_web)
        };
        let watch_config = if cli.watch_config_explicit {
            a.watch_config
        } else {
            file.watch_config.unwrap_or(d.watch_config)
        };
        let used_filter_table = file.filter.allow.is_some() || file.filter.block.is_some();
        let file_allow = match file.allow {
            Some(v) => file_filter_rules("allow", Some(v))?,
            None => file_filter_rules("filter.allow", file.filter.allow)?,
        };
        let file_block = match file.block {
            Some(v) => file_filter_rules("block", Some(v))?,
            None => file_filter_rules("filter.block", file.filter.block)?,
        };
        let allow = if a.allow.is_empty() {
            file_allow
        } else {
            a.allow
        };
        let block = if a.block.is_empty() {
            file_block
        } else {
            a.block
        };
        let mut deprecations = cli.deprecated;
        if used_keepalive_table {
            deprecations.push(
                "NOTICE: TOML [tcp_keepalive] table is deprecated; use top-level tcp_keepalive, tcp_keepalive_interval, tcp_keepalive_retries"
                    .to_string(),
            );
        }
        if used_filter_table {
            deprecations.push(
                "NOTICE: TOML [filter] table is deprecated; use top-level allow and block"
                    .to_string(),
            );
        }
        if file.mitm.cert_cache_max.is_some() {
            deprecations.push(
                "NOTICE: TOML mitm.cert_cache_max is deprecated; use mitm.cert_cache_max_entries"
                    .to_string(),
            );
        }

        Ok(Config {
            config_path: a.config,
            watch_config,
            watch_debounce: a
                .watch_debounce
                .or(file_debounce)
                .unwrap_or(d.watch_debounce),
            bind: a.bind.or(file.bind).unwrap_or(d.bind),
            http_port: a.http_port.or(file.http_port).unwrap_or(d.http_port),
            socks_port: a.socks_port.or(file.socks_port).unwrap_or(d.socks_port),
            connect_timeout: a
                .connect_timeout
                .or(file_connect)
                .unwrap_or(d.connect_timeout),
            max_connections: a
                .max_connections
                .or(file.max_connections)
                .unwrap_or(d.max_connections),
            tcp_keepalive_idle: a
                .tcp_keepalive
                .or(file_idle)
                .unwrap_or(d.tcp_keepalive_idle),
            tcp_keepalive_interval: a
                .tcp_keepalive_interval
                .or(file_interval)
                .unwrap_or(d.tcp_keepalive_interval),
            tcp_keepalive_retries: a
                .tcp_keepalive_retries
                .or(file_retries)
                .unwrap_or(d.tcp_keepalive_retries),
            allow,
            block,
            mitm_ca_cert: a.mitm_ca_cert.or(file.mitm.ca_cert),
            mitm_ca_key: a.mitm_ca_key.or(file.mitm.ca_key),
            mitm_ca_p12: a.mitm_ca_p12.or(file.mitm.ca_p12),
            mitm_ca_passphrase: a.mitm_ca_passphrase.or(file.mitm.ca_passphrase),
            mitm_ca_passphrase_file: a.mitm_ca_passphrase_file.or(file.mitm.ca_passphrase_file),
            mitm_cert_ttl: a.mitm_cert_ttl.or(file_ttl).unwrap_or(d.mitm_cert_ttl),
            mitm_cert_cache_max: a
                .mitm_cert_cache_max_entries
                .or(file.mitm.cert_cache_max_entries)
                .or(file.mitm.cert_cache_max)
                .unwrap_or(d.mitm_cert_cache_max),
            socks_block_web,
            log_level: a.log_level.or(file_level).unwrap_or(d.log_level),
            log_format: a.log_format.or(file_format).unwrap_or(d.log_format),
            http_access_log: a.http_access_log.or(file.logging.http_access_log),
            socks_log: a.socks_log.or(file.logging.socks_log),
            profiles: file.profiles,
            routing: file.routing,
            passphrase_from_cli: cli.passphrase_from_cli,
            deprecations,
        })
    }

    /// Apply the `FATAL` startup validation rules (also used to reject a hot-reload).
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_with(&self.routing_input())
    }

    /// [`Self::validate`] against an already-built [`Self::routing_input`], so callers that
    /// also compile it (hot-reload) build it only once.
    pub fn validate_with(&self, input: &RoutingInput) -> Result<(), ConfigError> {
        if self.http_port == 0 && self.socks_port == 0 {
            return Err(ConfigError::NoListeners);
        }
        if self.mitm_ca_p12.is_some() && (self.mitm_ca_cert.is_some() || self.mitm_ca_key.is_some())
        {
            return Err(ConfigError::AmbiguousCaSource);
        }
        if self.mitm_ca_cert.is_some() != self.mitm_ca_key.is_some() {
            return Err(ConfigError::IncompletePemCa);
        }
        if self.mitm_ca_passphrase.is_some() && self.mitm_ca_passphrase_file.is_some() {
            return Err(ConfigError::ConflictingPassphrase);
        }
        if self.mitm_cert_ttl < MIN_MITM_CERT_TTL {
            return Err(ConfigError::CertTtlTooShort(self.mitm_cert_ttl));
        }
        if self.connect_timeout.is_zero() {
            return Err(ConfigError::ZeroConnectTimeout);
        }
        self.validate_keepalive()?;
        // The routing model (profile shapes, password sources, profile references, self-loops
        // against the active listeners, and every rule/bypass/composite profile) is validated by
        // the engine exactly as it is compiled, so delegate there and map its errors onto
        // `ConfigError` with identical messages.
        input.validate().map_err(ConfigError::from)
    }

    /// Everything the engine needs to validate and compile the routing model, built from this
    /// merged configuration: declared profiles, the `[routing]` table, the global filter, MITM
    /// state, the active listener addresses (for self-loop detection), and upstream timeouts.
    pub fn routing_input(&self) -> RoutingInput {
        RoutingInput {
            profiles: self.profiles.clone(),
            routing: self.routing.clone(),
            filter: self.host_filter(),
            mitm_enabled: self.mitm_enabled(),
            listeners: self
                .active_ports()
                .into_iter()
                .map(|port| SocketAddr::new(self.bind, port))
                .collect(),
            keepalive: self.tcp_keepalive_settings(),
            connect_timeout: self.connect_timeout,
        }
    }

    /// MITM settings, independent of how this configuration was loaded.
    pub fn mitm_options(&self) -> MitmOptions {
        MitmOptions {
            ca: self.ca_source(),
            passphrase: self.mitm_ca_passphrase.clone(),
            passphrase_file: self.mitm_ca_passphrase_file.clone(),
            cert_ttl: self.mitm_cert_ttl,
            cert_cache_max: self.mitm_cert_cache_max,
        }
    }

    /// Listener settings, independent of how this configuration was loaded.
    pub fn server_options(&self) -> ServerOptions {
        ServerOptions {
            bind: self.bind,
            http_port: self.http_port,
            socks_port: self.socks_port,
            max_connections: self.max_connections,
            keepalive: self.tcp_keepalive_settings(),
        }
    }

    fn validate_keepalive(&self) -> Result<(), ConfigError> {
        if self.tcp_keepalive_idle.is_zero() {
            return Ok(());
        }
        let secs = Duration::from_secs(1)..=MAX_TCP_KEEPALIVE_DURATION;
        let fmt = |d: Duration| humantime::format_duration(d).to_string();
        if !secs.contains(&self.tcp_keepalive_idle) {
            return Err(ConfigError::InvalidKeepalive(format!(
                "--tcp-keepalive must be 0s (disabled) or between 1s and {}s (got {})",
                MAX_TCP_KEEPALIVE_DURATION.as_secs(),
                fmt(self.tcp_keepalive_idle)
            )));
        }
        if !secs.contains(&self.tcp_keepalive_interval) {
            return Err(ConfigError::InvalidKeepalive(format!(
                "--tcp-keepalive-interval must be between 1s and {}s (got {})",
                MAX_TCP_KEEPALIVE_DURATION.as_secs(),
                fmt(self.tcp_keepalive_interval)
            )));
        }
        if !(1..=MAX_TCP_KEEPALIVE_RETRIES).contains(&self.tcp_keepalive_retries) {
            return Err(ConfigError::InvalidKeepalive(format!(
                "--tcp-keepalive-retries must be between 1 and {MAX_TCP_KEEPALIVE_RETRIES} (got {})",
                self.tcp_keepalive_retries
            )));
        }
        Ok(())
    }

    /// Whether `name` is a declared or built-in profile.
    pub fn has_profile(&self, name: &str) -> bool {
        name == PROFILE_DIRECT || name == PROFILE_BLOCK || self.profiles.contains_key(name)
    }

    /// Declared profiles plus the built-in `direct` and `block` profiles (unless redeclared).
    pub fn profiles_with_builtins(&self) -> BTreeMap<String, ProfileConfig> {
        let mut all = self.profiles.clone();
        for (name, kind) in [
            (PROFILE_DIRECT, ProfileType::Direct),
            (PROFILE_BLOCK, ProfileType::Block),
        ] {
            all.entry(name.to_string())
                .or_insert_with(|| ProfileConfig::of_kind(kind));
        }
        all
    }

    /// Ports of the listeners this configuration enables.
    pub fn active_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = [self.http_port, self.socks_port]
            .into_iter()
            .filter(|p| *p > 0)
            .collect();
        ports.dedup();
        ports
    }

    /// The configured TCP keepalive parameters, or `None` when keepalive is disabled.
    pub fn tcp_keepalive_settings(&self) -> Option<KeepaliveSettings> {
        (!self.tcp_keepalive_idle.is_zero()).then_some(KeepaliveSettings {
            idle: self.tcp_keepalive_idle,
            interval: self.tcp_keepalive_interval,
            retries: self.tcp_keepalive_retries,
        })
    }

    /// The configured global destination filter, or `None` when unfiltered.
    pub fn host_filter(&self) -> Option<HostFilter> {
        HostFilter::from_lists(self.allow.clone(), self.block.clone())
    }

    /// The configured MITM CA source, or `None` when MITM mode is OFF.
    pub fn ca_source(&self) -> Option<CaSource> {
        match (&self.mitm_ca_p12, &self.mitm_ca_cert, &self.mitm_ca_key) {
            (Some(path), None, None) => Some(CaSource::Pkcs12 { path: path.clone() }),
            (None, Some(cert), Some(key)) => Some(CaSource::Pem {
                cert: cert.clone(),
                key: key.clone(),
            }),
            _ => None,
        }
    }

    /// Whether HTTPS MITM inspection is enabled (a complete CA source is configured).
    pub fn mitm_enabled(&self) -> bool {
        self.ca_source().is_some()
    }

    /// Whether both listeners share one port (single-port first-byte multiplexing).
    pub fn is_multiplexed(&self) -> bool {
        self.http_port > 0 && self.http_port == self.socks_port
    }

    /// Whether the bind address is reachable beyond the local host.
    pub fn is_non_loopback_bind(&self) -> bool {
        !self.bind.is_loopback()
    }

    /// Startup `INFO` notices (security and configuration hints), in display order.
    pub fn notices(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.is_non_loopback_bind() {
            out.push(format!(
                "SECURITY NOTICE: binding to non-loopback address {}; rusty-conduit-switch has \
                 NO inbound authentication, so anyone who can reach this address can use the proxy",
                self.bind
            ));
        }
        if self.passphrase_from_cli {
            out.push(
                "NOTICE: --mitm-ca-passphrase was passed on the command line, where it may be \
                 visible to other users and shell history; prefer \
                 RUSTY_CONDUIT_SWITCH_MITM_CA_PASSPHRASE or --mitm-ca-passphrase-file"
                    .to_string(),
            );
        }
        if self.watch_config && self.config_path.is_none() {
            out.push(
                "NOTICE: --watch-config has no effect without --config (nothing to watch)"
                    .to_string(),
            );
        }
        out.extend(self.deprecations.iter().cloned());
        out
    }

    /// One-line configuration summary for the startup banner (never includes secrets).
    pub fn summary(&self) -> String {
        fn port(p: u16) -> String {
            if p == 0 {
                "disabled".to_string()
            } else {
                p.to_string()
            }
        }
        fn path(p: &Option<PathBuf>) -> String {
            p.as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "none".to_string())
        }
        fn cap(n: usize) -> String {
            if n == 0 {
                "unlimited".to_string()
            } else {
                n.to_string()
            }
        }
        let mitm = match self.ca_source() {
            Some(CaSource::Pem { .. }) => "on(pem)",
            Some(CaSource::Pkcs12 { .. }) => "on(pkcs12)",
            None => "off",
        };
        let keepalive = match self.tcp_keepalive_settings() {
            Some(ka) => format!(
                "{}/{}x{}",
                humantime::format_duration(ka.idle),
                humantime::format_duration(ka.interval),
                ka.retries
            ),
            None => "off".to_string(),
        };
        let filter = self
            .host_filter()
            .map(|f| format!(" filter={}({})", f.mode_str(), f.len()))
            .unwrap_or_default();
        format!(
            "bind={} http_port={} socks_port={} multiplexed={} max_connections={} \
             connect_timeout={} tcp_keepalive={keepalive} mitm={mitm} mitm_cert_ttl={} \
             mitm_cert_cache_max_entries={} socks_block_web={} log_level={} log_format={} \
             http_access_log={} socks_log={} profiles={} rules={} watch_config={} config={}{filter}",
            self.bind,
            port(self.http_port),
            port(self.socks_port),
            self.is_multiplexed(),
            cap(self.max_connections),
            humantime::format_duration(self.connect_timeout),
            humantime::format_duration(self.mitm_cert_ttl),
            cap(self.mitm_cert_cache_max),
            self.socks_block_web,
            self.log_level,
            self.log_format,
            path(&self.http_access_log),
            path(&self.socks_log),
            self.profiles_with_builtins().len(),
            self.routing.rule_count(),
            self.watch_config,
            path(&self.config_path),
        )
    }
}

fn file_duration(key: &'static str, raw: Option<&str>) -> Result<Option<Duration>, ConfigError> {
    raw.map(|s| {
        humantime::parse_duration(s).map_err(|e| ConfigError::InvalidFileValue {
            key,
            message: format!("{s:?}: {e}"),
        })
    })
    .transpose()
}

fn file_parsed<T>(key: &'static str, raw: Option<&str>) -> Result<Option<T>, ConfigError>
where
    T: std::str::FromStr<Err = String>,
{
    raw.map(|s| {
        s.parse::<T>()
            .map_err(|message| ConfigError::InvalidFileValue { key, message })
    })
    .transpose()
}

fn file_filter_rules(
    key: &'static str,
    raw: Option<Vec<String>>,
) -> Result<Vec<FilterRule>, ConfigError> {
    let Some(entries) = raw else {
        return Ok(Vec::new());
    };
    entries
        .into_iter()
        .map(|s| {
            s.parse::<FilterRule>()
                .map_err(|message| ConfigError::InvalidFileValue { key, message })
        })
        .collect()
}

/// Serializes tests (across modules) that read or mutate process environment variables.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::MutexGuard;

    /// Holds the env lock and restores a clean `RUSTY_CONDUIT_SWITCH_*` environment on drop.
    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
    }

    fn clear_env() {
        for (k, _) in std::env::vars() {
            if k.starts_with("RUSTY_CONDUIT_SWITCH_") || k.starts_with("RCS_TEST_") {
                std::env::remove_var(k);
            }
        }
    }

    impl EnvGuard {
        fn new(vars: &[(&str, &str)]) -> Self {
            let lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            clear_env();
            for (k, v) in vars {
                std::env::set_var(k, v);
            }
            Self { _lock: lock }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            clear_env();
        }
    }

    fn temp_file(contents: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rusty-conduit-switch-config-test-{}-{}.toml",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::write(&path, contents).unwrap();
        path
    }

    fn cli(args: &[&str]) -> CliInput {
        let mut full = vec!["rusty-conduit-switch"];
        full.extend_from_slice(args);
        CliInput::try_parse_from(full).expect("cli parse")
    }

    fn load(args: &[&str]) -> Result<Config, ConfigError> {
        let cfg = Config::from_cli(cli(args))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn from_toml(text: &str) -> Result<Config, ConfigError> {
        let file = FileConfig::from_toml_str(text, Path::new("test.toml"))?;
        let cfg = Config::merge(CliInput::default(), Some(file))?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn defaults_when_nothing_is_set() {
        let _env = EnvGuard::new(&[]);
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.bind, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.http_port, 3128);
        assert_eq!(cfg.socks_port, 1080);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(10));
        assert_eq!(cfg.watch_debounce, Duration::from_millis(300));
        assert_eq!(cfg.max_connections, 4096);
        assert_eq!(cfg.mitm_cert_ttl, Duration::from_secs(3600));
        assert_eq!(cfg.mitm_cert_cache_max, 10_240);
        assert_eq!(
            cfg.tcp_keepalive_settings(),
            Some(KeepaliveSettings::DEFAULT)
        );
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert_eq!(cfg.log_format, LogFormat::Text);
        assert!(!cfg.watch_config);
        assert!(!cfg.mitm_enabled());
        assert!(!cfg.is_multiplexed());
        assert!(cfg.notices().is_empty());
        assert_eq!(cfg.routing.default, OneOrMany::One("direct".into()));
        assert!(cli(&[]).args.command.is_none());
    }

    const FULL_TOML: &str = r#"
bind = "10.0.0.1"
http_port = 1111
socks_port = 2222
watch_config = true
watch_debounce = "1s"
connect_timeout = "5s"
max_connections = 77

socks_block_web = true

[tcp_keepalive]
idle = "30s"
interval = "3s"
retries = 4

[filter]
block = ["*.ads.example", "10.9.0.0/16"]

[mitm]
ca_p12 = "/file/ca.p12"
ca_passphrase_file = "/file/pass"
cert_ttl = "30m"
cert_cache_max = 99

[logging]
level = "debug"
format = "json"
http_access_log = "/file/http.log"
socks_log = "/file/socks.log"
"#;

    #[test]
    fn toml_overrides_defaults() {
        let _env = EnvGuard::new(&[]);
        let path = temp_file(FULL_TOML);
        let cfg = load(&["--config", path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.bind, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.http_port, 1111);
        assert_eq!(cfg.socks_port, 2222);
        assert!(cfg.watch_config);
        assert_eq!(cfg.watch_debounce, Duration::from_secs(1));
        assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
        assert_eq!(cfg.max_connections, 77);
        assert_eq!(
            cfg.tcp_keepalive_settings(),
            Some(KeepaliveSettings {
                idle: Duration::from_secs(30),
                interval: Duration::from_secs(3),
                retries: 4
            })
        );
        assert_eq!(cfg.block.len(), 2);
        assert_eq!(cfg.host_filter().unwrap().mode_str(), "block");
        assert_eq!(cfg.mitm_ca_p12, Some(PathBuf::from("/file/ca.p12")));
        assert_eq!(cfg.mitm_cert_ttl, Duration::from_secs(1800));
        assert_eq!(cfg.mitm_cert_cache_max, 99);
        assert!(cfg.socks_block_web);
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert_eq!(cfg.http_access_log, Some(PathBuf::from("/file/http.log")));
        assert_eq!(cfg.socks_log, Some(PathBuf::from("/file/socks.log")));
        fs::remove_file(path).ok();
    }

    #[test]
    fn flat_and_deprecated_toml_keys() {
        let _env = EnvGuard::new(&[]);

        // (a) flat form
        let flat = from_toml(
            "tcp_keepalive = \"30s\"\n\
             tcp_keepalive_interval = \"5s\"\n\
             tcp_keepalive_retries = 2\n\
             allow = [\"*.ok.example\"]\n\
             [mitm]\n\
             cert_cache_max_entries = 11\n",
        )
        .unwrap();
        assert_eq!(
            flat.tcp_keepalive_settings(),
            Some(KeepaliveSettings {
                idle: Duration::from_secs(30),
                interval: Duration::from_secs(5),
                retries: 2,
            })
        );
        assert_eq!(flat.host_filter().unwrap().mode_str(), "allow");
        assert_eq!(flat.mitm_cert_cache_max, 11);
        assert!(flat.notices().is_empty());

        // (b) old table form yields the same values plus the three NOTICEs
        let legacy = from_toml(
            "[tcp_keepalive]\n\
             idle = \"30s\"\n\
             interval = \"5s\"\n\
             retries = 2\n\
             [filter]\n\
             allow = [\"*.ok.example\"]\n\
             [mitm]\n\
             cert_cache_max = 11\n",
        )
        .unwrap();
        assert_eq!(
            legacy.tcp_keepalive_settings(),
            flat.tcp_keepalive_settings()
        );
        assert_eq!(legacy.host_filter().unwrap().mode_str(), "allow");
        assert_eq!(legacy.mitm_cert_cache_max, 11);
        let notices = legacy.notices();
        assert!(notices.iter().any(|n| n == "NOTICE: TOML [tcp_keepalive] table is deprecated; use top-level tcp_keepalive, tcp_keepalive_interval, tcp_keepalive_retries"));
        assert!(notices.iter().any(
            |n| n == "NOTICE: TOML [filter] table is deprecated; use top-level allow and block"
        ));
        assert!(notices.iter().any(|n| n
            == "NOTICE: TOML mitm.cert_cache_max is deprecated; use mitm.cert_cache_max_entries"));

        // (c) flat tcp_keepalive + tcp_keepalive_interval without [filter]
        let flat_ka = from_toml(
            "tcp_keepalive = \"30s\"\n\
             tcp_keepalive_interval = \"7s\"\n",
        )
        .unwrap();
        assert_eq!(flat_ka.tcp_keepalive_idle, Duration::from_secs(30));
        assert_eq!(flat_ka.tcp_keepalive_interval, Duration::from_secs(7));
        assert!(flat_ka.notices().is_empty());

        // (d) tcp_keepalive = "x" errors with a message naming tcp_keepalive
        let err = from_toml("tcp_keepalive = \"x\"\n").unwrap_err();
        assert!(
            matches!(
                &err,
                ConfigError::InvalidFileValue {
                    key: "tcp_keepalive",
                    ..
                }
            ),
            "{err}"
        );
        assert!(err.to_string().contains("tcp_keepalive"), "{err}");

        let err = FileConfig::from_toml_str(
            "[tcp_keepalive]\nidle = \"1m\"\nbogus = 1\n",
            Path::new("x.toml"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");

        let err =
            FileConfig::from_toml_str("tcp_keepalive = 5\n", Path::new("x.toml")).unwrap_err();
        assert!(
            err.to_string().contains("expected a duration string"),
            "{err}"
        );
    }

    #[test]
    fn env_overrides_toml() {
        let path = temp_file(FULL_TOML);
        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SWITCH_CONFIG", path.to_str().unwrap()),
            ("RUSTY_CONDUIT_SWITCH_BIND", "::1"),
            ("RUSTY_CONDUIT_SWITCH_HTTP_PORT", "3333"),
            ("RUSTY_CONDUIT_SWITCH_SOCKS_PORT", "4444"),
            ("RUSTY_CONDUIT_SWITCH_WATCH_CONFIG", "false"),
            ("RUSTY_CONDUIT_SWITCH_CONNECT_TIMEOUT", "7s"),
            ("RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_IDLE", "0s"),
            ("RUSTY_CONDUIT_SWITCH_MITM_CERT_TTL", "2h"),
            ("RUSTY_CONDUIT_SWITCH_SOCKS_BLOCK_WEB", "false"),
            ("RUSTY_CONDUIT_SWITCH_LOG_LEVEL", "VERBOSE"),
            ("RUSTY_CONDUIT_SWITCH_BLOCK", "evil.example,10.0.0.0/8"),
        ]);
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.config_path, Some(path.clone()));
        assert_eq!(cfg.bind, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.http_port, 3333);
        assert_eq!(cfg.socks_port, 4444);
        assert!(!cfg.watch_config, "env false overrides toml true");
        assert_eq!(cfg.connect_timeout, Duration::from_secs(7));
        assert_eq!(cfg.tcp_keepalive_settings(), None);
        assert_eq!(cfg.mitm_cert_ttl, Duration::from_secs(7200));
        assert!(!cfg.socks_block_web);
        assert_eq!(cfg.log_level, LogLevel::Verbose);
        assert_eq!(
            cfg.block
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["evil.example", "10.0.0.0/8"]
        );
        // Not set in env: falls through to TOML.
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert_eq!(cfg.max_connections, 77);
        fs::remove_file(path).ok();
    }

    #[test]
    fn deprecated_cli_aliases_and_precedence() {
        let _env = EnvGuard::new(&[]);

        // (a) --tcp-keepalive-idle 0s sets tcp_keepalive_idle to zero and emits deprecation NOTICE
        let cfg = load(&["--tcp-keepalive-idle", "0s"]).unwrap();
        assert!(cfg.tcp_keepalive_idle.is_zero());
        assert!(cfg.notices().iter().any(|n| n == "NOTICE: --tcp-keepalive-idle / RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE_IDLE is deprecated; use --tcp-keepalive / RUSTY_CONDUIT_SWITCH_TCP_KEEPALIVE"));

        // (b) --mitm-cert-cache-max 7 sets mitm_cert_cache_max == 7 and emits deprecation NOTICE
        let cfg = load(&["--mitm-cert-cache-max", "7"]).unwrap();
        assert_eq!(cfg.mitm_cert_cache_max, 7);
        assert!(cfg.notices().iter().any(|n| n == "NOTICE: --mitm-cert-cache-max / RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX is deprecated; use --mitm-cert-cache-max-entries / RUSTY_CONDUIT_SWITCH_MITM_CERT_CACHE_MAX_ENTRIES"));

        // (c) --tcp-keepalive 30s --tcp-keepalive-idle 5s keeps 30s
        let cfg = load(&["--tcp-keepalive", "30s", "--tcp-keepalive-idle", "5s"]).unwrap();
        assert_eq!(cfg.tcp_keepalive_idle, Duration::from_secs(30));

        // (d) --tcp-keepalive 0s produces no deprecation NOTICE
        let cfg = load(&["--tcp-keepalive", "0s"]).unwrap();
        assert!(cfg.tcp_keepalive_idle.is_zero());
        assert!(cfg.notices().is_empty());
    }

    #[test]
    fn cli_overrides_env_and_toml() {
        let path = temp_file(FULL_TOML);
        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SWITCH_CONFIG", path.to_str().unwrap()),
            ("RUSTY_CONDUIT_SWITCH_BIND", "::1"),
            ("RUSTY_CONDUIT_SWITCH_HTTP_PORT", "3333"),
            ("RUSTY_CONDUIT_SWITCH_LOG_LEVEL", "VERBOSE"),
            ("RUSTY_CONDUIT_SWITCH_CONNECT_TIMEOUT", "7s"),
        ]);
        let cfg = load(&[
            "--bind",
            "127.0.0.2",
            "--http-port",
            "5555",
            "--socks-port",
            "6666",
            "--log-level",
            "error",
            "--connect-timeout",
            "2s",
            "--max-connections",
            "5",
            "--tcp-keepalive-retries",
            "9",
        ])
        .unwrap();
        assert_eq!(cfg.bind, "127.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.http_port, 5555);
        assert_eq!(cfg.socks_port, 6666);
        assert_eq!(cfg.log_level, LogLevel::Error);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(2));
        assert_eq!(cfg.max_connections, 5);
        assert_eq!(cfg.tcp_keepalive_retries, 9);
        // Not on CLI or env: from TOML.
        assert_eq!(cfg.socks_log, Some(PathBuf::from("/file/socks.log")));
        fs::remove_file(path).ok();
    }

    #[test]
    fn cli_config_path_overrides_env_config_path() {
        let env_path = temp_file("http_port = 1\n");
        let cli_path = temp_file("http_port = 2\n");
        let _env = EnvGuard::new(&[("RUSTY_CONDUIT_SWITCH_CONFIG", env_path.to_str().unwrap())]);
        let cfg = load(&["--config", cli_path.to_str().unwrap()]).unwrap();
        assert_eq!(cfg.http_port, 2);
        fs::remove_file(env_path).ok();
        fs::remove_file(cli_path).ok();
    }

    #[test]
    fn boolean_flags_override_toml_only_when_explicit() {
        let _env = EnvGuard::new(&[]);
        let file = FileConfig {
            watch_config: Some(true),
            socks_block_web: Some(true),
            ..Default::default()
        };
        let c = cli(&[]);
        assert!(!c.watch_config_explicit && !c.socks_block_web_explicit);
        let cfg = Config::merge(c, Some(file.clone())).unwrap();
        assert!(cfg.watch_config && cfg.socks_block_web);

        let c = cli(&["--watch-config", "--socks-block-web"]);
        assert!(c.watch_config_explicit && c.socks_block_web_explicit);
        drop(_env);

        let _env = EnvGuard::new(&[
            ("RUSTY_CONDUIT_SWITCH_WATCH_CONFIG", "0"),
            ("RUSTY_CONDUIT_SWITCH_SOCKS_BLOCK_WEB", "no"),
        ]);
        let cfg = Config::merge(cli(&[]), Some(file)).unwrap();
        assert!(!cfg.watch_config && !cfg.socks_block_web);
    }

    #[test]
    fn invalid_cli_values_are_rejected() {
        let _env = EnvGuard::new(&[]);
        for args in [
            &["x", "--log-level", "loud"][..],
            &["x", "--log-format", "xml"][..],
            &["x", "--bind", "not-an-ip"][..],
            &["x", "--http-port", "70000"][..],
            &["x", "--connect-timeout", "soon"][..],
            &["x", "--allow", "not a rule!"][..],
            &["x", "test-route"][..],
            &["x", "test-route", "--inbound", "ftp", "a.example"][..],
            &["x", "import-airswitch"][..],
            &["x", "bogus-subcommand"][..],
            &["x", "--socks-block-web-in-mitm"][..],
        ] {
            assert!(CliInput::try_parse_from(args).is_err(), "{args:?}");
        }
    }

    // ---- Subcommands ----

    #[test]
    fn subcommand_validate() {
        let _env = EnvGuard::new(&[]);
        let c = cli(&["validate", "--config", "/etc/rcs.toml"]);
        assert_eq!(c.args.command, Some(Command::Validate));
        assert_eq!(c.args.config, Some(PathBuf::from("/etc/rcs.toml")));
        // --config is global: may also precede the subcommand.
        let c = cli(&["--config", "/a.toml", "validate"]);
        assert_eq!(c.args.command, Some(Command::Validate));
        assert_eq!(c.args.config, Some(PathBuf::from("/a.toml")));
    }

    #[test]
    fn subcommand_test_route() {
        let _env = EnvGuard::new(&[]);
        let c = cli(&[
            "test-route",
            "--config",
            "c.toml",
            "--inbound",
            "socks",
            "db.internal:5432",
        ]);
        assert_eq!(
            c.args.command,
            Some(Command::TestRoute {
                inbound: Inbound::Socks,
                target: "db.internal:5432".into()
            })
        );
        assert_eq!(c.args.config, Some(PathBuf::from("c.toml")));
        let c = cli(&["test-route", "https://example.com/a?b"]);
        assert_eq!(
            c.args.command,
            Some(Command::TestRoute {
                inbound: Inbound::Http,
                target: "https://example.com/a?b".into()
            })
        );
    }

    #[test]
    fn subcommand_import_airswitch() {
        let _env = EnvGuard::new(&[]);
        let c = cli(&[
            "import-airswitch",
            "OmegaOptions.bak",
            "-o",
            "out.toml",
            "--profile",
            "auto switch",
        ]);
        assert_eq!(
            c.args.command,
            Some(Command::ImportAirswitch {
                bak_path: "OmegaOptions.bak".into(),
                output: Some("out.toml".into()),
                profile: Some("auto switch".into()),
                force: false,
            })
        );
        let c = cli(&["import-airswitch", "a.bak", "--output", "o.toml", "--force"]);
        assert!(matches!(
            c.args.command,
            Some(Command::ImportAirswitch {
                force: true,
                output: Some(_),
                profile: None,
                ..
            })
        ));
    }

    // ---- Profiles, routing, credentials ----

    const ROUTING_TOML: &str = r#"
[profiles.corp]
type = "http"
host = "10.0.0.2"
port = 3128
username = "alice"
password_env = "RCS_TEST_CORP_PASS"
bypass = ["127.0.0.1", "::1", "localhost", "*.local"]

[profiles.bastion]
type = "socks5"
host = "127.0.0.1"
port = 1081

[profiles.secure_gw]
type = "https"
host = "proxy.example.com"
port = 8443

[profiles.legacy_socks]
type = "socks4a"
host = "10.0.0.5"
port = 1080

[profiles.per_scheme]
type = "fixed"
http_proxy = "corp"
fallback_proxy = "direct"

[routing]
default = "direct"

[[routing.rules]]
name = "rfc1918-to-corp"
cidr = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
target = "corp"

[[routing.rules]]
name = "internal-domains-with-failover"
host_wildcard = ["*.internal.example", "dev-*.corp.net"]
target = ["bastion", "corp"]

[[routing.rules]]
name = "block-telemetry"
host_regex = "^telemetry\\..*\\.example\\.com$"
target = "block"

[[routing.rules]]
name = "ssh-over-bastion"
port = [22, "2200-2299"]
host_levels = { min = 1, max = 3 }
weekday = ["mon", "fri"]
time = "09:00-17:30"
target = "bastion"

[[routing.rules]]
inbound = "socks"
host_wildcard = ["*.db.internal"]
target = "bastion"

[[routing.rules]]
url_wildcard = ["http://downloads.example.com/private/*"]
disabled = true
target = "corp"

[routing.socks]
default = "bastion"

[[routing.socks.rules]]
host_wildcard = ["*.local"]
target = "direct"
"#;

    #[test]
    fn full_routing_schema_parses_and_validates() {
        let _env = EnvGuard::new(&[]);
        let cfg = from_toml(ROUTING_TOML).unwrap();
        assert_eq!(cfg.profiles.len(), 5);
        assert_eq!(cfg.profiles["per_scheme"].kind, ProfileType::Composite);
        assert_eq!(cfg.profiles_with_builtins().len(), 7);
        assert_eq!(cfg.routing.rules.len(), 6);
        assert_eq!(cfg.routing.rule_count(), 7);
        let r = &cfg.routing.rules[1];
        assert_eq!(
            r.target,
            OneOrMany::Many(vec!["bastion".into(), "corp".into()])
        );
        let r = &cfg.routing.rules[3];
        assert_eq!(
            r.port.as_ref().unwrap().as_slice(),
            &[PortSpec::Port(22), PortSpec::Range("2200-2299".into())]
        );
        assert_eq!(
            r.host_levels,
            Some(HostLevels {
                min: Some(1),
                max: Some(3)
            })
        );
        assert_eq!(r.time, Some(OneOrMany::One("09:00-17:30".into())));
        assert_eq!(cfg.routing.rules[4].inbound, Some(Inbound::Socks));
        assert!(cfg.routing.rules[5].disabled);
        assert_eq!(
            cfg.routing.default_for(Inbound::Socks),
            &OneOrMany::One("bastion".into())
        );
        assert_eq!(
            cfg.routing.default_for(Inbound::Http),
            &OneOrMany::One("direct".into())
        );
        assert_eq!(
            cfg.profiles["secure_gw"].redacted_upstream(),
            "https://proxy.example.com:8443"
        );
        assert_eq!(
            cfg.profiles["corp"].redacted_upstream(),
            "http://10.0.0.2:3128"
        );
    }

    #[test]
    fn unknown_fields_and_types_are_rejected() {
        for bad in [
            "[profiles.x]\ntype = \"ftp\"\nhost = \"a\"\nport = 1\n",
            "[profiles.x]\ntype = \"http\"\nhost = \"a\"\nport = 1\nhots = \"typo\"\n",
            "[[routing.rules]]\nhost = \"a\"\ntarget = \"direct\"\nbogus = 1\n",
            "[[routing.rules]]\nhost = \"a\"\n",
            "[[routing.rules]]\ninbound = \"ftp\"\ntarget = \"direct\"\n",
        ] {
            assert!(
                matches!(from_toml(bad), Err(ConfigError::ParseFile { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn credential_sources_are_mutually_exclusive() {
        let _env = EnvGuard::new(&[]);
        for (a, b) in [
            ("password = \"p\"", "password_env = \"E\""),
            ("password = \"p\"", "password_file = \"/f\""),
            ("password_env = \"E\"", "password_file = \"/f\""),
        ] {
            let toml = format!(
                "[profiles.corp]\ntype = \"http\"\nhost = \"10.0.0.2\"\nport = 3128\n\
                 username = \"u\"\n{a}\n{b}\n"
            );
            let err = from_toml(&toml).unwrap_err();
            assert!(
                matches!(&err, ConfigError::AmbiguousPassword { profile } if profile == "corp"),
                "{err}"
            );
            assert!(!err.to_string().contains("\"p\""));
        }
        // A single source is fine.
        from_toml(
            "[profiles.corp]\ntype = \"socks5\"\nhost = \"h\"\nport = 1\nusername = \"u\"\npassword = \"p\"\n",
        )
        .unwrap();
    }

    #[test]
    fn credential_resolution_from_each_source() {
        let _env = EnvGuard::new(&[("RCS_TEST_CORP_PASS", "from-env")]);
        let mut p = ProfileConfig::of_kind(ProfileType::Http);
        assert_eq!(p.resolve_password("p").unwrap(), None);
        p.password = Some("inline".into());
        assert_eq!(p.resolve_password("p").unwrap().as_deref(), Some("inline"));
        assert!(!format!("{p:?}").contains("inline"), "Debug must redact");
        p.password = None;
        p.password_env = Some("RCS_TEST_CORP_PASS".into());
        assert_eq!(
            p.resolve_password("p").unwrap().as_deref(),
            Some("from-env")
        );
        p.password_env = Some("RCS_TEST_MISSING".into());
        assert!(matches!(
            p.resolve_password("p"),
            Err(RoutingError::ResolvePassword { .. })
        ));
        p.password_env = None;
        let path = temp_file("from-file\r\n");
        p.password_file = Some(path.clone());
        assert_eq!(
            p.resolve_password("p").unwrap().as_deref(),
            Some("from-file")
        );
        p.password = Some("x".into());
        assert!(matches!(
            p.resolve_password("p"),
            Err(RoutingError::AmbiguousPassword { .. })
        ));
        fs::remove_file(path).ok();
    }

    #[test]
    fn builtin_profiles_and_references() {
        let _env = EnvGuard::new(&[]);
        // Built-ins need no declaration.
        let cfg = from_toml("[routing]\ndefault = [\"block\", \"direct\"]\n").unwrap();
        assert!(cfg.has_profile("direct") && cfg.has_profile("block"));
        assert_eq!(
            cfg.profiles_with_builtins()["block"].kind,
            ProfileType::Block
        );
        // Re-declaring a built-in with its own type is fine; another type is not.
        from_toml("[profiles.direct]\ntype = \"direct\"\n").unwrap();
        assert!(matches!(
            from_toml("[profiles.direct]\ntype = \"http\"\nhost = \"h\"\nport = 1\n"),
            Err(ConfigError::InvalidProfile { .. })
        ));
        // Unknown references anywhere are rejected.
        for bad in [
            "[routing]\ndefault = \"nope\"\n",
            "[[routing.rules]]\nhost = \"a\"\ntarget = [\"direct\", \"nope\"]\n",
            "[routing.http]\ndefault = \"nope\"\n",
            "[[routing.socks.rules]]\nhost = \"a\"\ntarget = \"nope\"\n",
            "[profiles.c]\ntype = \"composite\"\nfallback_proxy = \"nope\"\n",
        ] {
            assert!(
                matches!(from_toml(bad), Err(ConfigError::UnknownProfile { .. })),
                "{bad}"
            );
        }
        assert!(matches!(
            from_toml("[routing]\ndefault = []\n"),
            Err(ConfigError::EmptyTarget { .. })
        ));
    }

    #[test]
    fn proxy_profiles_require_host_and_port() {
        let _env = EnvGuard::new(&[]);
        for bad in [
            "[profiles.p]\ntype = \"http\"\nport = 1\n",
            "[profiles.p]\ntype = \"socks5\"\nhost = \"\"\nport = 1\n",
            "[profiles.p]\ntype = \"https\"\nhost = \"h\"\n",
            "[profiles.p]\ntype = \"socks4a\"\nhost = \"h\"\nport = 0\n",
            "[profiles.p]\ntype = \"composite\"\n",
        ] {
            assert!(
                matches!(from_toml(bad), Err(ConfigError::InvalidProfile { .. })),
                "{bad}"
            );
        }
    }

    // ---- Self-loop detection ----

    fn loop_check(bind: &str, http: u16, socks: u16, host: &str, port: u16) -> bool {
        let toml = format!(
            "bind = \"{bind}\"\nhttp_port = {http}\nsocks_port = {socks}\n\
             [profiles.up]\ntype = \"socks5\"\nhost = \"{host}\"\nport = {port}\n"
        );
        match from_toml(&toml) {
            Ok(_) => false,
            Err(ConfigError::SelfLoop { profile, .. }) => {
                assert_eq!(profile, "up");
                true
            }
            Err(e) => panic!("unexpected error {e}"),
        }
    }

    #[test]
    fn self_loop_rejected() {
        let _env = EnvGuard::new(&[]);
        // Same bind address and listener port.
        assert!(loop_check("127.0.0.1", 3128, 1080, "127.0.0.1", 1080));
        assert!(loop_check("127.0.0.1", 3128, 1080, "127.0.0.1", 3128));
        assert!(loop_check("127.0.0.1", 3128, 1080, "localhost", 3128));
        assert!(loop_check(
            "127.0.0.1",
            3128,
            1080,
            "::ffff:127.0.0.1",
            1080
        ));
        assert!(loop_check("::1", 3128, 1080, "[::1]", 1080));
        assert!(loop_check("10.1.2.3", 8080, 8080, "10.1.2.3", 8080));
        // Unspecified bind: loopback and unspecified upstreams loop too.
        assert!(loop_check("0.0.0.0", 3128, 1080, "127.0.0.1", 3128));
        assert!(loop_check("0.0.0.0", 3128, 1080, "::1", 1080));
        assert!(loop_check("::", 3128, 1080, "localhost", 1080));
        assert!(loop_check("0.0.0.0", 3128, 1080, "0.0.0.0", 1080));
    }

    #[test]
    fn self_loop_not_reported_for_distinct_targets() {
        let _env = EnvGuard::new(&[]);
        // Different port (e.g. an ssh -D listener next to us).
        assert!(!loop_check("127.0.0.1", 3128, 1080, "127.0.0.1", 1081));
        // Disabled listener port is not a loop.
        assert!(!loop_check("127.0.0.1", 3128, 0, "127.0.0.1", 1080));
        // Different address on a specific bind.
        assert!(!loop_check("10.1.2.3", 3128, 1080, "127.0.0.1", 3128));
        assert!(!loop_check("127.0.0.1", 3128, 1080, "10.0.0.2", 3128));
        // Hostnames other than localhost are never resolved.
        assert!(!loop_check(
            "0.0.0.0",
            3128,
            1080,
            "proxy.example.com",
            3128
        ));
    }

    #[test]
    fn self_loop_uses_cli_overridden_listener() {
        let toml = temp_file("[profiles.up]\ntype = \"http\"\nhost = \"127.0.0.1\"\nport = 9999\n");
        let _env = EnvGuard::new(&[]);
        load(&["--config", toml.to_str().unwrap()]).unwrap();
        let err = load(&["--config", toml.to_str().unwrap(), "--http-port", "9999"]).unwrap_err();
        assert!(matches!(err, ConfigError::SelfLoop { .. }), "{err}");
        fs::remove_file(toml).ok();
    }

    // ---- Other FATAL validation rules ----

    #[test]
    fn fatal_rules() {
        let _env = EnvGuard::new(&[]);
        assert!(matches!(
            load(&["--http-port", "0", "--socks-port", "0"]),
            Err(ConfigError::NoListeners)
        ));
        load(&["--http-port", "0"]).unwrap();
        assert!(matches!(
            load(&["--mitm-ca-p12", "a.p12", "--mitm-ca-cert", "c.pem"]),
            Err(ConfigError::AmbiguousCaSource)
        ));
        assert!(matches!(
            load(&["--mitm-ca-cert", "c.pem"]),
            Err(ConfigError::IncompletePemCa)
        ));
        assert!(load(&["--mitm-ca-cert", "c.pem", "--mitm-ca-key", "k.pem"])
            .unwrap()
            .mitm_enabled());
        assert!(matches!(
            load(&[
                "--mitm-ca-passphrase",
                "x",
                "--mitm-ca-passphrase-file",
                "/p"
            ]),
            Err(ConfigError::ConflictingPassphrase)
        ));
        assert!(matches!(
            load(&["--mitm-cert-ttl", "9s"]),
            Err(ConfigError::CertTtlTooShort(_))
        ));
        // Combined allow + block produces BlockExcept
        let cfg = load(&["--allow", "test.domain.net", "--block", "*.domain.net"]).unwrap();
        assert!(matches!(
            cfg.host_filter(),
            Some(HostFilter::BlockExcept { .. })
        ));
        assert!(matches!(
            load(&["--connect-timeout", "0s"]),
            Err(ConfigError::ZeroConnectTimeout)
        ));
        assert!(matches!(
            load(&["--tcp-keepalive-retries", "0"]),
            Err(ConfigError::InvalidKeepalive(_))
        ));
        assert!(matches!(
            load(&["--tcp-keepalive-interval", "0s"]),
            Err(ConfigError::InvalidKeepalive(_))
        ));
        load(&["--tcp-keepalive-idle", "0s", "--tcp-keepalive-retries", "0"]).unwrap();
    }

    #[test]
    fn fatal_bad_config_file() {
        let _env = EnvGuard::new(&[]);
        assert!(matches!(
            load(&["--config", "/definitely/not/here.toml"]),
            Err(ConfigError::ReadFile { .. })
        ));
        for (text, key) in [
            ("[logging]\nlevel = \"loud\"\n", "logging.level"),
            ("[mitm]\ncert_ttl = \"forever\"\n", "mitm.cert_ttl"),
            ("connect_timeout = \"soon\"\n", "connect_timeout"),
            ("[tcp_keepalive]\nidle = \"x\"\n", "tcp_keepalive.idle"),
            ("[filter]\nallow = [\"not a rule!\"]\n", "filter.allow"),
        ] {
            match from_toml(text) {
                Err(ConfigError::InvalidFileValue { key: k, .. }) => assert_eq!(k, key),
                other => panic!("{text}: {other:?}"),
            }
        }
        assert!(matches!(
            from_toml("unknown_key = 1\n"),
            Err(ConfigError::ParseFile { .. })
        ));
    }

    // ---- INFO notices ----

    #[test]
    fn notices() {
        let _env = EnvGuard::new(&[]);
        for bind in ["0.0.0.0", "192.168.1.10", "::"] {
            let cfg = load(&["--bind", bind]).unwrap();
            assert!(
                cfg.notices()[0].contains("NO inbound authentication"),
                "{bind}"
            );
        }
        assert!(load(&["--bind", "::1"]).unwrap().notices().is_empty());
        let cfg = load(&["--mitm-ca-passphrase", "s3cret"]).unwrap();
        assert!(cfg.passphrase_from_cli);
        assert!(!format!("{cfg:?}").contains("s3cret"));
        assert!(!cfg.summary().contains("s3cret"));
        assert!(cfg
            .notices()
            .iter()
            .any(|n| n.contains("--mitm-ca-passphrase")));
        let cfg = load(&["--socks-block-web"]).unwrap();
        assert!(cfg.socks_block_web);
        assert!(cfg.notices().is_empty());
        // The retired `[mitm] socks_block_web` key is an unknown field.
        let err =
            FileConfig::from_toml_str("[mitm]\nsocks_block_web = true\n", Path::new("x.toml"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("socks_block_web"), "{err}");
        let cfg = load(&["--watch-config"]).unwrap();
        assert!(cfg.notices().iter().any(|n| n.contains("--watch-config")));
    }
}
