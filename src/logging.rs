//! 6-level diagnostic logger and HTTP/SOCKS access-log sinks.
//!
//! * Diagnostics ([`Logger`]) go to `stderr`, filtered by [`LogLevel`].
//! * Access records ([`HttpAccessRecord`], [`SocksLogRecord`]) go through the async
//!   [`AccessLogger`] to their configured files (append mode, buffered) and are ALSO dumped
//!   to `stdout` when the level is `DEBUG` or `VERBOSE`.
//!
//! Every access/SOCKS record carries routing visibility: `rule`, `profile`, and a redacted
//! `upstream` (credentials are never emitted; see `docs/MASTER-PLAN.md` Section 9).

use std::fmt;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// Diagnostic verbosity, ordered from least to most verbose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    Quiet,
    Fatal,
    Error,
    Info,
    Debug,
    Verbose,
}

impl LogLevel {
    pub const ALL: [LogLevel; 6] = [
        LogLevel::Quiet,
        LogLevel::Fatal,
        LogLevel::Error,
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::Verbose,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Quiet => "QUIET",
            LogLevel::Fatal => "FATAL",
            LogLevel::Error => "ERROR",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
            LogLevel::Verbose => "VERBOSE",
        }
    }

    /// Whether access/SOCKS records are additionally dumped to `stdout` at this level.
    pub fn dumps_access_to_stdout(self) -> bool {
        self >= LogLevel::Debug
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LogLevel::ALL
            .into_iter()
            .find(|l| l.as_str().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| {
                format!("invalid log level {s:?} (expected QUIET, FATAL, ERROR, INFO, DEBUG, or VERBOSE)")
            })
    }
}

/// Access/SOCKS log record format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogFormat {
    /// Human-readable logfmt (`key=value` pairs).
    Text,
    /// NDJSON: one JSON object per line.
    Json,
}

impl LogFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            LogFormat::Text => "text",
            LogFormat::Json => "json",
        }
    }
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "text" => Ok(LogFormat::Text),
            "json" => Ok(LogFormat::Json),
            _ => Err(format!("invalid log format {s:?} (expected text or json)")),
        }
    }
}

const TS_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

/// RFC 3339 UTC timestamp with millisecond precision, e.g. `2026-11-22T13:30:01.123Z`.
pub fn format_timestamp(ts: OffsetDateTime) -> String {
    ts.to_offset(UtcOffset::UTC)
        .format(TS_FORMAT)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}

// ---------------------------------------------------------------------------
// Diagnostic logger (stderr)
// ---------------------------------------------------------------------------

type SharedWriter = Arc<Mutex<Box<dyn Write + Send>>>;

/// Level-filtered diagnostic logger writing to `stderr` (or an injected writer in tests).
#[derive(Clone)]
pub struct Logger {
    level: LogLevel,
    out: SharedWriter,
}

impl fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logger")
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

impl Logger {
    /// Logger writing diagnostics to `stderr`.
    pub fn stderr(level: LogLevel) -> Self {
        Self::with_writer(level, Box::new(io::stderr()))
    }

    /// Logger writing diagnostics to an arbitrary writer.
    pub fn with_writer(level: LogLevel, out: Box<dyn Write + Send>) -> Self {
        Self {
            level,
            out: Arc::new(Mutex::new(out)),
        }
    }

    pub fn level(&self) -> LogLevel {
        self.level
    }

    /// Whether a message at `level` would be written. `QUIET` messages are never emitted.
    pub fn enabled(&self, level: LogLevel) -> bool {
        level != LogLevel::Quiet && level <= self.level
    }

    /// Write a diagnostic line (`<ts> <LEVEL> <message>`) if `level` is enabled.
    pub fn log(&self, level: LogLevel, msg: impl fmt::Display) {
        if !self.enabled(level) {
            return;
        }
        let line = format!(
            "{} {:<7} {}\n",
            format_timestamp(OffsetDateTime::now_utc()),
            level.as_str(),
            msg
        );
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }

    pub fn fatal(&self, msg: impl fmt::Display) {
        self.log(LogLevel::Fatal, msg);
    }
    pub fn error(&self, msg: impl fmt::Display) {
        self.log(LogLevel::Error, msg);
    }
    pub fn info(&self, msg: impl fmt::Display) {
        self.log(LogLevel::Info, msg);
    }
    pub fn debug(&self, msg: impl fmt::Display) {
        self.log(LogLevel::Debug, msg);
    }
    pub fn verbose(&self, msg: impl fmt::Display) {
        self.log(LogLevel::Verbose, msg);
    }

    pub fn flush(&self) {
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        let _ = out.flush();
    }
}

// ---------------------------------------------------------------------------
// Access records
// ---------------------------------------------------------------------------

/// One HTTP/HTTPS access log entry (`kind=http`).
///
/// `rule`, `profile`, and `upstream` carry the routing decision that served the request;
/// `upstream` is always redacted so credentials never reach the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAccessRecord {
    pub ts: OffsetDateTime,
    pub client: SocketAddr,
    /// `http` or `https`.
    pub proto: String,
    pub mitm: bool,
    pub method: String,
    pub target: String,
    /// Routing rule name that matched (empty when routed by the default).
    pub rule: String,
    /// Selected upstream profile name (e.g. `bastion`, `corp`, `direct`).
    pub profile: String,
    /// Redacted upstream address (`scheme://host:port`, never `user:pass@`).
    pub upstream: String,
    pub status: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: u64,
}

/// One SOCKS connection log entry (`kind=socks`).
///
/// `rule`, `profile`, and `upstream` carry the routing decision that served the connection;
/// `upstream` is always redacted so credentials never reach the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksLogRecord {
    pub ts: OffsetDateTime,
    pub client: SocketAddr,
    /// `socks4`, `socks4a`, or `socks5`.
    pub proto: String,
    pub cmd: String,
    pub target: String,
    /// Routing rule name that matched (empty when routed by the default).
    pub rule: String,
    /// Selected upstream profile name (e.g. `corp`, `direct`).
    pub profile: String,
    /// Redacted upstream address (`scheme://host:port`, never `user:pass@`).
    pub upstream: String,
    /// e.g. `ok`, `blocked_web_in_mitm`, or an error label.
    pub status: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: u64,
}

/// A single field value, shared by the text and JSON encoders so both carry identical fields.
enum Value<'a> {
    Str(&'a str),
    Owned(String),
    Bool(bool),
    U64(u64),
}

impl Serialize for Value<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Str(v) => s.serialize_str(v),
            Value::Owned(v) => s.serialize_str(v),
            Value::Bool(v) => s.serialize_bool(*v),
            Value::U64(v) => s.serialize_u64(*v),
        }
    }
}

trait Fields {
    fn fields(&self) -> Vec<(&'static str, Value<'_>)>;
}

impl Fields for HttpAccessRecord {
    fn fields(&self) -> Vec<(&'static str, Value<'_>)> {
        vec![
            ("ts", Value::Owned(format_timestamp(self.ts))),
            ("kind", Value::Str("http")),
            ("client", Value::Owned(self.client.to_string())),
            ("proto", Value::Str(&self.proto)),
            ("mitm", Value::Bool(self.mitm)),
            ("method", Value::Str(&self.method)),
            ("target", Value::Str(&self.target)),
            ("rule", Value::Str(&self.rule)),
            ("profile", Value::Str(&self.profile)),
            ("upstream", Value::Str(&self.upstream)),
            ("status", Value::U64(u64::from(self.status))),
            ("bytes_in", Value::U64(self.bytes_in)),
            ("bytes_out", Value::U64(self.bytes_out)),
            ("duration_ms", Value::U64(self.duration_ms)),
        ]
    }
}

impl Fields for SocksLogRecord {
    fn fields(&self) -> Vec<(&'static str, Value<'_>)> {
        vec![
            ("ts", Value::Owned(format_timestamp(self.ts))),
            ("kind", Value::Str("socks")),
            ("client", Value::Owned(self.client.to_string())),
            ("proto", Value::Str(&self.proto)),
            ("cmd", Value::Str(&self.cmd)),
            ("target", Value::Str(&self.target)),
            ("rule", Value::Str(&self.rule)),
            ("profile", Value::Str(&self.profile)),
            ("upstream", Value::Str(&self.upstream)),
            ("status", Value::Str(&self.status)),
            ("bytes_in", Value::U64(self.bytes_in)),
            ("bytes_out", Value::U64(self.bytes_out)),
            ("duration_ms", Value::U64(self.duration_ms)),
        ]
    }
}

struct FieldMap<'a>(&'a [(&'static str, Value<'a>)]);

impl Serialize for FieldMap<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

/// Quote a logfmt value when it is empty or contains spaces, quotes, `=`, or control chars.
fn logfmt_value(v: &str) -> String {
    let needs_quotes = v.is_empty()
        || v.chars()
            .any(|c| c == ' ' || c == '"' || c == '=' || c.is_control());
    if !needs_quotes {
        return v.to_string();
    }
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn encode(fields: &[(&'static str, Value<'_>)], format: LogFormat) -> String {
    match format {
        LogFormat::Text => {
            let mut line = String::new();
            for (i, (k, v)) in fields.iter().enumerate() {
                if i > 0 {
                    line.push(' ');
                }
                line.push_str(k);
                line.push('=');
                match v {
                    Value::Str(s) => line.push_str(&logfmt_value(s)),
                    Value::Owned(s) => line.push_str(&logfmt_value(s)),
                    Value::Bool(b) => line.push_str(if *b { "true" } else { "false" }),
                    Value::U64(n) => line.push_str(&n.to_string()),
                }
            }
            line
        }
        LogFormat::Json => serde_json::to_string(&FieldMap(fields))
            .unwrap_or_else(|e| format!("{{\"log_encode_error\":{:?}}}", e.to_string())),
    }
}

impl HttpAccessRecord {
    /// Encode as one line (without trailing newline).
    pub fn format(&self, format: LogFormat) -> String {
        encode(&self.fields(), format)
    }
}

impl SocksLogRecord {
    /// Encode as one line (without trailing newline).
    pub fn format(&self, format: LogFormat) -> String {
        encode(&self.fields(), format)
    }
}

// ---------------------------------------------------------------------------
// Async access logger
// ---------------------------------------------------------------------------

/// Access-log sink configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLogConfig {
    pub format: LogFormat,
    pub http_access_log: Option<PathBuf>,
    pub socks_log: Option<PathBuf>,
    /// Also dump every record to `stdout` (true at `DEBUG` / `VERBOSE`).
    pub dump_stdout: bool,
}

impl AccessLogConfig {
    pub fn new(
        level: LogLevel,
        format: LogFormat,
        http_access_log: Option<PathBuf>,
        socks_log: Option<PathBuf>,
    ) -> Self {
        Self {
            format,
            http_access_log,
            socks_log,
            dump_stdout: level.dumps_access_to_stdout(),
        }
    }
}

type BoxWriter = Box<dyn AsyncWrite + Send + Unpin>;

enum Command {
    Http(String),
    Socks(String),
    Flush(oneshot::Sender<io::Result<()>>),
}

struct Sinks {
    http: Option<BufWriter<tokio::fs::File>>,
    socks: Option<BufWriter<tokio::fs::File>>,
    stdout: Option<BufWriter<BoxWriter>>,
}

impl Sinks {
    async fn write(&mut self, http: bool, line: &str) -> io::Result<()> {
        let file = if http {
            self.http.as_mut()
        } else {
            self.socks.as_mut()
        };
        if let Some(f) = file {
            f.write_all(line.as_bytes()).await?;
            f.write_all(b"\n").await?;
        }
        if let Some(out) = self.stdout.as_mut() {
            out.write_all(line.as_bytes()).await?;
            out.write_all(b"\n").await?;
            // stdout dumps are interactive diagnostics: keep them prompt.
            out.flush().await?;
        }
        Ok(())
    }

    async fn flush(&mut self) -> io::Result<()> {
        if let Some(f) = self.http.as_mut() {
            f.flush().await?;
        }
        if let Some(f) = self.socks.as_mut() {
            f.flush().await?;
        }
        if let Some(f) = self.stdout.as_mut() {
            f.flush().await?;
        }
        Ok(())
    }
}

async fn open_append(path: &Path) -> io::Result<BufWriter<tokio::fs::File>> {
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    Ok(BufWriter::new(file))
}

/// Async HTTP/SOCKS access logger backed by a single writer task.
///
/// Cheap to clone; all clones feed the same task. Call [`AccessLogger::shutdown`] (or at
/// least [`AccessLogger::flush`]) before exit so buffered file output is persisted.
#[derive(Clone)]
pub struct AccessLogger {
    format: LogFormat,
    http_active: bool,
    socks_active: bool,
    tx: Option<mpsc::Sender<Command>>,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
    errors: Logger,
}

impl fmt::Debug for AccessLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessLogger")
            .field("format", &self.format)
            .field("http_active", &self.http_active)
            .field("socks_active", &self.socks_active)
            .finish_non_exhaustive()
    }
}

const CHANNEL_CAPACITY: usize = 4096;

impl AccessLogger {
    /// Open the configured sinks, dumping to the process `stdout` when enabled.
    /// Must be called inside a Tokio runtime.
    pub async fn start(config: AccessLogConfig, errors: Logger) -> io::Result<Self> {
        Self::start_with_stdout(config, Box::new(tokio::io::stdout()), errors).await
    }

    /// Like [`AccessLogger::start`] but with an injected `stdout` writer (used by tests).
    pub async fn start_with_stdout(
        config: AccessLogConfig,
        stdout: BoxWriter,
        errors: Logger,
    ) -> io::Result<Self> {
        let http = match &config.http_access_log {
            Some(p) => Some(open_append(p).await?),
            None => None,
        };
        let socks = match &config.socks_log {
            Some(p) => Some(open_append(p).await?),
            None => None,
        };
        let stdout = config.dump_stdout.then(|| BufWriter::new(stdout));
        let http_active = http.is_some() || stdout.is_some();
        let socks_active = socks.is_some() || stdout.is_some();

        if !http_active && !socks_active {
            return Ok(Self {
                format: config.format,
                http_active,
                socks_active,
                tx: None,
                task: Arc::new(Mutex::new(None)),
                errors,
            });
        }

        let (tx, mut rx) = mpsc::channel::<Command>(CHANNEL_CAPACITY);
        let mut sinks = Sinks {
            http,
            socks,
            stdout,
        };
        let task_errors = errors.clone();
        let task = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    Command::Http(line) => {
                        if let Err(e) = sinks.write(true, &line).await {
                            task_errors.error(format!("http access log write failed: {e}"));
                        }
                    }
                    Command::Socks(line) => {
                        if let Err(e) = sinks.write(false, &line).await {
                            task_errors.error(format!("socks log write failed: {e}"));
                        }
                    }
                    Command::Flush(ack) => {
                        let _ = ack.send(sinks.flush().await);
                    }
                }
            }
            if let Err(e) = sinks.flush().await {
                task_errors.error(format!("access log flush failed: {e}"));
            }
        });

        Ok(Self {
            format: config.format,
            http_active,
            socks_active,
            tx: Some(tx),
            task: Arc::new(Mutex::new(Some(task))),
            errors,
        })
    }

    /// Whether HTTP records go anywhere (file or stdout).
    pub fn http_enabled(&self) -> bool {
        self.http_active
    }

    /// Whether SOCKS records go anywhere (file or stdout).
    pub fn socks_enabled(&self) -> bool {
        self.socks_active
    }

    pub fn format(&self) -> LogFormat {
        self.format
    }

    async fn send(&self, cmd: Command) {
        if let Some(tx) = &self.tx {
            if tx.send(cmd).await.is_err() {
                self.errors
                    .error("access logger is shut down; dropping record");
            }
        }
    }

    /// Record an HTTP/HTTPS access entry.
    pub async fn log_http(&self, record: &HttpAccessRecord) {
        if self.http_active {
            self.send(Command::Http(record.format(self.format))).await;
        }
    }

    /// Record a SOCKS connection entry.
    pub async fn log_socks(&self, record: &SocksLogRecord) {
        if self.socks_active {
            self.send(Command::Socks(record.format(self.format))).await;
        }
    }

    /// Flush all buffered output to the underlying files / stdout.
    pub async fn flush(&self) -> io::Result<()> {
        let Some(tx) = &self.tx else {
            return Ok(());
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        if tx.send(Command::Flush(ack_tx)).await.is_err() {
            return Ok(());
        }
        ack_rx.await.unwrap_or(Ok(()))
    }

    /// Flush and wait for the writer task to finish. Records sent by other clones after this
    /// returns are dropped with an `ERROR` diagnostic.
    pub async fn shutdown(&self) -> io::Result<()> {
        let result = self.flush().await;
        let task = self.task.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use time::macros::datetime;

    /// Shared in-memory buffer usable as both a sync and async writer.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl Buf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl AsyncWrite for Buf {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(b);
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "rusty-conduit-log-test-{}-{}-{tag}.log",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ))
    }

    fn http_record() -> HttpAccessRecord {
        HttpAccessRecord {
            ts: datetime!(2026-11-22 13:30:01.123456 UTC),
            client: "127.0.0.1:51234".parse().unwrap(),
            proto: "https".into(),
            mitm: true,
            method: "GET".into(),
            target: "https://example.com/api/v1".into(),
            rule: "internal-domains-with-failover".into(),
            profile: "bastion".into(),
            upstream: "socks5://127.0.0.1:1081".into(),
            status: 200,
            bytes_in: 142,
            bytes_out: 4096,
            duration_ms: 84,
        }
    }

    fn socks_record() -> SocksLogRecord {
        SocksLogRecord {
            ts: datetime!(2026-11-22 13:30:02.456 UTC),
            client: "127.0.0.1:51240".parse().unwrap(),
            proto: "socks5".into(),
            cmd: "CONNECT".into(),
            target: "github.com:22".into(),
            rule: "rfc1918-to-corp".into(),
            profile: "corp".into(),
            upstream: "http://10.0.0.2:3128".into(),
            status: "ok".into(),
            bytes_in: 1280,
            bytes_out: 8192,
            duration_ms: 1520,
        }
    }

    #[test]
    fn level_parsing_is_case_insensitive_and_ordered() {
        for (s, l) in [
            ("quiet", LogLevel::Quiet),
            ("FATAL", LogLevel::Fatal),
            ("Error", LogLevel::Error),
            ("info", LogLevel::Info),
            ("DeBuG", LogLevel::Debug),
            ("VERBOSE", LogLevel::Verbose),
        ] {
            assert_eq!(s.parse::<LogLevel>().unwrap(), l);
            assert_eq!(l.to_string().parse::<LogLevel>().unwrap(), l);
        }
        assert!("trace".parse::<LogLevel>().is_err());
        assert!(LogLevel::Quiet < LogLevel::Fatal);
        assert!(LogLevel::Fatal < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Verbose);
        assert_eq!("TEXT".parse::<LogFormat>().unwrap(), LogFormat::Text);
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert!("xml".parse::<LogFormat>().is_err());
    }

    #[test]
    fn stdout_dump_only_at_debug_and_verbose() {
        for l in LogLevel::ALL {
            let expected = matches!(l, LogLevel::Debug | LogLevel::Verbose);
            assert_eq!(l.dumps_access_to_stdout(), expected, "{l}");
        }
    }

    #[test]
    fn timestamp_is_rfc3339_millis_utc() {
        assert_eq!(
            format_timestamp(datetime!(2026-11-22 13:30:01.123456 UTC)),
            "2026-11-22T13:30:01.123Z"
        );
        assert_eq!(
            format_timestamp(datetime!(2026-11-22 15:30:01 +02:00)),
            "2026-11-22T13:30:01.000Z"
        );
    }

    #[test]
    fn http_record_text_format() {
        assert_eq!(
            http_record().format(LogFormat::Text),
            "ts=2026-11-22T13:30:01.123Z kind=http client=127.0.0.1:51234 proto=https mitm=true \
             method=GET target=https://example.com/api/v1 rule=internal-domains-with-failover \
             profile=bastion upstream=socks5://127.0.0.1:1081 status=200 bytes_in=142 \
             bytes_out=4096 duration_ms=84"
        );
    }

    #[test]
    fn socks_record_text_format() {
        assert_eq!(
            socks_record().format(LogFormat::Text),
            "ts=2026-11-22T13:30:02.456Z kind=socks client=127.0.0.1:51240 proto=socks5 \
             cmd=CONNECT target=github.com:22 rule=rfc1918-to-corp profile=corp \
             upstream=http://10.0.0.2:3128 status=ok bytes_in=1280 bytes_out=8192 \
             duration_ms=1520"
        );
    }

    #[test]
    fn text_format_quotes_special_values() {
        let mut r = http_record();
        r.target = "http://x/a b?q=\"1\"".into();
        r.method = String::new();
        let line = r.format(LogFormat::Text);
        assert!(line.contains(r#"target="http://x/a b?q=\"1\"""#), "{line}");
        assert!(line.contains(r#"method="""#), "{line}");
        assert!(!line.contains('\n'));
        r.target = "evil\nkind=forged".into();
        assert!(!r.format(LogFormat::Text).contains('\n'));
    }

    #[test]
    fn json_formats_have_identical_fields() {
        let v: serde_json::Value =
            serde_json::from_str(&http_record().format(LogFormat::Json)).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "ts": "2026-11-22T13:30:01.123Z", "kind": "http", "client": "127.0.0.1:51234",
                "proto": "https", "mitm": true, "method": "GET",
                "target": "https://example.com/api/v1", "rule": "internal-domains-with-failover",
                "profile": "bastion", "upstream": "socks5://127.0.0.1:1081", "status": 200,
                "bytes_in": 142, "bytes_out": 4096, "duration_ms": 84
            })
        );
        let line = socks_record().format(LogFormat::Json);
        assert!(!line.contains('\n'));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "ts": "2026-11-22T13:30:02.456Z", "kind": "socks", "client": "127.0.0.1:51240",
                "proto": "socks5", "cmd": "CONNECT", "target": "github.com:22",
                "rule": "rfc1918-to-corp", "profile": "corp",
                "upstream": "http://10.0.0.2:3128", "status": "ok",
                "bytes_in": 1280, "bytes_out": 8192, "duration_ms": 1520
            })
        );
        assert!(
            line.starts_with(r#"{"ts":"#),
            "field order preserved: {line}"
        );
    }

    #[test]
    fn diagnostic_level_filtering() {
        let all = [
            LogLevel::Fatal,
            LogLevel::Error,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Verbose,
        ];
        for configured in LogLevel::ALL {
            let buf = Buf::default();
            let logger = Logger::with_writer(configured, Box::new(buf.clone()));
            for l in all {
                logger.log(l, format!("msg-{l}"));
            }
            logger.log(LogLevel::Quiet, "never");
            let out = buf.text();
            for l in all {
                assert_eq!(
                    out.contains(&format!("msg-{l}")),
                    l <= configured,
                    "configured={configured} msg={l}"
                );
            }
            assert!(!out.contains("never"));
            if configured == LogLevel::Quiet {
                assert!(out.is_empty());
            }
        }
    }

    #[test]
    fn diagnostic_line_shape() {
        let buf = Buf::default();
        let logger = Logger::with_writer(LogLevel::Info, Box::new(buf.clone()));
        logger.info("hello world");
        logger.fatal("boom");
        let out = buf.text();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with(" INFO    hello world"), "{}", lines[0]);
        assert!(lines[1].ends_with(" FATAL   boom"), "{}", lines[1]);
        assert!(lines[0].as_bytes()[4] == b'-' && lines[0].contains('T'));
    }

    #[tokio::test]
    async fn routes_to_files_only_below_debug() {
        for level in [
            LogLevel::Quiet,
            LogLevel::Fatal,
            LogLevel::Error,
            LogLevel::Info,
        ] {
            let http = temp_path("http");
            let socks = temp_path("socks");
            let stdout = Buf::default();
            let cfg = AccessLogConfig::new(
                level,
                LogFormat::Text,
                Some(http.clone()),
                Some(socks.clone()),
            );
            assert!(!cfg.dump_stdout);
            let logger = AccessLogger::start_with_stdout(
                cfg,
                Box::new(stdout.clone()),
                Logger::with_writer(LogLevel::Quiet, Box::new(io::sink())),
            )
            .await
            .unwrap();
            logger.log_http(&http_record()).await;
            logger.log_socks(&socks_record()).await;
            logger.shutdown().await.unwrap();

            let h = std::fs::read_to_string(&http).unwrap();
            let s = std::fs::read_to_string(&socks).unwrap();
            assert_eq!(h, format!("{}\n", http_record().format(LogFormat::Text)));
            assert_eq!(s, format!("{}\n", socks_record().format(LogFormat::Text)));
            assert!(stdout.text().is_empty(), "no stdout dump at {level}");
            std::fs::remove_file(http).ok();
            std::fs::remove_file(socks).ok();
        }
    }

    #[tokio::test]
    async fn routes_to_files_and_stdout_at_debug_and_verbose() {
        for level in [LogLevel::Debug, LogLevel::Verbose] {
            let http = temp_path("http");
            let socks = temp_path("socks");
            let stdout = Buf::default();
            let cfg = AccessLogConfig::new(
                level,
                LogFormat::Json,
                Some(http.clone()),
                Some(socks.clone()),
            );
            assert!(cfg.dump_stdout);
            let logger = AccessLogger::start_with_stdout(
                cfg,
                Box::new(stdout.clone()),
                Logger::with_writer(LogLevel::Quiet, Box::new(io::sink())),
            )
            .await
            .unwrap();
            logger.log_http(&http_record()).await;
            logger.log_socks(&socks_record()).await;
            logger.shutdown().await.unwrap();

            let hline = http_record().format(LogFormat::Json);
            let sline = socks_record().format(LogFormat::Json);
            assert_eq!(
                std::fs::read_to_string(&http).unwrap(),
                format!("{hline}\n")
            );
            assert_eq!(
                std::fs::read_to_string(&socks).unwrap(),
                format!("{sline}\n")
            );
            assert_eq!(stdout.text(), format!("{hline}\n{sline}\n"), "at {level}");
            std::fs::remove_file(http).ok();
            std::fs::remove_file(socks).ok();
        }
    }

    #[tokio::test]
    async fn stdout_only_when_no_files_configured() {
        let stdout = Buf::default();
        let logger = AccessLogger::start_with_stdout(
            AccessLogConfig::new(LogLevel::Debug, LogFormat::Text, None, None),
            Box::new(stdout.clone()),
            Logger::with_writer(LogLevel::Quiet, Box::new(io::sink())),
        )
        .await
        .unwrap();
        assert!(logger.http_enabled() && logger.socks_enabled());
        logger.log_http(&http_record()).await;
        logger.flush().await.unwrap();
        assert_eq!(
            stdout.text(),
            format!("{}\n", http_record().format(LogFormat::Text))
        );
        logger.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn inactive_when_nothing_configured() {
        let stdout = Buf::default();
        let logger = AccessLogger::start_with_stdout(
            AccessLogConfig::new(LogLevel::Info, LogFormat::Text, None, None),
            Box::new(stdout.clone()),
            Logger::with_writer(LogLevel::Quiet, Box::new(io::sink())),
        )
        .await
        .unwrap();
        assert!(!logger.http_enabled() && !logger.socks_enabled());
        logger.log_http(&http_record()).await;
        logger.log_socks(&socks_record()).await;
        logger.flush().await.unwrap();
        logger.shutdown().await.unwrap();
        assert!(stdout.text().is_empty());
    }

    #[tokio::test]
    async fn file_sinks_append_and_flush_persists() {
        let http = temp_path("http");
        std::fs::write(&http, "existing\n").unwrap();
        let logger = AccessLogger::start_with_stdout(
            AccessLogConfig::new(LogLevel::Info, LogFormat::Text, Some(http.clone()), None),
            Box::new(Buf::default()),
            Logger::with_writer(LogLevel::Quiet, Box::new(io::sink())),
        )
        .await
        .unwrap();
        assert!(logger.http_enabled());
        assert!(!logger.socks_enabled());
        logger.log_http(&http_record()).await;
        logger.log_socks(&socks_record()).await; // no socks sink: dropped
        logger.flush().await.unwrap();
        let text = std::fs::read_to_string(&http).unwrap();
        assert_eq!(
            text,
            format!("existing\n{}\n", http_record().format(LogFormat::Text))
        );
        logger.shutdown().await.unwrap();
        std::fs::remove_file(http).ok();
    }

    #[tokio::test]
    async fn unopenable_log_path_is_an_error() {
        let err = AccessLogger::start_with_stdout(
            AccessLogConfig::new(
                LogLevel::Info,
                LogFormat::Text,
                Some(PathBuf::from("/definitely/not/a/dir/http.log")),
                None,
            ),
            Box::new(Buf::default()),
            Logger::with_writer(LogLevel::Quiet, Box::new(io::sink())),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("/definitely/not/a/dir/http.log"));
    }
}
