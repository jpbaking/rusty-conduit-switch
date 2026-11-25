//! Shared TCP dial and relay utilities.
//!
//! Upstream connections resolve hostnames directly through the OS resolver (via Tokio's
//! `lookup_host`) on **every** dial: there is no DNS cache and no connection pooling.
//!
//! [`PrefixedStream`] wraps a stream that may hold bytes read past a framing header (the
//! terminating `\r\n\r\n` of an HTTP response), replaying them before the underlying socket.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::Instant;

use crate::filter::{access_denied_error, normalize_domain, AccessDenied, HostFilter};

/// Default timeout for establishing an upstream TCP connection.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// TCP keepalive parameters applied to client and upstream sockets.
///
/// Probes are sent by the OS kernel only while a connection is completely idle; they carry no
/// payload and are invisible to HTTP, TLS, SOCKS, and any tunneled protocol. They keep NAT /
/// firewall / VPN state alive during long silent periods and let dead peers be detected after
/// roughly `idle + interval * retries`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveSettings {
    /// Idle time before the first probe is sent.
    pub idle: Duration,
    /// Time between unanswered probes.
    pub interval: Duration,
    /// Unanswered probes before the OS closes the connection.
    pub retries: u32,
}

impl KeepaliveSettings {
    /// Default: first probe after 60s idle, then every 10s, give up after 5 misses.
    pub const DEFAULT: Self = Self {
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(10),
        retries: 5,
    };

    /// Enable `SO_KEEPALIVE` on `stream` with these parameters. On platforms without
    /// per-socket interval / retry control only the idle time is applied.
    pub fn apply(&self, stream: &TcpStream) -> io::Result<()> {
        let params = socket2::TcpKeepalive::new().with_time(self.idle);
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "windows",
        ))]
        let params = params
            .with_interval(self.interval)
            .with_retries(self.retries);
        socket2::SockRef::from(stream).set_tcp_keepalive(&params)
    }
}

impl Default for KeepaliveSettings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl std::fmt::Display for KeepaliveSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "idle={} interval={} retries={}",
            humantime::format_duration(self.idle),
            humantime::format_duration(self.interval),
            self.retries
        )
    }
}

/// Configure a freshly dialed upstream socket: `TCP_NODELAY` plus optional keepalive.
///
/// A keepalive failure is not fatal: the connection still works, it just will not probe.
fn prepare_upstream(
    stream: TcpStream,
    keepalive: Option<&KeepaliveSettings>,
) -> io::Result<TcpStream> {
    stream.set_nodelay(true)?;
    if let Some(ka) = keepalive {
        let _ = ka.apply(&stream);
    }
    Ok(stream)
}

fn timed_out(host: &str, port: u16, timeout: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "connect to {host}:{port} timed out after {}",
            humantime::format_duration(timeout)
        ),
    )
}

/// Open a fresh TCP connection to `host:port` with `TCP_NODELAY` enabled (no keepalive).
///
/// `host` may be a DNS name or an IP literal (IPv6 literals with or without brackets). Name
/// resolution is performed by the OS on each call (zero DNS caching); every resolved address
/// is tried in order until one connects. The whole resolve + connect sequence is bounded by
/// `timeout`, after which an [`io::ErrorKind::TimedOut`] error is returned.
pub async fn connect_upstream(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    connect_upstream_filtered(host, port, timeout, None, None).await
}

/// Like [`connect_upstream`], additionally enforcing an optional destination [`HostFilter`].
///
/// When `filter` is `Some`, both domain rules and resolved-IP IP/CIDR rules are checked before
/// opening a TCP connection (so DNS-to-loopback / DNS-rebinding bypasses are rejected).
/// When `keepalive` is `Some`, TCP keepalive is enabled on the connected socket.
pub async fn connect_upstream_filtered(
    host: &str,
    port: u16,
    timeout: Duration,
    filter: Option<&HostFilter>,
    keepalive: Option<&KeepaliveSettings>,
) -> io::Result<TcpStream> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    let Some(filter) = filter else {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((host, port)))
            .await
            .map_err(|_| timed_out(host, port, timeout))??;
        return prepare_upstream(stream, keepalive);
    };

    let deadline = Instant::now() + timeout;
    if let Ok(ip) = host.parse::<IpAddr>() {
        filter.check_ip(ip).map_err(access_denied_error)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let stream = tokio::time::timeout(remaining, TcpStream::connect(SocketAddr::new(ip, port)))
            .await
            .map_err(|_| timed_out(host, port, timeout))??;
        return prepare_upstream(stream, keepalive);
    }

    let domain = normalize_domain(host);
    let domain_matched = filter.matches_domain(&domain);
    match filter {
        HostFilter::Block(_) if domain_matched => {
            return Err(access_denied_error(AccessDenied(format!(
                "destination {host} is blocklisted"
            ))));
        }
        HostFilter::Allow(_) if !domain_matched && !filter.has_ip_rules() => {
            return Err(access_denied_error(AccessDenied(format!(
                "destination {host} is not in allowlist"
            ))));
        }
        _ => {}
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    let resolved: Vec<SocketAddr> = tokio::time::timeout(remaining, lookup_host((host, port)))
        .await
        .map_err(|_| timed_out(host, port, timeout))??
        .collect();
    if resolved.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("DNS returned no addresses for {host}"),
        ));
    }

    let candidates: Vec<SocketAddr> = match filter {
        HostFilter::Block(_) => {
            if let Some(blocked) = resolved.iter().find(|a| filter.matches_ip(a.ip())) {
                return Err(access_denied_error(AccessDenied(format!(
                    "destination {host} resolved to blocklisted IP {}",
                    blocked.ip()
                ))));
            }
            resolved
        }
        HostFilter::Allow(_) if domain_matched => resolved,
        HostFilter::Allow(_) => {
            let allowed: Vec<SocketAddr> = resolved
                .into_iter()
                .filter(|a| filter.matches_ip(a.ip()))
                .collect();
            if allowed.is_empty() {
                return Err(access_denied_error(AccessDenied(format!(
                    "destination {host} is not in allowlist"
                ))));
            }
            allowed
        }
    };

    let mut last_err = None;
    for addr in candidates {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out(host, port, timeout));
        }
        match tokio::time::timeout(remaining, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return prepare_upstream(stream, keepalive),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => return Err(timed_out(host, port, timeout)),
        }
    }
    Err(last_err.unwrap_or_else(|| timed_out(host, port, timeout)))
}

/// Relay bytes in both directions until both sides reach EOF (or either side errors).
///
/// Returns `(bytes_in, bytes_out)` where `bytes_in` is the number of bytes read from
/// `client` and written to `upstream`, and `bytes_out` is the number of bytes read from
/// `upstream` and written to `client`. Data is streamed through fixed buffers and never
/// retained.
pub async fn relay_bidirectional<C, U>(client: &mut C, upstream: &mut U) -> io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin + ?Sized,
    U: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    tokio::io::copy_bidirectional(client, upstream).await
}

// ---------------------------------------------------------------------------
// PrefixedStream
// ---------------------------------------------------------------------------

/// A stream that replays bytes read past a framing header before the inner stream.
///
/// Used by the HTTP CONNECT dialer: after reading an upstream response's status line and
/// headers, any bytes read beyond the terminating `\r\n\r\n` are buffered here and returned to
/// the application before the underlying socket. Bytes are consumed strictly in order — the
/// pushback buffer is drained before the inner stream is touched.
#[derive(Debug, Clone)]
pub struct PrefixedStream<S> {
    inner: S,
    buffer: Vec<u8>,
}

impl<S> PrefixedStream<S> {
    /// Wrap `inner`, replaying any `buffer` bytes already read past a framing header.
    pub fn new(inner: S, buffer: Vec<u8>) -> Self {
        Self { inner, buffer }
    }

    /// Number of buffered bytes still to be replayed.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Consume the wrapper, returning the inner stream and any remaining buffered bytes.
    pub fn into_inner(self) -> (S, Vec<u8>) {
        (self.inner, self.buffer)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.buffer.is_empty() {
            let unfilled = buf.initialize_unfilled();
            let n = std::cmp::min(this.buffer.len(), unfilled.len());
            unfilled[..n].copy_from_slice(&this.buffer[..n]);
            buf.advance(n);
            this.buffer.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn relay_counts_bytes_in_both_directions() {
        // Upstream echo-ish server: reads the full request, replies with a fixed payload.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut received = Vec::new();
            sock.read_to_end(&mut received).await.unwrap();
            sock.write_all(&[b'r'; 2500]).await.unwrap();
            sock.shutdown().await.unwrap();
            received
        });

        // Proxy front listener: accepts the client and relays to upstream.
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (mut client, _) = front.accept().await.unwrap();
            let mut upstream = connect_upstream(
                &upstream_addr.ip().to_string(),
                upstream_addr.port(),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            assert!(upstream.nodelay().unwrap());
            relay_bidirectional(&mut client, &mut upstream)
                .await
                .unwrap()
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client.write_all(&[b'q'; 1234]).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();

        let (bytes_in, bytes_out) = relay_task.await.unwrap();
        let received = upstream_task.await.unwrap();
        assert_eq!(received, vec![b'q'; 1234]);
        assert_eq!(reply, vec![b'r'; 2500]);
        assert_eq!((bytes_in, bytes_out), (1234, 2500));
    }

    #[tokio::test]
    async fn connect_upstream_resolves_localhost_name() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let stream = connect_upstream("localhost", port, Duration::from_secs(5)).await;
        // `localhost` may resolve to ::1 first on some hosts; all addresses are tried.
        let stream = stream.unwrap();
        assert!(stream.nodelay().unwrap());
        accept.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connect_upstream_reports_refused() {
        // Bind then drop to obtain a (very likely) closed port.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let err = connect_upstream("127.0.0.1", port, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_ne!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn connect_upstream_accepts_bracketed_ipv6_literal() {
        let Ok(listener) = TcpListener::bind("[::1]:0").await else {
            return; // IPv6 loopback unavailable on this host.
        };
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        connect_upstream("[::1]", port, Duration::from_secs(5))
            .await
            .unwrap();
        accept.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn upstream_dial_applies_keepalive_settings() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await });
        let ka = KeepaliveSettings {
            idle: Duration::from_secs(45),
            interval: Duration::from_secs(7),
            retries: 4,
        };
        let stream =
            connect_upstream_filtered("127.0.0.1", port, Duration::from_secs(5), None, Some(&ka))
                .await
                .unwrap();
        let sock = socket2::SockRef::from(&stream);
        assert!(sock.keepalive().unwrap());
        assert!(stream.nodelay().unwrap());
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert_eq!(sock.tcp_keepalive_time().unwrap(), ka.idle);
            assert_eq!(sock.tcp_keepalive_interval().unwrap(), ka.interval);
            assert_eq!(sock.tcp_keepalive_retries().unwrap(), ka.retries);
        }
        accept.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn upstream_dial_without_keepalive_leaves_it_off() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move { listener.accept().await });
        let stream = connect_upstream("127.0.0.1", port, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(!socket2::SockRef::from(&stream).keepalive().unwrap());
        accept.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn prefixed_stream_replays_buffer_before_inner() {
        // Upstream returns a fixed "header\r\n\r\nBODY" payload.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            sock.write_all(b"HEAD\r\n\r\nBODY").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let mut upstream = connect_upstream(
            &upstream_addr.ip().to_string(),
            upstream_addr.port(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // Read the whole 12-byte response in one go, as a dialer using a large read
        // buffer would: the first 8 bytes are the HTTP response header ("HEAD\r\n\r\n"),
        // the last 4 ("BODY") were read past the framing and must be replayed.
        let mut whole = [0u8; 12];
        upstream.read_exact(&mut whole).await.unwrap();
        assert_eq!(&whole, b"HEAD\r\n\r\nBODY");

        // Re-wrap with the over-read "BODY" bytes replayed before the (now empty) inner stream.
        let mut ps = PrefixedStream::new(upstream, whole[8..].to_vec());
        assert_eq!(ps.buffered(), 4);
        let mut out = Vec::new();
        ps.read_to_end(&mut out).await.unwrap();
        upstream_task.await.unwrap();
        assert_eq!(out, b"BODY");
    }
}
