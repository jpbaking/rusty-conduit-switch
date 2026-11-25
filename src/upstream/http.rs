//! `http` and `https`: HTTP `CONNECT` tunnel client with optional Basic `Proxy-Authorization`.
//!
//! For `https` the connection to the proxy itself is TLS (`tokio-rustls`, `ring` provider),
//! verified with the OS trust store via `rustls-platform-verifier` unless custom trust
//! anchors are supplied or `tls_insecure_skip_verify` is set. Bytes the proxy sent after the
//! `CONNECT` response headers are preserved through [`UpstreamStream::Prefixed`].

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use super::{host_port, strip_brackets, with_timeout, DialFuture, UpstreamDialer, UpstreamStream};
use crate::net::{connect_upstream_filtered, KeepaliveSettings};

/// Largest `CONNECT` response header block accepted from a proxy.
pub const MAX_RESPONSE_HEADER: usize = 16 * 1024;

/// TLS settings for an `https` proxy.
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    /// Accept any proxy certificate (`tls_insecure_skip_verify = true`).
    pub insecure_skip_verify: bool,
    /// Trust exactly these roots instead of the OS store (used by tests / private CAs).
    pub roots: Vec<CertificateDer<'static>>,
}

/// Build the rustls client configuration for an `https` proxy.
pub fn client_config(opts: &TlsOptions) -> Result<ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let config = if opts.insecure_skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else if !opts.roots.is_empty() {
        let mut store = RootCertStore::empty();
        for root in &opts.roots {
            store.add(root.clone())?;
        }
        builder.with_root_certificates(store).with_no_client_auth()
    } else {
        builder.with_platform_verifier()?.with_no_client_auth()
    };
    Ok(config)
}

/// Certificate verifier for `tls_insecure_skip_verify`: accepts any certificate but still
/// checks handshake signatures.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Clone)]
struct TlsLayer {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

/// Dials through an upstream HTTP proxy (`http`) or HTTP-over-TLS proxy (`https`) using
/// `CONNECT host:port`. The target host is sent unresolved.
#[derive(Clone)]
pub struct HttpConnectDialer {
    proxy_host: String,
    proxy_port: u16,
    authorization: Option<String>,
    keepalive: Option<KeepaliveSettings>,
    tls: Option<TlsLayer>,
}

impl fmt::Debug for HttpConnectDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpConnectDialer")
            .field("upstream", &self.redacted_upstream())
            .field("auth", &self.authorization.as_ref().map(|_| "<redacted>"))
            .field("keepalive", &self.keepalive)
            .finish()
    }
}

/// Alias: the `https` dialer is an [`HttpConnectDialer`] with a TLS layer.
pub type HttpsConnectDialer = HttpConnectDialer;

impl HttpConnectDialer {
    /// A plain-TCP `http` proxy dialer.
    pub fn http(proxy_host: impl Into<String>, proxy_port: u16) -> Self {
        Self {
            proxy_host: proxy_host.into(),
            proxy_port,
            authorization: None,
            keepalive: None,
            tls: None,
        }
    }

    /// A TLS `https` proxy dialer; the certificate is checked against `proxy_host`.
    pub fn https(
        proxy_host: impl Into<String>,
        proxy_port: u16,
        tls: &TlsOptions,
    ) -> Result<Self, rustls::Error> {
        let proxy_host = proxy_host.into();
        let config = client_config(tls)?;
        let server_name = ServerName::try_from(strip_brackets(&proxy_host).to_string())
            .map_err(|_| rustls::Error::General("invalid proxy host name for TLS".into()))?;
        let mut d = Self::http(proxy_host, proxy_port);
        d.tls = Some(TlsLayer {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
        });
        Ok(d)
    }

    /// Send `Proxy-Authorization: Basic base64(user:pass)` (`None` disables).
    pub fn with_credentials(mut self, credentials: Option<(String, String)>) -> Self {
        self.authorization = credentials.map(|(u, p)| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
            )
        });
        self
    }

    /// Set TCP keepalive for the proxy socket (`None` disables).
    pub fn with_tcp_keepalive(mut self, keepalive: Option<KeepaliveSettings>) -> Self {
        self.keepalive = keepalive;
        self
    }

    /// Whether the proxy connection is TLS (`https`).
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// The `Proxy-Authorization` header value, for absolute-form request forwarding.
    /// Secret: never log it.
    pub fn proxy_authorization(&self) -> Option<&str> {
        self.authorization.as_deref()
    }

    /// Open a connection to the proxy itself (TCP, plus TLS for `https`) without sending
    /// `CONNECT`, for absolute-form HTTP forwarding.
    pub async fn connect_proxy(&self, timeout: Duration) -> io::Result<UpstreamStream> {
        let upstream = self.redacted_upstream();
        with_timeout(&format!("connect to {upstream}"), timeout, async {
            let tcp = connect_upstream_filtered(
                &self.proxy_host,
                self.proxy_port,
                timeout,
                None,
                self.keepalive.as_ref(),
            )
            .await?;
            match &self.tls {
                None => Ok(UpstreamStream::Tcp(tcp)),
                Some(tls) => {
                    let s = tls
                        .connector
                        .connect(tls.server_name.clone(), tcp)
                        .await
                        .map_err(|e| {
                            io::Error::new(e.kind(), format!("TLS to {upstream} failed: {e}"))
                        })?;
                    Ok(UpstreamStream::Tls(Box::new(s)))
                }
            }
        })
        .await
    }
}

impl UpstreamDialer for HttpConnectDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let target = host_port(host, port);
        Box::pin(async move {
            let upstream = self.redacted_upstream();
            with_timeout(
                &format!("CONNECT {target} via {upstream}"),
                timeout,
                async {
                    let mut stream = self.connect_proxy(timeout).await?;
                    let leftover = connect_tunnel(
                        &mut stream,
                        &target,
                        self.authorization.as_deref(),
                        &upstream,
                    )
                    .await?;
                    Ok(stream.with_prefix(leftover))
                },
            )
            .await
        })
    }

    fn redacted_upstream(&self) -> String {
        let scheme = if self.tls.is_some() { "https" } else { "http" };
        format!(
            "{scheme}://{}",
            host_port(&self.proxy_host, self.proxy_port)
        )
    }
}

/// Send `CONNECT target` on `stream` and read the response headers. Returns any bytes read
/// past the terminating `\r\n\r\n`. Errors never include the authorization header.
pub async fn connect_tunnel<S>(
    stream: &mut S,
    target: &str,
    authorization: Option<&str>,
    upstream: &str,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(auth) = authorization {
        req.push_str("Proxy-Authorization: ");
        req.push_str(auth);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("HTTP upstream {upstream} closed before CONNECT response"),
            ));
        }
        let search_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf[search_from..]) {
            break search_from + pos;
        }
        if buf.len() > MAX_RESPONSE_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("HTTP upstream {upstream} CONNECT response headers too large"),
            ));
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]);
    let status_line = head.lines().next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let code: u16 = parts
        .next()
        .and_then(|c| c.parse().ok())
        .filter(|_| version.starts_with("HTTP/1."))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("HTTP upstream {upstream} sent a malformed CONNECT response"),
            )
        })?;
    if !(200..300).contains(&code) {
        let reason: String = parts.next().unwrap_or_default().chars().take(64).collect();
        let kind = match code {
            403 | 407 => io::ErrorKind::PermissionDenied,
            _ => io::ErrorKind::ConnectionRefused,
        };
        return Err(io::Error::new(
            kind,
            format!("HTTP upstream {upstream} refused CONNECT {target}: {code} {reason}"),
        ));
    }
    Ok(buf[header_end..].to_vec())
}

/// Index just past the first `\r\n\r\n` in `buf`.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(reply: &'static [u8], auth: Option<&str>) -> (io::Result<Vec<u8>>, String) {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = server.read(&mut buf).await.unwrap();
            server.write_all(reply).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let res = connect_tunnel(&mut client, "db.internal:5432", auth, "http://p:1").await;
        (res, srv.await.unwrap())
    }

    #[tokio::test]
    async fn sends_connect_and_preserves_trailing_bytes() {
        let (res, req) = run(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nHELLO", Some("Basic abc")).await;
        assert_eq!(res.unwrap(), b"HELLO");
        assert!(
            req.starts_with("CONNECT db.internal:5432 HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(req.contains("Host: db.internal:5432\r\n"));
        assert!(req.contains("Proxy-Authorization: Basic abc\r\n"));
    }

    #[tokio::test]
    async fn rejects_non_2xx_without_leaking_auth() {
        let (res, _) = run(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
            Some("Basic c2VjcmV0"),
        )
        .await;
        let err = res.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let msg = err.to_string();
        assert!(msg.contains("407") && !msg.contains("c2VjcmV0"), "{msg}");
        let (res, _) = run(b"garbage\r\n\r\n", None).await;
        assert_eq!(res.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn credentials_are_redacted_and_encoded() {
        let d = HttpConnectDialer::http("10.0.0.2", 3128)
            .with_credentials(Some(("alice".into(), "pw".into())));
        assert_eq!(d.proxy_authorization(), Some("Basic YWxpY2U6cHc="));
        let dbg = format!("{d:?}");
        assert!(
            !dbg.contains("YWxpY2U6cHc=") && !dbg.contains("alice"),
            "{dbg}"
        );
        assert_eq!(d.redacted_upstream(), "http://10.0.0.2:3128");
    }

    #[test]
    fn builds_https_configs() {
        let insecure = TlsOptions {
            insecure_skip_verify: true,
            ..Default::default()
        };
        let d = HttpConnectDialer::https("proxy.example.com", 8443, &insecure).unwrap();
        assert!(d.is_tls());
        assert_eq!(d.redacted_upstream(), "https://proxy.example.com:8443");
        HttpConnectDialer::https("::1", 8443, &TlsOptions::default()).unwrap();
    }
}
