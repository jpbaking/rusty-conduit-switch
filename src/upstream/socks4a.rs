//! `socks4a`: SOCKS4a `CONNECT` client with remote DNS (`0.0.0.1` + hostname).

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{strip_brackets, with_timeout, DialFuture, UpstreamDialer, UpstreamStream};
use crate::net::{connect_upstream_filtered, KeepaliveSettings};

const VERSION: u8 = 0x04;
const CMD_CONNECT: u8 = 0x01;
const REPLY_GRANTED: u8 = 0x5a;

/// Dials through an upstream SOCKS4a proxy. IPv6 literals cannot be expressed in SOCKS4a
/// and fail cleanly with [`io::ErrorKind::Unsupported`] (so a failover chain moves on).
#[derive(Debug, Clone)]
pub struct Socks4aDialer {
    proxy_host: String,
    proxy_port: u16,
    user_id: String,
    keepalive: Option<KeepaliveSettings>,
}

impl Socks4aDialer {
    /// A dialer for the SOCKS4a proxy at `proxy_host:proxy_port` (empty user id).
    pub fn new(proxy_host: impl Into<String>, proxy_port: u16) -> Self {
        Self {
            proxy_host: proxy_host.into(),
            proxy_port,
            user_id: String::new(),
            keepalive: None,
        }
    }

    /// Send `user_id` in the `USERID` field.
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = user_id.into();
        self
    }

    /// Set TCP keepalive for the proxy socket (`None` disables).
    pub fn with_tcp_keepalive(mut self, keepalive: Option<KeepaliveSettings>) -> Self {
        self.keepalive = keepalive;
        self
    }
}

impl UpstreamDialer for Socks4aDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = host.to_string();
        Box::pin(async move {
            let request = encode_connect_request(&host, port, &self.user_id)?;
            let upstream = self.redacted_upstream();
            with_timeout(&format!("SOCKS4a upstream {upstream}"), timeout, async {
                let mut stream = connect_upstream_filtered(
                    &self.proxy_host,
                    self.proxy_port,
                    timeout,
                    None,
                    self.keepalive.as_ref(),
                )
                .await?;
                handshake(&mut stream, &request).await?;
                Ok(UpstreamStream::Tcp(stream))
            })
            .await
        })
    }

    fn redacted_upstream(&self) -> String {
        format!(
            "socks4a://{}",
            super::host_port(&self.proxy_host, self.proxy_port)
        )
    }
}

/// Build the SOCKS4a `CONNECT` request: IPv4 literals inline, hostnames after `0.0.0.1`.
pub fn encode_connect_request(host: &str, port: u16, user_id: &str) -> io::Result<Vec<u8>> {
    if user_id.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS4a user id must not contain NUL",
        ));
    }
    let bare = strip_brackets(host);
    let mut req = vec![VERSION, CMD_CONNECT];
    req.extend_from_slice(&port.to_be_bytes());
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(user_id.as_bytes());
            req.push(0);
        }
        Ok(IpAddr::V6(_)) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("SOCKS4a cannot carry IPv6 destination {bare}"),
            ))
        }
        Err(_) => {
            if bare.is_empty() || bare.contains('\0') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS4a hostname must be non-empty and contain no NUL",
                ));
            }
            req.extend_from_slice(&[0, 0, 0, 1]);
            req.extend_from_slice(user_id.as_bytes());
            req.push(0);
            req.extend_from_slice(bare.as_bytes());
            req.push(0);
        }
    }
    Ok(req)
}

async fn handshake<S>(stream: &mut S, request: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SOCKS4a upstream: unexpected reply version 0x{:02x}",
                reply[0]
            ),
        ));
    }
    match reply[1] {
        REPLY_GRANTED => Ok(()),
        code => {
            let (kind, msg) = match code {
                0x5b => (
                    io::ErrorKind::ConnectionRefused,
                    "request rejected or failed",
                ),
                0x5c => (io::ErrorKind::PermissionDenied, "identd unreachable"),
                0x5d => (io::ErrorKind::PermissionDenied, "identd user id mismatch"),
                _ => (io::ErrorKind::Other, "unknown reply"),
            };
            Err(io::Error::new(
                kind,
                format!("SOCKS4a upstream: {msg} (0x{code:02x})"),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_hostname_for_remote_dns() {
        let req = encode_connect_request("db.internal", 5432, "bob").unwrap();
        let mut want = vec![4, 1, 0x15, 0x38, 0, 0, 0, 1];
        want.extend_from_slice(b"bob\0db.internal\0");
        assert_eq!(req, want);
    }

    #[test]
    fn encodes_ipv4_literal_and_rejects_ipv6() {
        assert_eq!(
            encode_connect_request("10.0.0.5", 80, "").unwrap(),
            [4, 1, 0, 80, 10, 0, 0, 5, 0]
        );
        let err = encode_connect_request("[::1]", 80, "").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn maps_rejection() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(&[0, 0x5b, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let req = encode_connect_request("a.example", 1, "").unwrap();
        let err = handshake(&mut client, &req).await.unwrap_err();
        srv.await.unwrap();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }
}
