//! `socks5`: RFC 1928 `CONNECT` client with optional RFC 1929 username/password auth.
//!
//! Hostnames are always sent unresolved as `ATYP=0x03` (remote DNS); IP literals use
//! `ATYP=0x01` / `0x04`.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{strip_brackets, with_timeout, DialFuture, UpstreamDialer, UpstreamStream};
use crate::net::{connect_upstream_filtered, KeepaliveSettings};

const SOCKS_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const USER_PASS_VERSION: u8 = 0x01;

/// Dials through an upstream SOCKS5 proxy.
#[derive(Clone)]
pub struct Socks5Dialer {
    proxy_host: String,
    proxy_port: u16,
    credentials: Option<(String, String)>,
    keepalive: Option<KeepaliveSettings>,
}

impl fmt::Debug for Socks5Dialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Dialer")
            .field("upstream", &self.redacted_upstream())
            .field("auth", &self.credentials.as_ref().map(|_| "<redacted>"))
            .field("keepalive", &self.keepalive)
            .finish()
    }
}

impl Socks5Dialer {
    /// A dialer for the SOCKS5 proxy at `proxy_host:proxy_port` (no auth, keepalive off).
    pub fn new(proxy_host: impl Into<String>, proxy_port: u16) -> Self {
        Self {
            proxy_host: proxy_host.into(),
            proxy_port,
            credentials: None,
            keepalive: None,
        }
    }

    /// Offer RFC 1929 username/password auth (in addition to no-auth).
    pub fn with_credentials(mut self, credentials: Option<(String, String)>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Set TCP keepalive for the proxy socket (`None` disables).
    pub fn with_tcp_keepalive(mut self, keepalive: Option<KeepaliveSettings>) -> Self {
        self.keepalive = keepalive;
        self
    }
}

impl UpstreamDialer for Socks5Dialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = host.to_string();
        Box::pin(async move {
            let request = encode_connect_request(&host, port)?;
            let upstream = self.redacted_upstream();
            with_timeout(&format!("SOCKS5 upstream {upstream}"), timeout, async {
                let mut stream = connect_upstream_filtered(
                    &self.proxy_host,
                    self.proxy_port,
                    timeout,
                    None,
                    self.keepalive.as_ref(),
                )
                .await?;
                handshake(&mut stream, self.credentials.as_ref(), &request).await?;
                Ok(UpstreamStream::Tcp(stream))
            })
            .await
        })
    }

    fn redacted_upstream(&self) -> String {
        format!(
            "socks5://{}",
            super::host_port(&self.proxy_host, self.proxy_port)
        )
    }
}

/// Run the SOCKS5 method negotiation, optional RFC 1929 auth, and `CONNECT` on `stream`,
/// leaving it positioned at the first payload byte.
pub async fn handshake<S>(
    stream: &mut S,
    credentials: Option<&(String, String)>,
    request: &[u8],
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if credentials.is_some() {
        stream
            .write_all(&[SOCKS_VERSION, 0x02, METHOD_NO_AUTH, METHOD_USER_PASS])
            .await?;
    } else {
        stream
            .write_all(&[SOCKS_VERSION, 0x01, METHOD_NO_AUTH])
            .await?;
    }
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != SOCKS_VERSION {
        return Err(invalid_data(format!(
            "SOCKS5 upstream: unexpected version 0x{:02x} in method reply",
            choice[0]
        )));
    }
    match (choice[1], credentials) {
        (METHOD_NO_AUTH, _) => {}
        (METHOD_USER_PASS, Some((user, pass))) => authenticate(stream, user, pass).await?,
        (METHOD_NONE_ACCEPTABLE, _) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 upstream: no acceptable authentication method",
            ))
        }
        (other, _) => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("SOCKS5 upstream: selected unoffered auth method 0x{other:02x}"),
            ))
        }
    }

    stream.write_all(request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Err(invalid_data(format!(
            "SOCKS5 upstream: unexpected version 0x{:02x} in connect reply",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(reply_error(head[1]));
    }
    // Consume BND.ADDR and BND.PORT.
    let addr_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => usize::from(stream.read_u8().await?),
        other => {
            return Err(invalid_data(format!(
                "SOCKS5 upstream: unknown bound address type 0x{other:02x}"
            )))
        }
    };
    let mut bound = [0u8; 257];
    stream.read_exact(&mut bound[..addr_len + 2]).await?;
    Ok(())
}

/// RFC 1929 sub-negotiation. Errors never include the username or password.
async fn authenticate<S>(stream: &mut S, user: &str, pass: &str) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let too_long = |what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SOCKS5 upstream: {what} must be at most 255 bytes"),
        )
    };
    let ulen = u8::try_from(user.len()).map_err(|_| too_long("username"))?;
    let plen = u8::try_from(pass.len()).map_err(|_| too_long("password"))?;
    let mut msg = Vec::with_capacity(3 + user.len() + pass.len());
    msg.push(USER_PASS_VERSION);
    msg.push(ulen);
    msg.extend_from_slice(user.as_bytes());
    msg.push(plen);
    msg.extend_from_slice(pass.as_bytes());
    stream.write_all(&msg).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "SOCKS5 upstream: username/password authentication failed (0x{:02x})",
                reply[1]
            ),
        ));
    }
    Ok(())
}

/// Build the RFC 1928 `CONNECT` request; non-literal hosts are sent as `ATYP=0x03`.
pub fn encode_connect_request(host: &str, port: u16) -> io::Result<Vec<u8>> {
    let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0x00];
    let bracketed = host.starts_with('[') || host.ends_with(']');
    let bare = strip_brackets(host);
    if bracketed && bare.parse::<Ipv6Addr>().is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid bracketed IPv6 literal: {host:?}"),
        ));
    }
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let len = u8::try_from(bare.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("SOCKS5 domain must be 1-255 bytes, got {}", bare.len()),
                    )
                })?;
            request.push(ATYP_DOMAIN);
            request.push(len);
            request.extend_from_slice(bare.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

/// Map a non-zero SOCKS5 reply code to an [`io::Error`].
fn reply_error(code: u8) -> io::Error {
    let (kind, message) = match code {
        0x01 => (io::ErrorKind::Other, "general SOCKS server failure"),
        0x02 => (
            io::ErrorKind::PermissionDenied,
            "connection not allowed by ruleset",
        ),
        0x03 => (io::ErrorKind::NetworkUnreachable, "network unreachable"),
        0x04 => (io::ErrorKind::HostUnreachable, "host unreachable"),
        0x05 => (io::ErrorKind::ConnectionRefused, "connection refused"),
        0x06 => (io::ErrorKind::TimedOut, "TTL expired"),
        0x07 => (io::ErrorKind::Unsupported, "command not supported"),
        0x08 => (io::ErrorKind::Unsupported, "address type not supported"),
        _ => (io::ErrorKind::Other, "unknown SOCKS5 reply"),
    };
    io::Error::new(kind, format!("SOCKS5 upstream: {message} (0x{code:02x})"))
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_each_address_type() {
        assert_eq!(
            encode_connect_request("1.2.3.4", 80).unwrap(),
            [5, 1, 0, 1, 1, 2, 3, 4, 0, 80]
        );
        let v6 = encode_connect_request("[::1]", 443).unwrap();
        assert_eq!(v6[3], ATYP_IPV6);
        assert_eq!(v6.len(), 4 + 16 + 2);
        let dom = encode_connect_request("db.internal", 5432).unwrap();
        assert_eq!(&dom[..5], &[5, 1, 0, 3, 11]);
        assert_eq!(&dom[5..16], b"db.internal");
        assert!(encode_connect_request("[nope]", 1).is_err());
        assert!(encode_connect_request(&"a".repeat(256), 1).is_err());
    }

    #[tokio::test]
    async fn auth_failure_error_hides_credentials() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move {
            let mut greet = [0u8; 4];
            server.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet, [5, 2, 0, 2]);
            server.write_all(&[5, 2]).await.unwrap();
            let mut buf = [0u8; 64];
            let _ = server.read(&mut buf).await.unwrap();
            server.write_all(&[1, 1]).await.unwrap();
        });
        let creds = ("alice".to_string(), "s3cret".to_string());
        let req = encode_connect_request("x.example", 1).unwrap();
        let err = handshake(&mut client, Some(&creds), &req)
            .await
            .unwrap_err();
        srv.await.unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let msg = err.to_string();
        assert!(!msg.contains("alice") && !msg.contains("s3cret"), "{msg}");
        let d = Socks5Dialer::new("127.0.0.1", 1081).with_credentials(Some(creds));
        let dbg = format!("{d:?}");
        assert!(!dbg.contains("s3cret") && !dbg.contains("alice"), "{dbg}");
        assert_eq!(d.redacted_upstream(), "socks5://127.0.0.1:1081");
    }
}
