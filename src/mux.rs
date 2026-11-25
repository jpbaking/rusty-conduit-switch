//! Single-port first-byte protocol sniffer.
//!
//! When the HTTP and SOCKS ports are equal, each accepted connection is classified by
//! peeking (not consuming) its first byte:
//!
//! | First byte        | Protocol  |
//! |-------------------|-----------|
//! | `0x04`            | SOCKS4/4a |
//! | `0x05`            | SOCKS5    |
//! | `b'A'..=b'Z'`     | HTTP      |
//! | anything else     | rejected  |

use std::io;
use std::time::Duration;

use tokio::net::TcpStream;

/// Default time to wait for a client's first byte before rejecting it.
pub const DEFAULT_SNIFF_TIMEOUT: Duration = Duration::from_secs(5);

/// Protocol detected from the first byte of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedProtocol {
    Socks4,
    Socks5,
    Http,
    /// Unrecognized first byte; the connection must be rejected.
    Unknown(u8),
}

impl DetectedProtocol {
    /// Classify a first byte.
    pub fn from_first_byte(byte: u8) -> Self {
        match byte {
            0x04 => Self::Socks4,
            0x05 => Self::Socks5,
            b'A'..=b'Z' => Self::Http,
            other => Self::Unknown(other),
        }
    }
}

/// Reasons a protocol could not be sniffed.
#[derive(Debug, thiserror::Error)]
pub enum SniffError {
    #[error("client closed the connection before sending any data")]
    Eof,
    #[error("no data received within {}", humantime::format_duration(*.0))]
    Timeout(Duration),
    #[error("failed to read first byte: {0}")]
    Io(#[from] io::Error),
}

/// Peek at the first byte of `stream` (without consuming it) and classify the protocol.
///
/// Waits at most `timeout` for data to arrive.
pub async fn sniff_protocol(
    stream: &TcpStream,
    timeout: Duration,
) -> Result<DetectedProtocol, SniffError> {
    let mut buf = [0u8; 1];
    match tokio::time::timeout(timeout, stream.peek(&mut buf)).await {
        Err(_) => Err(SniffError::Timeout(timeout)),
        Ok(Err(e)) => Err(SniffError::Io(e)),
        Ok(Ok(0)) => Err(SniffError::Eof),
        Ok(Ok(_)) => Ok(DetectedProtocol::from_first_byte(buf[0])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Connect a loopback pair; returns (client side, server side).
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), server.unwrap().0)
    }

    async fn sniff_after_sending(bytes: &[u8]) -> Result<DetectedProtocol, SniffError> {
        let (mut client, mut server) = pair().await;
        client.write_all(bytes).await.unwrap();
        let result = sniff_protocol(&server, Duration::from_secs(5)).await;
        if result.is_ok() {
            // The peeked byte must still be readable (not consumed).
            let mut first = [0u8; 1];
            server.read_exact(&mut first).await.unwrap();
            assert_eq!(first[0], bytes[0]);
        }
        result
    }

    #[test]
    fn classifies_first_bytes() {
        assert_eq!(
            DetectedProtocol::from_first_byte(0x04),
            DetectedProtocol::Socks4
        );
        assert_eq!(
            DetectedProtocol::from_first_byte(0x05),
            DetectedProtocol::Socks5
        );
        for b in b'A'..=b'Z' {
            assert_eq!(DetectedProtocol::from_first_byte(b), DetectedProtocol::Http);
        }
        assert_eq!(
            DetectedProtocol::from_first_byte(b'g'),
            DetectedProtocol::Unknown(b'g')
        );
        assert_eq!(
            DetectedProtocol::from_first_byte(0x16),
            DetectedProtocol::Unknown(0x16)
        );
    }

    #[tokio::test]
    async fn sniffs_socks4() {
        assert_eq!(
            sniff_after_sending(&[0x04, 0x01, 0x00, 0x50])
                .await
                .unwrap(),
            DetectedProtocol::Socks4
        );
    }

    #[tokio::test]
    async fn sniffs_socks5() {
        assert_eq!(
            sniff_after_sending(&[0x05, 0x01, 0x00]).await.unwrap(),
            DetectedProtocol::Socks5
        );
    }

    #[tokio::test]
    async fn sniffs_http_get_and_connect() {
        assert_eq!(
            sniff_after_sending(b"GET http://example.com/ HTTP/1.1\r\n")
                .await
                .unwrap(),
            DetectedProtocol::Http
        );
        assert_eq!(
            sniff_after_sending(b"CONNECT example.com:443 HTTP/1.1\r\n")
                .await
                .unwrap(),
            DetectedProtocol::Http
        );
    }

    #[tokio::test]
    async fn sniffs_unknown_byte() {
        assert_eq!(
            sniff_after_sending(&[0x00, 0x01]).await.unwrap(),
            DetectedProtocol::Unknown(0x00)
        );
    }

    #[tokio::test]
    async fn eof_before_data() {
        let (client, server) = pair().await;
        drop(client);
        let err = sniff_protocol(&server, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, SniffError::Eof), "got {err:?}");
    }

    #[tokio::test]
    async fn times_out_without_data() {
        let (_client, server) = pair().await;
        let timeout = Duration::from_millis(100);
        let err = sniff_protocol(&server, timeout).await.unwrap_err();
        assert!(
            matches!(err, SniffError::Timeout(t) if t == timeout),
            "got {err:?}"
        );
    }
}
