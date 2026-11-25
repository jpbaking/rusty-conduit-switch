//! `--socks-block-web-in-mitm`: keep web traffic from bypassing HTTPS MITM logging by
//! tunnelling over SOCKS.
//!
//! Installed as the SOCKS [`RelayGuard`] only when MITM is ON and the flag is set. The
//! SOCKS relay forwards upstream → client bytes immediately (server-speaks-first protocols
//! such as SSH, SMTP, or Postgres are never delayed) and hands the **first**
//! client → upstream chunk to [`WebGuard::inspect`]. It is blocked when it is:
//!
//! * **plaintext HTTP** — starts with `GET `, `POST `, `HEAD `, `PUT `, `DELETE `,
//!   `OPTIONS `, `PATCH `, `CONNECT `, or `TRACE `; or
//! * **HTTPS** — a TLS handshake record (`0x16 0x03 …`) carrying a `ClientHello` (`0x01`)
//!   that either advertises an HTTP ALPN protocol (`http/1.1` or `h2`), or targets port
//!   `443` without advertising any non-HTTP ALPN protocol (no ALPN, or a `ClientHello` too
//!   fragmented to read the extensions from).
//!
//! Blocked sessions are closed without forwarding the chunk and logged with
//! `status=blocked_web_in_mitm`. Everything else is forwarded unchanged.

use super::{GuardVerdict, RelayGuard, SocksTarget};

/// SOCKS log status for blocked sessions.
pub const BLOCKED_STATUS: &str = "blocked_web_in_mitm";

/// Plaintext HTTP request-line prefixes.
pub const HTTP_METHOD_PREFIXES: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// ALPN protocol IDs treated as web traffic.
pub const HTTP_ALPN: [&[u8]; 2] = [b"http/1.1", b"h2"];

const HTTPS_PORT: u16 = 443;
const ALPN_EXTENSION: u16 = 0x0010;

/// The SOCKS web-traffic guard.
#[derive(Debug, Clone, Copy, Default)]
pub struct WebGuard;

impl RelayGuard for WebGuard {
    fn inspect(&self, target: &SocksTarget, first_chunk: &[u8]) -> GuardVerdict {
        if is_web_traffic(target.port, first_chunk) {
            GuardVerdict::Block {
                status: BLOCKED_STATUS.to_string(),
            }
        } else {
            GuardVerdict::Allow
        }
    }
}

/// Whether the first client chunk of a session to `port` is HTTP or HTTPS.
pub fn is_web_traffic(port: u16, chunk: &[u8]) -> bool {
    if is_plain_http(chunk) {
        return true;
    }
    match parse_client_hello(chunk) {
        TlsHello::NotClientHello => false,
        TlsHello::ClientHello { alpn: Some(protos) } => {
            protos.iter().any(|p| HTTP_ALPN.contains(&p.as_slice()))
                || (port == HTTPS_PORT && protos.is_empty())
        }
        TlsHello::ClientHello { alpn: None } | TlsHello::Truncated => port == HTTPS_PORT,
    }
}

/// Starts with one of [`HTTP_METHOD_PREFIXES`].
pub fn is_plain_http(chunk: &[u8]) -> bool {
    HTTP_METHOD_PREFIXES.iter().any(|m| chunk.starts_with(m))
}

/// Result of looking for a TLS `ClientHello` at the start of a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsHello {
    /// Not a TLS handshake record carrying a `ClientHello`.
    NotClientHello,
    /// A `ClientHello`; `alpn` is `None` when it has no ALPN extension.
    ClientHello { alpn: Option<Vec<Vec<u8>>> },
    /// A `ClientHello` whose extensions are cut off or malformed.
    Truncated,
}

/// Parse the leading TLS record of `chunk` far enough to read the ALPN extension.
pub fn parse_client_hello(chunk: &[u8]) -> TlsHello {
    // Record header: type 0x16 (handshake), legacy version 0x03 0x0?, length.
    if chunk.len() < 6 || chunk[0] != 0x16 || chunk[1] != 0x03 || chunk[5] != 0x01 {
        return TlsHello::NotClientHello;
    }
    match read_hello(&chunk[5..]) {
        Some(alpn) => TlsHello::ClientHello { alpn },
        None => TlsHello::Truncated,
    }
}

/// Minimal big-endian byte reader; every accessor returns `None` past the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
}

/// Parse a handshake message starting at its type byte. Returns the ALPN list
/// (`Some(None)` = no ALPN extension) or `None` when truncated / malformed.
fn read_hello(handshake: &[u8]) -> Option<Option<Vec<Vec<u8>>>> {
    let mut r = Reader(handshake);
    r.u8()?; // msg_type = client_hello
    let len = r.u24()?;
    let mut body = Reader(r.take(len).unwrap_or(r.0));
    body.take(2 + 32)?; // legacy_version + random
    body.vec8()?; // legacy_session_id
    body.vec16()?; // cipher_suites
    body.vec8()?; // legacy_compression_methods
    if body.0.is_empty() {
        return Some(None); // no extensions at all
    }
    let mut exts = Reader(body.vec16()?);
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let data = exts.vec16()?;
        if ty == ALPN_EXTENSION {
            let mut list = Reader(Reader(data).vec16()?);
            let mut protos = Vec::new();
            while !list.0.is_empty() {
                protos.push(list.vec8()?.to_vec());
            }
            return Some(Some(protos));
        }
    }
    Some(None)
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Build a TLS 1.2-style record containing a `ClientHello` with optional SNI and ALPN.
    pub fn client_hello(sni: Option<&str>, alpn: Option<&[&[u8]]>) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let mut entry = vec![0u8];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());
            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&entry);
            exts.extend_from_slice(&0u16.to_be_bytes());
            exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
            exts.extend_from_slice(&list);
        }
        if let Some(protos) = alpn {
            let mut list = Vec::new();
            for p in protos {
                list.push(p.len() as u8);
                list.extend_from_slice(p);
            }
            let mut data = (list.len() as u16).to_be_bytes().to_vec();
            data.extend_from_slice(&list);
            exts.extend_from_slice(&0x0010u16.to_be_bytes());
            exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
            exts.extend_from_slice(&data);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::client_hello;
    use super::*;
    use crate::socks::{guarded_first_chunk, TargetHost};

    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn target(port: u16) -> SocksTarget {
        SocksTarget {
            host: TargetHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port,
        }
    }

    fn blocked(port: u16, chunk: &[u8]) -> bool {
        WebGuard.inspect(&target(port), chunk)
            == GuardVerdict::Block {
                status: BLOCKED_STATUS.into(),
            }
    }

    #[test]
    fn blocks_plaintext_http_methods() {
        for m in HTTP_METHOD_PREFIXES {
            let mut req = m.to_vec();
            req.extend_from_slice(b"/ HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(blocked(8080, &req), "{}", String::from_utf8_lossy(m));
        }
        assert!(!blocked(8080, b"GETX / HTTP/1.1\r\n"));
        assert!(!blocked(8080, b"get / HTTP/1.1\r\n"));
    }

    #[test]
    fn parses_client_hello_alpn() {
        let hello = client_hello(Some("example.com"), Some(&[b"h2", b"http/1.1"]));
        assert_eq!(
            parse_client_hello(&hello),
            TlsHello::ClientHello {
                alpn: Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
            }
        );
        assert_eq!(
            parse_client_hello(&client_hello(Some("example.com"), None)),
            TlsHello::ClientHello { alpn: None }
        );
        assert_eq!(
            parse_client_hello(&hello[..hello.len() - 4]),
            TlsHello::Truncated
        );
        assert_eq!(
            parse_client_hello(b"SSH-2.0-x\r\n"),
            TlsHello::NotClientHello
        );
        // TLS record that is not a ClientHello (e.g. ServerHello type 0x02).
        let mut server_hello = hello.clone();
        server_hello[5] = 0x02;
        assert_eq!(parse_client_hello(&server_hello), TlsHello::NotClientHello);
    }

    #[test]
    fn blocks_tls_with_http_alpn_on_any_port() {
        for alpn in [
            &[b"h2" as &[u8]][..],
            &[b"http/1.1"],
            &[b"acme-tls/1", b"h2"],
        ] {
            assert!(blocked(8443, &client_hello(Some("a.example"), Some(alpn))));
            assert!(blocked(443, &client_hello(Some("a.example"), Some(alpn))));
        }
    }

    #[test]
    fn port_443_tls_blocked_unless_non_http_alpn() {
        assert!(blocked(443, &client_hello(Some("a.example"), None)));
        assert!(blocked(443, &client_hello(None, Some(&[]))));
        let hello = client_hello(Some("a.example"), Some(&[b"h2"]));
        assert!(blocked(443, &hello[..20]), "fragmented ClientHello on 443");
        // Non-HTTP ALPN on 443 is allowed (e.g. DNS-over-TLS style / custom protocols).
        assert!(!blocked(
            443,
            &client_hello(Some("a.example"), Some(&[b"imap"]))
        ));
        // Without HTTP ALPN, TLS to other ports is allowed.
        assert!(!blocked(993, &client_hello(Some("a.example"), None)));
        assert!(!blocked(
            993,
            &client_hello(Some("a.example"), Some(&[b"imap"]))
        ));
        assert!(!blocked(993, &hello[..20]));
    }

    #[test]
    fn allows_non_web_payloads() {
        assert!(!blocked(22, b"SSH-2.0-OpenSSH_9.6\r\n"));
        assert!(!blocked(443, b"\x00\x01\x02binary"));
        assert!(!blocked(5432, &[0, 0, 0, 8, 4, 210, 22, 47]));
        assert!(!blocked(443, b""));
    }

    #[tokio::test]
    async fn guarded_first_chunk_blocks_web_and_forwards_other_bytes() {
        // Blocked: the HTTP request never reaches the upstream side.
        let (mut client, mut client_peer) = tokio::io::duplex(1024);
        let (mut upstream, mut upstream_peer) = tokio::io::duplex(1024);
        client_peer
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let v = guarded_first_chunk(&mut client, &mut upstream, &WebGuard, &target(80))
            .await
            .unwrap();
        assert_eq!(
            v,
            GuardVerdict::Block {
                status: BLOCKED_STATUS.into()
            }
        );
        drop(upstream);
        let mut seen = Vec::new();
        upstream_peer.read_to_end(&mut seen).await.unwrap();
        assert!(seen.is_empty());

        // Allowed: a server banner flows to the client first, then the chunk is forwarded.
        let (mut client, mut client_peer) = tokio::io::duplex(1024);
        let (mut upstream, mut upstream_peer) = tokio::io::duplex(1024);
        upstream_peer
            .write_all(b"SSH-2.0-server\r\n")
            .await
            .unwrap();
        let mut banner = [0u8; 16];
        let ssh = target(22);
        let relay = guarded_first_chunk(&mut client, &mut upstream, &WebGuard, &ssh);
        let peer = async {
            client_peer.read_exact(&mut banner).await.unwrap();
            client_peer.write_all(b"SSH-2.0-client\r\n").await.unwrap();
        };
        let (v, ()) = tokio::join!(relay, peer);
        assert_eq!(v.unwrap(), GuardVerdict::Allow);
        assert_eq!(&banner, b"SSH-2.0-server\r\n");
        let mut fwd = [0u8; 16];
        upstream_peer.read_exact(&mut fwd).await.unwrap();
        assert_eq!(&fwd, b"SSH-2.0-client\r\n");
    }
}
