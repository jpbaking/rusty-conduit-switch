//! `direct`: connect from this machine using the OS/Tokio resolver (no DNS caching).

use std::sync::Arc;
use std::time::Duration;

use super::{DialFuture, UpstreamDialer, UpstreamStream};
use crate::filter::HostFilter;
use crate::net::{connect_upstream_filtered, KeepaliveSettings};

/// Dials targets directly: OS DNS on every dial, `TCP_NODELAY`, optional TCP keepalive and
/// optional destination [`HostFilter`] (checked on the name and every resolved IP).
#[derive(Debug, Clone, Default)]
pub struct DirectDialer {
    filter: Option<Arc<HostFilter>>,
    keepalive: Option<KeepaliveSettings>,
}

impl DirectDialer {
    /// A direct dialer with no filter and keepalive off.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enforce `filter` on the destination before connecting.
    pub fn with_filter(mut self, filter: Arc<HostFilter>) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set TCP keepalive for upstream sockets (`None` disables).
    pub fn with_tcp_keepalive(mut self, keepalive: Option<KeepaliveSettings>) -> Self {
        self.keepalive = keepalive;
        self
    }
}

impl UpstreamDialer for DirectDialer {
    fn connect(&self, host: &str, port: u16, timeout: Duration) -> DialFuture<'_> {
        let host = host.to_string();
        Box::pin(async move {
            let stream = connect_upstream_filtered(
                &host,
                port,
                timeout,
                self.filter.as_deref(),
                self.keepalive.as_ref(),
            )
            .await?;
            Ok(UpstreamStream::Tcp(stream))
        })
    }

    fn redacted_upstream(&self) -> String {
        "direct".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_connects_with_nodelay_and_keepalive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });
        let d = DirectDialer::new().with_tcp_keepalive(Some(KeepaliveSettings::DEFAULT));
        let mut s = d
            .connect("127.0.0.1", port, Duration::from_secs(5))
            .await
            .unwrap();
        let UpstreamStream::Tcp(tcp) = &s else {
            panic!("expected TCP stream");
        };
        assert!(tcp.nodelay().unwrap());
        assert!(socket2::SockRef::from(tcp).keepalive().unwrap());
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
        server.await.unwrap();
        assert_eq!(d.redacted_upstream(), "direct");
    }
}
