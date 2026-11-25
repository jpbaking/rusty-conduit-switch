//! `block`: refuse the connection without touching DNS or the network.

use std::time::Duration;

use super::{DialFuture, RouteBlocked, UpstreamDialer};

/// Always fails with [`RouteBlocked`] (`ErrorKind::PermissionDenied`).
#[derive(Debug, Clone)]
pub struct BlockDialer {
    profile: String,
}

impl BlockDialer {
    /// A block dialer reporting `profile` as the blocking profile.
    pub fn new(profile: impl Into<String>) -> Self {
        Self {
            profile: profile.into(),
        }
    }
}

impl Default for BlockDialer {
    fn default() -> Self {
        Self::new(crate::config::PROFILE_BLOCK)
    }
}

impl UpstreamDialer for BlockDialer {
    fn connect(&self, _host: &str, _port: u16, _timeout: Duration) -> DialFuture<'_> {
        let err = RouteBlocked {
            profile: self.profile.clone(),
        }
        .into_io();
        Box::pin(async move { Err(err) })
    }

    fn redacted_upstream(&self) -> String {
        "block".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::is_route_blocked;

    #[tokio::test]
    async fn block_returns_route_blocked_without_dns() {
        // An unresolvable name would fail differently if DNS were touched.
        let err = BlockDialer::default()
            .connect("does-not-exist.invalid", 443, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(is_route_blocked(&err));
        assert!(err.to_string().contains("`block`"));
    }
}
