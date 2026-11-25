//! HTTPS MITM support: CA loading ([`ca`]), per-host leaf signing ([`signer`]), and the
//! TTL-bounded leaf certificate cache ([`cache`]) — the only cache in rusty-conduit-switch. The
//! interception itself lives in [`crate::http::mitm_tunnel`].

pub mod ca;
pub mod cache;
pub mod signer;

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use time::OffsetDateTime;

use crate::config::{Config, ConfigError};
use crate::http::mitm_tunnel::{platform_client_config, MitmInterceptor};
use ca::{CaError, CaMaterial};
use cache::CertCache;
use signer::{LeafSigner, SignError};

/// The process-wide TLS crypto provider: `ring` (pure-Rust stack, no `aws-lc-rs`).
///
/// Passed explicitly to every rustls config builder, so no global default provider has to
/// be installed.
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Startup failures while enabling MITM mode (all are `FATAL`).
#[derive(Debug, thiserror::Error)]
pub enum MitmError {
    #[error(transparent)]
    Passphrase(#[from] ConfigError),
    #[error(transparent)]
    Ca(#[from] CaError),
    #[error(transparent)]
    Signer(#[from] SignError),
    #[error("failed to initialise upstream TLS verification: {0}")]
    UpstreamTls(#[from] rustls::Error),
}

/// Everything MITM mode needs at runtime, built once at startup.
#[derive(Debug)]
pub struct MitmState {
    pub interceptor: MitmInterceptor,
    pub cache: Arc<CertCache>,
    pub ca_subject: String,
    pub ca_not_after: OffsetDateTime,
}

impl MitmState {
    /// Load and validate the configured CA and build the signer, cache, and interceptor
    /// (upstream TLS verified with the platform verifier). Returns `Ok(None)` when MITM is
    /// OFF (no CA configured).
    pub fn from_config(cfg: &Config) -> Result<Option<Self>, MitmError> {
        let Some(source) = cfg.ca_source() else {
            return Ok(None);
        };
        let provider = crypto_provider();
        let upstream = platform_client_config(Arc::clone(&provider))?;
        Self::build(cfg, &source, provider, upstream).map(Some)
    }

    /// Like [`Self::from_config`] but with an explicit upstream TLS client config.
    pub fn build(
        cfg: &Config,
        source: &crate::config::CaSource,
        provider: Arc<CryptoProvider>,
        upstream: rustls::ClientConfig,
    ) -> Result<Self, MitmError> {
        let passphrase = cfg.resolve_passphrase()?;
        let ca = CaMaterial::load(source, passphrase.as_deref())?;
        let signer = LeafSigner::new(&ca, cfg.mitm_cert_ttl, Arc::clone(&provider))?;
        let cache = Arc::new(
            CertCache::new(Arc::new(signer), cfg.mitm_cert_ttl)
                .with_max_entries(cfg.mitm_cert_cache_max),
        );
        let interceptor = MitmInterceptor::new(Arc::clone(&cache), Arc::new(upstream), provider);
        Ok(Self {
            interceptor,
            cache,
            ca_subject: ca.subject().to_string(),
            ca_not_after: ca.not_after(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::ca::test_support::{ca_with_validity, test_ca};

    use std::fs;
    use std::time::Duration;

    fn cfg_with(dir: &std::path::Path, ca: &ca::test_support::TestCa) -> Config {
        let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
        fs::write(&cert, &ca.cert_pem).unwrap();
        fs::write(&key, &ca.key_pem).unwrap();
        Config {
            mitm_ca_cert: Some(cert),
            mitm_ca_key: Some(key),
            mitm_cert_ttl: Duration::from_secs(600),
            ..Config::default()
        }
    }

    #[test]
    fn mitm_off_without_ca() {
        assert!(MitmState::from_config(&Config::default())
            .unwrap()
            .is_none());
    }

    #[test]
    fn builds_state_from_pem_files_and_rejects_expired_ca() {
        let dir = std::env::temp_dir().join(format!("rc-mitm-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let cfg = cfg_with(&dir, &test_ca());
        let state = MitmState::from_config(&cfg).unwrap().unwrap();
        assert!(state.ca_subject.contains("Rusty Conduit Test CA"));
        assert_eq!(state.cache.ttl(), Duration::from_secs(600));
        assert_eq!(
            state.cache.max_entries(),
            crate::config::DEFAULT_MITM_CERT_CACHE_MAX
        );
        assert!(state.cache.is_empty());

        let mut capped = cfg_with(&dir, &test_ca());
        capped.mitm_cert_cache_max = 7;
        let state = MitmState::from_config(&capped).unwrap().unwrap();
        assert_eq!(state.cache.max_entries(), 7);

        let now = OffsetDateTime::now_utc();
        let expired =
            ca_with_validity(now - time::Duration::days(3), now - time::Duration::days(1));
        let cfg = cfg_with(&dir, &expired);
        let err = MitmState::from_config(&cfg).unwrap_err();
        assert!(matches!(err, MitmError::Ca(CaError::Expired(_))), "{err}");
        assert!(err.to_string().contains("expired"), "{err}");

        let mut cfg = cfg_with(&dir, &test_ca());
        cfg.mitm_ca_passphrase_file = Some(dir.join("missing-pass"));
        assert!(matches!(
            MitmState::from_config(&cfg),
            Err(MitmError::Passphrase(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }
}
