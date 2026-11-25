//! Dynamic per-host leaf certificate signing with `rcgen`.
//!
//! Every leaf gets a fresh ECDSA P-256 key pair, a cryptographically random 128-bit
//! positive serial number, `CN` = host, and a single SAN (`DNS` for names, `IP` for IP
//! literals). It is signed by the loaded CA with the validity window
//!
//! * `not_before = now - 5m` (client clock-skew protection), and
//! * `not_after  = now + TTL + 5m` (grace so a cert handed out just before its cache entry
//!   expires never expires mid-handshake or mid-connection).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    SanType, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;

use super::ca::{CaError, CaMaterial};

/// Clock-skew (`not_before`) and expiry-grace (`not_after`) buffer applied to every leaf.
pub const VALIDITY_BUFFER: Duration = Duration::from_secs(5 * 60);

/// Leaf signing failures.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("invalid MITM leaf host {0:?}")]
    InvalidHost(String),
    #[error("failed to sign MITM leaf certificate for {host}: {reason}")]
    Sign { host: String, reason: String },
    #[error(transparent)]
    Ca(#[from] CaError),
}

/// A freshly signed leaf certificate.
pub struct SignedLeaf {
    /// `[leaf, CA, intermediates…]`, ready to serve.
    pub certified: Arc<CertifiedKey>,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

/// Anything that can produce a leaf certificate for a host (the real [`LeafSigner`], or a
/// counting fake in tests).
pub trait CertSource: Send + Sync + 'static {
    fn sign(&self, host: &str) -> Result<Arc<CertifiedKey>, SignError>;
}

/// Signs per-host leaf certificates with the configured CA.
pub struct LeafSigner {
    issuer: Issuer<'static, KeyPair>,
    chain: Vec<CertificateDer<'static>>,
    ttl: Duration,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for LeafSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafSigner")
            .field("ttl", &self.ttl)
            .field("chain_len", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl LeafSigner {
    pub fn new(
        ca: &CaMaterial,
        ttl: Duration,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, SignError> {
        let issuer = Issuer::from_ca_cert_der(ca.cert(), ca.key_pair()?)
            .map_err(|e| CaError::Certificate(e.to_string()))?;
        Ok(Self {
            issuer,
            chain: ca.chain().to_vec(),
            ttl,
            provider,
        })
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Sign a leaf for `host` valid relative to `now`.
    pub fn sign_at(&self, host: &str, now: OffsetDateTime) -> Result<SignedLeaf, SignError> {
        let host = normalize_host(host);
        if host.is_empty() {
            return Err(SignError::InvalidHost(host));
        }
        let err = |reason: String| SignError::Sign {
            host: host.clone(),
            reason,
        };
        let san = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) if !is_dns_name(&host) => return Err(SignError::InvalidHost(host)),
            Err(_) => SanType::DnsName(
                host.clone()
                    .try_into()
                    .map_err(|_| SignError::InvalidHost(host.clone()))?,
            ),
        };

        let mut serial = [0u8; 16];
        self.provider
            .secure_random
            .fill(&mut serial)
            .map_err(|_| err("random number generator failure".into()))?;
        // Positive (encoded with a leading zero) and full 128-bit magnitude.
        serial[0] |= 0x80;

        let not_before = now - VALIDITY_BUFFER;
        let not_after = now + self.ttl + VALIDITY_BUFFER;

        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, &host);
        params.subject_alt_names = vec![san];
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params.not_before = not_before;
        params.not_after = not_after;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let leaf_key =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| err(e.to_string()))?;
        let cert = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| err(e.to_string()))?;

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key = self
            .provider
            .key_provider
            .load_private_key(key_der)
            .map_err(|e| err(e.to_string()))?;
        let mut chain = Vec::with_capacity(self.chain.len() + 1);
        chain.push(cert.der().clone());
        chain.extend(self.chain.iter().cloned());
        Ok(SignedLeaf {
            certified: Arc::new(CertifiedKey::new(chain, signing_key)),
            not_before,
            not_after,
        })
    }
}

impl CertSource for LeafSigner {
    fn sign(&self, host: &str) -> Result<Arc<CertifiedKey>, SignError> {
        self.sign_at(host, OffsetDateTime::now_utc())
            .map(|l| l.certified)
    }
}

/// Letters, digits, `-`, `_`, and `.`-separated non-empty labels of at most 63 bytes.
fn is_dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Canonical cache/SAN form of a host: lowercase, no IPv6 brackets, no trailing dot.
pub fn normalize_host(host: &str) -> String {
    let h = host.trim();
    let h = h
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(h);
    h.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::ca::test_support::test_ca;
    use crate::mitm::crypto_provider;

    use std::net::Ipv6Addr;

    use rustls::client::danger::ServerCertVerifier;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::RootCertStore;
    use x509_parser::extensions::GeneralName;

    fn signer(ttl: Duration) -> (LeafSigner, CertificateDer<'static>) {
        let ca = test_ca();
        let m = CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None)
            .unwrap()
            .validate()
            .unwrap();
        (
            LeafSigner::new(&m, ttl, crypto_provider()).unwrap(),
            m.cert().clone(),
        )
    }

    fn verify(ca: &CertificateDer<'static>, leaf: &CertifiedKey, name: &str, at: OffsetDateTime) {
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crypto_provider())
                .build()
                .unwrap();
        let secs = u64::try_from(at.unix_timestamp()).unwrap();
        verifier
            .verify_server_cert(
                &leaf.cert[0],
                &leaf.cert[1..],
                &ServerName::try_from(name.to_string()).unwrap(),
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(secs)),
            )
            .unwrap();
    }

    #[test]
    fn dns_leaf_has_san_and_chains_to_ca() {
        let (s, ca) = signer(Duration::from_secs(3600));
        let now = OffsetDateTime::now_utc();
        let leaf = s.sign_at("Example.COM.", now).unwrap();
        assert_eq!(leaf.certified.cert.len(), 2);
        assert_eq!(leaf.certified.cert[1], ca);
        verify(&ca, &leaf.certified, "example.com", now);

        let (_, x509) = x509_parser::parse_x509_certificate(&leaf.certified.cert[0]).unwrap();
        let san = x509.subject_alternative_name().unwrap().unwrap();
        assert_eq!(
            san.value.general_names,
            vec![GeneralName::DNSName("example.com")]
        );
        assert!(x509.subject().to_string().contains("CN=example.com"));
        assert!(!x509.is_ca());
        // Random positive 128-bit serial.
        assert_eq!(x509.serial.bits(), 128);
        let other = s.sign_at("example.com", now).unwrap();
        let (_, x2) = x509_parser::parse_x509_certificate(&other.certified.cert[0]).unwrap();
        assert_ne!(x509.serial, x2.serial);
        // Fresh P-256 key per leaf.
        assert_eq!(
            x509.public_key().algorithm.algorithm.to_id_string(),
            "1.2.840.10045.2.1"
        );
        assert_ne!(
            x509.public_key().subject_public_key.data,
            x2.public_key().subject_public_key.data
        );
    }

    #[test]
    fn ip_leaves_use_ip_sans() {
        let (s, ca) = signer(Duration::from_secs(3600));
        let now = OffsetDateTime::now_utc();
        let v4 = s.sign_at("127.0.0.1", now).unwrap();
        verify(&ca, &v4.certified, "127.0.0.1", now);
        let (_, x509) = x509_parser::parse_x509_certificate(&v4.certified.cert[0]).unwrap();
        let san = x509.subject_alternative_name().unwrap().unwrap();
        assert_eq!(
            san.value.general_names,
            vec![GeneralName::IPAddress(&[127, 0, 0, 1])]
        );

        let v6 = s.sign_at("[::1]", now).unwrap();
        verify(&ca, &v6.certified, "::1", now);
        let (_, x509) = x509_parser::parse_x509_certificate(&v6.certified.cert[0]).unwrap();
        let san = x509.subject_alternative_name().unwrap().unwrap();
        assert_eq!(
            san.value.general_names,
            vec![GeneralName::IPAddress(&Ipv6Addr::LOCALHOST.octets())]
        );
    }

    #[test]
    fn validity_window_is_now_minus_5m_to_now_plus_ttl_plus_5m() {
        let ttl = Duration::from_secs(1800);
        let (s, ca) = signer(ttl);
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let leaf = s.sign_at("example.com", now).unwrap();
        assert_eq!(leaf.not_before, now - Duration::from_secs(300));
        assert_eq!(leaf.not_after, now + ttl + Duration::from_secs(300));

        let (_, x509) = x509_parser::parse_x509_certificate(&leaf.certified.cert[0]).unwrap();
        let v = x509.validity();
        assert_eq!(
            v.not_before.timestamp(),
            (now - Duration::from_secs(300)).unix_timestamp()
        );
        assert_eq!(
            v.not_after.timestamp(),
            (now + Duration::from_secs(1800 + 300)).unix_timestamp()
        );

        // Valid inside the window (incl. skewed client clocks), rejected outside it.
        verify(
            &ca,
            &leaf.certified,
            "example.com",
            now - Duration::from_secs(299),
        );
        verify(
            &ca,
            &leaf.certified,
            "example.com",
            now + ttl + Duration::from_secs(299),
        );
        let mut roots = RootCertStore::empty();
        roots.add(ca).unwrap();
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crypto_provider())
                .build()
                .unwrap();
        let late = now + ttl + Duration::from_secs(301);
        let late = UnixTime::since_unix_epoch(Duration::from_secs(late.unix_timestamp() as u64));
        assert!(verifier
            .verify_server_cert(
                &leaf.certified.cert[0],
                &[],
                &ServerName::try_from("example.com").unwrap(),
                &[],
                late,
            )
            .is_err());
    }

    #[test]
    fn rejects_invalid_hosts() {
        let (s, _) = signer(Duration::from_secs(60));
        assert!(matches!(s.sign("  "), Err(SignError::InvalidHost(_))));
        assert!(matches!(s.sign("bad host"), Err(SignError::InvalidHost(_))));
        assert!(matches!(s.sign("a..b"), Err(SignError::InvalidHost(_))));
    }

    #[test]
    fn normalizes_hosts() {
        assert_eq!(normalize_host("WWW.Example.com."), "www.example.com");
        assert_eq!(normalize_host("[::1]"), "::1");
        assert_eq!(normalize_host("10.0.0.1"), "10.0.0.1");
    }
}
