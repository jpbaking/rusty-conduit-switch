//! MITM certificate-authority loading and startup validation.
//!
//! The CA is **always** user-supplied (it is never auto-generated):
//!
//! * **PEM** (`--mitm-ca-cert` + `--mitm-ca-key`): the certificate file holds the CA
//!   certificate (optionally followed by intermediates); the key file holds one private key
//!   as PKCS#8 (`PRIVATE KEY`), PKCS#1 RSA (`RSA PRIVATE KEY`), SEC1 EC (`EC PRIVATE KEY`),
//!   or passphrase-encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`, PBES2 or PKCS#12 PBE schemes).
//!   Legacy OpenSSL `Proc-Type: 4,ENCRYPTED` PEM keys are rejected with a conversion hint.
//! * **PKCS#12** (`--mitm-ca-p12`): `.p12`/`.pfx` parsed in pure Rust by `p12-keystore`
//!   (PBES2/AES as written by OpenSSL 3, and legacy PBE schemes), using the optional
//!   passphrase (empty when none is configured).
//!
//! [`CaMaterial::validate_at`] checks that the certificate parses, is currently within its
//! validity window, and matches the private key. Any failure is a startup `FATAL`.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use p12_keystore::Pkcs12Archive;
use rcgen::KeyPair;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;
use x509_parser::pem::Pem;

use crate::config::CaSource;

/// Errors raised while loading or validating the MITM CA.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("failed to read MITM CA file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("no PEM certificate found in MITM CA certificate input")]
    NoCertificate,
    #[error("no private key found in MITM CA key input")]
    NoKey,
    #[error("invalid PEM in MITM CA input: {0}")]
    Pem(String),
    #[error(
        "legacy OpenSSL-encrypted PEM keys (Proc-Type: 4,ENCRYPTED) are not supported; \
         convert with `openssl pkcs8 -topk8 -v2 aes-256-cbc` or use a PKCS#12 bundle"
    )]
    LegacyEncryptedPem,
    #[error("the MITM CA private key is encrypted but no passphrase was provided")]
    PassphraseRequired,
    #[error("failed to decrypt the MITM CA private key (wrong passphrase?): {0}")]
    Decrypt(String),
    #[error("unsupported or malformed MITM CA private key: {0}")]
    Key(String),
    #[error("failed to parse PKCS#12 MITM CA bundle (wrong passphrase?): {0}")]
    Pkcs12(String),
    #[error("PKCS#12 MITM CA bundle contains no private key")]
    Pkcs12NoKey,
    #[error("PKCS#12 MITM CA bundle contains no certificate")]
    Pkcs12NoCertificate,
    #[error("failed to parse the MITM CA certificate: {0}")]
    Certificate(String),
    #[error("the MITM CA certificate is not valid until {0}")]
    NotYetValid(String),
    #[error("the MITM CA certificate expired at {0}")]
    Expired(String),
    #[error("the MITM CA private key does not match the CA certificate")]
    KeyMismatch,
}

/// A loaded, validated CA: certificate chain (`chain[0]` is the signing CA) and its
/// PKCS#8 private key.
pub struct CaMaterial {
    chain: Vec<CertificateDer<'static>>,
    key: PrivatePkcs8KeyDer<'static>,
    subject: String,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl fmt::Debug for CaMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaMaterial")
            .field("subject", &self.subject)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("chain_len", &self.chain.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl CaMaterial {
    /// Load and validate the CA described by `source` (reads the files from disk).
    pub fn load(source: &CaSource, passphrase: Option<&str>) -> Result<Self, CaError> {
        match source {
            CaSource::Pem { cert, key } => {
                Self::from_pem(&read(cert)?, &read(key)?, passphrase)?.validate()
            }
            CaSource::Pkcs12 { path } => Self::from_pkcs12(&read(path)?, passphrase)?.validate(),
        }
    }

    /// Parse PEM certificate + key input (not yet validated; see [`Self::validate_at`]).
    pub fn from_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Self, CaError> {
        let chain: Vec<CertificateDer<'static>> = pem_blocks(cert_pem)?
            .into_iter()
            .filter(|p| p.label == "CERTIFICATE" || p.label == "TRUSTED CERTIFICATE")
            .map(|p| CertificateDer::from(p.contents))
            .collect();
        if chain.is_empty() {
            return Err(CaError::NoCertificate);
        }
        let key = key_from_pem(key_pem, passphrase)?;
        Self::assemble(chain, key)
    }

    /// Parse a PKCS#12 bundle (not yet validated; see [`Self::validate_at`]).
    ///
    /// The certificate whose public key matches the bundled private key becomes the signing
    /// CA; any other certificates are kept as chain certificates after it.
    pub fn from_pkcs12(data: &[u8], passphrase: Option<&str>) -> Result<Self, CaError> {
        let archive = Pkcs12Archive::from_pkcs12(data, passphrase.unwrap_or(""))
            .map_err(|e| CaError::Pkcs12(e.to_string()))?;
        if archive.keys.is_empty() {
            return Err(CaError::Pkcs12NoKey);
        }
        let certs: Vec<CertificateDer<'static>> = archive
            .certs
            .iter()
            .map(|b| CertificateDer::from(b.cert.as_der().to_vec()))
            .collect();
        if certs.is_empty() {
            return Err(CaError::Pkcs12NoCertificate);
        }
        for bag in &archive.keys {
            let key = PrivatePkcs8KeyDer::from(bag.key.as_der().to_vec());
            let Ok(pair) = KeyPair::try_from(&key) else {
                continue;
            };
            if let Some(idx) = certs.iter().position(|c| cert_matches_key(c, &pair)) {
                let mut chain = certs.clone();
                let ca = chain.remove(idx);
                chain.insert(0, ca);
                return Self::assemble(chain, key);
            }
        }
        Err(CaError::KeyMismatch)
    }

    fn assemble(
        chain: Vec<CertificateDer<'static>>,
        key: PrivatePkcs8KeyDer<'static>,
    ) -> Result<Self, CaError> {
        let (_, x509) = x509_parser::parse_x509_certificate(&chain[0])
            .map_err(|e| CaError::Certificate(e.to_string()))?;
        let validity = x509.validity();
        let ts = |t: &x509_parser::time::ASN1Time| {
            OffsetDateTime::from_unix_timestamp(t.timestamp())
                .map_err(|e| CaError::Certificate(e.to_string()))
        };
        let not_before = ts(&validity.not_before)?;
        let not_after = ts(&validity.not_after)?;
        let subject = x509.subject().to_string();
        Ok(Self {
            chain,
            key,
            subject,
            not_before,
            not_after,
        })
    }

    /// Validate against the current wall clock.
    pub fn validate(self) -> Result<Self, CaError> {
        self.validate_at(OffsetDateTime::now_utc())
    }

    /// Check the validity window at `now` and that the private key matches the certificate.
    pub fn validate_at(self, now: OffsetDateTime) -> Result<Self, CaError> {
        if now < self.not_before {
            return Err(CaError::NotYetValid(fmt_time(self.not_before)));
        }
        if now > self.not_after {
            return Err(CaError::Expired(fmt_time(self.not_after)));
        }
        let pair = self.key_pair()?;
        if !cert_matches_key(&self.chain[0], &pair) {
            return Err(CaError::KeyMismatch);
        }
        Ok(self)
    }

    /// The signing key as an `rcgen` key pair.
    pub fn key_pair(&self) -> Result<KeyPair, CaError> {
        KeyPair::try_from(&self.key).map_err(|e| CaError::Key(e.to_string()))
    }

    /// CA certificate chain; `chain()[0]` is the signing CA.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    /// The signing CA certificate.
    pub fn cert(&self) -> &CertificateDer<'static> {
        &self.chain[0]
    }

    /// CA subject distinguished name (RFC 4514 style).
    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn not_before(&self) -> OffsetDateTime {
        self.not_before
    }

    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }
}

fn read(path: &Path) -> Result<Vec<u8>, CaError> {
    fs::read(path).map_err(|source| CaError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn fmt_time(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.to_string())
}

/// Does `cert`'s subject public key equal the public key of `pair`?
fn cert_matches_key(cert: &CertificateDer<'_>, pair: &KeyPair) -> bool {
    match x509_parser::parse_x509_certificate(cert) {
        Ok((_, x509)) => {
            x509.public_key().subject_public_key.data.as_ref() == pair.public_key_raw()
        }
        Err(_) => false,
    }
}

/// All PEM blocks in `input` (text outside blocks is ignored).
fn pem_blocks(input: &[u8]) -> Result<Vec<Pem>, CaError> {
    let mut out = Vec::new();
    for item in Pem::iter_from_buffer(input) {
        match item {
            Ok(pem) => out.push(pem),
            Err(x509_parser::error::PEMError::MissingHeader) => break,
            Err(e) => return Err(CaError::Pem(e.to_string())),
        }
    }
    Ok(out)
}

/// Extract the first private key from PEM input as PKCS#8.
fn key_from_pem(
    input: &[u8],
    passphrase: Option<&str>,
) -> Result<PrivatePkcs8KeyDer<'static>, CaError> {
    if String::from_utf8_lossy(input).contains("Proc-Type: 4,ENCRYPTED") {
        return Err(CaError::LegacyEncryptedPem);
    }
    for block in pem_blocks(input)? {
        let der = match block.label.as_str() {
            "PRIVATE KEY" => block.contents,
            "RSA PRIVATE KEY" => wrap_pkcs1_rsa(&block.contents),
            "EC PRIVATE KEY" => return sec1_to_pkcs8(&block.contents),
            "ENCRYPTED PRIVATE KEY" => {
                let pass = passphrase.ok_or(CaError::PassphraseRequired)?;
                decrypt_pkcs8(&block.contents, pass)?
            }
            _ => continue,
        };
        return Ok(PrivatePkcs8KeyDer::from(der));
    }
    Err(CaError::NoKey)
}

// --- Minimal DER encoding helpers (used only to re-wrap keys for `rcgen`/`ring`). ---

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_CONTEXT_0: u8 = 0xA0;
/// OID 1.2.840.113549.1.7.1 (`id-data`), full TLV.
const OID_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
];
/// OID 1.2.840.113549.1.12.10.1.2 (`pkcs8ShroudedKeyBag`), full TLV.
const OID_SHROUDED_KEY_BAG: &[u8] = &[
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02,
];
/// `AlgorithmIdentifier { rsaEncryption, NULL }`, full TLV.
const ALG_RSA: &[u8] = &[
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
];
/// OID 1.2.840.10045.2.1 (`id-ecPublicKey`), full TLV.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// Named-curve OIDs (full TLV) accepted for SEC1 keys: P-256, P-384.
const EC_CURVES: [&[u8]; 2] = [
    &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
];

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn der_seq(parts: &[&[u8]]) -> Vec<u8> {
    der_tlv(TAG_SEQUENCE, &parts.concat())
}

/// `PrivateKeyInfo { version 0, algorithm, OCTET STRING key }`.
fn pkcs8(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
    der_seq(&[
        &[TAG_INTEGER, 0x01, 0x00],
        algorithm,
        &der_tlv(TAG_OCTET_STRING, key),
    ])
}

fn wrap_pkcs1_rsa(pkcs1: &[u8]) -> Vec<u8> {
    pkcs8(ALG_RSA, pkcs1)
}

/// Wrap a SEC1 `ECPrivateKey` as PKCS#8, trying each supported named curve.
fn sec1_to_pkcs8(sec1: &[u8]) -> Result<PrivatePkcs8KeyDer<'static>, CaError> {
    for curve in EC_CURVES {
        let der = PrivatePkcs8KeyDer::from(pkcs8(&der_seq(&[OID_EC_PUBLIC_KEY, curve]), sec1));
        if KeyPair::try_from(&der).is_ok() {
            return Ok(der);
        }
    }
    Err(CaError::Key(
        "EC PRIVATE KEY is not a P-256 or P-384 key".into(),
    ))
}

/// Decrypt a PKCS#8 `EncryptedPrivateKeyInfo` by wrapping it in a minimal, MAC-less
/// PKCS#12 `pkcs8ShroudedKeyBag` and letting `p12-keystore` decrypt it (it implements the
/// same PBES2 / PKCS#12-PBE schemes used for encrypted PEM keys).
fn decrypt_pkcs8(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, CaError> {
    let bag = der_seq(&[OID_SHROUDED_KEY_BAG, &der_tlv(TAG_CONTEXT_0, encrypted)]);
    let safe_contents = der_seq(&[&bag]);
    let content_info = |inner: &[u8]| {
        der_seq(&[
            OID_DATA,
            &der_tlv(TAG_CONTEXT_0, &der_tlv(TAG_OCTET_STRING, inner)),
        ])
    };
    let auth_safe = der_seq(&[&content_info(&safe_contents)]);
    let pfx = der_seq(&[&[TAG_INTEGER, 0x01, 0x03], &content_info(&auth_safe)]);
    let archive = Pkcs12Archive::from_pkcs12(&pfx, passphrase)
        .map_err(|e| CaError::Decrypt(e.to_string()))?;
    archive
        .keys
        .into_iter()
        .next()
        .map(|k| k.key.as_der().to_vec())
        .ok_or_else(|| CaError::Decrypt("key could not be decrypted".into()))
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Ephemeral test CAs generated with `rcgen`.

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    use time::{Duration, OffsetDateTime};

    /// An ephemeral CA as PEM strings.
    pub struct TestCa {
        pub cert_pem: String,
        pub key_pem: String,
        pub cert_der: Vec<u8>,
        pub key_der: Vec<u8>,
    }

    /// Generate an ECDSA P-256 CA valid from `nb` to `na`.
    pub fn ca_with_validity(nb: OffsetDateTime, na: OffsetDateTime) -> TestCa {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Rusty Conduit Test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = nb;
        params.not_after = na;
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }

    /// A currently valid ephemeral CA.
    pub fn test_ca() -> TestCa {
        let now = OffsetDateTime::now_utc();
        ca_with_validity(now - Duration::days(1), now + Duration::days(365))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    use p12_keystore::{
        Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain,
    };
    use time::Duration;

    fn p12_bytes(ca: &TestCa, password: &str, alg: EncryptionAlgorithm) -> Vec<u8> {
        let mut ks = KeyStore::new();
        let chain = PrivateKeyChain::new(
            b"key-id".to_vec(),
            PrivateKey::from_der(&ca.key_der).unwrap(),
            [Certificate::from_der(&ca.cert_der).unwrap()],
        );
        ks.add_entry("ca", KeyStoreEntry::PrivateKeyChain(chain));
        ks.writer(password)
            .encryption_algorithm(alg)
            .write()
            .unwrap()
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn loads_ephemeral_pem_ca() {
        let ca = test_ca();
        let m = CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None)
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(m.cert().as_ref(), ca.cert_der.as_slice());
        assert!(
            m.subject().contains("Rusty Conduit Test CA"),
            "{}",
            m.subject()
        );
        assert_eq!(m.chain().len(), 1);
    }

    #[test]
    fn loads_pem_ca_from_files() {
        let ca = test_ca();
        let dir = std::env::temp_dir().join(format!("rc-ca-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
        fs::write(&cert, &ca.cert_pem).unwrap();
        fs::write(&key, &ca.key_pem).unwrap();
        let m = CaMaterial::load(&CaSource::Pem { cert, key }, None).unwrap();
        assert_eq!(m.cert().as_ref(), ca.cert_der.as_slice());

        let missing = CaSource::Pkcs12 {
            path: dir.join("missing.p12"),
        };
        assert!(matches!(
            CaMaterial::load(&missing, None),
            Err(CaError::Read { .. })
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn loads_ephemeral_pkcs12_with_and_without_passphrase() {
        let ca = test_ca();
        for alg in [
            EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
            EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
        ] {
            let with = p12_bytes(&ca, "s3cret", alg);
            let m = CaMaterial::from_pkcs12(&with, Some("s3cret"))
                .unwrap()
                .validate()
                .unwrap();
            assert_eq!(m.cert().as_ref(), ca.cert_der.as_slice());
            assert!(matches!(
                CaMaterial::from_pkcs12(&with, Some("wrong")),
                Err(CaError::Pkcs12(_))
            ));
            assert!(matches!(
                CaMaterial::from_pkcs12(&with, None),
                Err(CaError::Pkcs12(_))
            ));

            let without = p12_bytes(&ca, "", alg);
            let m = CaMaterial::from_pkcs12(&without, None)
                .unwrap()
                .validate()
                .unwrap();
            assert_eq!(m.cert().as_ref(), ca.cert_der.as_slice());
        }
    }

    #[test]
    fn loads_openssl_generated_fixtures() {
        // PEM cert + SEC1, encrypted PKCS#8 (PBES2/AES-256-CBC), and PKCS#1 RSA keys.
        let m = CaMaterial::from_pem(FX_EC_CERT.as_bytes(), FX_EC_SEC1.as_bytes(), None)
            .unwrap()
            .validate()
            .unwrap();
        let ec_cert = m.cert().to_vec();
        let m = CaMaterial::from_pem(
            FX_EC_CERT.as_bytes(),
            FX_EC_ENCRYPTED.as_bytes(),
            Some("fixture-pass"),
        )
        .unwrap()
        .validate()
        .unwrap();
        assert_eq!(m.cert().as_ref(), ec_cert.as_slice());
        assert!(matches!(
            CaMaterial::from_pem(FX_EC_CERT.as_bytes(), FX_EC_ENCRYPTED.as_bytes(), None),
            Err(CaError::PassphraseRequired)
        ));
        assert!(matches!(
            CaMaterial::from_pem(
                FX_EC_CERT.as_bytes(),
                FX_EC_ENCRYPTED.as_bytes(),
                Some("nope")
            ),
            Err(CaError::Decrypt(_))
        ));
        CaMaterial::from_pem(FX_RSA_CERT.as_bytes(), FX_RSA_PKCS1.as_bytes(), None)
            .unwrap()
            .validate()
            .unwrap();

        // OpenSSL 3 `pkcs12 -export` (PBES2/AES-256-CBC + HMAC-SHA256), `-legacy`
        // (RC2-40 + SHA1 MAC), and empty-password bundles.
        for (p12, pass) in [
            (FX_P12_PBES2, Some("fixture-pass")),
            (FX_P12_LEGACY, Some("fixture-pass")),
            (FX_P12_NOPASS, None),
        ] {
            let m = CaMaterial::from_pkcs12(&hex(p12), pass)
                .unwrap()
                .validate()
                .unwrap();
            assert_eq!(m.cert().as_ref(), ec_cert.as_slice());
        }
    }

    #[test]
    fn rejects_invalid_and_expired_inputs() {
        let ca = test_ca();
        let other = test_ca();
        let now = OffsetDateTime::now_utc();

        assert!(matches!(
            CaMaterial::from_pem(b"not pem", ca.key_pem.as_bytes(), None),
            Err(CaError::NoCertificate)
        ));
        assert!(matches!(
            CaMaterial::from_pem(ca.cert_pem.as_bytes(), b"", None),
            Err(CaError::NoKey)
        ));
        assert!(matches!(
            CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.cert_pem.as_bytes(), None),
            Err(CaError::NoKey)
        ));
        let garbage = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(matches!(
            CaMaterial::from_pem(garbage.as_bytes(), ca.key_pem.as_bytes(), None),
            Err(CaError::Certificate(_))
        ));
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
                      DEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(matches!(
            CaMaterial::from_pem(ca.cert_pem.as_bytes(), legacy.as_bytes(), None),
            Err(CaError::LegacyEncryptedPem)
        ));

        // Key belonging to a different CA.
        let mismatched =
            CaMaterial::from_pem(ca.cert_pem.as_bytes(), other.key_pem.as_bytes(), None).unwrap();
        assert!(matches!(mismatched.validate(), Err(CaError::KeyMismatch)));

        // Expired and not-yet-valid certificates.
        let expired = ca_with_validity(now - Duration::days(10), now - Duration::days(1));
        let m = CaMaterial::from_pem(
            expired.cert_pem.as_bytes(),
            expired.key_pem.as_bytes(),
            None,
        )
        .unwrap();
        assert!(matches!(m.validate(), Err(CaError::Expired(_))));
        let future = ca_with_validity(now + Duration::days(1), now + Duration::days(10));
        let m = CaMaterial::from_pem(future.cert_pem.as_bytes(), future.key_pem.as_bytes(), None)
            .unwrap();
        assert!(matches!(m.validate(), Err(CaError::NotYetValid(_))));
        // ... and `validate_at` honours the supplied clock.
        let m = CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None).unwrap();
        assert!(matches!(
            m.validate_at(now + Duration::days(400)),
            Err(CaError::Expired(_))
        ));

        // Corrupt PKCS#12 data.
        assert!(matches!(
            CaMaterial::from_pkcs12(b"\x30\x03\x02\x01\x03", None),
            Err(CaError::Pkcs12(_))
        ));
    }

    #[test]
    fn debug_output_redacts_key() {
        let ca = test_ca();
        let m = CaMaterial::from_pem(ca.cert_pem.as_bytes(), ca.key_pem.as_bytes(), None).unwrap();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("<redacted>"), "{dbg}");
        assert!(!dbg.contains("BEGIN"), "{dbg}");
    }

    // ---- OpenSSL 3.5 generated fixtures (100-year validity, test-only keys). ----
    const FX_EC_CERT: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBrTCCAVOgAwIBAgIUVrCdpL2+40gpr2sy/3UYfvrP5XowCgYIKoZIzj0EAwIw\n\
IzEhMB8GA1UEAwwYUnVzdHkgQ29uZHVpdCBGaXh0dXJlIENBMCAXDTI2MTEyMjE0\n\
NDkyNVoYDzIxMjYxMDI5MTQ0OTI1WjAjMSEwHwYDVQQDDBhSdXN0eSBDb25kdWl0\n\
IEZpeHR1cmUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARA0uKKkCBEdzkL\n\
/qZeo+PwB3xXw3Ug5Qasjw22ERB7qKGVZfM2QA9Y8B/iEnNOBG1YDLTrm9+r/N+D\n\
DNRpRzsvo2MwYTAdBgNVHQ4EFgQUSgcM6Ubk7hGl3vLn/UZ3QJbRseAwHwYDVR0j\n\
BBgwFoAUSgcM6Ubk7hGl3vLn/UZ3QJbRseAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n\
HQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhAKfRWKn9APedYQ3uTupxSCr+\n\
VaRw8mjBW5CI1bx/G1ZgAiA9Ln7v5TQDzFtUq7uF7ImT3CwMJ+rIEzn3IEvwwwGD\n\
hQ==\n\
-----END CERTIFICATE-----\n\
";
    const FX_EC_SEC1: &str = "\
-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIEb60joegT0s1zR29whCTkF2l3ifAWoAUdvTg0MjItX2oAoGCCqGSM49\n\
AwEHoUQDQgAEQNLiipAgRHc5C/6mXqPj8Ad8V8N1IOUGrI8NthEQe6ihlWXzNkAP\n\
WPAf4hJzTgRtWAy065vfq/zfgwzUaUc7Lw==\n\
-----END EC PRIVATE KEY-----\n\
";
    const FX_EC_ENCRYPTED: &str = "\
-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDWbC245/zZyoLDsZYC\n\
mKbAAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQWnKh7eraU/M53GZn\n\
/tAMOgSBkMw+mY9es8LiIEVTJhtX67dIYbcZ5U36ti0E8FSKiMWSlP9Hae7+dzgI\n\
4e1D3s2kVTWtHQuJ9ATtCg787KLqCzr0yY2vfo6+nDbFHhcgNe7ow8wSZvB7MDwx\n\
q4PcbNRvKv3mmoFc8aaZJj6ZiSVwGLXwyneMRMYMXLiIMwzuw4qljXiGuFLmjbGZ\n\
joxcsWrS3A==\n\
-----END ENCRYPTED PRIVATE KEY-----\n\
";
    const FX_RSA_CERT: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIDQTCCAimgAwIBAgIUB97jZ6WMw7h9jjC9AiTbnoy5nh0wDQYJKoZIhvcNAQEL\n\
BQAwJzElMCMGA1UEAwwcUnVzdHkgQ29uZHVpdCBSU0EgRml4dHVyZSBDQTAgFw0y\n\
NjExMjIxNDQ5MzVaGA8yMTI2MTAyOTE0NDkzNVowJzElMCMGA1UEAwwcUnVzdHkg\n\
Q29uZHVpdCBSU0EgRml4dHVyZSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n\
AQoCggEBAJBRAaXqDIDuIe3swluOCasA+jxB58DeG4hJ86X124QIXLmIWgcs7pFD\n\
IsuTQ8Gh1qblQ/uIDhAmivtBrqvtNSRFlZL14j9+RvaZSW2fcw8n4Swj4DGl/zfH\n\
rFyoX+YtJmGdhpo6g3FVovcbjk/ZdRXMViqE0k74x52SVf/fcxiqnapLmWfsZtdJ\n\
/OLcj5qkuBhrCKrRVPP/jp6y3t5KSLVADW99xQ04kqY25U++cR4iDH40E7+zjWom\n\
33DWfpNAE9pf9JTejhArgKX5+yyQsjzFmAjcTUkoym4Zl+mfHGK4bmcsJ03rAGTF\n\
3fooNkyg5WrT9Vi3TuAfcVbOBjDGZRcCAwEAAaNjMGEwHQYDVR0OBBYEFFBTmVVs\n\
1ZtpZXdK/lfx5sul4fV3MB8GA1UdIwQYMBaAFFBTmVVs1ZtpZXdK/lfx5sul4fV3\n\
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUA\n\
A4IBAQBfoBWP9/EtJDZnG5dPMgH/XUYVWkKfcjnHXLXLXpzhNw3k2+NIvpq8l33j\n\
brxeiO1/QOSahHbCkhXwBbxzr0IZobBH2tVCTwvR3cpva9yqG4EFK8CZnfJOvrnf\n\
+BJRRl88I06Ea5ni88sv2yNSBbeQSpoDCosYMY5zOMGYRQwhqO1IzRjFBUC02JgP\n\
DElyLzlp+EfFSlnAzQD4S797ubjkbXQhNPjM41XsT87r1vh0qYFJiXbeaPfejZ8u\n\
/LNA5dHpQluT56scOSTxMvJr+0SKj/4c1b8fb9SR4GkOKR4OkBIJwQtieCxDCHht\n\
XzBeo6fXvnMmGsTQNHRlvIMwK4Zh\n\
-----END CERTIFICATE-----\n\
";
    const FX_RSA_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpAIBAAKCAQEAkFEBpeoMgO4h7ezCW44JqwD6PEHnwN4biEnzpfXbhAhcuYha\n\
ByzukUMiy5NDwaHWpuVD+4gOECaK+0Guq+01JEWVkvXiP35G9plJbZ9zDyfhLCPg\n\
MaX/N8esXKhf5i0mYZ2GmjqDcVWi9xuOT9l1FcxWKoTSTvjHnZJV/99zGKqdqkuZ\n\
Z+xm10n84tyPmqS4GGsIqtFU8/+OnrLe3kpItUANb33FDTiSpjblT75xHiIMfjQT\n\
v7ONaibfcNZ+k0AT2l/0lN6OECuApfn7LJCyPMWYCNxNSSjKbhmX6Z8cYrhuZywn\n\
TesAZMXd+ig2TKDlatP1WLdO4B9xVs4GMMZlFwIDAQABAoIBABGP6hVuFWDImenB\n\
pX1NcbEVCLQLM9AYDLMEh4QAwVqgnI1vdxU8dePI5GkbCLnS9LORXuPd5hLiaIi0\n\
W4n3RJT0wC5cLHucOw0zZj4oPfDwN3S5q5ofIJ8sdgs96j2xQjnK2QstEmXZDWCT\n\
l+PxC1CVxz6cCe6A/o8XCc7TkHFwfb/SsHTU6jMfI9iw3sLHZGjsoU+uAt6gCn3l\n\
SsrgneP8xi3xJzZ/CUBALbjomZa0VbsLKzRHOiO36fL5+omrn8PRqNvaVzTh3nvD\n\
IjXZTakUCjHOvGKkGhGa8c+FDXO3+/ctFItWLAtgqBhw3gNd23ZzTx4PQ6nbLFRO\n\
0yoHs0ECgYEAwlfEezb+7oARC70XOFeskVeCXvY0CObkTx/VSsNeXIzWXbGp1PFt\n\
KJJfjfs8br21R2EZzCGZJs/rKlm9TG3mLaZrZlniCMwZtv7ERpyB6178aXBchfPo\n\
KFcU2FwT70RcNwR7VqalIfHbfvCxafLhin8m57Fb52J+l7G0urKlyXECgYEAvhor\n\
WUTDeREuqR902q+hUU5/AcZwv1oHdeqC0sc/cNXrJaD10Zq6Mi8ZzurZXeGNATkQ\n\
aB6XmELmombFOBsuaZzUlavvsJTnKMN4G7f7qV2oCVKvpIlNJn8zX+0FZjrh2AOq\n\
YgFtOIL8PDTaNHNjVTfwlQDWM9F3Iw+sUzuykwcCgYEAwcF1L47+DVR7KiPkkZS/\n\
hMwlO33lFPb1qnlHUlmDq2vykMj/VEE7HlcIk2pmrtXOdRK3AJCCu3JRuBBuLVPo\n\
R50CuLFmLHUoMgzALNH+qWYy6wBODnLFA+sF6kuqyEJ0WZnLSfGs8zHJLz7S8pln\n\
CYiJhjeKNB87rQtL71MK/NECgYB0nEbk/mpNtH2D3rjmgH+bCWSdKSX2KvqSmWTg\n\
eLpws7gHoAHKLnhy2jOhmqv1i6rcCi4HQGTLUJZ7HkFyFjJVNI+utAZWsjBN8AGY\n\
NzaXgMzX0zHM4zBBIhvYhuMd/5aT1EPK1Icz+B1TrTQAoptXJfZc4GOE68OB7VZO\n\
xDrZNwKBgQCEaqDn7bCVm6tTX2Dh3ZsR/1308neZlpu35xw3O7b68Hs3NCMpXklG\n\
iLRcEX1hY7ibLs7qU65GZPZ4bhyQfhlkllwFyHxpwMaCWK8ZyRt6vRBaBrpVevQL\n\
kI1MvEoxjKOUgRYSyVwUBFPgCLuqK006gTK0VkATeKYoVZGSOQ2AKQ==\n\
-----END RSA PRIVATE KEY-----\n\
";
    const FX_P12_PBES2: &str = "\
        3082044c0201033082040206092a864886f70d010701a08203f3048203ef308203eb3082029a06092a864886f70d0107
        06a082028b308202870201003082028006092a864886f70d010701305f06092a864886f70d01050d3052303106092a86
        4886f70d01050c30240410af51691afc14c9e307a483cc43ea860402020800300c06082a864886f70d02090500301d06
        0960864801650304012a041035fb47e9424ab97517f9e4f37730a48c80820210b939bbd5d1c3f8b6837d4ae030cb194d
        2d830ec61b0c3e86112e90038e51ee04211e3cad246bdafe5cec8b3f8b1ec0f28fcd0f437968474f4ba5389bf128fab1
        2c0b7a77a6b6f3c565a0a79b3888507cd334691228d6b9c1b41c3974d9991ce6f505233808ae40d3355f99a287d02c7d
        55fecb0002d3dbd38318867e36d6b1900674795dc7b8675f99f26181675485cf654539b398d814676b950b6436afa9eb
        18413d25ef80fba0c59372717aa6d4da46695600d4acf8795b59b85583fe13fe79888ed5f53fe1767c3329b26f01582e
        ce14ac2ef2503261544d9aea0f4e9db515eda2e2f5b2c296346965a20d0ceaba894af2e29370bdcb66d4638b86062f7a
        c40f1454d0ad97c188b78e35d36e6e7e8bf7366f661554fd3d93b7441a3a97de70094fd678f4b84573153425d8e61d6e
        41ca215b9dd24215212b1ccc343c8f2ee888484084a6e053b2f97f89ba4826313dca5036a8de1372848eabf5c3d3cd35
        1d1cf78022f73512eb2289662114131c148b266d3eaf9b7b3c9e42c69c421901628e9522007fc4d767e87c85e7ff61f4
        e8d1d30e93b6bf40341eaaa741267b750f42271422079d2685760c2b5a7df2c341ba30b260ec6376dfb827e3ee6899a1
        27373e3e01c29f7a34c07407f482b8ecbaa4c0fede01f1c4b1a5eb114627a592cdb87b8fd152445c6d96865f45816e3c
        2e9a6ad5556e98af6599f6678d856ee7d5dfaca0616735da69d605d6901b74f93082014906092a864886f70d010701a0
        82013a04820136308201323082012e060b2a864886f70d010c0a0102a081f73081f4305f06092a864886f70d01050d30
        52303106092a864886f70d01050c302404108a9eb74df5912e5bc82d126ba47d5f8602020800300c06082a864886f70d
        02090500301d060960864801650304012a0410bc3fcf3ea66761faa7108591a0a15ca504819078ce9c59cd2deac3e06d
        ec3e79fb1d7e2f6f81821494adf7d59b0f759ef0cb1854ec3110a30a221a9a6ece5a82c9de0c24eabb3910283ef7274f
        04d383806b8a90371e198229f5315c2ec0c7d2f55400ab18ed543369ee9c0d167ca350224a1f42ccc73f6d0012132b8a
        b78e35fc508dfcdecdd5e540dff75263813fd3cb1a00725fcdd7a6f87a2b3a480e9035ca570a3125302306092a864886
        f70d01091531160414dca38e06b000543e49438814ab4ec8c76792de1d30413031300d06096086480165030402010500
        0420d233330b4c2f1be03f6aa5e0df6dc41a40ed4bf32fa4724d0127a80e08b2634d040826d64489a487c90202020800
    ";
    const FX_P12_LEGACY: &str = "\
        308203b20201033082037806092a864886f70d010701a082036904820365308203613082025706092a864886f70d0107
        06a0820248308202440201003082023d06092a864886f70d010701301c060a2a864886f70d010c0106300e0408edaa47
        54c359d96a02020800808202101dd1e1e54094391a751445f158eef703eadfcc2482d67d3577bea1d808c0fe2c291843
        5ae77895c0bb16b41cf244a67a7cc792ea97d1c8a62ad0a5b94f34f4115db5935af3da3369747c70342af35dc848249f
        fb4b50b6072d3c39c9b9463874c1f10996725554d75fbd2f8a62666455716a1f0c0612df1680e6f685414f7cb121c3be
        630c0d96dff4594349cce0eb067cb27734a5094287a70f7269d2949ccc22d9471759ae954b5aceec35bcc55f068a743a
        6b533ec8201b0a5115795cf48ad0e170263b0c579c8535ef2cc8e7819fe7543818e02e624bdc3252019c79f5e9a0b47c
        65c56c255a0ee2a69a1f34c84f4d0c35c379c61aea04438719991f47a44249edeed6588ea87a90f9467c8cea677ba35f
        33bc814a102cdc0386a4b993fae655444620e20f8f306b690ff464bf55f79f04a43532da8cb18b806108b34c35196205
        e90ceb4f44097a8c28d81328b9074aac035386bedccecb3afab85f6e043bcc5f38f549326a441ffe3ee0384769c73c4a
        eda181139b5cc6796f60f117de2fab91add444b349a37999b10302e454a4814b202d6b40e5f52ef9b181ff057aff7664
        8a46cca14f4df150ad01208d8f6d2689564e145f1eea9c9715c841aecff299bb4a3661d4b252d616c32771569739bb0d
        6a613c1212757f1df76603d598fbf0dcfd21c81f59fec91b4ef16a494e22a0aaf3677970d6d3f7d0a5a8e5b56fa7e18d
        f577423dee098423b16c86a7703082010206092a864886f70d010701a081f40481f13081ee3081eb060b2a864886f70d
        010c0a0102a081b43081b1301c060a2a864886f70d010c0103300e040817e34a904759825202020800048190a8cadaa5
        53c9c37a8de23da9e05ada7cf2183e6afccf001878eeb88af0504ba8446b140d60f57387419fc64b6fae7431e50dd0fb
        74eb686be7dcb6687878f44d2767f214fcd91ecddb7e5d57db4513165849c04f8e839edfb9a028d4a805a55682f20bbe
        4f48af5b58500fc2d663fd8eb6d76604e5cc8c742c7a4a52871772b0470a0e129d6f40c222cdc22dc4041eca31253023
        06092a864886f70d01091531160414dca38e06b000543e49438814ab4ec8c76792de1d30313021300906052b0e03021a
        050004144494765510587bda908d694c0a4fc126c5de75fb0408b95e25e11fc3289c02020800
    ";
    const FX_P12_NOPASS: &str = "\
        3082044c0201033082040206092a864886f70d010701a08203f3048203ef308203eb3082029a06092a864886f70d0107
        06a082028b308202870201003082028006092a864886f70d010701305f06092a864886f70d01050d3052303106092a86
        4886f70d01050c30240410a7eaff3da3c794ac4e890f415694b18d02020800300c06082a864886f70d02090500301d06
        0960864801650304012a0410dae09dc38359e60e7af033d3d8f9d1c180820210974f479fb62eea431d191fe64ed883f9
        1da27059f934b19c93ab5d5861751cd8614f3373db1c1bdfe7d903c584406488646cda6c59f5e0596bbec994edaaf7a5
        5fb2500dc80b5e5d8e6a30456ff83dd52d25dc78839aaab3dbc206f5cd5d0893141259200985f4dfbf5a67aea8a5d3a5
        1f1171cc83112054f331de87ba81b592b08e83319919be8e25ea5644696d5cd9d46a8afeac22af9c5bcdc5136a372af2
        bbda4cf0006cd6758693a19ad071b0b534d7afa5ac33299b97575187f18b5e3855a88a6f6b3637c087bd207e5ab9979a
        53ddad1e0f666b7968729e9f176a125db1690367d8135f93649165b313eb01c9837be837e4dd6442146979bbaf306721
        bb1d6281f5a0713d408bee2fd51912fc3a29e57e0bdbc25f1d1d61fc1aab1b8398ec222c6a0a4b6631d41f063bbf563f
        3bb623c6241b46c98c805a49323458e49a8e302703441c41b45e8c72527ad2db3d4e3c80c4761896d9f30e4b0396f2a1
        af9cca04f71f8b5b78d0f6c6bb7b67a4dd027b1b2a46c356e944766d28523f64b613a027610c51bba224def5a07beb0f
        210714f4701749c6b28c590d80b9515e4c5438bf4f5603b8152d569570389bdd2f91de86d97107678c5064c9ac3a3def
        8e32f474a16828cb04d83ebad698452a05ad9721880f158cb84140a6ef9c7d409135669bb5e40b81026c8e13546dd4f8
        8e73c91e2e289fa9f46f4dbee11199c7969c8500e6606dc5b246c5ee2750013a3082014906092a864886f70d010701a0
        82013a04820136308201323082012e060b2a864886f70d010c0a0102a081f73081f4305f06092a864886f70d01050d30
        52303106092a864886f70d01050c302404106ffc5a7cd6a48dd5c66dd90d29b50cfe02020800300c06082a864886f70d
        02090500301d060960864801650304012a04106a2c6047be01347b12524b40ba70e814048190acd929da85a06563af6c
        7700d892c2d2a17f38c2a32a8d3c8e234d5ea22be39c54555256c7f2313a2f2ca67638c439cbac5840406b70178fb00a
        d216baa321b68a6d66c4599b13c1635b9fac4016b14327c75353de3e5dfbc9435af36ddb76114779923b6a5ffbe877c6
        db2ae1b28a9d0cf1c1636fed0963599acd3ec9b382dfa019a49c19fdc9bce567824c8018bdf83125302306092a864886
        f70d01091531160414dca38e06b000543e49438814ab4ec8c76792de1d30413031300d06096086480165030402010500
        04201b4b1d83cac287317a5cf6c4a3684daeb4b2dbfc2e29ce0b4119643a18f09e620408091c89951b7e1fa702020800
    ";
}
