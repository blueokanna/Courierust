//! The server identity: a certificate chain plus the private key that
//! goes with its leaf.
//!
//! A TLS server is only as good as the pair it presents, so this type
//! exists to make "load the certificate and the key" a single checked
//! operation instead of three public fields a caller has to get right:
//!
//! * the chain and the key are parsed (DER, PKCS#8 / PKCS#1 / SEC1),
//! * the key is proven to match the leaf certificate with a sign/verify
//!   round trip against the leaf's public key — the same check rustls
//!   performs in `with_single_cert`, and the failure it prevents is the
//!   worst kind: a server that starts fine and rejects every handshake,
//! * `is_rsa` is derived from the key rather than declared by the caller,
//! * the key never reaches a log: the `Debug` impl prints its length.
//!
//! Loading is available from PEM (the format every deployment hands you),
//! from PEM files, or from DER for callers that keep the pair in memory
//! or fetch it from a secret store.

use crate::courierust_tls::sign::{key_matches_certificate, key_type, IdentityKeyType};
use crate::courierust_tls::x509::Certificate;
use crate::courierust_tls::{pem, TlsError, TlsResult};
use alloc::vec::Vec;

/// A certificate chain and the private key of its leaf.
///
/// Build one with [`Identity::from_pem`], [`Identity::from_pem_file`] or
/// [`Identity::from_der`]; every constructor validates. The chain is
/// DER, leaf first, exactly as it goes on the wire.
#[derive(Clone)]
pub struct Identity {
    pub(crate) cert_chain: Vec<Vec<u8>>,
    pub(crate) private_key: Vec<u8>,
    /// Derived from the parsed key at construction, never declared.
    pub(crate) is_rsa: bool,
}

impl Identity {
    /// A placeholder with no certificate and no key.
    ///
    /// It exists for `TlsSettings { identity, ..Default::default() }`-style
    /// construction and for [`crate::courierust_server::TlsSettings::default`];
    /// a server built on it cannot complete a handshake, which is why the
    /// server rejects an empty identity when it binds rather than failing
    /// per connection. [`Identity::is_empty`] reports it.
    pub fn empty() -> Self {
        Self {
            cert_chain: Vec::new(),
            private_key: Vec::new(),
            is_rsa: false,
        }
    }

    /// Validate a chain and key that are already DER.
    ///
    /// The leaf is `cert_chain[0]`; the rest are sent as intermediates.
    /// Fails on an empty chain, a certificate or key that does not parse,
    /// or a key that does not match the leaf certificate.
    pub fn from_der(cert_chain: Vec<Vec<u8>>, private_key: Vec<u8>) -> TlsResult<Self> {
        if cert_chain.is_empty() {
            return Err(TlsError::Certificate("empty certificate chain".into()));
        }
        let leaf = crate::courierust_tls::x509::parse_certificate(&cert_chain[0])?;
        for (index, der) in cert_chain.iter().enumerate().skip(1) {
            crate::courierust_tls::x509::parse_certificate(der).map_err(|e| {
                TlsError::Certificate(alloc::format!("certificate #{index} in the chain: {e}"))
            })?;
        }
        let is_rsa = match key_type(&private_key)? {
            IdentityKeyType::Rsa => true,
            IdentityKeyType::Ecdsa(_) | IdentityKeyType::Ed25519 => false,
        };
        if !key_matches_certificate(&leaf, &private_key) {
            return Err(TlsError::Certificate(
                "the private key does not match the leaf certificate".into(),
            ));
        }
        Ok(Self {
            cert_chain,
            private_key,
            is_rsa,
        })
    }

    /// Validate a PEM certificate chain and a PEM private key.
    ///
    /// The two documents are separate arguments because that is how
    /// deployments store them (one file each); a single file holding both
    /// also works — pass it twice, the reader picks the block it needs.
    /// Accepted key containers: PKCS#8 (`PRIVATE KEY`), PKCS#1
    /// (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> TlsResult<Self> {
        Self::from_der(
            pem::certificate_chain(cert_pem)?,
            pem::private_key(key_pem)?,
        )
    }

    /// [`Identity::from_pem`] over two files.
    pub fn from_pem_file(
        cert_path: impl AsRef<std::path::Path>,
        key_path: impl AsRef<std::path::Path>,
    ) -> TlsResult<Self> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();
        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|e| TlsError::Io(alloc::format!("{}: {e}", cert_path.display())))?;
        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|e| TlsError::Io(alloc::format!("{}: {e}", key_path.display())))?;
        Self::from_pem(&cert_pem, &key_pem)
    }

    /// Whether this identity carries no certificate (see
    /// [`Identity::empty`]).
    pub fn is_empty(&self) -> bool {
        self.cert_chain.is_empty()
    }

    /// The DER certificate chain, leaf first.
    pub fn cert_chain(&self) -> &[Vec<u8>] {
        &self.cert_chain
    }

    /// The DER private key.
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Whether the private key is RSA (derived from the key itself).
    pub fn is_rsa(&self) -> bool {
        self.is_rsa
    }

    /// The parsed leaf certificate.
    pub fn leaf_certificate(&self) -> TlsResult<Certificate> {
        let leaf = self
            .cert_chain
            .first()
            .ok_or_else(|| TlsError::Certificate("empty certificate chain".into()))?;
        crate::courierust_tls::x509::parse_certificate(leaf)
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::empty()
    }
}

/// Redacts the private key: an `Identity` ends up inside a `Debug`-printed
/// `TlsSettings` or `ServerConfig`, and a key that reaches a log line is a
/// key that has to be rotated.
impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field(
                "cert_chain",
                &core::format_args!("{} certificate(s)", self.cert_chain.len()),
            )
            .field(
                "private_key",
                &core::format_args!("<redacted: {} bytes>", self.private_key.len()),
            )
            .field("is_rsa", &self.is_rsa)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_crypto::base64;
    use crate::courierust_tls::testdata;

    fn armor(label: &str, der: &[u8]) -> alloc::string::String {
        let mut out = alloc::string::String::new();
        out.push_str("-----BEGIN ");
        out.push_str(label);
        out.push_str("-----\n");
        out.push_str(&base64::encode(der));
        out.push_str("\n-----END ");
        out.push_str(label);
        out.push_str("-----\n");
        out
    }

    fn pem_pair(
        cert: &[u8],
        key: &[u8],
        key_label: &str,
    ) -> (alloc::string::String, alloc::string::String) {
        (armor("CERTIFICATE", cert), armor(key_label, key))
    }

    #[test]
    fn loads_an_ed25519_pair_from_pem() {
        let (cert_pem, key_pem) = pem_pair(
            testdata::SERVER_CERT_DER,
            testdata::SERVER_KEY_DER,
            "PRIVATE KEY",
        );
        let id = Identity::from_pem(&cert_pem, &key_pem).expect("valid pair");
        assert!(!id.is_empty());
        assert!(!id.is_rsa());
        assert_eq!(id.cert_chain().len(), 1);
        assert_eq!(id.private_key(), testdata::SERVER_KEY_DER);
        assert_eq!(id.leaf_certificate().unwrap().dns_names, vec!["localhost"]);
    }

    #[test]
    fn loads_an_rsa_pair_and_derives_is_rsa() {
        let pem = armor("RSA PRIVATE KEY", testdata::RSA_SERVER_KEY_DER);
        let id = Identity::from_pem(&armor("CERTIFICATE", testdata::RSA_SERVER_CERT_DER), &pem)
            .expect("valid pair");
        assert!(id.is_rsa(), "is_rsa is derived from the key");
    }

    #[test]
    fn loads_a_p384_ec_pair_with_an_intermediate() {
        let two_blocks = alloc::format!(
            "{}{}",
            armor("CERTIFICATE", testdata::P384_LEAF_CERT_DER),
            armor("CERTIFICATE", testdata::P384_INTERMEDIATE_CERT_DER)
        );
        let key = armor("EC PRIVATE KEY", testdata::P384_LEAF_KEY_DER);
        let id = Identity::from_pem(&two_blocks, &key).expect("valid P-384 pair");
        assert_eq!(id.cert_chain().len(), 2);
        assert!(!id.is_rsa());
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        let err = Identity::from_pem(
            &armor("CERTIFICATE", testdata::SERVER_CERT_DER),
            &armor("PRIVATE KEY", testdata::RSA_SERVER_KEY_DER),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn a_garbage_key_is_refused_with_a_usable_message() {
        let err = Identity::from_der(vec![testdata::SERVER_CERT_DER.to_vec()], vec![0u8; 16])
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported private key format"), "{err}");
    }

    #[test]
    fn an_empty_chain_is_refused() {
        assert!(Identity::from_der(Vec::new(), testdata::SERVER_KEY_DER.to_vec()).is_err());
        assert!(Identity::default().is_empty());
        assert!(Identity::default().leaf_certificate().is_err());
    }

    #[test]
    fn a_malformed_intermediate_names_its_position() {
        let err = Identity::from_der(
            vec![testdata::SERVER_CERT_DER.to_vec(), vec![0x30, 0x01, 0x00]],
            testdata::SERVER_KEY_DER.to_vec(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("certificate #1"), "{err}");
    }

    #[test]
    fn debug_redacts_the_private_key() {
        let id = crate::courierust_tls::testdata::server_identity();
        let printed = alloc::format!("{id:?}");
        assert!(printed.contains("redacted"), "{printed}");
        // Neither the raw bytes nor their base64 may appear.
        let raw = alloc::format!("{:?}", &id.private_key()[..8]);
        assert!(!printed.contains(&raw), "{printed}");
        let encoded = base64::encode(id.private_key());
        assert!(!printed.contains(&encoded), "{printed}");
    }

    #[test]
    fn loads_from_files() {
        let dir = std::env::temp_dir();
        let stamp = alloc::format!(
            "courierust-identity-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let cert_path = dir.join(alloc::format!("{stamp}-cert.pem"));
        let key_path = dir.join(alloc::format!("{stamp}-key.pem"));
        std::fs::write(&cert_path, armor("CERTIFICATE", testdata::SERVER_CERT_DER)).unwrap();
        std::fs::write(&key_path, armor("PRIVATE KEY", testdata::SERVER_KEY_DER)).unwrap();
        let id = Identity::from_pem_file(&cert_path, &key_path).expect("pair on disk");
        assert_eq!(id.cert_chain().len(), 1);
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        let err = Identity::from_pem_file(&cert_path, &key_path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cert"), "{err}");
    }
}
