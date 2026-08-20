//! X.509 certificate parsing and chain validation (RFC 5280).
//!
//! A self-contained DER/ASN.1 parser plus chain building against a
//! caller-supplied [`RootStore`]. The crate intentionally does **not**
//! bundle any root certificates (no third-party data): production code
//! must load its trust anchors (e.g. from an OS store or a PEM bundle).

use alloc::string::String;
use alloc::vec::Vec;
use crate::tls::TlsError;

/// A DER-encoded certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Full DER.
    pub der: Vec<u8>,
    /// tbsCertificate DER (the signed portion).
    pub tbs: Vec<u8>,
    /// Signature algorithm OID of the certificate signature.
    pub sig_alg: SigAlg,
    /// Signature value (raw, without the trailing bit-string pad).
    pub signature: Vec<u8>,
    /// Subject public key info.
    pub spki: Spki,
    /// Serial number.
    pub serial: Vec<u8>,
    /// Issuer name (DER).
    pub issuer_der: Vec<u8>,
    /// Subject name (DER).
    pub subject_der: Vec<u8>,
    /// Not-before (Unix time).
    pub not_before: i64,
    /// Not-after (Unix time).
    pub not_after: i64,
    /// Subject alternative names (DNS).
    pub dns_names: Vec<String>,
    /// Subject alternative names (iPAddress, raw 4/16-byte octets).
    pub ip_names: Vec<Vec<u8>>,
    /// Basic constraints CA flag (None = extension absent).
    pub is_ca: Option<bool>,
    /// Key usage (bit flags).
    pub key_usage: KeyUsage,
    /// Extended key usage OIDs (raw).
    pub eku: Vec<Vec<u8>>,
}

/// Signature algorithm of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    /// sha256WithRSAEncryption
    RsaSha256,
    /// sha384WithRSAEncryption
    RsaSha384,
    /// sha512WithRSAEncryption
    RsaSha512,
    /// ecdsa-with-SHA256
    EcdsaSha256,
    /// ecdsa-with-SHA384
    EcdsaSha384,
    /// Ed25519
    Ed25519,
    /// Unknown or unsupported.
    Unknown,
}

/// SubjectPublicKeyInfo (algorithm + raw key bytes).
#[derive(Debug, Clone)]
pub struct Spki {
    /// Algorithm OID (e.g. rsaEncryption, id-ecPublicKey, Ed25519).
    pub oid: Vec<u8>,
    /// The key material (RSAPublicKey DER for RSA; EC point for ECDSA;
    /// 32 raw bytes for Ed25519).
    pub key: Vec<u8>,
}

/// Key usage bit flags (RFC 5280 §4.2.1.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyUsage {
    /// digitalSignature
    pub digital_signature: bool,
    /// nonRepudiation / contentCommitment
    pub content_commitment: bool,
    /// keyEncipherment
    pub key_encipherment: bool,
    /// dataEncipherment
    pub data_encipherment: bool,
    /// keyAgreement
    pub key_agreement: bool,
    /// keyCertSign
    pub key_cert_sign: bool,
    /// cRLSign
    pub crl_sign: bool,
    /// encipherOnly
    pub encipher_only: bool,
    /// decipherOnly
    pub decipher_only: bool,
}

impl KeyUsage {
    fn from_bits(bits: &[u8]) -> Self {
        let mut u = Self::default();
        if bits.is_empty() {
            return u;
        }
        let b0 = bits[0];
        let b1 = bits.get(1).copied().unwrap_or(0);
        u.digital_signature = b0 & 0x80 != 0;
        u.content_commitment = b0 & 0x40 != 0;
        u.key_encipherment = b0 & 0x20 != 0;
        u.data_encipherment = b0 & 0x10 != 0;
        u.key_agreement = b0 & 0x08 != 0;
        u.key_cert_sign = b0 & 0x04 != 0;
        u.crl_sign = b0 & 0x02 != 0;
        u.encipher_only = b0 & 0x01 != 0;
        u.decipher_only = b1 & 0x80 != 0;
        u
    }
}

/// A trust anchor.
#[derive(Debug, Clone)]
pub struct RootCert {
    /// DER-encoded self-signed (or trusted) certificate.
    pub der: Vec<u8>,
}

/// A store of trust anchors.
#[derive(Debug, Clone, Default)]
pub struct RootStore {
    roots: Vec<RootCert>,
}

impl RootStore {
    /// An empty store (nothing is trusted).
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Add a DER-encoded root certificate.
    pub fn add_der(&mut self, der: Vec<u8>) {
        self.roots.push(RootCert { der });
    }

    /// Load root certificates from a PEM bundle.
    pub fn add_pem(&mut self, pem: &str) -> crate::tls::TlsResult<usize> {
        let certs = parse_pem_certificates(pem)?;
        let n = certs.len();
        for c in certs {
            self.roots.push(RootCert { der: c });
        }
        Ok(n)
    }

    /// Number of roots.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// All roots.
    pub fn roots(&self) -> &[RootCert] {
        &self.roots
    }
}

/// Parse all `CERTIFICATE` blocks from a PEM document.
pub fn parse_pem_certificates(pem: &str) -> crate::tls::TlsResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut current: Option<Vec<u8>> = None;
    let mut in_cert = false;
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current = Some(Vec::new());
        } else if line.starts_with("-----END CERTIFICATE-----") {
            if let Some(mut b64) = current.take() {
                let raw: String = b64
                    .drain(..)
                    .filter(|c| !c.is_ascii_whitespace())
                    .map(|c| c as char)
                    .collect();
                let der = base64_decode(&raw)
                    .ok_or_else(|| TlsError::Protocol("invalid PEM base64".into()))?;
                out.push(der);
            }
            in_cert = false;
        } else if in_cert {
            if let Some(buf) = current.as_mut() {
                buf.extend_from_slice(line.as_bytes());
            }
        }
    }
    Ok(out)
}

/// Minimal RFC 4648 base64 decoder (no padding required).
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut nbits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

// Forward-declared: the full certificate parser is implemented in the
// `cert` submodule with the DER parser.
pub(crate) mod der;

/// Parse a DER certificate into a [`Certificate`].
pub fn parse_certificate(der: &[u8]) -> crate::tls::TlsResult<Certificate> {
    der::parse_certificate(der)
}

/// Check whether `name` matches the certificate's subject alternative
/// names. An IP-literal name is matched against the iPAddress SANs only
/// (RFC 6125 §6.4.4); a DNS name is matched against the dNSName SANs with
/// a single left-most `*` wildcard (RFC 6125 §6.4.3). A certificate with
/// no SAN at all cannot be matched and returns `false`.
pub fn hostname_matches(name: &str, dns_names: &[String], ip_names: &[Vec<u8>]) -> bool {
    let name = name.trim_end_matches('.');
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        let bytes = match ip {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        return ip_names.iter().any(|i| *i == bytes);
    }
    if dns_names.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    for d in dns_names {
        let d = d.trim_end_matches('.');
        if dns_match(&lower, &d.to_ascii_lowercase()) {
            return true;
        }
    }
    false
}

/// RFC 6125 DNS-ID comparison with a single `*` in the left-most label.
fn dns_match(name: &str, pattern: &str) -> bool {
    // Exact match.
    if name == pattern {
        return true;
    }
    // Only a bare `*.` wildcard is accepted (matches exactly one label).
    if !pattern.starts_with("*.") {
        return false;
    }
    let suffix = &pattern[2..];
    if suffix.contains('*') {
        return false;
    }
    // The name must end with the suffix, and the wildcard must replace
    // exactly one non-empty label (no further dots in that label).
    let Some(stripped) = name.strip_suffix(suffix) else {
        return false;
    };
    if !stripped.ends_with('.') {
        return false;
    }
    let label = &stripped[..stripped.len() - 1];
    !label.is_empty() && !label.contains('.')
}

/// Validate a certificate chain (leaf first) against the root store.
///
/// Performs: validity-window checks for every certificate, name chaining
/// (issuer == next subject), signature verification of each certificate
/// with its issuer's public key, CA/basic-constraints and key-usage
/// enforcement for non-leaf certificates, and a trust-anchor check
/// against the supplied [`RootStore`].
pub fn validate_chain(
    roots: &RootStore,
    chain: &[Vec<u8>],
    now: i64,
) -> crate::tls::TlsResult<()> {
    if chain.is_empty() {
        return Err(TlsError::Certificate("empty certificate chain".into()));
    }
    let certs: Vec<Certificate> = chain
        .iter()
        .map(|d| der::parse_certificate(d))
        .collect::<crate::tls::TlsResult<Vec<_>>>()?;

    // 1. Validity windows.
    for (i, c) in certs.iter().enumerate() {
        if now < c.not_before || now > c.not_after {
            return Err(TlsError::Certificate(format!(
                "certificate {} outside validity window",
                i
            )));
        }
    }

    // 2. Chain signatures and name chaining.
    for i in 0..certs.len() - 1 {
        let child = &certs[i];
        let parent = &certs[i + 1];
        if child.issuer_der != parent.subject_der {
            return Err(TlsError::Certificate("issuer/subject name mismatch".into()));
        }
        if !verify_cert_signature(child, &parent.spki) {
            return Err(TlsError::Certificate("certificate signature invalid".into()));
        }
        // Every non-leaf in the presented chain must be a CA.
        if child.is_ca != Some(true) {
            return Err(TlsError::Certificate("intermediate is not a CA".into()));
        }
        if child.key_usage.digital_signature
            && !child.key_usage.key_cert_sign
            && !child.is_ca.is_none()
        {
            // If key usage is present and the cert is a CA, it must allow
            // keyCertSign.
            if !child.key_usage.key_cert_sign {
                return Err(TlsError::Certificate("CA lacks keyCertSign".into()));
            }
        }
    }

    // 3. Trust anchor.
    let last = certs.last().unwrap();
    let anchored = {
        let mut found = false;
        for root in roots.roots() {
            if root.der == last.der {
                found = true;
                break;
            }
        }
        found
    };
    if !anchored {
        // The last presented cert must be signed by a root.
        let mut verified = false;
        for root in roots.roots() {
            let Ok(root_cert) = der::parse_certificate(&root.der) else {
                continue;
            };
            if last.issuer_der != root_cert.subject_der {
                continue;
            }
            if verify_cert_signature(last, &root_cert.spki) {
                // The root must be self-signed / its own issuer.
                if root_cert.issuer_der == root_cert.subject_der {
                    verified = true;
                    break;
                }
            }
        }
        if !verified {
            return Err(TlsError::Certificate("no trusted root found".into()));
        }
    } else if last.issuer_der != last.subject_der {
        // A presented trust anchor must be self-issued.
        if !verify_cert_signature(last, &last.spki) {
            return Err(TlsError::Certificate("root is not self-signed".into()));
        }
    }

    // 4. Leaf must not be a CA (end-entity).
    if certs[0].is_ca == Some(true) && certs.len() == 1 {
        // A lone self-signed leaf is allowed only if it is the anchor.
        if !anchored {
            return Err(TlsError::Certificate("leaf is a CA".into()));
        }
    }

    Ok(())
}

/// Verify a certificate's signature over its tbsCertificate with the
/// issuer's SPKI.
fn verify_cert_signature(cert: &Certificate, issuer: &Spki) -> bool {
    use crate::tls::crypto::hash::{Digest, Sha256, Sha384};
    use crate::tls::crypto::rsa::{RsaPublicKey, DIGEST_INFO_SHA256, DIGEST_INFO_SHA384, DIGEST_INFO_SHA512};
    use crate::tls::crypto::{ecdsa, ed25519};
    use crate::tls::x509::der::{OID_EC_PUBLIC_KEY, OID_ED25519, OID_RSA_ENCRYPTION, parse_rsa_public_key};

    match cert.sig_alg {
        SigAlg::RsaSha256 | SigAlg::RsaSha384 | SigAlg::RsaSha512 => {
            if issuer.oid != OID_RSA_ENCRYPTION {
                return false;
            }
            let Some((n, e)) = parse_rsa_public_key(&issuer.key) else {
                return false;
            };
            let key = RsaPublicKey { n, e };
            let digest = match cert.sig_alg {
                SigAlg::RsaSha256 => {
                    let mut h = Sha256::new();
                    h.update(&cert.tbs);
                    h.finalize()
                }
                SigAlg::RsaSha384 => {
                    let mut h = Sha384::new();
                    h.update(&cert.tbs);
                    h.finalize()
                }
                _ => {
                    // SHA-512
                    let mut h = Sha512Digest::new();
                    h.update(&cert.tbs);
                    h.finalize()
                }
            };
            let digest_info = match cert.sig_alg {
                SigAlg::RsaSha256 => DIGEST_INFO_SHA256,
                SigAlg::RsaSha384 => DIGEST_INFO_SHA384,
                _ => DIGEST_INFO_SHA512,
            };
            key.verify_pkcs1v15(digest_info, &digest, &cert.signature)
        }
        SigAlg::EcdsaSha256 | SigAlg::EcdsaSha384 => {
            if issuer.oid != OID_EC_PUBLIC_KEY || issuer.key.len() != 65 || issuer.key[0] != 0x04 {
                return false;
            }
            let mut qx = [0u8; 32];
            let mut qy = [0u8; 32];
            qx.copy_from_slice(&issuer.key[1..33]);
            qy.copy_from_slice(&issuer.key[33..65]);
            match cert.sig_alg {
                SigAlg::EcdsaSha256 => {
                    let mut h = Sha256::new();
                    h.update(&cert.tbs);
                    let d = h.finalize();
                    ecdsa::verify_der(&qx, &qy, &d, &cert.signature)
                }
                _ => {
                    let mut h = Sha384::new();
                    h.update(&cert.tbs);
                    let d = h.finalize();
                    ecdsa::verify_der(&qx, &qy, &d, &cert.signature)
                }
            }
        }
        SigAlg::Ed25519 => {
            if issuer.oid != OID_ED25519 || issuer.key.len() != 32 {
                return false;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&issuer.key);
            let mut sig = [0u8; 64];
            if cert.signature.len() != 64 {
                return false;
            }
            sig.copy_from_slice(&cert.signature);
            ed25519::verify(&pk, &cert.tbs, &sig)
        }
        SigAlg::Unknown => false,
    }
}

/// SHA-512 digest adapter for certificate signatures.
struct Sha512Digest;
impl Sha512Digest {
    fn new() -> crate::tls::crypto::ed25519::Sha512 {
        crate::tls::crypto::ed25519::Sha512::new()
    }
}
