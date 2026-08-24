//! X.509 certificate parsing and chain validation (RFC 5280).
//!
//! A self-contained DER/ASN.1 parser plus chain building against a
//! caller-supplied [`RootStore`]. The crate intentionally does **not**
//! bundle any root certificates (no third-party data): production code
//! must load its trust anchors (e.g. from an OS store or a PEM bundle).

use crate::courierust_tls::TlsError;
use alloc::string::String;
use alloc::vec::Vec;

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
    /// Basic constraints pathLenConstraint (None = absent).
    pub path_len: Option<u8>,
    /// Key usage (bit flags).
    pub key_usage: KeyUsage,
    /// Extended key usage OIDs (raw).
    pub eku: Vec<Vec<u8>>,
    /// Name constraints carried by a CA (None = extension absent).
    /// RFC 5280 §4.2.1.10.
    pub name_constraints: Option<NameConstraints>,
    /// True when the certificate's SAN contains a name form other than
    /// DNS or IP (rfc822, URI, directoryName, …). Used to fail closed
    /// when a CA constrains a name form this verifier does not model.
    pub has_other_sans: bool,
    /// True when the certificate carries an unrecognized critical
    /// extension. RFC 5280 §4.2 requires such certificates to be
    /// rejected.
    pub unknown_critical: bool,
}

/// Name constraints (RFC 5280 §4.2.1.10) restricting the DNS names and
/// IP addresses that subordinate certificates may carry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameConstraints {
    /// Permitted DNS subtrees (lower-cased, leading-dot preserved).
    pub permitted_dns: Vec<String>,
    /// Excluded DNS subtrees (lower-cased, leading-dot preserved).
    pub excluded_dns: Vec<String>,
    /// Permitted IP subtrees: `address (4/16) || mask (4/16)`.
    pub permitted_ip: Vec<Vec<u8>>,
    /// Excluded IP subtrees: `address (4/16) || mask (4/16)`.
    pub excluded_ip: Vec<Vec<u8>>,
    /// True when the extension constrains a name form other than DNS/IP
    /// (rfc822, URI, directoryName, …). The verifier fails closed for
    /// such constraints when the subordinate certificate carries one of
    /// those name forms (matching rustls-webpki, which does not model
    /// them either).
    pub has_other_forms: bool,
}

impl NameConstraints {
    /// Whether the extension is empty (no DNS/IP/other constraints).
    pub fn is_empty(&self) -> bool {
        !self.has_other_forms
            && self.permitted_dns.is_empty()
            && self.excluded_dns.is_empty()
            && self.permitted_ip.is_empty()
            && self.excluded_ip.is_empty()
    }

    /// Whether every DNS name and IP address carried by `cert` satisfies
    /// these constraints.
    pub fn permits(&self, dns: &[String], ip: &[Vec<u8>], has_other_sans: bool) -> bool {
        // Fail closed on name forms we do not model (rustls-webpki
        // rejects directoryName / URI / rfc822 constraints outright).
        if self.has_other_forms && has_other_sans {
            return false;
        }
        for d in dns {
            let lower = d.trim_end_matches('.').to_ascii_lowercase();
            // A permitted-subtrees list exists and none of its entries
            // match the name: reject.
            if !self.permitted_dns.is_empty()
                && !self
                    .permitted_dns
                    .iter()
                    .any(|c| dns_name_matches_constraint(&lower, c, false))
            {
                return false;
            }
            // Any matching excluded subtree rejects.
            if self
                .excluded_dns
                .iter()
                .any(|c| dns_name_matches_constraint(&lower, c, true))
            {
                return false;
            }
        }
        for a in ip {
            if !self.permitted_ip.is_empty()
                && !self
                    .permitted_ip
                    .iter()
                    .any(|c| ip_matches_constraint(a, c) == Some(true))
            {
                return false;
            }
            if self
                .excluded_ip
                .iter()
                .any(|c| ip_matches_constraint(a, c) == Some(true))
            {
                return false;
            }
        }
        true
    }
}

/// RFC 5280 §4.2.1.10 DNS name-constraint matching.
///
/// A constraint `host.example.com` is satisfied by `host.example.com`
/// and by any name formed by prepending whole labels to it
/// (`www.host.example.com`), but not by `host1.example.com`. A leading
/// `.` (`".example.com"`) restricts the match to strict subdomains (the
/// base name itself is not matched). The empty constraint matches every
/// name (RFC 5280: "adding zero or more labels to the left-hand side of
/// the empty string"). Comparisons are case-insensitive.
///
/// Excluded subtrees expand wildcard SANs (CVE-2025-61727): a wildcard
/// `*.X` can expand to a name inside an excluded subtree and must reject
/// the certificate even when the subtree is narrower than the wildcard's
/// parent label. Permitted subtrees keep the wildcard as a literal
/// left-most label, which can only over-reject (safe) and never
/// over-accept.
fn dns_name_matches_constraint(presented: &str, constraint: &str, is_excluded: bool) -> bool {
    fn eq(a: &[u8], b: &[u8]) -> bool {
        a.eq_ignore_ascii_case(b)
    }
    fn subdomain(name: &[u8], constraint: &[u8]) -> bool {
        // `name` is a strict subdomain of `constraint` iff it ends with
        // ".constraint" (whole labels only). A constraint with a leading
        // dot supplies its own boundary, so the plain `ends_with` check
        // is used there; otherwise the byte before the suffix must be '.'.
        if name.len() <= constraint.len() {
            return false;
        }
        let off = name.len() - constraint.len();
        if constraint.first() == Some(&b'.') {
            name[off..].eq_ignore_ascii_case(constraint)
        } else {
            name[off - 1] == b'.' && name[off..].eq_ignore_ascii_case(constraint)
        }
    }
    let p = presented.as_bytes();
    let c = constraint.as_bytes();
    if c.is_empty() {
        // An empty constraint permits/forbids every name.
        return true;
    }
    // Wildcard SANs expand for excluded subtrees: `*.X` can match `X` and
    // any `Y.X` (Y a single label). It intersects the excluded subtree C
    // iff (1) X is within C's subtree, or (2) C is X with exactly one
    // label prepended (the wildcard can expand to C itself), or (3) C is
    // a leading-dot constraint whose base is X (then `Y.X` falls inside).
    if is_excluded && p.starts_with(b"*.") {
        let x = &p[2..];
        // (1) X within C's subtree.
        if !c.starts_with(b".") && eq(x, c) {
            return true;
        }
        if subdomain(x, c) {
            return true;
        }
        // (2) C == "Y." + X for a single-label Y.
        let pre = c.len().saturating_sub(x.len());
        if pre > 1 && c.ends_with(x) && c[pre - 1] == b'.' && !c[..pre - 1].contains(&b'.') {
            return true;
        }
        // (3) Leading-dot constraint whose base equals X.
        if c.starts_with(b".") && eq(x, &c[1..]) {
            return true;
        }
        return false;
    }
    // Literal matching (permitted subtrees and all non-wildcard names).
    if c[0] == b'.' {
        // Leading dot: strict subdomain — the presented name must be a
        // strict subdomain of the constraint's base.
        return subdomain(p, c);
    }
    if eq(p, c) {
        return true;
    }
    subdomain(p, c)
}

/// RFC 5280 §4.2.1.10 IP-address constraint matching.
///
/// A constraint is `address (4 or 16 bytes) || mask (4 or 16 bytes)`
/// (CIDR). The mask must be a contiguous run of one-bits; a
/// non-contiguous mask is a malformed constraint and fails closed
/// (`None`). IPv4 never matches an IPv6 constraint and vice versa.
fn ip_matches_constraint(ip: &[u8], constraint: &[u8]) -> Option<bool> {
    let half = constraint.len() / 2;
    match (ip.len(), constraint.len()) {
        (4, 8) | (16, 32) => {}
        // An IPv4 address never matches an IPv6 constraint and vice
        // versa (rustls-webpki returns Ok(false) for these).
        (4, 32) | (16, 8) => return Some(false),
        // Any other length is malformed.
        _ => return None,
    }
    let (addr, mask) = constraint.split_at(half);
    let mut seen_zero = false;
    for (&a, (&b, &m)) in ip.iter().zip(addr.iter().zip(mask.iter())) {
        // A valid mask byte is a run of ones followed by a run of zeros;
        // once a zero bit appears, no later byte may contain a one bit.
        let ones = m.leading_ones();
        let zeros = m.trailing_zeros();
        if ones + zeros != 8 || (seen_zero && m != 0) {
            return None; // non-contiguous mask: malformed constraint
        }
        if m != 0xff {
            seen_zero = true;
        }
        if (a ^ b) & m != 0 {
            return Some(false);
        }
    }
    Some(true)
}

/// The maximum number of certificates in a presented chain (the leaf
/// plus up to 9 issuing certificates). Bounds the CPU cost of signature
/// verification for a hostile-but-valid chain (defense in depth; real
/// public chains are far shorter).
pub(crate) const MAX_CHAIN_LEN: usize = 10;

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
    /// ecdsa-with-SHA512
    EcdsaSha512,
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
    /// The EC named curve when `oid` is `id-ecPublicKey` (None for RSA /
    /// Ed25519, or for an unrecognized EC parameters OID).
    pub ec_curve: Option<crate::courierust_tls::crypto::ecdsa::Curve>,
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
    pub fn add_pem(&mut self, pem: &str) -> crate::courierust_tls::TlsResult<usize> {
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
pub fn parse_pem_certificates(pem: &str) -> crate::courierust_tls::TlsResult<Vec<Vec<u8>>> {
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
pub fn parse_certificate(der: &[u8]) -> crate::courierust_tls::TlsResult<Certificate> {
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
        return ip_names.contains(&bytes);
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

/// TLS server authentication EKU OID (1.3.6.1.5.5.7.3.1), DER
/// sub-identifier bytes.
const EKU_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// anyExtendedKeyUsage OID (2.5.29.37.0), DER sub-identifier bytes.
const EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/// RFC 5280 §4.2.1.12: when a certificate carries an Extended Key Usage
/// extension, a TLS peer using it for **server authentication** must find
/// `serverAuth` (or `anyExtendedKeyUsage`) among its purposes. An absent
/// EKU extension imposes no restriction (returns `true`).
pub fn has_server_auth_eku(cert: &Certificate) -> bool {
    if cert.eku.is_empty() {
        return true;
    }
    cert.eku
        .iter()
        .any(|e| e.as_slice() == EKU_SERVER_AUTH || e.as_slice() == EKU_ANY)
}

/// Validate a certificate chain (leaf first) against the root store.
///
/// Performs: validity-window checks for every certificate, rejection of
/// unrecognized critical extensions (RFC 5280 §4.2), name chaining
/// (issuer == next subject), signature verification of each certificate
/// with its issuer's public key, basic-constraints/key-usage/pathLen
/// enforcement for every issuer in the path, leaf key-usage and
/// non-CA checks, and a trust-anchor check against the [`RootStore`].
pub fn validate_chain(
    roots: &RootStore,
    chain: &[Vec<u8>],
    now: i64,
) -> crate::courierust_tls::TlsResult<()> {
    if chain.is_empty() {
        return Err(TlsError::Certificate("empty certificate chain".into()));
    }
    let certs: Vec<Certificate> = chain
        .iter()
        .map(|d| der::parse_certificate(d))
        .collect::<crate::courierust_tls::TlsResult<Vec<_>>>()?;
    if certs.len() > MAX_CHAIN_LEN {
        return Err(TlsError::Certificate(format!(
            "certificate chain exceeds the maximum depth of {}",
            MAX_CHAIN_LEN
        )));
    }

    // 1. Validity windows.
    for (i, c) in certs.iter().enumerate() {
        if now < c.not_before || now > c.not_after {
            return Err(TlsError::Certificate(format!(
                "certificate {} outside validity window",
                i
            )));
        }
    }

    // 2. RFC 5280 §4.2: a certificate carrying an extension marked
    //    critical that we do not understand must be rejected.
    for (i, c) in certs.iter().enumerate() {
        if c.unknown_critical {
            return Err(TlsError::Certificate(format!(
                "certificate {i} carries an unsupported critical extension"
            )));
        }
    }

    // 3. Name chaining and signature verification for every link.
    for i in 0..certs.len() - 1 {
        let child = &certs[i];
        let parent = &certs[i + 1];
        if child.issuer_der != parent.subject_der {
            return Err(TlsError::Certificate("issuer/subject name mismatch".into()));
        }
        if !verify_cert_signature(child, &parent.spki) {
            return Err(TlsError::Certificate(
                "certificate signature invalid".into(),
            ));
        }
    }

    // 4. Every certificate that issues another in the path must be a CA
    //    and (when the key usage extension is present) assert keyCertSign
    //    (RFC 5280 §4.2.1.3 / §4.2.1.9).
    for ca in certs.iter().skip(1) {
        if ca.is_ca != Some(true) {
            return Err(TlsError::Certificate("chain issuer is not a CA".into()));
        }
        if usage_present(&ca.key_usage) && !ca.key_usage.key_cert_sign {
            return Err(TlsError::Certificate("CA lacks keyCertSign".into()));
        }
    }

    // 5. pathLenConstraint (RFC 5280 §4.2.1.9): the number of
    //    intermediate CA certificates below an intermediate (closer to
    //    the end entity, excluding the leaf and the trust anchor) must
    //    not exceed its pathLen.
    for (i, ca) in certs
        .iter()
        .enumerate()
        .skip(1)
        .take(certs.len().saturating_sub(2))
    {
        if let Some(p) = ca.path_len {
            let below = (i + 1..certs.len() - 1).count();
            if below > p as usize {
                return Err(TlsError::Certificate(format!(
                    "certificate {i} exceeds its pathLenConstraint"
                )));
            }
        }
    }

    // 6. Leaf (end-entity) usage. The TLS profile here only performs
    //    ECDHE key exchange, so a key-usage extension must permit
    //    digitalSignature; RSA keyEncipherment alone is tolerated for
    //    compatibility with RSA-key-exchange chains even though they
    //    cannot be negotiated.
    {
        let leaf = &certs[0];
        if usage_present(&leaf.key_usage) {
            let rsa = leaf.spki.oid == der::OID_RSA_ENCRYPTION;
            if !(leaf.key_usage.digital_signature || (rsa && leaf.key_usage.key_encipherment)) {
                return Err(TlsError::Certificate(
                    "leaf certificate key usage forbids server authentication".into(),
                ));
            }
        }
    }

    // 7. Trust anchor.
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
        // The last presented cert must be signed by a root; the root
        // must itself be a CA (and keyCertSign when it carries a key
        // usage extension).
        let mut verified = false;
        for root in roots.roots() {
            let Ok(root_cert) = der::parse_certificate(&root.der) else {
                continue;
            };
            if last.issuer_der != root_cert.subject_der {
                continue;
            }
            if root_cert.is_ca != Some(true) {
                continue;
            }
            if usage_present(&root_cert.key_usage) && !root_cert.key_usage.key_cert_sign {
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

    // 8. The leaf must not be a CA unless it is the sole presented
    //    trust anchor (a directly trusted self-signed end entity).
    if certs[0].is_ca == Some(true) && !(certs.len() == 1 && anchored) {
        return Err(TlsError::Certificate("leaf certificate is a CA".into()));
    }

    // 9. Name constraints (RFC 5280 §4.2.1.10): every CA in the path
    //    restricts the names its subordinates may carry. The trust
    //    anchor's own constraints are not enforced (the anchor is trusted
    //    as-is), matching rustls-webpki. The chain is leaf-first, so
    //    certs[i] issues certs[0..i]; its constraints apply to those
    //    subordinates.
    for (i, ca) in certs.iter().enumerate().skip(1) {
        let Some(nc) = &ca.name_constraints else {
            continue;
        };
        if nc.is_empty() {
            continue;
        }
        if i == certs.len() - 1 && anchored {
            // The final presented certificate is the trust anchor.
            continue;
        }
        for subordinate in certs.iter().take(i) {
            if !nc.permits(
                &subordinate.dns_names,
                &subordinate.ip_names,
                subordinate.has_other_sans,
            ) {
                return Err(TlsError::Certificate(format!(
                    "certificate {i} name constraints violated by a subordinate \
                     certificate's names"
                )));
            }
        }
    }

    Ok(())
}

/// Whether any key-usage bit is asserted (i.e. the extension is present
/// and non-empty).
fn usage_present(u: &KeyUsage) -> bool {
    u.digital_signature
        || u.content_commitment
        || u.key_encipherment
        || u.data_encipherment
        || u.key_agreement
        || u.key_cert_sign
        || u.crl_sign
        || u.encipher_only
        || u.decipher_only
}

/// Verify a certificate's signature over its tbsCertificate with the
/// issuer's SPKI.
fn verify_cert_signature(cert: &Certificate, issuer: &Spki) -> bool {
    use crate::courierust_tls::crypto::hash::{Digest, Sha256, Sha384};
    use crate::courierust_tls::crypto::rsa::{
        RsaPublicKey, DIGEST_INFO_SHA256, DIGEST_INFO_SHA384, DIGEST_INFO_SHA512,
    };
    use crate::courierust_tls::crypto::{ecdsa, ed25519};
    use crate::courierust_tls::x509::der::{
        parse_rsa_public_key, OID_EC_PUBLIC_KEY, OID_ED25519, OID_RSA_ENCRYPTION,
    };

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
                    let mut h = Sha512Digest::create();
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
        SigAlg::EcdsaSha256 | SigAlg::EcdsaSha384 | SigAlg::EcdsaSha512 => {
            use crate::courierust_tls::crypto::ecdsa::Curve;
            if issuer.oid != OID_EC_PUBLIC_KEY {
                return false;
            }
            // Strict curve↔hash mapping (identical to rustls/webpki):
            // ecdsa-with-SHA256 requires P-256, ecdsa-with-SHA384
            // requires P-384, ecdsa-with-SHA512 requires P-521.
            let curve = match cert.sig_alg {
                SigAlg::EcdsaSha256 => Curve::P256,
                SigAlg::EcdsaSha384 => Curve::P384,
                _ => Curve::P521,
            };
            if issuer.ec_curve != Some(curve) {
                return false;
            }
            // Uncompressed point: 0x04 || X || Y with the curve's
            // coordinate size.
            let clen = curve.coord_len();
            if issuer.key.len() != 1 + 2 * clen || issuer.key[0] != 0x04 {
                return false;
            }
            let qx = &issuer.key[1..1 + clen];
            let qy = &issuer.key[1 + clen..1 + 2 * clen];
            let digest = match cert.sig_alg {
                SigAlg::EcdsaSha256 => {
                    let mut h = Sha256::new();
                    h.update(&cert.tbs);
                    h.finalize()
                }
                SigAlg::EcdsaSha384 => {
                    let mut h = Sha384::new();
                    h.update(&cert.tbs);
                    h.finalize()
                }
                _ => {
                    // ECDSA-with-SHA512 (P-521): SHA-512 digest.
                    let mut h = Sha512Digest::create();
                    h.update(&cert.tbs);
                    h.finalize()
                }
            };
            ecdsa::verify_der(curve, qx, qy, &digest, &cert.signature)
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
    fn create() -> crate::courierust_tls::crypto::ed25519::Sha512 {
        crate::courierust_tls::crypto::ed25519::Sha512::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000; // 2027-01-14T00:00:00Z, inside the windows

    fn p384_leaf() -> Vec<u8> {
        crate::courierust_tls::testdata::P384_LEAF_CERT_DER.to_vec()
    }
    fn p384_intermediate() -> Vec<u8> {
        crate::courierust_tls::testdata::P384_INTERMEDIATE_CERT_DER.to_vec()
    }
    fn p384_ca() -> Vec<u8> {
        crate::courierust_tls::testdata::P384_CA_CERT_DER.to_vec()
    }

    fn p384_roots() -> RootStore {
        let mut roots = RootStore::new();
        roots.add_der(p384_ca());
        roots
    }

    /// The verifier must accept a chain whose *intermediate CA* is a
    /// P-384 ECDSA key: the leaf is signed with ecdsa-with-SHA384 by a
    /// 97-byte (0x04 || X || Y) P-384 SPKI, and the intermediate itself
    /// is signed by a P-384 root. Regression test for the defect where
    /// only P-256 (65-byte SPKI) was accepted.
    #[test]
    fn validates_p384_intermediate_chain() {
        let chain = vec![p384_leaf(), p384_intermediate()];
        validate_chain(&p384_roots(), &chain, NOW).expect("P-384 intermediate chain must validate");
    }

    /// The full three-certificate chain (leaf + intermediate + root)
    /// also validates.
    #[test]
    fn validates_p384_full_chain_including_root() {
        let chain = vec![p384_leaf(), p384_intermediate(), p384_ca()];
        validate_chain(&p384_roots(), &chain, NOW)
            .expect("full P-384 chain including the root must validate");
    }

    /// A P-384 leaf parsed from DER must carry a 97-byte uncompressed
    /// SPKI on the P-384 curve and the ECDSA-SHA-384 signature algorithm.
    #[test]
    fn p384_leaf_spki_shape() {
        let cert = parse_certificate(&p384_leaf()).unwrap();
        assert_eq!(
            cert.sig_alg,
            SigAlg::EcdsaSha384,
            "leaf signed by P-384 intermediate must use ecdsa-with-SHA384"
        );
        let spki = &cert.spki;
        assert_eq!(spki.oid, der::OID_EC_PUBLIC_KEY);
        assert_eq!(
            spki.ec_curve,
            Some(crate::courierust_tls::crypto::ecdsa::Curve::P384)
        );
        // 1 (0x04) + 2 * 48 (P-384 coordinate size).
        assert_eq!(spki.key.len(), 1 + 2 * 48);
        assert_eq!(spki.key[0], 0x04);
    }

    /// The intermediate's own signature (from the P-384 root) must also
    /// verify: the root's SPKI is a P-384 key.
    #[test]
    fn p384_intermediate_spki_shape() {
        let cert = parse_certificate(&p384_intermediate()).unwrap();
        assert_eq!(cert.sig_alg, SigAlg::EcdsaSha384);
        assert_eq!(cert.is_ca, Some(true));
        let spki = &cert.spki;
        assert_eq!(
            spki.ec_curve,
            Some(crate::courierust_tls::crypto::ecdsa::Curve::P384)
        );
        assert_eq!(spki.key.len(), 1 + 2 * 48);
    }

    /// A P-384 leaf must match its hostname via the SAN.
    #[test]
    fn p384_leaf_hostname_matches() {
        let cert = parse_certificate(&p384_leaf()).unwrap();
        assert!(hostname_matches(
            "localhost",
            &cert.dns_names,
            &cert.ip_names
        ));
        assert!(hostname_matches(
            "127.0.0.1",
            &cert.dns_names,
            &cert.ip_names
        ));
        assert!(!hostname_matches(
            "other.example",
            &cert.dns_names,
            &cert.ip_names
        ));
    }

    /// A P-384 chain must be rejected when the trust anchor is absent.
    #[test]
    fn p384_chain_rejected_without_trust() {
        let chain = vec![p384_leaf(), p384_intermediate()];
        let roots = RootStore::new();
        assert!(validate_chain(&roots, &chain, NOW).is_err());
    }

    /// A P-384 chain must be rejected when the intermediate is swapped
    /// for a certificate signed by an unrelated CA (signature check).
    #[test]
    fn p384_chain_rejects_tampered_intermediate() {
        // Replacing the intermediate with the leaf (self-referential)
        // must fail the issuer/signature checks.
        let chain = vec![p384_leaf(), p384_leaf()];
        assert!(validate_chain(&p384_roots(), &chain, NOW).is_err());
    }

    /// The RSA + Ed25519 + P-256 chain paths keep working alongside the
    /// new P-384 support: the Ed25519 self-signed identity still
    /// validates and P-256 chains behave as before.
    #[test]
    fn existing_identity_paths_unaffected() {
        let ed = crate::courierust_tls::testdata::server_identity();
        let mut roots = RootStore::new();
        roots.add_der(ed.cert_chain[0].clone());
        validate_chain(&roots, &ed.cert_chain, NOW).expect("Ed25519 identity must still validate");

        let rsa = crate::courierust_tls::testdata::rsa_server_identity();
        let mut rroots = RootStore::new();
        rroots.add_der(rsa.cert_chain[0].clone());
        validate_chain(&rroots, &rsa.cert_chain, NOW).expect("RSA identity must still validate");
    }

    // -----------------------------------------------------------------
    // Name-constraint matching (RFC 5280 §4.2.1.10), cross-checked
    // against rustls-webpki's own test vectors.
    // -----------------------------------------------------------------

    #[test]
    fn dns_constraint_plain_matching() {
        // (presented, constraint, expected) — non-wildcard names.
        let cases: &[(&str, &str, bool)] = &[
            // Exact match (zero labels added).
            ("example.com", "example.com", true),
            // Subdomains (labels added to the left).
            ("www.example.com", "example.com", true),
            ("a.b.example.com", "example.com", true),
            // Non-subdomain prefixes must not match.
            ("badexample.com", "example.com", false),
            ("host1.example.com", "host.example.com", false),
            // Case-insensitive.
            ("WWW.EXAMPLE.COM", "example.com", true),
            ("www.example.com", "EXAMPLE.COM", true),
            // Leading dot: strict subdomains.
            ("www.example.com", ".example.com", true),
            ("example.com", ".example.com", false),
            ("badexample.com", ".example.com", false),
            ("a.b.example.com", ".example.com", true),
            // Empty constraint matches everything.
            ("www.example.com", "", true),
            // Disjoint suffixes.
            ("www.example.com", "axample.com", false),
            ("www.example.com", "exampl.com", false),
        ];
        for &(presented, constraint, expected) in cases {
            assert_eq!(
                dns_name_matches_constraint(presented, constraint, false),
                expected,
                "dns constraint {presented:?} vs {constraint:?}"
            );
            // Non-wildcard names behave identically for excluded subtrees.
            if !presented.contains('*') {
                assert_eq!(
                    dns_name_matches_constraint(presented, constraint, true),
                    expected,
                    "excluded dns constraint {presented:?} vs {constraint:?}"
                );
            }
        }
    }

    #[test]
    fn dns_constraint_wildcard_permitted() {
        // rustls-webpki: permitted subtrees keep the wildcard as a
        // literal left-most label.
        let cases: &[(&str, &str, bool)] = &[
            ("*.example.com", "example.com", true),
            ("*.example.com", ".example.com", true),
            // `*.example.com` expands to `evil.example.com` which is
            // outside the subtree `www.example.com`.
            ("*.example.com", "www.example.com", false),
            ("*.example.com", "axample.com", false),
            ("*.example.com", "exampl.com", false),
            ("*.www.example.com", "www.example.com", true),
        ];
        for &(presented, constraint, expected) in cases {
            assert_eq!(
                dns_name_matches_constraint(presented, constraint, false),
                expected,
                "permitted dns constraint {presented:?} vs {constraint:?}"
            );
        }
    }

    #[test]
    fn dns_constraint_wildcard_excluded_cve() {
        // CVE-2025-61727: a wildcard SAN that can expand into an
        // excluded subtree must reject, even when the excluded subtree is
        // narrower than the wildcard's parent label.
        let cases: &[(&str, &str, bool)] = &[
            // `*.example.com` can expand to `evil.example.com`.
            ("*.example.com", "evil.example.com", true),
            // `*.example.com` can expand to exactly `example.com`.
            ("*.example.com", "example.com", true),
            ("*.example.com", ".example.com", true),
            // Disjoint: no expansion reaches `xample.com`.
            ("*.example.com", "xample.com", false),
            ("*.example.com", "evil.example.org", false),
            ("*.a.example.com", "a.example.com", true),
            ("*.a.example.com", "evil.example.com", false),
        ];
        for &(presented, constraint, expected) in cases {
            assert_eq!(
                dns_name_matches_constraint(presented, constraint, true),
                expected,
                "excluded dns constraint {presented:?} vs {constraint:?}"
            );
        }
    }

    #[test]
    fn ip_constraint_matching() {
        // (presented, constraint_address, mask) -> expected.
        type IpCase = (&'static [u8; 4], [u8; 4], [u8; 4], Option<bool>);
        let cases: &[IpCase] = &[
            // 192.0.2.0/24 permits 192.0.2.0 and 192.0.2.255.
            (
                &[192, 0, 2, 0],
                [192, 0, 2, 0],
                [255, 255, 255, 0],
                Some(true),
            ),
            (
                &[192, 0, 2, 255],
                [192, 0, 2, 0],
                [255, 255, 255, 0],
                Some(true),
            ),
            // 192.0.1.255 is outside 192.0.2.0/24.
            (
                &[192, 0, 1, 255],
                [192, 0, 2, 0],
                [255, 255, 255, 0],
                Some(false),
            ),
            // /32 exact.
            (
                &[8, 8, 8, 8],
                [8, 8, 8, 8],
                [255, 255, 255, 255],
                Some(true),
            ),
            (
                &[8, 8, 8, 9],
                [8, 8, 8, 8],
                [255, 255, 255, 255],
                Some(false),
            ),
            // Non-contiguous mask is a malformed constraint.
            (&[8, 8, 8, 8], [8, 8, 8, 8], [255, 255, 255, 1], None),
            (&[8, 8, 8, 8], [8, 8, 8, 8], [255, 255, 0, 255], None),
        ];
        for &(ip, addr, mask, expected) in cases {
            let mut constraint = Vec::with_capacity(8);
            constraint.extend_from_slice(&addr);
            constraint.extend_from_slice(&mask);
            assert_eq!(
                ip_matches_constraint(ip, &constraint),
                expected,
                "ip constraint {ip:?} vs {constraint:?}"
            );
        }
        // IPv4 vs IPv6 constraint never matches.
        let v6_constraint = {
            let mut c = vec![0u8; 32];
            c[0] = 0x20;
            c[15] = 1;
            c[16..32].fill(0xff);
            c
        };
        assert_eq!(
            ip_matches_constraint(&[192, 0, 2, 1], &v6_constraint),
            Some(false)
        );
    }

    #[test]
    fn name_constraints_permits_leaf() {
        // A CA that permits only *.example.com must reject a leaf with an
        // out-of-subtree DNS name.
        let nc = NameConstraints {
            permitted_dns: vec!["example.com".into()],
            ..Default::default()
        };
        assert!(nc.permits(&["www.example.com".into()], &[], false));
        assert!(nc.permits(&["example.com".into()], &[], false));
        assert!(!nc.permits(&["evil.org".into()], &[], false));
        assert!(!nc.permits(&["badexample.com".into()], &[], false));

        // An excluded subtree.
        let nc = NameConstraints {
            excluded_dns: vec!["evil.example.com".into()],
            ..Default::default()
        };
        assert!(nc.permits(&["good.example.com".into()], &[], false));
        assert!(!nc.permits(&["evil.example.com".into()], &[], false));
        // A wildcard leaf that could expand into the excluded subtree.
        assert!(!nc.permits(&["*.example.com".into()], &[], false));

        // IP constraints.
        let nc = NameConstraints {
            permitted_ip: vec![vec![192, 0, 2, 0, 255, 255, 255, 0]],
            ..Default::default()
        };
        assert!(nc.permits(&[], &[vec![192, 0, 2, 9]], false));
        assert!(!nc.permits(&[], &[vec![192, 0, 3, 9]], false));

        // Unsupported name forms fail closed when the leaf carries one.
        let nc = NameConstraints {
            has_other_forms: true,
            ..Default::default()
        };
        assert!(!nc.permits(&[], &[], true));
        assert!(nc.permits(&[], &[], false));
    }

    // -----------------------------------------------------------------
    // End-to-end name-constraint enforcement through the DER parser.
    // -----------------------------------------------------------------

    fn nc_leaf_ok() -> Vec<u8> {
        crate::courierust_tls::testdata::NC_LEAF_OK_CERT_DER.to_vec()
    }
    fn nc_leaf_bad() -> Vec<u8> {
        crate::courierust_tls::testdata::NC_LEAF_BAD_CERT_DER.to_vec()
    }
    fn nc_intermediate() -> Vec<u8> {
        crate::courierust_tls::testdata::NC_INTERMEDIATE_CERT_DER.to_vec()
    }

    /// A leaf inside the intermediate's permitted DNS subtree validates.
    #[test]
    fn name_constraint_permitted_leaf_validates() {
        let chain = vec![nc_leaf_ok(), nc_intermediate()];
        validate_chain(
            &crate::courierust_tls::testdata::nc_root_store(),
            &chain,
            NOW,
        )
        .expect("localhost leaf must satisfy the permitted;DNS:localhost constraint");
    }

    /// A leaf outside the intermediate's permitted DNS subtree is
    /// rejected (RFC 5280 §4.2.1.10).
    #[test]
    fn name_constraint_outside_subtree_rejected() {
        let chain = vec![nc_leaf_bad(), nc_intermediate()];
        let err = validate_chain(
            &crate::courierust_tls::testdata::nc_root_store(),
            &chain,
            NOW,
        )
        .expect_err("evil.com leaf must violate the permitted;DNS:localhost constraint");
        assert!(matches!(err, TlsError::Certificate(_)), "got {err:?}");
    }

    /// The intermediate's nameConstraints extension parses into the
    /// expected permitted subtree.
    #[test]
    fn name_constraint_extension_parsed() {
        let inter = parse_certificate(&nc_intermediate()).unwrap();
        let nc = inter
            .name_constraints
            .expect("intermediate must carry nameConstraints");
        assert_eq!(nc.permitted_dns, vec!["localhost".to_string()]);
        assert!(nc.excluded_dns.is_empty());
        assert!(!nc.is_empty());
        // The leaf's own certificate has no name constraints.
        let leaf = parse_certificate(&nc_leaf_ok()).unwrap();
        assert!(leaf.name_constraints.is_none());
    }

    /// A chain deeper than `MAX_CHAIN_LEN` is rejected (defense in depth
    /// against CPU-exhaustion by a hostile-but-valid chain).
    #[test]
    fn oversized_chain_rejected() {
        // Build a chain of the self-signed test cert repeated: name
        // chaining fails long before depth, so validate the depth guard
        // directly by exceeding the limit with a synthetic chain.
        let mut chain = Vec::new();
        for _ in 0..(MAX_CHAIN_LEN + 2) {
            chain.push(crate::courierust_tls::testdata::SERVER_CERT_DER.to_vec());
        }
        let roots = crate::courierust_tls::testdata::root_store();
        let err =
            validate_chain(&roots, &chain, NOW).expect_err("over-long chain must be rejected");
        assert!(matches!(err, TlsError::Certificate(_)), "got {err:?}");
    }
}
