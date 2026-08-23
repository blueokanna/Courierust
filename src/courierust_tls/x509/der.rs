//! A minimal, strict DER (X.690) parser plus X.509 v3 certificate
//! parsing. The parser validates lengths and terminates on any
//! malformed input — hostile certificates cannot cause panics or
//! out-of-bounds access.

use crate::courierust_tls::x509::{Certificate, KeyUsage, SigAlg, Spki};
use crate::courierust_tls::TlsError;
use alloc::string::String;
use alloc::vec::Vec;

/// A parsed DER element (tag + content slice).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Element<'a> {
    /// The full tag byte (with class/constructed bits).
    pub tag: u8,
    /// Content bytes (for constructed tags, this is the concatenated child TLV stream).
    pub content: &'a [u8],
}

/// Whether a tag byte denotes a constructed element.
#[inline]
#[allow(dead_code)]
pub(crate) fn is_constructed(tag: u8) -> bool {
    tag & 0x20 != 0
}

/// Read the next TLV from `der` starting at `pos`. Returns the element
/// and advances `pos` past the complete element.
pub(crate) fn read_element<'a>(der: &'a [u8], pos: &mut usize) -> Option<Element<'a>> {
    if *pos >= der.len() {
        return None;
    }
    let tag = der[*pos];
    *pos += 1;
    if *pos >= der.len() {
        return None;
    }
    let len_byte = der[*pos];
    *pos += 1;
    let len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 8 || *pos + n > der.len() {
            return None;
        }
        let mut l = 0usize;
        for _ in 0..n {
            l = (l << 8) | der[*pos] as usize;
            *pos += 1;
        }
        l
    };
    if *pos + len > der.len() {
        return None;
    }
    let content = &der[*pos..*pos + len];
    *pos += len;
    Some(Element { tag, content })
}

/// Assert that the element at `pos` is a `SEQUENCE` and return its
/// content.
pub(crate) fn expect_sequence<'a>(der: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let e = read_element(der, pos)?;
    if e.tag != 0x30 {
        return None;
    }
    Some(e.content)
}

/// Parse an OBJECT IDENTIFIER from its DER content into the canonical
/// dotted-decimal string (for debugging) — but the exact DER bytes are
/// the comparison key, so this is only informational.
#[allow(dead_code)] // used by the TLS handshake certificate validation
pub(crate) fn oid_to_string(oid: &[u8]) -> String {
    let mut out = String::new();
    if oid.is_empty() {
        return out;
    }
    let first = core::cmp::min(oid[0] / 40, 2);
    let second = oid[0] - first * 40;
    out.push_str(&format!("{first}.{second}"));
    let mut value: u64 = 0;
    for &b in &oid[1..] {
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            out.push('.');
            out.push_str(&value.to_string());
            value = 0;
        }
    }
    out
}

/// Parse a UTCTime / GeneralizedTime value into a Unix timestamp.
fn parse_time(der: &[u8], pos: &mut usize) -> Option<i64> {
    let e = read_element(der, pos)?;
    match e.tag {
        0x17 => {
            let s = core::str::from_utf8(e.content).ok()?;
            let (year, rest) = if s.len() == 13 && s.ends_with('Z') {
                (parse2(&s[0..2])?, &s[2..12])
            } else if s.len() == 15 && s.ends_with('Z') {
                (parse2(&s[0..2])?, &s[2..14])
            } else {
                return None;
            };
            let yy = if year < 50 { 2000 + year } else { 1900 + year };
            let (month, rest) = split2(rest)?;
            let (day, rest) = split2(rest)?;
            let (hour, rest) = split2(rest)?;
            let (min, rest) = split2(rest)?;
            let (sec, _) = if rest.is_empty() {
                (0, "")
            } else {
                split2(rest)?
            };
            to_unix(yy, month, day, hour, min, sec)
        }
        0x18 => {
            let s = core::str::from_utf8(e.content).ok()?;
            if s.len() < 15 || !s.ends_with('Z') {
                return None;
            }
            let year: i64 = s[0..4].parse().ok()?;
            let month: i64 = s[4..6].parse().ok()?;
            let day: i64 = s[6..8].parse().ok()?;
            let hour: i64 = s[8..10].parse().ok()?;
            let min: i64 = s[10..12].parse().ok()?;
            let sec: i64 = s[12..14].parse().ok()?;
            to_unix(year, month, day, hour, min, sec)
        }
        _ => None,
    }
}

fn parse2(s: &str) -> Option<i64> {
    s.parse().ok()
}

fn split2(s: &str) -> Option<(i64, &str)> {
    if s.len() < 2 {
        return None;
    }
    let v: i64 = s[0..2].parse().ok()?;
    Some((v, &s[2..]))
}

/// Convert a broken-down time to a Unix timestamp (days-from-civil).
fn to_unix(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

// ---- OID constants (DER content bytes) ----

#[allow(dead_code)] // used by the TLS handshake certificate validation
pub(crate) const OID_RSA_ENCRYPTION: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
pub(crate) const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
pub(crate) const OID_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
pub(crate) const OID_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
#[allow(dead_code)] // used by the TLS handshake certificate validation
pub(crate) const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub(crate) const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
pub(crate) const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
pub(crate) const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
/// Named curve prime256v1 / secp256r1 (1.2.840.10045.3.1.7).
pub(crate) const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// Named curve secp384r1 (1.3.132.0.34).
pub(crate) const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// Named curve secp521r1 (1.3.132.0.35).
pub(crate) const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];
pub(crate) const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
pub(crate) const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
pub(crate) const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
pub(crate) const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
pub(crate) const OID_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
/// Name constraints (2.5.29.30).
pub(crate) const OID_NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
#[allow(dead_code)] // used by the TLS handshake certificate validation
pub(crate) const OID_KEY_USAGE_SERVER_AUTH: &[u8] =
    &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
#[allow(dead_code)] // used by the TLS handshake certificate validation
pub(crate) const OID_KEY_USAGE_CLIENT_AUTH: &[u8] =
    &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

fn sig_alg_from_oid(oid: &[u8]) -> SigAlg {
    if oid == OID_RSA_SHA256 {
        SigAlg::RsaSha256
    } else if oid == OID_RSA_SHA384 {
        SigAlg::RsaSha384
    } else if oid == OID_RSA_SHA512 {
        SigAlg::RsaSha512
    } else if oid == OID_ECDSA_SHA256 {
        SigAlg::EcdsaSha256
    } else if oid == OID_ECDSA_SHA384 {
        SigAlg::EcdsaSha384
    } else if oid == OID_ECDSA_SHA512 {
        SigAlg::EcdsaSha512
    } else if oid == OID_ED25519 {
        SigAlg::Ed25519
    } else {
        SigAlg::Unknown
    }
}

/// Parse an AlgorithmIdentifier (SEQUENCE { OID, params? }) and return
/// (oid_bytes, full_content).
fn parse_algorithm_identifier<'a>(der: &'a [u8], pos: &mut usize) -> Option<(Vec<u8>, &'a [u8])> {
    let seq = expect_sequence(der, pos)?;
    let mut p = 0usize;
    let oid_e = read_element(seq, &mut p)?;
    if oid_e.tag != 0x06 {
        return None;
    }
    let oid = oid_e.content.to_vec();
    Some((oid, seq))
}

/// Parse a Name (RDNSequence) and return its full DER content.
fn parse_name(der: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let e = read_element(der, pos)?;
    if e.tag != 0x30 {
        return None;
    }
    Some(e.content.to_vec())
}

/// Parse a SubjectPublicKeyInfo.
///
/// For `id-ecPublicKey` keys the algorithm parameters (the named curve
/// OID) are captured so certificate signature verification can enforce
/// the strict curve↔hash mapping used by rustls/webpki.
fn parse_spki(der: &[u8], pos: &mut usize) -> Option<Spki> {
    // SPKI: SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING }
    let spki_seq = expect_sequence(der, pos)?;
    let mut p = 0usize;
    // AlgorithmIdentifier: SEQUENCE { OID, parameters OPTIONAL }
    let alg = expect_sequence(spki_seq, &mut p)?;
    let mut ap = 0usize;
    let oid_e = read_element(alg, &mut ap)?;
    if oid_e.tag != 0x06 {
        return None;
    }
    let oid = oid_e.content.to_vec();
    let mut ec_curve = None;
    if oid == OID_EC_PUBLIC_KEY {
        // The parameters must be the named curve OID.
        if let Some(params) = read_element(alg, &mut ap) {
            if params.tag == 0x06 {
                ec_curve = match params.content {
                    OID_P256 => Some(crate::courierust_tls::crypto::ecdsa::Curve::P256),
                    OID_P384 => Some(crate::courierust_tls::crypto::ecdsa::Curve::P384),
                    OID_P521 => Some(crate::courierust_tls::crypto::ecdsa::Curve::P521),
                    _ => None,
                };
            }
        }
    } else if read_element(alg, &mut ap).is_some() {
        // RSA / Ed25519: skip the optional NULL (or absent) parameters.
    }
    // subjectPublicKey: BIT STRING, after the AlgorithmIdentifier in the
    // SPKI sequence.
    let key_e = read_element(spki_seq, &mut p)?;
    if key_e.tag != 0x03 {
        return None;
    }
    if key_e.content.is_empty() {
        return None;
    }
    let key = key_e.content[1..].to_vec();
    Some(Spki { oid, key, ec_curve })
}

/// Fully parse a DER X.509 certificate.
pub(crate) fn parse_certificate(der: &[u8]) -> crate::courierust_tls::TlsResult<Certificate> {
    let mut pos = 0usize;
    let outer =
        read_element(der, &mut pos).ok_or_else(|| TlsError::Protocol("bad cert header".into()))?;
    if outer.tag != 0x30 || pos != der.len() {
        return Err(TlsError::Protocol(
            "certificate is not a single SEQUENCE".into(),
        ));
    }
    let mut p = 0usize;
    let tbs_start = p;
    let tbs_der = expect_sequence(outer.content, &mut p)
        .ok_or_else(|| TlsError::Protocol("missing tbsCertificate".into()))?
        .to_vec();
    // RFC 5280 §4.1.1.2: the certificate signature is computed over the
    // full DER encoding of the tbsCertificate, including the SEQUENCE tag
    // and length header — not just its content. Keep the whole element for
    // signature verification while parsing the fields from the content.
    let tbs_full = outer.content[tbs_start..p].to_vec();
    let (sig_alg, _) = parse_algorithm_identifier(outer.content, &mut p)
        .ok_or_else(|| TlsError::Protocol("missing signature algorithm".into()))?;
    let sig_e = read_element(outer.content, &mut p)
        .ok_or_else(|| TlsError::Protocol("missing signature value".into()))?;
    if sig_e.tag != 0x03 || sig_e.content.is_empty() {
        return Err(TlsError::Protocol("bad signature value".into()));
    }
    let signature = sig_e.content[1..].to_vec();
    let mut t = 0usize;
    let first = read_element(&tbs_der, &mut t)
        .ok_or_else(|| TlsError::Protocol("bad tbsCertificate".into()))?;
    if first.tag == 0xA0 {
        let mut vp = 0usize;
        let v = read_element(first.content, &mut vp)
            .ok_or_else(|| TlsError::Protocol("bad version".into()))?;
        if v.tag != 0x02 {
            return Err(TlsError::Protocol("bad version".into()));
        }
    }
    let serial_e: Element<'_> = if first.tag == 0xA0 {
        read_element(&tbs_der, &mut t).ok_or_else(|| TlsError::Protocol("missing serial".into()))?
    } else {
        first
    };
    if serial_e.tag != 0x02 {
        return Err(TlsError::Protocol("missing serial".into()));
    }
    let serial = serial_e.content.to_vec();
    let _ = parse_algorithm_identifier(&tbs_der, &mut t)
        .ok_or_else(|| TlsError::Protocol("missing tbs signature alg".into()))?;
    let issuer_der =
        parse_name(&tbs_der, &mut t).ok_or_else(|| TlsError::Protocol("missing issuer".into()))?;
    let validity = read_element(&tbs_der, &mut t)
        .ok_or_else(|| TlsError::Protocol("missing validity".into()))?
        .content
        .to_vec();
    let mut vp = 0usize;
    let not_before =
        parse_time(&validity, &mut vp).ok_or_else(|| TlsError::Protocol("bad notBefore".into()))?;
    let not_after =
        parse_time(&validity, &mut vp).ok_or_else(|| TlsError::Protocol("bad notAfter".into()))?;
    let subject_der =
        parse_name(&tbs_der, &mut t).ok_or_else(|| TlsError::Protocol("missing subject".into()))?;
    let spki =
        parse_spki(&tbs_der, &mut t).ok_or_else(|| TlsError::Protocol("missing SPKI".into()))?;

    // Extensions.
    let mut dns_names: Vec<String> = Vec::new();
    let mut ip_names: Vec<Vec<u8>> = Vec::new();
    let mut is_ca: Option<bool> = None;
    let mut path_len: Option<u8> = None;
    let mut key_usage = KeyUsage::default();
    let mut eku: Vec<Vec<u8>> = Vec::new();
    let mut name_constraints = None;
    let mut has_other_sans = false;
    let mut unknown_critical = false;
    if let Some(e) = read_element(&tbs_der, &mut t) {
        if e.tag == 0xA3 {
            let mut p2 = 0usize;
            let ext_seq = expect_sequence(e.content, &mut p2)
                .ok_or_else(|| TlsError::Protocol("bad extensions".into()))?;
            let mut q = 0usize;
            while q < ext_seq.len() {
                let ext = read_element(ext_seq, &mut q)
                    .ok_or_else(|| TlsError::Protocol("bad extension".into()))?;
                if ext.tag != 0x30 {
                    return Err(TlsError::Protocol("bad extension".into()));
                }
                let mut r = 0usize;
                let oid_e = read_element(ext.content, &mut r)
                    .ok_or_else(|| TlsError::Protocol("bad extension oid".into()))?;
                if oid_e.tag != 0x06 {
                    return Err(TlsError::Protocol("bad extension oid".into()));
                }
                let oid = oid_e.content;
                let mut critical = false;
                let value_e = loop {
                    let e = read_element(ext.content, &mut r)
                        .ok_or_else(|| TlsError::Protocol("extension value missing".into()))?;
                    if e.tag == 0x01 {
                        // critical BOOLEAN (DEFAULT FALSE).
                        critical = !e.content.is_empty() && e.content[0] != 0;
                        continue;
                    }
                    if e.tag == 0x04 {
                        break e;
                    }
                    return Err(TlsError::Protocol(
                        "extension value not octet string".into(),
                    ));
                };
                apply_extension(
                    oid,
                    critical,
                    value_e.content,
                    &mut dns_names,
                    &mut ip_names,
                    &mut is_ca,
                    &mut path_len,
                    &mut key_usage,
                    &mut eku,
                    &mut name_constraints,
                    &mut has_other_sans,
                    &mut unknown_critical,
                );
            }
        }
    }

    Ok(Certificate {
        der: der.to_vec(),
        tbs: tbs_full,
        sig_alg: sig_alg_from_oid(&sig_alg),
        signature,
        spki,
        serial,
        issuer_der,
        subject_der,
        not_before,
        not_after,
        dns_names,
        ip_names,
        is_ca,
        path_len,
        key_usage,
        eku,
        name_constraints,
        has_other_sans,
        unknown_critical,
    })
}

/// Apply one parsed extension.
#[allow(clippy::too_many_arguments)]
fn apply_extension(
    oid: &[u8],
    critical: bool,
    value: &[u8],
    dns_names: &mut Vec<String>,
    ip_names: &mut Vec<Vec<u8>>,
    is_ca: &mut Option<bool>,
    path_len: &mut Option<u8>,
    key_usage: &mut KeyUsage,
    eku: &mut Vec<Vec<u8>>,
    name_constraints: &mut Option<super::NameConstraints>,
    has_other_sans: &mut bool,
    unknown_critical: &mut bool,
) {
    if oid == OID_BASIC_CONSTRAINTS {
        // SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
        let mut p = 0usize;
        if let Some(seq) = expect_sequence(value, &mut p) {
            let mut q = 0usize;
            if let Some(e) = read_element(seq, &mut q) {
                if e.tag == 0x01 {
                    *is_ca = Some(!e.content.is_empty() && e.content[0] != 0);
                }
            }
            if let Some(e) = read_element(seq, &mut q) {
                if e.tag == 0x02 && !e.content.is_empty() {
                    let mut v: u64 = 0;
                    for &b in e.content {
                        v = v.saturating_mul(256).saturating_add(b as u64);
                    }
                    *path_len = Some(v.min(u8::MAX as u64) as u8);
                }
            }
        }
    } else if oid == OID_KEY_USAGE {
        // BIT STRING
        let mut p = 0usize;
        if let Some(e) = read_element(value, &mut p) {
            if e.tag == 0x03 && !e.content.is_empty() {
                *key_usage = KeyUsage::from_bits(&e.content[1..]);
            }
        }
    } else if oid == OID_SUBJECT_ALT_NAME {
        // GeneralNames: SEQUENCE OF GeneralName; dNSName = [2] IA5String,
        // iPAddress = [7] OCTET STRING (4 or 16 bytes). Any other form
        // (rfc822 = [1], directoryName = [4], URI = [6], …) is tracked so
        // name-constraint checking can fail closed for forms this verifier
        // does not model.
        let mut p = 0usize;
        if let Some(seq) = expect_sequence(value, &mut p) {
            let mut q = 0usize;
            while q < seq.len() {
                if let Some(e) = read_element(seq, &mut q) {
                    match e.tag {
                        0x82 => match core::str::from_utf8(e.content) {
                            Ok(s) if !s.is_empty() => dns_names.push(s.to_string()),
                            _ => {}
                        },
                        0x87 if e.content.len() == 4 || e.content.len() == 16 => {
                            ip_names.push(e.content.to_vec());
                        }
                        0x81 | 0x83 | 0x84 | 0x85 | 0x86 | 0x88 => {
                            *has_other_sans = true;
                        }
                        _ => {}
                    }
                }
            }
        }
    } else if oid == OID_EXTENDED_KEY_USAGE {
        // SEQUENCE OF OIDs.
        let mut p = 0usize;
        if let Some(seq) = expect_sequence(value, &mut p) {
            let mut q = 0usize;
            while q < seq.len() {
                if let Some(e) = read_element(seq, &mut q) {
                    if e.tag == 0x06 {
                        eku.push(e.content.to_vec());
                    }
                }
            }
        }
    } else if oid == OID_NAME_CONSTRAINTS {
        // NameConstraints ::= SEQUENCE {
        //     permittedSubtrees [0] GeneralSubtrees OPTIONAL,
        //     excludedSubtrees [1] GeneralSubtrees OPTIONAL }
        // The [0]/[1] tags are IMPLICIT for GeneralSubtrees, so their
        // content is directly a sequence of GeneralSubtree elements:
        //   GeneralSubtree ::= SEQUENCE { base GeneralName,
        //                                minimum [0] BaseDistance DEFAULT 0,
        //                                maximum [1] BaseDistance OPTIONAL }
        let mut nc = super::NameConstraints::default();
        let mut p = 0usize;
        if let Some(seq) = expect_sequence(value, &mut p) {
            let mut q = 0usize;
            while let Some(e) = read_element(seq, &mut q) {
                let permitted = match e.tag {
                    0xa0 => true,
                    0xa1 => false,
                    _ => continue,
                };
                // `e.content` is the SEQUENCE OF GeneralSubtree (the
                // GeneralSubtrees SEQUENCE tag is implicit in [0]/[1]).
                let mut s = 0usize;
                while s < e.content.len() {
                    if let Some(st) = read_element(e.content, &mut s) {
                        if st.tag != 0x30 {
                            continue;
                        }
                        // The first element of GeneralSubtree is the
                        // base GeneralName (minimum/maximum [0]/[1]
                        // follow; they are intentionally ignored — RFC
                        // 5280 treats minimum=0/maximum absent as the
                        // common case and TLS verifiers do not use the
                        // deprecated distance fields).
                        let mut b = 0usize;
                        if let Some(base) = read_element(st.content, &mut b) {
                            match base.tag {
                                0x82 => {
                                    let name = core::str::from_utf8(base.content)
                                        .unwrap_or("")
                                        .to_ascii_lowercase();
                                    if permitted {
                                        nc.permitted_dns.push(name);
                                    } else {
                                        nc.excluded_dns.push(name);
                                    }
                                }
                                0x87 => {
                                    let oct = base.content.to_vec();
                                    if oct.len() == 8 || oct.len() == 32 {
                                        if permitted {
                                            nc.permitted_ip.push(oct);
                                        } else {
                                            nc.excluded_ip.push(oct);
                                        }
                                    }
                                }
                                _ => nc.has_other_forms = true,
                            }
                        }
                    }
                }
            }
        }
        // A malformed NameConstraints extension (no SEQUENCE) fails closed.
        if !nc.is_empty() || p == 0 {
            *name_constraints = Some(nc);
        }
    } else if critical {
        // RFC 5280 §4.2: an unrecognized extension marked critical
        // forces rejection of the certificate.
        *unknown_critical = true;
    }
}

/// Extract the RSA public key (modulus, exponent) from an
/// RSAPublicKey DER (SEQUENCE { modulus INTEGER, publicExponent INTEGER }).
/// The INTEGERs are normalized by stripping the leading zero sign byte
/// so the modulus length equals its real byte length (a 2048-bit
/// modulus is 256 bytes, not 257): the RSA verification code treats
/// `n.len()` as the key size.
pub(crate) fn parse_rsa_public_key(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut p = 0usize;
    let seq = expect_sequence(der, &mut p)?;
    let mut q = 0usize;
    let n = read_element(seq, &mut q)?;
    if n.tag != 0x02 {
        return None;
    }
    let e = read_element(seq, &mut q)?;
    if e.tag != 0x02 {
        return None;
    }
    Some((strip_int(n.content).to_vec(), strip_int(e.content).to_vec()))
}

/// Remove a leading 0x00 sign byte from a positive INTEGER.
fn strip_int(v: &[u8]) -> &[u8] {
    if v.len() > 1 && v[0] == 0 {
        &v[1..]
    } else {
        v
    }
}
