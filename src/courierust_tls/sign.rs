//! Server-side CertificateVerify / ServerKeyExchange signing.
//!
//! Parses a PKCS#8 / PKCS#1 private key (RSA, Ed25519 or ECDSA on the
//! NIST P-256 / P-384 / P-521 curves) and produces the TLS 1.3
//! CertificateVerify signature (RFC 8446 §4.4.3) or the TLS 1.2
//! ServerKeyExchange signature (RFC 5246 §7.4.3). RSA uses PKCS#1 v1.5
//! or PSS; Ed25519 uses RFC 8032; ECDSA uses a deterministic RFC 6979
//! nonce with constant-time scalar arithmetic.

use super::crypto::ecdsa::Curve;
use super::crypto::hash::{Digest, Sha256, Sha384};
use super::crypto::{ecdsa, ed25519, rsa};
use super::key_schedule::{CipherSuite, SuiteHash};
use super::x509::der::{expect_sequence, read_element};
use super::{Identity, TlsError, TlsResult};
use alloc::vec::Vec;

/// DER OID: rsaEncryption (1.2.840.113549.1.1.1).
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// DER OID: Ed25519 (1.3.101.112).
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// DER OID: id-ecPublicKey (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// DER OID: prime256v1 / secp256r1 (1.2.840.10045.3.1.7).
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER OID: secp384r1 (1.3.132.0.34).
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// DER OID: secp521r1 (1.3.132.0.35).
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

/// A parsed private key.
enum ParsedKey {
    Rsa { n: Vec<u8>, d: Vec<u8> },
    Ed25519([u8; 32]),
    Ec { curve: Curve, d: Vec<u8> },
}

/// The certificate key type of an [`Identity`], used to pick the
/// TLS 1.2 ECDHE signature family (RFC 5246 §7.4.3 / RFC 8422 §5.5)
/// and the TLS 1.3 signature scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityKeyType {
    /// RSA (ECDHE_RSA suites; PKCS#1 v1.5 SKE signatures).
    Rsa,
    /// ECDSA on one of the NIST curves (ECDHE_ECDSA suites).
    Ecdsa(Curve),
    /// Ed25519 — usable for TLS 1.3 CertificateVerify; not usable for
    /// TLS 1.2 key exchange (no mainstream TLS 1.2 stack offers it).
    Ed25519,
}

/// Determine the key type of an [`Identity`].
pub(crate) fn identity_key_type(identity: &Identity) -> TlsResult<IdentityKeyType> {
    match parse_private_key(&identity.private_key)? {
        ParsedKey::Rsa { .. } => Ok(IdentityKeyType::Rsa),
        ParsedKey::Ec { curve, .. } => Ok(IdentityKeyType::Ecdsa(curve)),
        ParsedKey::Ed25519(_) => Ok(IdentityKeyType::Ed25519),
    }
}

/// The cipher-suite hash a server should prefer given its identity key.
///
/// TLS 1.3 fixes the ECDSA CertificateVerify scheme from the suite hash
/// (SHA-256 → P-256, SHA-384 → P-384), so a server with an EC identity
/// must only negotiate suites whose hash matches its curve. P-521 would
/// need a SHA-512 suite, which the TLS 1.3 profile does not offer, so
/// there is no compatible suite (mirrors rustls).
pub(crate) fn tls13_suite_hash_pref(identity: &Identity) -> Option<SuiteHash> {
    match identity_key_type(identity).ok()? {
        IdentityKeyType::Rsa | IdentityKeyType::Ed25519 => None,
        IdentityKeyType::Ecdsa(Curve::P256) => Some(SuiteHash::Sha256),
        IdentityKeyType::Ecdsa(Curve::P384) => Some(SuiteHash::Sha384),
        IdentityKeyType::Ecdsa(Curve::P521) => None,
    }
}

/// Sign the TLS 1.2 `ServerKeyExchange` body with the identity key and
/// the digest algorithm matching the key (RFC 5246 §4.7): RSA uses
/// PKCS#1 v1.5 over SHA-256/SHA-384, ECDSA a DER `ECDSA-Sig-Value` with
/// SHA-256 (P-256) / SHA-384 (P-384) / SHA-512 (P-521).
/// Returns `(hash_alg, sig_alg, signature)`.
pub(crate) fn sign_tls12_server_key_exchange(
    identity: &Identity,
    message: &[u8],
) -> TlsResult<Option<(u8, u8, Vec<u8>)>> {
    let key = parse_private_key(&identity.private_key)?;
    match key {
        ParsedKey::Rsa { n, d } => {
            let mut h = Sha256::new();
            let digest = {
                h.update(message);
                h.finalize()
            };
            rsa::sign_pkcs1v15(&n, &d, rsa::DIGEST_INFO_SHA256, &digest)
                .map(|sig| (4, 1, sig))
                .map(Some)
                .ok_or_else(|| TlsError::Certificate("RSA signing failed".into()))
        }
        ParsedKey::Ec { curve, d } => {
            let (hash_alg, digest) = match curve {
                Curve::P256 => {
                    let mut h = Sha256::new();
                    h.update(message);
                    (4, h.finalize())
                }
                Curve::P384 => {
                    let mut h = Sha384::new();
                    h.update(message);
                    (5, h.finalize())
                }
                Curve::P521 => {
                    let mut h = ed25519::Sha512::new();
                    h.update(message);
                    (6, h.finalize())
                }
            };
            match ecdsa::sign(curve, &d, &digest) {
                Some((r, s)) => {
                    let der = encode_ecdsa_sig(&r, &s);
                    Ok(Some((hash_alg, 3, der)))
                }
                None => Err(TlsError::Certificate("ECDSA signing failed".into())),
            }
        }
        ParsedKey::Ed25519(seed) => {
            // RFC 8422 §4.3: Ed25519 signs the raw SKE params with scheme
            // 0x0807 (no separate digest). The wire form is the two-byte
            // scheme, parsed by the peer as hash_alg=0x08, sig_alg=0x07.
            let sig = ed25519::sign(&seed, message);
            Ok(Some((0x08, 0x07, sig.to_vec())))
        }
    }
}

/// Sign the TLS 1.3 CertificateVerify message for a server identity.
/// Returns `(signature_scheme, signature)`.
pub(crate) fn sign_server_cert_verify(
    identity: &Identity,
    message: &[u8],
    suite: CipherSuite,
) -> TlsResult<Option<(u16, Vec<u8>)>> {
    let key = parse_private_key(&identity.private_key)?;
    match key {
        ParsedKey::Rsa { n, d } => {
            let (scheme_pss, scheme_pkcs1, salt_len, digest_info) = match suite.hash() {
                SuiteHash::Sha256 => (0x0804, 0x0401, 32, rsa::DIGEST_INFO_SHA256),
                SuiteHash::Sha384 => (0x0805, 0x0501, 48, rsa::DIGEST_INFO_SHA384),
            };
            let mut h: super::crypto::hash::BoxDigest = match suite.hash() {
                SuiteHash::Sha256 => Box::<Sha256>::default(),
                SuiteHash::Sha384 => Box::<Sha384>::default(),
            };
            if let Some(sig) = rsa::sign_pss(h.as_mut(), &n, &d, message, salt_len) {
                return Ok(Some((scheme_pss, sig)));
            }
            let mut h: super::crypto::hash::BoxDigest = match suite.hash() {
                SuiteHash::Sha256 => Box::<Sha256>::default(),
                SuiteHash::Sha384 => Box::<Sha384>::default(),
            };
            let digest = {
                h.update(message);
                h.finalize()
            };
            if let Some(sig) = rsa::sign_pkcs1v15(&n, &d, digest_info, &digest) {
                return Ok(Some((scheme_pkcs1, sig)));
            }
            Err(TlsError::Certificate("RSA signing failed".into()))
        }
        ParsedKey::Ed25519(seed) => {
            let sig = ed25519::sign(&seed, message);
            Ok(Some((0x0807, sig.to_vec())))
        }
        ParsedKey::Ec { curve, d } => {
            // TLS 1.3 fixes the ECDSA scheme from the suite hash: a P-256
            // key requires a SHA-256 suite (0x0403) and a P-384 key a
            // SHA-384 suite (0x0503). P-521 would need SHA-512, for which
            // no TLS 1.3 suite exists, so it cannot produce a TLS 1.3
            // CertificateVerify (identical to rustls).
            let (scheme, digest) = match (curve, suite.hash()) {
                (Curve::P256, SuiteHash::Sha256) => {
                    let mut h = Sha256::new();
                    h.update(message);
                    (0x0403, h.finalize())
                }
                (Curve::P384, SuiteHash::Sha384) => {
                    let mut h = Sha384::new();
                    h.update(message);
                    (0x0503, h.finalize())
                }
                (Curve::P521, _) => {
                    return Err(TlsError::Certificate(
                        "P-521 identity cannot sign a TLS 1.3 CertificateVerify \
                         (no SHA-512 cipher suite)"
                            .into(),
                    ))
                }
                _ => {
                    return Err(TlsError::Certificate(
                        "ECDSA identity curve incompatible with the negotiated \
                         cipher suite"
                            .into(),
                    ))
                }
            };
            match ecdsa::sign(curve, &d, &digest) {
                Some((r, s)) => {
                    let der = encode_ecdsa_sig(&r, &s);
                    Ok(Some((scheme, der)))
                }
                None => Err(TlsError::Certificate("ECDSA signing failed".into())),
            }
        }
    }
}

/// DER-encode an ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }.
///
/// Handles body lengths ≥ 128 bytes (P-384/P-521 signatures) with the
/// DER long-form length (0x81 <len>) — a bare high-bit byte would be
/// misread as a multi-byte length.
fn encode_ecdsa_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn enc_int(v: &[u8]) -> Vec<u8> {
        let mut body = v.to_vec();
        // Strip leading zeros but keep at least one byte.
        while body.len() > 1 && body[0] == 0 {
            body.remove(0);
        }
        if body[0] & 0x80 != 0 {
            body.insert(0, 0);
        }
        let mut out = Vec::with_capacity(2 + body.len());
        out.push(0x02);
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
        out
    }
    let r_der = enc_int(r);
    let s_der = enc_int(s);
    let body_len = r_der.len() + s_der.len();
    let mut out = Vec::with_capacity(4 + body_len);
    out.push(0x30);
    // DER length: short form below 128, long form otherwise.
    if body_len < 128 {
        out.push(body_len as u8);
    } else {
        out.push(0x81);
        out.push(body_len as u8);
    }
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    out
}

/// Parse a PKCS#8 or PKCS#1 (RSA) private key.
fn parse_private_key(der: &[u8]) -> TlsResult<ParsedKey> {
    // Try PKCS#8 first.
    if let Some(k) = parse_pkcs8(der) {
        return Ok(k);
    }
    // Fall back to PKCS#1 RSAPrivateKey.
    if let Some(k) = parse_pkcs1_rsa(der) {
        return Ok(k);
    }
    Err(TlsError::Certificate(
        "unsupported private key format".into(),
    ))
}

/// Parse a PKCS#8 PrivateKeyInfo.
fn parse_pkcs8(der: &[u8]) -> Option<ParsedKey> {
    let mut pos = 0usize;
    let seq = expect_sequence(der, &mut pos)?;
    if pos != der.len() {
        return None;
    }
    let mut p = 0usize;
    // version INTEGER
    let version = read_element(seq, &mut p)?;
    if version.tag != 0x02 {
        return None;
    }
    // AlgorithmIdentifier
    let alg = read_element(seq, &mut p)?;
    if alg.tag != 0x30 {
        return None;
    }
    let mut a = 0usize;
    let oid = read_element(alg.content, &mut a)?;
    if oid.tag != 0x06 {
        return None;
    }
    // OCTET STRING privateKey
    let key = read_element(seq, &mut p)?;
    if key.tag != 0x04 {
        return None;
    }
    if oid.content == OID_RSA_ENCRYPTION {
        return parse_pkcs1_rsa(key.content);
    }
    if oid.content == OID_ED25519 {
        // RFC 8410 §4: the private key is an OCTET STRING containing the
        // 32-byte seed. OpenSSL additionally wraps the seed in a nested
        // OCTET STRING (`04 22 04 20 <seed>`); accept both forms.
        let seed_bytes = if key.content.len() == 32 {
            key.content
        } else if key.content.len() == 34 && key.content[0] == 0x04 && key.content[1] == 0x20 {
            &key.content[2..]
        } else {
            return None;
        };
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_bytes);
        return Some(ParsedKey::Ed25519(seed));
    }
    if oid.content == OID_EC_PUBLIC_KEY {
        // The params must be a recognized named curve.
        let params = read_element(alg.content, &mut a)?;
        if params.tag != 0x06 {
            return None;
        }
        let curve = match params.content {
            OID_P256 => Curve::P256,
            OID_P384 => Curve::P384,
            OID_P521 => Curve::P521,
            _ => return None,
        };
        // ECPrivateKey: SEQUENCE { INTEGER version, OCTET STRING d, [1] pub? }
        let mut e = 0usize;
        let ec_seq = expect_sequence(key.content, &mut e)?;
        let mut ep = 0usize;
        let ver = read_element(ec_seq, &mut ep)?;
        if ver.tag != 0x02 {
            return None;
        }
        let d_oct = read_element(ec_seq, &mut ep)?;
        if d_oct.tag != 0x04 {
            return None;
        }
        let coord_len = curve.coord_len();
        // OpenSSL writes the scalar in a fixed-size OCTET STRING; accept
        // exactly coord_len bytes, or a shorter minimal encoding.
        if d_oct.content.is_empty() || d_oct.content.len() > coord_len {
            return None;
        }
        let mut d = vec![0u8; coord_len];
        d[coord_len - d_oct.content.len()..].copy_from_slice(d_oct.content);
        return Some(ParsedKey::Ec { curve, d });
    }
    None
}

/// Parse a PKCS#1 RSAPrivateKey: SEQUENCE { version, n, e, d, ... }.
fn parse_pkcs1_rsa(der: &[u8]) -> Option<ParsedKey> {
    let mut pos = 0usize;
    let seq = expect_sequence(der, &mut pos)?;
    if pos != der.len() {
        return None;
    }
    let mut p = 0usize;
    // version INTEGER
    let ver = read_element(seq, &mut p)?;
    if ver.tag != 0x02 {
        return None;
    }
    // n
    let n = read_element(seq, &mut p)?;
    if n.tag != 0x02 {
        return None;
    }
    // e
    let e = read_element(seq, &mut p)?;
    if e.tag != 0x02 {
        return None;
    }
    // d
    let d = read_element(seq, &mut p)?;
    if d.tag != 0x02 {
        return None;
    }
    // Strip sign padding from INTEGERs.
    let nv = strip_int(n.content);
    let dv = strip_int(d.content);
    Some(ParsedKey::Rsa {
        n: nv.to_vec(),
        d: dv.to_vec(),
    })
}

/// Remove a leading 0x00 sign byte from a positive INTEGER.
fn strip_int(v: &[u8]) -> &[u8] {
    if v.len() > 1 && v[0] == 0 {
        &v[1..]
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s = s.replace(' ', "");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// RFC 8032 §7.1 test vector 1: seed + public key.
    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let seed: [u8; 32] =
            hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap();
        let msg = b"";
        let sig = ed25519::sign(&seed, msg);
        // RFC 8032 expects this exact signature.
        assert_eq!(
            to_hex(&sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        let pk: [u8; 32] = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .try_into()
            .unwrap();
        assert!(ed25519::verify(&pk, msg, &sig));
        assert!(!ed25519::verify(&pk, b"tampered", &sig));
    }

    /// RFC 6979 §A.2.5 P-256 key: sign a digest and verify it with the
    /// known public key.
    #[test]
    fn ecdsa_p256_sign_verify_roundtrip() {
        let d: Vec<u8> = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let digest: Vec<u8> =
            hex("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf");
        let (r, s) = ecdsa::sign(Curve::P256, &d, &digest).expect("sign");
        let qx = hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
        let qy = hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
        // Encode as DER ECDSA-Sig-Value and verify.
        let der = encode_ecdsa_sig(&r, &s);
        assert!(super::super::crypto::ecdsa::verify_der(
            Curve::P256,
            &qx,
            &qy,
            &digest,
            &der
        ));
        // Tamper with the digest → must fail.
        let mut bad = digest;
        bad[0] ^= 1;
        assert!(!super::super::crypto::ecdsa::verify_der(
            Curve::P256,
            &qx,
            &qy,
            &bad,
            &der
        ));
    }

    /// RSA PKCS#1 v1.5 and PSS sign → verify round-trip with a real
    /// 1024-bit key (n, d generated with an independent implementation).
    #[test]
    fn rsa_sign_verify_roundtrip() {
        let n: Vec<u8> = hex(
            "a643f09b73976142b45694f8a8ae222e00926aae43f8ac9ed9e3828535e19e8d\
             57e435a703e47fd795ba13836faa2121e40abe6768b16a3c930e004f2c0e73f2\
             56e61598ea9fb2e3501ecef756e5465d99a1435a38997167ec54152a777dd2d9\
             2035cfd55e444fb1a14b804ff40b8a23d46c9fab0a451d21af837f5799d57809",
        );
        let d: Vec<u8> = hex(
            "775819235c4b72f2f0839d97076d46f7824d96e9d3bc721bec06d4af4dc7cf89\
             61675be3b0759a16635117a4a6c895d3bfdebe6177d2b1911d75555f7f1e38b6\
             b38050ddc7c619086cca42cf319313c7adf92a4a8e17c3e7f6789208bbf65c09\
             cacd0b3cb16eb3b70838379844509fae17818045f34953e5201fdf1c65a1a5a1",
        );
        let msg = b"TLS 1.3 server CertificateVerify";
        // PKCS#1 v1.5 (SHA-256)
        let mut h = Sha256::new();
        let digest = {
            h.update(msg);
            h.finalize()
        };
        let sig = rsa::sign_pkcs1v15(&n, &d, rsa::DIGEST_INFO_SHA256, &digest).expect("sign pkcs1");
        let key = super::super::crypto::rsa::RsaPublicKey {
            n: n.clone(),
            e: vec![0x01, 0x00, 0x01],
        };
        assert!(key.verify_pkcs1v15(rsa::DIGEST_INFO_SHA256, &digest, &sig));

        // PSS (SHA-256, salt 32)
        let mut h = Sha256::new();
        let sig = rsa::sign_pss(&mut h, &n, &d, msg, 32).expect("sign pss");
        let mut h = Sha256::new();
        assert!(key.verify_pss(&mut h, msg, 32, &sig));
    }
}
