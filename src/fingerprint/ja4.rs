//! JA4 TLS `ClientHello` fingerprint (FoxIO; SHA-256-based).
//!
//! Implemented from the official JA4 specification:
//!
//! ```text
//! JA4 = (t|q|d) (version2) (d|i) (cipher_count2) (ext_count2) (alpn2)
//!       "_" (sha256(ciphers sorted)[..12])
//!       "_" (sha256(extensions sorted minus SNI+ALPN "_" sigalgs in order)[..12])
//! ```
//!
//! GREASE values are ignored everywhere; all hashes are lowercase hex.

use crate::crypto::sha256::sha256_hex;
use crate::fingerprint::profile::{is_grease, TlsProfile};
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Build the JA4 fingerprint from a profile.
pub fn ja4(p: &TlsProfile) -> String {
    let mut out = String::with_capacity(80);

    // a-part
    out.push(if p.protocol == 'q' {
        'q'
    } else if p.protocol == 'd' {
        'd'
    } else {
        't'
    });
    out.push_str(&ja4_version(p));
    out.push(if p.has_sni { 'd' } else { 'i' });

    let ciphers: Vec<u16> = p
        .ciphers
        .iter()
        .copied()
        .filter(|&c| !is_grease(c))
        .collect();
    let exts: Vec<u16> = p
        .extensions
        .iter()
        .copied()
        .filter(|&e| !is_grease(e))
        .collect();
    out.push_str(&two_digits(ciphers.len()));
    out.push_str(&two_digits(exts.len()));
    out.push_str(&ja4_alpn(&p.alpn));
    out.push('_');

    // b-part: hash of sorted cipher hex list
    if ciphers.is_empty() {
        out.push_str("000000000000");
    } else {
        let mut sorted = ciphers.clone();
        sorted.sort_unstable();
        let s = hex_join(&sorted);
        out.push_str(&sha256_hex(s.as_bytes())[..12]);
    }
    out.push('_');

    // c-part: sorted extensions minus SNI(0) and ALPN(16), then sigalgs
    // in original order.
    let mut exts2: Vec<u16> = exts
        .iter()
        .copied()
        .filter(|&e| e != 0 && e != 0x0010)
        .collect();
    exts2.sort_unstable();
    if exts2.is_empty() {
        out.push_str("000000000000");
    } else {
        let mut s = hex_join(&exts2);
        if !p.signature_algorithms.is_empty() {
            s.push('_');
            s.push_str(&hex_join(&p.signature_algorithms));
        }
        out.push_str(&sha256_hex(s.as_bytes())[..12]);
    }
    out
}

/// TLS version as two chars ("13", "12", ...), "00" for unknown.
/// Per the JA4 spec the version comes from the `supported_versions`
/// extension (highest value) when present, else the version field.
pub fn ja4_version(p: &TlsProfile) -> String {
    let v = p
        .supported_versions
        .iter()
        .copied()
        .filter(|&x| !is_grease(x))
        .max()
        .unwrap_or(p.tls_version);
    version_to_str(v)
}

fn version_to_str(v: u16) -> String {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
    .to_string()
}

/// Two hex/zero-padded digit count (capped at 99).
fn two_digits(n: usize) -> String {
    format!("{:02}", n.min(99))
}

/// First+last chars of the first ALPN value ("00" if absent).
fn ja4_alpn(alpn: &[String]) -> String {
    let first = match alpn.first() {
        Some(s) => s,
        None => return "00".to_string(),
    };
    let b = first.as_bytes();
    if b.is_empty() {
        return "00".to_string();
    }
    let first_alnum = b[0].is_ascii_alphanumeric();
    let last_alnum = b[b.len() - 1].is_ascii_alphanumeric();
    if first_alnum && last_alnum {
        format!("{}{}", b[0] as char, b[b.len() - 1] as char)
    } else {
        let hex: String = b.iter().map(|x| format!("{:02x}", x)).collect();
        let chars: Vec<char> = hex.chars().collect();
        format!("{}{}", chars[0], chars[chars.len() - 1])
    }
}

/// Comma-delimited lowercase 4-hex join.
fn hex_join(v: &[u16]) -> String {
    let mut s = String::new();
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{:04x}", x));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::profile::chrome_tls_profile;

    #[test]
    fn matches_official_spec_example() {
        // The JA4 spec's worked example (which is Chrome's ClientHello):
        //   t13d1516h2_8daaf6152771_e5627efa2ab1
        let p = chrome_tls_profile();
        assert_eq!(ja4(&p), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn no_alpn_gives_00() {
        let mut p = TlsProfile::default();
        p.alpn.clear();
        let fp = ja4(&p);
        assert!(fp.starts_with("t12d00"), "{fp}");
    }

    #[test]
    fn grease_is_filtered() {
        let p = TlsProfile {
            ciphers: vec![0x1301, 0x0a0a, 0x1302, 0x1a1a],
            extensions: vec![0x0000, 0x0010, 0x0a0a, 0x002b],
            alpn: vec!["h2".into()],
            ..Default::default()
        };
        let fp = ja4(&p);
        assert!(fp.starts_with("t12d0203h2"), "{fp}");
    }
}
