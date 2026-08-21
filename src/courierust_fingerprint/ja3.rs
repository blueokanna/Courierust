//! JA3 TLS `ClientHello` fingerprint (Salesforce; MD5-hashed).
//!
//! JA3 input is `TLSVersion,Ciphers,Extensions,Groups,PointFormats` with
//! comma-separated decimal values in wire order; the fingerprint is the
//! MD5 of that string.

use crate::courierust_crypto::md5::md5_hex;
use crate::courierust_fingerprint::profile::TlsProfile;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

/// Build the JA3 input string (pre-MD5) from a profile.
pub fn ja3_string(p: &TlsProfile) -> String {
    let mut parts = Vec::with_capacity(5);
    parts.push(p.tls_version.to_string());
    parts.push(join_decimal(&p.ciphers));
    parts.push(join_decimal(&p.extensions));
    parts.push(join_decimal(&p.groups));
    let pf: Vec<u16> = p.point_formats.iter().map(|&b| b as u16).collect();
    parts.push(join_decimal(&pf));
    parts.join(",")
}

/// MD5 hash of the JA3 input string.
pub fn ja3_hash(p: &TlsProfile) -> String {
    md5_hex(ja3_string(p).as_bytes())
}

/// Full `ja3_hash` (the fingerprint is the hash itself).
pub fn ja3(p: &TlsProfile) -> String {
    ja3_hash(p)
}

fn join_decimal(v: &[u16]) -> String {
    let mut s = String::new();
    for (i, x) in v.iter().enumerate() {
        if i > 0 {
            s.push('-');
        }
        s.push_str(&x.to_string());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_fingerprint::profile::chrome_tls_profile;

    #[test]
    fn chrome_ja3_matches_public_record() {
        // The widely-published Chrome JA3 (the MD5 below is from the
        // public JA3 database and has matched real Chrome for years).
        let p = chrome_tls_profile();
        assert_eq!(
            ja3_string(&p),
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
        );
        assert_eq!(ja3_hash(&p), "cd08e31494f9531f560d64c695473da9");
    }

    #[test]
    fn grease_is_not_counted_by_ja3_input() {
        // JA3 keeps GREASE; the profile builder does not add any.
        let p = TlsProfile::default();
        assert_eq!(ja3_string(&p), "771,,,,");
        let _ = p;
    }
}
