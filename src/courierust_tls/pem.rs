//! PEM reading (RFC 7468).
//!
//! One reader for every PEM input this stack accepts — a server
//! identity's certificate chain, its private key (PKCS#8, PKCS#1 or
//! SEC1), a trust-anchor bundle — so the armour rules are enforced once
//! instead of per caller: a `BEGIN` must have its matching `END`, labels
//! must agree, the payload must decode, and nothing half-decoded is ever
//! handed on.

use crate::courierust_crypto::base64;
use crate::courierust_tls::{TlsError, TlsResult};
use alloc::string::String;
use alloc::vec::Vec;

/// One `-----BEGIN <label>-----` … `-----END <label>-----` block.
#[derive(Debug, Clone)]
pub(crate) struct Block {
    /// The label between `BEGIN ` and `-----` (e.g. `CERTIFICATE`).
    pub(crate) label: String,
    /// The decoded DER payload.
    pub(crate) der: Vec<u8>,
}

/// Every PEM block in `pem`, in document order.
///
/// Text outside blocks is ignored on purpose: PEM files in the wild carry
/// comments, `Bag Attributes` / `subject=…` dumps, and a single file may
/// legitimately bundle a key next to its certificate. What is *not*
/// tolerated is a block that cannot be trusted — an `END` without a
/// `BEGIN`, a label mismatch, a missing `END`, invalid base64 — because
/// half a certificate or half a key is worse than none: it would fail
/// later, at handshake time, in a place that cannot explain why.
pub(crate) fn blocks(pem: &str) -> TlsResult<Vec<Block>> {
    let mut out = Vec::new();
    let mut open: Option<(String, String)> = None;
    for line in pem.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let label = rest
                .strip_suffix("-----")
                .ok_or_else(|| TlsError::Protocol("malformed PEM BEGIN line".into()))?;
            if label.is_empty() {
                return Err(TlsError::Protocol("empty PEM label".into()));
            }
            if open.is_some() {
                return Err(TlsError::Protocol("nested PEM block".into()));
            }
            open = Some((String::from(label), String::new()));
        } else if let Some(rest) = line.strip_prefix("-----END ") {
            let label = rest
                .strip_suffix("-----")
                .ok_or_else(|| TlsError::Protocol("malformed PEM END line".into()))?;
            let (begin, body) = open
                .take()
                .ok_or_else(|| TlsError::Protocol("PEM END without BEGIN".into()))?;
            if begin != label {
                return Err(TlsError::Protocol(
                    "PEM BEGIN/END labels do not match".into(),
                ));
            }
            let der = base64::decode_str(&body)
                .map_err(|_| TlsError::Protocol("invalid base64 in PEM block".into()))?;
            out.push(Block { label: begin, der });
        } else if let Some((_, body)) = open.as_mut() {
            body.push_str(line);
        }
    }
    if open.is_some() {
        return Err(TlsError::Protocol("PEM block without END".into()));
    }
    Ok(out)
}

/// The payloads of every block carrying `label`.
pub(crate) fn der_blocks(pem: &str, label: &str) -> TlsResult<Vec<Vec<u8>>> {
    Ok(blocks(pem)?
        .into_iter()
        .filter(|block| block.label == label)
        .map(|block| block.der)
        .collect())
}

/// The certificate chain in `pem` (leaf first, as RFC 7468 §2.1 orders a
/// chain file). An input without a single `CERTIFICATE` block is an
/// error: a server configured with an empty chain would fail every
/// handshake, long after the misconfiguration.
pub(crate) fn certificate_chain(pem: &str) -> TlsResult<Vec<Vec<u8>>> {
    let chain = der_blocks(pem, "CERTIFICATE")?;
    if chain.is_empty() {
        return Err(TlsError::Certificate(
            "no CERTIFICATE block in the PEM input".into(),
        ));
    }
    Ok(chain)
}

/// The private key in `pem`: PKCS#8 (`PRIVATE KEY`), PKCS#1
/// (`RSA PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`).
pub(crate) fn private_key(pem: &str) -> TlsResult<Vec<u8>> {
    let mut key: Option<Vec<u8>> = None;
    for block in blocks(pem)? {
        match block.label.as_str() {
            "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                if key.is_some() {
                    return Err(TlsError::Certificate(
                        "more than one private key in the PEM input".into(),
                    ));
                }
                key = Some(block.der);
            }
            "ENCRYPTED PRIVATE KEY" => {
                return Err(TlsError::Certificate(
                    "encrypted private keys are not supported: decrypt the key first \
                     (openssl pkey -in key.pem -out key.plain.pem)"
                        .into(),
                ))
            }
            _ => {}
        }
    }
    key.ok_or_else(|| {
        TlsError::Certificate(
            "no private key in the PEM input (expected PRIVATE KEY, RSA PRIVATE KEY \
             or EC PRIVATE KEY)"
                .into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn armor(label: &str, der: &[u8]) -> String {
        let mut out = String::new();
        out.push_str("-----BEGIN ");
        out.push_str(label);
        out.push_str("-----\n");
        let b64 = base64::encode(der);
        let mut first = true;
        for chunk in b64.as_bytes().chunks(64) {
            if !first {
                out.push('\n');
            }
            first = false;
            out.push_str(core::str::from_utf8(chunk).unwrap());
        }
        out.push_str("\n-----END ");
        out.push_str(label);
        out.push_str("-----\n");
        out
    }

    #[test]
    fn round_trips_an_armored_block() {
        let der: Vec<u8> = (0u8..=255).collect();
        let pem = armor("CERTIFICATE", &der);
        let blocks = blocks(&pem).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].der, der);
    }

    #[test]
    fn ignores_text_outside_blocks() {
        let der = vec![1u8, 2, 3];
        let pem = format!(
            "Bag Attributes\n    friendlyName: test\n    subject=CN=localhost\n{}",
            armor("CERTIFICATE", &der)
        );
        let blocks = blocks(&pem).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].der, der);
    }

    #[test]
    fn keeps_document_order_across_multiple_blocks() {
        let pem = format!(
            "{}{}",
            armor("CERTIFICATE", &[1, 2]),
            armor("CERTIFICATE", &[3, 4])
        );
        let chain = der_blocks(&pem, "CERTIFICATE").unwrap();
        assert_eq!(chain, vec![vec![1, 2], vec![3, 4]]);
    }

    #[test]
    fn rejects_broken_armor() {
        // END without BEGIN.
        assert!(blocks("-----END CERTIFICATE-----\n").is_err());
        // Label mismatch.
        assert!(blocks("-----BEGIN CERTIFICATE-----\nAA==\n-----END PRIVATE KEY-----\n").is_err());
        // Missing END.
        assert!(blocks("-----BEGIN CERTIFICATE-----\nAA==\n").is_err());
        // Nested BEGIN.
        assert!(blocks(
            "-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAA==\n\
             -----END CERTIFICATE-----\n"
        )
        .is_err());
        // Not base64.
        assert!(blocks("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n").is_err());
    }

    #[test]
    fn an_empty_chain_is_an_error() {
        let pem = armor("PRIVATE KEY", &[9, 9]);
        assert!(certificate_chain(&pem).is_err());
    }

    #[test]
    fn encrypted_keys_are_named_not_guessed_at() {
        let pem = armor("ENCRYPTED PRIVATE KEY", &[9, 9]);
        let err = private_key(&pem).unwrap_err().to_string();
        assert!(err.contains("encrypted"), "{err}");
    }

    #[test]
    fn picks_the_key_and_refuses_two_of_them() {
        let one = format!(
            "{}{}",
            armor("CERTIFICATE", &[1]),
            armor("PRIVATE KEY", &[2])
        );
        assert_eq!(private_key(&one).unwrap(), vec![2]);
        let two = format!(
            "{}{}",
            armor("PRIVATE KEY", &[2]),
            armor("EC PRIVATE KEY", &[3])
        );
        assert!(private_key(&two).is_err());
    }
}
