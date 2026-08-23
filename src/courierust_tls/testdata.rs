//! Test-only TLS identity: an Ed25519 self-signed certificate for
//! `localhost` (valid 2026-08-20 .. 2036-08-17), generated with OpenSSL
//! 3.x. Used by the end-to-end TLS handshake and HTTPS integration tests.
//!
//! This is a test artifact only — it is never used as a default trust
//! anchor by the library.

/// DER-encoded self-signed certificate.
/// subject = CN=localhost, issuer = CN=localhost.
/// SAN: DNS:localhost, IP:127.0.0.1.
/// basicConstraints = critical, CA:TRUE; keyUsage = digitalSignature,
/// keyCertSign, cRLSign.
pub(crate) const SERVER_CERT_DER: &[u8] = &[
    0x30, 0x82, 0x01, 0x69, 0x30, 0x82, 0x01, 0x1b, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x7b,
    0xa7, 0x64, 0x6f, 0x10, 0x02, 0x62, 0x8d, 0x15, 0x37, 0x61, 0xff, 0xd1, 0xa5, 0xba, 0x8b, 0x22,
    0x49, 0xab, 0x5d, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
    0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x38, 0x32, 0x30, 0x31, 0x33, 0x32, 0x36, 0x35, 0x39,
    0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x38, 0x31, 0x37, 0x31, 0x33, 0x32, 0x36, 0x35, 0x39, 0x5a,
    0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63,
    0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03,
    0x21, 0x00, 0xc1, 0xc6, 0xfc, 0x0c, 0xe9, 0x2b, 0x4a, 0x7b, 0xc3, 0x43, 0xd6, 0x44, 0x5a, 0x54,
    0xdc, 0x8a, 0xf6, 0x86, 0x39, 0x0f, 0x5c, 0x4d, 0xc9, 0x79, 0x21, 0x98, 0x8b, 0xa3, 0xc8, 0x12,
    0x23, 0x30, 0xa3, 0x7f, 0x30, 0x7d, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
    0x14, 0x36, 0xa2, 0x38, 0x9e, 0x39, 0x4a, 0xa8, 0xf1, 0x9b, 0x60, 0xf6, 0x58, 0x4b, 0x5f, 0x2a,
    0x49, 0xaa, 0xbe, 0xe2, 0x0b, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
    0x80, 0x14, 0x36, 0xa2, 0x38, 0x9e, 0x39, 0x4a, 0xa8, 0xf1, 0x9b, 0x60, 0xf6, 0x58, 0x4b, 0x5f,
    0x2a, 0x49, 0xaa, 0xbe, 0xe2, 0x0b, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x13, 0x30,
    0x11, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x87, 0x04, 0x7f, 0x00,
    0x00, 0x01, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
    0x02, 0x01, 0x86, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0xee, 0xd2, 0x7a,
    0x76, 0xff, 0x3d, 0xb9, 0xaf, 0xa9, 0x87, 0x68, 0xbd, 0x85, 0xf9, 0xf6, 0xff, 0xc8, 0x2b, 0xfb,
    0xd0, 0x48, 0x94, 0x69, 0x7a, 0x19, 0x94, 0x45, 0x09, 0x8a, 0x67, 0x4e, 0x8c, 0xec, 0x54, 0xab,
    0xaa, 0xa0, 0xba, 0xec, 0x12, 0xea, 0xfe, 0x12, 0xbf, 0xf8, 0x0e, 0x87, 0x96, 0xed, 0xd9, 0x48,
    0x65, 0xce, 0xf8, 0x48, 0xf6, 0x0c, 0x09, 0xa7, 0x5b, 0x50, 0x5e, 0x00, 0x02,
];

/// PKCS#8 DER-encoded Ed25519 private key matching [`SERVER_CERT_DER`].
pub(crate) const SERVER_KEY_DER: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    0x18, 0xab, 0xee, 0xbf, 0x68, 0x5a, 0x04, 0x6a, 0xcb, 0xd0, 0x92, 0x42, 0x43, 0xaf, 0x2e, 0xe2,
    0x88, 0xb6, 0x91, 0x81, 0x91, 0xea, 0x18, 0x0e, 0x75, 0x6e, 0x62, 0xe6, 0x0e, 0x17, 0x4e, 0xd1,
];

/// A fixed Unix timestamp inside the certificate validity window, so the
/// tests are deterministic regardless of the machine clock.
pub(crate) const NOW: i64 = 1_800_000_000; // 2027-01-14T00:00:00Z

/// The server identity for the test certificate.
pub(crate) fn server_identity() -> crate::courierust_tls::Identity {
    crate::courierust_tls::Identity {
        cert_chain: vec![SERVER_CERT_DER.to_vec()],
        private_key: SERVER_KEY_DER.to_vec(),
        is_rsa: false,
    }
}

/// A root store that trusts the test certificate.
pub(crate) fn root_store() -> crate::courierust_tls::RootStore {
    let mut roots = crate::courierust_tls::RootStore::new();
    roots.add_der(SERVER_CERT_DER.to_vec());
    roots
}

// ---------------------------------------------------------------------
// TLS 1.2 test identity (RSA 2048, self-signed for `localhost`)
// ---------------------------------------------------------------------
//
// TLS 1.2 requires a certificate key that can sign a ServerKeyExchange;
// the Ed25519 identity above is TLS 1.3-only. This RSA 2048 certificate
// (generated with OpenSSL 3.x, valid 2026-08-23..2036-08-20, subject
// CN=localhost, SAN DNS:localhost + IP:127.0.0.1, CA:TRUE, serverAuth)
// covers the TLS 1.2 ECDHE_RSA suites. The DER is embedded via
// `include_bytes!` from this directory (kept as files so the constants
// cannot drift from what openssl actually emitted).

/// DER-encoded RSA 2048 self-signed certificate for `localhost`.
pub(crate) const RSA_SERVER_CERT_DER: &[u8] = include_bytes!("testdata/rsa_server_cert.der");

/// PKCS#8 DER-encoded RSA 2048 private key matching [`RSA_SERVER_CERT_DER`].
pub(crate) const RSA_SERVER_KEY_DER: &[u8] = include_bytes!("testdata/rsa_server_key.der");

/// The RSA server identity used by the TLS 1.2 tests.
pub(crate) fn rsa_server_identity() -> crate::courierust_tls::Identity {
    crate::courierust_tls::Identity {
        cert_chain: vec![RSA_SERVER_CERT_DER.to_vec()],
        private_key: RSA_SERVER_KEY_DER.to_vec(),
        is_rsa: true,
    }
}

/// A root store that trusts the RSA test certificate.
pub(crate) fn rsa_root_store() -> crate::courierust_tls::RootStore {
    let mut roots = crate::courierust_tls::RootStore::new();
    roots.add_der(RSA_SERVER_CERT_DER.to_vec());
    roots
}

// ---------------------------------------------------------------------
// P-384 ECDSA chain (root → intermediate → leaf) for `localhost`
// ---------------------------------------------------------------------
//
// Generated with OpenSSL 3.x (`scripts/gen_p384_certs.ps1`), valid
// 2026-08-23..2036-08-20:
//   * p384_ca_cert         — self-signed P-384 root (CA:TRUE, keyCertSign)
//   * p384_intermediate_cert — P-384 intermediate, signed by the root
//     with ecdsa-with-SHA384 (CA:TRUE, keyCertSign)
//   * p384_leaf_cert       — P-384 leaf for CN=localhost, SAN
//     DNS:localhost + IP:127.0.0.1, signed by the P-384 intermediate
//     with ecdsa-with-SHA384 (CA:FALSE, serverAuth)
//
// This is the exact case the chain verifier must accept: an ECDSA
// intermediate whose SPKI is a 97-byte P-384 uncompressed point, with
// both intermediate and leaf signed using ecdsa-with-SHA384.

/// DER-encoded P-384 root CA certificate.
pub(crate) const P384_CA_CERT_DER: &[u8] = include_bytes!("testdata/p384_ca_cert.der");
/// DER-encoded P-384 intermediate CA certificate.
pub(crate) const P384_INTERMEDIATE_CERT_DER: &[u8] =
    include_bytes!("testdata/p384_intermediate_cert.der");
/// DER-encoded P-384 leaf certificate (CN=localhost).
pub(crate) const P384_LEAF_CERT_DER: &[u8] = include_bytes!("testdata/p384_leaf_cert.der");
/// PKCS#8 DER-encoded P-384 private key matching [`P384_LEAF_CERT_DER`].
pub(crate) const P384_LEAF_KEY_DER: &[u8] = include_bytes!("testdata/p384_leaf_key.der");

/// The P-384 server identity: leaf + intermediate, signed by the P-384
/// root. Used to prove that an ECDSA P-384 intermediate CA validates.
pub(crate) fn p384_server_identity() -> crate::courierust_tls::Identity {
    crate::courierust_tls::Identity {
        cert_chain: vec![
            P384_LEAF_CERT_DER.to_vec(),
            P384_INTERMEDIATE_CERT_DER.to_vec(),
        ],
        private_key: P384_LEAF_KEY_DER.to_vec(),
        is_rsa: false,
    }
}

/// A root store that trusts the P-384 root CA.
pub(crate) fn p384_root_store() -> crate::courierust_tls::RootStore {
    let mut roots = crate::courierust_tls::RootStore::new();
    roots.add_der(P384_CA_CERT_DER.to_vec());
    roots
}

// ---------------------------------------------------------------------
// Name-constraint test chain (root → constrained intermediate → leaf)
// ---------------------------------------------------------------------
//
// Generated with OpenSSL 3.x (`scripts/gen_nc_certs.ps1`):
//   * nc_ca_cert         — self-signed P-256 root
//   * nc_intermediate_cert — P-256 intermediate carrying
//     `nameConstraints = critical, permitted;DNS:localhost`
//   * nc_leaf_ok_cert    — leaf for CN=localhost, SAN DNS:localhost +
//     IP:127.0.0.1 (inside the permitted subtree)
//   * nc_leaf_bad_cert   — leaf for CN=evil.com, SAN DNS:evil.com
//     (outside the permitted subtree — must be rejected)

/// DER-encoded name-constraint root CA.
pub(crate) const NC_CA_CERT_DER: &[u8] = include_bytes!("testdata/nc_ca_cert.der");
/// DER-encoded name-constraint intermediate CA.
pub(crate) const NC_INTERMEDIATE_CERT_DER: &[u8] =
    include_bytes!("testdata/nc_intermediate_cert.der");
/// DER-encoded leaf inside the permitted subtree (localhost).
pub(crate) const NC_LEAF_OK_CERT_DER: &[u8] = include_bytes!("testdata/nc_leaf_ok_cert.der");
/// DER-encoded leaf outside the permitted subtree (evil.com).
pub(crate) const NC_LEAF_BAD_CERT_DER: &[u8] = include_bytes!("testdata/nc_leaf_bad_cert.der");

/// A root store that trusts the name-constraint root CA.
pub(crate) fn nc_root_store() -> crate::courierust_tls::RootStore {
    let mut roots = crate::courierust_tls::RootStore::new();
    roots.add_der(NC_CA_CERT_DER.to_vec());
    roots
}
