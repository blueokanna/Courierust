//! A TLS `ClientHello` parameter profile — the input shared by the JA3
//! and JA4 builders.
//!
//! Values are the raw wire parameters; the builders handle GREASE
//! filtering and hashing. A profile describes *what* a client sends, so
//! you can feed it to any TLS library and reproduce a browser-shaped
//! handshake.

/// A TLS `ClientHello` profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsProfile {
    /// Transport: `'t'` (TCP), `'q'` (QUIC), `'d'` (DTLS).
    pub protocol: char,
    /// TLS protocol version field of the `ClientHello`, e.g. `0x0303`
    /// (TLS 1.2 — what JA3 reports; browsers often keep this at 1.2 even
    /// when negotiating 1.3).
    pub tls_version: u16,
    /// Values of the `supported_versions` extension (0x002b) in order.
    /// JA4 derives the version from the highest of these when present.
    pub supported_versions: alloc::vec::Vec<u16>,
    /// Whether the SNI extension (0x0000) is present.
    pub has_sni: bool,
    /// Cipher suites in `ClientHello` order.
    pub ciphers: alloc::vec::Vec<u16>,
    /// Extensions in `ClientHello` order (SNI and ALPN included).
    pub extensions: alloc::vec::Vec<u16>,
    /// Signature algorithms (extension 0x000d) in order.
    pub signature_algorithms: alloc::vec::Vec<u16>,
    /// Supported groups (extension 0x000a) in order.
    pub groups: alloc::vec::Vec<u16>,
    /// EC point formats (extension 0x000b).
    pub point_formats: alloc::vec::Vec<u8>,
    /// ALPN protocols in order (e.g. `h2`, `http/1.1`).
    pub alpn: alloc::vec::Vec<alloc::string::String>,
}

impl Default for TlsProfile {
    fn default() -> Self {
        Self {
            protocol: 't',
            tls_version: 0x0303,
            supported_versions: alloc::vec::Vec::new(),
            has_sni: true,
            ciphers: alloc::vec::Vec::new(),
            extensions: alloc::vec::Vec::new(),
            signature_algorithms: alloc::vec::Vec::new(),
            groups: alloc::vec::Vec::new(),
            point_formats: alloc::vec::Vec::new(),
            alpn: alloc::vec::Vec::new(),
        }
    }
}

/// Whether a 16-bit value is a GREASE value (RFC 8701).
///
/// GREASE values have the form `0x?a?a` — both bytes equal and the low
/// nibble `0xa`: `0x0a0a, 0x1a1a, .., 0xfafa`.
#[inline]
pub fn is_grease(v: u16) -> bool {
    v & 0x000f == 0x000a && (v >> 8) == (v & 0x00ff)
}

/// A representative Chrome `ClientHello` profile.
///
/// The cipher and extension sets below are the ones Chromium has shipped
/// for years (they are also the exact example used in the JA4 spec, so
/// the derived JA4 is independently verifiable). Chrome deliberately
/// randomizes *extension ordering* between builds and even connections,
/// which is why JA4 sorts extensions — the *set* stays stable even as the
/// order changes. Treat these as "typical Chrome"; override the fields
/// for a specific build.
pub fn chrome_tls_profile() -> TlsProfile {
    TlsProfile {
        protocol: 't',
        // The ClientHello version field stays at TLS 1.2 (0x0303 = 771)
        // — what the classic Chrome JA3 records.
        tls_version: 0x0303,
        // Negotiates TLS 1.3 via supported_versions (JA4 reports "13").
        supported_versions: alloc::vec![0x0304, 0x0303, 0x0302, 0x0301],
        has_sni: true,
        // TLS 1.3 AES-GCM / CHACHA + TLS 1.2 ECDHE suites + CBC fallbacks.
        ciphers: alloc::vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
        // Classic wire order: SNI, extended_master_secret,
        // renegotiation_info, supported_groups, ec_point_formats,
        // session_ticket, ALPN, status_request, signature_algorithms,
        // signed_certificate_timestamp, key_share, psk_key_exchange_modes,
        // supported_versions, compress_certificate,
        // application_settings, padding.
        extensions: alloc::vec![
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012,
            0x0033, 0x002d, 0x002b, 0x001b, 0x4469, 0x0015,
        ],
        // rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pkcs1_sha256,
        // ecdsa_secp256r1_sha256, rsa_pss_rsae_sha512, rsa_pkcs1_sha512,
        // ecdsa_secp384r1_sha384, rsa_pkcs1_sha1.
        signature_algorithms: alloc::vec![
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        // x25519, secp256r1, secp384r1
        groups: alloc::vec![29, 23, 24],
        point_formats: alloc::vec![0],
        alpn: alloc::vec!["h2".into(), "http/1.1".into()],
    }
}

