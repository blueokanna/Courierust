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

/// A representative modern Chromium `ClientHello` profile.
///
/// The parameters mirror what Chrome/Edge (~M140) put on the wire: the
/// long-stable cipher list, ML-DSA signature schemes, the ECH GREASE
/// extension, and the current `application_settings` extension number.
/// One deliberate omission: the post-quantum hybrid group
/// (`X25519MLKEM768`) is *not* advertised, because a fabricated hybrid
/// share fails strict parsing on the peer side (there is no real ML-KEM
/// key behind it), which upstream risk-controls read as an
/// impersonating client. The classical group list below is what every
/// TLS 1.3 stack negotiates. Chrome deliberately randomizes *extension
/// ordering* between builds and even connections, which is why JA4
/// sorts extensions — the *set* stays stable even as the order changes.
/// Treat these as "typical modern Chromium"; override the fields for a
/// specific build.
pub fn chrome_tls_profile() -> TlsProfile {
    TlsProfile {
        protocol: 't',
        tls_version: 0x0303,
        supported_versions: alloc::vec![0x0304, 0x0303],
        has_sni: true,
        ciphers: alloc::vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        extensions: alloc::vec![
            0x0000, 0x000a, 0x0012, 0x0033, 0xfe0d, 0x002b, 0x0010, 0x002d, 0x0023, 0x0017, 0x000d,
            0x001b, 0x0005, 0x44cd, 0x000b, 0xff01,
        ],
        signature_algorithms: alloc::vec![
            0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ],
        groups: alloc::vec![29, 23, 24],
        point_formats: alloc::vec![0],
        alpn: alloc::vec!["h2".into(), "http/1.1".into()],
    }
}

/// Frozen samples for the published fingerprint vectors.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::TlsProfile;

    /// The exact ClientHello parameters of the published JA3/JA4
    /// sample (the well-known Chrome record). Frozen so the vector
    /// tests keep a fixed input while [`super::chrome_tls_profile`]
    /// tracks new Chromium releases.
    pub(crate) fn ja_sample_profile() -> TlsProfile {
        TlsProfile {
            protocol: 't',
            tls_version: 0x0303,
            supported_versions: alloc::vec![0x0304, 0x0303, 0x0302, 0x0301],
            has_sni: true,
            ciphers: alloc::vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: alloc::vec![
                0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012,
                0x0033, 0x002d, 0x002b, 0x001b, 0x4469, 0x0015,
            ],
            signature_algorithms: alloc::vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            groups: alloc::vec![29, 23, 24],
            point_formats: alloc::vec![0],
            alpn: alloc::vec!["h2".into(), "http/1.1".into()],
        }
    }
}
