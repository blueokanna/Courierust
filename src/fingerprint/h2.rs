//! Chrome's HTTP/2 wire fingerprint.
//!
//! Beyond the TLS `ClientHello` (JA3/JA4), browsers are identified by
//! their HTTP/2 behavior: the SETTINGS values and their order, the
//! initial `WINDOW_UPDATE`, and the way headers are ordered on the wire.
//! This module encodes the values Chromium has used for years so an
//! HTTP/2 connection *behaves* like Chrome, not just handshakes like it.
//!
//! > Values are the long-standing Chromium defaults (`http2_session.cc`
//! > / `spdy_session.cc`). They are configurable; Chromium changes them
//! > occasionally, and servers fingerprint the whole behavior, so keep
//! > the profile in sync with the Chrome build you are impersonating.

use crate::h2::settings::{
    Setting, Settings, SETTINGS_ENABLE_PUSH, SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_INITIAL_WINDOW_SIZE, SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_MAX_HEADER_LIST_SIZE,
};
use crate::hpack::HeaderField;
use alloc::vec::Vec;

/// Chrome's HTTP/2 fingerprint constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChromeH2Fingerprint {
    /// SETTINGS_HEADER_TABLE_SIZE
    pub header_table_size: u32,
    /// SETTINGS_ENABLE_PUSH (Chrome: 0, push is dead)
    pub enable_push: u32,
    /// SETTINGS_MAX_CONCURRENT_STREAMS
    pub max_concurrent_streams: u32,
    /// SETTINGS_INITIAL_WINDOW_SIZE (6 MiB)
    pub initial_window_size: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE
    pub max_header_list_size: u32,
    /// The connection-level `WINDOW_UPDATE` increment sent right after
    /// SETTINGS (65535 + 12517377 = 12 MiB total).
    pub connection_window_update: u32,
    /// Whether regular headers are emitted lowercase-sorted after the
    /// pseudo-headers (Chrome behavior).
    pub sort_headers: bool,
}

impl Default for ChromeH2Fingerprint {
    fn default() -> Self {
        Self {
            header_table_size: 65_536,
            enable_push: 0,
            max_concurrent_streams: 100,
            initial_window_size: 6_291_456, // 0x00600000
            max_header_list_size: 262_144,  // 0x00040000
            connection_window_update: 12_517_377, // 0x00BF0001
            sort_headers: true,
        }
    }
}

impl ChromeH2Fingerprint {
    /// The exact Chrome fingerprint.
    pub fn chrome() -> Self {
        Self::default()
    }

    /// The SETTINGS entries in the order Chrome sends them.
    pub fn settings_entries(&self) -> Vec<Setting> {
        alloc::vec![
            Setting { id: SETTINGS_HEADER_TABLE_SIZE, value: self.header_table_size },
            Setting { id: SETTINGS_ENABLE_PUSH, value: self.enable_push },
            Setting { id: SETTINGS_MAX_CONCURRENT_STREAMS, value: self.max_concurrent_streams },
            Setting { id: SETTINGS_INITIAL_WINDOW_SIZE, value: self.initial_window_size },
            Setting { id: SETTINGS_MAX_HEADER_LIST_SIZE, value: self.max_header_list_size },
        ]
    }

    /// Apply the fingerprint onto local settings, preserving Chrome's
    /// advertised values.
    pub fn apply_to_settings(&self, s: &mut Settings) {
        s.header_table_size = self.header_table_size;
        s.enable_push = self.enable_push;
        s.max_concurrent_streams = self.max_concurrent_streams;
        s.initial_window_size = self.initial_window_size;
        s.max_header_list_size = self.max_header_list_size;
    }

    /// Build an `h2::Config` shaped like Chrome (client role).
    pub fn h2_config(&self) -> crate::h2::connection::Config {
        let mut cfg = crate::h2::connection::Config::default();
        cfg.client = true;
        self.apply_to_settings(&mut cfg.local_settings);
        cfg
    }
}

/// Reorder a header block like Chrome: pseudo-headers first, then the
/// regular headers sorted by (lowercased) name.
pub fn order_headers_chrome(fields: &[HeaderField]) -> Vec<HeaderField> {
    let mut out = Vec::with_capacity(fields.len());
    let mut rest: Vec<&HeaderField> = Vec::new();
    for f in fields {
        if f.name.is_pseudo() {
            out.push(f.clone());
        } else {
            rest.push(f);
        }
    }
    rest.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    for f in rest {
        out.push(f.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpack::HeaderField;
    use crate::http::header::{HeaderName, HeaderValue};

    fn hf(n: &str, v: &str) -> HeaderField {
        HeaderField::new(
            HeaderName::from_bytes(n.as_bytes()).unwrap(),
            HeaderValue::from_bytes(v.as_bytes()).unwrap(),
        )
    }

    #[test]
    fn chrome_settings_values() {
        let c = ChromeH2Fingerprint::chrome();
        assert_eq!(c.header_table_size, 65_536);
        assert_eq!(c.enable_push, 0);
        assert_eq!(c.max_concurrent_streams, 100);
        assert_eq!(c.initial_window_size, 6_291_456);
        assert_eq!(c.max_header_list_size, 262_144);
        assert_eq!(c.connection_window_update, 12_517_377);
    }

    #[test]
    fn chrome_header_order() {
        let fields = vec![
            hf("accept-encoding", "gzip"),
            hf(":method", "GET"),
            hf("user-agent", "x"),
            hf(":path", "/"),
            hf("cache-control", "no-cache"),
        ];
        let ordered = order_headers_chrome(&fields);
        let names: Vec<&str> = ordered.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec![":method", ":path", "accept-encoding", "cache-control", "user-agent"]);
    }
}
