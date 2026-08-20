//! HTTP/2 SETTINGS parameters and typed settings table.

use crate::error::{Error, Result};
use alloc::vec::Vec;

/// SETTINGS_HEADER_TABLE_SIZE (RFC 9113 §6.5.2)
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
/// SETTINGS_ENABLE_PUSH
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
/// SETTINGS_MAX_CONCURRENT_STREAMS
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
/// SETTINGS_INITIAL_WINDOW_SIZE
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
/// SETTINGS_MAX_FRAME_SIZE
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
/// SETTINGS_MAX_HEADER_LIST_SIZE
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;
/// SETTINGS_NO_RFC7540_PRIORITIES (RFC 9218 §2.1)
pub const SETTINGS_NO_RFC7540_PRIORITIES: u16 = 0x9;

/// A single settings entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    /// Parameter identifier.
    pub id: u16,
    /// Parameter value.
    pub value: u32,
}

/// Typed local/peer settings.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    /// Header-table size for HPACK (default 4096).
    pub header_table_size: u32,
    /// Whether server push is enabled (default 1; clients MUST send 0).
    pub enable_push: u32,
    /// Maximum concurrent streams (0 = unlimited).
    pub max_concurrent_streams: u32,
    /// Initial stream flow-control window (default 65535).
    pub initial_window_size: u32,
    /// Maximum accepted frame payload size (default 16384).
    pub max_frame_size: u32,
    /// Maximum header list size (0 = unlimited).
    pub max_header_list_size: u32,
    /// Whether RFC 7540 priorities are disabled (RFC 9218).
    pub no_rfc7540_priorities: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: 1,
            max_concurrent_streams: 0,
            initial_window_size: 65535,
            max_frame_size: 16384,
            max_header_list_size: 0,
            no_rfc7540_priorities: 0,
        }
    }
}

impl Settings {
    /// Build from a list of entries, validating values.
    pub fn apply(&mut self, entries: &[Setting]) -> Result<()> {
        for s in entries {
            match s.id {
                SETTINGS_HEADER_TABLE_SIZE => self.header_table_size = s.value,
                SETTINGS_ENABLE_PUSH => {
                    if s.value > 1 {
                        return Err(Error::protocol("SETTINGS_ENABLE_PUSH must be 0 or 1"));
                    }
                    self.enable_push = s.value;
                }
                SETTINGS_MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = s.value,
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if s.value > 0x7fff_ffff {
                        return Err(Error::protocol("SETTINGS_INITIAL_WINDOW_SIZE too large"));
                    }
                    self.initial_window_size = s.value;
                }
                SETTINGS_MAX_FRAME_SIZE => {
                    if !(16_384..=16_777_215).contains(&s.value) {
                        return Err(Error::protocol("SETTINGS_MAX_FRAME_SIZE out of range"));
                    }
                    self.max_frame_size = s.value;
                }
                SETTINGS_MAX_HEADER_LIST_SIZE => self.max_header_list_size = s.value,
                SETTINGS_NO_RFC7540_PRIORITIES => {
                    if s.value > 1 {
                        return Err(Error::protocol(
                            "SETTINGS_NO_RFC7540_PRIORITIES must be 0 or 1",
                        ));
                    }
                    self.no_rfc7540_priorities = s.value;
                }
                _ => {} // Unknown settings are ignored.
            }
        }
        Ok(())
    }

    /// Emit all known parameters in a canonical order (fingerprint
    /// modules can reorder this).
    pub fn to_vec(&self) -> Vec<Setting> {
        vec![
            Setting {
                id: SETTINGS_HEADER_TABLE_SIZE,
                value: self.header_table_size,
            },
            Setting {
                id: SETTINGS_ENABLE_PUSH,
                value: self.enable_push,
            },
            Setting {
                id: SETTINGS_MAX_CONCURRENT_STREAMS,
                value: self.max_concurrent_streams,
            },
            Setting {
                id: SETTINGS_INITIAL_WINDOW_SIZE,
                value: self.initial_window_size,
            },
            Setting {
                id: SETTINGS_MAX_FRAME_SIZE,
                value: self.max_frame_size,
            },
            Setting {
                id: SETTINGS_MAX_HEADER_LIST_SIZE,
                value: self.max_header_list_size,
            },
            Setting {
                id: SETTINGS_NO_RFC7540_PRIORITIES,
                value: self.no_rfc7540_priorities,
            },
        ]
    }

    /// Serialize the settings as an HTTP/2 SETTINGS frame **payload**
    /// (RFC 7540 §6.5): a sequence of 6-byte entries
    /// `{ u16 identifier, u32 value }`. This is the exact byte layout
    /// used by the `HTTP2-Settings` header of an RFC 7540 §3.2 `h2c`
    /// Upgrade (base64url-encoded, without the frame header).
    pub fn to_wire(&self) -> Vec<u8> {
        let entries = self.to_vec();
        let mut out = Vec::with_capacity(entries.len() * 6);
        for s in entries {
            out.extend_from_slice(&s.id.to_be_bytes());
            out.extend_from_slice(&s.value.to_be_bytes());
        }
        out
    }
}
