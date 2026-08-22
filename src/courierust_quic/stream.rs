//! QUIC stream identifiers (RFC 9000 §2.1).
//!
//! A stream id's low two bits encode the stream type: `0x0` client
//! bidi, `0x1` server bidi, `0x2` client uni, `0x3` server uni. Streams
//! of the same type are numbered starting at 0.

/// Client-initiated bidirectional stream type.
pub const CLIENT_BIDI: u64 = 0x0;
/// Server-initiated bidirectional stream type.
pub const SERVER_BIDI: u64 = 0x1;
/// Client-initiated unidirectional stream type.
pub const CLIENT_UNI: u64 = 0x2;
/// Server-initiated unidirectional stream type.
pub const SERVER_UNI: u64 = 0x3;

/// The stream type bits of `id`.
#[inline]
pub fn stream_type(id: u64) -> u64 {
    id & 0x3
}

/// The zero-based index of `id` within its type.
#[inline]
pub fn stream_index(id: u64) -> u64 {
    id >> 2
}

/// Build the `index`-th stream id of `type`.
#[inline]
pub fn stream_id(stream_type: u64, index: u64) -> u64 {
    (index << 2) | stream_type
}

/// Whether `id` is client-initiated.
#[inline]
pub fn is_client_initiated(id: u64) -> bool {
    matches!(stream_type(id), CLIENT_BIDI | CLIENT_UNI)
}

/// Whether `id` is a unidirectional stream.
#[inline]
pub fn is_unidirectional(id: u64) -> bool {
    matches!(stream_type(id), CLIENT_UNI | SERVER_UNI)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_types() {
        // Client bidi streams: 0, 4, 8, ...
        assert_eq!(stream_type(0), CLIENT_BIDI);
        assert_eq!(stream_type(4), CLIENT_BIDI);
        assert_eq!(stream_index(4), 1);
        assert_eq!(stream_id(CLIENT_BIDI, 2), 8);
        // Server bidi: 1, 5, ...
        assert_eq!(stream_type(5), SERVER_BIDI);
        // Client uni: 2, 6, ...
        assert_eq!(stream_type(2), CLIENT_UNI);
        assert_eq!(stream_type(6), CLIENT_UNI);
        // Server uni: 3, 7, ...
        assert_eq!(stream_type(3), SERVER_UNI);
        assert!(is_client_initiated(6));
        assert!(!is_client_initiated(7));
        assert!(is_unidirectional(2));
        assert!(!is_unidirectional(0));
    }
}
