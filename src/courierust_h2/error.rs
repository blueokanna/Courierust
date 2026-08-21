//! HTTP/2 error codes (RFC 9113 §7).

/// HTTP/2 error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    /// NO_ERROR
    NoError = 0x0,
    /// PROTOCOL_ERROR
    ProtocolError = 0x1,
    /// INTERNAL_ERROR
    InternalError = 0x2,
    /// FLOW_CONTROL_ERROR
    FlowControlError = 0x3,
    /// SETTINGS_TIMEOUT
    SettingsTimeout = 0x4,
    /// STREAM_CLOSED
    StreamClosed = 0x5,
    /// FRAME_SIZE_ERROR
    FrameSizeError = 0x6,
    /// REFUSED_STREAM
    RefusedStream = 0x7,
    /// CANCEL
    Cancel = 0x8,
    /// COMPRESSION_ERROR
    CompressionError = 0x9,
    /// CONNECT_ERROR
    ConnectError = 0xa,
    /// ENHANCE_YOUR_CALM
    EnhanceYourCalm = 0xb,
    /// INADEQUATE_SECURITY
    InadequateSecurity = 0xc,
    /// HTTP_1_1_REQUIRED
    Http11Required = 0xd,
}

impl ErrorCode {
    /// Look up a code.
    #[inline]
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x2 => Self::InternalError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            _ => return None,
        })
    }

    /// Numeric value.
    #[inline]
    pub const fn as_u32(&self) -> u32 {
        *self as u32
    }
}
