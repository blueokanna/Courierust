//! gRPC status codes (mirror of `google.rpc.Code`).

/// OK
pub const OK: u32 = 0;
/// CANCELLED
pub const CANCELLED: u32 = 1;
/// UNKNOWN
pub const UNKNOWN: u32 = 2;
/// INVALID_ARGUMENT
pub const INVALID_ARGUMENT: u32 = 3;
/// DEADLINE_EXCEEDED
pub const DEADLINE_EXCEEDED: u32 = 4;
/// NOT_FOUND
pub const NOT_FOUND: u32 = 5;
/// ALREADY_EXISTS
pub const ALREADY_EXISTS: u32 = 6;
/// PERMISSION_DENIED
pub const PERMISSION_DENIED: u32 = 7;
/// RESOURCE_EXHAUSTED
pub const RESOURCE_EXHAUSTED: u32 = 8;
/// FAILED_PRECONDITION
pub const FAILED_PRECONDITION: u32 = 9;
/// ABORTED
pub const ABORTED: u32 = 10;
/// OUT_OF_RANGE
pub const OUT_OF_RANGE: u32 = 11;
/// UNIMPLEMENTED
pub const UNIMPLEMENTED: u32 = 12;
/// INTERNAL
pub const INTERNAL: u32 = 13;
/// UNAVAILABLE
pub const UNAVAILABLE: u32 = 14;
/// DATA_LOSS
pub const DATA_LOSS: u32 = 15;
/// UNAUTHENTICATED
pub const UNAUTHENTICATED: u32 = 16;

/// Canonical name for a code.
pub fn name(code: u32) -> &'static str {
    match code {
        OK => "OK",
        CANCELLED => "CANCELLED",
        UNKNOWN => "UNKNOWN",
        INVALID_ARGUMENT => "INVALID_ARGUMENT",
        DEADLINE_EXCEEDED => "DEADLINE_EXCEEDED",
        NOT_FOUND => "NOT_FOUND",
        ALREADY_EXISTS => "ALREADY_EXISTS",
        PERMISSION_DENIED => "PERMISSION_DENIED",
        RESOURCE_EXHAUSTED => "RESOURCE_EXHAUSTED",
        FAILED_PRECONDITION => "FAILED_PRECONDITION",
        ABORTED => "ABORTED",
        OUT_OF_RANGE => "OUT_OF_RANGE",
        UNIMPLEMENTED => "UNIMPLEMENTED",
        INTERNAL => "INTERNAL",
        UNAVAILABLE => "UNAVAILABLE",
        DATA_LOSS => "DATA_LOSS",
        UNAUTHENTICATED => "UNAUTHENTICATED",
        _ => "UNKNOWN",
    }
}

/// A gRPC status value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The status code.
    pub code: u32,
    /// The status message.
    pub message: String,
}

impl Status {
    /// Build a status.
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The canonical name.
    pub fn name(&self) -> &'static str {
        name(self.code)
    }
}

impl Default for Status {
    fn default() -> Self {
        Self {
            code: OK,
            message: String::new(),
        }
    }
}
