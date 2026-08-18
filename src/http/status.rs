//! HTTP status codes (RFC 9110 §15).

use core::fmt;

/// An HTTP status code.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusCode(u16);

impl StatusCode {
    /// 100 Continue
    pub const CONTINUE: Self = Self(100);
    /// 101 Switching Protocols
    pub const SWITCHING_PROTOCOLS: Self = Self(101);
    /// 200 OK
    pub const OK: Self = Self(200);
    /// 201 Created
    pub const CREATED: Self = Self(201);
    /// 202 Accepted
    pub const ACCEPTED: Self = Self(202);
    /// 203 Non-Authoritative Information
    pub const NON_AUTHORITATIVE_INFORMATION: Self = Self(203);
    /// 204 No Content
    pub const NO_CONTENT: Self = Self(204);
    /// 205 Reset Content
    pub const RESET_CONTENT: Self = Self(205);
    /// 206 Partial Content
    pub const PARTIAL_CONTENT: Self = Self(206);
    /// 300 Multiple Choices
    pub const MULTIPLE_CHOICES: Self = Self(300);
    /// 301 Moved Permanently
    pub const MOVED_PERMANENTLY: Self = Self(301);
    /// 302 Found
    pub const FOUND: Self = Self(302);
    /// 303 See Other
    pub const SEE_OTHER: Self = Self(303);
    /// 304 Not Modified
    pub const NOT_MODIFIED: Self = Self(304);
    /// 307 Temporary Redirect
    pub const TEMPORARY_REDIRECT: Self = Self(307);
    /// 308 Permanent Redirect
    pub const PERMANENT_REDIRECT: Self = Self(308);
    /// 400 Bad Request
    pub const BAD_REQUEST: Self = Self(400);
    /// 401 Unauthorized
    pub const UNAUTHORIZED: Self = Self(401);
    /// 402 Payment Required
    pub const PAYMENT_REQUIRED: Self = Self(402);
    /// 403 Forbidden
    pub const FORBIDDEN: Self = Self(403);
    /// 404 Not Found
    pub const NOT_FOUND: Self = Self(404);
    /// 405 Method Not Allowed
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// 406 Not Acceptable
    pub const NOT_ACCEPTABLE: Self = Self(406);
    /// 407 Proxy Authentication Required
    pub const PROXY_AUTHENTICATION_REQUIRED: Self = Self(407);
    /// 408 Request Timeout
    pub const REQUEST_TIMEOUT: Self = Self(408);
    /// 409 Conflict
    pub const CONFLICT: Self = Self(409);
    /// 410 Gone
    pub const GONE: Self = Self(410);
    /// 411 Length Required
    pub const LENGTH_REQUIRED: Self = Self(411);
    /// 412 Precondition Failed
    pub const PRECONDITION_FAILED: Self = Self(412);
    /// 413 Payload Too Large
    pub const PAYLOAD_TOO_LARGE: Self = Self(413);
    /// 414 URI Too Long
    pub const URI_TOO_LONG: Self = Self(414);
    /// 415 Unsupported Media Type
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    /// 416 Range Not Satisfiable
    pub const RANGE_NOT_SATISFIABLE: Self = Self(416);
    /// 417 Expectation Failed
    pub const EXPECTATION_FAILED: Self = Self(417);
    /// 421 Misdirected Request
    pub const MISDIRECTED_REQUEST: Self = Self(421);
    /// 422 Unprocessable Entity
    pub const UNPROCESSABLE_ENTITY: Self = Self(422);
    /// 426 Upgrade Required
    pub const UPGRADE_REQUIRED: Self = Self(426);
    /// 428 Precondition Required
    pub const PRECONDITION_REQUIRED: Self = Self(428);
    /// 429 Too Many Requests
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    /// 431 Request Header Fields Too Large
    pub const REQUEST_HEADER_FIELDS_TOO_LARGE: Self = Self(431);
    /// 451 Unavailable For Legal Reasons
    pub const UNAVAILABLE_FOR_LEGAL_REASONS: Self = Self(451);
    /// 500 Internal Server Error
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    /// 501 Not Implemented
    pub const NOT_IMPLEMENTED: Self = Self(501);
    /// 502 Bad Gateway
    pub const BAD_GATEWAY: Self = Self(502);
    /// 503 Service Unavailable
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    /// 504 Gateway Timeout
    pub const GATEWAY_TIMEOUT: Self = Self(504);
    /// 505 HTTP Version Not Supported
    pub const HTTP_VERSION_NOT_SUPPORTED: Self = Self(505);

    /// Wrap a raw code.
    #[inline]
    pub const fn from_u16(n: u16) -> Self {
        Self(n)
    }

    /// The raw code.
    #[inline]
    pub const fn as_u16(&self) -> u16 {
        self.0
    }

    /// The canonical reason phrase, if the code is standard.
    pub fn canonical_reason(&self) -> Option<&'static str> {
        Some(match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            421 => "Misdirected Request",
            422 => "Unprocessable Entity",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            _ => return None,
        })
    }

    /// 1xx class.
    #[inline]
    pub fn is_informational(&self) -> bool {
        (100..200).contains(&self.0)
    }

    /// 2xx class.
    #[inline]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    /// 3xx class.
    #[inline]
    pub fn is_redirection(&self) -> bool {
        (300..400).contains(&self.0)
    }

    /// 4xx class.
    #[inline]
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0)
    }

    /// 5xx class.
    #[inline]
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0)
    }
}

impl Default for StatusCode {
    #[inline]
    fn default() -> Self {
        Self::OK
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatusCode({})", self.0)
    }
}

impl From<u16> for StatusCode {
    #[inline]
    fn from(n: u16) -> Self {
        Self(n)
    }
}

impl From<StatusCode> for u16 {
    #[inline]
    fn from(s: StatusCode) -> Self {
        s.0
    }
}
