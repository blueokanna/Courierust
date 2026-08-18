//! HTTP response messages (generic over the body type).

use crate::http::body::Body;
use crate::http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::http::status::StatusCode;
use crate::http::version::Version;

/// An HTTP response. The body type is generic so the `no_std` core can use
/// [`Body`] while the threaded layer can use a streaming body.
#[derive(Clone)]
pub struct Response<B = Body> {
    /// Status code.
    pub status: StatusCode,
    /// Protocol version.
    pub version: Version,
    /// Header fields (order preserved).
    pub headers: HeaderMap,
    /// Body.
    pub body: B,
}

impl Response<Body> {
    /// Build an empty OK response.
    #[inline]
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }

    /// Build a response with a status code.
    #[inline]
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Body::Empty,
        }
    }
}

impl<B> Response<B> {
    /// Set a header (replaces existing same-named fields).
    pub fn header(mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Append a header (keeps duplicates).
    pub fn append_header(mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> Self {
        self.headers.append(name.into(), value.into());
        self
    }

    /// Replace the body (generic variant).
    pub fn with_body<B2>(self, body: B2) -> Response<B2> {
        Response {
            status: self.status,
            version: self.version,
            headers: self.headers,
            body,
        }
    }
}

impl<B: Default> Default for Response<B> {
    fn default() -> Self {
        Self {
            status: StatusCode::OK,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: B::default(),
        }
    }
}

impl<B: core::fmt::Debug> core::fmt::Debug for Response<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .finish()
    }
}

impl Response<Body> {
    /// Consume, returning the head and the body.
    pub fn into_parts(self) -> (ResponseHead, Body) {
        let head = ResponseHead {
            status: self.status,
            version: self.version,
            headers: self.headers,
        };
        (head, self.body)
    }
}

/// The head of a response (everything except the body).
#[derive(Clone, Debug)]
pub struct ResponseHead {
    /// Status code.
    pub status: StatusCode,
    /// Protocol version.
    pub version: Version,
    /// Header fields.
    pub headers: HeaderMap,
}

impl ResponseHead {
    /// Build from a status code.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
        }
    }

    /// Attach a body.
    pub fn with_body<B>(self, body: B) -> Response<B> {
        Response {
            status: self.status,
            version: self.version,
            headers: self.headers,
            body,
        }
    }
}
