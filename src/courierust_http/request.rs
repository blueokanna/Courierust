//! HTTP request messages (generic over the body type).

use crate::courierust_http::body::Body;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::uri::PathAndQuery;
use crate::courierust_http::version::Version;

/// An HTTP request. The body type is generic so the `no_std` core can use
/// [`Body`] while the threaded layer can use a streaming body.
#[derive(Clone)]
pub struct Request<B = Body> {
    /// Request method.
    pub method: Method,
    /// Request target.
    pub uri: PathAndQuery,
    /// Protocol version.
    pub version: Version,
    /// Header fields (order preserved).
    pub headers: HeaderMap,
    /// Body.
    pub body: B,
}

impl Request<Body> {
    /// Build a request with a GET method.
    #[inline]
    pub fn get(uri: impl Into<PathAndQuery>) -> Self {
        Self::new(Method::GET, uri)
    }

    /// Build a request with a POST method.
    #[inline]
    pub fn post(uri: impl Into<PathAndQuery>) -> Self {
        Self::new(Method::POST, uri)
    }
}

impl<B: Default> Request<B> {
    /// Build a request with a method and target.
    pub fn new(method: Method, uri: impl Into<PathAndQuery>) -> Self {
        Self {
            method,
            uri: uri.into(),
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: B::default(),
        }
    }
}

impl<B> Request<B> {
    /// Replace the body (generic variant).
    pub fn with_body<B2>(self, body: B2) -> Request<B2> {
        Request {
            method: self.method,
            uri: self.uri,
            version: self.version,
            headers: self.headers,
            body,
        }
    }

    /// Set a header (replaces existing same-named fields).
    pub fn header(mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Append a header (keeps duplicates).
    pub fn append_header(
        mut self,
        name: impl Into<HeaderName>,
        value: impl Into<HeaderValue>,
    ) -> Self {
        self.headers.append(name.into(), value.into());
        self
    }
}

impl<B: Default> Default for Request<B> {
    fn default() -> Self {
        Self::new(Method::GET, "/")
    }
}

impl<B: core::fmt::Debug> core::fmt::Debug for Request<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("uri", &self.uri)
            .field("version", &self.version)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .finish()
    }
}

impl Request<Body> {
    /// Consume, returning the head and the body.
    pub fn into_parts(self) -> (RequestHead, Body) {
        let head = RequestHead {
            method: self.method,
            uri: self.uri,
            version: self.version,
            headers: self.headers,
        };
        (head, self.body)
    }
}

/// The head of a request (everything except the body).
#[derive(Clone, Debug)]
pub struct RequestHead {
    /// Request method.
    pub method: Method,
    /// Request target.
    pub uri: PathAndQuery,
    /// Protocol version.
    pub version: Version,
    /// Header fields.
    pub headers: HeaderMap,
}

impl RequestHead {
    /// Build from parts.
    pub fn new(method: Method, uri: PathAndQuery) -> Self {
        Self {
            method,
            uri,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
        }
    }

    /// Attach a body.
    pub fn with_body<B>(self, body: B) -> Request<B> {
        Request {
            method: self.method,
            uri: self.uri,
            version: self.version,
            headers: self.headers,
            body,
        }
    }

    /// Extract the pseudo-header block for HTTP/2, validating that the
    /// required pseudo-headers are present. `scheme` is the connection's
    /// URI scheme (`http` or `https`); RFC 9113 §8.1.2.3 requires the
    /// `:scheme` pseudo-header to match the transport, and nginx rejects
    /// a TLS connection that claims `http`.
    pub fn to_h2_fields(&self, scheme: &str) -> crate::courierust_hpack::HeaderList {
        let mut fields = crate::courierust_hpack::HeaderList::with_capacity(self.headers.len() + 4);
        fields.push(crate::courierust_hpack::HeaderField::new(
            HeaderName::from_lowercase(":method"),
            HeaderValue::from(self.method.as_str()),
        ));
        fields.push(crate::courierust_hpack::HeaderField::new(
            HeaderName::from_lowercase(":path"),
            HeaderValue::from_bytes(self.uri.as_bytes())
                .unwrap_or_else(|_| HeaderValue::from_static("/")),
        ));
        if let Some(auth) = self
            .headers
            .get("authority")
            .or_else(|| self.headers.get("host"))
        {
            fields.push(crate::courierust_hpack::HeaderField::new(
                HeaderName::from_lowercase(":authority"),
                auth.clone(),
            ));
        }
        // A single scheme pseudo-header matching the actual transport
        // (http for plain, https for TLS).
        let is_https = scheme.eq_ignore_ascii_case("https");
        fields.push(crate::courierust_hpack::HeaderField::new(
            HeaderName::from_lowercase(":scheme"),
            HeaderValue::from_bytes(if is_https { b"https" } else { b"http" })
                .unwrap_or_else(|_| HeaderValue::from_static("http")),
        ));
        for (n, v) in self.headers.iter() {
            if n.as_str() == "authority"
                || n.as_str() == "host"
                || n.as_str() == "connection"
                || n.as_str() == "keep-alive"
                || n.as_str() == "proxy-connection"
                || n.as_str() == "transfer-encoding"
                || n.as_str() == "upgrade"
            {
                continue; // hop-by-hop / translated by HTTP/2
            }
            fields.push(crate::courierust_hpack::HeaderField::new(
                n.clone(),
                v.clone(),
            ));
        }
        fields
    }
}
