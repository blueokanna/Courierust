//! Fluent request construction: the front end to [`Client::execute`].
//!
//! ```no_run
//! # use courierust::courierust_client::Client;
//! # fn main() -> courierust::Result<()> {
//! let client = Client::new();
//! let resp = client
//!     .request("https://example.com/api/items", courierust::courierust_http::Method::POST)
//!     .query([("page", "2")])
//!     .header("accept", "application/json")
//!     .basic_auth("user", "secret")
//!     .timeout(std::time::Duration::from_secs(5))
//!     .body(r#"{"name":"widget"}"#)
//!     .send()?;
//! assert!(resp.status.is_success());
//! # Ok(())
//! # }
//! ```
//!
//! Everything here is a thin, additive layer: it builds the same
//! [`Request`] the crate has always sent and hands it to the same
//! [`Client::execute`] path, so h1, h2, h3, redirects and the pools
//! behave exactly as they do for a hand-built request. The only state the
//! builder adds is what a single request can meaningfully override —
//! its priority and its transport deadline — and nothing it does can be
//! undone by a caller who passes `Request` directly.
//!
//! The builder never panics and never drops an error on the floor. A
//! header value that cannot go on the wire (CR, LF or NUL in it) is
//! refused by the transport that serializes the message — h1, h2 and h3
//! each name the field in the error — so a chain that looks fine still
//! fails loudly at `send` instead of silently sending something else.

use crate::courierust_body::Body;
use crate::courierust_client::Client;
use crate::courierust_error::Result;
use crate::courierust_h2::priority::Priority;
use crate::courierust_http::form;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use std::time::Duration;

/// A request under construction, bound to the client that will send it.
///
/// Obtained from [`Client::request`] (or one of the verb shorthands such
/// as [`Client::put`]); [`RequestBuilder::send`] consumes it.
pub struct RequestBuilder<'a> {
    client: &'a Client,
    url: String,
    req: Request<Body>,
    priority: Priority,
    timeout: Option<Duration>,
}

impl<'a> RequestBuilder<'a> {
    /// Start building a request for `url` with `method`.
    ///
    /// The URL — not the request's URI — decides scheme, authority and
    /// path; `Request::new(method, "/")` starts with the path the URL
    /// carries, which is what [`Client::execute`] expects.
    pub(crate) fn new(client: &'a Client, url: String, method: Method) -> Self {
        Self {
            client,
            url,
            req: Request::new(method, "/"),
            priority: Priority::default(),
            timeout: None,
        }
    }

    /// Set a header field, replacing any field of the same name.
    ///
    /// The name and value conversions are the same ones
    /// [`Request::header`] uses, so a chain and a hand-built request
    /// cannot drift apart in what they accept.
    pub fn header(mut self, name: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> Self {
        self.req.headers.insert(name.into(), value.into());
        self
    }

    /// Add a header field without replacing a field of the same name.
    pub fn append_header(
        mut self,
        name: impl Into<HeaderName>,
        value: impl Into<HeaderValue>,
    ) -> Self {
        self.req.headers.append(name.into(), value.into());
        self
    }

    /// Merge a whole header map, replacing fields of the same names.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        for (name, value) in headers.into_vec() {
            self.req.headers.insert(name, value);
        }
        self
    }

    /// Set the request body.
    pub fn body(mut self, body: impl Into<Body>) -> Self {
        self.req.body = body.into();
        self
    }

    /// Append a query string to the URL, percent-encoding both halves of
    /// every pair.
    ///
    /// The encoding is `application/x-www-form-urlencoded`
    /// ([`crate::courierust_http::form`]): a space becomes `+`, everything
    /// outside the passthrough set becomes `%XX`. That is what browsers
    /// and most frameworks produce and expect in a query string; a caller
    /// who needs RFC 3986 `%20` form writes the query into the URL
    /// itself, where it is sent verbatim.
    pub fn query<'p, I>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (&'p str, &'p str)>,
    {
        let encoded = form::serialize(params);
        if !encoded.is_empty() {
            // The query goes before any fragment. Appending to the end of
            // `http://host/path#section` would put the parameters inside
            // the fragment, where a server never sees them — the request
            // would arrive without a query at all.
            let at = self.url.find('#').unwrap_or(self.url.len());
            let separator = if self.url[..at].contains('?') {
                '&'
            } else {
                '?'
            };
            self.url.insert(at, separator);
            self.url.insert_str(at + 1, &encoded);
        }
        self
    }

    /// Set an `application/x-www-form-urlencoded` body.
    ///
    /// Sets `content-type` too, unless the caller already chose one.
    pub fn form<'p, I>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = (&'p str, &'p str)>,
    {
        let encoded = form::serialize(fields);
        if !self.req.headers.contains_key("content-type") {
            self.req.headers.insert(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
        }
        self.req.body = Body::from(encoded);
        self
    }

    /// Send `Authorization: Basic …` (RFC 7617).
    ///
    /// `user:password` is base64-encoded as a whole, so a non-ASCII
    /// username or password travels as UTF-8 bytes with no further
    /// escaping. The encoding exists to survive a transport, not to
    /// protect the password: it belongs on `https://`. RFC 7617 forbids a
    /// colon inside the user-id; one is encoded as-is, and a server splits
    /// on the first colon, so it would read the rest of the user-id as
    /// part of the password.
    pub fn basic_auth(self, username: &str, password: &str) -> Self {
        let mut credentials = String::with_capacity(username.len() + password.len() + 1);
        credentials.push_str(username);
        credentials.push(':');
        credentials.push_str(password);
        let mut value = String::with_capacity(
            6 + crate::courierust_crypto::base64::encoded_len(credentials.len()),
        );
        value.push_str("Basic ");
        crate::courierust_crypto::base64::encode_into(credentials.as_bytes(), &mut value);
        self.header(
            HeaderName::from_static("authorization"),
            HeaderValue::from(value),
        )
    }

    /// Send `Authorization: Bearer …` (RFC 6750).
    pub fn bearer_auth(self, token: &str) -> Self {
        let mut value = String::with_capacity(7 + token.len());
        value.push_str("Bearer ");
        value.push_str(token);
        self.header(
            HeaderName::from_static("authorization"),
            HeaderValue::from(value),
        )
    }

    /// Signal an RFC 9218 priority for this request.
    ///
    /// A hint, not a scheduling instruction: HTTP/2 reads it (it is the
    /// input to the WUCS scheduler) and HTTP/1.1 and HTTP/3 have no
    /// field to carry it, so those transports send the request
    /// unchanged.
    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Bound this request by `timeout` instead of
    /// [`ClientConfig::read_timeout`](crate::courierust_client::ClientConfig::read_timeout).
    ///
    /// The timeout has the same meaning as the configured one — a
    /// transport deadline for the request's own progress, not a wall
    /// clock over the whole exchange — and applies to each attempt, so a
    /// redirect chain gives every hop a full timeout. It is restored
    /// afterwards: a pooled connection returns to the pool with the
    /// client's configured deadline, never with this one.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Send the request.
    ///
    /// Redirects are followed per
    /// [`ClientConfig::max_redirects`](crate::courierust_client::ClientConfig::max_redirects),
    /// and the client's
    /// [`default_headers`](crate::courierust_client::ClientConfig::default_headers)
    /// are merged in first — a field set here always wins.
    pub fn send(self) -> Result<Response<Body>> {
        self.client
            .execute_built(&self.url, self.req, self.priority, self.timeout)
    }
}
