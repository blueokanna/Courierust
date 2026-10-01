//! `multipart/form-data` request bodies (RFC 7578).
//!
//! The encoder is a pure function of the form and its boundary, so it is
//! testable byte for byte, and the boundary is drawn from the platform
//! entropy source rather than a counter: a predictable boundary lets
//! attacker-supplied content close a part early and forge the next one,
//! which is the multipart form of an injection bug.
//!
//! What this module does **not** do is streaming. [`Multipart::encode`]
//! materializes the body, which is what a `POST` over HTTP/1.1 needs anyway
//! (the length must be known before the request line is written) and what
//! the client's `Body::Bytes` path uploads. A caller with a body too large
//! to hold should send it as a single part's own stream instead.

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_client::Client;
use crate::courierust_error::{Error, Result};
use crate::courierust_http::header::{HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// One part of a form: a field, or a file upload.
#[derive(Debug, Clone)]
pub struct Part {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Part {
    /// A field with a text value.
    pub fn text(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            filename: None,
            content_type: None,
            body: value.into().into_bytes(),
        }
    }

    /// A file upload. `content_type` defaults to
    /// `application/octet-stream` on the wire when omitted, which is what
    /// RFC 7578 §4.4 recommends for unknown binary data.
    pub fn file(
        name: impl Into<String>,
        filename: impl Into<String>,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            name: name.into(),
            filename: Some(filename.into()),
            content_type: content_type.map(str::to_string),
            body: body.into(),
        }
    }

    /// A part with an explicit body and no filename.
    pub fn bytes(name: impl Into<String>, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            filename: None,
            content_type: Some(content_type.to_string()),
            body: body.into(),
        }
    }
}

/// A `multipart/form-data` form.
#[derive(Debug, Clone)]
pub struct Multipart {
    boundary: String,
    parts: Vec<Part>,
}

impl Multipart {
    /// An empty form with a random boundary.
    ///
    /// Fails rather than falling back to a predictable boundary when the
    /// platform entropy source is unavailable: a guessable boundary is a
    /// correctness *and* security problem, and a silent one at that.
    pub fn new() -> Result<Self> {
        let mut entropy = [0u8; 24];
        if !crate::courierust_tls::crypto::rng::fill_random(&mut entropy) {
            return Err(Error::protocol(
                "multipart: the platform entropy source is unavailable, so no boundary can be made",
            ));
        }
        let mut boundary = String::with_capacity(49);
        // Hex, with no character that needs quoting (`bcharsnospace`).
        for byte in entropy {
            boundary.push_str(&format!("{byte:02x}"));
        }
        Ok(Self::with_boundary(boundary))
    }

    /// An empty form with a caller-chosen boundary (tests, or a protocol
    /// that has to agree on one in advance).
    pub fn with_boundary(boundary: impl Into<String>) -> Self {
        Self {
            boundary: boundary.into(),
            parts: Vec::new(),
        }
    }

    /// Append a part.
    pub fn part(mut self, part: Part) -> Self {
        self.parts.push(part);
        self
    }

    /// Append a text field.
    pub fn text(self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.part(Part::text(name, value))
    }

    /// Append a file upload.
    pub fn file(
        self,
        name: impl Into<String>,
        filename: impl Into<String>,
        content_type: Option<&str>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        self.part(Part::file(name, filename, content_type, body))
    }

    /// The boundary in use.
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// The `Content-Type` header value, boundary included.
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// The number of parts.
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Whether the form has no parts.
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Encode the body, `Content-Length` and all.
    ///
    /// Validation is here rather than in the builder so the builder stays
    /// chainable and every failure has one place to be reported from:
    /// a name, filename or boundary containing CR or LF would let a caller
    /// (or the content it was handed) inject headers, and a boundary that
    /// appears inside a part would end it early.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if !is_bchars(&self.boundary) {
            return Err(Error::protocol(
                "multipart: boundary must be 1..=70 characters of RFC 2046 bcharsnospace",
            ));
        }
        let delimiter = format!("\r\n--{}", self.boundary);
        let mut out = Vec::new();
        for part in &self.parts {
            if part.name.is_empty() {
                return Err(Error::protocol("multipart: a part needs a name"));
            }
            check_parameter(&part.name, "name")?;
            if let Some(filename) = &part.filename {
                check_parameter(filename, "filename")?;
            }
            if let Some(content_type) = &part.content_type {
                check_parameter(content_type, "content-type")?;
            }
            if contains(&part.body, delimiter.as_bytes()) {
                // The body would close this part and open the next from its
                // own content: a form that uploads a file containing the
                // delimiter must fail loudly, not upload the wrong bytes.
                return Err(Error::protocol(format!(
                    "multipart: part `{}` contains the boundary",
                    part.name
                )));
            }
            out.extend_from_slice(b"--");
            out.extend_from_slice(self.boundary.as_bytes());
            out.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
            out.extend_from_slice(part.name.as_bytes());
            out.push(b'"');
            if let Some(filename) = &part.filename {
                out.extend_from_slice(b"; filename=\"");
                out.extend_from_slice(filename.as_bytes());
                out.push(b'"');
            }
            out.extend_from_slice(b"\r\nContent-Type: ");
            match &part.content_type {
                Some(content_type) => out.extend_from_slice(content_type.as_bytes()),
                None if part.filename.is_some() => {
                    out.extend_from_slice(b"application/octet-stream")
                }
                // RFC 7578 §4.5: a text field with no type is text/plain.
                None => out.extend_from_slice(b"text/plain"),
            }
            out.extend_from_slice(b"\r\n\r\n");
            out.extend_from_slice(&part.body);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"--");
        out.extend_from_slice(self.boundary.as_bytes());
        out.extend_from_slice(b"--\r\n");
        Ok(out)
    }
}

/// RFC 2046 `bcharsnospace`: what may appear in a boundary.
fn is_bchars(boundary: &str) -> bool {
    !boundary.is_empty()
        && boundary.len() <= 70
        && boundary.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'\''
                        | b'('
                        | b')'
                        | b'+'
                        | b'_'
                        | b','
                        | b'-'
                        | b'.'
                        | b'/'
                        | b':'
                        | b'='
                        | b'?'
                )
        })
}

/// Reject anything that would break out of a quoted parameter.
fn check_parameter(value: &str, what: &str) -> Result<()> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(Error::protocol(format!(
            "multipart: a {what} may not contain CR, LF or NUL"
        )));
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

impl Client {
    /// Send a `multipart/form-data` request.
    ///
    /// The body is the encoded form: `Content-Type` carries the boundary and
    /// `Content-Length` is the exact byte count, so the request is framed
    /// before a byte of it is written.
    pub fn execute_multipart(
        &self,
        url: &str,
        method: Method,
        form: &Multipart,
    ) -> Result<Response<Body>> {
        let mut req = Request::<Body>::new(method, "/");
        req.headers.insert(
            HeaderName::from_lowercase("content-type"),
            HeaderValue::from_bytes(form.content_type().as_bytes())?,
        );
        req.body = Body::Bytes(Bytes::from(form.encode()?));
        self.execute(url, req)
    }

    /// [`Self::execute_multipart`] with `POST`, which is what a form is
    /// almost always submitted with.
    pub fn post_multipart(&self, url: &str, form: &Multipart) -> Result<Response<Body>> {
        self.execute_multipart(url, Method::POST, form)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(form: &Multipart) -> String {
        String::from_utf8(form.encode().expect("encode")).expect("utf8")
    }

    #[test]
    fn the_wire_format_is_what_rfc_7578_says() {
        let form = Multipart::with_boundary("B").text("field", "value").file(
            "upload",
            "a.txt",
            Some("text/plain"),
            b"body".to_vec(),
        );
        assert_eq!(form.content_type(), "multipart/form-data; boundary=B");
        assert_eq!(
            encoded(&form),
            "--B\r\n\
             Content-Disposition: form-data; name=\"field\"\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             value\r\n\
             --B\r\n\
             Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             body\r\n\
             --B--\r\n"
        );
    }

    #[test]
    fn a_missing_content_type_gets_the_rfc_defaults() {
        let form = Multipart::with_boundary("B").text("t", "1").file(
            "f",
            "x.bin",
            None,
            b"\x00\x01".to_vec(),
        );
        assert_eq!(
            encoded(&form),
            "--B\r\n\
             Content-Disposition: form-data; name=\"t\"\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             1\r\n\
             --B\r\n\
             Content-Disposition: form-data; name=\"f\"; filename=\"x.bin\"\r\n\
             Content-Type: application/octet-stream\r\n\
             \r\n\
             \u{0}\u{1}\r\n\
             --B--\r\n"
        );
    }

    #[test]
    fn an_empty_form_is_still_a_well_formed_body() {
        let form = Multipart::with_boundary("B");
        assert_eq!(encoded(&form), "--B--\r\n");
        assert!(form.is_empty());
    }

    #[test]
    fn a_body_containing_the_boundary_is_refused_not_misframed() {
        // Deterministic boundaries are the realistic way this collides, and
        // the failure mode (a part that ends early) is invisible on the wire.
        let form =
            Multipart::with_boundary("B").file("f", "f.bin", None, b"x\r\n--B\r\ny".to_vec());
        let error = form.encode().expect_err("must refuse");
        assert!(error.to_string().contains("boundary"), "{error}");
    }

    #[test]
    fn header_injection_through_a_name_is_refused() {
        for bad in ["a\r\nX: y", "a\nb", "a\u{0}b"] {
            let form = Multipart::with_boundary("B").text(bad, "v");
            assert!(form.encode().is_err(), "{bad:?} must be refused");
        }
        let form = Multipart::with_boundary("B").file("ok", "evil\r\nX: y", None, Vec::new());
        assert!(form.encode().is_err(), "a filename is a parameter too");
        let quoted = Multipart::with_boundary("B").text("ok", "v");
        let mut quoted = quoted;
        quoted.parts[0].content_type = Some("text/plain\r\nX: y".to_string());
        assert!(
            quoted.encode().is_err(),
            "a content-type is a parameter too"
        );
    }

    #[test]
    fn an_illegal_boundary_is_refused() {
        for bad in ["", "with space", "quote\"", "line\rbreak", &"x".repeat(71)] {
            let form = Multipart::with_boundary(bad).text("a", "b");
            assert!(form.encode().is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_random_boundary_is_unpredictable_and_legal() {
        let a = Multipart::new().expect("entropy");
        let b = Multipart::new().expect("entropy");
        assert_ne!(a.boundary(), b.boundary());
        assert_eq!(a.boundary().len(), 48, "24 bytes of hex");
        assert!(a.encode().is_ok());
    }
}
