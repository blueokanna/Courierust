//! HTTP/1.x wire protocol helpers shared by the client and server:
//! request/status line parsing, header block reading, body framing
//! (Content-Length / chunked) and head serialization.

use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, Result};
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::uri::PathAndQuery;
use crate::courierust_http::version::Version;
use crate::courierust_io::{BufReader, Read};
use alloc::vec::Vec;

/// Maximum size of a single header line.
const MAX_LINE: usize = 64 * 1024;
/// Maximum number of header lines.
const MAX_HEADERS: usize = 1024;
/// Maximum size of the header block.
const MAX_HEADER_BLOCK: usize = 1024 * 1024;

/// A parsed request line.
#[derive(Debug, Clone)]
pub struct RequestLine {
    /// Method.
    pub method: Method,
    /// Request target.
    pub target: PathAndQuery,
    /// Protocol version.
    pub version: Version,
}

/// Parse a request line (`METHOD SP target SP HTTP/x.y`). Strict RFC 9112
/// §3: exactly three tokens, version required; trailing junk is rejected
/// so a proxy and this server cannot disagree on message boundaries.
pub fn parse_request_line(line: &[u8]) -> Result<RequestLine> {
    let line = trim_crlf(line);
    let mut parts = line.split(|&b| b == b' ');
    let method = parts
        .next()
        .filter(|m| !m.is_empty())
        .ok_or_else(|| Error::protocol("missing method"))
        .and_then(Method::from_bytes)?;
    let target = parts
        .next()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| Error::protocol("missing request target"))
        .and_then(PathAndQuery::from_bytes)?;
    let version = parts
        .next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::protocol("missing HTTP version"))
        .and_then(parse_version)?;
    if parts.next().is_some() {
        return Err(Error::protocol("malformed request line"));
    }
    Ok(RequestLine {
        method,
        target,
        version,
    })
}

/// Parse a status line (`HTTP/x.y SP code SP reason`).
pub fn parse_status_line(line: &[u8]) -> Result<(StatusCode, Version)> {
    let line = trim_crlf(line);
    let mut parts = line.splitn(3, |&b| b == b' ');
    let version = parts
        .next()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| Error::protocol("missing version"))
        .and_then(parse_version)?;
    let code = parts
        .next()
        .ok_or_else(|| Error::protocol("missing status code"))?;
    if code.len() != 3 || !code.iter().all(|c| c.is_ascii_digit()) {
        return Err(Error::protocol("status code must be 3 digits"));
    }
    let code: u16 = core::str::from_utf8(code)
        .map_err(|_| Error::protocol("non-ASCII status code"))?
        .parse()
        .map_err(|_| Error::protocol("invalid status code"))?;
    if !(100..=599).contains(&code) {
        return Err(Error::protocol("status code out of range"));
    }
    Ok((StatusCode::from_u16(code), version))
}

/// Parse an HTTP version token (`HTTP/1.1`).
pub fn parse_version(v: &[u8]) -> Result<Version> {
    Ok(match v {
        b"HTTP/1.0" => Version::HTTP_10,
        b"HTTP/1.1" => Version::HTTP_11,
        b"HTTP/2" => Version::HTTP_2,
        _ => return Err(Error::protocol("unsupported HTTP version")),
    })
}

/// Read a header block (lines until an empty line).
pub fn read_headers<R: Read>(reader: &mut BufReader<R>) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let mut total = 0usize;
    loop {
        let line = reader.read_until(b'\n', MAX_LINE)?;
        total += line.len();
        if total > MAX_HEADER_BLOCK {
            return Err(Error::overflow("header block too large"));
        }
        if line.len() >= MAX_LINE {
            return Err(Error::overflow("header line too long"));
        }
        let trimmed = trim_crlf(&line);
        if trimmed.is_empty() {
            break; // end of headers
        }
        if headers.len() >= MAX_HEADERS {
            return Err(Error::overflow("too many header fields"));
        }
        let (name, value) = split_header(trimmed)?;
        headers.append(name, value);
    }
    Ok(headers)
}

/// Like [`read_headers`] but reads each line into the connection's
/// [`crate::courierust_io::Scratch`] line buffer, so steady-state header parsing
/// performs no allocation. The per-connection scratch is the hot path
/// for keep-alive servers and clients.
pub fn read_headers_scratch<R: Read>(
    reader: &mut BufReader<R>,
    scratch: &mut crate::courierust_io::Scratch,
) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let mut total = 0usize;
    loop {
        let line = scratch.line();
        reader.read_until_into(b'\n', MAX_LINE, line)?;
        total += line.len();
        if total > MAX_HEADER_BLOCK {
            return Err(Error::overflow("header block too large"));
        }
        if line.len() >= MAX_LINE {
            return Err(Error::overflow("header line too long"));
        }
        let trimmed = trim_crlf(line);
        if trimmed.is_empty() {
            break; // end of headers
        }
        if headers.len() >= MAX_HEADERS {
            return Err(Error::overflow("too many header fields"));
        }
        let (name, value) = split_header(trimmed)?;
        headers.append(name, value);
    }
    Ok(headers)
}

/// Split a single `Name: value` line.
pub(crate) fn split_header(line: &[u8]) -> Result<(HeaderName, HeaderValue)> {
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or_else(|| Error::protocol("header line missing colon"))?;
    let name = HeaderName::from_bytes(&line[..colon])?;
    let mut start = colon + 1;
    let mut end = line.len();
    while start < end && (line[start] == b' ' || line[start] == b'\t') {
        start += 1;
    }
    while end > start && (line[end - 1] == b' ' || line[end - 1] == b'\t') {
        end -= 1;
    }
    let value = HeaderValue::from_bytes(&line[start..end])?;
    Ok((name, value))
}

/// Trim CR/LF and surrounding whitespace.
pub(crate) fn trim_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r' || line[end - 1] == b' ') {
        end -= 1;
    }
    &line[..end]
}

/// How a message body is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLen {
    /// No body (e.g. HEAD, 204/304, no Content-Length).
    None,
    /// Fixed length.
    Length(usize),
    /// Transfer-Encoding: chunked.
    Chunked,
}

/// Determine the body framing from headers and method/status.
pub fn body_length(
    headers: &HeaderMap,
    method: Option<&Method>,
    status: Option<StatusCode>,
) -> Result<BodyLen> {
    // RFC 9112 §6.3: a response to a HEAD request, or any response with
    // a 1xx/204/304 status, never carries a body regardless of the
    // framing header fields present. These checks MUST precede
    // Content-Length/Transfer-Encoding parsing: otherwise a
    // "204/304 + Content-Length: N" or a "HEAD + Content-Length: N"
    // response would be mis-framed and a client would wait for bytes
    // that never arrive (and, behind a proxy, the mismatch becomes a
    // response-queue-poisoning / smuggling vector).
    let head_response = method == Some(&Method::HEAD);
    let bodyless_status = status.is_some_and(|s| {
        s.is_informational() || s == StatusCode::NO_CONTENT || s == StatusCode::NOT_MODIFIED
    });
    if status.is_some() && (head_response || bodyless_status) {
        return Ok(BodyLen::None);
    }
    let mut te_count = 0usize;
    let mut chunked_pos: Option<usize> = None;
    let mut any_te = false;
    for v in headers.get_all("transfer-encoding") {
        any_te = true;
        let s = v
            .to_str()
            .map_err(|_| Error::protocol("invalid transfer-encoding"))?;
        for tok in s.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                return Err(Error::protocol("invalid transfer-encoding"));
            }
            if tok.eq_ignore_ascii_case("chunked") {
                if chunked_pos.is_some() {
                    return Err(Error::protocol("chunked repeated in transfer-encoding"));
                }
                chunked_pos = Some(te_count);
            }
            te_count += 1;
        }
    }
    if any_te {
        match chunked_pos {
            Some(i) if i == te_count - 1 => return Ok(BodyLen::Chunked),
            Some(_) => {
                return Err(Error::protocol(
                    "chunked must be the final transfer-encoding",
                ))
            }
            None => return Err(Error::protocol("unsupported transfer-encoding")),
        }
    }
    let cls: Vec<&HeaderValue> = headers.get_all("content-length").collect();
    if !cls.is_empty() {
        let parse_len = |v: &HeaderValue| -> Option<usize> {
            let s = v.to_str().ok()?.trim();
            s.parse::<usize>().ok()
        };
        let first = parse_len(cls[0]).ok_or_else(|| Error::protocol("invalid content-length"))?;
        for v in cls.iter().skip(1) {
            if parse_len(v) != Some(first) {
                return Err(Error::protocol("conflicting content-length"));
            }
        }
        return Ok(BodyLen::Length(first));
    }
    if let Some(m) = method {
        if *m == Method::HEAD {
            return Ok(BodyLen::None);
        }
        // Requests without Content-Length/chunked have no body.
        return Ok(BodyLen::None);
    }
    if let Some(s) = status {
        if s.is_informational() || s == StatusCode::NO_CONTENT || s == StatusCode::NOT_MODIFIED {
            return Ok(BodyLen::None);
        }
    }
    Ok(BodyLen::None)
}

/// Append exactly `total` bytes from `reader` into `out` (which must
/// already hold no more than `total` bytes), in bulk.
fn read_into<R: Read>(reader: &mut BufReader<R>, out: &mut Vec<u8>, total: usize) -> Result<()> {
    out.reserve(total.saturating_sub(out.len()));
    while out.len() < total {
        let b = reader.fill_buf()?;
        if b.is_empty() {
            return Err(Error::eof());
        }
        let take = core::cmp::min(total - out.len(), b.len());
        out.extend_from_slice(&b[..take]);
        reader.consume(take);
    }
    Ok(())
}

/// Read a fixed-length body.
pub fn read_body_fixed<R: Read>(
    reader: &mut BufReader<R>,
    len: usize,
    max: usize,
) -> Result<Bytes> {
    let mut out = Vec::new();
    read_body_fixed_into(reader, len, max, &mut out)?;
    Ok(Bytes::from(out))
}

/// Read a fixed-length body into a scratch body buffer (no steady-state
/// allocation).
pub fn read_body_fixed_scratch<R: Read>(
    reader: &mut BufReader<R>,
    len: usize,
    max: usize,
    scratch: &mut crate::courierust_io::Scratch,
) -> Result<Bytes> {
    let out = scratch.body();
    read_body_fixed_into(reader, len, max, out)?;
    Ok(Bytes::from(core::mem::take(out)))
}

fn read_body_fixed_into<R: Read>(
    reader: &mut BufReader<R>,
    len: usize,
    max: usize,
    out: &mut Vec<u8>,
) -> Result<()> {
    if len > max {
        return Err(Error::overflow("body exceeds limit"));
    }
    read_into(reader, out, len)
}

/// Read a chunked body, returning the decoded bytes.
pub fn read_body_chunked<R: Read>(reader: &mut BufReader<R>, max: usize) -> Result<Bytes> {
    let mut out = Vec::new();
    read_body_chunked_into(reader, max, &mut out)?;
    Ok(Bytes::from(out))
}

/// Read a chunked body into a scratch body buffer (no steady-state
/// allocation).
pub fn read_body_chunked_scratch<R: Read>(
    reader: &mut BufReader<R>,
    max: usize,
    scratch: &mut crate::courierust_io::Scratch,
) -> Result<Bytes> {
    let out = scratch.body();
    read_body_chunked_into(reader, max, out)?;
    Ok(Bytes::from(core::mem::take(out)))
}

/// Decode a chunked body into `out`. Sizes are validated against `max`
/// with saturating arithmetic (hostile lengths cannot overflow the
/// limit). The single authority for chunked framing — the event-driven
/// incremental parser shares [`parse_chunk_size`] and the same rules so
/// the blocking and event paths can never disagree on a request's
/// meaning (a disagreement is a smuggling vector behind a proxy).
fn read_body_chunked_into<R: Read>(
    reader: &mut BufReader<R>,
    max: usize,
    out: &mut Vec<u8>,
) -> Result<()> {
    let mut line = Vec::new();
    let mut trailer_total = 0usize;
    loop {
        line.clear();
        reader.read_until_into(b'\n', MAX_LINE, &mut line)?;
        let size = parse_chunk_size(trim_crlf(&line))
            .ok_or_else(|| Error::protocol("invalid chunk size"))?;
        if size == 0 {
            loop {
                line.clear();
                reader.read_until_into(b'\n', MAX_LINE, &mut line)?;
                trailer_total += line.len();
                if trailer_total > MAX_HEADER_BLOCK {
                    return Err(Error::overflow("trailer section too large"));
                }
                if trim_crlf(&line).is_empty() {
                    break;
                }
            }
            break;
        }
        if size > max.saturating_sub(out.len()) {
            return Err(Error::overflow("body exceeds limit"));
        }
        read_into(reader, out, out.len() + size)?;
        let mut crlf = [0u8; 2];
        reader.read_exact_into(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(Error::protocol("chunk terminator missing"));
        }
    }
    Ok(())
}

/// Parse a chunk-size line (`1A`, `1A;ext`, optional whitespace). The
/// size must be pure hex; trailing garbage or overflow returns `None`.
/// Shared by the blocking and event-driven parsers so both paths accept
/// and reject exactly the same byte sequences.
pub(crate) fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let before_ext = match line.iter().position(|&b| b == b';') {
        Some(i) => &line[..i],
        None => line,
    };
    let s = core::str::from_utf8(before_ext).ok()?;
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    usize::from_str_radix(s, 16).ok()
}

/// Serialize a request head into `out`.
pub fn write_request_head(
    out: &mut Vec<u8>,
    method: &Method,
    target: &PathAndQuery,
    version: Version,
    headers: &HeaderMap,
) -> Result<()> {
    out.extend_from_slice(method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(version.wire_str().as_bytes());
    out.extend_from_slice(b"\r\n");
    write_headers(out, headers)
}

/// Serialize a response head into `out`.
pub fn write_response_head(
    out: &mut Vec<u8>,
    status: StatusCode,
    version: Version,
    headers: &HeaderMap,
) -> Result<()> {
    out.extend_from_slice(version.wire_str().as_bytes());
    out.push(b' ');
    let code = IToA::new(status.as_u16() as usize);
    out.extend_from_slice(code.as_slice());
    if let Some(reason) = status.canonical_reason() {
        out.push(b' ');
        out.extend_from_slice(reason.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    write_headers(out, headers)
}

/// Serialize header fields (validated) into `out`.
pub fn write_headers(out: &mut Vec<u8>, headers: &HeaderMap) -> Result<()> {
    for (n, v) in headers.iter() {
        if n.is_pseudo() {
            continue; // pseudo-headers are not serialized in HTTP/1
        }
        // Defense in depth: values constructed via `from_static` skip
        // validation, so reject CR/LF/NUL here rather than letting a
        // crafted value split the message (header injection).
        if v.as_bytes()
            .iter()
            .any(|&c| c == b'\r' || c == b'\n' || c == 0)
        {
            return Err(Error::invalid_header_value());
        }
        out.extend_from_slice(n.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

/// Encode a chunked body chunk.
pub fn encode_chunk(data: &[u8], out: &mut Vec<u8>) {
    put_hex_usize(out, data.len());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// The chunked terminator.
pub const CHUNKED_END: &[u8] = b"0\r\n\r\n";

/// A stack buffer for decimal formatting, so header values like
/// `Content-Length` need no heap allocation.
pub struct IToA {
    buf: [u8; 20],
    len: usize,
}

impl IToA {
    /// Format `v` as decimal ASCII.
    pub fn new(v: usize) -> Self {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        if v == 0 {
            i -= 1;
            buf[i] = b'0';
        } else {
            let mut n = v;
            while n > 0 {
                i -= 1;
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        Self {
            buf,
            len: buf.len() - i,
        }
    }

    /// The formatted digits.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // Digits are written right-to-left from the end of the buffer;
        // the formatted value occupies the trailing `len` bytes.
        &self.buf[self.buf.len() - self.len..]
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Append `v` as lowercase hex into `out` (chunk framing).
fn put_hex_usize(out: &mut Vec<u8>, mut v: usize) {
    let mut buf = [0u8; 16];
    let mut i = buf.len();
    if v == 0 {
        out.push(b'0');
        return;
    }
    while v > 0 {
        i -= 1;
        buf[i] = HEX_DIGITS[v & 0xf];
        v >>= 4;
    }
    out.extend_from_slice(&buf[i..]);
}

/// Whether a `Connection` header value contains the exact comma-separated
/// token `tok` (RFC 9110 §7.6.1). Substring matching here is a bug:
/// `Connection: keep-aliveX` is not a keep-alive request, and
/// `Connection: closex` is not a close request.
fn connection_has_token(value: &str, tok: &str) -> bool {
    value.split(',').any(|t| t.trim().eq_ignore_ascii_case(tok))
}

/// Whether a response indicates connection close.
pub fn wants_close(headers: &HeaderMap) -> bool {
    headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| connection_has_token(v, "close"))
        .unwrap_or(false)
}

/// Whether the request asked for keep-alive.
pub fn keep_alive_requested(version: Version, headers: &HeaderMap) -> bool {
    match headers.get("connection").and_then(|v| v.to_str().ok()) {
        Some(c) if connection_has_token(c, "close") => false,
        Some(c) if connection_has_token(c, "keep-alive") => true,
        _ => version == Version::HTTP_11,
    }
}

/// A URL-unsafe check: headers we must never forward on the wire.
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_error::ErrorKind;
    use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
    use crate::courierust_http::method::Method;
    use crate::courierust_io::{BufReader, SliceReader};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (n, v) in pairs {
            h.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_bytes(v.as_bytes()).unwrap(),
            );
        }
        h
    }

    /// Request-smuggling guard (RFC 9112 §6.3, CWE-444): duplicate
    /// Content-Length fields with differing values must be rejected.
    #[test]
    fn conflicting_content_length_rejected() {
        let h = headers(&[("content-length", "5"), ("content-length", "6")]);
        assert!(body_length(&h, Some(&Method::POST), None).is_err());
    }

    #[test]
    fn identical_content_length_accepted() {
        let h = headers(&[("content-length", "5"), ("content-length", "5")]);
        assert_eq!(
            body_length(&h, Some(&Method::POST), None).unwrap(),
            BodyLen::Length(5)
        );
    }

    #[test]
    fn transfer_encoding_wins_over_content_length() {
        let h = headers(&[("transfer-encoding", "chunked"), ("content-length", "5")]);
        assert_eq!(
            body_length(&h, Some(&Method::POST), None).unwrap(),
            BodyLen::Chunked
        );
    }

    /// A chunk-size line too large for `usize` must be rejected with
    /// `Overflow`, never panic or wrap past the limit (DoS guard).
    #[test]
    fn chunk_size_overflow_rejected() {
        // "ffffffffffffffff\r\n" = usize::MAX, then a payload would follow.
        let wire = b"ffffffffffffffff\r\nrest";
        let mut reader = BufReader::new(SliceReader::new(wire), 64);
        let mut out = Vec::new();
        let r = read_body_chunked_into(&mut reader, 1024, &mut out);
        assert!(r.is_err());
        assert!(matches!(
            r,
            Err(Error {
                kind: ErrorKind::Overflow,
                ..
            })
        ));
    }

    /// Trailer sections are capped so an endless trailer stream cannot pin
    /// a connection.
    #[test]
    fn chunk_trailer_section_capped() {
        // 0-chunk followed by a trailer section that never ends.
        let mut wire = b"0\r\n".to_vec();
        let line = vec![b'x'; 1024];
        for _ in 0..2 * 1024 {
            wire.extend_from_slice(&line);
            wire.push(b'\n');
        }
        let mut reader = BufReader::new(SliceReader::new(&wire), 4096);
        let mut out = Vec::new();
        let r = read_body_chunked_into(&mut reader, 1024, &mut out);
        assert!(r.is_err());
        assert!(matches!(
            r,
            Err(Error {
                kind: ErrorKind::Overflow,
                ..
            })
        ));
    }

    #[test]
    fn itoa_formats_zero_and_large() {
        assert_eq!(IToA::new(0).as_slice(), b"0");
        assert_eq!(IToA::new(200).as_slice(), b"200");
        assert_eq!(IToA::new(65535).as_slice(), b"65535");
    }

    /// Request-smuggling guard: `Transfer-Encoding: notchunked` is not
    /// chunked — the codeword must be exactly `chunked` (a substring
    /// `ends_with` check would wrongly accept it).
    #[test]
    fn transfer_encoding_notchunked_rejected() {
        let h = headers(&[("transfer-encoding", "notchunked")]);
        assert!(body_length(&h, Some(&Method::POST), None).is_err());
    }

    /// `chunked` must be the final codeword; a non-final chunked is a
    /// smuggling vector.
    #[test]
    fn transfer_encoding_chunked_not_final_rejected() {
        let h = headers(&[("transfer-encoding", "chunked, gzip")]);
        assert!(body_length(&h, Some(&Method::POST), None).is_err());
    }

    /// Repeated `chunked` codewords are rejected.
    #[test]
    fn transfer_encoding_repeated_chunked_rejected() {
        let h = headers(&[("transfer-encoding", "chunked, chunked")]);
        assert!(body_length(&h, Some(&Method::POST), None).is_err());
    }

    /// RFC 9112 §6.3: a response to a HEAD request never carries a body,
    /// even when Content-Length is present (a "200-to-HEAD +
    /// Content-Length: N" would otherwise hang the client waiting for N
    /// bytes that never arrive).
    #[test]
    fn head_response_with_content_length_has_no_body() {
        let h = headers(&[("content-length", "100")]);
        assert_eq!(
            body_length(&h, Some(&Method::HEAD), Some(StatusCode::OK)).unwrap(),
            BodyLen::None
        );
        // Same framing on a plain GET response does carry the body.
        assert_eq!(
            body_length(&h, Some(&Method::GET), Some(StatusCode::OK)).unwrap(),
            BodyLen::Length(100)
        );
    }

    /// RFC 9112 §6.3: 204/304 responses never carry a body regardless of
    /// Content-Length/Transfer-Encoding (a caching proxy that emits
    /// "304 + Content-Length" for the cached entity is standard).
    #[test]
    fn no_content_and_not_modified_have_no_body() {
        let cl = headers(&[("content-length", "100")]);
        assert_eq!(
            body_length(&cl, Some(&Method::GET), Some(StatusCode::NO_CONTENT)).unwrap(),
            BodyLen::None
        );
        assert_eq!(
            body_length(&cl, Some(&Method::GET), Some(StatusCode::NOT_MODIFIED)).unwrap(),
            BodyLen::None
        );
        let te = headers(&[("transfer-encoding", "chunked")]);
        assert_eq!(
            body_length(&te, Some(&Method::GET), Some(StatusCode::NO_CONTENT)).unwrap(),
            BodyLen::None
        );
    }

    /// A 1xx informational response never carries a body.
    #[test]
    fn informational_response_has_no_body() {
        let h = headers(&[("content-length", "100")]);
        assert_eq!(
            body_length(&h, Some(&Method::GET), Some(StatusCode::CONTINUE)).unwrap(),
            BodyLen::None
        );
    }

    /// Multiple TE fields are combined as one codeword list.
    #[test]
    fn transfer_encoding_split_across_fields_accepted() {
        let h = headers(&[
            ("transfer-encoding", "gzip"),
            ("transfer-encoding", "chunked"),
        ]);
        assert_eq!(
            body_length(&h, Some(&Method::POST), None).unwrap(),
            BodyLen::Chunked
        );
    }

    /// A request line must have exactly three tokens (RFC 9112 §3);
    /// trailing junk must not be silently ignored.
    #[test]
    fn request_line_extra_tokens_rejected() {
        assert!(parse_request_line(b"GET / HTTP/1.1 garbage\r\n").is_err());
        assert!(parse_request_line(b"GET / HTTP/1.1 extra more\r\n").is_err());
        assert!(parse_request_line(b"GET /\r\n").is_err()); // missing version
    }

    #[test]
    fn request_line_normal_accepted() {
        assert!(parse_request_line(b"GET /a?b HTTP/1.1\r\n").is_ok());
    }

    /// RFC 9112 §2.3: status-code = 3DIGIT. Leading zeros, wrong widths
    /// and non-digits must be rejected, not silently canonicalized.
    #[test]
    fn status_line_requires_three_digits() {
        assert!(parse_status_line(b"HTTP/1.1 200 OK\r\n").is_ok());
        assert!(parse_status_line(b"HTTP/1.1 404 Not Found\r\n").is_ok());
        assert!(parse_status_line(b"HTTP/1.1 0200 OK\r\n").is_err()); // leading zero
        assert!(parse_status_line(b"HTTP/1.1 2000 OK\r\n").is_err()); // 4 digits
        assert!(parse_status_line(b"HTTP/1.1 20 OK\r\n").is_err()); // 2 digits
        assert!(parse_status_line(b"HTTP/1.1 2a0 OK\r\n").is_err()); // non-digit
        assert!(parse_status_line(b"HTTP/1.1 999 OK\r\n").is_err()); // out of range
        assert!(parse_status_line(b"HTTP/1.1 099 OK\r\n").is_err()); // 3 digits but < 100
    }

    /// Chunk-size parsing is shared by the blocking and event-driven
    /// parsers; whitespace and extensions around the size are tolerated,
    /// trailing garbage is not.
    #[test]
    fn chunk_size_whitespace_and_garbage() {
        assert_eq!(parse_chunk_size(b"1A\r\n"), Some(0x1a));
        assert_eq!(parse_chunk_size(b"1A ;ext\r\n"), Some(0x1a));
        assert_eq!(parse_chunk_size(b"1A\t;ext\r\n"), Some(0x1a));
        assert_eq!(parse_chunk_size(b" 1A \r\n"), Some(0x1a));
        assert_eq!(parse_chunk_size(b"1A zzz\r\n"), None); // garbage after size
        assert_eq!(parse_chunk_size(b"\r\n"), None); // empty
        assert_eq!(
            parse_chunk_size(b"ffffffffffffffffffff\r\n"),
            None // overflows usize
        );
    }

    /// `Connection` is a comma-separated token list; substring matching
    /// must not treat `closex`/`keep-aliveX` as the real tokens.
    #[test]
    fn connection_token_boundary() {
        let close = headers(&[("connection", "closex")]);
        assert!(!wants_close(&close), "closex must not count as close");
        let mixed = headers(&[("connection", "keep-alive, close")]);
        assert!(wants_close(&mixed), "exact close token must count");
        let ka = headers(&[("connection", "keep-aliveX")]);
        assert!(
            !keep_alive_requested(Version::HTTP_10, &ka),
            "keep-aliveX must not count as keep-alive for HTTP/1.0"
        );
        let ok = headers(&[("connection", "keep-alive")]);
        assert!(keep_alive_requested(Version::HTTP_10, &ok));
    }
}
