//! HTTP/1.x wire protocol helpers shared by the client and server:
//! request/status line parsing, header block reading, body framing
//! (Content-Length / chunked) and head serialization.

use crate::bytes::Bytes;
use crate::error::{Error, Result};
use crate::http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::http::method::Method;
use crate::http::status::StatusCode;
use crate::http::uri::PathAndQuery;
use crate::http::version::Version;
use crate::io::{BufReader, Read};

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

/// Parse a request line (`METHOD SP target SP HTTP/x.y`).
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
    let version = match parts.next() {
        Some(v) => parse_version(v)?,
        None => Version::HTTP_10,
    };
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
    let code: u16 = std::str::from_utf8(code)
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
/// [`crate::io::Scratch`] line buffer, so steady-state header parsing
/// performs no allocation. The per-connection scratch is the hot path
/// for keep-alive servers and clients.
pub fn read_headers_scratch<R: Read>(
    reader: &mut BufReader<R>,
    scratch: &mut crate::io::Scratch,
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
fn split_header(line: &[u8]) -> Result<(HeaderName, HeaderValue)> {
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or_else(|| Error::protocol("header line missing colon"))?;
    let name = HeaderName::from_bytes(&line[..colon])?;
    // OWS trimming around the value.
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
fn trim_crlf(line: &[u8]) -> &[u8] {
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
    let te = headers
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !te.is_empty() {
        if te.to_ascii_lowercase().ends_with("chunked") {
            return Ok(BodyLen::Chunked);
        }
        return Err(Error::protocol("unsupported transfer-encoding"));
    }
    // Multiple Content-Length fields are only legal if their values agree;
    // a disagreement is a request-smuggling vector (RFC 9112 §6.3, CWE-444)
    // and must be rejected outright. `get_all` preserves duplicates.
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
    // No framing: only requests with a body / responses with one carry
    // one. HEAD, 1xx, 204, 304 never have a body.
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
    // Responses without framing are body-less (keep-alive requires
    // framing; close-delimited bodies are handled by the caller).
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
    scratch: &mut crate::io::Scratch,
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
    scratch: &mut crate::io::Scratch,
) -> Result<Bytes> {
    let out = scratch.body();
    read_body_chunked_into(reader, max, out)?;
    Ok(Bytes::from(core::mem::take(out)))
}

/// Decode a chunked body into `out`. Chunk sizes are validated against
/// `max` with saturating arithmetic so a hostile size line can never
/// overflow past the limit (remote DoS guard).
fn read_body_chunked_into<R: Read>(
    reader: &mut BufReader<R>,
    max: usize,
    out: &mut Vec<u8>,
) -> Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        reader.read_until_into(b'\n', MAX_LINE, &mut line)?;
        let size_str = trim_crlf(&line);
        let size_str = match size_str.iter().position(|&b| b == b';') {
            Some(i) => &size_str[..i], // strip chunk extensions
            None => size_str,
        };
        let size_str =
            std::str::from_utf8(size_str).map_err(|_| Error::protocol("chunk size not ASCII"))?;
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| Error::protocol("invalid chunk size"))?;
        if size == 0 {
            // Trailer section until blank line. Cap it so an endless
            // stream of trailer lines cannot pin this connection (a
            // slowloris-style resource drain).
            let mut trailer_total = 0usize;
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
        // Saturating subtraction: a huge advertised size can never wrap
        // `out.len() + size` past `max`.
        if size > max.saturating_sub(out.len()) {
            return Err(Error::overflow("body exceeds limit"));
        }
        read_into(reader, out, out.len() + size)?;
        // CRLF after chunk data.
        let mut crlf = [0u8; 2];
        reader.read_exact_into(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(Error::protocol("chunk terminator missing"));
        }
    }
    Ok(())
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

/// Whether a response indicates connection close.
pub fn wants_close(headers: &HeaderMap) -> bool {
    headers
        .get("connection")
        .map(|v| {
            v.to_str()
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("close")
        })
        .unwrap_or(false)
}

/// Whether the request asked for keep-alive.
pub fn keep_alive_requested(version: Version, headers: &HeaderMap) -> bool {
    match headers
        .get("connection")
        .map(|v| v.to_str().unwrap_or("").to_ascii_lowercase())
    {
        Some(c) if c.contains("close") => false,
        Some(c) if c.contains("keep-alive") => true,
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
    use crate::error::ErrorKind;
    use crate::http::header::{HeaderMap, HeaderName, HeaderValue};
    use crate::http::method::Method;
    use crate::io::{BufReader, SliceReader};

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
}
