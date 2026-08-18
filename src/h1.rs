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
use std::io::Write;

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
    let has_cl = headers.contains_key("content-length");
    if has_cl {
        let cl = headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error::protocol("invalid content-length"))?;
        let n: usize = cl
            .trim()
            .parse()
            .map_err(|_| Error::protocol("invalid content-length"))?;
        return Ok(BodyLen::Length(n));
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

/// Read a fixed-length body.
pub fn read_body_fixed<R: Read>(
    reader: &mut BufReader<R>,
    len: usize,
    max: usize,
) -> Result<Bytes> {
    if len > max {
        return Err(Error::overflow("body exceeds limit"));
    }
    let data = reader.read_exact(len)?;
    Ok(Bytes::from(data))
}

/// Read a chunked body, returning the decoded bytes.
pub fn read_body_chunked<R: Read>(reader: &mut BufReader<R>, max: usize) -> Result<Bytes> {
    let mut out = Vec::new();
    loop {
        let line = reader.read_until(b'\n', MAX_LINE)?;
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
            // Trailer section until blank line.
            loop {
                let t = reader.read_until(b'\n', MAX_LINE)?;
                if trim_crlf(&t).is_empty() {
                    break;
                }
            }
            break;
        }
        if out.len() + size > max {
            return Err(Error::overflow("body exceeds limit"));
        }
        let chunk = reader.read_exact(size)?;
        out.extend_from_slice(&chunk);
        // CRLF after chunk data.
        let crlf = reader.read_exact(2)?;
        if crlf != b"\r\n" {
            return Err(Error::protocol("chunk terminator missing"));
        }
    }
    Ok(Bytes::from(out))
}

/// Serialize a request head into `out`.
pub fn write_request_head(
    out: &mut Vec<u8>,
    method: &Method,
    target: &PathAndQuery,
    version: Version,
    headers: &HeaderMap,
) -> Result<()> {
    write!(
        out,
        "{} {} {}\r\n",
        method.as_str(),
        target.as_str(),
        version.wire_str()
    )
    .map_err(|e| Error::io(e.to_string()))?;
    write_headers(out, headers)
}

/// Serialize a response head into `out`.
pub fn write_response_head(
    out: &mut Vec<u8>,
    status: StatusCode,
    version: Version,
    headers: &HeaderMap,
) -> Result<()> {
    let reason = status.canonical_reason().unwrap_or("");
    write!(
        out,
        "{} {} {}\r\n",
        version.wire_str(),
        status.as_u16(),
        reason
    )
    .map_err(|e| Error::io(e.to_string()))?;
    write_headers(out, headers)
}

/// Serialize header fields (validated) into `out`.
pub fn write_headers(out: &mut Vec<u8>, headers: &HeaderMap) -> Result<()> {
    for (n, v) in headers.iter() {
        if n.is_pseudo() {
            continue; // pseudo-headers are not serialized in HTTP/1
        }
        write!(out, "{}: ", n.as_str()).map_err(|e| Error::io(e.to_string()))?;
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(())
}

/// Encode a chunked body chunk.
pub fn encode_chunk(data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// The chunked terminator.
pub const CHUNKED_END: &[u8] = b"0\r\n\r\n";

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
