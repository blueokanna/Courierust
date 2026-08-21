//! HTTP/1.1 connection serving.

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, Result};
use crate::courierust_h1;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::request::Request;
use crate::courierust_http::version::Version;
use crate::courierust_io::{BufReader, BufWriter, Scratch};
use crate::courierust_net::ConnStream;
use crate::courierust_server::{Handler, ServerConfig};
use std::sync::mpsc::{Receiver, RecvTimeoutError};

/// Serve HTTP/1.1 requests on `stream` until the connection closes.
pub(crate) fn serve(
    stream: &ConnStream,
    handler: &dyn Handler,
    config: &ServerConfig,
) -> Result<()> {
    let mut reader = BufReader::new(stream, 16 * 1024);
    let mut writer = BufWriter::new(stream, 16 * 1024);
    let mut scratch = Scratch::new();
    loop {
        // Request line.
        let line = scratch.line();
        match reader.read_until_into(b'\n', 16 * 1024, line) {
            Err(Error {
                kind: crate::courierust_error::ErrorKind::UnexpectedEof,
                ..
            }) => return Ok(()),
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        let rl = courierust_h1::parse_request_line(line)?;
        let headers = courierust_h1::read_headers_scratch(&mut reader, &mut scratch)?;
        let upgrade = is_h2c_upgrade(&headers);
        let body = match courierust_h1::body_length(&headers, Some(&rl.method), None)? {
            courierust_h1::BodyLen::None => Body::Empty,
            courierust_h1::BodyLen::Length(n) => {
                Body::Bytes(courierust_h1::read_body_fixed_scratch(
                    &mut reader,
                    n,
                    config.max_body,
                    &mut scratch,
                )?)
            }
            courierust_h1::BodyLen::Chunked => {
                Body::Bytes(courierust_h1::read_body_chunked_scratch(
                    &mut reader,
                    config.max_body,
                    &mut scratch,
                )?)
            }
        };
        let req = Request {
            method: rl.method,
            uri: rl.target,
            version: rl.version,
            headers,
            body,
        };
        let resp = handler.handle(req);

        // RFC 7540 §3.2: an `h2c` Upgrade request switches this connection
        // to HTTP/2 (when the server is configured to speak h2). The
        // handler's response to the upgrade request is delivered on h2
        // stream 1. An h1-only server ignores the Upgrade and answers
        // normally.
        if upgrade && config.http2 {
            let out =
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";
            writer.write_all(out)?;
            writer.flush()?;
            drop(writer);
            drop(reader);
            return crate::courierust_server::h2::serve_upgraded(stream, handler, config, resp);
        }

        // `keep_alive_requested` applies exact-token `Connection`
        // semantics (a `closex` token does not close) and already
        // returns false for a close token; no separate substring check
        // here, or this path and the event path would disagree.
        let keep_alive = courierust_h1::keep_alive_requested(resp.version, &resp.headers)
            && resp.version != Version::HTTP_10;

        // Build wire headers (drop hop-by-hop, add framing).
        let mut out_headers = HeaderMap::with_capacity(resp.headers.len() + 2);
        for (n, v) in resp.headers.iter() {
            if courierust_h1::is_hop_by_hop(n.as_str()) {
                continue;
            }
            out_headers.append(n.clone(), v.clone());
        }
        let chunked = matches!(resp.body, Body::Channel(_));
        let body_len = match &resp.body {
            Body::Bytes(b) => Some(b.len()),
            _ => None,
        };
        if chunked {
            out_headers.insert(
                HeaderName::from_lowercase("transfer-encoding"),
                HeaderValue::from_static("chunked"),
            );
        } else if let Some(n) = body_len {
            let cl = courierust_h1::IToA::new(n);
            out_headers.insert(
                HeaderName::from_lowercase("content-length"),
                HeaderValue::from_bytes(cl.as_slice())?,
            );
        } else if !(resp.status.is_informational()
            || resp.status == crate::courierust_http::status::StatusCode::NO_CONTENT
            || resp.status == crate::courierust_http::status::StatusCode::NOT_MODIFIED)
        {
            // Empty body: pin Content-Length: 0 so the response framing is
            // unambiguous for the peer.
            out_headers.insert(
                HeaderName::from_lowercase("content-length"),
                HeaderValue::from_static("0"),
            );
        }
        out_headers.insert(
            HeaderName::from_lowercase("connection"),
            HeaderValue::from_static(if keep_alive { "keep-alive" } else { "close" }),
        );

        let head = scratch.body();
        courierust_h1::write_response_head(head, resp.status, Version::HTTP_11, &out_headers)?;
        writer.write_all(head)?;
        match resp.body {
            Body::Empty => {}
            Body::Bytes(b) => {
                writer.write_all(&b)?;
            }
            Body::Channel(rx) => {
                stream_response(&mut writer, rx, config.read_timeout)?;
            }
        }
        writer.flush()?;

        if !keep_alive {
            break;
        }
    }
    Ok(())
}

/// Whether the request is an RFC 7540 §3.2 `h2c` Upgrade: `Upgrade: h2c`
/// plus a `Connection` token of `upgrade` and an `HTTP2-Settings` header.
fn is_h2c_upgrade(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if upgrade != "h2c" {
        return false;
    }
    if !headers.contains_key("http2-settings") {
        return false;
    }
    headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
        .split(',')
        .any(|t| t.trim() == "upgrade")
}

/// Stream a channel body as chunked encoding.
fn stream_response(
    writer: &mut BufWriter<&ConnStream>,
    rx: Receiver<Result<Bytes>>,
    timeout: Option<std::time::Duration>,
) -> Result<()> {
    let mut buf = Vec::new();
    loop {
        let chunk = match timeout {
            Some(t) => match rx.recv_timeout(t) {
                Ok(c) => c?,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(Error::timeout("body stream timed out"));
                }
                Err(RecvTimeoutError::Disconnected) => break,
            },
            None => match rx.recv() {
                Ok(c) => c?,
                Err(_) => break,
            },
        };
        if chunk.is_empty() {
            continue;
        }
        buf.clear();
        courierust_h1::encode_chunk(&chunk, &mut buf);
        writer.write_all(&buf)?;
    }
    writer.write_all(courierust_h1::CHUNKED_END)?;
    Ok(())
}
