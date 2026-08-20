//! HTTP/1.1 connection serving.

use crate::body::Body;
use crate::bytes::Bytes;
use crate::error::{Error, Result};
use crate::h1;
use crate::http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::http::request::Request;
use crate::http::version::Version;
use crate::io::{BufReader, BufWriter, Scratch};
use crate::server::{Handler, ServerConfig};
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, RecvTimeoutError};

/// Serve HTTP/1.1 requests on `stream` until the connection closes.
pub fn serve(stream: TcpStream, handler: &dyn Handler, config: &ServerConfig) -> Result<()> {
    let mut reader = BufReader::new(&stream, 16 * 1024);
    let mut writer = BufWriter::new(&stream, 16 * 1024);
    let mut scratch = Scratch::new();
    loop {
        // Request line.
        let line = scratch.line();
        match reader.read_until_into(b'\n', 16 * 1024, line) {
            Err(Error {
                kind: crate::error::ErrorKind::UnexpectedEof,
                ..
            }) => return Ok(()),
            Err(e) => return Err(e),
            Ok(()) => {}
        }
        let rl = h1::parse_request_line(line)?;
        let headers = h1::read_headers_scratch(&mut reader, &mut scratch)?;
        let body = match h1::body_length(&headers, Some(&rl.method), None)? {
            h1::BodyLen::None => Body::Empty,
            h1::BodyLen::Length(n) => Body::Bytes(h1::read_body_fixed_scratch(
                &mut reader,
                n,
                config.max_body,
                &mut scratch,
            )?),
            h1::BodyLen::Chunked => Body::Bytes(h1::read_body_chunked_scratch(
                &mut reader,
                config.max_body,
                &mut scratch,
            )?),
        };
        let req = Request {
            method: rl.method,
            uri: rl.target,
            version: rl.version,
            headers,
            body,
        };
        let resp = handler.handle(req);

        let keep_alive = h1::keep_alive_requested(resp.version, &resp.headers)
            && !resp
                .headers
                .get("connection")
                .map(|v| {
                    v.to_str()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .contains("close")
                })
                .unwrap_or(false)
            && resp.version != Version::HTTP_10;

        // Build wire headers (drop hop-by-hop, add framing).
        let mut out_headers = HeaderMap::with_capacity(resp.headers.len() + 2);
        for (n, v) in resp.headers.iter() {
            if h1::is_hop_by_hop(n.as_str()) {
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
            let cl = h1::IToA::new(n);
            out_headers.insert(
                HeaderName::from_lowercase("content-length"),
                HeaderValue::from_bytes(cl.as_slice())?,
            );
        } else if !(resp.status.is_informational()
            || resp.status == crate::http::status::StatusCode::NO_CONTENT
            || resp.status == crate::http::status::StatusCode::NOT_MODIFIED)
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
        h1::write_response_head(head, resp.status, Version::HTTP_11, &out_headers)?;
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

/// Stream a channel body as chunked encoding.
fn stream_response(
    writer: &mut BufWriter<&TcpStream>,
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
        h1::encode_chunk(&chunk, &mut buf);
        writer.write_all(&buf)?;
    }
    writer.write_all(h1::CHUNKED_END)?;
    Ok(())
}
