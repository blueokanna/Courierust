//! HTTP/1.1 connection serving.

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, Result};
use crate::courierust_h1;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::version::Version;
use crate::courierust_io::{BufReader, BufWriter, Scratch};
use crate::courierust_net::ConnStream;
use crate::courierust_server::{ws, Handler, ServerConfig};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;

/// Bytes of unread request data a refusal is willing to drain before the
/// socket closes (`linger_close`), and how long it is willing to wait.
///
pub(crate) const LINGER_BUDGET: usize = 64 * 1024;
pub(crate) const LINGER_DEADLINE: std::time::Duration = std::time::Duration::from_millis(250);

/// Serve HTTP/1.1 requests on `stream` until the connection closes.
pub(crate) fn serve(
    stream: &Arc<ConnStream>,
    handler: &dyn Handler,
    config: &ServerConfig,
) -> Result<()> {
    let mut reader = BufReader::new(stream.clone(), 16 * 1024);
    let mut writer = BufWriter::new(stream.clone(), 16 * 1024);
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
        let rl = match courierust_h1::parse_request_line(line) {
            Ok(rl) => rl,
            Err(e) => {
                // A malformed request line gets an answer, not a silent
                // disconnect: a client (or a proxy in front) that sends a
                // bad request should learn that, and a silent close is
                // indistinguishable from a network failure.
                write_early_error(&mut writer, 400, "bad request")?;
                let _ = writer.flush();
                stream.linger_close(LINGER_BUDGET, LINGER_DEADLINE);
                return Err(e);
            }
        };
        let headers = courierust_h1::read_headers_scratch(&mut reader, &mut scratch)?;

        // RFC 9112 §3.2: an HTTP/1.1 request must carry exactly one,
        // non-empty `Host` field. Checking it *before* the body is read
        // means an ambiguous request cannot reach a handler or pin a body
        // buffer, and a proxy in front never has to guess which authority
        // the request meant.
        let mut early = courierust_h1::host_header_error(rl.version, &headers)
            .map(|reason| error_response(400, reason));
        let refuses_early = early.is_some();

        let upgrade = early.is_none() && is_h2c_upgrade(&headers);
        let body = if early.is_some() {
            Body::Empty
        } else {
            match courierust_h1::body_length(&headers, Some(&rl.method), None)? {
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
            }
        };
        // RFC 7230 §6.3: a request carrying `Connection: close` forces the
        // connection closed after this response, regardless of the
        // response's own keep-alive hints.
        let request_close = courierust_h1::wants_close(&headers);
        let req = Request {
            method: rl.method,
            uri: rl.target,
            version: rl.version,
            headers,
            body,
        };

        // ---- WebSocket upgrade -------------------------------------
        // Decided *before* the normal handler runs, so the policy checks
        // (origin, subprotocol, extensions, version) can inspect the very
        // request the client sent. When the upgrade is accepted this call
        // never returns: the connection becomes a framed byte stream.
        if early.is_none()
            && config.websocket.enabled
            && crate::courierust_ws::is_websocket_upgrade(&req.headers)
        {
            match handler.websocket(&req) {
                ws::WsUpgradeReply::Pass => {}
                ws::WsUpgradeReply::Refuse(resp) => early = Some(resp),
                ws::WsUpgradeReply::Accept(service) => {
                    let peer = stream.peer_addr().ip();
                    let tls_active = config.tls.is_some();
                    match ws::plan(&req, peer, tls_active, &config.websocket) {
                        Ok(plan) => {
                            let mut head = HeaderMap::with_capacity(6);
                            for (n, v) in plan.accept_headers()?.iter() {
                                head.append(n.clone(), v.clone());
                            }
                            let bytes = scratch.body();
                            courierust_h1::write_response_head(
                                bytes,
                                StatusCode::SWITCHING_PROTOCOLS,
                                Version::HTTP_11,
                                &head,
                            )?;
                            writer.write_all(bytes)?;
                            writer.flush()?;
                            // The reader still holds any bytes the client
                            // pipelined behind the handshake — hand it to
                            // the session so none are lost. Frame traffic
                            // is read in much larger chunks than a request
                            // head, so the buffer grows first.
                            let mut reader = reader;
                            reader.ensure_capacity(config.websocket.read_buffer);
                            return ws::serve_blocking(
                                stream.clone(),
                                reader,
                                plan,
                                service,
                                &config.websocket,
                            );
                        }
                        Err(refusal) => early = Some(refusal.response()),
                    }
                }
            }
        }

        let resp = match early {
            Some(resp) => resp,
            None => handler.handle(req),
        };

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
            return crate::courierust_server::h2::serve_upgraded(
                stream.as_ref(),
                handler,
                config,
                resp,
            );
        }

        // `keep_alive_requested` applies exact-token `Connection`
        // semantics (a `closex` token does not close) and already
        // returns false for a close token; no separate substring check
        // here, or this path and the event path would disagree.
        let keep_alive = !request_close
            && courierust_h1::keep_alive_requested(resp.version, &resp.headers)
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
        if refuses_early {
            // The peer is likely still sending a body we chose not to
            // read; draining a bounded amount keeps the response from
            // being destroyed by a RST on Linux.
            stream.linger_close(LINGER_BUDGET, LINGER_DEADLINE);
        }

        if !keep_alive {
            break;
        }
    }
    Ok(())
}

/// RFC 9112 §3.2: an HTTP/1.1 request carries exactly one `Host` field,
/// and it is not empty. HTTP/1.0 (and older) may omit it.
/// A small, fully-framed error response (`Connection: close`), used for
/// requests refused before a handler sees them (the `Host` rule, a
/// malformed request line).
pub(crate) fn error_response(status: u16, message: &str) -> Response<Body> {
    let mut resp: Response<Body> = Response::with_status(StatusCode::from_u16(status));
    resp.headers.insert(
        HeaderName::from_lowercase("content-type"),
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.headers.insert(
        HeaderName::from_lowercase("connection"),
        HeaderValue::from_static("close"),
    );
    resp.body = Body::Bytes(Bytes::from(alloc::format!("{message}\n")));
    resp
}

/// Write an error response for a request that failed to parse, where the
/// normal response path (which needs a parsed `Request`) cannot be used.
///
/// Fully framed (`Content-Length` + `Connection: close`) so the peer
/// knows exactly where the message ends even though this is the last
/// thing it will get.
fn write_early_error(
    writer: &mut BufWriter<Arc<ConnStream>>,
    status: u16,
    message: &str,
) -> Result<()> {
    let body = alloc::format!("{message}\n");
    let mut headers = HeaderMap::with_capacity(3);
    headers.insert(
        HeaderName::from_lowercase("content-type"),
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        HeaderName::from_lowercase("content-length"),
        HeaderValue::from_bytes(courierust_h1::IToA::new(body.len()).as_slice())?,
    );
    headers.insert(
        HeaderName::from_lowercase("connection"),
        HeaderValue::from_static("close"),
    );
    let mut scratch = Scratch::new();
    // `Scratch::body()` clears the buffer on every call, so the slice must
    // be taken once and used for both the write and the send.
    let head = scratch.body();
    courierust_h1::write_response_head(
        head,
        StatusCode::from_u16(status),
        Version::HTTP_11,
        &headers,
    )?;
    writer.write_all(head)?;
    writer.write_all(body.as_bytes())?;
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
    writer: &mut BufWriter<Arc<ConnStream>>,
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
