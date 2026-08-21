//! HTTP/2 connection serving (prior knowledge / h2c).
//!
//! Requests are decoded from HEADERS+DATA and handed to the handler;
//! responses stream back with flow-control-aware backpressure: channel
//! bodies are only drained when the connection accepts more data.

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, Result};
use crate::courierust_h2::connection::{Config as H2Config, Connection, Event};
use crate::courierust_h2::error::ErrorCode;
use crate::courierust_hpack::HeaderField;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::version::Version;
use crate::courierust_net::ConnStream;
use crate::courierust_server::{Handler, ServerConfig};
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, TryRecvError};

/// A response body waiting for flow-control room.
struct Deferred {
    rx: Receiver<Result<Bytes>>,
    ending: bool,
    /// Trailing header block to send once the body ends (HTTP/2).
    trailers: Option<Vec<HeaderField>>,
}

/// Consume and verify the 24-byte HTTP/2 client connection preface.
fn read_preface(stream: &ConnStream) -> Result<()> {
    let mut br = crate::courierust_io::BufReader::new(stream, 24);
    let mut preface = [0u8; 24];
    br.read_exact_into(&mut preface)?;
    if !crate::courierust_h2::connection::is_preface(&preface) {
        return Err(Error::protocol("invalid h2 client preface"));
    }
    Ok(())
}

/// A short read timeout lets the serve loop wake to flush deferred
/// (channel) response bodies even while the peer is silent; without it a
/// blocked read and a pending stream body deadlock until the long
/// timeout. 250 ms is long enough that a legitimate read (including a
/// multi-record TLS read) is never spuriously interrupted under load.
fn configure_read_timeout(stream: &ConnStream) {
    let _ = stream.configure(Some(std::time::Duration::from_millis(250)));
}

/// Serve HTTP/2 requests on `stream` (client preface already verified via
/// peek or ALPN; consumed here).
pub(crate) fn serve(
    stream: &ConnStream,
    handler: &dyn Handler,
    config: &ServerConfig,
) -> Result<()> {
    read_preface(stream)?;
    configure_read_timeout(stream);
    let mut conn = Connection::new(stream, stream, server_config(config));
    let mut req_bodies: HashMap<u32, RequestBuilder> = HashMap::new();
    let mut deferred: HashMap<u32, Deferred> = HashMap::new();
    serve_loop(&mut conn, handler, config, &mut req_bodies, &mut deferred)
}

/// Serve the HTTP/2 side of an RFC 7540 §3.2 `h2c` Upgrade. The client's
/// preface arrives only after the `101` response; the upgraded HTTP/1.1
/// request occupies stream 1 (half-closed remote) and `resp` — the
/// handler's response to that request — is sent on stream 1 before the
/// regular loop takes over.
pub(crate) fn serve_upgraded(
    stream: &ConnStream,
    handler: &dyn Handler,
    config: &ServerConfig,
    resp: Response<Body>,
) -> Result<()> {
    read_preface(stream)?;
    configure_read_timeout(stream);
    let mut conn = Connection::new(stream, stream, server_config(config));
    conn.register_upgrade_stream()?;
    let mut req_bodies: HashMap<u32, RequestBuilder> = HashMap::new();
    let mut deferred: HashMap<u32, Deferred> = HashMap::new();
    send_response(&mut conn, 1, resp, &mut deferred)?;
    serve_loop(&mut conn, handler, config, &mut req_bodies, &mut deferred)
}

/// The shared h2 event loop: poll, dispatch events, flush deferred
/// channel bodies, and apply connection liveness policies.
fn serve_loop(
    conn: &mut Connection<&ConnStream, &ConnStream>,
    handler: &dyn Handler,
    config: &ServerConfig,
    req_bodies: &mut HashMap<u32, RequestBuilder>,
    deferred: &mut HashMap<u32, Deferred>,
) -> Result<()> {
    let mut peer_goaway = false;

    let started = std::time::Instant::now();
    let mut last_rx = started;
    let mut last_ping: Option<std::time::Instant> = None;

    loop {
        if !deferred.is_empty() {
            let _ = conn.flush();
            flush_deferred(conn, deferred)?;
        }

        match conn.poll_available(64) {
            Ok(true) => last_rx = std::time::Instant::now(),
            Ok(false) => {}
            Err(e) => return Err(e),
        }

        while let Some(ev) = conn.next_event() {
            match ev {
                Event::Headers {
                    stream_id,
                    headers,
                    end_stream,
                    ..
                } => {
                    if end_stream {
                        let resp = handler.handle(build_request(&headers, Body::Empty)?);
                        send_response(conn, stream_id, resp, deferred)?;
                    } else {
                        req_bodies.insert(
                            stream_id,
                            RequestBuilder {
                                headers,
                                body: Vec::new(),
                            },
                        );
                    }
                }
                Event::Data {
                    stream_id,
                    data,
                    end_stream,
                } => {
                    if let Some(rb) = req_bodies.get_mut(&stream_id) {
                        rb.body.extend_from_slice(&data);
                        if rb.body.len() > config.max_body {
                            conn.send_rst(stream_id, ErrorCode::EnhanceYourCalm);
                            req_bodies.remove(&stream_id);
                            continue;
                        }
                        if end_stream {
                            if let Some(rb) = req_bodies.remove(&stream_id) {
                                let body = if rb.body.is_empty() {
                                    Body::Empty
                                } else {
                                    Body::Bytes(Bytes::from(rb.body))
                                };
                                let resp = handler.handle(build_request(&rb.headers, body)?);
                                send_response(conn, stream_id, resp, deferred)?;
                            }
                        }
                    }
                }
                Event::Rst { stream_id, .. } => {
                    req_bodies.remove(&stream_id);
                    deferred.remove(&stream_id);
                }
                Event::StreamError { stream_id, .. } => {
                    req_bodies.remove(&stream_id);
                    deferred.remove(&stream_id);
                }
                Event::GoAway { .. } => {
                    peer_goaway = true;
                }
                _ => {}
            }
        }

        if conn.is_closed() {
            break;
        }
        if !apply_liveness(
            conn,
            config,
            started,
            &mut last_rx,
            &mut last_ping,
            !req_bodies.is_empty() || !deferred.is_empty(),
        ) {
            break;
        }
        if peer_goaway && req_bodies.is_empty() && deferred.is_empty() {
            break;
        }
    }
    Ok(())
}

/// Apply connection liveness policies between polls (server side):
///
/// 1. **SETTINGS_TIMEOUT** — if the peer never ACKs our SETTINGS within
///    [`ServerConfig::h2_settings_timeout`], drop the connection.
/// 2. **Idle reaping** — a connection with no in-flight requests that has
///    seen no inbound traffic for [`ServerConfig::h2_idle_timeout`] is
///    closed, releasing the worker thread it occupied (so a pile of idle
///    h2 keep-alive connections cannot exhaust the pool).
/// 3. **Keepalive PING** — after [`ServerConfig::h2_ping_interval`] of
///    inbound silence a PING is sent; if no frame at all arrives within
///    [`ServerConfig::h2_ping_timeout`] the peer is presumed dead.
///
/// Returns `false` when the serve loop should exit.
fn apply_liveness(
    conn: &mut Connection<&ConnStream, &ConnStream>,
    config: &ServerConfig,
    started: std::time::Instant,
    last_rx: &mut std::time::Instant,
    last_ping: &mut Option<std::time::Instant>,
    has_work: bool,
) -> bool {
    let now = std::time::Instant::now();

    if let Some(t) = config.h2_settings_timeout {
        if conn.settings_ack_pending() && now.duration_since(started) >= t {
            conn.send_goaway(ErrorCode::SettingsTimeout, b"peer did not ACK SETTINGS");
            return false;
        }
    }

    if !has_work {
        if let Some(t) = config.h2_idle_timeout {
            if now.duration_since(*last_rx) >= t {
                conn.send_goaway(ErrorCode::NoError, b"idle timeout");
                return false;
            }
        }
    }

    if let Some(interval) = config.h2_ping_interval {
        if now.duration_since(*last_rx) >= interval {
            match *last_ping {
                None => {
                    let nanos = now.duration_since(started).as_nanos() as u64;
                    conn.send_ping(nanos.to_be_bytes());
                    *last_ping = Some(now);
                }
                Some(sent) => {
                    if *last_rx < sent {
                        if let Some(pt) = config.h2_ping_timeout {
                            if now.duration_since(sent) >= pt {
                                return false;
                            }
                        }
                    } else {
                        *last_ping = None;
                    }
                }
            }
        } else {
            *last_ping = None;
        }
    }
    true
}

fn server_config(config: &ServerConfig) -> H2Config {
    let mut c = H2Config {
        client: false,
        auto_release_credit: config.auto_release_credit,
        ..Default::default()
    };
    c.local_settings.max_header_list_size = config.max_header_list as u32;
    c.local_settings.max_concurrent_streams = config.h2_max_concurrent_streams;
    if c.local_settings.initial_window_size < 256 * 1024 {
        c.local_settings.initial_window_size = 256 * 1024;
    }
    c
}

/// A request head waiting for its body.
struct RequestBuilder {
    headers: Vec<HeaderField>,
    body: Vec<u8>,
}

/// Convert an h2 header block into a request.
pub fn build_request(headers: &[HeaderField], body: Body) -> Result<Request<Body>> {
    let mut method: Option<crate::courierust_bytes::Bytes> = None;
    let mut uri: Option<crate::courierust_bytes::Bytes> = None;
    let mut authority: Option<crate::courierust_bytes::Bytes> = None;
    let mut map = HeaderMap::new();
    for f in headers {
        match f.name.as_str() {
            ":method" => method = Some(Bytes::from(f.value.as_bytes())),
            ":path" => uri = Some(Bytes::from(f.value.as_bytes())),
            ":authority" => authority = Some(Bytes::from(f.value.as_bytes())),
            _ => {
                if !f.name.is_pseudo() {
                    map.append(f.name.clone(), f.value.clone());
                }
            }
        }
    }
    let method = method.ok_or_else(|| Error::protocol("request missing :method"))?;
    let method = crate::courierust_http::method::Method::from_bytes(method.as_slice())?;
    let uri = uri.ok_or_else(|| Error::protocol("request missing :path"))?;
    let uri = crate::courierust_http::uri::PathAndQuery::from_bytes(uri.as_slice())?;
    if let Some(a) = authority {
        if !map.contains_key("host") {
            map.insert(
                HeaderName::from_lowercase("host"),
                HeaderValue::from_bytes(a.as_slice())?,
            );
        }
    }
    Ok(Request {
        method,
        uri,
        version: Version::HTTP_2,
        headers: map,
        body,
    })
}

/// Convert a response into HPACK fields and send it.
fn send_response(
    conn: &mut Connection<&ConnStream, &ConnStream>,
    sid: u32,
    resp: Response<Body>,
    deferred: &mut HashMap<u32, Deferred>,
) -> Result<()> {
    let fields = response_fields(&resp);
    let trailers = resp.trailers.as_ref().map(trailer_fields);
    enum K {
        Empty,
        Bytes(Bytes),
        Channel(Receiver<Result<Bytes>>),
    }
    let kind = match resp.body {
        Body::Empty => K::Empty,
        Body::Bytes(b) if b.is_empty() => K::Empty,
        Body::Bytes(b) => K::Bytes(b),
        Body::Channel(rx) => K::Channel(rx),
    };
    let has_trailers = trailers.is_some();
    match kind {
        K::Empty => {
            conn.send_headers(sid, &fields, !has_trailers)?;
            if let Some(t) = trailers {
                conn.send_trailers(sid, &t)?;
            }
        }
        K::Bytes(b) => {
            conn.send_headers(sid, &fields, false)?;
            conn.send_data(sid, b, !has_trailers)?;
            if let Some(t) = trailers {
                conn.send_trailers(sid, &t)?;
            }
        }
        K::Channel(rx) => {
            conn.send_headers(sid, &fields, false)?;
            deferred.insert(
                sid,
                Deferred {
                    rx,
                    ending: false,
                    trailers,
                },
            );
        }
    }
    Ok(())
}

/// Convert a trailer header map into HPACK fields (pseudo-headers are
/// never legal in trailers and are dropped defensively).
fn trailer_fields(t: &crate::courierust_http::header::HeaderMap) -> Vec<HeaderField> {
    let mut fields = Vec::with_capacity(t.len());
    for (n, v) in t.iter() {
        if !n.is_pseudo() {
            fields.push(HeaderField::new(n.clone(), v.clone()));
        }
    }
    fields
}

/// Build the HPACK response block.
pub fn response_fields(resp: &Response<Body>) -> Vec<HeaderField> {
    let mut fields = Vec::with_capacity(resp.headers.len() + 2);
    fields.push(HeaderField::new(
        HeaderName::from_lowercase(":status"),
        HeaderValue::from_bytes(resp.status.as_u16().to_string().as_bytes())
            .unwrap_or_else(|_| HeaderValue::from_static("200")),
    ));
    for (n, v) in resp.headers.iter() {
        if !n.is_pseudo() {
            fields.push(HeaderField::new(n.clone(), v.clone()));
        }
    }
    fields
}

/// Drain deferred (channel) bodies into the connection as room allows.
fn flush_deferred(
    conn: &mut Connection<&ConnStream, &ConnStream>,
    deferred: &mut HashMap<u32, Deferred>,
) -> Result<()> {
    let mut done: Vec<u32> = Vec::new();
    for (sid, d) in deferred.iter_mut() {
        loop {
            if d.ending {
                let res = match &d.trailers {
                    Some(t) => conn.send_trailers(*sid, t),
                    None => conn.send_data(*sid, Bytes::new(), true).map(|_| ()),
                };
                match res {
                    Ok(_) => {
                        done.push(*sid);
                        break;
                    }
                    Err(_) => break, // buffer full; retry later
                }
            }
            match d.rx.try_recv() {
                Ok(Ok(b)) if !b.is_empty() => match conn.send_data(*sid, b, false) {
                    Ok(_) => continue,
                    Err(_) => break,
                },
                Ok(Err(_e)) => {
                    conn.send_rst(*sid, ErrorCode::InternalError);
                    done.push(*sid);
                    break;
                }
                Ok(Ok(_)) => continue,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    d.ending = true;
                    continue;
                }
            }
        }
    }
    for sid in done {
        deferred.remove(&sid);
    }
    Ok(())
}
