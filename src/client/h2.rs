//! HTTP/2 client connection: a dedicated driver thread multiplexes
//! streams over one TCP connection. Requests are submitted over a
//! channel; responses stream back through per-stream channels.

use crate::body::Body;
use crate::bytes::Bytes;
use crate::client::ClientConfig;
use crate::error::{Error, Result};
use crate::h2::connection::{Config as H2Config, Connection, Event};
use crate::h2::error::ErrorCode;
use crate::h2::priority::Priority;
use crate::hpack::HeaderField;
use crate::http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::http::response::ResponseHead;
use crate::http::status::StatusCode;
use crate::http::version::Version;
use crate::net;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// A response as delivered by the h2 driver, including trailers.
pub struct H2Response {
    /// Response head.
    pub head: ResponseHead,
    /// Streaming body.
    pub body: Body,
    /// Trailers (populated once the body ends).
    pub trailers: Arc<std::sync::Mutex<Option<HeaderMap>>>,
}

/// A command submitted to the h2 driver.
pub enum H2Cmd {
    /// Open a stream and send headers (and an optional body).
    Request {
        /// HPACK header block.
        fields: Vec<HeaderField>,
        /// Optional request body (fully materialized).
        body: Option<Bytes>,
        /// Whether the stream ends after the headers/body.
        end_stream: bool,
        /// RFC 9218 priority to signal.
        priority: Priority,
        /// Reply carrying the response head + streaming body.
        reply: Sender<Result<H2Response>>,
    },
    /// Stop the driver.
    Shutdown,
}

/// A handle to a live h2 connection driver.
#[derive(Clone)]
pub struct H2Conn {
    /// Command channel to the driver thread.
    pub tx: Sender<H2Cmd>,
    /// Remote address.
    pub peer: SocketAddr,
    /// Whether the connection still accepts new streams (flipped by the
    /// driver on GOAWAY / close).
    pub accepting: Arc<std::sync::atomic::AtomicBool>,
}

/// A stream awaiting its response.
struct Pending {
    /// Where the final response goes (sent when headers arrive).
    reply: Option<Sender<Result<H2Response>>>,
    /// Where body chunks go.
    body_tx: Option<Sender<Result<Bytes>>>,
    /// Where the body receiver lives (attached to the response).
    body_rx: Option<Receiver<Result<Bytes>>>,
    /// Trailers accumulator shared with the caller.
    trailers: Arc<std::sync::Mutex<Option<HeaderMap>>>,
}

/// Start an h2 connection driver over `stream`.
pub fn start(stream: TcpStream, cfg: &ClientConfig) -> Result<H2Conn> {
    let peer = stream.peer_addr().map_err(|e| Error::io(e.to_string()))?;
    let (tx, rx) = channel::<H2Cmd>();
    let cfg = cfg.clone();
    let accepting = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let accepting2 = accepting.clone();
    thread::Builder::new()
        .name("courierust-h2-driver".into())
        .spawn(move || driver(stream, rx, cfg, accepting2))?;
    Ok(H2Conn {
        tx,
        peer,
        accepting,
    })
}

fn driver(stream: TcpStream, rx: Receiver<H2Cmd>, cfg: ClientConfig, accepting: Arc<AtomicBool>) {
    // A short read timeout wakes the driver to drain commands even when
    // the peer is silent.
    let _ = net::configure(&stream, Some(Duration::from_millis(20)));
    let mut conn = Connection::new(&stream, &stream, h2_config(&cfg));
    let mut pending: HashMap<u32, Pending> = HashMap::new();
    let mut goaway = false;

    loop {
        // 1. Drain commands.
        let mut got_cmd = false;
        while let Ok(cmd) = rx.try_recv() {
            got_cmd = true;
            if !handle_cmd(&mut conn, &mut pending, &mut goaway, cmd) {
                cleanup(&mut conn, &mut pending);
                return;
            }
        }

        // 2. Poll the connection.
        let progress = match conn.poll() {
            Ok(p) => p,
            Err(e) => {
                fail_all(&mut pending, e);
                break;
            }
        };

        // 3. Drain events.
        drain_events(&mut conn, &mut pending, &mut goaway, &accepting);

        // 4. Liveness.
        if conn.is_closed() {
            accepting.store(false, std::sync::atomic::Ordering::Release);
            fail_all(&mut pending, Error::eof());
            break;
        }
        if pending.is_empty() && !got_cmd && !progress {
            // Idle with no streams: block for the next command so an idle
            // connection burns no CPU, while the socket read timeout still
            // lets unsolicited inbound frames through.
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(cmd) => {
                    if !handle_cmd(&mut conn, &mut pending, &mut goaway, cmd) {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }
    cleanup(&mut conn, &mut pending);
}

/// Handle one driver command. Returns `false` to shut the driver down.
fn handle_cmd(
    conn: &mut Connection<&TcpStream, &TcpStream>,
    pending: &mut HashMap<u32, Pending>,
    goaway: &mut bool,
    cmd: H2Cmd,
) -> bool {
    match cmd {
        H2Cmd::Shutdown => {
            conn.send_goaway(ErrorCode::NoError, b"client shutdown");
            false
        }
        H2Cmd::Request {
            fields,
            body,
            end_stream,
            priority,
            reply,
        } => {
            if *goaway {
                let _ = reply.send(Err(Error::canceled("connection received GOAWAY")));
                return true;
            }
            match conn.open_request(priority) {
                Ok(sid) => {
                    let (body_tx, body_rx) = channel::<Result<Bytes>>();
                    let trailers = Arc::new(std::sync::Mutex::new(None));
                    let body_empty = body.is_none() && end_stream;
                    if let Err(e) = conn.send_headers(sid, &fields, body_empty) {
                        let _ = reply.send(Err(e));
                        return true;
                    }
                    if let Some(b) = body {
                        if let Err(e) = conn.send_data(sid, b, end_stream) {
                            let _ = reply.send(Err(e));
                            return true;
                        }
                    }
                    pending.insert(
                        sid,
                        Pending {
                            reply: Some(reply),
                            body_tx: Some(body_tx),
                            body_rx: Some(body_rx),
                            trailers,
                        },
                    );
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            }
            true
        }
    }
}

/// Drain and dispatch connection events to pending streams.
fn drain_events(
    conn: &mut Connection<&TcpStream, &TcpStream>,
    pending: &mut HashMap<u32, Pending>,
    goaway: &mut bool,
    accepting: &Arc<AtomicBool>,
) {
    while let Some(ev) = conn.next_event() {
        match ev {
            Event::Headers {
                stream_id,
                headers,
                end_stream,
                ..
            } => {
                if let Some(p) = pending.get_mut(&stream_id) {
                    match build_response(&headers) {
                        Ok(head) => {
                            if end_stream {
                                if let Some(reply) = p.reply.take() {
                                    let _ = reply.send(Ok(H2Response {
                                        head,
                                        body: Body::Empty,
                                        trailers: p.trailers.clone(),
                                    }));
                                }
                                pending.remove(&stream_id);
                            } else {
                                let body_rx = p.body_rx.take();
                                if let Some(reply) = p.reply.take() {
                                    let body = match body_rx {
                                        Some(rx) => Body::Channel(rx),
                                        None => Body::Empty,
                                    };
                                    let _ = reply.send(Ok(H2Response {
                                        head,
                                        body,
                                        trailers: p.trailers.clone(),
                                    }));
                                }
                                // Keep the pending entry so `body_tx`
                                // stays alive for the DATA frames that
                                // follow the response head.
                            }
                        }
                        Err(e) => {
                            let _ = p.reply.take().map(|r| r.send(Err(e)));
                            pending.remove(&stream_id);
                        }
                    }
                }
            }
            Event::Data {
                stream_id,
                data,
                end_stream,
            } => {
                if let Some(p) = pending.get_mut(&stream_id) {
                    let _ = p.body_tx.as_ref().map(|tx| tx.send(Ok(data)));
                    if end_stream {
                        pending.remove(&stream_id);
                    }
                }
            }
            Event::Trailers { stream_id, headers } => {
                // Store trailers for the caller, then close the body
                // channel (the stream ends with trailers).
                if let Some(p) = pending.get_mut(&stream_id) {
                    let mut map = HeaderMap::new();
                    for f in &headers {
                        map.append(f.name.clone(), f.value.clone());
                    }
                    *p.trailers.lock().unwrap() = Some(map);
                    pending.remove(&stream_id);
                }
            }
            Event::Rst {
                stream_id,
                error_code,
            } => {
                if let Some(p) = pending.remove(&stream_id) {
                    let _ = p.reply.map(|r| {
                        r.send(Err(Error::h2(error_code.as_u32(), "stream reset by peer")))
                    });
                }
            }
            Event::GoAway {
                error_code,
                last_stream_id,
                ..
            } => {
                accepting.store(false, std::sync::atomic::Ordering::Release);
                *goaway = true;
                let dead: Vec<u32> = pending
                    .keys()
                    .copied()
                    .filter(|&s| s > last_stream_id)
                    .collect();
                for sid in dead {
                    if let Some(p) = pending.remove(&sid) {
                        let _ = p.reply.map(|r| {
                            r.send(Err(Error::h2(error_code.as_u32(), "peer sent GOAWAY")))
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

/// Rebuild a response head from an h2 header block.
fn build_response(headers: &[HeaderField]) -> Result<ResponseHead> {
    let mut status = StatusCode::OK;
    let mut map = HeaderMap::new();
    for f in headers {
        if f.name.is_pseudo() {
            if f.name.as_str() == ":status" {
                let code: u16 = std::str::from_utf8(f.value.as_bytes())
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::protocol("missing/invalid :status"))?;
                status = StatusCode::from_u16(code);
            }
            // Other pseudo-headers are ignored in responses.
        } else {
            map.append(f.name.clone(), f.value.clone());
        }
    }
    Ok(ResponseHead {
        status,
        version: Version::HTTP_2,
        headers: map,
    })
}

fn h2_config(cfg: &ClientConfig) -> H2Config {
    let mut c = H2Config {
        client: true,
        max_send_buffer: cfg.max_body,
        auto_release_credit: true,
        ..Default::default()
    };
    // Advertise a generous initial window so small requests flow without
    // window-update round trips.
    if c.local_settings.initial_window_size < 256 * 1024 {
        c.local_settings.initial_window_size = 256 * 1024;
    }
    if let Ok(hl) = cfg.max_header_list.try_into() {
        c.local_settings.max_header_list_size = hl;
    }
    c
}

fn fail_all(pending: &mut HashMap<u32, Pending>, err: Error) {
    for (_, p) in pending.drain() {
        let _ = p.reply.map(|r| r.send(Err(err.clone())));
    }
}

fn cleanup(_conn: &mut Connection<&TcpStream, &TcpStream>, pending: &mut HashMap<u32, Pending>) {
    fail_all(pending, Error::canceled("connection closed"));
}

/// Convert a header list into the HPACK fields for an h2 request.
pub fn request_fields(req: &crate::http::request::Request<Body>) -> Vec<HeaderField> {
    let head = crate::http::request::RequestHead {
        method: req.method.clone(),
        uri: req.uri.clone(),
        version: req.version,
        headers: req.headers.clone(),
    };
    head.to_h2_fields()
}

/// A helper for the driver: build the pseudo-header set manually if
/// needed.
#[allow(dead_code)]
fn _field(name: &str, value: &str) -> HeaderField {
    HeaderField::new(
        HeaderName::from_hpack_bytes(name.as_bytes()).unwrap(),
        HeaderValue::from_bytes(value.as_bytes()).unwrap(),
    )
}
