//! HTTP/2 connection serving (prior knowledge / h2c).
//!
//! Requests are decoded from HEADERS+DATA and handed to the handler;
//! responses stream back with flow-control-aware backpressure: channel
//! bodies are only drained when the connection accepts more data.

use crate::body::Body;
use crate::bytes::Bytes;
use crate::error::{Error, Result};
use crate::h2::connection::{Config as H2Config, Connection, Event};
use crate::h2::error::ErrorCode;
use crate::hpack::HeaderField;
use crate::http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::http::request::Request;
use crate::http::response::Response;
use crate::http::version::Version;
use crate::server::{Handler, ServerConfig};
use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, TryRecvError};

/// A response body waiting for flow-control room.
struct Deferred {
    rx: Receiver<Result<Bytes>>,
    ending: bool,
}

/// Serve HTTP/2 requests on `stream` (client preface already verified via
/// peek; consumed here).
pub fn serve(stream: TcpStream, handler: &dyn Handler, config: &ServerConfig) -> Result<()> {
    // The caller peeked the preface; consume exactly the 24 bytes so the
    // connection reads the client's SETTINGS next.
    let mut br = crate::io::BufReader::new(&stream, 24);
    let mut preface = [0u8; 24];
    br.read_exact_into(&mut preface)?;
    if !crate::h2::connection::is_preface(&preface) {
        return Err(Error::protocol("invalid h2 client preface"));
    }
    drop(br);

    // A short read timeout lets the serve loop wake to flush deferred
    // (channel) response bodies even while the peer is silent; without it
    // a blocked read and a pending stream body deadlock until the long
    // timeout.
    let _ = crate::net::configure(&stream, Some(std::time::Duration::from_millis(20)));

    let mut conn = Connection::new(&stream, &stream, server_config(config));

    let mut req_bodies: HashMap<u32, RequestBuilder> = HashMap::new();
    let mut deferred: HashMap<u32, Deferred> = HashMap::new();
    let mut peer_goaway = false;

    loop {
        if !deferred.is_empty() {
            // Give the connection a chance to drain before pulling more.
            let _ = conn.flush();
            flush_deferred(&mut conn, &mut deferred)?;
        }

        match conn.poll() {
            Ok(_) => {}
            Err(e) => {
                eprintln!("DEBUG h2 serve poll err: {:?}", e);
                return Err(e);
            }
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
                        send_response(&mut conn, stream_id, resp, &mut deferred)?;
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
                                send_response(&mut conn, stream_id, resp, &mut deferred)?;
                            }
                        }
                    }
                }
                Event::Rst { stream_id, .. } => {
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
        if peer_goaway && req_bodies.is_empty() && deferred.is_empty() {
            break;
        }
    }
    Ok(())
}

/// Build the h2 connection config for a server.
fn server_config(config: &ServerConfig) -> H2Config {
    let mut c = H2Config {
        client: false,
        auto_release_credit: false, // released as the handler consumes
        ..Default::default()
    };
    c.local_settings.max_header_list_size = config.max_header_list as u32;
    c.local_settings.max_concurrent_streams = 1024;
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
    let mut method: Option<crate::bytes::Bytes> = None;
    let mut uri: Option<crate::bytes::Bytes> = None;
    let mut authority: Option<crate::bytes::Bytes> = None;
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
    let method = crate::http::method::Method::from_bytes(method.as_slice())?;
    let uri = uri.ok_or_else(|| Error::protocol("request missing :path"))?;
    let uri = crate::http::uri::PathAndQuery::from_bytes(uri.as_slice())?;
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
    conn: &mut Connection<&TcpStream, &TcpStream>,
    sid: u32,
    resp: Response<Body>,
    deferred: &mut HashMap<u32, Deferred>,
) -> Result<()> {
    let fields = response_fields(&resp);
    // Classify the body before moving it.
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
    let empty = matches!(kind, K::Empty);
    conn.send_headers(sid, &fields, empty)?;
    match kind {
        K::Empty => {}
        K::Bytes(b) => {
            conn.send_data(sid, b, true)?;
        }
        K::Channel(rx) => {
            deferred.insert(sid, Deferred { rx, ending: false });
        }
    }
    Ok(())
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
    conn: &mut Connection<&TcpStream, &TcpStream>,
    deferred: &mut HashMap<u32, Deferred>,
) -> Result<()> {
    let mut done: Vec<u32> = Vec::new();
    for (sid, d) in deferred.iter_mut() {
        loop {
            if d.ending {
                // Finish the stream with an empty END_STREAM frame.
                match conn.send_data(*sid, Bytes::new(), true) {
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
                    Err(_) => break, // flow-control backpressure
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
