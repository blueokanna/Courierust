//! gRPC health checking protocol (`grpc.health.v1.Health`).
//!
//! The health protocol is small enough that the two message types are
//! hand-encoded (no protobuf dependency):
//!
//! ```proto
//! message HealthCheckRequest  { string service = 1; }
//! message HealthCheckResponse { ServingStatus status = 1; }
//! ```
//!
//! Both methods are implemented: `Check` (unary) and `Watch`
//! (server-streaming). `Watch` streams the current status immediately,
//! then a fresh status whenever it changes, and stays open until the
//! client disconnects (or the service is dropped).

use crate::body::BodySender;
use crate::bytes::Bytes;
use crate::error::{Error, Result};
use crate::grpc::status;
use crate::grpc::StreamingService;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// The health Check method path.
pub const CHECK_METHOD: &str = "/grpc.health.v1.Health/Check";
/// The health Watch method path (server-streaming).
pub const WATCH_METHOD: &str = "/grpc.health.v1.Health/Watch";

/// `ServingStatus` enum values (grpc.health.v1).
pub mod serving_status {
    /// Status is unknown.
    pub const UNKNOWN: i32 = 0;
    /// Service is up and serving.
    pub const SERVING: i32 = 1;
    /// Service is down.
    pub const NOT_SERVING: i32 = 2;
    /// Service was never registered.
    pub const SERVICE_UNKNOWN: i32 = 3;
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= buf.len() {
            return Err(Error::protocol("health: truncated varint"));
        }
        let b = buf[*pos];
        *pos += 1;
        if shift >= 64 {
            return Err(Error::protocol("health: varint overflow"));
        }
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn encode_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let b = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// Decode a `HealthCheckRequest` and return the requested service name
/// (empty string for the overall health check).
pub fn decode_request(msg: &[u8]) -> Result<String> {
    let mut pos = 0usize;
    let mut service = String::new();
    while pos < msg.len() {
        let tag = read_varint(msg, &mut pos)?;
        let field = tag >> 3;
        let wire = tag & 0x07;
        match (field, wire) {
            (1, 2) => {
                let len = read_varint(msg, &mut pos)? as usize;
                if pos + len > msg.len() {
                    return Err(Error::protocol("health: truncated string"));
                }
                service = String::from_utf8_lossy(&msg[pos..pos + len]).into_owned();
                pos += len;
            }
            (_, 0) => {
                read_varint(msg, &mut pos)?;
            }
            (_, 1) => pos += 8,
            (_, 2) => {
                let len = read_varint(msg, &mut pos)? as usize;
                if pos + len > msg.len() {
                    return Err(Error::protocol("health: truncated bytes"));
                }
                pos += len;
            }
            (_, 5) => pos += 4,
            _ => return Err(Error::protocol("health: unsupported wire type")),
        }
    }
    Ok(service)
}

/// Encode a `HealthCheckResponse` with the given `ServingStatus`.
pub fn encode_response(serving: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.push(0x08); // field 1, wire type varint
    encode_varint(&mut out, serving as u64);
    out
}

/// Shared, mutable health state. `version` is bumped on every change so
/// `Watch` callers can cheaply detect that a new status is available.
struct HealthState {
    overall: i32,
    services: HashMap<String, i32>,
    version: u64,
}

/// A `grpc.health.v1.Health` service.
///
/// Tracks an overall status plus optional per-service statuses. The
/// `Check` method returns `SERVING` for known services, `SERVICE_UNKNOWN`
/// for unknown ones, and the overall status for the empty service name.
/// The `Watch` method streams the status and pushes updates whenever it
/// changes; a `Watch` call occupies the connection's worker for as long
/// as it is open (the crate's documented per-connection worker model).
#[derive(Clone)]
pub struct HealthService {
    state: Arc<(Mutex<HealthState>, Condvar)>,
}

impl Default for HealthService {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthService {
    /// A health service with overall status `SERVING` and no services.
    pub fn new() -> Self {
        Self {
            state: Arc::new((
                Mutex::new(HealthState {
                    overall: serving_status::SERVING,
                    services: HashMap::new(),
                    version: 0,
                }),
                Condvar::new(),
            )),
        }
    }

    /// Set the overall serving status (returned for the empty service).
    pub fn set_overall(self, s: i32) -> Self {
        let mut state = self.state.0.lock().unwrap();
        state.overall = s;
        state.version = state.version.wrapping_add(1);
        self.state.1.notify_all();
        drop(state);
        self
    }

    /// Register a service and its serving status.
    pub fn set_service(self, service: &str, s: i32) -> Self {
        let mut state = self.state.0.lock().unwrap();
        state.services.insert(service.to_string(), s);
        state.version = state.version.wrapping_add(1);
        self.state.1.notify_all();
        drop(state);
        self
    }

    /// Update the overall status at runtime (wakes any `Watch` callers).
    pub fn update_overall(&self, s: i32) {
        let mut state = self.state.0.lock().unwrap();
        state.overall = s;
        state.version = state.version.wrapping_add(1);
        self.state.1.notify_all();
    }

    /// Update a service's status at runtime (wakes any `Watch` callers).
    pub fn update_service(&self, service: &str, s: i32) {
        let mut state = self.state.0.lock().unwrap();
        state.services.insert(service.to_string(), s);
        state.version = state.version.wrapping_add(1);
        self.state.1.notify_all();
    }

    /// The current status for a service name (empty = overall).
    fn status(&self, service: &str) -> i32 {
        let state = self.state.0.lock().unwrap();
        if service.is_empty() {
            state.overall
        } else {
            state
                .services
                .get(service)
                .copied()
                .unwrap_or(serving_status::SERVICE_UNKNOWN)
        }
    }
}

impl StreamingService for HealthService {
    fn serve(
        &self,
        method: &str,
        reqs: &mut dyn Iterator<Item = Result<Bytes>>,
        tx: &BodySender,
    ) -> Result<()> {
        match method {
            CHECK_METHOD => {
                let req = reqs.next().transpose()?.unwrap_or_default();
                let service = decode_request(&req)
                    .map_err(|e| Error::grpc(status::INVALID_ARGUMENT, e.to_string()))?;
                tx.send(Bytes::from(encode_response(self.status(&service))))?;
                Ok(())
            }
            WATCH_METHOD => {
                let req = reqs.next().transpose()?.unwrap_or_default();
                let service = decode_request(&req)
                    .map_err(|e| Error::grpc(status::INVALID_ARGUMENT, e.to_string()))?;
                self.watch(&service, tx)
            }
            _ => Err(Error::grpc(
                status::UNIMPLEMENTED,
                format!("{method} is not a health method"),
            )),
        }
    }
}

impl HealthService {
    /// Server-streaming `Watch`: send the current status immediately,
    /// then push a fresh status on every change, until the client
    /// disconnects (detected when the response channel closes).
    fn watch(&self, service: &str, tx: &BodySender) -> Result<()> {
        let mut last_version = u64::MAX; // force the first send
        loop {
            let (st, version) = {
                let state = self.state.0.lock().unwrap();
                let st = if service.is_empty() {
                    state.overall
                } else {
                    state
                        .services
                        .get(service)
                        .copied()
                        .unwrap_or(serving_status::SERVICE_UNKNOWN)
                };
                (st, state.version)
            };
            if version != last_version {
                if tx.send(Bytes::from(encode_response(st))).is_err() {
                    // The client disconnected: end the stream cleanly.
                    return Ok(());
                }
                last_version = version;
            }
            // Wait for a status change; the timeout also lets this loop
            // observe a client disconnect (via the send above).
            let guard = self.state.0.lock().unwrap();
            let _ = self
                .state
                .1
                .wait_timeout(guard, Duration::from_millis(500))
                .unwrap();
        }
    }
}
