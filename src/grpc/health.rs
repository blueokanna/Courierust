//! gRPC health checking protocol (`grpc.health.v1.Health`).
//!
//! The health protocol is small enough that the two message types are
//! hand-encoded (no protobuf dependency):
//!
//! ```proto
//! message HealthCheckRequest  { string service = 1; }
//! message HealthCheckResponse { ServingStatus status = 1; }
//! ```

use crate::body::BodySender;
use crate::bytes::Bytes;
use crate::error::{Error, Result};
use crate::grpc::status;
use crate::grpc::StreamingService;

/// The health Check method path.
pub const CHECK_METHOD: &str = "/grpc.health.v1.Health/Check";

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

/// A `grpc.health.v1.Health` service.
///
/// Tracks an overall status plus optional per-service statuses. The
/// `Check` method returns `SERVING` for known services, `SERVICE_UNKNOWN`
/// for unknown ones, and the overall status for the empty service name.
pub struct HealthService {
    overall: i32,
    services: std::collections::HashMap<String, i32>,
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
            overall: serving_status::SERVING,
            services: std::collections::HashMap::new(),
        }
    }

    /// Set the overall serving status (returned for the empty service).
    pub fn set_overall(mut self, s: i32) -> Self {
        self.overall = s;
        self
    }

    /// Register a service and its serving status.
    pub fn set_service(mut self, service: &str, s: i32) -> Self {
        self.services.insert(service.to_string(), s);
        self
    }
}

impl StreamingService for HealthService {
    fn serve(
        &self,
        method: &str,
        reqs: &mut dyn Iterator<Item = Result<Bytes>>,
        tx: &BodySender,
    ) -> Result<()> {
        if method != CHECK_METHOD {
            return Err(Error::grpc(
                status::UNIMPLEMENTED,
                format!("{method} is not a health method"),
            ));
        }
        let req = reqs.next().transpose()?.unwrap_or_default();
        let service =
            decode_request(&req).map_err(|e| Error::grpc(status::INVALID_ARGUMENT, e.to_string()))?;
        let st = if service.is_empty() {
            self.overall
        } else {
            self.services
                .get(&service)
                .copied()
                .unwrap_or(serving_status::SERVICE_UNKNOWN)
        };
        tx.send(Bytes::from(encode_response(st)))?;
        Ok(())
    }
}
