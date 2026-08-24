//! gRPC health checking demo (`grpc.health.v1.Health`, gRPC A17).
//!
//! The single innovation demonstrated here is *a hand-encoded health
//! protocol*: both `Check` (unary) and `Watch` (server-streaming) run on
//! the crate's own HTTP/2 + gRPC framing, and the two tiny protobuf
//! messages are encoded/decoded by hand — no protobuf dependency.
//!
//! Run with `cargo run --example grpc_health`.

use courierust::courierust_bytes::Bytes;
use courierust::courierust_grpc::health::{self, serving_status, CHECK_METHOD, WATCH_METHOD};
use courierust::courierust_grpc::{GrpcClient, GrpcServer};

fn main() -> courierust::Result<()> {
    let service = health::HealthService::new()
        .set_overall(serving_status::SERVING)
        .set_service("greeter.Greeter", serving_status::SERVING);
    let server = GrpcServer::bind_streaming("127.0.0.1:0", service)?;
    let addr = server.local_addr()?;
    let _handle = server.serve_background()?;
    println!("health server on {addr}");

    let client = GrpcClient::new(&format!("http://{addr}"))?;
    let reply = client.call(CHECK_METHOD, Bytes::new())?;
    let status = parse_health_status(&reply)?;
    assert_eq!(status, serving_status::SERVING);
    println!("overall Check -> status={status} (SERVING)");

    let reply = client.call(CHECK_METHOD, health_request("greeter.Greeter"))?;
    let status = parse_health_status(&reply)?;
    assert_eq!(status, serving_status::SERVING);
    println!("greeter.Greeter Check -> status={status} (SERVING)");

    let reply = client.call(CHECK_METHOD, health_request("no.such.service"))?;
    let status = parse_health_status(&reply)?;
    assert_eq!(status, serving_status::SERVICE_UNKNOWN);
    println!("no.such.service Check -> status={status} (SERVICE_UNKNOWN)");

    let reply = client.call(WATCH_METHOD, health_request("greeter.Greeter"))?;
    let status = parse_health_status(&reply)?;
    assert_eq!(status, serving_status::SERVING);
    println!("greeter.Greeter Watch -> first update status={status} (SERVING)");

    println!("all health checks verified");
    Ok(())
}

/// Encode `HealthCheckRequest { string service = 1; }` by hand.
fn health_request(service: &str) -> Bytes {
    let mut out = Vec::with_capacity(service.len() + 2);
    out.push(0x0a); // field 1, wire type 2 (length-delimited)
    out.push(service.len() as u8);
    out.extend_from_slice(service.as_bytes());
    Bytes::from(out)
}

/// Decode `HealthCheckResponse { ServingStatus status = 1; }` by hand.
fn parse_health_status(reply: &[u8]) -> courierust::Result<i32> {
    if reply.first() != Some(&0x08) {
        // field 1, wire type 0 (varint)
        return Err(courierust::Error::protocol("unexpected health response"));
    }
    let mut status: u64 = 0;
    let mut shift = 0;
    for &byte in &reply[1..] {
        status |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(status as i32);
        }
        shift += 7;
    }
    Err(courierust::Error::protocol("truncated health status"))
}
