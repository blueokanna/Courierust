//! HTTP/1.1 wire codec demo — the exact parsing/serialization
//! primitives `courierust_h1` exposes, with no sockets involved.
//!
//! The single innovation demonstrated here is *strict message-boundary
//! parsing*: request/status lines are validated token-by-token (trailing
//! junk is rejected so a proxy and this server cannot disagree on where
//! a message ends) and chunked framing is emitted with the canonical
//! hex sizes.
//!
//! Run with `cargo run --example h1_codec`.

use courierust::courierust_h1::{
    encode_chunk, parse_request_line, parse_status_line, write_request_head, write_response_head,
};
use courierust::courierust_http::header::HeaderMap;
use courierust::courierust_http::method::Method;
use courierust::courierust_http::status::StatusCode;
use courierust::courierust_http::uri::PathAndQuery;
use courierust::courierust_http::version::Version;

fn main() -> courierust::Result<()> {
    // --- Request line ------------------------------------------------
    let line = parse_request_line(b"GET /index.html?q=1 HTTP/1.1")?;
    println!(
        "request  : method={} target={} version={}",
        line.method, line.target, line.version
    );

    // Strict: a trailing token must be rejected.
    assert!(parse_request_line(b"GET / HTTP/1.1 extra").is_err());
    println!("request line rejects trailing junk (strict boundary)");

    // --- Status line -------------------------------------------------
    let (status, version) = parse_status_line(b"HTTP/1.1 404 Not Found")?;
    println!("response : status={} version={}", status.as_u16(), version);
    assert!(parse_status_line(b"HTTP/1.1 99 Weird").is_err());
    println!("status line rejects out-of-range codes");

    // --- Serialization -----------------------------------------------
    let method = Method::GET;
    let target = PathAndQuery::from_bytes(b"/")?;
    let headers = HeaderMap::new();

    let mut out = Vec::new();
    write_request_head(&mut out, &method, &target, Version::HTTP_11, &headers)?;
    println!("request head -> {:?}", String::from_utf8_lossy(&out));
    assert!(out.ends_with(b"\r\n\r\n"));

    let mut out = Vec::new();
    write_response_head(&mut out, StatusCode::from(200), Version::HTTP_11, &headers)?;
    println!("response head -> {:?}", String::from_utf8_lossy(&out));
    assert!(out.ends_with(b"\r\n\r\n"));

    // --- Chunked transfer encoding -----------------------------------
    let mut wire = Vec::new();
    encode_chunk(b"hello", &mut wire);
    encode_chunk(b"", &mut wire); // terminating chunk
    assert_eq!(wire, b"5\r\nhello\r\n0\r\n\r\n");
    println!("chunked body -> {:?}", String::from_utf8_lossy(&wire));

    // A larger chunk exercises the hex size formatting.
    let mut wire = Vec::new();
    encode_chunk(&[0xAB; 300], &mut wire);
    assert!(wire.starts_with(b"12c\r\n"));
    println!("300-byte chunk -> starts with {:?}", &wire[..5]);

    println!("all HTTP/1.1 codec primitives verified");
    Ok(())
}
