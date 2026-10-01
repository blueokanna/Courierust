//! Server reflection (`grpc.reflection.v1alpha.ServerReflection`).
//!
//! A reflection client — `grpcurl`, `grpc_cli`, Postman — asks a server what
//! it serves and what its messages look like, so it can be used without a
//! local copy of the `.proto` files. This implementation answers from the
//! descriptors `build.rs` emitted **from the same parse that generated the
//! code**, which is the only version of this feature that can be trusted:
//! a hand-written descriptor is a second source of truth, and the two drift.
//!
//! Supported requests: `list_services`, `file_containing_symbol` (a service,
//! a method or a message) and `file_by_filename`. Everything else — the
//! extension queries, which this crate's proto subset has no syntax for —
//! is answered `UNIMPLEMENTED` rather than with an empty success, because a
//! tool that gets an empty answer concludes "there is nothing there" and a
//! tool that gets `UNIMPLEMENTED` concludes "this server cannot tell me".
//!
//! The compiled files have no `import`, so a `FileDescriptorResponse` is
//! always exactly one descriptor and there is no dependency walk to do.
//! `assert_no_imports` keeps that claim honest: if a future `.proto` gains
//! an import, the unit tests fail instead of a client receiving a descriptor
//! whose dependencies it cannot resolve.

use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_grpc::generated::descriptors;
use crate::courierust_grpc::proto::{self, SliceReader, WireType};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// The full method name a client must call to reach this service.
pub const SERVER_REFLECTION_METHOD: &str =
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";

/// The name of the reflection service itself.
pub const SERVER_REFLECTION_SERVICE: &str = "grpc.reflection.v1alpha.ServerReflection";

/// gRPC status `NOT_FOUND`.
const NOT_FOUND: u64 = 5;
/// gRPC status `UNIMPLEMENTED`.
const UNIMPLEMENTED: u64 = 12;

/// Reflection for the services compiled into this binary.
///
/// Install it like any other streaming service:
///
/// ```
/// # use courierust::courierust_grpc::{GrpcServer, reflection::ReflectionService};
/// # fn demo(addr: &str) -> courierust::Result<()> {
/// let server = GrpcServer::bind_streaming(addr, ReflectionService::new())?;
/// # let _ = server;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct ReflectionService;

impl ReflectionService {
    /// A reflection service over every file this build compiled.
    pub fn new() -> Self {
        assert_no_imports();
        Self
    }
}

impl crate::courierust_grpc::StreamingService for ReflectionService {
    fn serve(
        &self,
        method: &str,
        reqs: &mut dyn Iterator<Item = Result<Bytes>>,
        tx: &crate::courierust_body::BodySender,
    ) -> Result<()> {
        if method != "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo" {
            return Err(Error::with_message(
                ErrorKind::Grpc(UNIMPLEMENTED as u32),
                format!("reflection: no such method `{method}`"),
            ));
        }
        // One response per request: `ServerReflectionInfo` is a stream in
        // both directions, but the protocol is request/response at heart, and
        // a client that pipelines two lookups gets the second answer as soon
        // as it asks for it rather than at the end.
        for request in reqs {
            let response = answer(&request?);
            tx.send(Bytes::from(response))?;
        }
        Ok(())
    }
}

/// What the client asked for, decoded from a `ServerReflectionRequest`.
enum Query {
    /// `file_by_filename`
    FileByName(String),
    /// `file_containing_symbol`
    Symbol(String),
    /// `list_services`
    ListServices,
    /// A query this server does not implement, or an empty request.
    Unsupported(&'static str),
}

/// Decode a `ServerReflectionRequest` and answer it.
fn answer(request: &[u8]) -> Vec<u8> {
    let mut reader = SliceReader::new(request);
    let mut host = String::new();
    let mut query = Query::Unsupported("no query in the request");
    while reader.remaining() > 0 {
        let Ok((number, wire)) = read_tag(&mut reader) else {
            break;
        };
        match (number, wire) {
            // host = 1
            (1, WireType::LengthDelimited) => {
                host = read_string(&mut reader).unwrap_or_default();
            }
            // file_by_filename = 3, file_containing_symbol = 4,
            // all_extension_numbers_of_type = 6, list_services = 7
            (3, WireType::LengthDelimited) => {
                query = read_string(&mut reader)
                    .map(Query::FileByName)
                    .unwrap_or(Query::Unsupported("malformed file_by_filename"));
            }
            (4, WireType::LengthDelimited) => {
                query = read_string(&mut reader)
                    .map(Query::Symbol)
                    .unwrap_or(Query::Unsupported("malformed file_containing_symbol"));
            }
            (6, WireType::LengthDelimited) => {
                let _ = read_string(&mut reader);
                query = Query::Unsupported("extension numbers");
            }
            (7, WireType::LengthDelimited) => {
                let _ = read_string(&mut reader);
                query = Query::ListServices;
            }
            // file_containing_extension = 5 is a message; anything else is
            // skipped so a newer client's field cannot break the decoder.
            _ => {
                if skip(&mut reader, wire).is_err() {
                    break;
                }
            }
        }
    }

    let mut response = Vec::new();
    proto::encode_string_field(&mut response, 1, &host); // valid_host
    proto::encode_bytes_field(&mut response, 2, request); // original_request
                                                          // Each helper returns its arm already tagged, so this appends rather than
                                                          // wraps: a second wrap would bury the answer one level deeper than every
                                                          // client looks for it, and the client would report `nothing there`.
    response.extend_from_slice(&match query {
        Query::ListServices => list_services(),
        Query::FileByName(name) => file_by(&name),
        Query::Symbol(symbol) => file_of_symbol(&symbol),
        Query::Unsupported(what) => {
            error_response(UNIMPLEMENTED, &format!("unsupported query: {what}"))
        }
    });
    response
}

/// `list_services_response`, including this server's own reflection service.
fn list_services() -> Vec<u8> {
    let mut list = Vec::new();
    let mut names: Vec<&str> = descriptors::SERVICES.to_vec();
    names.push(SERVER_REFLECTION_SERVICE);
    names.sort_unstable();
    names.dedup();
    for name in names {
        let mut service = Vec::new();
        proto::encode_string_field(&mut service, 1, name);
        proto::encode_bytes_field(&mut list, 1, &service);
    }
    let mut message = Vec::new();
    proto::encode_bytes_field(&mut message, 6, &list);
    message
}

/// `file_descriptor_response` for one descriptor, or `NOT_FOUND`.
fn file_response(descriptor: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    proto::encode_bytes_field(&mut body, 1, descriptor);
    let mut message = Vec::new();
    proto::encode_bytes_field(&mut message, 4, &body);
    message
}

fn file_by(name: &str) -> Vec<u8> {
    // The names clients send come from an earlier response, so an exact match
    // is the common case. A bare file name is accepted too, because a
    // hand-written request should not have to know whether the build
    // registered a path prefix.
    let wanted = basename(name);
    let found = descriptors::FILES
        .iter()
        .find(|(file, _)| *file == name)
        .or_else(|| {
            descriptors::FILES
                .iter()
                .find(|(file, _)| basename(file) == wanted)
        });
    match found {
        Some((_, descriptor)) => file_response(descriptor),
        None => error_response(NOT_FOUND, &format!("no such file: {name}")),
    }
}

/// The last path component: what a hand-written request is most likely to
/// send for a file the build knows by a longer name.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn file_of_symbol(symbol: &str) -> Vec<u8> {
    let symbol = symbol.trim_start_matches('.');
    let file = descriptors::SYMBOLS
        .iter()
        .find(|(defined, _)| *defined == symbol)
        .map(|(_, file)| *file)
        // A client may ask for a method by name; the lookup table has the
        // exact symbols, so an unknown one is genuinely unknown.
        .or_else(|| {
            descriptors::SERVICES
                .iter()
                .find(|service| **service == symbol)
                .and_then(|service| {
                    descriptors::SYMBOLS
                        .iter()
                        .find(|(defined, _)| defined.starts_with(&format!("{service}.")))
                        .map(|(_, file)| *file)
                })
        });
    match file {
        Some(file) => file_by(file),
        None => error_response(NOT_FOUND, &format!("no such symbol: {symbol}")),
    }
}

/// `error_response` with a gRPC status code.
fn error_response(code: u64, message: &str) -> Vec<u8> {
    let mut error = Vec::new();
    proto::encode_varint_field(&mut error, 1, code);
    proto::encode_string_field(&mut error, 2, message);
    let mut body = Vec::new();
    proto::encode_bytes_field(&mut body, 7, &error);
    body
}

fn read_string(reader: &mut SliceReader<'_>) -> Option<String> {
    let len = reader.read_varint().ok()? as usize;
    let bytes = reader.take(len).ok()?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Read a tag from a bounded reader.
///
/// The shared [`proto::read_tag`] takes a slice; every walk in this module
/// goes through a [`SliceReader`], which enforces that a length-delimited
/// field cannot read past the message that encloses it — the property that
/// keeps a hostile request from making the server interpret the following
/// bytes as part of this field.
fn read_tag(reader: &mut SliceReader<'_>) -> Result<(u32, WireType)> {
    let tag = reader.read_varint()?;
    let number = (tag >> 3) as u32;
    let wire = WireType::from_code((tag & 0x7) as u8)
        .ok_or_else(|| Error::protocol("reflection: invalid protobuf wire type"))?;
    if number == 0 {
        return Err(Error::protocol("reflection: field number 0 is reserved"));
    }
    Ok((number, wire))
}

/// Skip one field of any wire type.
fn skip(reader: &mut SliceReader<'_>, wire: WireType) -> Result<()> {
    match wire {
        WireType::Varint => {
            reader.read_varint()?;
        }
        WireType::Fixed64 => {
            reader.read_fixed64()?;
        }
        WireType::Fixed32 => {
            reader.read_fixed32()?;
        }
        WireType::LengthDelimited => {
            let len = reader.read_varint()? as usize;
            reader.take(len)?;
        }
    }
    Ok(())
}

/// Fail loudly if a compiled `.proto` gained an `import`: this module answers
/// with one descriptor and no dependency walk, which would silently become a
/// lie the moment a file imported another.
fn assert_no_imports() {
    for (_, descriptor) in descriptors::FILES {
        let mut reader = SliceReader::new(descriptor);
        while reader.remaining() > 0 {
            let Ok((number, wire)) = read_tag(&mut reader) else {
                return;
            };
            // dependency = 3
            if number == 3 && wire == WireType::LengthDelimited {
                panic!(
                    "reflection: a compiled .proto has an import, so file_descriptor_response \
                     would have to send a dependency set it does not build"
                );
            }
            if skip(&mut reader, wire).is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(field: u32, value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        proto::encode_string_field(&mut out, field, value);
        out
    }

    /// The payload of response `field`, when the answer carries that arm.
    fn response_body(response: &[u8], field: u32) -> Option<Vec<u8>> {
        let mut reader = SliceReader::new(response);
        while reader.remaining() > 0 {
            let (number, wire) = read_tag(&mut reader).unwrap();
            if wire != WireType::LengthDelimited {
                let _ = reader.read_varint();
                continue;
            }
            let len = reader.read_varint().unwrap() as usize;
            let value = reader.take(len).unwrap();
            if number == field {
                return Some(value.to_vec());
            }
        }
        None
    }

    /// The `FileDescriptorResponse` of an answer (`file_descriptor_response`
    /// is response field 4).
    fn file_descriptor_response(request: &[u8]) -> Vec<u8> {
        response_body(&answer(request), 4).expect("no file_descriptor_response")
    }

    /// The `ListServiceResponse` of an answer (response field 6).
    fn list_service_response(request: &[u8]) -> Vec<u8> {
        response_body(&answer(request), 6).expect("no list_services_response")
    }

    fn strings(body: &[u8], field: u32) -> Vec<String> {
        payloads(body, field)
            .into_iter()
            .map(|value| String::from_utf8_lossy(&value).into_owned())
            .collect()
    }

    /// The payloads of field `field`, as raw bytes.
    ///
    /// A descriptor is binary, and decoding it to `String` first is
    /// corruption: a length of 132 is the bytes `0x84 0x01`, and `0x84` is a
    /// bare UTF-8 continuation byte, so `from_utf8_lossy` replaces it with
    /// U+FFFD — three bytes where there were two — and the message that
    /// follows is no longer a message.
    fn payloads(body: &[u8], field: u32) -> Vec<Vec<u8>> {
        let mut reader = SliceReader::new(body);
        let mut found = Vec::new();
        while reader.remaining() > 0 {
            let (number, wire) = read_tag(&mut reader).unwrap();
            if wire == WireType::LengthDelimited {
                let len = reader.read_varint().unwrap() as usize;
                let value = reader.take(len).unwrap();
                if number == field {
                    found.push(value.to_vec());
                }
            } else {
                let _ = reader.read_varint();
            }
        }
        found
    }

    /// The gRPC status code of an `error_response`, when the answer is one.
    fn error_code(response: &[u8]) -> Option<u64> {
        // error_response = 7, then ErrorResponse.error_code = 1.
        let error = response_body(response, 7)?;
        let mut reader = SliceReader::new(&error);
        let _ = read_tag(&mut reader).unwrap();
        Some(reader.read_varint().unwrap())
    }

    #[test]
    fn list_services_names_every_service_and_its_own() {
        // `ListServiceResponse.service` is a message, so the name is one
        // level deeper than the list entry.
        let body = list_service_response(&request(7, ""));
        let mut names = Vec::new();
        for service in strings(&body, 1) {
            let name = strings(service.as_bytes(), 1);
            assert_eq!(name.len(), 1, "one name per service: {service:?}");
            names.push(name[0].clone());
        }
        assert!(
            names.contains(&"helloworld.Greeter".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&SERVER_REFLECTION_SERVICE.to_string()),
            "a reflection client is entitled to see the service it is calling: {names:?}"
        );
        assert!(names.windows(2).all(|w| w[0] <= w[1]), "sorted: {names:?}");
    }

    /// `(package, messages, services)` from a `FileDescriptorProto`.
    ///
    /// Deliberately walks the bytes by hand rather than through the crate's
    /// own `SliceReader`: the numbering has to agree with `descriptor.proto`,
    /// and a decoder sharing code with the encoder under test would not
    /// notice if both were wrong the same way.
    fn decode_descriptor(bytes: &[u8]) -> (String, Vec<String>, Vec<String>) {
        let (mut package, mut messages, mut services) = (String::new(), Vec::new(), Vec::new());
        for (number, value) in fields(bytes) {
            match number {
                2 => package = String::from_utf8_lossy(value).into_owned(),
                // message_type = 4 and service = 6 are messages whose own
                // `name` is field 1.
                4 => messages.push(first_string(value)),
                6 => services.push(first_string(value)),
                _ => {}
            }
        }
        (package, messages, services)
    }

    /// Every `(field number, payload)` of a length-delimited field.
    fn fields(body: &[u8]) -> Vec<(u32, &[u8])> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < body.len() {
            let (tag, next) = varint(body, i);
            i = next;
            let number = (tag >> 3) as u32;
            match tag & 7 {
                0 => i = varint(body, i).1,
                2 => {
                    let (len, next) = varint(body, i);
                    i = next;
                    let end = i + len as usize;
                    assert!(end <= body.len(), "field {number} overruns at {i}");
                    out.push((number, &body[i..end]));
                    i = end;
                }
                other => panic!("unexpected wire type {other} at offset {i}"),
            }
        }
        out
    }

    fn varint(body: &[u8], mut i: usize) -> (u64, usize) {
        let (mut value, mut shift) = (0u64, 0u32);
        loop {
            let byte = body[i];
            i += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return (value, i);
            }
            shift += 7;
        }
    }

    /// The value of field 1 of a message (its `name`).
    fn first_string(body: &[u8]) -> String {
        fields(body)
            .into_iter()
            .find(|(number, _)| *number == 1)
            .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
            .unwrap_or_default()
    }

    #[test]
    fn a_symbol_resolves_to_its_file_descriptor() {
        for symbol in [
            "helloworld.Greeter",
            "helloworld.Greeter.SayHello",
            ".helloworld.HelloRequest",
        ] {
            let body = file_descriptor_response(&request(4, symbol));
            let found = payloads(&body, 1);
            assert_eq!(found.len(), 1, "{symbol}: {found:?}");
            let (package, messages, services) = decode_descriptor(&found[0]);
            assert_eq!(package, "helloworld", "{symbol}");
            assert_eq!(services, vec!["Greeter"], "{symbol}");
            assert_eq!(messages, vec!["HelloRequest", "HelloReply"], "{symbol}");
        }
    }

    #[test]
    fn a_file_name_resolves_with_or_without_its_path() {
        for name in ["helloworld.proto", "proto/helloworld.proto"] {
            let body = file_descriptor_response(&request(3, name));
            assert!(!strings(&body, 1).is_empty(), "{name}");
        }
    }

    #[test]
    fn the_original_request_is_echoed_back() {
        let ask = request(4, "helloworld.HelloRequest");
        let response = answer(&ask);
        assert_eq!(
            response_body(&response, 2).as_deref(),
            Some(ask.as_slice()),
            "original_request (field 2) must come back byte for byte"
        );
    }

    #[test]
    fn an_unknown_symbol_is_not_found_rather_than_empty() {
        let response = answer(&request(4, "helloworld.Nope"));
        assert!(
            response_body(&response, 4).is_none(),
            "an unknown symbol has no descriptor to send"
        );
        assert_eq!(error_code(&response), Some(NOT_FOUND));
    }

    #[test]
    fn an_extension_query_is_unimplemented_not_empty() {
        assert_eq!(
            error_code(&answer(&request(6, "helloworld.HelloRequest"))),
            Some(UNIMPLEMENTED),
            "an answer of `nothing here` is not the same as `I cannot answer`"
        );
    }
}
