//! Build-time generated protobuf messages and gRPC service stubs.
//!
//! [`build.rs`](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
//! compiles every `proto/*.proto` file at build time into
//! `OUT_DIR/courierust_generated.rs` (a zero-dependency generator: the
//! wire codec it targets is [`crate::courierust_grpc::proto`]). The
//! generated items are namespaced under each proto `package`.
//!
//! This is the "batteries included" code-generation chain: declare your
//! messages and services in a `.proto` file, and get type-safe, IDE
//! friendly Rust types plus typed gRPC client stubs — no prost, no
//! `tonic-build`, no third-party crates.

include!(concat!(env!("OUT_DIR"), "/courierust_generated.rs"));

#[cfg(test)]
mod tests {
    use super::helloworld::{Greeter, HelloReply, HelloRequest};
    use crate::courierust_grpc::codec::{DecodeMessage, EncodeMessage};

    /// Round-trip the generated messages against canonical protobuf
    /// bytes (field 1 = "name", field 2 = repeated "tags"):
    /// `0a 03 61 62 63` (name="abc") and `12 03 78 79 7a` (tags=["xyz"]).
    #[test]
    fn generated_message_wire_round_trip() {
        let mut request = HelloRequest {
            name: "abc".into(),
            ..Default::default()
        };
        request.tags.push("xyz".into());
        let bytes = request.encode_message().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x0a, 0x03, 0x61, 0x62, 0x63, // name = "abc"
                0x12, 0x03, 0x78, 0x79, 0x7a, // tags = ["xyz"]
            ]
        );
        let decoded = HelloRequest::decode_message(&bytes).unwrap();
        assert_eq!(decoded, request);

        let reply = HelloReply {
            message: "hi".into(),
            count: 7,
        };
        let bytes = reply.encode_message().unwrap();
        assert_eq!(
            bytes,
            vec![
                0x0a, 0x02, 0x68, 0x69, // message = "hi"
                0x10, 0x07, // count = 7
            ]
        );
        assert_eq!(HelloReply::decode_message(&bytes).unwrap(), reply);
    }

    /// Unknown fields in the wire must be skipped; defaults applied.
    #[test]
    fn generated_message_skips_unknown_fields() {
        let mut wire = Vec::new();
        crate::courierust_grpc::proto::Encoder::string(&mut wire, 99, "unknown");
        crate::courierust_grpc::proto::Encoder::string(&mut wire, 1, "known");
        let decoded = HelloRequest::decode_message(&wire).unwrap();
        assert_eq!(decoded.name, "known");
        assert!(decoded.tags.is_empty());
    }

    /// The generated service stub has type-checked methods and the
    /// correct fully-qualified method paths.
    #[test]
    fn generated_service_stub_paths() {
        let stub =
            Greeter::new(crate::courierust_grpc::GrpcClient::new("http://127.0.0.1:1").unwrap());
        assert_eq!(stub.service_path(), "/helloworld.Greeter");
        // The methods exist and are typed; calling without a server
        // fails at the transport layer, not the type layer.
        let _ = stub.say_hello(HelloRequest::default());
        let _ = stub.watch(HelloRequest::default());
    }
}
