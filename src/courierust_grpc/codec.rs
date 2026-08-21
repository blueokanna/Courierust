//! Message codec traits for gRPC.
//!
//! Protobuf serialization is deliberately external: implement these
//! traits for your message types (or wrap a codec such as prost) and
//! plug them into [`crate::courierust_grpc::GrpcClient::call_unary`].

use crate::courierust_error::{Error, Result};

/// A message that can be serialized for gRPC transport.
pub trait EncodeMessage {
    /// Serialize to the raw protobuf bytes.
    fn encode_message(&self) -> Result<Vec<u8>>;
}

/// A message that can be deserialized from gRPC transport.
pub trait DecodeMessage: Sized {
    /// Parse from raw protobuf bytes.
    fn decode_message(bytes: &[u8]) -> Result<Self>;
}

/// A pass-through codec for raw bytes (useful for tests and proxies).
pub struct BytesCodec;

impl EncodeMessage for Vec<u8> {
    fn encode_message(&self) -> Result<Vec<u8>> {
        Ok(self.clone())
    }
}

impl DecodeMessage for Vec<u8> {
    fn decode_message(bytes: &[u8]) -> Result<Self> {
        Ok(bytes.to_vec())
    }
}

impl EncodeMessage for String {
    fn encode_message(&self) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
}

impl DecodeMessage for String {
    fn decode_message(bytes: &[u8]) -> Result<Self> {
        String::from_utf8(bytes.to_vec()).map_err(|e| Error::protocol(e.to_string()))
    }
}
