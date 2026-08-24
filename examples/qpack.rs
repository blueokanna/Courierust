//! QPACK codec demo (RFC 9204) — the header-compression layer of
//! HTTP/3.
//!
//! The single innovation demonstrated here is *the complete QPACK codec
//! in isolation*: the 99-entry static table, prefix integers, Huffman
//! strings, every field-line representation, and the bounded dynamic
//! table — all operating on plain bytes with no HTTP/3 connection state.
//!
//! Run with `cargo run --example qpack`.

use courierust::courierust_h3::qpack::{
    decode_field_line, decode_integer, decode_string, encode_field_line, encode_integer,
    encode_string, static_index, DynamicTable,
};
use courierust::courierust_hpack::huffman::HuffmanDecoder;

fn main() -> courierust::Result<()> {
    // One decoder, reused across every literal (the production pattern).
    let huff = HuffmanDecoder::new();
    // --- 1. Static table (RFC 9204 Appendix A) -----------------------
    println!(
        "static \":method\" \"GET\" -> index {:?}",
        static_index(":method", "GET")
    );
    println!(
        "static \":status\" \"200\" -> index {:?}",
        static_index(":status", "200")
    );

    // --- 2. Prefix integers (§4.1.1) ---------------------------------
    let mut out = Vec::new();
    encode_integer(10, 5, 0x00, &mut out);
    let mut pos = 0;
    let value = decode_integer(&out, 5, &mut pos)?;
    assert_eq!(value, 10);
    assert_eq!(pos, out.len());
    println!("prefix integer 10 (5-bit) -> {out:02x?}");

    // A value that overflows the prefix uses the escape (all-ones) form.
    let mut out = Vec::new();
    encode_integer(200, 5, 0x00, &mut out);
    let mut pos = 0;
    let value = decode_integer(&out, 5, &mut pos)?;
    assert_eq!(value, 200);
    assert_eq!(pos, out.len());
    println!("prefix integer 200 (5-bit) -> {out:02x?}");

    // --- 3. Huffman strings (§4.1.2) ---------------------------------
    let mut out = Vec::new();
    encode_string(b"www.example.com", 8, 0x00, &mut out);
    let mut pos = 0;
    let string = decode_string(&out, 8, &mut pos, &huff)?;
    assert_eq!(string, b"www.example.com");
    println!("huffman string -> {out:02x?}");

    // --- 4. Field-line round trips -----------------------------------
    let empty = DynamicTable::new(4096);

    // Indexed (exact static match): one byte on the wire.
    let mut out = Vec::new();
    encode_field_line(":method", b"GET", &empty, 0, &mut out);
    let mut pos = 0;
    let line = decode_field_line(&out, &mut pos, &empty, 0, &huff)?;
    assert_eq!(
        (line.name.as_str(), line.value.as_slice()),
        (":method", b"GET".as_slice())
    );
    println!("indexed field line -> {out:02x?}  ({:?})", line);

    // Literal with static name reference + Huffman value.
    let mut out = Vec::new();
    encode_field_line("user-agent", b"courierust/1.0", &empty, 0, &mut out);
    let mut pos = 0;
    let line = decode_field_line(&out, &mut pos, &empty, 0, &huff)?;
    assert_eq!(
        (line.name.as_str(), line.value.as_slice()),
        ("user-agent", b"courierust/1.0".as_slice())
    );
    println!("literal field line -> {out:02x?}  ({:?})", line);

    // --- 5. Dynamic table: insert, then reference --------------------
    let mut table = DynamicTable::new(4096);
    assert!(table.insert("x-custom-header", "value-1"));
    println!(
        "dynamic insert -> entries={} bytes={}",
        table.len(),
        table.size()
    );

    // A field already in the dynamic table encodes as one short
    // post-base reference.
    let mut out = Vec::new();
    encode_field_line("x-custom-header", b"value-1", &table, 0, &mut out);
    let mut pos = 0;
    let line = decode_field_line(&out, &mut pos, &table, 0, &huff)?;
    assert_eq!(
        (line.name.as_str(), line.value.as_slice()),
        ("x-custom-header", b"value-1".as_slice())
    );
    println!("dynamic reference -> {out:02x?}  ({:?})", line);

    // Eviction: a tiny table must drop old entries to make room.
    let mut small = DynamicTable::new(64);
    small.insert("a", "1");
    small.insert("b", "2");
    println!(
        "small table after inserts -> entries={} bytes={} (bounded by capacity {})",
        small.len(),
        small.size(),
        small.capacity()
    );

    println!("all QPACK primitives round-tripped");
    Ok(())
}
