//! HPACK Huffman codec demo (RFC 7541 §5.2).
//!
//! The single innovation demonstrated here is the *table-driven decoder*:
//! the 257-symbol code is compiled once into lazily-built two-level
//! 256-entry tables, after which each symbol is resolved with one
//! indexed read per 8 consumed bits — no bit-by-bit backtracking, no
//! per-symbol loop over the code length. Encoding uses a u64 bit
//! accumulator with whole-byte drains.
//!
//! Run with `cargo run --example huffman`.

use courierust::courierust_hpack::huffman::{decode, encode, HuffmanDecoder};

fn main() {
    // RFC 7541 Appendix B worked example: "www.example.com".
    let input = b"www.example.com";
    let mut wire = Vec::new();
    let written = encode(input, &mut wire);
    assert_eq!(written, input.len());
    assert_eq!(
        wire,
        [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]
    );
    println!(
        "encode {:?} ({} bytes) -> {} bytes",
        String::from_utf8_lossy(input),
        input.len(),
        wire.len()
    );
    println!("  wire: {wire:02x?}");

    // Decode with the table-driven decoder (reused across messages).
    let decoder = HuffmanDecoder::new();
    let mut out = Vec::new();
    let read = decoder.decode(&wire, &mut out, 1024).unwrap();
    assert_eq!(read, input.len());
    assert_eq!(&out[..], input);
    println!(
        "decode -> {} bytes: {:?}",
        read,
        String::from_utf8_lossy(&out)
    );

    // A couple more round-trips over the same built tables.
    for msg in [
        b"accept-encoding: gzip, deflate".as_slice(),
        b"courierust".as_slice(),
    ] {
        let mut w = Vec::new();
        encode(msg, &mut w);
        out.clear();
        let n = decoder.decode(&w, &mut out, 1024).unwrap();
        assert_eq!(&out[..n], msg);
        println!(
            "round-trip {:?} ({} bytes -> {} bytes)",
            String::from_utf8_lossy(msg),
            msg.len(),
            w.len()
        );
    }

    // Padding must be all-ones (RFC 7541 §5.2): flipping the final
    // padding bit must be rejected, not silently accepted.
    let mut corrupted = wire.clone();
    *corrupted.last_mut().unwrap() ^= 0x01;
    let mut out = Vec::new();
    let rejected = decode(&corrupted, &mut out).is_err();
    assert!(rejected, "corrupted padding must be rejected");
    println!("corrupted padding rejected (invalid padding check)");
}
