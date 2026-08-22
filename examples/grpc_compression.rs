//! gRPC gzip codec demo — the self-contained RFC 1951/1952 deflate,
//! gzip container and CRC-32 that back the `grpc-encoding: gzip` path.
//!
//! The single innovation demonstrated here is *dependency-free
//! compression*: DEFLATE (uncompressed + fixed-Huffman blocks) and the
//! full gzip container are implemented from scratch, so a gRPC client
//! and server can negotiate `gzip` without pulling in flate2/zlib.
//!
//! Run with `cargo run --example grpc_compression`.

use courierust::courierust_grpc::compress::{crc32, deflate, gunzip, gzip, inflate};

fn main() -> courierust::Result<()> {
    let data = b"The quick brown fox jumps over the lazy dog";

    // --- Raw DEFLATE ------------------------------------------------
    let compressed = deflate(data);
    let restored = inflate(&compressed, 1 << 20)?;
    assert_eq!(&restored[..], data);
    println!(
        "deflate: {} bytes -> {} bytes (raw DEFLATE)",
        data.len(),
        compressed.len()
    );

    // --- gzip container (header + DEFLATE + CRC32 + ISIZE) -----------
    let gz = gzip(data);
    let out = gunzip(&gz, 1 << 20)?;
    assert_eq!(&out[..], data);
    println!(
        "gzip: {} bytes -> {} bytes (container round-trip)",
        data.len(),
        gz.len()
    );

    // --- CRC-32 (IEEE, RFC 1952 §8) ---------------------------------
    // The canonical known answer for this exact string.
    let crc = crc32(data);
    assert_eq!(crc, 0x414f_a339);
    println!("crc32 of {:?} = 0x{crc:08x}", String::from_utf8_lossy(data));

    // --- A repetitive payload actually shrinks ----------------------
    let repetitive: Vec<u8> = vec![b'a'; 2048];
    let gz = gzip(&repetitive);
    let out = gunzip(&gz, 1 << 20)?;
    assert_eq!(&out[..], repetitive);
    println!(
        "gzip 2048x'a' -> {} bytes ({}% saving)",
        gz.len(),
        100 - gz.len() * 100 / repetitive.len()
    );

    // --- Error paths: corrupt / truncated input ---------------------
    let mut truncated = gz[..gz.len() - 4].to_vec();
    truncated.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // bad ISIZE
    assert!(gunzip(&truncated, 1 << 20).is_err());
    println!("corrupt gzip trailer rejected");

    println!("all compression primitives verified");
    Ok(())
}
