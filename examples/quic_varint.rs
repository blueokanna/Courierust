//! QUIC variable-length integer demo (RFC 9000 §16).
//!
//! The single innovation demonstrated here is *length self-describing
//! integers*: the two most-significant bits of the first byte select a
//! 1 / 2 / 4 / 8-byte big-endian encoding, so a small integer costs one
//! byte while the full 62-bit range stays available. This one primitive
//! carries every length and identifier on the QUIC / HTTP/3 wire.
//!
//! Run with `cargo run --example quic_varint`.

use courierust::courierust_quic::varint::{decode, encode, MAX};

fn main() -> courierust::Result<()> {
    // Worked examples (RFC 9000 §16.1, using the crate's minimal
    // encoding — values do not need the minimum width, but a canonical
    // encoder always produces it).
    let cases: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (37, &[0x25]),
        (63, &[0x3f]),
        (64, &[0x40, 0x40]),
        (16383, &[0x7f, 0xff]),
        (9472, &[0x65, 0x00]),
        (16384, &[0x80, 0x00, 0x40, 0x00]),
    ];
    for &(value, expected) in cases {
        let wire = encode(value);
        assert_eq!(wire, expected, "encoding of {value}");
        let (decoded, used) = decode(&wire)?;
        assert_eq!((decoded, used), (value, wire.len()));
        println!("{value:>5} -> {wire:02x?}  ({used} byte(s))");
    }

    // Boundary sweep: 6 / 14 / 30 / 62 bits force the next width.
    let boundaries = [0u64, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, MAX];
    for value in boundaries {
        let wire = encode(value);
        let (decoded, used) = decode(&wire)?;
        assert_eq!((decoded, used), (value, wire.len()));
        println!("value 2^{} -> {} byte(s)", bits_needed(value), wire.len());
    }

    // Truncated input is a hard error, never a silent misread.
    assert!(decode(&[]).is_err());
    assert!(decode(&[0x40]).is_err()); // claims 2 bytes, has 1
    assert!(decode(&[0x80, 0x00]).is_err()); // claims 4 bytes, has 2
    println!("truncated varints rejected");
    Ok(())
}

/// Number of significant bits (used for the boundary-sweep printout).
fn bits_needed(value: u64) -> u32 {
    64 - value.leading_zeros()
}
