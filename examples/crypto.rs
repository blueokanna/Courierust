//! Standalone digest demo — the self-contained MD5 (RFC 1321) and
//! SHA-256 (FIPS 180-4) implementations that also feed the JA3/JA4
//! fingerprinting code.
//!
//! The single innovation demonstrated here is *dependency-free hashing*:
//! both digests are implemented from scratch in this crate, so the
//! protocol core stays `no_std + alloc` with zero third-party crypto.
//!
//! Run with `cargo run --example crypto`.

use courierust::courierust_crypto::md5::md5_hex;
use courierust::courierust_crypto::sha256::sha256_hex;

fn main() {
    // --- MD5: RFC 1321 test suite ------------------------------------
    let md5_cases: &[(&[u8], &str)] = &[
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
    ];
    for (input, expected) in md5_cases {
        let got = md5_hex(input);
        assert_eq!(&got, expected, "md5({:?})", String::from_utf8_lossy(input));
    }
    println!("MD5: {} RFC 1321 vectors pass", md5_cases.len());

    // --- SHA-256: FIPS 180-4 §B.2 ------------------------------------
    let sha_cases: &[(&[u8], &str)] = &[
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (input, expected) in sha_cases {
        let got = sha256_hex(input);
        assert_eq!(
            &got,
            expected,
            "sha256({:?})",
            String::from_utf8_lossy(input)
        );
    }
    println!("SHA-256: {} FIPS vectors pass", sha_cases.len());

    // --- Same input, different internal chunking ---------------------
    // Hashing a message that spans multiple 64-byte SHA-256 blocks
    // exercises the block buffer and padding path.
    let long_message = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let digest = sha256_hex(long_message);
    assert_eq!(digest.len(), 64);
    println!("sha256 of a 96-byte message (2 blocks) -> {digest}");

    println!("all digest vectors verified");
}
