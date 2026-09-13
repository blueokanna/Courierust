//! `application/x-www-form-urlencoded` encoding (WHATWG URL Standard).
//!
//! Query strings and form bodies need the same thing: a byte serializer
//! that survives being put in a URL. The core keeps it here, next to the
//! message model, so the client builder and a server parsing form input
//! share one implementation instead of each inventing its own escaping.
//!
//! The serializer is the WHATWG *urlencoded byte serializer*, which is
//! what browsers, `curl --data-urlencode` and every HTTP framework agree
//! on: alphanumerics and `* - . _` pass through, a space becomes `+`, and
//! everything else — including every byte of a multi-byte UTF-8 character
//! — becomes `%XX` with **uppercase** hex digits.
//!
//! The parser is deliberately stricter than WHATWG's: a malformed `%`
//! escape or a body that is not valid UTF-8 is an error rather than a
//! U+FFFD replacement. Substituting would let a mangled field value look
//! like a legitimate one, and the caller can substitute for itself —
//! refusing is the only choice it cannot undo.

use crate::courierust_error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;

/// Whether `b` survives the serializer untouched.
///
/// The allowed set is `*` `-` `.` `_` `0-9` `A-Z` `a-z`; every other byte
/// — including `~`, `!`, `'`, `(`, `)`, which RFC 3986 would allow in a
/// query — is escaped, so the output is safe in a URL, in an HTML form
/// and in a body without further analysis.
#[inline]
fn is_passthrough(b: u8) -> bool {
    matches!(b, b'*' | b'-' | b'.' | b'_') || b.is_ascii_alphanumeric()
}

/// Append the urlencoded form of `input` to `out`.
///
/// Appending to a `String` rather than returning one keeps a caller that
/// builds `a=1&b=2&c=3` from allocating once per component.
pub fn encode_to(input: &str, out: &mut String) {
    for &b in input.as_bytes() {
        match b {
            b' ' => out.push('+'),
            _ if is_passthrough(b) => out.push(b as char),
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
}

/// Encode one component: `"a b&c"` → `"a+b%26c"`.
pub fn encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    encode_to(input, &mut out);
    out
}

/// Serialize `(name, value)` pairs into a form body / query string:
/// `[("q", "a b"), ("n", "1")]` → `"q=a+b&n=1"`.
///
/// Both halves of every pair are encoded, so a name containing `=` or a
/// value containing `&` cannot forge a field.
pub fn serialize<'a, I>(pairs: I) -> String
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out = String::new();
    for (name, value) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        encode_to(name, &mut out);
        out.push('=');
        encode_to(value, &mut out);
    }
    out
}

/// Decode one component to bytes: `+` and `%XX` are undone, and every
/// other byte is taken literally.
///
/// The result is a byte sequence, not text: a form field may legally
/// carry `%00` or a byte sequence that is not UTF-8, and only the caller
/// knows whether that is meaningful. Use [`decode`] for the text case.
pub fn decode_bytes(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .ok_or_else(|| Error::protocol("truncated percent-encoding in form data"))?;
                let hi = hex_digit(hex[0])?;
                let lo = hex_digit(hex[1])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Decode one component as UTF-8 text. Differs from WHATWG in rejecting a
/// body that is not valid UTF-8 rather than substituting U+FFFD.
pub fn decode(input: &str) -> Result<String> {
    let bytes = decode_bytes(input)?;
    String::from_utf8(bytes).map_err(|_| Error::protocol("form data is not valid UTF-8"))
}

/// Split a form body / query string into decoded `(name, value)`
/// pairs. A field without `=` is a name with an empty value, which is how
/// the standard parses it.
pub fn parse(body: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for field in body.split('&') {
        if field.is_empty() {
            continue;
        }
        let (name, value) = match field.split_once('=') {
            Some((name, value)) => (name, value),
            None => (field, ""),
        };
        out.push((decode(name)?, decode(value)?));
    }
    Ok(out)
}

#[inline]
fn hex_digit(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::protocol("invalid percent-encoding in form data")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_set_is_the_urlencoded_one() {
        assert_eq!(encode("AZaz09*-._"), "AZaz09*-._");
        assert_eq!(encode("~!'()"), "%7E%21%27%28%29");
        assert_eq!(encode("a=b&c"), "a%3Db%26c");
        assert_eq!(encode("q a+b"), "q+a%2Bb");
        assert_eq!(encode(""), "");
    }

    #[test]
    fn multi_byte_characters_escape_per_byte() {
        assert_eq!(encode("中"), "%E4%B8%AD");
        assert_eq!(encode("é"), "%C3%A9");
        assert_eq!(decode("A%c3%a9Z").unwrap(), "AéZ");
    }

    #[test]
    fn serialize_joins_with_ampersand_and_escapes_both_halves() {
        assert_eq!(
            serialize([("q", "a b"), ("n", "1"), ("x&y", "z=w")]),
            "q=a+b&n=1&x%26y=z%3Dw"
        );
        assert_eq!(serialize(Vec::new()), "");
    }

    #[test]
    fn decode_undoes_plus_escape_and_literal_bytes() {
        assert_eq!(decode("a+b").unwrap(), "a b");
        assert_eq!(decode("a%2Bb").unwrap(), "a+b");
        assert_eq!(decode_bytes("%00%FF").unwrap(), [0x00, 0xff]);
        assert_eq!(decode("plain").unwrap(), "plain");
    }

    #[test]
    fn malformed_escapes_are_refused() {
        for bad in ["%", "%2", "%zz", "a%4", "100%"] {
            assert!(decode(bad).is_err(), "{bad} must not decode");
        }
    }

    #[test]
    fn invalid_utf8_is_refused_but_the_bytes_are_not() {
        assert!(decode("%FF").is_err());
        assert_eq!(decode_bytes("%FF").unwrap(), [0xff]);
    }

    #[test]
    fn parse_splits_fields_and_keeps_empty_values() {
        assert_eq!(
            parse("a=1&b=hello+world&flag&empty=").unwrap(),
            [
                ("a".into(), "1".into()),
                ("b".into(), "hello world".into()),
                ("flag".into(), String::new()),
                ("empty".into(), String::new()),
            ]
        );
        assert_eq!(parse("").unwrap(), Vec::new());
        assert!(parse("a=%zz").is_err());
    }

    #[test]
    fn encode_decode_round_trips_arbitrary_text() {
        let samples = [
            "",
            "simple",
            "spaces and + plus",
            "&=?#%",
            "中文 测试",
            "emoji 🚀 ok",
        ];
        for sample in samples {
            assert_eq!(decode(&encode(sample)).unwrap(), sample, "{sample}");
        }
    }
}
