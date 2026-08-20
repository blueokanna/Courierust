import zlib, binascii, json

vectors = [
    b"",
    b"hello",
    b"a" * 18,
    b"The quick brown fox jumps over the lazy dog. " * 20,
    b"courierust gzip compression negotiation test payload with some repetition repetition repetition",
    bytes(range(256)) * 8,
]

out = []
for p in vectors:
    # Raw DEFLATE (RFC 1951) via zlib, stripping the 2-byte zlib header and
    # 4-byte Adler-32 trailer.
    z = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = z.compress(p) + z.flush()
    # gzip member (RFC 1952).
    g = zlib.compressobj(9, zlib.DEFLATED, 31)
    gzipped = g.compress(p) + g.flush()
    out.append({
        "plain_hex": p.hex(),
        "deflate_hex": deflated.hex(),
        "gzip_hex": gzipped.hex(),
    })

with open("gzip_vectors.json", "w") as f:
    json.dump(out, f, indent=1)
print("ok", len(out))
for o in out:
    print(len(bytes.fromhex(o["plain_hex"])), "->", len(bytes.fromhex(o["gzip_hex"])))
