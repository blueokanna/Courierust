"""Generate the far-distance DEFLATE interop vectors.

Every existing vector in `courierust_deflate`'s test module is small enough
that zlib never emits a distance code above 21 (base 1025, 9 extra bits),
which is exactly the range a wrong extra-bit count in the table would not
show up in. This script produces the missing coverage: a payload whose
second half is a verbatim copy of the first, so zlib has to emit distance
codes 26-27 (10240 bytes back, 12 extra bits).

Outputs (written next to the module that consumes them):

    src/courierust_deflate/vectors/far.plain    - the raw payload
    src/courierust_deflate/vectors/far.deflate  - raw DEFLATE (RFC 1951)
    src/courierust_deflate/vectors/far.gzip     - gzip member (RFC 1952)

Run:  python scripts/gen_deflate_far_vectors.py
"""

import os
import random
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.normpath(os.path.join(HERE, "..", "src", "courierust_deflate", "vectors"))

PREFIX_LEN = 10240


def main() -> None:
    rng = random.Random(20260914)  # fixed seed: the vectors are part of the test suite
    prefix = rng.randbytes(PREFIX_LEN)
    payload = prefix + prefix

    raw = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = raw.compress(payload) + raw.flush()

    gz = zlib.compressobj(9, zlib.DEFLATED, 31)
    gzipped = gz.compress(payload) + gz.flush()

    # The whole point of the vector: the second copy must be a long
    # back-reference, not a re-emission of the literals. The first copy is
    # random, so it cannot compress — the bound is "second copy ~free".
    assert len(deflated) < PREFIX_LEN + 2048, (
        "zlib did not use far back-references; regenerate with more entropy"
    )
    assert zlib.decompress(deflated, -15) == payload
    assert zlib.decompress(gzipped, 31) == payload

    os.makedirs(OUT_DIR, exist_ok=True)
    for name, blob in (("far.plain", payload), ("far.deflate", deflated), ("far.gzip", gzipped)):
        with open(os.path.join(OUT_DIR, name), "wb") as f:
            f.write(blob)

    print(f"payload {len(payload)} -> raw deflate {len(deflated)}, gzip {len(gzipped)}")


if __name__ == "__main__":
    main()
