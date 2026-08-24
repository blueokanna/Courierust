# courierust_hpack

HPACK (RFC 7541) header block encoder and decoder. `no_std`, zero dependencies.

## The part that has to be right

The **decoder**. HPACK is one of those formats where being "mostly correct" means being completely broken — a mis-decoded header block desynchronizes the entire connection. So the decoder is validated **byte-for-byte against the official RFC 7541 Appendix C vectors (C.2–C.6)**, and the Huffman decoder is exercised against the full spec table.

The encoder has it easy (RFC grants encoders latitude), but I still follow the canonical strategy:

1. full-match → indexed;
2. else literal-with-indexed-name, add to dynamic table if reusable;
3. sensitive fields (`authorization`, `cookie`, ...) → never-indexed, always;
4. Huffman when it shortens the wire form.

## What's inside

- **61-entry static table + dynamic table**, with hash-accelerated index lookup.
- **8-bit two-level table-driven Huffman decode** — the decode tables are built at compile time, and short codes take a fast path. No bit-by-bit crawling.
- `HeaderField` carries a `never_indexed` marker, so "don't ever put this in the dynamic table" survives the round trip.
- Encoder and decoder share the same table machinery — no two implementations to drift apart.

## The hardening you didn't ask for

HPACK is a compression bomb delivery system if you're not careful. The decoder rejects:

- integer overflow in prefix integers;
- Huffman EOS codes and invalid padding;
- dynamic-table size above the peer's SETTINGS limit;
- header lists over the configured cap.

A peer that wants to make you allocate 4 GB from a 3-byte block gets an error, not memory.

## Why not just use the `hpack` crate

Because this stack is `no_std` with zero deps, and because — like everything else here — it's a good way to actually *know* the format instead of trusting a dependency to have gotten it right.
