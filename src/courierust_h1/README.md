# courierust_h1

HTTP/1.x wire helpers shared by the client and the server: request-line parsing, header-block reading, body framing (Content-Length / chunked), and head serialization. This is where HTTP/1.1 actually gets *parsed*, as opposed to modeled (`courierust_http`).

## The part that must be strict

**Request-line parsing** follows RFC 9112 §3 to the letter: exactly three tokens (`METHOD SP target SP HTTP/x.y`), version required, trailing junk rejected. The reason isn't pedantry — it's smuggling. If a proxy and your server disagree on where a message boundary is, attackers get to smuggle requests. Strict three-token parsing is the cheap way to make disagreement impossible.

**Chunked framing** is the same story. Chunk sizes, CRLF terminators, trailer sections — all parsed by a *single* shared parser, and the event-driven incremental server path reuses that exact parser (see `courierust_server::event`). Two code paths that disagree on a request's meaning are exactly how smuggling happens behind a proxy, so there is exactly one authority.

## What's here

- `parse_request_line` — strict three-token request line.
- `read_headers_scratch` — header block reading against caps (line/header-count/block-size), reusing a `Scratch` so keep-alive steady state does zero per-request allocation.
- `body_length` — decides `None` / `Content-Length` / `chunked` from the method + headers.
- `read_body_fixed_scratch` / `read_body_chunked_scratch` — bounded body reads (a huge advertised length is rejected up front, not waited for).
- `parse_chunk_size` — the single authority for chunk sizes, shared by the blocking and event-driven paths.
- `write_request_head` / `write_response_head` — serialization.
- `keep_alive_requested` / `wants_close` — exact-token `Connection` semantics (a `closex` token does *not* close), so the two server paths never disagree.
- `is_hop_by_hop` — the RFC 9110 hop-by-hop field list.

## The caps

64 KiB per line, 1024 headers, 1 MiB header block, body limits from config. Slowloris feeds are bounded before they become a problem.

## Usage

The client and server call these directly. If you're writing your own h1 transport, this is the parsing layer to reuse — it's shared for a reason.
