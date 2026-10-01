# courierust_http

The HTTP message model: request, response, headers, URI, status, version, body.

This is the **vocabulary** of the whole stack. Every layer above — h1, h2, h3, gRPC, client, server — speaks in terms of the types defined here. If you're going to read one module first, read this one.

## Why it exists

Every protocol layer needs a shared model of "what an HTTP message is". The obvious move is to depend on the `http` crate. The problem: I wanted the core to compile on `no_std` with **zero dependencies**, and `http` is not `no_std`-clean in the way I needed. So I wrote the model by hand. It's not hard — it's just that somebody has to do it.

## What's inside

- `Request` / `Response` — the message containers.
- `HeaderMap` / `HeaderName` / `HeaderValue` — names validated as RFC 9110 tokens, values byte-checked. No silent lowercasing surprises; h2 pseudo-headers (`:method`, etc.) are first-class.
- `Uri` / `PathAndQuery` / `Url` — absolute-form and origin-form targets, plus the client-side absolute URL type with authority/scheme splitting.
- `Method`, `StatusCode`, `Version` — the enums you expect, with the ones you forget (like `CONNECT`).
- `Body` — `Empty` / `Bytes` at this layer. The channel-backed streaming variant lives in `courierust_body` (std layer), so the core stays allocation-light and `no_std`.
- `form` — the `application/x-www-form-urlencoded` byte serializer and its parser (`encode`, `serialize`, `decode`, `decode_bytes`, `parse`). Query strings and form bodies need the same escaping, and the client builder uses this rather than growing its own.
- `header::is_valid_field_value` — the character class an RFC 9110 §5.5 field value may contain. h1 rejects a value carrying CR, LF or NUL when it writes the message; h2 and h3 use this same check, because there it is a *malformed message* (RFC 9113 §8.2.1, RFC 9114 §10.3) that a conforming peer resets rather than a framing accident.

## The design calls

- **One source of truth.** Nobody re-implements "what a header name is" anywhere else in the stack. If the validation is wrong, it's wrong in exactly one place.
- **`no_std` first.** This module has no idea what a socket is. That's deliberate — it's what lets the same model run in a kernel module and on a server.
- **Strict where it matters.** Header names are tokens, not "whatever bytes you typed". Being lenient here is how smuggling bugs start.

## Scope

It's a model, not a codec. Wire parsing/serialization lives in `courierust_h1` / `courierust_h2` / `courierust_h3`. This module just holds the state that moves through them.
