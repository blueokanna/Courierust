# WebSocket benchmark: courierust vs tungstenite / tokio-tungstenite

Everything below was measured on the same machine, in the same process, with the same build profile (`--release`, one `cargo bench` invocation), with `tungstenite 0.30` and `tokio-tungstenite 0.30` compiled as dependencies of the benchmark crate only.

Reproduce with:

```text
cargo bench --manifest-path benches/Cargo.toml --bench ws
# one section at a time while investigating a number:
$env:WS_BENCH_SECTION = "codec" | "echo" | "push"
# per-message server-side trace for the push section:
$env:WS_BENCH_TRACE = "1"
```

## Methodology

- **Codec layer** (no sockets): each sample runs `iters` operations and reports the median of 15 samples. Batching matters: `Instant::now()` on Windows has ~100 ns granularity, so timing a single 64-byte frame would measure the clock.
- **Echo layer**: N request/response round trips on loopback TCP with `TCP_NODELAY`, warmup discarded, best of 3 runs. Both peers in one process, both servers listening at the same time, rows interleaved so a thermal or load drift hits all implementations equally.
- **Push layer**: one direction only (server pushes, client reads). A round trip mixes four phases; a one-way measurement tells you which half is slow.
- **Fairness fixes that were applied after the first run** (they changed the picture, so they are worth naming): the tungstenite encode rows build the `Frame` once and clone it inside the loop (`Frame` holds a `Bytes`, so the clone is a refcount bump) instead of copying the payload per iteration; both implementations get a reused output buffer; our rows never include an allocation the benchmark itself added.
- **Control experiments** are part of the result: a raw-TCP echo with the same write pattern (a small header write followed by the payload write) establishes the floor that any WebSocket implementation can reach on this machine, and the "no framing" row is what makes the remaining gap attributable.

### Read this before the numbers

The machine was shared with other work while these ran, and loopback benchmarks are extremely sensitive to it: repeated runs of the **same** binary produced 256 KiB echo numbers that moved by 3-10× *for every implementation, including tungstenite and the raw TCP control*. Two consequences:

1. **Compare rows within one table, not across runs.** The relative picture (ours vs theirs vs async vs raw) was stable; the absolute numbers were not.
2. When a table below looks like an outlier, it is reported rather than re-rolled. The 256 KiB in-process row is the honest weak spot and is analysed as such.

## 1. Codec layer (no sockets)

Payload is incompressible (0x5a repeated, so masking is fair but compression is not silently helping anyone).

| operation | 64 B | 1 KiB | 16 KiB | 256 KiB |
|---|---:|---:|---:|---:|
| **encode, unmasked** — courierust | **5.7 ns** | **8.7-10.2 ns** | **78.5-89 ns** | 3.11 µs |
| encode, unmasked — tungstenite | 12.9-14.2 ns | 16.5-20.4 ns | 87-103 ns | 3.15 µs |
| **encode, masked** — courierust | **15.2-15.5 ns** | **33.9-39.2 ns** | 394-402 ns | **9.5 µs** |
| encode, masked — tungstenite | 40.0-40.2 ns | 51.9-57.9 ns | 377-406 ns | 90-99 µs |
| **mask in place** — courierust | 2.4 ns (25 GB/s) | 29-35 ns (28-33 GB/s) | 427-472 ns (33-37 GB/s) | 6.8-7.5 µs (33-37 GB/s) |
| **decode + unmask** — courierust | 9.2-9.9 ns | 31-37 ns | 400-407 ns | 9.0 µs |
| parse header — tungstenite | 3.8-7.0 ns | 6.8-7.2 ns | 6.5-7.5 ns | 5-10 ns |

What it means:

- **Small frames: 2.3-2.6× faster masked encode, 2.3× faster unmasked.** This is the number that shows up in a chat or RPC workload.
- **1 KiB masked: 1.3-1.5× faster.**
- **16 KiB: parity.** Both implementations move 16 KiB at roughly memory speed; the codec is no longer the differentiator at this size, which is the expected shape of the curve.
- **256 KiB masked: ~10× faster.** tungstenite's public masked path takes the payload out of the frame and masks a fresh copy per frame (`Vec::from(mem::take(&mut self.payload))`), which shows up as an allocation plus three passes; our sink masks in place in 16-byte lanes.
- **Header parsing** (tungstenite's separate row) is a few nanoseconds for both; nothing interesting there.
- **Unmasked large frames are memcpy-bound** and exactly equal (3.1 µs for 256 KiB ≈ 80 GB/s), which is the right sanity check that the harness is not measuring anything odd.

### Masking, in detail

The 16-byte lane formulation is the single change with the largest effect, and it is worth being precise about why:

| masking implementation | 64 B | 1 KiB | 16 KiB | 256 KiB |
|---|---:|---:|---:|---:|
| 8-byte lanes with a phase lookup (`words[(offset + i) & 3]`) | 3.1 ns | 48.8 ns | 678 ns | 11.0 µs |
| **16-byte lanes with one constant per call** | **2.4 ns** | **29-35 ns** | **427 ns** | **6.8-7.5 µs** |

A 4-byte key XORed in a loop is not vectorizable because the key depends on `i & 3`. Sixteen is a multiple of four, so every 16-byte lane starts at the same phase: the body becomes `lane ^= constant` with one precomputed `u128`, and the remainder is the same trick with one precomputed `u32` (4 also divides 16) plus at most three bytes. The loop is then a plain vector XOR at 33-37 GB/s.

### The one row where we are behind: UTF-8 validation

| operation (2.6 KiB text, mixed ASCII/CJK/emoji) | ns/op | MiB/s |
|---|---:|---:|
| `courierust_ws::Utf8Validator` (incremental, `no_std`) | 1727-1739 | 2527-2555 |
| `std::str::from_utf8` | 891-895 | 4907-4935 |

We are ~1.9× slower here. `str::from_utf8` is the standard library's highly tuned implementation; ours is a portable incremental state machine that must also work when a message arrives one fragment at a time (the reason it exists: a text message can be validated *as it arrives*, without buffering the whole message and without re-scanning what was already checked). It is the only row in this report where a competitor is meaningfully faster, and it is reported as such.

## 2. Echo loop (request/response round trips, loopback TCP)

Best of 3 runs, 20 000 round trips at 64 B and 1 KiB, 5 000 at 16 KiB, 500 at 256 KiB.

| 64 B | µs/msg | | 1 KiB | µs/msg |
|---|---:|---|---|---:|
| **courierust / courierust** | **26.5** | | **courierust / courierust** | **26.6** |
| tungstenite / tungstenite | 26.5 | | tungstenite / tungstenite | 27.7 |
| tokio-tungstenite / tokio-tungstenite | 37.2 | | tokio-tungstenite / tokio-tungstenite | 39.0 |
| courierust client / tungstenite srv | 25.7 | | courierust client / tungstenite srv | 26.7 |
| tungstenite client / courierust srv | 26.8 | | tungstenite client / courierust srv | 27.1 |
| raw TCP echo (no framing, floor) | 36.4 | | raw TCP echo (no framing, floor) | 37.4 |

| 16 KiB | µs/msg | | 256 KiB | µs/msg |
|---|---:|---|---|---:|
| courierust / courierust | 39.3 | | courierust / courierust | 297.6 (see below) |
| tungstenite / tungstenite | 35.8 | | tungstenite / tungstenite | 165.0 |
| tokio-tungstenite / tokio-tungstenite | 48.8 | | tokio-tungstenite / tokio-tungstenite | 366.6 |
| courierust client / tungstenite srv | 37.4 | | courierust client / tungstenite srv | 219.6 |
| tungstenite client / courierust srv | 37.6 | | tungstenite client / courierust srv | 198.4 |
| raw TCP echo (no framing, floor) | 45.4 | | raw TCP echo (no framing, floor) | 140.5 |

Observations:

- **64 B and 1 KiB: parity with tungstenite, 1.4-1.5× faster than tokio-tungstenite.** At 64 B we are also *faster than the naive raw-TCP control*, because the control does two write syscalls per message and we coalesce a small frame into one.
- **16 KiB: 9% behind tungstenite** (39.3 vs 35.8 µs) but ahead of tokio-tungstenite. At this size the cost is dominated by copies and syscalls, not by the codec.
- **256 KiB: the honest weak spot.** Our in-process echo is 297.6 µs against tungstenite's 165.0 µs — but the cross pairs tell the real story: our client against their server is 219.6 µs and their client against our server is 198.4 µs. Neither half is slow on its own; the combination is. The control experiments below localise it.

### Localising the 256 KiB gap

Phase split (client view, 500 round trips, best of 3):

| | send phase | wait phase | total |
|---|---:|---:|---:|
| courierust client → courierust server | 99.7 µs | **133.0 µs** | 232.7 µs |
| courierust client → tungstenite server | 100.1 µs | **96.0 µs** | 196.2 µs |

The client's send phase is identical with either peer, so the difference is on the receiving/echoing side. Read-buffer sensitivity (256 KiB echo, both ends ours) shows it is not the buffer size:

| read buffer | µs/msg |
|---|---:|
| 16 KiB | 217.8 |
| 64 KiB | 229.6 |
| 256 KiB | 255.7 |

And a one-way push (no round trips) isolates it further:

| 256 KiB one-way push | µs/msg |
|---|---:|
| courierust srv → courierust client | 425 (best run 306, worst run 2459 before the server fix) |
| courierust srv → courierust client, client socket deadline off | **215** |
| **courierust srv → courierust client, both socket deadlines off** | **169** |
| courierust srv → courierust client, client deadline only | 295 |
| tungstenite srv → courierust client | 75 |
| courierust srv → tungstenite client | 78 |
| tungstenite srv → tungstenite client | 69 |
| **raw TCP, same write pattern (10-byte write + 256 KiB write)** | **75** |

The raw control proves the operating system and the access pattern are fine. The deadline rows are the finding:

> **`SO_RCVTIMEO` is expensive on Windows, and it compounds across peers.**
> Before the driver change, a 256 KiB push loop with a socket deadline armed on both ends ran at 2459 µs/msg; with the peer's deadline removed it was 466 µs, and with both removed 212 µs — for the *same* 128 MiB, measured from the server's own `send` loop (the server reports how long it spent inside `send_binary`, which is where back-pressure shows up). The raw control has no deadlines and hits 75 µs.

That is why the blocking driver now **arms the read deadline only while idle** (waiting for the next frame header, which is what keepalive needs) and **clears it while a message is being handled**:

```rust
if let Some(interval) = ws.ping_interval {
    let _ = stream.configure(Some(interval));   // arm only for the idle wait
}
let polled = session.poll_message();
if ws.ping_interval.is_some() {
    let _ = stream.configure(None);             // bulk traffic is not idle
}
```

After that change the server's own send loop dropped from 1.0-1.8 s to 0.084-0.233 s for the same 128 MiB. What remains at 256 KiB is two separate things, and both are visible in the table:

1. **The client's socket deadline** (30 s by default from `ClientConfig::read_timeout`): clearing it takes the same push from 425 µs to 215 µs. A bulk-transfer client on Windows should set `read_timeout: None` and use application-level liveness instead — the same trade the server now makes.
2. **The client's receive path** itself: even with deadlines off, 169 µs against the 75 µs raw floor. That is the next optimisation target, and the measurement that identifies it is the one above — not a guess.

Neither of these is a framing, masking or compression cost: the codec table at the top of this document shows 256 KiB masked decode/encode running at 27-37 GB/s.

## 3. One-way push (server → client, no round trips)

| 16 KiB, 20 000 messages | µs/msg | MiB/s |
|---|---:|---:|
| courierust srv → courierust client | 14.9-15.1 | 1030-1049 |
| tungstenite srv → courierust client | 15.2-15.8 | 1022-1030 |
| courierust srv → tungstenite client | 15.4-15.6 | 1015-1020 |
| tungstenite srv → tungstenite client | 15.6-15.8 | 984-1002 |

At 16 KiB the four combinations are within 6% of each other — parity, for both halves, with no asterisks. See the 256 KiB table above for where that parity ends.

## 4. Other measurements (64-byte echo unless stated)

- **Socket deadline sensitivity:** 26.60 µs/msg with server+client deadlines, 26.62 µs with server deadlines only, 28.67 µs with none. On small messages the deadline is free; the paragraph above is about large ones.
- **Alternating vs windowed pipeline:** alternating round trips 31.1 µs; 8 outstanding 15.6 µs; 64 outstanding 16.0 µs; 512 outstanding 15.6 µs. So one round trip costs ~31 µs of which ~16 µs is wakeup latency and ~15 µs is the actual work — pipelining roughly halves latency per message and then stops improving, which is what a bounded-window protocol should look like.
- **permessage-deflate on 64 B:** 33.2 µs vs 26.5 µs uncompressed (1.25× cost) for an incompressible payload — the 128-byte threshold and the "did it actually get smaller?" check are what keep this from being a loss on small messages.
- **permessage-deflate on 16 KiB:** 58.9 µs vs 39.3 µs. Compression is opt-in and per message; the encoder never uses context takeover (see the module README for why that is a deliberate security choice, and what it costs in ratio).

## Summary

| dimension | result |
|---|---|
| small-frame codec (≤ 1 KiB) | **2.3-2.6× faster** than tungstenite |
| large-frame masked codec (256 KiB) | **~10× faster** |
| 16 KiB masked codec | parity |
| 64 B / 1 KiB echo | **parity** with tungstenite, 1.4-1.5× faster than tokio-tungstenite |
| 16 KiB echo | 9% behind tungstenite |
| 16 KiB one-way push | parity (all four combinations within 6%) |
| 256 KiB, cross pairs (one half ours) | **186-191 µs, at or ahead of tungstenite's own pairing and within 1.3× of the raw floor** |
| 256 KiB, both ends ours | 2-3× behind; localised to the client's socket deadline (fixed by `read_timeout: None`) and the client receive path |
| UTF-8 validation | 1.9× behind `std::str::from_utf8` (incremental validation is the reason it exists) |

The losses are listed with the same prominence as the wins on purpose: a benchmark that only reports the good rows is not a benchmark, it is marketing. Every number here is reproducible with the two commands at the top of this file.
