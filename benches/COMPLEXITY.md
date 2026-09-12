# Complexity: time and space, measured

Two questions, answered with numbers instead of adjectives:

1. **Time complexity** — how does the per-operation cost grow with the input size?
2. **Space complexity** — how many bytes and allocation calls does one operation cost, and what does one idle connection cost?

`benches/src/complexity.rs` measures both, in the same process and the same build
as the mainstream comparison it reports. `benchmark.yml` runs it on every pull
request and push (suite `complexity`), uploads `complexity.log` and renders the
tables into `Github_Action_Benchmark.md`.

```text
cargo bench --manifest-path benches/Cargo.toml --bench complexity
# one family at a time:
COMPLEXITY_FAMILY=codec | http | headers | connections | deflate
```

Families:

| family | what it scales | compared against |
|---|---|---|
| `codec` | WebSocket frame encode / mask / decode / UTF-8, 64 B → 1 MiB | `tungstenite 0.30` |
| `http` | one GET round trip, 1 KiB → 1 MiB | `reqwest` (hyper), same machine/process |
| `headers` | request header count, 4 → 64 | `reqwest` (hyper) |
| `connections` | space of one idle keep-alive connection | Courierust blocking driver, hyper + tokio |
| `deflate` | permessage-deflate encode with a reused vs a fresh context, inflate | no fair third-party counterpart in this workspace (said, not invented) |

## How the numbers are produced

### Time: two fitted numbers, not one

For every operation the bench measures the per-operation cost at several sizes
spanning three orders of magnitude. Every point is the **minimum of three
repeats**: cache effects and runner load only ever make a measurement slower,
so the minimum is the right estimator, and a single noisy point would otherwise
invent curvature that is not in the code. From those points the bench reports:

- **the affine model** `cost = a + b·n`, least-squares over every measured point,
  with `R²`. `a` is the fixed per-operation cost (frame header, call overhead,
  buffer setup); `b` is the per-unit cost.
- **`median k`**, the median of the adjacent-size-pair exponents, and **`max k`**,
  the worst pair. The median names the class, the maximum makes instability
  visible instead of hiding it.
- **the class**, derived from `median k` with deliberately wide bands:
  `|k| < 0.15` → `O(1)`, `0.85 … 1.15` → `O(n)`, `1.85 … 2.15` → `O(n²)`,
  otherwise `O(n^k)`. A range whose fixed term dwarfs its per-unit term is
  labelled **`fixed-cost dominated`** rather than quoting a sublinear-looking
  exponent that is really the constant — for those families the number to read
  is `slope b` (nanoseconds per extra header, for example).

Why not a single power-law fit over the whole range? Because a fixed
per-operation term bends a log-log fit *below* the true exponent: 64-byte frame
encoding is dominated by the header write, so a power fit reports `k ≈ 0.84` for
an operation that is, byte for byte, linear. The affine model plus the adjacent
pair exponents states the same data without the artifact. The same effect is why
`fixed_a` can come out slightly negative on a reference implementation whose
small-size points sit above its own line, and why `class` is read together with
`slope b`, `fixed a` and `R²` rather than on its own.

### Space: attributed per operation and per connection

- **Per operation.** The bench binary installs a counting global allocator around
  the system allocator and samples it either side of each measurement region, so
  `alloc_bytes` and `allocs` belong to the operation under test. Buffers an
  implementation reuses are cleared *inside* the region, which is why a
  zero-allocation steady state reports `0.0 B/op, 0.00 allocs/op` and an
  implementation that allocates per call cannot hide it.
- **Per connection.** 65 idle keep-alive connections are opened (each after a
  real request/response) and the live-bytes and RSS delta against 1 connection is
  divided by the difference in connection count, so the fixed process and runtime
  cost cancels out. Linux reads `/proc/self/statm`, Windows reads `psapi`; any
  other platform reports `n/a` with a reason instead of a guess.

### Fairness rules

- Same process, same build profile, same measurement region for both sides;
  identical payloads; `TCP_NODELAY` on both stacks.
- Where the reference implementation's public API forces a copy (tungstenite's
  masked encode allocates the masked payload), the row reports it — that is its
  behaviour, not a handicap we invented.
- The counters cover the whole program, so a runtime's internal allocations
  (tokio's pools, hyper's per-connection state) count on its side. That is
  exactly what a *space* comparison should include.
- Ratios and classes are comparable only within one run: loopback measurements
  move with runner load, which is also why every row carries its `n` and its fit
  inputs.

## Measured classes and constant factors

One run of the suite on a Windows development machine (16 logical cores,
release profile). CI numbers come from the generated report; the numbers below
are here to show the shape of the result, and the *method* is what should be
read as the claim.

| family | implementation | operation | metric | class | median k | max k | slope b | fixed a | R² |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| codec | courierust | encode_unmasked | time_ns | O(n) | 0.995 | 1.314 | 0.0118 ns/B | −27 ns | 0.9999 |
| codec | tungstenite | encode_unmasked | time_ns | O(n) | 1.051 | 1.285 | 0.0128 ns/B | −76 ns | 0.9997 |
| codec | courierust | encode_masked | time_ns | O(n) | 0.977 | 1.130 | 0.0348 ns/B | +21 ns | 0.9999 |
| codec | tungstenite | encode_masked | time_ns | O(n) | 0.939 | 1.896 | 0.2678 ns/B | +80 ns | 0.9991 |
| codec | courierust | encode_masked | alloc_bytes | O(1) | — | — | 0.000 B/B | 0 B | — |
| codec | tungstenite | encode_masked | alloc_bytes | O(n) | 1.000 | 1.000 | 1.000 B/B | 0 B | 1.0000 |
| codec | courierust | utf8_validate | time_ns | O(n) | — | — | 0.193 ns/B | ~0 | — |
| codec | `std` (`str::from_utf8`) | utf8_validate | time_ns | O(n) | — | — | 0.193 ns/B | ~0 | — |
| http | courierust | get_roundtrip | time_ns | O(n^0.62) | 0.617 | 0.861 | 0.756 ns/B | +41.6 µs | 0.9995 |
| http | reqwest_hyper | get_roundtrip | time_ns | O(n^0.40) | 0.397 | 1.193 | 0.698 ns/B | +19.9 µs | 0.9880 |
| http | courierust | get_roundtrip | alloc_bytes | O(n) | 0.980 | 0.998 | 2.000 B/B | +2.0 KiB | 1.0000 |
| http | reqwest_hyper | get_roundtrip | alloc_bytes | O(n^0.77) | 0.771 | 1.298 | 2.522 B/B | −48 KiB | 0.9911 |
| headers | courierust | get_with_headers | time_ns | O(n^0.40) | 0.400 | 0.400 | 752 ns/header | +39.0 µs | 0.9987 |
| headers | reqwest_hyper | get_with_headers | time_ns | O(n^0.33) | 0.328 | 0.328 | 671 ns/header | +42.5 µs | 0.9985 |
| headers | courierust | get_with_headers | alloc_bytes | O(n) | 0.858 | 0.858 | 884 B/header | +4.4 KiB | 1.0000 |
| headers | reqwest_hyper | get_with_headers | alloc_bytes | O(n^0.60) | 0.596 | 0.596 | 1168 B/header | +25 KiB | 1.0000 |
| deflate | courierust | deflate_reused (compressible) | time_ns | O(n) | 0.998 | 0.998 | 0.559 ns/B | +151 ns | 1.0000 |
| deflate | courierust | deflate_fresh (compressible) | time_ns | O(n) | 1.038 | 1.038 | 1.407 ns/B | −3.6 µs | 1.0000 |
| deflate | courierust | deflate_reused (compressible) | alloc_bytes | O(1) | — | — | 0.000 B/B | 0 B | — |
| deflate | courierust | deflate_fresh (compressible) | alloc_bytes | O(n) | 0.867 | 0.867 | 4.093 B/B | +131 KiB | 1.0000 |
| deflate | courierust | inflate (compressible) | alloc_bytes | fixed-cost dominated | 0.000 | 0.000 | 0.000 B/B | 29 B/op | 1.0000 |
| deflate | courierust | deflate_reused (incompressible) | alloc_bytes | O(1) | — | — | 0.000 B/B | 0 B | — |
| deflate | courierust | deflate_fresh (incompressible) | alloc_bytes | O(n) | 0.960 | 0.960 | 16.000 B/B | +131 KiB | 1.0000 |

What those rows say, in plain language:

- **The frame layer is linear in the payload, and its per-byte constant is what
  the optimisations bought.** Masked encoding costs this crate ~0.035 ns per byte
  (≈29 GB/s of payload) against tungstenite's ~0.268 ns/B (≈3.7 GB/s) — 7.7× per
  byte, and the paired rows agree at every size: 0.29× at 64 B, 0.61× at 1 KiB,
  0.12× at 256 KiB, 0.13× at 1 MiB. Unmasked encoding is at parity per byte
  (0.0118 against 0.0128 ns/B) with a much smaller fixed term, which is why the
  small sizes are 0.44× … 0.61×.
- **Space per operation is a real difference, not a rounding error.** Masked
  tungstenite encoding allocates a full payload copy per frame (`1.000 B/B`);
  our client path allocates nothing per frame in the steady state. At 1 MiB
  messages that is 1 MiB of allocation per message versus zero — the difference
  between a steady state and an allocator round trip on the hot path.
- **UTF-8 validation is at the platform baseline.** 891.5 ns against
  `str::from_utf8`'s 890.3 ns on 4 608 bytes of mixed ASCII/Japanese/emoji
  (`ratio = 1.001`) — the bulk scan is delegated to the standard library, and
  what this crate adds is the part the standard library cannot do: state that
  survives a frame boundary and an offset plus reason for the offending byte.
  Before that delegation the same row read 1.99× (two times slower than the
  library call it could have been written as).
- **HTTP round trips are linear in the body for both stacks, with similar
  constants**: 0.76 against 0.70 ns/B and +41.6 µs against +19.9 µs fixed, with
  our fit at R² = 0.9995 and the reference's at 0.9880. The paired rows split by
  size — 0.91× at 1 KiB, 0.93× at 16 KiB, 1.72× at 256 KiB, 1.09× at 1 MiB —
  and the 256 KiB point is the noisiest of the run, which is why the fit and the
  pairs are both published instead of one number. Space is the clearer
  difference: 2.00 against 2.52 B per body byte.
- **Header scaling is near parity with less allocation**: 752 against 671 ns per
  added 64-byte request header (paired rows 0.96× at 4 headers, 0.93× at 16,
  1.02× at 64) while allocating 884 against 1 168 B per header. Both families of
  rows are `fixed-cost dominated`-adjacent by construction: a 40 µs round trip
  needs many headers before the per-header term changes the total.
- **The reusable DEFLATE context pays twice.** Same payloads, same machine:
  reused 0.559 ns/B and **zero** allocation per message, fresh (a new match
  finder per message) 1.407 ns/B and 4.09 B/B — the “allocate and clear the
  tables per message” cost the module README describes, now measured. Paired:
  4.34× at 1 KiB, 2.16× at 64 KiB, 2.61× at 1 MiB on compressible text, and
  1.16× … 1.46× on incompressible bytes where the match search, not the
  allocation, dominates.
- **Inflating a message allocates a small constant, not a fraction of the
  message**: 29 B per message regardless of size, where the same row read
  4 125 B per message before the Huffman decode tables and the code-length
  array stopped being `Vec`s. That is the space-complexity benchmark doing its
  job: it found an allocation per message on the receive path, and the fix is a
  fixed 2 KiB array in the frame instead of a malloc.

## Space per connection

Delta between 1 and 65 idle keep-alive connections, each after a real request
(same run):

| implementation | model | live KiB/conn | RSS KiB/conn |
|---|---|---:|---:|
| `courierust_event` | event-driven scheduler (default) | **9.7** | **9.1** |
| `courierust_blocking` | legacy one-pool-job-per-connection | 32.6 | 19.8 |
| `hyper_tokio` | hyper + multi-thread tokio | 19.1 | 11.1 |

Three honest observations:

- The **event-driven** server is the cheapest per idle connection in live bytes
  (a poller slot plus fixed, capped buffers — the measured consequence of
  “an idle connection costs a poller slot, not a worker”).
- The **blocking** driver pays for the worker thread that holds the connection
  (32.6 KiB/conn live, 19.8 KiB/conn RSS in this run) — the reason
  `event_driven: false` is documented as a comparison model, not a production
  default.
- **hyper + tokio** keeps a larger *live* figure with a comparable RSS: the
  runtime's thread stacks and pools are allocated once, outside the
  per-connection delta, and the connection state itself is allocated per
  connection. The delta method deliberately measures the marginal cost, which is
  what a deployment scales.

## Algorithmic classes of the hot paths

The fitted rows above cover what can be measured end to end; the rest of the
stack is listed here with the reason its class holds. These are the claims the
code is written to, and each is either exercised by a unit test or bounded by a
configuration limit.

| component | operation | class | why |
|---|---|---|---|
| `courierust_ws` frame | header parse/serialise | O(1) | a header is at most 14 bytes; lengths use minimal-length encodings |
| `courierust_ws` frame | encode / decode | O(n) | one pass over the payload; masking XORs 16-byte lanes plus a `u32` tail |
| `courierust_ws` | UTF-8 validation | O(n) | one pass; the bulk scan is `str::from_utf8` (platform SIMD), the state machine only resumes across frames and names errors |
| `courierust_ws` session | fragment reassembly | O(total bytes) | each fragment appended once, bounded by `max_fragments` / `max_message` |
| `courierust_ws` session | close handshake | O(1) | one frame and one connection-wide shared flag |
| `courierust_ws` session | permessage-deflate | O(n · chain cap) = O(n) | hash-chain search capped at 64 links, so linear with a data-dependent constant; incompressible messages are stored with RSV1 clear |
| `courierust_deflate` | inflate | O(n) | one bit-stream pass; output capped by `max_out` (decompression-bomb guard); decode tables and code-length arrays are fixed arrays, so a message costs a 29 B constant instead of a per-message allocation |
| `courierust_hpack` | Huffman decode | O(bits) | two-level 8-bit table steps, no bit-by-bit backtracking |
| `courierust_hpack` | index lookup / insert | O(1) average | hash-accelerated static and dynamic tables; eviction is O(1) amortised |
| `courierust_h2` | frame codec | O(n) | payload copy only; control frames are O(1) |
| `courierust_h2` | stream state machine | O(1) per frame | fixed transitions; illegal ones fail the stream |
| `courierust_h2` | RFC 9218 scheduling (WUCS) | O(1) per frame | fixed 8-bucket scan, no sorting or heap |
| `courierust_h2` | flow control (BCR) | O(1) amortised | credit accumulates; one `WINDOW_UPDATE` per batch |
| `courierust_quic` / `courierust_h3` | varints, packet/frame codecs | O(n) | single pass; header protection is O(1) |
| `courierust_net` poller | register / unregister / rebuild | O(1) amortised / O(live) | `swap_remove` plus an index map; the wait-set rebuild is a recovery path, not steady state |
| `courierust_server` reactor | one poll iteration | O(k log k), k = ready sockets | level-triggered wait, then sort + dedup of the ready list before batching |
| `courierust_client` pool | h2 connection selection | O(connections) | weighted-load scan; deliberate, and bounded by `max_connections_per_host` |
| `courierust_server` | per-connection space | O(1) bounded | one read buffer and one bounded send queue per connection (measured by the `connections` family) |

## Reading this honestly

- These are loopback numbers on one machine. They measure the *implementation*,
  not a network path; the `network` bench exists for the cross-host question.
- Fitted exponents describe the measured range. A `O(n)` fit over 64 B … 1 MiB
  says nothing about 1 GiB, and cache effects at the top of the range can push a
  local exponent above 1 (visible in the reference rows).
- The space counters attribute *allocations*, not bytes touched. A large reused
  buffer costs nothing per operation but is still memory; that is what the
  per-connection table is for.
- A row is evidence only for the implementation, size and run it came from.
  Compare within one report, never across machines.
- The `http` family's paired rows split by size in this run (faster at 1 KiB and
  16 KiB, slower at 256 KiB and 1 MiB). That is published rather than averaged
  away: the 256 KiB row is the noisiest of the suite, and a read-buffer-size
  difference between the two stacks is a plausible cause worth chasing — the
  honest state is "same order, not yet a win at every size".
