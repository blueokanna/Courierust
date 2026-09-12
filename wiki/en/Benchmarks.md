# Benchmarks

The `benches/` workspace provides release-profile executables:

- `throughput`: Courierust HTTP/1.1 keep-alive, parallel HTTP/1.1, h2c multiplexing, and HTTPS plus HTTP/2.
- `compare`: paired loopback comparisons with hyper and reqwest.
- `concurrency`: incomplete-header and slow-sender connection pressure against the server scheduler.
- `network`: an explicit cross-machine client/server endpoint; it never labels loopback as remote evidence.
- `interop`: protocol correctness checks against hyper, hyper-util, and reqwest. It is a validation suite, not a performance benchmark.

Run the same suites used by GitHub Actions:

```bash
cargo bench --manifest-path benches/Cargo.toml --locked --bench throughput
cargo bench --manifest-path benches/Cargo.toml --locked --bench compare
cargo bench --manifest-path benches/Cargo.toml --locked --bench concurrency
cargo bench --manifest-path benches/Cargo.toml --locked --bench interop
```

The benchmark profile uses thin LTO and one code-generation unit. Each suite exits non-zero on a protocol or assertion failure. GitHub Actions captures a separate log for every suite, publishes a structured report to the run summary, and uploads the report and raw logs as an artifact.

## Throughput

`throughput` measures complete request/response round trips on loopback. Every request verifies status and consumes the entire response body before it is counted. It covers empty, 1 KiB, and 64 KiB responses where applicable.

| Case family | Transport | Workload |
| --- | --- | --- |
| `h1_sequential` | HTTP/1.1 | One keep-alive client connection |
| `h1_parallel_w*` | HTTP/1.1 | Independent clients at 1, 4, and 8 workers |
| `h2_multiplex_w*` | h2c prior knowledge | One pooled HTTP/2 connection at 1, 8, and 32 workers |
| `https_h2_sequential` | TLS 1.2/1.3 plus HTTP/2 | Certificate verification, ALPN, and encrypted request/response path |

Each result records RPS, response throughput, P50/P75/P90/P95/P99 request latency, and the actual server thread count. `BENCH_REQUESTS` and `BENCH_SERVER_THREADS` can override the default request count and server worker count. HTTP/1.1 parallel cases raise the effective server thread count to at least the client worker count because the Linux blocking server model reserves one worker per idle keep-alive connection.

## HTTP/3 (`h3` bench)

The `h3` bench (`cargo bench --manifest-path benches/Cargo.toml --bench h3`) measures the pooled HTTP/3 path: a cold connect, warm sequential requests, a 64 KiB upload, a 64 KiB response download, and parallel workers over one QUIC connection. `BENCH_REQUESTS`, `H3_WORKERS`, `BENCH_BODY_BYTES`, and `BENCH_RESPONSE_BYTES` tune the load; `H3_SCENARIOS=1` runs the full body-size × direction × worker matrix and `H3_SWEEP=1` sweeps workers × ACK-delay × cwnd in child processes.

The reactor's latency model is deadline-driven, not cadence-driven. The poll timeout is `max(0, next protocol deadline − now)` — the earliest pending ACK batch, loss/PTO timer, path validation, or request timeout — and the first ack-eliciting packet of every burst is acknowledged immediately (later packets coalesce into that ACK). A fixed poll tick used to gate every cwnd-limited round: each ACK waited a full `ack_delay()` plus the next poll wake, which put a multi-millisecond step into the latency tail on loopback. With immediate ACKs and deadline-folded polls, `h3_sequential` is p50 ~115 µs / max ~0.2 ms, `h3_parallel`×4 is p50 ~180 µs / p99 ~0.35 ms, and a 64 KiB upload is p50 ~1.15 ms. The `h3_ack_deferred` / `h3_credit_stalls` counters in `courierust_net::Stats` distinguish a flow paced by the ACK batch window from one paced by the congestion window.

`COURIERUST_H3_ACK_DELAY_MS`, `COURIERUST_H3_MIN_ACK_DELAY_MS`, `COURIERUST_H3_CWND`, `COURIERUST_H3_SERVER_POLL_MS`, and `COURIERUST_H3_CLIENT_*_POLL_MS` override the corresponding knobs. `COURIERUST_H3_TRACE` enables a per-packet event stream (slow under load — don't leave it on for timing), and `COURIERUST_H3_TRACE_MS` enables only the per-request phase split (`total_us|send_us|wait_headers_us|recv_body_us`) so a slow path is attributable to a phase without the per-packet overhead.

Loopback H3 numbers are one-runner evidence: they depend on CPU allocation, kernel scheduling, and background load. The `network` bench is the cross-host measurement, and it is reported `not_configured` when no `COURIERUST_NETWORK_URL` is supplied — never invented.

## WebSocket (`ws` bench)

The `ws` bench (`cargo bench --manifest-path benches/Cargo.toml --bench ws`) measures the WebSocket path in three layers, and compares the first two against `tungstenite 0.30` and `tokio-tungstenite 0.30` **in the same process, same build profile, same run** (comparing rows across runs on a loaded machine is meaningless — the document says so explicitly):

- **codec**: encode, mask, decode and UTF-8 validation over a range of payload sizes;
- **echo round trip**: client-masked request → server-unmasked response, so both ends of this crate and the reference implementations are measured on the same socket pair;
- **one-way push**: a server pushing a stream of messages to a client that only reads (the fan-out shape), which is where the bounded send queue and the reactor wakeup path show up.

The engine decisions this measures (16-byte-lane masking, zero-copy reads above 8 KiB, a reusable DEFLATE context, one write per small frame) are written up next to the numbers, together with the rows this crate **loses** — 256 KiB messages between two ends of this crate are slower than tungstenite's pairing, and the localised cause (plus the Windows socket-deadline finding behind it) is in `benches/WS_BENCHMARK.md`. `WS_BENCH_SECTION=echo|push|codec` runs one layer only.

## Complexity (time and space)

`cargo bench --manifest-path benches/Cargo.toml --bench complexity` measures how
cost *grows*, not just how fast something is. Every family is sampled at several
sizes spanning three orders of magnitude — each point is the minimum of three
repeats, because noise only ever makes a measurement slower — and two models are
fitted: the affine model `cost = a + b·n` (a fixed per-operation term plus a
per-unit term, with R²) and the adjacent-size-pair exponents, whose *median*
names the reported class while the worst pair is printed next to it so a single
noisy pair cannot pass as a trend. Space is attributed per operation by a
counting allocator compiled into the bench binary, and per connection by a
live-bytes/RSS delta between 1 and 65 idle keep-alive connections.

| family | scales | compared against |
|---|---|---|
| `codec` | WebSocket frame encode / mask / decode / UTF-8, 64 B → 1 MiB | `tungstenite` |
| `http` | one GET round trip, 1 KiB → 1 MiB | `reqwest` (hyper) |
| `headers` | request header count, 4 → 64 | `reqwest` (hyper) |
| `connections` | space of one idle keep-alive connection | blocking driver, hyper + tokio |
| `deflate` | permessage-deflate encode (reused vs fresh context) and inflate | no fair third-party peer in this workspace |

Method, a sample run, per-connection memory and the algorithmic class of every
hot path: `benches/COMPLEXITY.md`. The CI report carries the current numbers.

## Cross-library comparison

`compare` keeps the peer fixed while measuring one implementation at a time:

- Client comparison: Courierust and reqwest clients use the same hyper server.
- Server comparison: the same reqwest client is used against Courierust and hyper servers.
- Protocols: HTTP/1.1 and h2c prior knowledge.
- Payloads: 1 KiB and 64 KiB sequential responses, plus an 8-worker 1 KiB client-load case.
- Each measurement consumes and validates the complete response body.

Every configuration is repeated an even number of times. The execution order alternates on each round so neither side is always measured first. The emitted result combines all rounds and contains the actual repetition count. Set `BENCH_REPETITIONS`, `BENCH_REQUESTS`, `BENCH_PARALLEL_REQUESTS`, and `BENCH_COMPARE_WORKERS` to tune the load. Odd repetition settings are rounded up to the next even value to preserve balanced ordering.

The `raw_tcp_floor` row is only a transport reference for a four-byte echo. It is not an HTTP comparison row and must not be used to claim a percentage of HTTP performance. The harness intentionally does not publish process-wide allocation counts because server threads, runtimes, logging, and the harness itself make that number non-attributable to one client or server implementation.

The large-body h2c comparison uses async Reqwest with a shared Tokio runtime and
fully consumes the request and response bodies. The old blocking Reqwest
measurement showed a fixed approximately 41 ms wait against both peers; that
harness anomaly is retained only in historical reports and is not performance
evidence. The h2c client rows are workload-specific: a single worker does not
establish universal leadership, and an 8-worker result must be read together
with the connection policy and tail latency.

`network` requires two separately operated hosts. Start the server with `COURIERUST_NETWORK_ROLE=server` and `COURIERUST_NETWORK_BIND=0.0.0.0:8080`, then set the client's `COURIERUST_NETWORK_URL` to that host. Use `COURIERUST_NETWORK_TLS=true` plus DER certificate/key paths for HTTPS. The generated report marks the case `not_configured` when no remote URL is supplied; no cross-machine number is invented.

`concurrency` records incomplete HTTP/1.1 headers and slow senders. It reports the platform and whether the Windows event-driven path was enabled, so a Linux blocking-pool result is not presented as Windows event-loop evidence.

## Reading Results

Results are emitted as `RESULT|...` records for machine parsing and include protocol, payload, client workers, server threads, request count, RPS, response MB/s, percentile latency, and sample count. Compare only rows with the same protocol, payload, worker count, server thread count, and layer. Loopback measurements are sensitive to runner CPU allocation, kernel scheduling, and background load; use them for controlled comparisons on the same runner, not as universal performance claims.

`interop` emits `INTEROP|...` records. A failure or timeout is a compatibility regression and fails CI regardless of performance numbers.

The workflow also runs the `h2_frame` and `hpack_block` `cargo-fuzz` targets. The generated `Github_Action_Benchmark.md` is committed to the repository on successful main-branch pushes and is available from the repository itself, not only from the Actions summary or artifact.
