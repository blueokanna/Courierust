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
| `https_h2_sequential` | TLS 1.3 plus HTTP/2 | Certificate verification, ALPN, and encrypted request/response path |

Each result records RPS, response throughput, P50/P75/P90/P95/P99 request latency, and the actual server thread count. `BENCH_REQUESTS` and `BENCH_SERVER_THREADS` can override the default request count and server worker count. HTTP/1.1 parallel cases raise the effective server thread count to at least the client worker count because the Linux blocking server model reserves one worker per idle keep-alive connection.

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
