# Benchmarks

The repository ships a **zero-dependency** benchmark harness (`benches/throughput.rs`) — no criterion, consistent with the crate's no-third-party-deps rule. It measures the things the crate actually claims: keep-alive round-trips, multi-core scaling, HTTP/2 multiplexing, and RFC 9218 priority behavior.

## Run it

```bash
cargo bench --bench throughput
```

This builds with the `bench` profile (`lto = "thin"`, `codegen-units = 1`) and prints, per case:

```
h1_sequential:            22882 req/s (total=0.874s, n=20000, workers=1)
h1_concurrent:            71902 req/s (total=0.223s, n=16000, workers=8)
h2_multiplex:             35892 req/s (total=0.178s, n=6400, workers=32)
h2_priority_high_latency: 1.18 ms (high-urgency completion, workers=64)
```

The GitHub Actions `benchmark.yml` workflow runs the same command on push to `main` (when `src/`, `benches/`, or `Cargo.toml` change) and on manual dispatch, and posts the numbers to the run summary.

## What each case measures

| Case | Setup | What it tells you |
|---|---|---|
| `h1_sequential` | 20,000 GETs, one client, one keep-alive connection | raw round-trip latency of the HTTP/1.1 codec |
| `h1_concurrent` | 8 threads × 2,000 GETs, one client per thread | multi-core scaling; per-worker pool shards avoid lock contention |
| `h2_multiplex` | 32 threads × 200 GETs over the shared (≤4) h2 connections | HTTP/2 multiplexing throughput with interleaved streams |
| `h2_priority_high_latency` | 64 low-urgency requests in flight, then one urgency-0 request | WUCS anti-starvation: how fast the high-urgency stream completes |

## Reading the numbers

- `h1_concurrent` should scale with core count; if it does not, the bottleneck is usually the client or server side locks, not the wire codec.
- `h2_multiplex` throughput with 32 interleaved streams is expected to be **below** `h1_concurrent` on loopback: each stream carries framing overhead and the scheduler round-robins between them. The interesting number is that it stays high and does not collapse under load.
- `h2_priority_high_latency` is the latency of a single urgency-0 request launched *behind* a pile of low-urgency work. Sub-millisecond to low-millisecond is healthy; if it climbs into the tens of milliseconds, the scheduler is starving the high-urgency bucket (RFC 9218 §10 violation).

## Notes

- Numbers are loopback-only and depend on the runner's core count, OS, and clock — treat them as **relative** measurements for your machine, not absolute spec claims.
- The harness panics on any request error, so a red run means a real protocol bug, not a slow machine.
- On Windows, `cargo bench` prints results to stderr; `2>&1` captures them in CI.
