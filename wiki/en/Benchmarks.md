# Benchmarks

The repository ships two benchmark harnesses in the `benches/` sub-crate (`courierust_benchmark`):

- `throughput` — zero-dependency self-measurement: keep-alive round-trips, multi-core scaling, HTTP/2 multiplexing, RFC 9218 priority behavior.
- `compare` — cross-library comparison against the mainstream stack (**hyper**, **reqwest**, **tiny_http**) with a process-wide counting allocator so allocation counts are comparable too.

## Run it

```bash
cargo bench --manifest-path benches/Cargo.toml --bench throughput
cargo bench --manifest-path benches/Cargo.toml --bench compare
```

Builds use the `bench` profile (`lto = "thin"`, `codegen-units = 1`). The GitHub Actions `benchmark.yml` runs both on push to `main`, pull requests, and manual dispatch. It posts the full report to the run summary and uploads `Github_Action_Benchmark.md` (plus the raw logs) as the `Github_Action_Benchmark` artifact.

`Github_Action_Benchmark.md` in the repository is a locally generated example in the same format used by the workflow.

## Self-measurement (`throughput`)

```
h1_sequential:            22882 req/s (total=0.874s, n=20000, workers=1)
h1_concurrent:            71902 req/s (total=0.223s, n=16000, workers=8)
h2_multiplex:             35892 req/s (total=0.178s, n=6400, workers=32)
h2_priority_high_latency: 1.18 ms (high-urgency completion, workers=64)
```

| Case | Setup | What it tells you |
|---|---|---|
| `h1_sequential` | 20,000 GETs, one client, one keep-alive connection | raw round-trip latency of the HTTP/1.1 codec |
| `h1_concurrent` | 8 threads × 2,000 GETs, one client per thread | multi-core scaling; per-worker pool shards avoid lock contention |
| `h2_multiplex` | 32 threads × 200 GETs over the shared (≤4) h2 connections | HTTP/2 multiplexing throughput with interleaved streams |
| `h2_priority_high_latency` | 64 low-urgency requests in flight, then one urgency-0 request | WUCS anti-starvation: how fast the high-urgency stream completes |

## Cross-library comparison (`compare`)

Sequential keep-alive round-trips on loopback, 2,000 requests per case, one client. The `raw_tcp_floor` row is a raw socket write+read with **no HTTP at all** — it is the platform's syscall floor and the ceiling any HTTP stack can reach on that machine. Sample run (Windows, 2026-08; the box was under load, so absolute numbers are depressed — the ratios are what matter):

```
raw_tcp_floor:                                    ~12,000 req/s   (platform floor)
h1 courierust client + courierust server:         9,190 req/s   47 allocs/req
h1 courierust client + tiny_http server:          6,854 req/s   64 allocs/req
h1 courierust client + hyper server:              8,952 req/s   32 allocs/req
h1 reqwest client + courierust server:            3,953 req/s   73 allocs/req
h1 reqwest client + tiny_http server:             4,488 req/s   88 allocs/req
h2 courierust client (h2c):                       5,263 req/s   73 allocs/req
h2 courierust client + hyper server (h2c):        3,747 req/s   59 allocs/req
h2 reqwest client (h2c):                          2,886 req/s  100 allocs/req
```

Readings:

- **Courierust is at the syscall floor.** Its full h1 stack runs at ~76% of the raw TCP floor; the mainstream stack (reqwest + tiny_http) runs at ~37%. The gap between an HTTP stack and `raw_tcp_floor` is the headroom left in the wire codec — Courierust has very little left to give on this platform.
- **Server-side**: Courierust, hyper, and tiny_http are all within ~35% of each other (all bounded by the floor); the differentiator is the client and the allocation count.
- **Client-side**: Courierust's h1 client is ~2.3× faster than reqwest's against the same server; its h2 client is ~1.8× faster than reqwest's h2c client.
- **Allocations**: 47 per request for the Courierust full stack vs 88 for reqwest + tiny_http. The `Scratch` (connection-scoped buffer recycling) and the reused h2 frame buffer are what keep this low.

## Reading the numbers

- `h1_concurrent` should scale with core count; if it does not, the bottleneck is usually client/server locks, not the wire codec.
- `h2_multiplex` below `h1_concurrent` on loopback is expected: framing overhead plus scheduler round-robining. The interesting property is that it stays high and does not collapse under load.
- `h2_priority_high_latency` is the latency of one urgency-0 request launched *behind* a pile of low-urgency work. Sub-millisecond to low-millisecond is healthy; tens of milliseconds means the scheduler is starving the high-urgency bucket (RFC 9218 §10 violation).

## Notes

- Loopback numbers depend on the runner's core count, OS, and clock — treat them as **relative** measurements.
- The harness panics on any request error, so a red run means a real protocol bug, not a slow machine.
- On Windows, benchmark output goes to stderr; `2>&1` captures it in CI.
- The `compare` harness uses a process-wide counting allocator, so `allocs/req` counts everything the process allocates (harness included) — apples-to-apples across libraries.
