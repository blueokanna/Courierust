# Protocol Benchmark Evidence

Generated from the supplied benchmark logs; see suite status and environment provenance.

## Run

- Commit: 6f1cb5276d61411ef78dc8130b111f81ba55e17e
- Ref: main
- Runner: Linux
- Throughput exit code: 0
- Comparison exit code: 0
- Concurrency exit code: 0
- Interop exit code: 0
- HTTP/3 exit code: 0
- Complexity exit code: 0
- Cross-machine exit code: not-configured
- Fuzz exit code: 0
- gRPC comparison exit code: 0
- TLS comparison exit code: 0
- WebSocket comparison exit code: 0
- Workflow run: [42374379772](https://github.com/blueokanna/Courierust/actions/runs/42374379772)

## Evidence Rules

- gRPC, TLS and WebSocket tables retain every repetition. Compare rows only with the same protocol, workload, security settings and one unchanged peer. No aggregate winner is computed.
- Latencies use the nearest-rank estimator. Fewer than 1000 samples makes P99 exploratory; even a larger sample is not an SLA or a confidence interval. Closed-loop traffic does not measure overload or correct coordinated omission.
- gRPC uses the same generated protobuf codec on both sides, four messages per streaming RPC, one connection, identity compression and verified final status. This finite-stream workload does not prove interactive full-duplex behavior or bounded memory under backpressure.
- TLS comparison rows pin AES-128-GCM, certificate verification, ALPN and key exchange (P-256 for TLS 1.2, X25519 for TLS 1.3). Full-handshake rows include TCP connection setup and disable resumption; record rows use a pre-established connection.
- WebSocket comparison rows use one persistent connection, binary echo, TCP_NODELAY, no compression and full payload checks. Async-client rows include the synchronous caller runtime-entry cost. Codec and raw-TCP diagnostic rows are not WebSocket end-to-end baselines.
- Rows marked `invalid`, `diagnostic` or `not_available` are retained for auditability and excluded from speed ratios.
- The `*_h2c_large_body_to_hyper` rows diagnose a 1 MiB POST against the same hyper h2 server. Flow-control window updates affect both clients. Consult the current timings; no fixed latency is assumed. These diagnostic rows are excluded from speed ratios.
- The current `quinn_h3_client_to_courierust` row determines interop status: `valid` means handshake and full response validation succeeded; `not_available` preserves the actual failure reason. No historical failure is assumed to persist.
- Loopback is not cross-machine evidence. The cross-machine table is evidence only when `target_scope=remote` and `status=ok`.
- TLS rows measure the built-in TLS 1.2/1.3 path; certificate, hostname, and ALPN checks must pass for the case to be valid. `negotiated_alpn` is reported; `session_resumption=n/a` because each TLSVERIFY row is a single handshake that does not measure resumption (the stack does implement TLS 1.3 session tickets).
- Fuzz status is evidence only for the recorded target, run count, and duration; an unconfigured target is not a pass.
- `STATS` belongs to the attached client/server instance and includes its lifetime before the snapshot, including warmup. H1/H2 read/write fields count transport API calls, not necessarily OS syscalls when TLS is present. Event poll/wake counters cover the server event loop, not the dedicated H2 driver threads; H3 UDP counters cover their own transport. Relaxed counter snapshots are not atomic across fields.
- Complexity classes are empirical fits over the measured sizes, not proofs of asymptotic complexity. The paired ratio is only meaningful within one run; missing complexity logs mean this run has no complexity evidence.

## Reading the numbers (correct interpretation)

- Change one implementation at a time: compare clients against the same server, or servers with the same client. Keep protocol, payload, concurrency and security policy fixed. Do not compute ratios across protocols.
- Pool limits have different meanings: reqwest pool_max_idle_per_host caps idle connections; Courierust max_connections_per_host caps active connections. Equal numeric limits do not make concurrent connection policies equivalent. Runtime and pool costs are included; this report does not attribute them without profiling.
- Large H3 tail ratios warrant repeat measurements and profiling. Reactor scheduling, packet queues, congestion control and runner load are possible causes; a single run cannot identify the cause or establish a general H3-versus-H2 ranking.
- The H1 server is built for event-driven protection (incomplete headers, idle keep-alive, slow senders); hyper is a mature async architecture. A short-request microbenchmark cannot dismiss the scheduling value — the concurrency/slow-connection rows measure production usability and resource isolation.
- H3 connection reuse plus cross-implementation interop (quinn+h3 → Courierust server) is stronger evidence than Courierust-to-Courierust.

## Throughput

| Case | Protocol | Mode | Payload | Workers | Server threads | Requests | RPS | Resp MB/s | P50 us | P75 us | P90 us | P95 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| h1_sequential | h1 | sequential | empty | 1 | 4 | 4000 | 29103.3 | 0.000 | 33.62 | 35.05 | 36.46 | 38.80 | 45.69 | 27.37 | 33.86 | 63.43 | 3.11 | 51.64 | 1.36 | 2000 |
| h1_sequential | h1 | sequential | 1k | 1 | 4 | 4000 | 29390.7 | 30.096 | 33.17 | 34.67 | 35.99 | 38.77 | 45.87 | 27.40 | 33.93 | 107.87 | 3.56 | 58.59 | 1.38 | 2000 |
| h1_sequential | h1 | sequential | 64k | 1 | 4 | 4000 | 22954.8 | 1504.368 | 42.86 | 44.62 | 48.60 | 50.29 | 55.44 | 38.83 | 43.28 | 71.86 | 3.72 | 60.85 | 1.29 | 2000 |
| h1_parallel_w1 | h1 | parallel | 1k | 1 | 4 | 4000 | 28818.2 | 29.510 | 35.19 | 36.41 | 38.42 | 40.57 | 47.35 | 25.75 | 35.31 | 61.17 | 3.23 | 55.58 | 1.35 | 2000 |
| h1_parallel_w4 | h1 | parallel | 1k | 4 | 4 | 4000 | 75177.6 | 76.982 | 37.53 | 52.66 | 77.77 | 94.48 | 243.54 | 17.74 | 47.10 | 939.31 | 51.56 | 769.02 | 6.49 | 2000 |
| h1_parallel_w8 | h1 | parallel | 1k | 8 | 8 | 4000 | 77895.1 | 79.765 | 65.30 | 107.19 | 144.74 | 184.31 | 471.47 | 17.86 | 87.95 | 3128.87 | 149.75 | 2499.46 | 7.22 | 2000 |
| h2_multiplex_w1 | h2c | multiplex | 1k | 1 | 4 | 4000 | 22951.9 | 23.503 | 42.00 | 44.10 | 49.77 | 51.24 | 58.17 | 33.39 | 43.73 | 401.21 | 13.39 | 315.75 | 1.38 | 2000 |
| h2_multiplex_w8 | h2c | multiplex | 1k | 8 | 4 | 4000 | 68514.9 | 70.159 | 104.31 | 122.63 | 146.22 | 166.31 | 534.02 | 40.19 | 114.98 | 1033.61 | 73.81 | 803.91 | 5.12 | 2000 |
| h2_multiplex_w32 | h2c | multiplex | 1k | 32 | 4 | 4000 | 67599.2 | 69.222 | 375.68 | 607.71 | 735.20 | 833.11 | 1538.68 | 45.78 | 451.11 | 2773.57 | 276.97 | 2766.26 | 4.10 | 2016 |
| h2_multiplex_w1 | h2c | multiplex | 64k | 1 | 4 | 4000 | 13612.4 | 892.104 | 71.03 | 72.40 | 76.22 | 82.65 | 140.16 | 62.95 | 73.19 | 589.24 | 29.65 | 481.99 | 1.97 | 2000 |
| h2_multiplex_w8 | h2c | multiplex | 64k | 8 | 4 | 4000 | 23446.4 | 1536.581 | 327.67 | 369.94 | 441.96 | 532.09 | 930.65 | 69.73 | 341.22 | 2087.18 | 133.73 | 1338.41 | 2.84 | 2000 |
| h2_multiplex_w32 | h2c | multiplex | 64k | 32 | 4 | 4000 | 36544.7 | 2394.993 | 857.18 | 938.45 | 1027.36 | 1132.58 | 2075.11 | 124.19 | 868.77 | 2418.32 | 221.05 | 2382.70 | 2.42 | 2016 |
| https_h2_sequential | https+h2 | sequential | empty | 1 | 4 | 2000 | 24314.2 | 0.000 | 40.89 | 42.06 | 43.54 | 45.69 | 52.75 | 32.63 | 41.10 | 69.92 | 2.91 | 58.63 | 1.29 | 2000 |
| https_h2_sequential | https+h2 | sequential | 1k | 1 | 4 | 2000 | 20907.6 | 21.409 | 45.77 | 49.19 | 53.43 | 56.33 | 64.68 | 41.64 | 47.80 | 242.53 | 6.57 | 83.52 | 1.41 | 2000 |
| https_h2_sequential | https+h2 | sequential | 64k | 1 | 4 | 2000 | 3486.9 | 228.517 | 273.83 | 283.91 | 298.64 | 320.56 | 627.81 | 261.55 | 286.76 | 1058.83 | 60.32 | 956.51 | 2.29 | 2000 |

## TLS Verification Evidence

| Protocol | Cert verified | Hostname verified | Negotiated ALPN | Session resumption | Cipher suite | Error |
| --- | --- | --- | --- | --- | --- | --- |
| https+h2 | true | true | h2 | n/a | 0x1303 | - |
| https+h2 | true | true | h2 | n/a | 0x1303 | - |
| https+h2 | true | true | h2 | n/a | 0x1303 | - |
| https+h2 | false | not_evaluated | none | n/a | - | Io: TLS certificate error: no trusted root found |
| https+h1 | true | false | none | n/a | - | TLS certificate error: hostname mismatch |
| https+h1 | true | true | http/1.1 | n/a | - | - |
| https+h2 | not_evaluated | not_evaluated | none | n/a | - | Protocol: server did not negotiate any ALPN protocol; HTTP/2 over TLS requires ALPN h2 |

## Cross-Library Comparison

| Case | Layer | Protocol | Client | Server | Payload | Workers | Server threads | Pool policy | Pool value | Reps | Status | Reason | Requests | RPS | Resp MB/s | P50 us | P75 us | P90 us | P95 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| raw_tcp_floor | transport | h1 | std_tcp | std_tcp | 4b | 1 | 1 | raw_tcp | 1 | 1 | valid | - | 2000 | 44007.5 | 0.176 | 22.80 | 23.41 | 23.92 | 25.34 | 33.05 | 19.96 | 22.69 | 41.31 | 2.21 | 37.79 | 1.45 | 2000 |
| courierust_client_to_hyper | client | h1 | courierust | hyper | 1k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 38871.2 | 39.804 | 25.27 | 25.69 | 26.79 | 27.55 | 36.45 | 19.02 | 25.69 | 91.76 | 2.23 | 41.23 | 1.44 | 4000 |
| reqwest_client_to_hyper | client | h1 | reqwest | hyper | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 19619.2 | 20.090 | 46.91 | 48.33 | 50.94 | 57.16 | 238.41 | 39.54 | 50.93 | 660.69 | 34.93 | 461.10 | 5.08 | 4000 |
| reqwest_client_to_courierust | server | h1 | reqwest | courierust | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 16056.3 | 16.442 | 60.23 | 62.97 | 66.91 | 72.07 | 81.91 | 52.74 | 62.24 | 586.10 | 18.64 | 466.28 | 1.36 | 4000 |
| reqwest_client_to_hyper | server | h1 | reqwest | hyper | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 21154.7 | 21.662 | 47.13 | 48.37 | 49.98 | 53.47 | 61.38 | 41.62 | 47.24 | 213.87 | 4.48 | 71.78 | 1.30 | 4000 |
| courierust_client_to_hyper | client | h1 | courierust | hyper | 1k | 8 | 4 | courierust_max_connections_per_host | 8 | 2 | valid | - | 4000 | 124348.7 | 127.333 | 54.10 | 77.78 | 91.07 | 101.07 | 166.24 | 18.33 | 60.76 | 1516.34 | 52.34 | 751.09 | 3.07 | 4000 |
| reqwest_client_to_hyper | client | h1 | reqwest | hyper | 1k | 8 | 4 | reqwest_pool_max_idle_per_host | 8 | 2 | valid | - | 4000 | 52920.9 | 54.191 | 150.69 | 160.74 | 172.78 | 193.95 | 260.94 | 43.21 | 148.79 | 581.51 | 37.02 | 532.38 | 1.73 | 4000 |
| courierust_client_to_hyper | client | h1 | courierust | hyper | 64k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 18663.4 | 1223.122 | 52.87 | 53.58 | 56.16 | 59.15 | 66.10 | 48.97 | 53.55 | 114.35 | 3.21 | 83.58 | 1.25 | 4000 |
| reqwest_client_to_hyper | client | h1 | reqwest | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 13338.6 | 874.156 | 74.05 | 76.86 | 82.39 | 84.74 | 94.17 | 65.29 | 74.94 | 153.03 | 5.82 | 120.98 | 1.27 | 4000 |
| reqwest_client_to_courierust | server | h1 | reqwest | courierust | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 10491.6 | 687.575 | 92.48 | 96.46 | 106.52 | 110.57 | 120.92 | 82.63 | 95.27 | 903.66 | 16.34 | 150.28 | 1.31 | 4000 |
| reqwest_client_to_hyper | server | h1 | reqwest | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 13233.3 | 867.259 | 73.21 | 77.79 | 83.52 | 85.85 | 98.87 | 64.36 | 75.54 | 121.77 | 6.08 | 116.25 | 1.35 | 4000 |
| courierust_client_to_hyper | client | h2c | courierust | hyper | 1k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 21051.5 | 21.557 | 46.31 | 48.06 | 52.22 | 55.14 | 63.03 | 38.06 | 47.47 | 189.77 | 4.56 | 75.90 | 1.36 | 4000 |
| reqwest_client_to_hyper | client | h2c | reqwest | hyper | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 18587.4 | 19.033 | 52.73 | 54.68 | 57.17 | 62.71 | 68.72 | 48.55 | 53.77 | 109.75 | 4.00 | 80.08 | 1.30 | 4000 |
| reqwest_client_to_courierust | server | h2c | reqwest | courierust | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 19465.2 | 19.932 | 49.48 | 51.24 | 53.88 | 59.07 | 65.52 | 45.97 | 51.35 | 682.98 | 17.27 | 304.72 | 1.32 | 4000 |
| reqwest_client_to_hyper | server | h2c | reqwest | hyper | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 18792.6 | 19.244 | 51.87 | 53.48 | 56.84 | 61.26 | 68.29 | 47.87 | 53.18 | 528.16 | 8.37 | 80.11 | 1.32 | 4000 |
| courierust_h2_conn1xw32 | client | h2c | courierust | hyper | 1k | 32 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 52530.6 | 53.791 | 497.74 | 658.97 | 952.62 | 1173.84 | 1621.69 | 50.29 | 561.70 | 2902.77 | 304.02 | 2482.03 | 3.26 | 4000 |
| courierust_h2_conn4xw8 | client | h2c | courierust | hyper | 1k | 32 | 4 | courierust_max_connections_per_host | 4 | 2 | valid | - | 4000 | 72660.1 | 74.404 | 363.05 | 506.89 | 678.98 | 830.60 | 1193.96 | 33.26 | 402.93 | 2222.97 | 239.94 | 2129.45 | 3.29 | 4000 |
| courierust_h2_conn8xw4 | client | h2c | courierust | hyper | 1k | 32 | 4 | courierust_max_connections_per_host | 8 | 2 | valid | - | 4000 | 77447.6 | 79.306 | 346.32 | 467.45 | 602.90 | 714.13 | 1161.10 | 37.51 | 375.47 | 2819.40 | 223.70 | 2336.14 | 3.35 | 4000 |
| courierust_client_to_hyper | client | h2c | courierust | hyper | 1k | 8 | 4 | courierust_max_connections_per_host | 8 | 2 | valid | - | 4000 | 61818.5 | 63.302 | 113.36 | 147.91 | 188.65 | 224.44 | 332.83 | 33.87 | 125.19 | 916.99 | 59.98 | 571.09 | 2.94 | 4000 |
| reqwest_client_to_hyper | client | h2c | reqwest | hyper | 1k | 8 | 4 | reqwest_pool_max_idle_per_host | 8 | 2 | valid | - | 4000 | 55205.6 | 56.531 | 138.19 | 169.70 | 204.16 | 226.83 | 283.02 | 37.34 | 142.15 | 454.41 | 48.33 | 398.68 | 2.05 | 4000 |
| courierust_client_to_hyper | client | h2c | courierust | hyper | 64k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 10520.7 | 689.487 | 95.44 | 98.06 | 100.64 | 105.49 | 112.46 | 83.64 | 95.02 | 211.01 | 6.39 | 136.37 | 1.18 | 4000 |
| reqwest_client_to_hyper | client | h2c | reqwest | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 10923.4 | 715.875 | 89.84 | 95.60 | 100.00 | 104.11 | 114.32 | 79.78 | 91.52 | 190.02 | 7.02 | 130.72 | 1.27 | 4000 |
| reqwest_client_to_courierust | server | h2c | reqwest | courierust | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 10906.0 | 714.734 | 90.56 | 93.35 | 98.53 | 103.20 | 109.67 | 76.22 | 91.67 | 168.91 | 5.62 | 127.76 | 1.21 | 4000 |
| reqwest_client_to_hyper | server | h2c | reqwest | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 11056.6 | 724.603 | 88.65 | 93.43 | 97.96 | 102.07 | 110.43 | 76.99 | 90.42 | 620.89 | 13.95 | 140.24 | 1.25 | 4000 |
| courierust_h2c_large_body_to_hyper | client | h2c | courierust | hyper | 64k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | diagnostic | flow_control_workload_not_a_speed_ratio | 64 | 539.5 | 35.359 | 1839.81 | 1872.50 | 1898.43 | 1953.93 | 2529.72 | 1718.61 | 1853.41 | 2529.72 | 98.47 | 2529.72 | 1.37 | 64 |
| reqwest_async_h2c_large_body_to_hyper | client | h2c | reqwest-async | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | diagnostic | flow_control_workload_not_a_speed_ratio | 64 | 693.5 | 45.450 | 1420.05 | 1487.31 | 1521.59 | 1532.49 | 1548.96 | 1350.47 | 1441.91 | 1548.96 | 50.91 | 1548.96 | 1.09 | 64 |
| courierust_h3_client_to_courierust | client | h3 | courierust-h3 | courierust-h3 | 1k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 11163.8 | 11.432 | 89.59 | 99.60 | 105.90 | 110.76 | 119.06 | 55.49 | 89.54 | 154.52 | 13.10 | 131.28 | 1.33 | 4000 |
| quinn_h3_client_to_courierust | client | h3 | quinn+h3 | courierust-h3 | 1k | 1 | 4 | quinn_single_connection | 1 | 2 | valid | - | 4000 | 9406.6 | 9.632 | 103.56 | 106.88 | 111.93 | 118.01 | 142.35 | 88.02 | 106.26 | 1277.57 | 39.43 | 739.06 | 1.37 | 4000 |
| courierust_h3_client_to_courierust | client | h3 | courierust-h3 | courierust-h3 | 64k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 1803.1 | 118.170 | 540.38 | 549.64 | 561.02 | 642.75 | 909.01 | 488.64 | 554.56 | 1959.55 | 80.83 | 1593.05 | 1.68 | 4000 |
| quinn_h3_client_to_courierust | client | h3 | quinn+h3 | courierust-h3 | 64k | 1 | 4 | quinn_single_connection | 1 | 2 | valid | - | 4000 | 1654.9 | 108.454 | 635.15 | 662.21 | 674.93 | 681.44 | 693.58 | 472.14 | 604.21 | 2274.55 | 75.66 | 1092.83 | 1.09 | 4000 |

## gRPC: Courierust / tonic

| Protocol | Case | Client | Server | Mode | Bytes/message | Workers | Repeat | Warmup | Completed | RPS | P50 us | P95 us | P99 us | Samples | Tail evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| grpc-h2 | Unary | courierust | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 19502.94 | 50.01 | 58.46 | 66.95 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 13517.43 | 73.75 | 84.56 | 92.95 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 13500.16 | 73.97 | 81.87 | 84.14 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 20105.92 | 48.58 | 55.94 | 63.29 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 19456.23 | 48.64 | 63.44 | 83.15 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 13060.48 | 75.04 | 87.34 | 94.34 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 13139.70 | 75.69 | 83.15 | 90.56 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 19085.06 | 51.08 | 58.92 | 67.24 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 18001.89 | 53.56 | 63.73 | 69.14 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 13152.43 | 76.08 | 81.30 | 92.58 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 13300.44 | 74.59 | 85.19 | 91.92 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 17936.61 | 53.53 | 61.50 | 74.29 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 18139.75 | 53.28 | 60.78 | 74.45 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 11966.18 | 82.20 | 92.84 | 95.41 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 12067.52 | 81.50 | 93.86 | 97.56 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 18051.24 | 52.97 | 64.23 | 72.34 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 8639.36 | 114.89 | 136.83 | 145.06 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 12803.26 | 75.59 | 94.78 | 104.07 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 12864.84 | 76.31 | 86.10 | 97.14 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 9163.00 | 106.99 | 123.53 | 141.12 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 9204.31 | 106.03 | 130.03 | 150.90 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 13334.55 | 74.24 | 88.13 | 102.03 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 13397.58 | 74.52 | 86.28 | 90.19 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 9233.57 | 106.99 | 126.49 | 139.04 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 8612.85 | 112.29 | 138.16 | 163.89 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 14422.05 | 66.36 | 84.81 | 109.41 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 14514.72 | 66.69 | 81.15 | 85.57 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 8725.29 | 113.22 | 131.60 | 142.11 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 8648.12 | 110.84 | 135.21 | 152.31 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 12445.15 | 78.70 | 90.99 | 97.87 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 12774.77 | 77.48 | 87.11 | 90.15 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 8845.57 | 110.54 | 131.86 | 138.99 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 4505.36 | 219.67 | 242.01 | 252.27 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 5475.88 | 184.90 | 198.11 | 203.43 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 5614.90 | 178.27 | 198.52 | 210.12 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 4594.33 | 215.08 | 237.34 | 240.94 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 4562.37 | 218.98 | 238.58 | 257.71 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 6451.87 | 153.42 | 177.93 | 187.51 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 6537.95 | 153.51 | 170.63 | 174.53 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 5605.94 | 199.47 | 232.81 | 236.56 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 2602.31 | 384.23 | 416.23 | 420.25 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 2252.09 | 442.51 | 469.02 | 553.28 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 2226.51 | 445.13 | 476.44 | 551.79 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 2655.47 | 376.67 | 392.57 | 400.72 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 2688.01 | 370.08 | 392.73 | 395.85 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 2232.40 | 443.45 | 499.40 | 563.00 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 2177.96 | 460.60 | 493.37 | 504.70 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 3017.33 | 330.03 | 347.07 | 352.97 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 3473.36 | 280.70 | 354.68 | 372.77 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 3236.21 | 306.00 | 350.14 | 380.58 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 3304.33 | 298.53 | 339.17 | 370.66 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 3825.51 | 262.05 | 348.97 | 360.54 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 3661.35 | 264.66 | 356.14 | 784.03 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 3544.56 | 286.94 | 319.57 | 342.21 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 3978.34 | 251.48 | 275.23 | 288.86 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 3432.14 | 285.85 | 362.91 | 381.91 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 2330.75 | 435.18 | 508.93 | 517.62 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 2688.34 | 359.69 | 460.78 | 520.57 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 2587.53 | 373.53 | 471.18 | 538.96 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 2349.83 | 422.24 | 510.79 | 558.12 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 2349.96 | 424.39 | 510.29 | 549.36 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 2485.80 | 403.47 | 456.78 | 475.72 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 2654.56 | 366.57 | 463.42 | 512.63 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 2354.01 | 414.83 | 523.80 | 544.08 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 9458.19 | 103.00 | 116.80 | 184.28 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 7193.01 | 135.53 | 161.54 | 183.65 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 7200.87 | 136.97 | 164.67 | 173.50 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 9646.45 | 99.76 | 123.11 | 160.75 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 9656.29 | 100.66 | 123.38 | 137.14 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 7106.80 | 136.86 | 170.73 | 187.83 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 7014.19 | 137.56 | 165.84 | 194.47 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 9710.32 | 100.19 | 115.52 | 143.61 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 8922.62 | 108.50 | 137.58 | 153.06 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 6664.90 | 147.36 | 167.43 | 209.85 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 6787.75 | 144.00 | 166.91 | 196.08 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 8703.60 | 111.85 | 134.70 | 157.69 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 8856.60 | 109.06 | 137.19 | 155.69 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 6771.29 | 143.81 | 172.97 | 200.64 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 6970.25 | 140.32 | 164.28 | 171.49 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 8671.68 | 113.11 | 129.16 | 152.48 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 6026.30 | 162.66 | 185.86 | 203.04 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 6738.20 | 146.37 | 172.63 | 196.41 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 6815.79 | 142.95 | 169.26 | 208.28 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 6111.60 | 159.31 | 197.12 | 225.56 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 6467.84 | 150.61 | 188.22 | 211.24 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 6938.56 | 139.61 | 161.33 | 210.21 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 6856.93 | 142.26 | 166.66 | 199.31 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 6470.08 | 150.53 | 182.98 | 224.49 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 6119.14 | 159.42 | 188.24 | 207.75 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 6949.82 | 140.39 | 163.72 | 205.40 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 6924.43 | 142.42 | 167.11 | 190.31 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 4188.98 | 167.35 | 702.89 | 839.95 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 6179.57 | 159.84 | 187.56 | 198.61 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 6743.29 | 143.17 | 174.13 | 193.84 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 6895.67 | 143.20 | 163.18 | 179.29 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 6241.29 | 158.04 | 183.60 | 208.34 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 5903.75 | 164.18 | 202.74 | 241.32 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 5057.33 | 192.62 | 224.08 | 238.94 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 4228.86 | 233.66 | 269.58 | 304.00 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 5218.37 | 188.73 | 223.16 | 255.36 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 4942.95 | 191.55 | 247.66 | 345.90 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 4129.06 | 234.65 | 292.74 | 356.25 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 4115.58 | 236.85 | 294.46 | 316.72 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 5003.64 | 195.41 | 231.08 | 269.23 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 3814.82 | 252.57 | 325.18 | 396.13 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 3656.49 | 267.63 | 315.96 | 325.17 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 3685.50 | 268.72 | 300.14 | 317.45 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 4364.28 | 229.40 | 252.32 | 270.12 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 4305.56 | 230.65 | 257.21 | 288.06 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 3664.03 | 272.28 | 301.53 | 314.88 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 3607.58 | 275.17 | 301.38 | 313.43 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 4203.43 | 236.52 | 270.04 | 282.90 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 1414.15 | 724.99 | 771.90 | 781.70 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 1544.52 | 621.80 | 756.30 | 773.48 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 1529.12 | 624.27 | 767.66 | 774.20 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 1425.98 | 732.94 | 776.11 | 787.82 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 1430.60 | 719.49 | 751.94 | 763.75 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 1534.59 | 619.37 | 759.13 | 767.33 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 1604.61 | 598.06 | 757.75 | 767.12 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 1464.02 | 717.71 | 766.60 | 781.59 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 1349.55 | 775.71 | 837.27 | 844.49 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 1432.23 | 663.77 | 814.07 | 826.22 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 1431.62 | 659.28 | 823.92 | 834.17 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 1305.56 | 764.38 | 795.04 | 843.89 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 1317.43 | 776.82 | 828.26 | 838.65 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 1471.47 | 652.92 | 806.19 | 834.75 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 1438.43 | 658.20 | 810.08 | 839.16 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 1375.35 | 768.24 | 809.49 | 854.05 | 100 | exploratory | ok |

## TLS: Courierust / rustls (aws-lc-rs)

| Protocol | Case | Client | Server | Mode | Bytes/message | Workers | Repeat | Warmup | Completed | RPS | P50 us | P95 us | P99 us | Samples | Tail evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 1 | 4 | 100 | 519.04 | 1695.10 | 2943.70 | 3875.16 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 1 | 4 | 100 | 3570.83 | 279.07 | 298.55 | 306.30 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 2 | 4 | 100 | 3503.93 | 279.56 | 315.16 | 330.49 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 2 | 4 | 100 | 590.82 | 1684.77 | 1739.66 | 1749.24 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 3 | 4 | 100 | 592.73 | 1681.54 | 1727.34 | 1754.58 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 3 | 4 | 100 | 3408.22 | 283.24 | 328.48 | 361.42 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 4 | 4 | 100 | 3310.97 | 301.07 | 325.03 | 328.48 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 4 | 4 | 100 | 588.81 | 1694.25 | 1737.20 | 1753.14 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 1 | 4 | 100 | 31630.57 | 30.76 | 34.97 | 44.86 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 1 | 4 | 100 | 39094.48 | 25.32 | 26.88 | 36.97 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 2 | 4 | 100 | 42929.68 | 23.00 | 24.32 | 27.79 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 2 | 4 | 100 | 31998.32 | 30.67 | 32.75 | 43.62 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 3 | 4 | 100 | 32264.14 | 30.63 | 32.84 | 35.85 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 3 | 4 | 100 | 43002.71 | 22.87 | 24.58 | 33.62 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 4 | 4 | 100 | 42137.77 | 22.84 | 26.81 | 37.07 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 4 | 4 | 100 | 32202.86 | 30.42 | 35.14 | 41.60 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 1 | 4 | 100 | 2737.26 | 363.10 | 377.18 | 382.86 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 1 | 4 | 100 | 15125.93 | 64.88 | 75.28 | 88.92 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 2 | 4 | 100 | 14209.53 | 65.44 | 77.98 | 104.31 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 2 | 4 | 100 | 2733.65 | 363.27 | 374.90 | 382.07 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 3 | 4 | 100 | 2748.53 | 361.07 | 371.18 | 384.04 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 3 | 4 | 100 | 15104.10 | 65.26 | 71.17 | 77.62 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 4 | 4 | 100 | 14939.11 | 65.80 | 79.44 | 80.99 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 4 | 4 | 100 | 2746.51 | 361.85 | 375.79 | 376.73 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | courierust | connect | 0 | 1 | 1 | 4 | 100 | 422.30 | 2365.33 | 2393.85 | 2421.12 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 1 | 4 | 100 | 1021.94 | 974.44 | 1006.49 | 1021.72 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 2 | 4 | 100 | 1003.98 | 990.09 | 1025.61 | 1048.24 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | courierust | connect | 0 | 1 | 2 | 4 | 100 | 401.63 | 2384.42 | 3011.10 | 4870.80 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | courierust | connect | 0 | 1 | 3 | 4 | 100 | 418.24 | 2373.32 | 2458.13 | 2631.97 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 3 | 4 | 100 | 992.50 | 1005.45 | 1042.55 | 1060.13 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 4 | 4 | 100 | 999.36 | 1002.67 | 1021.25 | 1023.38 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | courierust | connect | 0 | 1 | 4 | 4 | 100 | 421.65 | 2363.82 | 2437.32 | 2514.66 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 25925.13 | 37.94 | 42.33 | 49.95 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 32661.19 | 30.04 | 32.36 | 41.28 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 32357.20 | 30.44 | 32.27 | 44.26 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 24127.34 | 40.65 | 46.15 | 52.39 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 25606.99 | 38.44 | 42.88 | 49.43 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 31941.21 | 30.85 | 32.53 | 41.04 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 29801.53 | 33.09 | 35.74 | 45.28 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 25018.71 | 38.73 | 45.65 | 55.06 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 1526.29 | 654.73 | 663.48 | 669.09 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 2720.66 | 364.03 | 377.72 | 383.77 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 2646.07 | 372.27 | 390.05 | 415.88 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 1512.68 | 661.21 | 669.01 | 670.59 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 1511.59 | 661.66 | 668.69 | 700.61 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 2742.22 | 363.01 | 375.94 | 376.86 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 2664.18 | 371.11 | 385.71 | 388.02 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 1383.67 | 662.55 | 1248.76 | 1607.10 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 1 | 4 | 100 | 812.12 | 1218.33 | 1296.54 | 1421.04 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 1 | 4 | 100 | 3935.36 | 247.15 | 282.21 | 333.07 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 2 | 4 | 100 | 4027.19 | 244.58 | 275.24 | 284.18 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 2 | 4 | 100 | 804.59 | 1242.21 | 1285.56 | 1303.68 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 3 | 4 | 100 | 811.32 | 1225.55 | 1272.85 | 1292.09 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 3 | 4 | 100 | 4045.78 | 241.23 | 274.38 | 287.84 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 4 | 4 | 100 | 3790.15 | 248.44 | 290.27 | 676.48 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 4 | 4 | 100 | 796.72 | 1250.09 | 1296.73 | 1315.23 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 1 | 4 | 100 | 34114.31 | 28.53 | 32.31 | 44.94 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 1 | 4 | 100 | 41138.14 | 23.67 | 27.56 | 34.22 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 2 | 4 | 100 | 40971.35 | 23.80 | 26.15 | 36.30 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 2 | 4 | 100 | 34241.96 | 28.61 | 30.32 | 42.91 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 3 | 4 | 100 | 34381.07 | 28.63 | 31.15 | 36.23 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 3 | 4 | 100 | 41449.28 | 23.58 | 25.40 | 35.55 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 4 | 4 | 100 | 41485.81 | 23.61 | 25.62 | 33.75 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 4 | 4 | 100 | 34652.65 | 28.28 | 30.96 | 40.83 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 1 | 4 | 100 | 2804.93 | 354.74 | 367.11 | 371.34 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 1 | 4 | 100 | 14521.36 | 66.15 | 77.60 | 85.88 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 2 | 4 | 100 | 15012.15 | 65.47 | 77.65 | 82.05 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 2 | 4 | 100 | 2835.54 | 350.27 | 362.55 | 364.96 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 3 | 4 | 100 | 2813.90 | 352.78 | 364.62 | 370.82 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 3 | 4 | 100 | 15119.93 | 65.48 | 70.84 | 79.65 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 4 | 4 | 100 | 14831.69 | 66.02 | 78.08 | 89.13 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 4 | 4 | 100 | 2820.00 | 352.32 | 364.13 | 366.61 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | courierust | connect | 0 | 1 | 1 | 4 | 100 | 660.29 | 1513.90 | 1548.11 | 1586.62 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 1 | 4 | 100 | 1807.06 | 554.46 | 581.70 | 591.85 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 2 | 4 | 100 | 1814.81 | 553.71 | 579.17 | 584.26 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | courierust | connect | 0 | 1 | 2 | 4 | 100 | 662.35 | 1512.29 | 1537.43 | 1542.86 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | courierust | connect | 0 | 1 | 3 | 4 | 100 | 661.79 | 1504.65 | 1541.17 | 1558.49 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 3 | 4 | 100 | 1753.96 | 565.56 | 635.31 | 681.30 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 4 | 4 | 100 | 1379.71 | 572.94 | 1347.50 | 1526.32 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | courierust | connect | 0 | 1 | 4 | 4 | 100 | 582.40 | 1508.02 | 3129.79 | 4250.85 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 29387.45 | 33.17 | 37.73 | 48.31 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 35066.05 | 28.03 | 30.46 | 38.14 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 35049.80 | 27.95 | 30.64 | 39.33 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 30207.06 | 32.67 | 35.41 | 38.44 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 29827.17 | 32.93 | 35.44 | 45.63 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 35203.78 | 27.91 | 30.57 | 35.79 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 33929.19 | 28.09 | 33.86 | 43.49 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 21291.27 | 32.59 | 157.38 | 198.50 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 1553.96 | 642.09 | 654.27 | 667.74 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 2721.82 | 366.22 | 390.37 | 398.36 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 2704.99 | 366.37 | 383.90 | 424.62 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 1533.72 | 651.46 | 666.59 | 668.76 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 1545.75 | 646.69 | 655.92 | 659.39 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 2776.86 | 355.16 | 371.38 | 421.30 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 2797.92 | 354.88 | 365.84 | 386.03 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 1555.56 | 642.67 | 651.61 | 652.65 | 100 | exploratory | ok |

## WebSocket: Courierust / tungstenite / tokio-tungstenite

| Protocol | Case | Client | Server | Mode | Bytes/message | Workers | Repeat | Warmup | Completed | RPS | P50 us | P95 us | P99 us | Samples | Tail evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ws | binary_echo | courierust | tungstenite | reuse | 64 | 1 | 1 | 16 | 1000 | 44960.68 | 21.85 | 24.67 | 31.79 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 64 | 1 | 1 | 16 | 1000 | 46749.46 | 20.84 | 24.75 | 31.72 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 64 | 1 | 1 | 16 | 1000 | 33230.44 | 29.45 | 33.96 | 41.54 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 64 | 1 | 2 | 16 | 1000 | 31864.95 | 30.74 | 35.90 | 40.70 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 64 | 1 | 2 | 16 | 1000 | 45392.04 | 20.85 | 26.39 | 32.48 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 64 | 1 | 2 | 16 | 1000 | 44156.30 | 22.30 | 24.02 | 30.75 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 64 | 1 | 3 | 16 | 1000 | 43550.92 | 22.51 | 25.89 | 32.44 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 64 | 1 | 3 | 16 | 1000 | 45431.83 | 21.64 | 22.95 | 31.08 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 64 | 1 | 3 | 16 | 1000 | 31858.70 | 30.70 | 36.94 | 43.41 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 64 | 1 | 4 | 16 | 1000 | 31295.40 | 30.83 | 35.96 | 46.04 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 64 | 1 | 4 | 16 | 1000 | 45238.95 | 21.51 | 26.39 | 31.26 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 64 | 1 | 4 | 16 | 1000 | 43967.43 | 22.35 | 25.24 | 32.13 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 1024 | 1 | 1 | 16 | 1000 | 43371.85 | 22.59 | 25.66 | 31.93 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 1024 | 1 | 1 | 16 | 1000 | 44838.86 | 21.45 | 25.03 | 31.90 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 1024 | 1 | 1 | 16 | 1000 | 32481.92 | 30.28 | 32.69 | 43.09 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 1024 | 1 | 2 | 16 | 1000 | 32522.97 | 29.77 | 34.27 | 41.84 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 1024 | 1 | 2 | 16 | 1000 | 46723.97 | 20.88 | 24.23 | 31.00 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 1024 | 1 | 2 | 16 | 1000 | 44322.17 | 21.90 | 25.40 | 30.48 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 1024 | 1 | 3 | 16 | 1000 | 43654.39 | 22.53 | 24.54 | 31.56 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 1024 | 1 | 3 | 16 | 1000 | 42645.64 | 23.29 | 26.89 | 32.58 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 1024 | 1 | 3 | 16 | 1000 | 32367.14 | 30.07 | 36.33 | 44.31 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 1024 | 1 | 4 | 16 | 1000 | 32379.87 | 30.07 | 36.58 | 43.65 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 1024 | 1 | 4 | 16 | 1000 | 46388.34 | 21.06 | 23.78 | 30.85 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 1024 | 1 | 4 | 16 | 1000 | 43479.56 | 22.45 | 25.64 | 31.56 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 16384 | 1 | 1 | 16 | 1000 | 38386.45 | 25.99 | 27.55 | 36.09 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 16384 | 1 | 1 | 16 | 1000 | 40093.74 | 24.62 | 26.08 | 33.55 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 16384 | 1 | 1 | 16 | 1000 | 29282.97 | 33.60 | 37.65 | 44.77 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 16384 | 1 | 2 | 16 | 1000 | 29161.39 | 33.95 | 37.60 | 46.21 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 16384 | 1 | 2 | 16 | 1000 | 39368.96 | 24.88 | 27.67 | 36.98 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 16384 | 1 | 2 | 16 | 1000 | 38475.92 | 26.11 | 27.65 | 35.23 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 16384 | 1 | 3 | 16 | 1000 | 38312.20 | 26.12 | 28.13 | 38.53 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 16384 | 1 | 3 | 16 | 1000 | 37237.06 | 26.39 | 29.88 | 37.94 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 16384 | 1 | 3 | 16 | 1000 | 29146.99 | 33.99 | 36.08 | 45.27 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 16384 | 1 | 4 | 16 | 1000 | 30065.26 | 33.19 | 34.83 | 43.98 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 16384 | 1 | 4 | 16 | 1000 | 38358.94 | 25.74 | 28.29 | 37.47 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 16384 | 1 | 4 | 16 | 1000 | 38589.72 | 25.98 | 27.50 | 34.56 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 262144 | 1 | 1 | 16 | 1000 | 4283.50 | 232.72 | 247.62 | 254.24 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 262144 | 1 | 1 | 16 | 1000 | 9442.54 | 106.81 | 118.37 | 127.39 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 262144 | 1 | 1 | 16 | 1000 | 9299.82 | 106.17 | 124.30 | 133.67 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 262144 | 1 | 2 | 16 | 1000 | 8879.67 | 111.45 | 128.41 | 138.40 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 262144 | 1 | 2 | 16 | 1000 | 9459.99 | 102.23 | 123.62 | 129.65 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 262144 | 1 | 2 | 16 | 1000 | 9694.11 | 101.79 | 111.99 | 120.51 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 262144 | 1 | 3 | 16 | 1000 | 10109.36 | 98.29 | 107.63 | 114.61 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 262144 | 1 | 3 | 16 | 1000 | 10280.57 | 97.05 | 106.60 | 116.25 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 262144 | 1 | 3 | 16 | 1000 | 9525.80 | 103.18 | 121.38 | 129.04 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 262144 | 1 | 4 | 16 | 1000 | 6499.27 | 107.13 | 415.14 | 648.80 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 262144 | 1 | 4 | 16 | 1000 | 10629.15 | 94.08 | 101.75 | 108.76 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 262144 | 1 | 4 | 16 | 1000 | 10409.02 | 93.93 | 105.53 | 113.00 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 64 | 1 | 1 | 16 | 1000 | 42667.39 | 23.07 | 24.81 | 32.49 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 64 | 1 | 1 | 16 | 1000 | 44317.49 | 22.07 | 26.35 | 31.42 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 64 | 1 | 1 | 16 | 1000 | 33655.65 | 29.11 | 33.58 | 40.69 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 64 | 1 | 2 | 16 | 1000 | 33074.64 | 29.51 | 34.01 | 39.30 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 64 | 1 | 2 | 16 | 1000 | 43705.25 | 22.50 | 26.81 | 34.05 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 64 | 1 | 2 | 16 | 1000 | 46119.93 | 21.11 | 25.38 | 32.18 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 64 | 1 | 3 | 16 | 1000 | 40574.38 | 23.94 | 30.97 | 35.59 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 64 | 1 | 3 | 16 | 1000 | 46853.41 | 21.03 | 22.47 | 30.55 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 64 | 1 | 3 | 16 | 1000 | 33195.72 | 29.73 | 31.93 | 40.86 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 64 | 1 | 4 | 16 | 1000 | 33693.57 | 29.15 | 33.43 | 39.43 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 64 | 1 | 4 | 16 | 1000 | 42446.63 | 22.98 | 27.80 | 33.45 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 64 | 1 | 4 | 16 | 1000 | 39844.92 | 24.70 | 27.07 | 34.45 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 1024 | 1 | 1 | 16 | 1000 | 41581.88 | 23.79 | 27.18 | 33.61 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 1024 | 1 | 1 | 16 | 1000 | 43762.93 | 22.53 | 23.85 | 31.23 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 1024 | 1 | 1 | 16 | 1000 | 33799.94 | 29.10 | 32.20 | 39.82 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 1024 | 1 | 2 | 16 | 1000 | 33255.71 | 29.50 | 33.86 | 41.93 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 1024 | 1 | 2 | 16 | 1000 | 42591.18 | 22.79 | 27.97 | 36.80 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 1024 | 1 | 2 | 16 | 1000 | 44831.85 | 21.98 | 23.59 | 30.23 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 1024 | 1 | 3 | 16 | 1000 | 40993.08 | 23.83 | 28.27 | 34.77 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 1024 | 1 | 3 | 16 | 1000 | 48050.65 | 20.43 | 22.68 | 28.66 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 1024 | 1 | 3 | 16 | 1000 | 33435.63 | 29.38 | 32.39 | 40.87 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 1024 | 1 | 4 | 16 | 1000 | 33245.07 | 29.50 | 34.70 | 39.91 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 1024 | 1 | 4 | 16 | 1000 | 47009.33 | 20.86 | 23.57 | 28.11 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 1024 | 1 | 4 | 16 | 1000 | 45361.16 | 21.74 | 23.58 | 28.92 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 16384 | 1 | 1 | 16 | 1000 | 38311.71 | 25.77 | 27.49 | 35.56 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 16384 | 1 | 1 | 16 | 1000 | 38616.90 | 25.47 | 28.43 | 37.13 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 16384 | 1 | 1 | 16 | 1000 | 29727.13 | 33.02 | 37.95 | 45.52 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 16384 | 1 | 2 | 16 | 1000 | 30132.15 | 32.73 | 34.63 | 44.79 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 16384 | 1 | 2 | 16 | 1000 | 39216.93 | 25.31 | 26.25 | 35.17 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 16384 | 1 | 2 | 16 | 1000 | 38661.30 | 25.60 | 26.61 | 32.70 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 16384 | 1 | 3 | 16 | 1000 | 37947.35 | 26.04 | 27.28 | 34.88 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 16384 | 1 | 3 | 16 | 1000 | 41076.57 | 24.11 | 24.94 | 31.37 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 16384 | 1 | 3 | 16 | 1000 | 29726.39 | 33.17 | 34.74 | 45.44 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 16384 | 1 | 4 | 16 | 1000 | 29787.66 | 33.12 | 35.35 | 45.07 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 16384 | 1 | 4 | 16 | 1000 | 38527.97 | 25.30 | 28.04 | 35.34 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 16384 | 1 | 4 | 16 | 1000 | 37802.40 | 26.12 | 27.50 | 35.27 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 262144 | 1 | 1 | 16 | 1000 | 9763.34 | 101.76 | 111.09 | 115.00 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 262144 | 1 | 1 | 16 | 1000 | 10222.23 | 96.56 | 107.57 | 112.65 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 262144 | 1 | 1 | 16 | 1000 | 8767.97 | 114.05 | 123.99 | 133.68 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 262144 | 1 | 2 | 16 | 1000 | 8544.87 | 115.97 | 132.45 | 137.84 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 262144 | 1 | 2 | 16 | 1000 | 10286.74 | 96.81 | 104.89 | 109.06 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 262144 | 1 | 2 | 16 | 1000 | 9799.24 | 100.94 | 111.96 | 120.00 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 262144 | 1 | 3 | 16 | 1000 | 9794.62 | 101.54 | 109.87 | 115.16 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 262144 | 1 | 3 | 16 | 1000 | 10309.53 | 96.70 | 104.67 | 109.06 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 262144 | 1 | 3 | 16 | 1000 | 9071.16 | 109.97 | 126.01 | 136.59 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 262144 | 1 | 4 | 16 | 1000 | 9389.39 | 105.48 | 117.76 | 123.54 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 262144 | 1 | 4 | 16 | 1000 | 9776.54 | 97.82 | 117.70 | 126.23 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 262144 | 1 | 4 | 16 | 1000 | 8810.83 | 105.46 | 120.08 | 385.63 | 1000 | sampled | ok |

## Build and machine provenance

~~~text
Sat Nov  7 12:52:37 UTC 2026
6f1cb5276d61411ef78dc8130b111f81ba55e17e
rustc 1.98.0 (88d9e12ae 2026-08-18)
binary: rustc
commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea
commit-date: 2026-08-18
host: x86_64-unknown-linux-gnu
release: 1.98.0
LLVM version: 22.1.8
cargo 1.98.0 (797e8a9bc 2026-08-05)
Linux runnervmwuk1x 7.0.0-1019-azure #20-Ubuntu SMP PREEMPT Mon Oct 19 22:41:16 UTC 2026 x86_64 GNU/Linux
Architecture:                            x86_64
CPU op-mode(s):                          32-bit, 64-bit
Address sizes:                           48 bits physical, 48 bits virtual
Byte Order:                              Little Endian
CPU(s):                                  4
On-line CPU(s) list:                     0-3
Vendor ID:                               AuthenticAMD
Model name:                              AMD EPYC 9V45 96-Core Processor
CPU family:                              26
Model:                                   2
Thread(s) per core:                      2
Core(s) per socket:                      2
Socket(s):                               1
Stepping:                                1
BogoMIPS:                                5192.24
Flags:                                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology tsc_reliable nonstop_tsc cpuid extd_apicid aperfmperf tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy svm cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid avx512f avx512dq rdseed adx smap avx512ifma clflushopt clwb avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves user_shstk avx_vnni avx512_bf16 clzero xsaveerptr rdpru arat npt nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold v_vmsave_vmload avx512vbmi umip avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg avx512_vpopcntdq rdpid fsrm avx512_vp2intersect
Virtualization:                          AMD-V
Hypervisor vendor:                       Microsoft
Virtualization type:                     full
L1d cache:                               96 KiB (2 instances)
L1i cache:                               64 KiB (2 instances)
L2 cache:                                2 MiB (2 instances)
L3 cache:                                32 MiB (1 instance)
NUMA node(s):                            1
NUMA node0 CPU(s):                       0-3
Vulnerability Gather data sampling:      Not affected
Vulnerability Ghostwrite:                Not affected
Vulnerability Indirect target selection: Not affected
Vulnerability Itlb multihit:             Not affected
Vulnerability L1tf:                      Not affected
Vulnerability Mds:                       Not affected
Vulnerability Meltdown:                  Not affected
Vulnerability Mmio stale data:           Not affected
Vulnerability Old microcode:             Not affected
Vulnerability Reg file data sampling:    Not affected
Vulnerability Retbleed:                  Not affected
Vulnerability Spec rstack overflow:      Vulnerable: Safe RET, no microcode
Vulnerability Spec store bypass:         Vulnerable
Vulnerability Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
Vulnerability Spectre v2:                Mitigation; Retpolines; STIBP disabled; RSB filling; PBRSB-eIBRS Not affected; BHI Not affected
Vulnerability Srbds:                     Not affected
Vulnerability Tsa:                       Not affected
Vulnerability Tsx async abort:           Not affected
Vulnerability Vmscape:                   Not affected
ff5c621ce2b72a9b54f88b5df08f219bdb9e131e26719fdd7fd4d210d0fc721e  Cargo.lock
dcfcc00d278cefdd4368326e41be0cbdabecbd2cdd1d8b9df4d8fb325826b114  benches/Cargo.lock
courierust_benchmark v0.1.1 (/home/runner/work/Courierust/Courierust/benches)
[2m├──[0m bytes v1.12.1
[2m├──[0m courierust v1.1.0 (/home/runner/work/Courierust/Courierust)
[2m├──[0m futures-util v0.3.34
[2m├──[0m h3 v0.0.8
[2m├──[0m h3-quinn v0.0.10
[2m├──[0m http v1.5.0
[2m├──[0m http-body-util v0.1.5
[2m├──[0m hyper v1.11.0
[2m├──[0m hyper-util v0.1.20
[2m├──[0m prost v0.14.4
[2m├──[0m quinn v0.11.11
[2m│[0m   [94m[1m[build-dependencies][39m[22m
[2m├──[0m reqwest v0.13.4
[2m├──[0m rustls v0.23.43
[2m├──[0m tokio v1.53.1
[2m├──[0m tokio-rustls v0.26.4
[2m├──[0m tokio-stream v0.1.19
[2m├──[0m tokio-tungstenite v0.30.0
[2m├──[0m tonic v0.14.9
[2m├──[0m tonic-prost v0.14.9
[2m└──[0m tungstenite v0.30.0
[94m[1m[build-dependencies][39m[22m
[1m[34m├──[0m protoc-bin-vendored v3.3.0
[1m[34m└──[0m tonic-prost-build v0.14.9
~~~

## Concurrency and Slow Connections

- These rows measure production usability and resource isolation: an event-driven scheduler must keep idle/partial/slow (Slowloris-style) connections off the worker pool while a fast probe still completes. The `pool` row is the diagnostic counter-model.

| Case | Model | Platform | Status | Event enabled | Connections | Worker threads | Probe us | Probe status | Byte delay us | Completed | Wall ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| idle_partial_herd | event | linux | probe_ok | true | 200 | 2 | 190.21 | - | - | - | - |
| idle_partial_herd | pool | linux | probe_blocked | false | 200 | 2 | na | - | - | - | - |
| slow_sender_herd | event | linux | ok | true | 16 | 2 | 493.17 | probe_ok | 10000 | 16 | 394.04 |

## HTTP/3 (QUIC)

- `h3_connect` is a cold request: QUIC handshake + TLS 1.3 + server Retry address validation on a fresh connection.
- `h3_sequential` and `h3_parallel` reuse the pooled per-authority QUIC connection (`mode=reuse`), so they measure the warm per-request cost of connection reuse.

| Case | Mode | Workers | Requests | Elapsed ms | Connect ms | RPS | P50 us | P75 us | P90 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| h3_connect | connect | 1 | 1 | - | 4.070 | - | - | - | - | - | - | - | - | - | - | - | - |
| h3_sequential | reuse | 1 | 1000 | 73.446 | - | 13615.4 | 71.6 | 74.1 | 87.0 | 93.8 | 57.37 | 73.41 | 110.11 | 7.37 | 102.55 | 1.31 | 1000 |
| h3_parallel | reuse | 8 | 1000 | 24.258 | - | 41224.3 | 189.9 | 203.6 | 219.9 | 260.4 | 114.92 | 192.02 | 413.45 | 24.97 | 411.83 | 1.37 | 1000 |

## Complexity (time and space)

- Complexity diagnostics retain their existing minimum-of-three estimator at several input sizes. This lower-envelope measurement is not a typical-latency or tail estimate; scheduling and frequency changes can affect the fitted curve.
- `class` is named by `median k`, the median of the adjacent-pair exponents, so the label describes the *typical* growth factor per 16× inside the measured range; `max k` is the worst pair, so one noisy pair cannot pass as a trend. `slope b` is the per-unit cost and `fixed a` the per-operation cost that does not scale with the input; R² is the fit quality (1.0 = exact).
- A range whose fixed term dwarfs its per-unit term is labelled `fixed-cost dominated` instead of quoting a sublinear-looking exponent that is really the constant; for those families read `slope b` (for example nanoseconds per extra header).
- Space is attributed per operation by a counting allocator compiled into the bench binary (allocation bytes and allocation calls), and per connection by a live-bytes/RSS delta between 1 and 65 idle keep-alive connections — the fixed process/runtime cost cancels out of a delta.
- `ratio` is Courierust divided by the reference at the same size: below 1 means Courierust is cheaper. Rows are comparable only within one run.

| family | implementation | operation | metric | fitted class | median k | max k | slope b | fixed a | R² | points |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|
| codec | courierust | encode_unmasked | time_ns | O(n^1.26) | 1.255 | 1.471 | 0.016034 | -458.5229 | 0.9855 | 5 |
| codec | courierust | encode_unmasked | alloc_bytes | O(1) | 0.000 | 0.000 | 0.000000 | 0.0000 | 1.0000 | 5 |
| codec | tungstenite | encode_unmasked | time_ns | O(n^1.29) | 1.293 | 1.339 | 0.016233 | -368.0586 | 0.9911 | 5 |
| codec | tungstenite | encode_unmasked | alloc_bytes | O(1) | 0.000 | 0.000 | 0.000000 | 0.0000 | 1.0000 | 5 |
| codec | courierust | encode_masked | time_ns | O(n) | 1.097 | 1.107 | 0.037356 | -325.8737 | 0.9988 | 5 |
| codec | courierust | encode_masked | alloc_bytes | O(1) | 0.000 | 0.000 | 0.000000 | 0.0000 | 1.0000 | 5 |
| codec | tungstenite | encode_masked | time_ns | O(n) | 1.068 | 1.388 | 0.043694 | -1042.3578 | 0.9888 | 5 |
| codec | tungstenite | encode_masked | alloc_bytes | O(n) | 1.000 | 1.000 | 1.000000 | 0.0000 | 1.0000 | 5 |
| http | courierust | get_roundtrip | time_ns | O(n^0.27) | 0.273 | 1.733 | 0.841778 | -17446.5680 | 0.9624 | 4 |
| http | courierust | get_roundtrip | alloc_bytes | O(n) | 0.969 | 0.997 | 1.999782 | 3149.6894 | 1.0000 | 4 |
| http | reqwest_hyper | get_roundtrip | time_ns | O(n^0.29) | 0.288 | 0.642 | 0.208836 | 47458.9959 | 0.9982 | 4 |
| http | reqwest_hyper | get_roundtrip | alloc_bytes | O(n) | 0.888 | 0.987 | 2.571603 | 45293.4097 | 0.9984 | 4 |
| headers | courierust | get_with_headers | time_ns | O(n^0.46) | 0.455 | 0.455 | 861.522321 | 34348.4067 | 0.9998 | 3 |
| headers | courierust | get_with_headers | alloc_bytes | O(n^0.85) | 0.846 | 0.846 | 980.602381 | 5345.7867 | 1.0000 | 3 |
| headers | reqwest_hyper | get_with_headers | time_ns | O(n^0.38) | 0.378 | 0.378 | 621.146845 | 41039.2267 | 0.9833 | 3 |
| headers | reqwest_hyper | get_with_headers | alloc_bytes | O(n^0.60) | 0.596 | 0.596 | 1168.000000 | 24970.6400 | 1.0000 | 3 |
| deflate | courierust | deflate_reused_compressible | time_ns | O(n) | 1.001 | 1.001 | 0.462014 | 67.6852 | 1.0000 | 3 |
| deflate | courierust | deflate_reused_compressible | alloc_bytes | n/a | n/a | n/a | n/a | n/a | n/a | 1 |
| deflate | courierust | deflate_fresh_compressible | time_ns | O(n) | 1.011 | 1.011 | 0.511845 | 117.4429 | 1.0000 | 3 |
| deflate | courierust | deflate_fresh_compressible | alloc_bytes | O(n) | 0.867 | 0.867 | 4.093389 | 131406.3313 | 1.0000 | 3 |
| deflate | courierust | inflate_compressible | time_ns | O(n^0.84) | 0.843 | 0.843 | 0.075013 | 2954.7817 | 1.0000 | 3 |
| deflate | courierust | inflate_compressible | alloc_bytes | fixed-cost dominated | 0.000 | 0.000 | 0.000000 | 29.0000 | 1.0000 | 3 |
| deflate | courierust | deflate_reused_incompressible | time_ns | O(n^1.33) | 1.326 | 1.326 | 17.183826 | -35258.8713 | 1.0000 | 3 |
| deflate | courierust | deflate_reused_incompressible | alloc_bytes | O(1) | 0.000 | 0.000 | 0.000000 | 0.0000 | 1.0000 | 3 |
| deflate | courierust | deflate_fresh_incompressible | time_ns | O(n^1.26) | 1.260 | 1.260 | 19.791846 | -129184.1315 | 0.9999 | 3 |
| deflate | courierust | deflate_fresh_incompressible | alloc_bytes | O(n) | 0.960 | 0.960 | 16.000000 | 131048.0000 | 1.0000 | 3 |

### Constant factors (paired at the same size)

| family | operation | metric | n | courierust | reference | ratio (ours/reference) |
|---|---|---|---:|---:|---:|---:|
| codec | encode_unmasked | time_ns | 64 | 6.6000 | 16.1043 | 0.410 |
| codec | encode_unmasked | alloc_bytes | 64 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 64 | 17.5240 | 47.6020 | 0.368 |
| codec | encode_masked | alloc_bytes | 64 | 0.0000 | 64.0000 | 0.000 |
| codec | encode_unmasked | time_ns | 1024 | 10.1905 | 20.1055 | 0.507 |
| codec | encode_unmasked | alloc_bytes | 1024 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 1024 | 41.0820 | 62.0040 | 0.663 |
| codec | encode_masked | alloc_bytes | 1024 | 0.0000 | 1024.0000 | 0.000 |
| codec | encode_unmasked | time_ns | 16384 | 67.1050 | 73.5100 | 0.913 |
| codec | encode_unmasked | alloc_bytes | 16384 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 16384 | 401.7550 | 344.9750 | 1.165 |
| codec | encode_masked | alloc_bytes | 16384 | 0.0000 | 16384.0000 | 0.000 |
| codec | encode_unmasked | time_ns | 262144 | 2178.3000 | 2651.0000 | 0.822 |
| codec | encode_unmasked | alloc_bytes | 262144 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 262144 | 8422.5000 | 6669.5750 | 1.263 |
| codec | encode_masked | alloc_bytes | 262144 | 0.0000 | 262144.0000 | 0.000 |
| codec | encode_unmasked | time_ns | 1048576 | 16741.0750 | 16958.9000 | 0.987 |
| codec | encode_unmasked | alloc_bytes | 1048576 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 1048576 | 39103.3500 | 45698.0750 | 0.856 |
| codec | encode_masked | alloc_bytes | 1048576 | 0.0000 | 1048576.0000 | 0.000 |
| codec | utf8_validate | time_ns | 4608 | 693.5585 | 704.1495 | 0.985 |
| http | get_roundtrip | time_ns | 1024 | 34068.6010 | 44635.6159 | 0.763 |
| http | get_roundtrip | alloc_bytes | 1024 | 5299.8100 | 26714.0398 | 0.198 |
| http | get_roundtrip | time_ns | 16384 | 38043.1333 | 48986.3429 | 0.777 |
| http | get_roundtrip | alloc_bytes | 16384 | 35922.3143 | 51458.8381 | 0.698 |
| http | get_roundtrip | time_ns | 262144 | 81020.2400 | 108736.0000 | 0.745 |
| http | get_roundtrip | alloc_bytes | 262144 | 527233.4800 | 794887.4400 | 0.663 |
| http | get_roundtrip | time_ns | 1048576 | 895070.8000 | 264839.2000 | 3.380 |
| http | get_roundtrip | alloc_bytes | 1048576 | 2100109.7200 | 2723531.9200 | 0.771 |
| headers | get_with_headers | time_ns | 4 | 38165.8750 | 45769.6950 | 0.834 |
| headers | get_with_headers | time_ns | 16 | 47668.5400 | 48170.2250 | 0.990 |
| headers | get_with_headers | time_ns | 64 | 89578.6800 | 81354.0950 | 1.101 |
| deflate | fresh_vs_reused_compressible | time_ns | 1024 | 1680.1400 | 693.1500 | 2.424 |
| deflate | fresh_vs_reused_compressible | time_ns | 65536 | 32554.9750 | 30183.8750 | 1.079 |
| deflate | fresh_vs_reused_compressible | time_ns | 1048576 | 536893.7000 | 484534.5000 | 1.108 |
| deflate | fresh_vs_reused_incompressible | time_ns | 1024 | 5544.0850 | 4298.5000 | 1.290 |
| deflate | fresh_vs_reused_incompressible | time_ns | 65536 | 1045921.3750 | 1067498.0000 | 0.980 |
| deflate | fresh_vs_reused_incompressible | time_ns | 1048576 | 20631581.8000 | 17984729.6000 | 1.147 |

### Space: cost of one idle connection

| implementation | connections | live KiB/conn | RSS KiB/conn |
|---|---:|---:|---:|
| courierust_event | 65 | 10.06 | 8.19 |
| courierust_blocking | 65 | 32.70 | 16.31 |
| hyper_tokio | 65 | 18.91 | 10.25 |

### Time: selected scaling points

| family | implementation | operation | n (bytes) | ns/op |
|---|---|---|---:|---:|
| codec | courierust | encode_unmasked | 64 | 6.6000 |
| codec | tungstenite | encode_unmasked | 64 | 16.1043 |
| codec | courierust | encode_masked | 64 | 17.5240 |
| codec | tungstenite | encode_masked | 64 | 47.6020 |
| codec | courierust | encode_unmasked | 1024 | 10.1905 |
| codec | tungstenite | encode_unmasked | 1024 | 20.1055 |
| codec | courierust | encode_masked | 1024 | 41.0820 |
| codec | tungstenite | encode_masked | 1024 | 62.0040 |
| codec | courierust | encode_unmasked | 16384 | 67.1050 |
| codec | tungstenite | encode_unmasked | 16384 | 73.5100 |
| codec | courierust | encode_masked | 16384 | 401.7550 |
| codec | tungstenite | encode_masked | 16384 | 344.9750 |
| codec | courierust | encode_unmasked | 262144 | 2178.3000 |
| codec | tungstenite | encode_unmasked | 262144 | 2651.0000 |
| codec | courierust | encode_masked | 262144 | 8422.5000 |
| codec | tungstenite | encode_masked | 262144 | 6669.5750 |
| codec | courierust | encode_unmasked | 1048576 | 16741.0750 |
| codec | tungstenite | encode_unmasked | 1048576 | 16958.9000 |
| codec | courierust | encode_masked | 1048576 | 39103.3500 |
| codec | tungstenite | encode_masked | 1048576 | 45698.0750 |
| http | courierust | get_roundtrip | 1024 | 34068.6010 |
| http | reqwest_hyper | get_roundtrip | 1024 | 44635.6159 |
| http | courierust | get_roundtrip | 16384 | 38043.1333 |
| http | reqwest_hyper | get_roundtrip | 16384 | 48986.3429 |
| http | courierust | get_roundtrip | 262144 | 81020.2400 |
| http | reqwest_hyper | get_roundtrip | 262144 | 108736.0000 |
| http | courierust | get_roundtrip | 1048576 | 895070.8000 |
| http | reqwest_hyper | get_roundtrip | 1048576 | 264839.2000 |

## Reactor / Connection / Stream Evidence

| Protocol | Case | Payload | Workers | Accepted conns | Active conns | Poll syscalls | Wakeups | Queue peak | H1 conns | H1 read | H1 write | H2 conns | H2 active | H2 streams | H2 stream peak | H2 stream/conn peak | H2 read | H2 write | H3 conns | H3 active | H3 streams | H3 active streams | H3 stream peak | H3 stream/conn peak | H3 queue peak | H3 UDP recv | H3 UDP send |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| h2c | h2_multiplex_w1 | 1k | 1 | 1 | 0 | 2 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 1 | 1 | 4253 | 4003 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w1 | 1k | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 1 | 1 | 4003 | 4253 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w8 | 1k | 8 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 8 | 8 | 1270 | 1093 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w8 | 1k | 8 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 8 | 8 | 1004 | 1746 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w32 | 1k | 32 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 32 | 32 | 490 | 341 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w32 | 1k | 32 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 32 | 32 | 401 | 683 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w1 | 64k | 1 | 1 | 0 | 2 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 1 | 1 | 8004 | 4004 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w1 | 64k | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 1 | 1 | 20008 | 8005 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w8 | 64k | 8 | 1 | 0 | 2 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 8 | 8 | 1617 | 1027 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w8 | 64k | 8 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 8 | 8 | 16626 | 1756 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w32 | 64k | 32 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 32 | 32 | 581 | 469 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w32 | 64k | 32 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 32 | 32 | 16141 | 792 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Cross-Machine

| Role | Status | Scope | Protocol | Workers | Max connections | Requests | Bytes | RPS | Resp MB/s | P50 us | P95 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| client | not_configured | remote | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | COURIERUST_REMOTE_URL_not_set |

## Fuzz

| Target | Status | Runs | Duration s | Corpus | Reason |
| --- | --- | --- | --- | --- | --- |
| h2_frame | ok | smoke | 70 | fuzz/corpus/h2_frame | command_exit_0 |
| hpack_block | ok | smoke | 21 | fuzz/corpus/hpack_block | command_exit_0 |
| h1_request | ok | smoke | 22 | fuzz/corpus/h1_request | command_exit_0 |
| h2_connection | ok | smoke | 23 | fuzz/corpus/h2_connection | command_exit_0 |
| ws_frame | ok | smoke | 22 | fuzz/corpus/ws_frame | command_exit_0 |
| ws_handshake | ok | smoke | 21 | fuzz/corpus/ws_handshake | command_exit_0 |
| ws_session | ok | smoke | 22 | fuzz/corpus/ws_session | command_exit_0 |

## Interop Validation

| Case | Result |
| --- | --- |
| courierust_client_h1_to_hyper_h1 | ok |
| courierust_client_h2c_to_hyper_h2 | ok |
| hyper_client_h1_to_courierust_h1 | ok |
| hyper_client_h2c_to_courierust_h2 | ok |
| reqwest_h1_to_courierust_h1 | ok |
| reqwest_h2c_to_courierust_h2 | ok |
| courierust_h2c_large_body_to_hyper_h2 | ok |
| courierust_h1_slow_reader_to_hyper_h1 | ok |
| tls_rejects_untrusted_certificate | ok |
| tls_rejects_hostname_mismatch | ok |
| tls_alpn_downgrade_to_h1 | ok |
| tls_h2_alpn_rejected | ok |
| h1_connection_close_honored | ok |
| courierust_h2_client_survives_peer_goaway | ok |
| h3_self_roundtrip | ok |
| h3_self_connection_reuse | ok |
| h3_self_large_body_flow_control | ok |
| h3_self_multiplex_concurrent | ok |
| suite | all_cases_passed |
| grpc_status_both_clients_to_tonic | ok |
| grpc_status_both_clients_to_courierust | ok |

## TLS Interop Matrix

| _No TLS interop evidence captured_ | | | | | |

## Captured Benchmark Output


### grpc.log
~~~text
META|suite=grpc|transport=h2c|tls=off|codec=prost_shared|compression=identity|connections=1|server_threads=2|stream_messages=4|order=alternating|validation=bytes_sequence_final_status|load=closed_loop
META|tonic_server_tcp_nodelay=true|client_tcp_nodelay=true|courierust_server_tcp_nodelay=true
INTEROP|case=grpc_status_both_clients_to_tonic|ok
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=5.127|rps=19502.94|p50_us=50.01|p95_us=58.46|p99_us=66.95|samples=100|min_us=47.44|mean_us=51.25|max_us=72.92|stddev_us=4.24|p999_us=72.92|tail_ratio=1.34|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=7.398|rps=13517.43|p50_us=73.75|p95_us=84.56|p99_us=92.95|samples=100|min_us=61.03|mean_us=73.95|max_us=95.06|stddev_us=5.56|p999_us=95.06|tail_ratio=1.26|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=7.407|rps=13500.16|p50_us=73.97|p95_us=81.87|p99_us=84.14|samples=100|min_us=63.61|mean_us=73.99|max_us=89.74|stddev_us=4.02|p999_us=89.74|tail_ratio=1.14|cv=0.05
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4.974|rps=20105.92|p50_us=48.58|p95_us=55.94|p99_us=63.29|samples=100|min_us=47.08|mean_us=49.71|max_us=64.08|stddev_us=3.16|p999_us=64.08|tail_ratio=1.30|cv=0.06
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=5.140|rps=19456.23|p50_us=48.64|p95_us=63.44|p99_us=83.15|samples=100|min_us=47.22|mean_us=51.37|max_us=98.15|stddev_us=7.82|p999_us=98.15|tail_ratio=1.71|cv=0.15
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=7.657|rps=13060.48|p50_us=75.04|p95_us=87.34|p99_us=94.34|samples=100|min_us=67.08|mean_us=76.51|max_us=110.01|stddev_us=5.87|p999_us=110.01|tail_ratio=1.26|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=7.611|rps=13139.70|p50_us=75.69|p95_us=83.15|p99_us=90.56|samples=100|min_us=67.57|mean_us=76.06|max_us=92.41|stddev_us=4.00|p999_us=92.41|tail_ratio=1.20|cv=0.05
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=5.240|rps=19085.06|p50_us=51.08|p95_us=58.92|p99_us=67.24|samples=100|min_us=48.38|mean_us=52.37|max_us=75.19|stddev_us=4.00|p999_us=75.19|tail_ratio=1.32|cv=0.08
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=5.555|rps=18001.89|p50_us=53.56|p95_us=63.73|p99_us=69.14|samples=100|min_us=49.73|mean_us=55.52|max_us=75.05|stddev_us=4.47|p999_us=75.05|tail_ratio=1.29|cv=0.08
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=7.603|rps=13152.43|p50_us=76.08|p95_us=81.30|p99_us=92.58|samples=100|min_us=65.48|mean_us=76.00|max_us=99.64|stddev_us=5.13|p999_us=99.64|tail_ratio=1.22|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=7.519|rps=13300.44|p50_us=74.59|p95_us=85.19|p99_us=91.92|samples=100|min_us=62.97|mean_us=75.15|max_us=93.80|stddev_us=5.28|p999_us=93.80|tail_ratio=1.23|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=5.575|rps=17936.61|p50_us=53.53|p95_us=61.50|p99_us=74.29|samples=100|min_us=51.62|mean_us=55.72|max_us=77.51|stddev_us=4.82|p999_us=77.51|tail_ratio=1.39|cv=0.09
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=5.513|rps=18139.75|p50_us=53.28|p95_us=60.78|p99_us=74.45|samples=100|min_us=51.21|mean_us=55.10|max_us=74.72|stddev_us=4.12|p999_us=74.72|tail_ratio=1.40|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=8.357|rps=11966.18|p50_us=82.20|p95_us=92.84|p99_us=95.41|samples=100|min_us=78.45|mean_us=83.54|max_us=97.61|stddev_us=3.65|p999_us=97.61|tail_ratio=1.16|cv=0.04
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=8.287|rps=12067.52|p50_us=81.50|p95_us=93.86|p99_us=97.56|samples=100|min_us=75.12|mean_us=82.84|max_us=97.59|stddev_us=4.09|p999_us=97.59|tail_ratio=1.20|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=5.540|rps=18051.24|p50_us=52.97|p95_us=64.23|p99_us=72.34|samples=100|min_us=51.26|mean_us=55.37|max_us=76.04|stddev_us=4.61|p999_us=76.04|tail_ratio=1.37|cv=0.08
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=11.575|rps=8639.36|p50_us=114.89|p95_us=136.83|p99_us=145.06|samples=100|min_us=98.18|mean_us=115.71|max_us=145.67|stddev_us=10.33|p999_us=145.67|tail_ratio=1.26|cv=0.09
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=7.811|rps=12803.26|p50_us=75.59|p95_us=94.78|p99_us=104.07|samples=100|min_us=64.22|mean_us=78.07|max_us=127.53|stddev_us=8.50|p999_us=127.53|tail_ratio=1.38|cv=0.11
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=7.773|rps=12864.84|p50_us=76.31|p95_us=86.10|p99_us=97.14|samples=100|min_us=63.63|mean_us=77.69|max_us=102.50|stddev_us=6.14|p999_us=102.50|tail_ratio=1.27|cv=0.08
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=10.913|rps=9163.00|p50_us=106.99|p95_us=123.53|p99_us=141.12|samples=100|min_us=93.45|mean_us=109.10|max_us=146.39|stddev_us=9.49|p999_us=146.39|tail_ratio=1.32|cv=0.09
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=10.864|rps=9204.31|p50_us=106.03|p95_us=130.03|p99_us=150.90|samples=100|min_us=93.51|mean_us=108.61|max_us=152.75|stddev_us=11.43|p999_us=152.75|tail_ratio=1.42|cv=0.11
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=7.499|rps=13334.55|p50_us=74.24|p95_us=88.13|p99_us=102.03|samples=100|min_us=63.02|mean_us=74.94|max_us=110.34|stddev_us=7.12|p999_us=110.34|tail_ratio=1.37|cv=0.09
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=7.464|rps=13397.58|p50_us=74.52|p95_us=86.28|p99_us=90.19|samples=100|min_us=63.56|mean_us=74.56|max_us=90.25|stddev_us=4.89|p999_us=90.25|tail_ratio=1.21|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=10.830|rps=9233.57|p50_us=106.99|p95_us=126.49|p99_us=139.04|samples=100|min_us=92.24|mean_us=108.27|max_us=148.66|stddev_us=9.64|p999_us=148.66|tail_ratio=1.30|cv=0.09
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=11.611|rps=8612.85|p50_us=112.29|p95_us=138.16|p99_us=163.89|samples=100|min_us=94.01|mean_us=116.06|max_us=234.47|stddev_us=16.50|p999_us=234.47|tail_ratio=1.46|cv=0.14
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=6.934|rps=14422.05|p50_us=66.36|p95_us=84.81|p99_us=109.41|samples=100|min_us=61.85|mean_us=69.31|max_us=117.72|stddev_us=8.97|p999_us=117.72|tail_ratio=1.65|cv=0.13
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=6.890|rps=14514.72|p50_us=66.69|p95_us=81.15|p99_us=85.57|samples=100|min_us=62.69|mean_us=68.85|max_us=91.06|stddev_us=5.49|p999_us=91.06|tail_ratio=1.28|cv=0.08
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=11.461|rps=8725.29|p50_us=113.22|p95_us=131.60|p99_us=142.11|samples=100|min_us=98.57|mean_us=114.57|max_us=147.40|stddev_us=8.19|p999_us=147.40|tail_ratio=1.26|cv=0.07
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=11.563|rps=8648.12|p50_us=110.84|p95_us=135.21|p99_us=152.31|samples=100|min_us=104.01|mean_us=115.60|max_us=197.30|stddev_us=12.51|p999_us=197.30|tail_ratio=1.37|cv=0.11
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=8.035|rps=12445.15|p50_us=78.70|p95_us=90.99|p99_us=97.87|samples=100|min_us=66.60|mean_us=80.32|max_us=112.96|stddev_us=5.87|p999_us=112.96|tail_ratio=1.24|cv=0.07
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=7.828|rps=12774.77|p50_us=77.48|p95_us=87.11|p99_us=90.15|samples=100|min_us=73.58|mean_us=78.25|max_us=92.78|stddev_us=3.49|p999_us=92.78|tail_ratio=1.16|cv=0.04
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=11.305|rps=8845.57|p50_us=110.54|p95_us=131.86|p99_us=138.99|samples=100|min_us=96.08|mean_us=113.01|max_us=139.43|stddev_us=8.72|p999_us=139.43|tail_ratio=1.26|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=22.196|rps=4505.36|p50_us=219.67|p95_us=242.01|p99_us=252.27|samples=100|min_us=203.75|mean_us=221.93|max_us=254.06|stddev_us=12.01|p999_us=254.06|tail_ratio=1.15|cv=0.05
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=18.262|rps=5475.88|p50_us=184.90|p95_us=198.11|p99_us=203.43|samples=100|min_us=151.40|mean_us=182.59|max_us=211.83|stddev_us=12.10|p999_us=211.83|tail_ratio=1.10|cv=0.07
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=17.810|rps=5614.90|p50_us=178.27|p95_us=198.52|p99_us=210.12|samples=100|min_us=149.56|mean_us=178.06|max_us=212.74|stddev_us=11.08|p999_us=212.74|tail_ratio=1.18|cv=0.06
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=21.766|rps=4594.33|p50_us=215.08|p95_us=237.34|p99_us=240.94|samples=100|min_us=201.08|mean_us=217.63|max_us=246.22|stddev_us=10.56|p999_us=246.22|tail_ratio=1.12|cv=0.05
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=21.918|rps=4562.37|p50_us=218.98|p95_us=238.58|p99_us=257.71|samples=100|min_us=195.50|mean_us=219.15|max_us=328.35|stddev_us=16.17|p999_us=328.35|tail_ratio=1.18|cv=0.07
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=15.499|rps=6451.87|p50_us=153.42|p95_us=177.93|p99_us=187.51|samples=100|min_us=129.93|mean_us=154.94|max_us=194.29|stddev_us=12.82|p999_us=194.29|tail_ratio=1.22|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=15.295|rps=6537.95|p50_us=153.51|p95_us=170.63|p99_us=174.53|samples=100|min_us=129.28|mean_us=152.90|max_us=179.22|stddev_us=10.72|p999_us=179.22|tail_ratio=1.14|cv=0.07
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=17.838|rps=5605.94|p50_us=199.47|p95_us=232.81|p99_us=236.56|samples=100|min_us=100.54|mean_us=178.35|max_us=243.44|stddev_us=46.34|p999_us=243.44|tail_ratio=1.19|cv=0.26
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=38.427|rps=2602.31|p50_us=384.23|p95_us=416.23|p99_us=420.25|samples=100|min_us=347.31|mean_us=384.23|max_us=422.33|stddev_us=21.91|p999_us=422.33|tail_ratio=1.09|cv=0.06
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=44.403|rps=2252.09|p50_us=442.51|p95_us=469.02|p99_us=553.28|samples=100|min_us=400.84|mean_us=443.99|max_us=570.93|stddev_us=24.01|p999_us=570.93|tail_ratio=1.25|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=44.913|rps=2226.51|p50_us=445.13|p95_us=476.44|p99_us=551.79|samples=100|min_us=378.78|mean_us=449.09|max_us=566.51|stddev_us=24.41|p999_us=566.51|tail_ratio=1.24|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=37.658|rps=2655.47|p50_us=376.67|p95_us=392.57|p99_us=400.72|samples=100|min_us=351.78|mean_us=376.53|max_us=402.50|stddev_us=9.68|p999_us=402.50|tail_ratio=1.06|cv=0.03
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=37.202|rps=2688.01|p50_us=370.08|p95_us=392.73|p99_us=395.85|samples=100|min_us=347.87|mean_us=371.98|max_us=398.93|stddev_us=10.50|p999_us=398.93|tail_ratio=1.07|cv=0.03
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=44.795|rps=2232.40|p50_us=443.45|p95_us=499.40|p99_us=563.00|samples=100|min_us=383.98|mean_us=447.90|max_us=563.64|stddev_us=36.77|p999_us=563.64|tail_ratio=1.27|cv=0.08
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=45.914|rps=2177.96|p50_us=460.60|p95_us=493.37|p99_us=504.70|samples=100|min_us=386.62|mean_us=459.11|max_us=569.39|stddev_us=27.67|p999_us=569.39|tail_ratio=1.10|cv=0.06
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=33.142|rps=3017.33|p50_us=330.03|p95_us=347.07|p99_us=352.97|samples=100|min_us=306.78|mean_us=331.37|max_us=363.43|stddev_us=10.31|p999_us=363.43|tail_ratio=1.07|cv=0.03
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=28.791|rps=3473.36|p50_us=280.70|p95_us=354.68|p99_us=372.77|samples=100|min_us=207.38|mean_us=287.86|max_us=381.12|stddev_us=42.32|p999_us=381.12|tail_ratio=1.33|cv=0.15
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=30.900|rps=3236.21|p50_us=306.00|p95_us=350.14|p99_us=380.58|samples=100|min_us=239.47|mean_us=308.97|max_us=401.60|stddev_us=24.90|p999_us=401.60|tail_ratio=1.24|cv=0.08
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=30.263|rps=3304.33|p50_us=298.53|p95_us=339.17|p99_us=370.66|samples=100|min_us=228.69|mean_us=302.60|max_us=420.69|stddev_us=24.68|p999_us=420.69|tail_ratio=1.24|cv=0.08
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=26.140|rps=3825.51|p50_us=262.05|p95_us=348.97|p99_us=360.54|samples=100|min_us=193.74|mean_us=261.36|max_us=361.26|stddev_us=51.20|p999_us=361.26|tail_ratio=1.38|cv=0.20
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=27.312|rps=3661.35|p50_us=264.66|p95_us=356.14|p99_us=784.03|samples=100|min_us=194.60|mean_us=273.09|max_us=883.89|stddev_us=92.31|p999_us=883.89|tail_ratio=2.96|cv=0.34
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=28.212|rps=3544.56|p50_us=286.94|p95_us=319.57|p99_us=342.21|samples=100|min_us=220.51|mean_us=282.09|max_us=360.48|stddev_us=26.66|p999_us=360.48|tail_ratio=1.19|cv=0.09
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=25.136|rps=3978.34|p50_us=251.48|p95_us=275.23|p99_us=288.86|samples=100|min_us=216.37|mean_us=251.32|max_us=295.91|stddev_us=16.94|p999_us=295.91|tail_ratio=1.15|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=29.136|rps=3432.14|p50_us=285.85|p95_us=362.91|p99_us=381.91|samples=100|min_us=225.94|mean_us=291.32|max_us=396.00|stddev_us=36.75|p999_us=396.00|tail_ratio=1.34|cv=0.13
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=42.905|rps=2330.75|p50_us=435.18|p95_us=508.93|p99_us=517.62|samples=100|min_us=331.99|mean_us=428.99|max_us=544.74|stddev_us=48.37|p999_us=544.74|tail_ratio=1.19|cv=0.11
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=37.198|rps=2688.34|p50_us=359.69|p95_us=460.78|p99_us=520.57|samples=100|min_us=303.24|mean_us=371.93|max_us=538.23|stddev_us=45.12|p999_us=538.23|tail_ratio=1.45|cv=0.12
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=38.647|rps=2587.53|p50_us=373.53|p95_us=471.18|p99_us=538.96|samples=100|min_us=314.52|mean_us=386.43|max_us=544.72|stddev_us=52.87|p999_us=544.72|tail_ratio=1.44|cv=0.14
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=42.556|rps=2349.83|p50_us=422.24|p95_us=510.79|p99_us=558.12|samples=100|min_us=314.02|mean_us=425.51|max_us=661.49|stddev_us=56.90|p999_us=661.49|tail_ratio=1.32|cv=0.13
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=42.554|rps=2349.96|p50_us=424.39|p95_us=510.29|p99_us=549.36|samples=100|min_us=328.48|mean_us=425.49|max_us=552.84|stddev_us=51.85|p999_us=552.84|tail_ratio=1.29|cv=0.12
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=40.229|rps=2485.80|p50_us=403.47|p95_us=456.78|p99_us=475.72|samples=100|min_us=314.39|mean_us=402.24|max_us=490.27|stddev_us=33.24|p999_us=490.27|tail_ratio=1.18|cv=0.08
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=37.671|rps=2654.56|p50_us=366.57|p95_us=463.42|p99_us=512.63|samples=100|min_us=284.32|mean_us=376.66|max_us=516.96|stddev_us=46.49|p999_us=516.96|tail_ratio=1.40|cv=0.12
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=42.481|rps=2354.01|p50_us=414.83|p95_us=523.80|p99_us=544.08|samples=100|min_us=303.55|mean_us=424.76|max_us=557.15|stddev_us=59.48|p999_us=557.15|tail_ratio=1.31|cv=0.14
INTEROP|case=grpc_status_both_clients_to_courierust|ok
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=10.573|rps=9458.19|p50_us=103.00|p95_us=116.80|p99_us=184.28|samples=100|min_us=92.98|mean_us=105.69|max_us=201.99|stddev_us=14.14|p999_us=201.99|tail_ratio=1.79|cv=0.13
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=13.902|rps=7193.01|p50_us=135.53|p95_us=161.54|p99_us=183.65|samples=100|min_us=121.49|mean_us=138.99|max_us=191.75|stddev_us=11.72|p999_us=191.75|tail_ratio=1.36|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=13.887|rps=7200.87|p50_us=136.97|p95_us=164.67|p99_us=173.50|samples=100|min_us=120.03|mean_us=138.83|max_us=218.58|stddev_us=13.48|p999_us=218.58|tail_ratio=1.27|cv=0.10
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=10.367|rps=9646.45|p50_us=99.76|p95_us=123.11|p99_us=160.75|samples=100|min_us=92.08|mean_us=103.64|max_us=182.06|stddev_us=13.88|p999_us=182.06|tail_ratio=1.61|cv=0.13
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=10.356|rps=9656.29|p50_us=100.66|p95_us=123.38|p99_us=137.14|samples=100|min_us=93.33|mean_us=103.53|max_us=149.86|stddev_us=9.66|p999_us=149.86|tail_ratio=1.36|cv=0.09
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=14.071|rps=7106.80|p50_us=136.86|p95_us=170.73|p99_us=187.83|samples=100|min_us=120.27|mean_us=140.67|max_us=215.56|stddev_us=14.23|p999_us=215.56|tail_ratio=1.37|cv=0.10
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=14.257|rps=7014.19|p50_us=137.56|p95_us=165.84|p99_us=194.47|samples=100|min_us=123.75|mean_us=142.53|max_us=212.13|stddev_us=13.45|p999_us=212.13|tail_ratio=1.41|cv=0.09
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=10.298|rps=9710.32|p50_us=100.19|p95_us=115.52|p99_us=143.61|samples=100|min_us=95.21|mean_us=102.96|max_us=149.66|stddev_us=8.88|p999_us=149.66|tail_ratio=1.43|cv=0.09
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=11.207|rps=8922.62|p50_us=108.50|p95_us=137.58|p99_us=153.06|samples=100|min_us=96.96|mean_us=112.04|max_us=175.80|stddev_us=11.68|p999_us=175.80|tail_ratio=1.41|cv=0.10
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=15.004|rps=6664.90|p50_us=147.36|p95_us=167.43|p99_us=209.85|samples=100|min_us=127.74|mean_us=150.00|max_us=241.46|stddev_us=16.11|p999_us=241.46|tail_ratio=1.42|cv=0.11
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=14.732|rps=6787.75|p50_us=144.00|p95_us=166.91|p99_us=196.08|samples=100|min_us=129.69|mean_us=147.29|max_us=206.34|stddev_us=13.04|p999_us=206.34|tail_ratio=1.36|cv=0.09
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=11.489|rps=8703.60|p50_us=111.85|p95_us=134.70|p99_us=157.69|samples=100|min_us=103.74|mean_us=114.87|max_us=158.31|stddev_us=10.49|p999_us=158.31|tail_ratio=1.41|cv=0.09
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=11.291|rps=8856.60|p50_us=109.06|p95_us=137.19|p99_us=155.69|samples=100|min_us=98.31|mean_us=112.87|max_us=170.41|stddev_us=11.97|p999_us=170.41|tail_ratio=1.43|cv=0.11
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=14.768|rps=6771.29|p50_us=143.81|p95_us=172.97|p99_us=200.64|samples=100|min_us=128.48|mean_us=147.64|max_us=216.59|stddev_us=14.06|p999_us=216.59|tail_ratio=1.40|cv=0.10
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=14.347|rps=6970.25|p50_us=140.32|p95_us=164.28|p99_us=171.49|samples=100|min_us=127.35|mean_us=143.43|max_us=173.61|stddev_us=8.88|p999_us=173.61|tail_ratio=1.22|cv=0.06
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=11.532|rps=8671.68|p50_us=113.11|p95_us=129.16|p99_us=152.48|samples=100|min_us=104.57|mean_us=115.29|max_us=160.19|stddev_us=8.28|p999_us=160.19|tail_ratio=1.35|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=16.594|rps=6026.30|p50_us=162.66|p95_us=185.86|p99_us=203.04|samples=100|min_us=149.47|mean_us=165.90|max_us=226.57|stddev_us=11.62|p999_us=226.57|tail_ratio=1.25|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=14.841|rps=6738.20|p50_us=146.37|p95_us=172.63|p99_us=196.41|samples=100|min_us=130.59|mean_us=148.37|max_us=202.40|stddev_us=13.14|p999_us=202.40|tail_ratio=1.34|cv=0.09
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=14.672|rps=6815.79|p50_us=142.95|p95_us=169.26|p99_us=208.28|samples=100|min_us=123.41|mean_us=146.68|max_us=239.61|stddev_us=15.43|p999_us=239.61|tail_ratio=1.46|cv=0.11
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=16.362|rps=6111.60|p50_us=159.31|p95_us=197.12|p99_us=225.56|samples=100|min_us=144.00|mean_us=163.59|max_us=231.91|stddev_us=16.55|p999_us=231.91|tail_ratio=1.42|cv=0.10
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=15.461|rps=6467.84|p50_us=150.61|p95_us=188.22|p99_us=211.24|samples=100|min_us=139.27|mean_us=154.58|max_us=244.42|stddev_us=15.71|p999_us=244.42|tail_ratio=1.40|cv=0.10
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=14.412|rps=6938.56|p50_us=139.61|p95_us=161.33|p99_us=210.21|samples=100|min_us=134.51|mean_us=144.09|max_us=228.35|stddev_us=14.92|p999_us=228.35|tail_ratio=1.51|cv=0.10
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=14.584|rps=6856.93|p50_us=142.26|p95_us=166.66|p99_us=199.31|samples=100|min_us=127.72|mean_us=145.80|max_us=215.69|stddev_us=13.51|p999_us=215.69|tail_ratio=1.40|cv=0.09
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=15.456|rps=6470.08|p50_us=150.53|p95_us=182.98|p99_us=224.49|samples=100|min_us=140.28|mean_us=154.53|max_us=226.96|stddev_us=14.33|p999_us=226.96|tail_ratio=1.49|cv=0.09
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=16.342|rps=6119.14|p50_us=159.42|p95_us=188.24|p99_us=207.75|samples=100|min_us=144.70|mean_us=163.39|max_us=283.75|stddev_us=16.96|p999_us=283.75|tail_ratio=1.30|cv=0.10
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=14.389|rps=6949.82|p50_us=140.39|p95_us=163.72|p99_us=205.40|samples=100|min_us=131.77|mean_us=143.85|max_us=213.24|stddev_us=12.48|p999_us=213.24|tail_ratio=1.46|cv=0.09
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=14.442|rps=6924.43|p50_us=142.42|p95_us=167.11|p99_us=190.31|samples=100|min_us=122.02|mean_us=144.38|max_us=239.62|stddev_us=15.17|p999_us=239.62|tail_ratio=1.34|cv=0.11
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=23.872|rps=4188.98|p50_us=167.35|p95_us=702.89|p99_us=839.95|samples=100|min_us=146.62|mean_us=238.69|max_us=874.10|stddev_us=172.09|p999_us=874.10|tail_ratio=5.02|cv=0.72
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=16.182|rps=6179.57|p50_us=159.84|p95_us=187.56|p99_us=198.61|samples=100|min_us=140.02|mean_us=161.79|max_us=202.12|stddev_us=11.83|p999_us=202.12|tail_ratio=1.24|cv=0.07
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=14.830|rps=6743.29|p50_us=143.17|p95_us=174.13|p99_us=193.84|samples=100|min_us=122.72|mean_us=148.25|max_us=212.33|stddev_us=14.38|p999_us=212.33|tail_ratio=1.35|cv=0.10
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=14.502|rps=6895.67|p50_us=143.20|p95_us=163.18|p99_us=179.29|samples=100|min_us=124.53|mean_us=144.98|max_us=179.76|stddev_us=10.94|p999_us=179.76|tail_ratio=1.25|cv=0.08
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=16.022|rps=6241.29|p50_us=158.04|p95_us=183.60|p99_us=208.34|samples=100|min_us=143.11|mean_us=160.18|max_us=216.21|stddev_us=12.99|p999_us=216.21|tail_ratio=1.32|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=16.938|rps=5903.75|p50_us=164.18|p95_us=202.74|p99_us=241.32|samples=100|min_us=153.73|mean_us=169.35|max_us=341.30|stddev_us=23.11|p999_us=341.30|tail_ratio=1.47|cv=0.14
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=19.773|rps=5057.33|p50_us=192.62|p95_us=224.08|p99_us=238.94|samples=100|min_us=181.63|mean_us=197.69|max_us=259.05|stddev_us=12.99|p999_us=259.05|tail_ratio=1.24|cv=0.07
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=23.647|rps=4228.86|p50_us=233.66|p95_us=269.58|p99_us=304.00|samples=100|min_us=190.64|mean_us=236.42|max_us=316.49|stddev_us=20.45|p999_us=316.49|tail_ratio=1.30|cv=0.09
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=19.163|rps=5218.37|p50_us=188.73|p95_us=223.16|p99_us=255.36|samples=100|min_us=158.23|mean_us=191.58|max_us=325.91|stddev_us=21.77|p999_us=325.91|tail_ratio=1.35|cv=0.11
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=20.231|rps=4942.95|p50_us=191.55|p95_us=247.66|p99_us=345.90|samples=100|min_us=164.36|mean_us=202.26|max_us=609.00|stddev_us=50.07|p999_us=609.00|tail_ratio=1.81|cv=0.25
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=24.219|rps=4129.06|p50_us=234.65|p95_us=292.74|p99_us=356.25|samples=100|min_us=199.76|mean_us=242.13|max_us=383.41|stddev_us=30.41|p999_us=383.41|tail_ratio=1.52|cv=0.13
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=24.298|rps=4115.58|p50_us=236.85|p95_us=294.46|p99_us=316.72|samples=100|min_us=198.49|mean_us=242.93|max_us=321.30|stddev_us=23.50|p999_us=321.30|tail_ratio=1.34|cv=0.10
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=19.985|rps=5003.64|p50_us=195.41|p95_us=231.08|p99_us=269.23|samples=100|min_us=172.80|mean_us=199.81|max_us=317.47|stddev_us=20.05|p999_us=317.47|tail_ratio=1.38|cv=0.10
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=26.214|rps=3814.82|p50_us=252.57|p95_us=325.18|p99_us=396.13|samples=100|min_us=214.34|mean_us=262.09|max_us=402.80|stddev_us=35.18|p999_us=402.80|tail_ratio=1.57|cv=0.13
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=27.349|rps=3656.49|p50_us=267.63|p95_us=315.96|p99_us=325.17|samples=100|min_us=240.26|mean_us=273.43|max_us=341.99|stddev_us=19.08|p999_us=341.99|tail_ratio=1.21|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=27.133|rps=3685.50|p50_us=268.72|p95_us=300.14|p99_us=317.45|samples=100|min_us=229.12|mean_us=271.29|max_us=375.01|stddev_us=18.35|p999_us=375.01|tail_ratio=1.18|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=22.913|rps=4364.28|p50_us=229.40|p95_us=252.32|p99_us=270.12|samples=100|min_us=202.69|mean_us=229.09|max_us=281.29|stddev_us=17.33|p999_us=281.29|tail_ratio=1.18|cv=0.08
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=23.226|rps=4305.56|p50_us=230.65|p95_us=257.21|p99_us=288.06|samples=100|min_us=204.01|mean_us=232.22|max_us=289.90|stddev_us=16.09|p999_us=289.90|tail_ratio=1.25|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=27.292|rps=3664.03|p50_us=272.28|p95_us=301.53|p99_us=314.88|samples=100|min_us=235.05|mean_us=272.88|max_us=319.34|stddev_us=15.93|p999_us=319.34|tail_ratio=1.16|cv=0.06
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=27.719|rps=3607.58|p50_us=275.17|p95_us=301.38|p99_us=313.43|samples=100|min_us=245.64|mean_us=277.15|max_us=317.95|stddev_us=13.83|p999_us=317.95|tail_ratio=1.14|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=23.790|rps=4203.43|p50_us=236.52|p95_us=270.04|p99_us=282.90|samples=100|min_us=201.09|mean_us=237.87|max_us=304.24|stddev_us=16.34|p999_us=304.24|tail_ratio=1.20|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=70.714|rps=1414.15|p50_us=724.99|p95_us=771.90|p99_us=781.70|samples=100|min_us=545.26|mean_us=707.09|max_us=791.50|stddev_us=66.66|p999_us=791.50|tail_ratio=1.08|cv=0.09
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=64.745|rps=1544.52|p50_us=621.80|p95_us=756.30|p99_us=773.48|samples=100|min_us=550.63|mean_us=647.40|max_us=775.03|stddev_us=70.34|p999_us=775.03|tail_ratio=1.24|cv=0.11
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=65.397|rps=1529.12|p50_us=624.27|p95_us=767.66|p99_us=774.20|samples=100|min_us=578.94|mean_us=653.92|max_us=777.13|stddev_us=65.36|p999_us=777.13|tail_ratio=1.24|cv=0.10
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=70.127|rps=1425.98|p50_us=732.94|p95_us=776.11|p99_us=787.82|samples=100|min_us=542.47|mean_us=701.22|max_us=789.88|stddev_us=80.61|p999_us=789.88|tail_ratio=1.07|cv=0.11
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=69.901|rps=1430.60|p50_us=719.49|p95_us=751.94|p99_us=763.75|samples=100|min_us=538.26|mean_us=698.97|max_us=770.49|stddev_us=64.37|p999_us=770.49|tail_ratio=1.06|cv=0.09
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=65.164|rps=1534.59|p50_us=619.37|p95_us=759.13|p99_us=767.33|samples=100|min_us=551.88|mean_us=651.59|max_us=768.15|stddev_us=69.57|p999_us=768.15|tail_ratio=1.24|cv=0.11
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=62.321|rps=1604.61|p50_us=598.06|p95_us=757.75|p99_us=767.12|samples=100|min_us=556.54|mean_us=623.16|max_us=774.91|stddev_us=61.03|p999_us=774.91|tail_ratio=1.28|cv=0.10
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=68.305|rps=1464.02|p50_us=717.71|p95_us=766.60|p99_us=781.59|samples=100|min_us=538.01|mean_us=683.00|max_us=789.31|stddev_us=78.74|p999_us=789.31|tail_ratio=1.09|cv=0.12
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=74.099|rps=1349.55|p50_us=775.71|p95_us=837.27|p99_us=844.49|samples=100|min_us=607.19|mean_us=740.94|max_us=848.92|stddev_us=79.62|p999_us=848.92|tail_ratio=1.09|cv=0.11
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=69.821|rps=1432.23|p50_us=663.77|p95_us=814.07|p99_us=826.22|samples=100|min_us=604.65|mean_us=698.16|max_us=826.89|stddev_us=71.45|p999_us=826.89|tail_ratio=1.24|cv=0.10
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=69.851|rps=1431.62|p50_us=659.28|p95_us=823.92|p99_us=834.17|samples=100|min_us=609.65|mean_us=698.46|max_us=846.43|stddev_us=74.92|p999_us=846.43|tail_ratio=1.27|cv=0.11
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=76.596|rps=1305.56|p50_us=764.38|p95_us=795.04|p99_us=843.89|samples=100|min_us=623.06|mean_us=765.90|max_us=850.61|stddev_us=25.16|p999_us=850.61|tail_ratio=1.10|cv=0.03
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=75.905|rps=1317.43|p50_us=776.82|p95_us=828.26|p99_us=838.65|samples=100|min_us=608.50|mean_us=759.00|max_us=851.73|stddev_us=66.36|p999_us=851.73|tail_ratio=1.08|cv=0.09
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=67.959|rps=1471.47|p50_us=652.92|p95_us=806.19|p99_us=834.75|samples=100|min_us=609.20|mean_us=679.53|max_us=835.74|stddev_us=65.00|p999_us=835.74|tail_ratio=1.28|cv=0.10
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=69.520|rps=1438.43|p50_us=658.20|p95_us=810.08|p99_us=839.16|samples=100|min_us=607.03|mean_us=695.15|max_us=860.23|stddev_us=70.53|p999_us=860.23|tail_ratio=1.27|cv=0.10
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=72.709|rps=1375.35|p50_us=768.24|p95_us=809.49|p99_us=854.05|samples=100|min_us=586.17|mean_us=727.04|max_us=867.97|stddev_us=80.38|p999_us=867.97|tail_ratio=1.11|cv=0.11
~~~

### tls.log
~~~text
META|suite=tls|layer=tls_over_tcp|alpn=courierust-benchmark|verify=true|resumption=disabled|certificate=bench_h3_p256|courierust_clienthello=chrome_profile_with_pinned_crypto|rustls_provider=aws_lc_rs|nodelay=true|timeout_s=5|connections=1|load=closed_loop|validation=negotiated_parameters_and_full_payload|order=alternating
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=192.662|rps=519.04|p50_us=1695.10|p95_us=2943.70|p99_us=3875.16|samples=100|min_us=1642.64|mean_us=1926.51|max_us=4053.60|stddev_us=473.32|p999_us=4053.60|tail_ratio=2.29|cv=0.25
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=28.005|rps=3570.83|p50_us=279.07|p95_us=298.55|p99_us=306.30|samples=100|min_us=266.59|mean_us=280.02|max_us=309.71|stddev_us=9.87|p999_us=309.71|tail_ratio=1.10|cv=0.04
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=28.539|rps=3503.93|p50_us=279.56|p95_us=315.16|p99_us=330.49|samples=100|min_us=268.50|mean_us=285.36|max_us=343.29|stddev_us=15.31|p999_us=343.29|tail_ratio=1.18|cv=0.05
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=169.258|rps=590.82|p50_us=1684.77|p95_us=1739.66|p99_us=1749.24|samples=100|min_us=1662.23|mean_us=1692.53|max_us=1786.30|stddev_us=23.02|p999_us=1786.30|tail_ratio=1.04|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=168.711|rps=592.73|p50_us=1681.54|p95_us=1727.34|p99_us=1754.58|samples=100|min_us=1655.61|mean_us=1687.07|max_us=1814.11|stddev_us=23.26|p999_us=1814.11|tail_ratio=1.04|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=29.341|rps=3408.22|p50_us=283.24|p95_us=328.48|p99_us=361.42|samples=100|min_us=270.89|mean_us=293.37|max_us=810.43|stddev_us=54.57|p999_us=810.43|tail_ratio=1.28|cv=0.19
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=30.203|rps=3310.97|p50_us=301.07|p95_us=325.03|p99_us=328.48|samples=100|min_us=273.08|mean_us=301.99|max_us=333.40|stddev_us=13.59|p999_us=333.40|tail_ratio=1.09|cv=0.04
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=169.835|rps=588.81|p50_us=1694.25|p95_us=1737.20|p99_us=1753.14|samples=100|min_us=1659.97|mean_us=1698.30|max_us=1759.42|stddev_us=19.13|p999_us=1759.42|tail_ratio=1.03|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=3.161|rps=31630.57|p50_us=30.76|p95_us=34.97|p99_us=44.86|samples=100|min_us=30.07|mean_us=31.59|max_us=47.70|stddev_us=3.02|p999_us=47.70|tail_ratio=1.46|cv=0.10
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=2.558|rps=39094.48|p50_us=25.32|p95_us=26.88|p99_us=36.97|samples=100|min_us=22.53|mean_us=25.55|max_us=49.24|stddev_us=3.04|p999_us=49.24|tail_ratio=1.46|cv=0.12
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=2.329|rps=42929.68|p50_us=23.00|p95_us=24.32|p99_us=27.79|samples=100|min_us=22.26|mean_us=23.27|max_us=35.03|stddev_us=1.45|p999_us=35.03|tail_ratio=1.21|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=3.125|rps=31998.32|p50_us=30.67|p95_us=32.75|p99_us=43.62|samples=100|min_us=30.09|mean_us=31.22|max_us=43.64|stddev_us=2.28|p999_us=43.64|tail_ratio=1.42|cv=0.07
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3.099|rps=32264.14|p50_us=30.63|p95_us=32.84|p99_us=35.85|samples=100|min_us=29.96|mean_us=30.97|max_us=43.20|stddev_us=1.56|p999_us=43.20|tail_ratio=1.17|cv=0.05
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=2.325|rps=43002.71|p50_us=22.87|p95_us=24.58|p99_us=33.62|samples=100|min_us=22.18|mean_us=23.23|max_us=35.92|stddev_us=1.79|p999_us=35.92|tail_ratio=1.47|cv=0.08
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=2.373|rps=42137.77|p50_us=22.84|p95_us=26.81|p99_us=37.07|samples=100|min_us=22.27|mean_us=23.71|max_us=41.25|stddev_us=2.80|p999_us=41.25|tail_ratio=1.62|cv=0.12
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3.105|rps=32202.86|p50_us=30.42|p95_us=35.14|p99_us=41.60|samples=100|min_us=29.84|mean_us=31.02|max_us=47.17|stddev_us=2.41|p999_us=47.17|tail_ratio=1.37|cv=0.08
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=36.533|rps=2737.26|p50_us=363.10|p95_us=377.18|p99_us=382.86|samples=100|min_us=357.33|mean_us=365.30|max_us=388.35|stddev_us=6.03|p999_us=388.35|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=6.611|rps=15125.93|p50_us=64.88|p95_us=75.28|p99_us=88.92|samples=100|min_us=62.90|mean_us=66.08|max_us=89.28|stddev_us=4.51|p999_us=89.28|tail_ratio=1.37|cv=0.07
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=7.038|rps=14209.53|p50_us=65.44|p95_us=77.98|p99_us=104.31|samples=100|min_us=63.94|mean_us=70.35|max_us=391.60|stddev_us=32.77|p999_us=391.60|tail_ratio=1.59|cv=0.47
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=36.581|rps=2733.65|p50_us=363.27|p95_us=374.90|p99_us=382.07|samples=100|min_us=357.36|mean_us=365.78|max_us=406.67|stddev_us=6.81|p999_us=406.67|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=36.383|rps=2748.53|p50_us=361.07|p95_us=371.18|p99_us=384.04|samples=100|min_us=355.66|mean_us=363.80|max_us=384.10|stddev_us=5.41|p999_us=384.10|tail_ratio=1.06|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=6.621|rps=15104.10|p50_us=65.26|p95_us=71.17|p99_us=77.62|samples=100|min_us=63.43|mean_us=66.18|max_us=79.60|stddev_us=2.78|p999_us=79.60|tail_ratio=1.19|cv=0.04
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=6.694|rps=14939.11|p50_us=65.80|p95_us=79.44|p99_us=80.99|samples=100|min_us=64.42|mean_us=66.91|max_us=82.92|stddev_us=3.80|p999_us=82.92|tail_ratio=1.23|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=36.410|rps=2746.51|p50_us=361.85|p95_us=375.79|p99_us=376.73|samples=100|min_us=357.74|mean_us=364.07|max_us=377.13|stddev_us=5.55|p999_us=377.13|tail_ratio=1.04|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=236.798|rps=422.30|p50_us=2365.33|p95_us=2393.85|p99_us=2421.12|samples=100|min_us=2345.81|mean_us=2367.94|max_us=2433.02|stddev_us=15.15|p999_us=2433.02|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=97.853|rps=1021.94|p50_us=974.44|p95_us=1006.49|p99_us=1021.72|samples=100|min_us=950.18|mean_us=978.49|max_us=1041.02|stddev_us=18.23|p999_us=1041.02|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=99.604|rps=1003.98|p50_us=990.09|p95_us=1025.61|p99_us=1048.24|samples=100|min_us=972.14|mean_us=995.99|max_us=1091.17|stddev_us=18.66|p999_us=1091.17|tail_ratio=1.06|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=248.985|rps=401.63|p50_us=2384.42|p95_us=3011.10|p99_us=4870.80|samples=100|min_us=2337.76|mean_us=2489.81|max_us=5187.08|stddev_us=437.65|p999_us=5187.08|tail_ratio=2.04|cv=0.18
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=239.095|rps=418.24|p50_us=2373.32|p95_us=2458.13|p99_us=2631.97|samples=100|min_us=2336.01|mean_us=2390.91|max_us=2706.09|stddev_us=60.86|p999_us=2706.09|tail_ratio=1.11|cv=0.03
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=100.756|rps=992.50|p50_us=1005.45|p95_us=1042.55|p99_us=1060.13|samples=100|min_us=982.29|mean_us=1007.50|max_us=1080.57|stddev_us=18.11|p999_us=1080.57|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=100.064|rps=999.36|p50_us=1002.67|p95_us=1021.25|p99_us=1023.38|samples=100|min_us=976.49|mean_us=1000.59|max_us=1027.69|stddev_us=12.89|p999_us=1027.69|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=237.161|rps=421.65|p50_us=2363.82|p95_us=2437.32|p99_us=2514.66|samples=100|min_us=2307.21|mean_us=2371.56|max_us=2601.96|stddev_us=42.40|p999_us=2601.96|tail_ratio=1.06|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=3.857|rps=25925.13|p50_us=37.94|p95_us=42.33|p99_us=49.95|samples=100|min_us=37.37|mean_us=38.55|max_us=60.63|stddev_us=2.82|p999_us=60.63|tail_ratio=1.32|cv=0.07
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=3.062|rps=32661.19|p50_us=30.04|p95_us=32.36|p99_us=41.28|samples=100|min_us=29.50|mean_us=30.59|max_us=53.70|stddev_us=2.76|p999_us=53.70|tail_ratio=1.37|cv=0.09
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=3.091|rps=32357.20|p50_us=30.44|p95_us=32.27|p99_us=44.26|samples=100|min_us=29.75|mean_us=30.88|max_us=46.64|stddev_us=2.26|p999_us=46.64|tail_ratio=1.45|cv=0.07
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4.145|rps=24127.34|p50_us=40.65|p95_us=46.15|p99_us=52.39|samples=100|min_us=40.03|mean_us=41.42|max_us=56.55|stddev_us=2.70|p999_us=56.55|tail_ratio=1.29|cv=0.07
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3.905|rps=25606.99|p50_us=38.44|p95_us=42.88|p99_us=49.43|samples=100|min_us=37.78|mean_us=39.02|max_us=52.83|stddev_us=2.33|p999_us=52.83|tail_ratio=1.29|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3.131|rps=31941.21|p50_us=30.85|p95_us=32.53|p99_us=41.04|samples=100|min_us=30.14|mean_us=31.28|max_us=44.75|stddev_us=2.02|p999_us=44.75|tail_ratio=1.33|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3.356|rps=29801.53|p50_us=33.09|p95_us=35.74|p99_us=45.28|samples=100|min_us=32.38|mean_us=33.52|max_us=46.48|stddev_us=2.02|p999_us=46.48|tail_ratio=1.37|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3.997|rps=25018.71|p50_us=38.73|p95_us=45.65|p99_us=55.06|samples=100|min_us=37.95|mean_us=39.94|max_us=59.60|stddev_us=3.36|p999_us=59.60|tail_ratio=1.42|cv=0.08
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=65.518|rps=1526.29|p50_us=654.73|p95_us=663.48|p99_us=669.09|samples=100|min_us=641.44|mean_us=655.15|max_us=695.44|stddev_us=7.28|p999_us=695.44|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=36.756|rps=2720.66|p50_us=364.03|p95_us=377.72|p99_us=383.77|samples=100|min_us=359.82|mean_us=367.53|max_us=430.62|stddev_us=8.51|p999_us=430.62|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=37.792|rps=2646.07|p50_us=372.27|p95_us=390.05|p99_us=415.88|samples=100|min_us=368.27|mean_us=377.89|max_us=422.46|stddev_us=9.72|p999_us=422.46|tail_ratio=1.12|cv=0.03
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=66.108|rps=1512.68|p50_us=661.21|p95_us=669.01|p99_us=670.59|samples=100|min_us=648.65|mean_us=661.05|max_us=672.39|stddev_us=5.25|p999_us=672.39|tail_ratio=1.01|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=66.155|rps=1511.59|p50_us=661.66|p95_us=668.69|p99_us=700.61|samples=100|min_us=650.36|mean_us=661.53|max_us=708.36|stddev_us=8.25|p999_us=708.36|tail_ratio=1.06|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=36.467|rps=2742.22|p50_us=363.01|p95_us=375.94|p99_us=376.86|samples=100|min_us=357.15|mean_us=364.64|max_us=378.39|stddev_us=5.57|p999_us=378.39|tail_ratio=1.04|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=37.535|rps=2664.18|p50_us=371.11|p95_us=385.71|p99_us=388.02|samples=100|min_us=367.27|mean_us=375.32|max_us=388.75|stddev_us=6.97|p999_us=388.75|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=72.272|rps=1383.67|p50_us=662.55|p95_us=1248.76|p99_us=1607.10|samples=100|min_us=649.03|mean_us=722.69|max_us=1759.79|stddev_us=214.87|p999_us=1759.79|tail_ratio=2.43|cv=0.30
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=123.134|rps=812.12|p50_us=1218.33|p95_us=1296.54|p99_us=1421.04|samples=100|min_us=1195.82|mean_us=1231.29|max_us=1445.49|stddev_us=41.58|p999_us=1445.49|tail_ratio=1.17|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=25.411|rps=3935.36|p50_us=247.15|p95_us=282.21|p99_us=333.07|samples=100|min_us=232.69|mean_us=254.07|max_us=342.49|stddev_us=20.36|p999_us=342.49|tail_ratio=1.35|cv=0.08
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=24.831|rps=4027.19|p50_us=244.58|p95_us=275.24|p99_us=284.18|samples=100|min_us=232.97|mean_us=248.27|max_us=311.54|stddev_us=14.40|p999_us=311.54|tail_ratio=1.16|cv=0.06
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=124.286|rps=804.59|p50_us=1242.21|p95_us=1285.56|p99_us=1303.68|samples=100|min_us=1195.64|mean_us=1242.81|max_us=1377.43|stddev_us=27.18|p999_us=1377.43|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=123.256|rps=811.32|p50_us=1225.55|p95_us=1272.85|p99_us=1292.09|samples=100|min_us=1194.64|mean_us=1232.51|max_us=1306.43|stddev_us=23.01|p999_us=1306.43|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=24.717|rps=4045.78|p50_us=241.23|p95_us=274.38|p99_us=287.84|samples=100|min_us=234.76|mean_us=247.14|max_us=294.62|stddev_us=12.29|p999_us=294.62|tail_ratio=1.19|cv=0.05
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=26.384|rps=3790.15|p50_us=248.44|p95_us=290.27|p99_us=676.48|samples=100|min_us=235.88|mean_us=263.80|max_us=727.09|stddev_us=66.95|p999_us=727.09|tail_ratio=2.72|cv=0.25
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=125.515|rps=796.72|p50_us=1250.09|p95_us=1296.73|p99_us=1315.23|samples=100|min_us=1219.75|mean_us=1255.10|max_us=1345.88|stddev_us=24.21|p999_us=1345.88|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=2.931|rps=34114.31|p50_us=28.53|p95_us=32.31|p99_us=44.94|samples=100|min_us=27.80|mean_us=29.29|max_us=47.50|stddev_us=2.94|p999_us=47.50|tail_ratio=1.57|cv=0.10
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=2.431|rps=41138.14|p50_us=23.67|p95_us=27.56|p99_us=34.22|samples=100|min_us=22.93|mean_us=24.28|max_us=40.13|stddev_us=2.42|p999_us=40.13|tail_ratio=1.45|cv=0.10
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=2.441|rps=40971.35|p50_us=23.80|p95_us=26.15|p99_us=36.30|samples=100|min_us=23.14|mean_us=24.38|max_us=38.78|stddev_us=2.34|p999_us=38.78|tail_ratio=1.53|cv=0.10
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=2.920|rps=34241.96|p50_us=28.61|p95_us=30.32|p99_us=42.91|samples=100|min_us=28.00|mean_us=29.18|max_us=44.22|stddev_us=2.45|p999_us=44.22|tail_ratio=1.50|cv=0.08
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=2.909|rps=34381.07|p50_us=28.63|p95_us=31.15|p99_us=36.23|samples=100|min_us=28.08|mean_us=29.06|max_us=42.30|stddev_us=1.82|p999_us=42.30|tail_ratio=1.27|cv=0.06
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=2.413|rps=41449.28|p50_us=23.58|p95_us=25.40|p99_us=35.55|samples=100|min_us=22.97|mean_us=24.10|max_us=37.14|stddev_us=2.21|p999_us=37.14|tail_ratio=1.51|cv=0.09
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=2.410|rps=41485.81|p50_us=23.61|p95_us=25.62|p99_us=33.75|samples=100|min_us=22.93|mean_us=24.08|max_us=36.70|stddev_us=1.98|p999_us=36.70|tail_ratio=1.43|cv=0.08
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=2.886|rps=34652.65|p50_us=28.28|p95_us=30.96|p99_us=40.83|samples=100|min_us=27.71|mean_us=28.83|max_us=41.99|stddev_us=2.34|p999_us=41.99|tail_ratio=1.44|cv=0.08
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=35.652|rps=2804.93|p50_us=354.74|p95_us=367.11|p99_us=371.34|samples=100|min_us=349.37|mean_us=356.49|max_us=375.52|stddev_us=5.42|p999_us=375.52|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=6.886|rps=14521.36|p50_us=66.15|p95_us=77.60|p99_us=85.88|samples=100|min_us=64.86|mean_us=68.84|max_us=87.09|stddev_us=4.75|p999_us=87.09|tail_ratio=1.30|cv=0.07
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=6.661|rps=15012.15|p50_us=65.47|p95_us=77.65|p99_us=82.05|samples=100|min_us=63.49|mean_us=66.58|max_us=84.76|stddev_us=3.85|p999_us=84.76|tail_ratio=1.25|cv=0.06
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=35.267|rps=2835.54|p50_us=350.27|p95_us=362.55|p99_us=364.96|samples=100|min_us=343.15|mean_us=352.64|max_us=367.94|stddev_us=4.92|p999_us=367.94|tail_ratio=1.04|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=35.538|rps=2813.90|p50_us=352.78|p95_us=364.62|p99_us=370.82|samples=100|min_us=348.05|mean_us=355.35|max_us=382.21|stddev_us=5.66|p999_us=382.21|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=6.614|rps=15119.93|p50_us=65.48|p95_us=70.84|p99_us=79.65|samples=100|min_us=64.08|mean_us=66.11|max_us=80.48|stddev_us=2.78|p999_us=80.48|tail_ratio=1.22|cv=0.04
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=6.742|rps=14831.69|p50_us=66.02|p95_us=78.08|p99_us=89.13|samples=100|min_us=64.82|mean_us=67.40|max_us=101.07|stddev_us=5.18|p999_us=101.07|tail_ratio=1.35|cv=0.08
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=35.461|rps=2820.00|p50_us=352.32|p95_us=364.13|p99_us=366.61|samples=100|min_us=345.95|mean_us=354.58|max_us=366.75|stddev_us=4.78|p999_us=366.75|tail_ratio=1.04|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=151.450|rps=660.29|p50_us=1513.90|p95_us=1548.11|p99_us=1586.62|samples=100|min_us=1459.96|mean_us=1514.44|max_us=2096.58|stddev_us=63.20|p999_us=2096.58|tail_ratio=1.05|cv=0.04
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=55.338|rps=1807.06|p50_us=554.46|p95_us=581.70|p99_us=591.85|samples=100|min_us=522.88|mean_us=553.32|max_us=595.42|stddev_us=19.23|p999_us=595.42|tail_ratio=1.07|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=55.102|rps=1814.81|p50_us=553.71|p95_us=579.17|p99_us=584.26|samples=100|min_us=519.38|mean_us=550.96|max_us=592.77|stddev_us=19.41|p999_us=592.77|tail_ratio=1.06|cv=0.04
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=150.979|rps=662.35|p50_us=1512.29|p95_us=1537.43|p99_us=1542.86|samples=100|min_us=1471.33|mean_us=1509.73|max_us=1550.74|stddev_us=19.01|p999_us=1550.74|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=151.106|rps=661.79|p50_us=1504.65|p95_us=1541.17|p99_us=1558.49|samples=100|min_us=1464.39|mean_us=1511.00|max_us=1822.48|stddev_us=38.22|p999_us=1822.48|tail_ratio=1.04|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=57.014|rps=1753.96|p50_us=565.56|p95_us=635.31|p99_us=681.30|samples=100|min_us=515.05|mean_us=570.08|max_us=899.80|stddev_us=44.73|p999_us=899.80|tail_ratio=1.20|cv=0.08
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=72.479|rps=1379.71|p50_us=572.94|p95_us=1347.50|p99_us=1526.32|samples=100|min_us=511.92|mean_us=724.74|max_us=1570.33|stddev_us=275.52|p999_us=1570.33|tail_ratio=2.66|cv=0.38
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=171.703|rps=582.40|p50_us=1508.02|p95_us=3129.79|p99_us=4250.85|samples=100|min_us=1454.60|mean_us=1716.94|max_us=4374.97|stddev_us=565.57|p999_us=4374.97|tail_ratio=2.82|cv=0.33
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=3.403|rps=29387.45|p50_us=33.17|p95_us=37.73|p99_us=48.31|samples=100|min_us=32.65|mean_us=34.00|max_us=54.63|stddev_us=3.13|p999_us=54.63|tail_ratio=1.46|cv=0.09
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=2.852|rps=35066.05|p50_us=28.03|p95_us=30.46|p99_us=38.14|samples=100|min_us=27.39|mean_us=28.49|max_us=39.17|stddev_us=1.83|p999_us=39.17|tail_ratio=1.36|cv=0.06
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=2.853|rps=35049.80|p50_us=27.95|p95_us=30.64|p99_us=39.33|samples=100|min_us=27.20|mean_us=28.50|max_us=42.02|stddev_us=2.22|p999_us=42.02|tail_ratio=1.41|cv=0.08
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=3.310|rps=30207.06|p50_us=32.67|p95_us=35.41|p99_us=38.44|samples=100|min_us=32.22|mean_us=33.08|max_us=45.90|stddev_us=1.66|p999_us=45.90|tail_ratio=1.18|cv=0.05
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3.353|rps=29827.17|p50_us=32.93|p95_us=35.44|p99_us=45.63|samples=100|min_us=32.28|mean_us=33.50|max_us=58.08|stddev_us=2.91|p999_us=58.08|tail_ratio=1.39|cv=0.09
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=2.841|rps=35203.78|p50_us=27.91|p95_us=30.57|p99_us=35.79|samples=100|min_us=25.74|mean_us=28.38|max_us=43.72|stddev_us=2.02|p999_us=43.72|tail_ratio=1.28|cv=0.07
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=2.947|rps=33929.19|p50_us=28.09|p95_us=33.86|p99_us=43.49|samples=100|min_us=27.17|mean_us=29.44|max_us=50.40|stddev_us=3.39|p999_us=50.40|tail_ratio=1.55|cv=0.12
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=4.697|rps=21291.27|p50_us=32.59|p95_us=157.38|p99_us=198.50|samples=100|min_us=31.52|mean_us=46.94|max_us=220.82|stddev_us=40.89|p999_us=220.82|tail_ratio=6.09|cv=0.87
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=64.352|rps=1553.96|p50_us=642.09|p95_us=654.27|p99_us=667.74|samples=100|min_us=626.47|mean_us=643.49|max_us=683.10|stddev_us=8.47|p999_us=683.10|tail_ratio=1.04|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=36.740|rps=2721.82|p50_us=366.22|p95_us=390.37|p99_us=398.36|samples=100|min_us=348.42|mean_us=367.37|max_us=410.79|stddev_us=11.71|p999_us=410.79|tail_ratio=1.09|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=36.969|rps=2704.99|p50_us=366.37|p95_us=383.90|p99_us=424.62|samples=100|min_us=357.97|mean_us=369.66|max_us=502.68|stddev_us=15.74|p999_us=502.68|tail_ratio=1.16|cv=0.04
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=65.201|rps=1533.72|p50_us=651.46|p95_us=666.59|p99_us=668.76|samples=100|min_us=637.17|mean_us=651.98|max_us=670.07|stddev_us=7.44|p999_us=670.07|tail_ratio=1.03|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=64.694|rps=1545.75|p50_us=646.69|p95_us=655.92|p99_us=659.39|samples=100|min_us=634.20|mean_us=646.90|max_us=666.33|stddev_us=5.58|p999_us=666.33|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=36.012|rps=2776.86|p50_us=355.16|p95_us=371.38|p99_us=421.30|samples=100|min_us=351.77|mean_us=360.09|max_us=446.12|stddev_us=12.60|p999_us=446.12|tail_ratio=1.19|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=35.741|rps=2797.92|p50_us=354.88|p95_us=365.84|p99_us=386.03|samples=100|min_us=350.45|mean_us=357.38|max_us=386.57|stddev_us=6.40|p999_us=386.57|tail_ratio=1.09|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=64.286|rps=1555.56|p50_us=642.67|p95_us=651.61|p99_us=652.65|samples=100|min_us=632.77|mean_us=642.83|max_us=652.89|stddev_us=5.05|p999_us=652.89|tail_ratio=1.02|cv=0.01
~~~

### ws.log
~~~text
META|suite=ws|protocol=ws|tls=off|compression=off|connections=1|nodelay=true|timeout=none|load=closed_loop|validation=opcode_and_full_payload|order=alternating
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=22.242|rps=44960.68|p50_us=21.85|p95_us=24.67|p99_us=31.79|samples=1000|min_us=20.85|mean_us=22.20|max_us=38.73|stddev_us=1.66|p999_us=36.83|tail_ratio=1.45|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=21.391|rps=46749.46|p50_us=20.84|p95_us=24.75|p99_us=31.72|samples=1000|min_us=19.71|mean_us=21.35|max_us=36.00|stddev_us=2.05|p999_us=35.43|tail_ratio=1.52|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=30.093|rps=33230.44|p50_us=29.45|p95_us=33.96|p99_us=41.54|samples=1000|min_us=28.31|mean_us=30.07|max_us=57.05|stddev_us=2.46|p999_us=46.19|tail_ratio=1.41|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=31.382|rps=31864.95|p50_us=30.74|p95_us=35.90|p99_us=40.70|samples=1000|min_us=28.68|mean_us=31.32|max_us=50.26|stddev_us=2.25|p999_us=45.77|tail_ratio=1.32|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=22.030|rps=45392.04|p50_us=20.85|p95_us=26.39|p99_us=32.48|samples=1000|min_us=19.79|mean_us=21.99|max_us=42.14|stddev_us=2.56|p999_us=41.74|tail_ratio=1.56|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=22.647|rps=44156.30|p50_us=22.30|p95_us=24.02|p99_us=30.75|samples=1000|min_us=21.38|mean_us=22.60|max_us=36.09|stddev_us=1.48|p999_us=34.28|tail_ratio=1.38|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=22.962|rps=43550.92|p50_us=22.51|p95_us=25.89|p99_us=32.44|samples=1000|min_us=21.32|mean_us=22.92|max_us=38.65|stddev_us=1.74|p999_us=35.27|tail_ratio=1.44|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=22.011|rps=45431.83|p50_us=21.64|p95_us=22.95|p99_us=31.08|samples=1000|min_us=20.70|mean_us=21.97|max_us=58.02|stddev_us=1.98|p999_us=42.74|tail_ratio=1.44|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=31.389|rps=31858.70|p50_us=30.70|p95_us=36.94|p99_us=43.41|samples=1000|min_us=29.70|mean_us=31.36|max_us=51.54|stddev_us=2.51|p999_us=50.42|tail_ratio=1.41|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=31.954|rps=31295.40|p50_us=30.83|p95_us=35.96|p99_us=46.04|samples=1000|min_us=29.86|mean_us=31.91|max_us=292.21|stddev_us=10.10|p999_us=198.56|tail_ratio=1.49|cv=0.32
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=22.105|rps=45238.95|p50_us=21.51|p95_us=26.39|p99_us=31.26|samples=1000|min_us=17.42|mean_us=22.06|max_us=40.05|stddev_us=2.01|p999_us=36.50|tail_ratio=1.45|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=22.744|rps=43967.43|p50_us=22.35|p95_us=25.24|p99_us=32.13|samples=1000|min_us=21.51|mean_us=22.71|max_us=38.12|stddev_us=1.75|p999_us=36.87|tail_ratio=1.44|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=23.056|rps=43371.85|p50_us=22.59|p95_us=25.66|p99_us=31.93|samples=1000|min_us=20.06|mean_us=23.01|max_us=37.59|stddev_us=1.67|p999_us=35.14|tail_ratio=1.41|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=22.302|rps=44838.86|p50_us=21.45|p95_us=25.03|p99_us=31.90|samples=1000|min_us=20.46|mean_us=22.27|max_us=38.00|stddev_us=1.99|p999_us=37.35|tail_ratio=1.49|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=30.786|rps=32481.92|p50_us=30.28|p95_us=32.69|p99_us=43.09|samples=1000|min_us=28.52|mean_us=30.75|max_us=59.23|stddev_us=2.35|p999_us=45.48|tail_ratio=1.42|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=30.747|rps=32522.97|p50_us=29.77|p95_us=34.27|p99_us=41.84|samples=1000|min_us=28.50|mean_us=30.72|max_us=234.38|stddev_us=9.11|p999_us=221.83|tail_ratio=1.41|cv=0.30
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=21.402|rps=46723.97|p50_us=20.88|p95_us=24.23|p99_us=31.00|samples=1000|min_us=19.86|mean_us=21.36|max_us=39.25|stddev_us=1.95|p999_us=37.35|tail_ratio=1.48|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=22.562|rps=44322.17|p50_us=21.90|p95_us=25.40|p99_us=30.48|samples=1000|min_us=20.71|mean_us=22.52|max_us=43.46|stddev_us=1.96|p999_us=41.15|tail_ratio=1.39|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=22.907|rps=43654.39|p50_us=22.53|p95_us=24.54|p99_us=31.56|samples=1000|min_us=21.39|mean_us=22.87|max_us=40.72|stddev_us=1.66|p999_us=37.24|tail_ratio=1.40|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=23.449|rps=42645.64|p50_us=23.29|p95_us=26.89|p99_us=32.58|samples=1000|min_us=20.30|mean_us=23.42|max_us=38.79|stddev_us=2.03|p999_us=36.41|tail_ratio=1.40|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=30.896|rps=32367.14|p50_us=30.07|p95_us=36.33|p99_us=44.31|samples=1000|min_us=28.56|mean_us=30.86|max_us=54.23|stddev_us=2.76|p999_us=50.05|tail_ratio=1.47|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=30.883|rps=32379.87|p50_us=30.07|p95_us=36.58|p99_us=43.65|samples=1000|min_us=28.25|mean_us=30.85|max_us=67.87|stddev_us=2.85|p999_us=47.38|tail_ratio=1.45|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=21.557|rps=46388.34|p50_us=21.06|p95_us=23.78|p99_us=30.85|samples=1000|min_us=20.18|mean_us=21.52|max_us=83.93|stddev_us=2.55|p999_us=35.35|tail_ratio=1.46|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=22.999|rps=43479.56|p50_us=22.45|p95_us=25.64|p99_us=31.56|samples=1000|min_us=16.68|mean_us=22.96|max_us=51.23|stddev_us=2.03|p999_us=43.49|tail_ratio=1.41|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=26.051|rps=38386.45|p50_us=25.99|p95_us=27.55|p99_us=36.09|samples=1000|min_us=23.91|mean_us=26.00|max_us=39.33|stddev_us=1.87|p999_us=39.24|tail_ratio=1.39|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=24.942|rps=40093.74|p50_us=24.62|p95_us=26.08|p99_us=33.55|samples=1000|min_us=23.06|mean_us=24.89|max_us=39.84|stddev_us=1.58|p999_us=39.81|tail_ratio=1.36|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=34.150|rps=29282.97|p50_us=33.60|p95_us=37.65|p99_us=44.77|samples=1000|min_us=31.90|mean_us=34.11|max_us=51.97|stddev_us=2.31|p999_us=50.08|tail_ratio=1.33|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=34.292|rps=29161.39|p50_us=33.95|p95_us=37.60|p99_us=46.21|samples=1000|min_us=31.24|mean_us=34.25|max_us=51.00|stddev_us=2.43|p999_us=49.86|tail_ratio=1.36|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=25.401|rps=39368.96|p50_us=24.88|p95_us=27.67|p99_us=36.98|samples=1000|min_us=21.50|mean_us=25.36|max_us=76.48|stddev_us=2.56|p999_us=44.99|tail_ratio=1.49|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=25.990|rps=38475.92|p50_us=26.11|p95_us=27.65|p99_us=35.23|samples=1000|min_us=23.67|mean_us=25.95|max_us=48.90|stddev_us=2.14|p999_us=47.19|tail_ratio=1.35|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=26.101|rps=38312.20|p50_us=26.12|p95_us=28.13|p99_us=38.53|samples=1000|min_us=23.74|mean_us=26.06|max_us=44.68|stddev_us=2.32|p999_us=43.29|tail_ratio=1.48|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=26.855|rps=37237.06|p50_us=26.39|p95_us=29.88|p99_us=37.94|samples=1000|min_us=25.33|mean_us=26.83|max_us=42.89|stddev_us=2.02|p999_us=41.01|tail_ratio=1.44|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=34.309|rps=29146.99|p50_us=33.99|p95_us=36.08|p99_us=45.27|samples=1000|min_us=30.97|mean_us=34.27|max_us=64.32|stddev_us=2.39|p999_us=58.25|tail_ratio=1.33|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=33.261|rps=30065.26|p50_us=33.19|p95_us=34.83|p99_us=43.98|samples=1000|min_us=30.72|mean_us=33.22|max_us=48.69|stddev_us=2.15|p999_us=48.48|tail_ratio=1.32|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=26.070|rps=38358.94|p50_us=25.74|p95_us=28.29|p99_us=37.47|samples=1000|min_us=22.59|mean_us=26.04|max_us=48.76|stddev_us=2.27|p999_us=40.84|tail_ratio=1.46|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=25.914|rps=38589.72|p50_us=25.98|p95_us=27.50|p99_us=34.56|samples=1000|min_us=23.65|mean_us=25.88|max_us=40.69|stddev_us=1.85|p999_us=40.39|tail_ratio=1.33|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=233.454|rps=4283.50|p50_us=232.72|p95_us=247.62|p99_us=254.24|samples=1000|min_us=218.29|mean_us=233.40|max_us=259.50|stddev_us=7.49|p999_us=258.99|tail_ratio=1.09|cv=0.03
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=105.904|rps=9442.54|p50_us=106.81|p95_us=118.37|p99_us=127.39|samples=1000|min_us=81.29|mean_us=105.86|max_us=437.75|stddev_us=19.91|p999_us=384.41|tail_ratio=1.19|cv=0.19
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=107.529|rps=9299.82|p50_us=106.17|p95_us=124.30|p99_us=133.67|samples=1000|min_us=94.23|mean_us=107.49|max_us=150.11|stddev_us=8.75|p999_us=146.27|tail_ratio=1.26|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=112.617|rps=8879.67|p50_us=111.45|p95_us=128.41|p99_us=138.40|samples=1000|min_us=96.28|mean_us=112.57|max_us=221.56|stddev_us=10.22|p999_us=180.80|tail_ratio=1.24|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=105.708|rps=9459.99|p50_us=102.23|p95_us=123.62|p99_us=129.65|samples=1000|min_us=86.79|mean_us=105.67|max_us=137.46|stddev_us=10.48|p999_us=136.86|tail_ratio=1.27|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=103.155|rps=9694.11|p50_us=101.79|p95_us=111.99|p99_us=120.51|samples=1000|min_us=94.37|mean_us=103.11|max_us=133.03|stddev_us=4.64|p999_us=127.51|tail_ratio=1.18|cv=0.04
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=98.918|rps=10109.36|p50_us=98.29|p95_us=107.63|p99_us=114.61|samples=1000|min_us=90.58|mean_us=98.86|max_us=143.29|stddev_us=4.62|p999_us=137.61|tail_ratio=1.17|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=97.271|rps=10280.57|p50_us=97.05|p95_us=106.60|p99_us=116.25|samples=1000|min_us=83.36|mean_us=97.22|max_us=143.00|stddev_us=5.74|p999_us=127.44|tail_ratio=1.20|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=104.978|rps=9525.80|p50_us=103.18|p95_us=121.38|p99_us=129.04|samples=1000|min_us=94.16|mean_us=104.93|max_us=135.64|stddev_us=7.60|p999_us=135.21|tail_ratio=1.25|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=153.863|rps=6499.27|p50_us=107.13|p95_us=415.14|p99_us=648.80|samples=1000|min_us=94.20|mean_us=153.82|max_us=853.75|stddev_us=116.16|p999_us=834.11|tail_ratio=6.06|cv=0.76
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=94.081|rps=10629.15|p50_us=94.08|p95_us=101.75|p99_us=108.76|samples=1000|min_us=82.52|mean_us=94.04|max_us=117.23|stddev_us=4.94|p999_us=116.00|tail_ratio=1.16|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=96.070|rps=10409.02|p50_us=93.93|p95_us=105.53|p99_us=113.00|samples=1000|min_us=88.99|mean_us=96.03|max_us=124.89|stddev_us=4.67|p999_us=118.28|tail_ratio=1.20|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=23.437|rps=42667.39|p50_us=23.07|p95_us=24.81|p99_us=32.49|samples=1000|min_us=22.25|mean_us=23.41|max_us=42.17|stddev_us=1.72|p999_us=35.55|tail_ratio=1.41|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=22.564|rps=44317.49|p50_us=22.07|p95_us=26.35|p99_us=31.42|samples=1000|min_us=21.17|mean_us=22.54|max_us=36.75|stddev_us=1.87|p999_us=35.48|tail_ratio=1.42|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=29.713|rps=33655.65|p50_us=29.11|p95_us=33.58|p99_us=40.69|samples=1000|min_us=27.66|mean_us=29.68|max_us=92.22|stddev_us=2.91|p999_us=45.17|tail_ratio=1.40|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=30.235|rps=33074.64|p50_us=29.51|p95_us=34.01|p99_us=39.30|samples=1000|min_us=27.56|mean_us=30.19|max_us=63.90|stddev_us=2.47|p999_us=48.74|tail_ratio=1.33|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=22.881|rps=43705.25|p50_us=22.50|p95_us=26.81|p99_us=34.05|samples=1000|min_us=19.83|mean_us=22.85|max_us=38.41|stddev_us=2.22|p999_us=37.52|tail_ratio=1.51|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=21.683|rps=46119.93|p50_us=21.11|p95_us=25.38|p99_us=32.18|samples=1000|min_us=19.84|mean_us=21.65|max_us=43.98|stddev_us=2.14|p999_us=37.84|tail_ratio=1.52|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=24.646|rps=40574.38|p50_us=23.94|p95_us=30.97|p99_us=35.59|samples=1000|min_us=22.75|mean_us=24.62|max_us=54.98|stddev_us=2.53|p999_us=38.65|tail_ratio=1.49|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=21.343|rps=46853.41|p50_us=21.03|p95_us=22.47|p99_us=30.55|samples=1000|min_us=19.99|mean_us=21.30|max_us=36.17|stddev_us=1.64|p999_us=35.45|tail_ratio=1.45|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=30.124|rps=33195.72|p50_us=29.73|p95_us=31.93|p99_us=40.86|samples=1000|min_us=28.29|mean_us=30.09|max_us=44.12|stddev_us=1.93|p999_us=43.99|tail_ratio=1.37|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=29.679|rps=33693.57|p50_us=29.15|p95_us=33.43|p99_us=39.43|samples=1000|min_us=27.83|mean_us=29.65|max_us=48.36|stddev_us=2.09|p999_us=47.11|tail_ratio=1.35|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=23.559|rps=42446.63|p50_us=22.98|p95_us=27.80|p99_us=33.45|samples=1000|min_us=19.68|mean_us=23.53|max_us=39.49|stddev_us=2.18|p999_us=38.99|tail_ratio=1.46|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=25.097|rps=39844.92|p50_us=24.70|p95_us=27.07|p99_us=34.45|samples=1000|min_us=23.39|mean_us=25.07|max_us=40.55|stddev_us=1.89|p999_us=39.86|tail_ratio=1.39|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=24.049|rps=41581.88|p50_us=23.79|p95_us=27.18|p99_us=33.61|samples=1000|min_us=21.92|mean_us=24.01|max_us=41.04|stddev_us=2.04|p999_us=37.22|tail_ratio=1.41|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=22.850|rps=43762.93|p50_us=22.53|p95_us=23.85|p99_us=31.23|samples=1000|min_us=21.61|mean_us=22.82|max_us=35.87|stddev_us=1.47|p999_us=35.46|tail_ratio=1.39|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=29.586|rps=33799.94|p50_us=29.10|p95_us=32.20|p99_us=39.82|samples=1000|min_us=27.48|mean_us=29.55|max_us=47.02|stddev_us=2.01|p999_us=43.05|tail_ratio=1.37|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=30.070|rps=33255.71|p50_us=29.50|p95_us=33.86|p99_us=41.93|samples=1000|min_us=27.76|mean_us=30.03|max_us=44.92|stddev_us=2.31|p999_us=44.20|tail_ratio=1.42|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=23.479|rps=42591.18|p50_us=22.79|p95_us=27.97|p99_us=36.80|samples=1000|min_us=20.91|mean_us=23.45|max_us=43.91|stddev_us=2.60|p999_us=42.47|tail_ratio=1.61|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=22.306|rps=44831.85|p50_us=21.98|p95_us=23.59|p99_us=30.23|samples=1000|min_us=21.01|mean_us=22.27|max_us=34.46|stddev_us=1.38|p999_us=34.25|tail_ratio=1.37|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=24.394|rps=40993.08|p50_us=23.83|p95_us=28.27|p99_us=34.77|samples=1000|min_us=22.77|mean_us=24.37|max_us=59.69|stddev_us=2.25|p999_us=37.60|tail_ratio=1.46|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=20.811|rps=48050.65|p50_us=20.43|p95_us=22.68|p99_us=28.66|samples=1000|min_us=19.43|mean_us=20.77|max_us=33.34|stddev_us=1.51|p999_us=32.82|tail_ratio=1.40|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=29.908|rps=33435.63|p50_us=29.38|p95_us=32.39|p99_us=40.87|samples=1000|min_us=27.85|mean_us=29.87|max_us=60.79|stddev_us=2.35|p999_us=48.91|tail_ratio=1.39|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=30.080|rps=33245.07|p50_us=29.50|p95_us=34.70|p99_us=39.91|samples=1000|min_us=27.97|mean_us=30.05|max_us=51.14|stddev_us=2.14|p999_us=42.91|tail_ratio=1.35|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=21.272|rps=47009.33|p50_us=20.86|p95_us=23.57|p99_us=28.11|samples=1000|min_us=19.93|mean_us=21.23|max_us=31.79|stddev_us=1.44|p999_us=31.39|tail_ratio=1.35|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=22.045|rps=45361.16|p50_us=21.74|p95_us=23.58|p99_us=28.92|samples=1000|min_us=20.63|mean_us=22.01|max_us=34.95|stddev_us=1.27|p999_us=31.42|tail_ratio=1.33|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=26.102|rps=38311.71|p50_us=25.77|p95_us=27.49|p99_us=35.56|samples=1000|min_us=24.40|mean_us=26.06|max_us=47.13|stddev_us=1.74|p999_us=42.15|tail_ratio=1.38|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=25.895|rps=38616.90|p50_us=25.47|p95_us=28.43|p99_us=37.13|samples=1000|min_us=21.23|mean_us=25.86|max_us=42.30|stddev_us=2.25|p999_us=41.44|tail_ratio=1.46|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=33.639|rps=29727.13|p50_us=33.02|p95_us=37.95|p99_us=45.52|samples=1000|min_us=31.72|mean_us=33.60|max_us=52.07|stddev_us=2.33|p999_us=48.54|tail_ratio=1.38|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=33.187|rps=30132.15|p50_us=32.73|p95_us=34.63|p99_us=44.79|samples=1000|min_us=31.50|mean_us=33.15|max_us=51.13|stddev_us=2.09|p999_us=48.63|tail_ratio=1.37|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=25.499|rps=39216.93|p50_us=25.31|p95_us=26.25|p99_us=35.17|samples=1000|min_us=23.07|mean_us=25.47|max_us=40.54|stddev_us=1.73|p999_us=39.75|tail_ratio=1.39|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=25.866|rps=38661.30|p50_us=25.60|p95_us=26.61|p99_us=32.70|samples=1000|min_us=24.26|mean_us=25.83|max_us=43.27|stddev_us=1.43|p999_us=40.03|tail_ratio=1.28|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=26.352|rps=37947.35|p50_us=26.04|p95_us=27.28|p99_us=34.88|samples=1000|min_us=24.93|mean_us=26.31|max_us=37.65|stddev_us=1.44|p999_us=37.17|tail_ratio=1.34|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=24.345|rps=41076.57|p50_us=24.11|p95_us=24.94|p99_us=31.37|samples=1000|min_us=23.12|mean_us=24.31|max_us=37.23|stddev_us=1.31|p999_us=36.16|tail_ratio=1.30|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=33.640|rps=29726.39|p50_us=33.17|p95_us=34.74|p99_us=45.44|samples=1000|min_us=31.61|mean_us=33.60|max_us=67.22|stddev_us=2.34|p999_us=51.72|tail_ratio=1.37|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=33.571|rps=29787.66|p50_us=33.12|p95_us=35.35|p99_us=45.07|samples=1000|min_us=31.76|mean_us=33.54|max_us=55.40|stddev_us=2.14|p999_us=51.04|tail_ratio=1.36|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=25.955|rps=38527.97|p50_us=25.30|p95_us=28.04|p99_us=35.34|samples=1000|min_us=23.95|mean_us=25.92|max_us=42.07|stddev_us=1.96|p999_us=40.65|tail_ratio=1.40|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=26.453|rps=37802.40|p50_us=26.12|p95_us=27.50|p99_us=35.27|samples=1000|min_us=24.95|mean_us=26.41|max_us=45.15|stddev_us=1.60|p999_us=40.59|tail_ratio=1.35|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=102.424|rps=9763.34|p50_us=101.76|p95_us=111.09|p99_us=115.00|samples=1000|min_us=96.03|mean_us=102.38|max_us=132.94|stddev_us=3.65|p999_us=117.50|tail_ratio=1.13|cv=0.04
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=97.826|rps=10222.23|p50_us=96.56|p95_us=107.57|p99_us=112.65|samples=1000|min_us=90.18|mean_us=97.78|max_us=194.26|stddev_us=5.95|p999_us=175.87|tail_ratio=1.17|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=114.051|rps=8767.97|p50_us=114.05|p95_us=123.99|p99_us=133.68|samples=1000|min_us=98.80|mean_us=114.01|max_us=212.51|stddev_us=7.18|p999_us=188.25|tail_ratio=1.17|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=117.029|rps=8544.87|p50_us=115.97|p95_us=132.45|p99_us=137.84|samples=1000|min_us=97.81|mean_us=116.99|max_us=150.78|stddev_us=7.96|p999_us=142.97|tail_ratio=1.19|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=97.212|rps=10286.74|p50_us=96.81|p95_us=104.89|p99_us=109.06|samples=1000|min_us=89.28|mean_us=97.17|max_us=123.04|stddev_us=3.65|p999_us=115.47|tail_ratio=1.13|cv=0.04
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=102.049|rps=9799.24|p50_us=100.94|p95_us=111.96|p99_us=120.00|samples=1000|min_us=94.68|mean_us=102.00|max_us=131.61|stddev_us=4.70|p999_us=130.13|tail_ratio=1.19|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=102.097|rps=9794.62|p50_us=101.54|p95_us=109.87|p99_us=115.16|samples=1000|min_us=95.61|mean_us=102.05|max_us=136.87|stddev_us=3.64|p999_us=130.37|tail_ratio=1.13|cv=0.04
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=96.998|rps=10309.53|p50_us=96.70|p95_us=104.67|p99_us=109.06|samples=1000|min_us=87.50|mean_us=96.95|max_us=115.65|stddev_us=3.76|p999_us=113.76|tail_ratio=1.13|cv=0.04
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=110.240|rps=9071.16|p50_us=109.97|p95_us=126.01|p99_us=136.59|samples=1000|min_us=95.10|mean_us=110.20|max_us=142.73|stddev_us=9.42|p999_us=141.43|tail_ratio=1.24|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=106.503|rps=9389.39|p50_us=105.48|p95_us=117.76|p99_us=123.54|samples=1000|min_us=98.78|mean_us=106.46|max_us=133.46|stddev_us=5.19|p999_us=130.39|tail_ratio=1.17|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=102.286|rps=9776.54|p50_us=97.82|p95_us=117.70|p99_us=126.23|samples=1000|min_us=88.81|mean_us=102.24|max_us=136.84|stddev_us=9.35|p999_us=132.82|tail_ratio=1.29|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=113.497|rps=8810.83|p50_us=105.46|p95_us=120.08|p99_us=385.63|samples=1000|min_us=97.22|mean_us=113.45|max_us=791.73|stddev_us=53.32|p999_us=656.54|tail_ratio=3.66|cv=0.47
~~~
### Throughput
~~~text
courierust throughput suite (loopback)
META|suite=throughput|requests=4000|server_threads=4|max_samples=2048
RESULT|suite=throughput|case=h1_sequential|protocol=h1|mode=sequential|payload=empty|bytes=0|workers=1|server_threads=4|requests=4000|elapsed_ms=137.442|rps=29103.3|response_mbps=0.000|p50_us=33.62|p75_us=35.05|p90_us=36.46|p95_us=38.80|p99_us=45.69|min_us=27.37|mean_us=33.86|max_us=63.43|stddev_us=3.11|p999_us=51.64|tail_ratio=1.36|cv=0.09|samples=2000
RESULT|suite=throughput|case=h1_sequential|protocol=h1|mode=sequential|payload=1k|bytes=1024|workers=1|server_threads=4|requests=4000|elapsed_ms=136.097|rps=29390.7|response_mbps=30.096|p50_us=33.17|p75_us=34.67|p90_us=35.99|p95_us=38.77|p99_us=45.87|min_us=27.40|mean_us=33.93|max_us=107.87|stddev_us=3.56|p999_us=58.59|tail_ratio=1.38|cv=0.10|samples=2000
RESULT|suite=throughput|case=h1_sequential|protocol=h1|mode=sequential|payload=64k|bytes=65536|workers=1|server_threads=4|requests=4000|elapsed_ms=174.255|rps=22954.8|response_mbps=1504.368|p50_us=42.86|p75_us=44.62|p90_us=48.60|p95_us=50.29|p99_us=55.44|min_us=38.83|mean_us=43.28|max_us=71.86|stddev_us=3.72|p999_us=60.85|tail_ratio=1.29|cv=0.09|samples=2000
RESULT|suite=throughput|case=h1_parallel_w1|protocol=h1|mode=parallel|payload=1k|bytes=1024|workers=1|server_threads=4|requests=4000|elapsed_ms=138.801|rps=28818.2|response_mbps=29.510|p50_us=35.19|p75_us=36.41|p90_us=38.42|p95_us=40.57|p99_us=47.35|min_us=25.75|mean_us=35.31|max_us=61.17|stddev_us=3.23|p999_us=55.58|tail_ratio=1.35|cv=0.09|samples=2000
RESULT|suite=throughput|case=h1_parallel_w4|protocol=h1|mode=parallel|payload=1k|bytes=1024|workers=4|server_threads=4|requests=4000|elapsed_ms=53.207|rps=75177.6|response_mbps=76.982|p50_us=37.53|p75_us=52.66|p90_us=77.77|p95_us=94.48|p99_us=243.54|min_us=17.74|mean_us=47.10|max_us=939.31|stddev_us=51.56|p999_us=769.02|tail_ratio=6.49|cv=1.09|samples=2000
RESULT|suite=throughput|case=h1_parallel_w8|protocol=h1|mode=parallel|payload=1k|bytes=1024|workers=8|server_threads=8|requests=4000|elapsed_ms=51.351|rps=77895.1|response_mbps=79.765|p50_us=65.30|p75_us=107.19|p90_us=144.74|p95_us=184.31|p99_us=471.47|min_us=17.86|mean_us=87.95|max_us=3128.87|stddev_us=149.75|p999_us=2499.46|tail_ratio=7.22|cv=1.70|samples=2000
RESULT|suite=throughput|case=h2_multiplex_w1|protocol=h2c|mode=multiplex|payload=1k|bytes=1024|workers=1|server_threads=4|requests=4000|elapsed_ms=174.277|rps=22951.9|response_mbps=23.503|p50_us=42.00|p75_us=44.10|p90_us=49.77|p95_us=51.24|p99_us=58.17|min_us=33.39|mean_us=43.73|max_us=401.21|stddev_us=13.39|p999_us=315.75|tail_ratio=1.38|cv=0.31|samples=2000
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=1k|workers=1|connections_accepted=1|connections_active=0|event_poll_syscalls=2|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=4253|h2_write_syscalls=4003|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=1k|workers=1|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=4003|h2_write_syscalls=4253|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w8|protocol=h2c|mode=multiplex|payload=1k|bytes=1024|workers=8|server_threads=4|requests=4000|elapsed_ms=58.381|rps=68514.9|response_mbps=70.159|p50_us=104.31|p75_us=122.63|p90_us=146.22|p95_us=166.31|p99_us=534.02|min_us=40.19|mean_us=114.98|max_us=1033.61|stddev_us=73.81|p999_us=803.91|tail_ratio=5.12|cv=0.64|samples=2000
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=1k|workers=8|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=1270|h2_write_syscalls=1093|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=1k|workers=8|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=1004|h2_write_syscalls=1746|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w32|protocol=h2c|mode=multiplex|payload=1k|bytes=1024|workers=32|server_threads=4|requests=4000|elapsed_ms=59.172|rps=67599.2|response_mbps=69.222|p50_us=375.68|p75_us=607.71|p90_us=735.20|p95_us=833.11|p99_us=1538.68|min_us=45.78|mean_us=451.11|max_us=2773.57|stddev_us=276.97|p999_us=2766.26|tail_ratio=4.10|cv=0.61|samples=2016
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=1k|workers=32|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=490|h2_write_syscalls=341|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=1k|workers=32|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=401|h2_write_syscalls=683|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w1|protocol=h2c|mode=multiplex|payload=64k|bytes=65536|workers=1|server_threads=4|requests=4000|elapsed_ms=293.849|rps=13612.4|response_mbps=892.104|p50_us=71.03|p75_us=72.40|p90_us=76.22|p95_us=82.65|p99_us=140.16|min_us=62.95|mean_us=73.19|max_us=589.24|stddev_us=29.65|p999_us=481.99|tail_ratio=1.97|cv=0.41|samples=2000
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=64k|workers=1|connections_accepted=1|connections_active=0|event_poll_syscalls=2|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=8004|h2_write_syscalls=4004|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=64k|workers=1|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=20008|h2_write_syscalls=8005|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w8|protocol=h2c|mode=multiplex|payload=64k|bytes=65536|workers=8|server_threads=4|requests=4000|elapsed_ms=170.602|rps=23446.4|response_mbps=1536.581|p50_us=327.67|p75_us=369.94|p90_us=441.96|p95_us=532.09|p99_us=930.65|min_us=69.73|mean_us=341.22|max_us=2087.18|stddev_us=133.73|p999_us=1338.41|tail_ratio=2.84|cv=0.39|samples=2000
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=64k|workers=8|connections_accepted=1|connections_active=0|event_poll_syscalls=2|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=1617|h2_write_syscalls=1027|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=64k|workers=8|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=16626|h2_write_syscalls=1756|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w32|protocol=h2c|mode=multiplex|payload=64k|bytes=65536|workers=32|server_threads=4|requests=4000|elapsed_ms=109.455|rps=36544.7|response_mbps=2394.993|p50_us=857.18|p75_us=938.45|p90_us=1027.36|p95_us=1132.58|p99_us=2075.11|min_us=124.19|mean_us=868.77|max_us=2418.32|stddev_us=221.05|p999_us=2382.70|tail_ratio=2.42|cv=0.25|samples=2016
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=64k|workers=32|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=581|h2_write_syscalls=469|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=64k|workers=32|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=16141|h2_write_syscalls=792|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=https_h2_sequential|protocol=https+h2|mode=sequential|payload=empty|bytes=0|workers=1|server_threads=4|requests=2000|elapsed_ms=82.257|rps=24314.2|response_mbps=0.000|p50_us=40.89|p75_us=42.06|p90_us=43.54|p95_us=45.69|p99_us=52.75|min_us=32.63|mean_us=41.10|max_us=69.92|stddev_us=2.91|p999_us=58.63|tail_ratio=1.29|cv=0.07|samples=2000
TLSVERIFY|protocol=https+h2|cert_verified=true|hostname_verified=true|negotiated_alpn=h2|session_resumption=n/a|cipher_suite=0x1303
RESULT|suite=throughput|case=https_h2_sequential|protocol=https+h2|mode=sequential|payload=1k|bytes=1024|workers=1|server_threads=4|requests=2000|elapsed_ms=95.659|rps=20907.6|response_mbps=21.409|p50_us=45.77|p75_us=49.19|p90_us=53.43|p95_us=56.33|p99_us=64.68|min_us=41.64|mean_us=47.80|max_us=242.53|stddev_us=6.57|p999_us=83.52|tail_ratio=1.41|cv=0.14|samples=2000
TLSVERIFY|protocol=https+h2|cert_verified=true|hostname_verified=true|negotiated_alpn=h2|session_resumption=n/a|cipher_suite=0x1303
RESULT|suite=throughput|case=https_h2_sequential|protocol=https+h2|mode=sequential|payload=64k|bytes=65536|workers=1|server_threads=4|requests=2000|elapsed_ms=573.576|rps=3486.9|response_mbps=228.517|p50_us=273.83|p75_us=283.91|p90_us=298.64|p95_us=320.56|p99_us=627.81|min_us=261.55|mean_us=286.76|max_us=1058.83|stddev_us=60.32|p999_us=956.51|tail_ratio=2.29|cv=0.21|samples=2000
TLSVERIFY|protocol=https+h2|cert_verified=true|hostname_verified=true|negotiated_alpn=h2|session_resumption=n/a|cipher_suite=0x1303
total: complete
~~~

### Cross-Library Comparison
~~~text
courierust comparison suite (loopback, shared-peer matrix)
META|suite=compare|requests_per_repetition=2000|parallel_requests_per_repetition=2000|parallel_workers=8|repetitions=2|max_samples=2048
RESULT|suite=compare|case=raw_tcp_floor|layer=transport|protocol=h1|client=std_tcp|server=std_tcp|payload=4b|bytes=4|workers=1|server_threads=1|pool_policy=raw_tcp|pool_value=1|repetitions=1|status=valid|reason=-|requests=2000|elapsed_ms=45.447|rps=44007.5|response_mbps=0.176|p50_us=22.80|p75_us=23.41|p90_us=23.92|p95_us=25.34|p99_us=33.05|min_us=19.96|mean_us=22.69|max_us=41.31|stddev_us=2.21|p999_us=37.79|tail_ratio=1.45|cv=0.10|samples=2000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h1|client=courierust|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=102.904|rps=38871.2|response_mbps=39.804|p50_us=25.27|p75_us=25.69|p90_us=26.79|p95_us=27.55|p99_us=36.45|min_us=19.02|mean_us=25.69|max_us=91.76|stddev_us=2.23|p999_us=41.23|tail_ratio=1.44|cv=0.09|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h1|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=203.882|rps=19619.2|response_mbps=20.090|p50_us=46.91|p75_us=48.33|p90_us=50.94|p95_us=57.16|p99_us=238.41|min_us=39.54|mean_us=50.93|max_us=660.69|stddev_us=34.93|p999_us=461.10|tail_ratio=5.08|cv=0.69|samples=4000
RESULT|suite=compare|case=reqwest_client_to_courierust|layer=server|protocol=h1|client=reqwest|server=courierust|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=249.124|rps=16056.3|response_mbps=16.442|p50_us=60.23|p75_us=62.97|p90_us=66.91|p95_us=72.07|p99_us=81.91|min_us=52.74|mean_us=62.24|max_us=586.10|stddev_us=18.64|p999_us=466.28|tail_ratio=1.36|cv=0.30|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=server|protocol=h1|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=189.083|rps=21154.7|response_mbps=21.662|p50_us=47.13|p75_us=48.37|p90_us=49.98|p95_us=53.47|p99_us=61.38|min_us=41.62|mean_us=47.24|max_us=213.87|stddev_us=4.48|p999_us=71.78|tail_ratio=1.30|cv=0.09|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h1|client=courierust|server=hyper|payload=1k|bytes=1024|workers=8|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=32.168|rps=124348.7|response_mbps=127.333|p50_us=54.10|p75_us=77.78|p90_us=91.07|p95_us=101.07|p99_us=166.24|min_us=18.33|mean_us=60.76|max_us=1516.34|stddev_us=52.34|p999_us=751.09|tail_ratio=3.07|cv=0.86|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h1|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=8|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=75.585|rps=52920.9|response_mbps=54.191|p50_us=150.69|p75_us=160.74|p90_us=172.78|p95_us=193.95|p99_us=260.94|min_us=43.21|mean_us=148.79|max_us=581.51|stddev_us=37.02|p999_us=532.38|tail_ratio=1.73|cv=0.25|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h1|client=courierust|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=214.324|rps=18663.4|response_mbps=1223.122|p50_us=52.87|p75_us=53.58|p90_us=56.16|p95_us=59.15|p99_us=66.10|min_us=48.97|mean_us=53.55|max_us=114.35|stddev_us=3.21|p999_us=83.58|tail_ratio=1.25|cv=0.06|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h1|client=reqwest|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=299.882|rps=13338.6|response_mbps=874.156|p50_us=74.05|p75_us=76.86|p90_us=82.39|p95_us=84.74|p99_us=94.17|min_us=65.29|mean_us=74.94|max_us=153.03|stddev_us=5.82|p999_us=120.98|tail_ratio=1.27|cv=0.08|samples=4000
RESULT|suite=compare|case=reqwest_client_to_courierust|layer=server|protocol=h1|client=reqwest|server=courierust|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=381.259|rps=10491.6|response_mbps=687.575|p50_us=92.48|p75_us=96.46|p90_us=106.52|p95_us=110.57|p99_us=120.92|min_us=82.63|mean_us=95.27|max_us=903.66|stddev_us=16.34|p999_us=150.28|tail_ratio=1.31|cv=0.17|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=server|protocol=h1|client=reqwest|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=302.267|rps=13233.3|response_mbps=867.259|p50_us=73.21|p75_us=77.79|p90_us=83.52|p95_us=85.85|p99_us=98.87|min_us=64.36|mean_us=75.54|max_us=121.77|stddev_us=6.08|p999_us=116.25|tail_ratio=1.35|cv=0.08|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=190.011|rps=21051.5|response_mbps=21.557|p50_us=46.31|p75_us=48.06|p90_us=52.22|p95_us=55.14|p99_us=63.03|min_us=38.06|mean_us=47.47|max_us=189.77|stddev_us=4.56|p999_us=75.90|tail_ratio=1.36|cv=0.10|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h2c|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=215.200|rps=18587.4|response_mbps=19.033|p50_us=52.73|p75_us=54.68|p90_us=57.17|p95_us=62.71|p99_us=68.72|min_us=48.55|mean_us=53.77|max_us=109.75|stddev_us=4.00|p999_us=80.08|tail_ratio=1.30|cv=0.07|samples=4000
RESULT|suite=compare|case=reqwest_client_to_courierust|layer=server|protocol=h2c|client=reqwest|server=courierust|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=205.495|rps=19465.2|response_mbps=19.932|p50_us=49.48|p75_us=51.24|p90_us=53.88|p95_us=59.07|p99_us=65.52|min_us=45.97|mean_us=51.35|max_us=682.98|stddev_us=17.27|p999_us=304.72|tail_ratio=1.32|cv=0.34|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=server|protocol=h2c|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=212.850|rps=18792.6|response_mbps=19.244|p50_us=51.87|p75_us=53.48|p90_us=56.84|p95_us=61.26|p99_us=68.29|min_us=47.87|mean_us=53.18|max_us=528.16|stddev_us=8.37|p999_us=80.11|tail_ratio=1.32|cv=0.16|samples=4000
RESULT|suite=compare|case=courierust_h2_conn1xw32|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=32|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=76.146|rps=52530.6|response_mbps=53.791|p50_us=497.74|p75_us=658.97|p90_us=952.62|p95_us=1173.84|p99_us=1621.69|min_us=50.29|mean_us=561.70|max_us=2902.77|stddev_us=304.02|p999_us=2482.03|tail_ratio=3.26|cv=0.54|samples=4000
RESULT|suite=compare|case=courierust_h2_conn4xw8|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=32|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=4|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=55.051|rps=72660.1|response_mbps=74.404|p50_us=363.05|p75_us=506.89|p90_us=678.98|p95_us=830.60|p99_us=1193.96|min_us=33.26|mean_us=402.93|max_us=2222.97|stddev_us=239.94|p999_us=2129.45|tail_ratio=3.29|cv=0.60|samples=4000
RESULT|suite=compare|case=courierust_h2_conn8xw4|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=32|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=51.648|rps=77447.6|response_mbps=79.306|p50_us=346.32|p75_us=467.45|p90_us=602.90|p95_us=714.13|p99_us=1161.10|min_us=37.51|mean_us=375.47|max_us=2819.40|stddev_us=223.70|p999_us=2336.14|tail_ratio=3.35|cv=0.60|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=8|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=64.706|rps=61818.5|response_mbps=63.302|p50_us=113.36|p75_us=147.91|p90_us=188.65|p95_us=224.44|p99_us=332.83|min_us=33.87|mean_us=125.19|max_us=916.99|stddev_us=59.98|p999_us=571.09|tail_ratio=2.94|cv=0.48|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h2c|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=8|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=72.456|rps=55205.6|response_mbps=56.531|p50_us=138.19|p75_us=169.70|p90_us=204.16|p95_us=226.83|p99_us=283.02|min_us=37.34|mean_us=142.15|max_us=454.41|stddev_us=48.33|p999_us=398.68|tail_ratio=2.05|cv=0.34|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h2c|client=courierust|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=380.201|rps=10520.7|response_mbps=689.487|p50_us=95.44|p75_us=98.06|p90_us=100.64|p95_us=105.49|p99_us=112.46|min_us=83.64|mean_us=95.02|max_us=211.01|stddev_us=6.39|p999_us=136.37|tail_ratio=1.18|cv=0.07|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h2c|client=reqwest|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=366.187|rps=10923.4|response_mbps=715.875|p50_us=89.84|p75_us=95.60|p90_us=100.00|p95_us=104.11|p99_us=114.32|min_us=79.78|mean_us=91.52|max_us=190.02|stddev_us=7.02|p999_us=130.72|tail_ratio=1.27|cv=0.08|samples=4000
RESULT|suite=compare|case=reqwest_client_to_courierust|layer=server|protocol=h2c|client=reqwest|server=courierust|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=366.772|rps=10906.0|response_mbps=714.734|p50_us=90.56|p75_us=93.35|p90_us=98.53|p95_us=103.20|p99_us=109.67|min_us=76.22|mean_us=91.67|max_us=168.91|stddev_us=5.62|p999_us=127.76|tail_ratio=1.21|cv=0.06|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=server|protocol=h2c|client=reqwest|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=361.776|rps=11056.6|response_mbps=724.603|p50_us=88.65|p75_us=93.43|p90_us=97.96|p95_us=102.07|p99_us=110.43|min_us=76.99|mean_us=90.42|max_us=620.89|stddev_us=13.95|p999_us=140.24|tail_ratio=1.25|cv=0.15|samples=4000
RESULT|suite=compare|case=courierust_h2c_large_body_to_hyper|layer=client|protocol=h2c|client=courierust|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=diagnostic|reason=flow_control_workload_not_a_speed_ratio|requests=64|elapsed_ms=118.620|rps=539.5|response_mbps=35.359|p50_us=1839.81|p75_us=1872.50|p90_us=1898.43|p95_us=1953.93|p99_us=2529.72|min_us=1718.61|mean_us=1853.41|max_us=2529.72|stddev_us=98.47|p999_us=2529.72|tail_ratio=1.37|cv=0.05|samples=64
RESULT|suite=compare|case=reqwest_async_h2c_large_body_to_hyper|layer=client|protocol=h2c|client=reqwest-async|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=diagnostic|reason=flow_control_workload_not_a_speed_ratio|requests=64|elapsed_ms=92.284|rps=693.5|response_mbps=45.450|p50_us=1420.05|p75_us=1487.31|p90_us=1521.59|p95_us=1532.49|p99_us=1548.96|min_us=1350.47|mean_us=1441.91|max_us=1548.96|stddev_us=50.91|p999_us=1548.96|tail_ratio=1.09|cv=0.04|samples=64
RESULT|suite=compare|case=courierust_h3_client_to_courierust|layer=client|protocol=h3|client=courierust-h3|server=courierust-h3|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=358.300|rps=11163.8|response_mbps=11.432|p50_us=89.59|p75_us=99.60|p90_us=105.90|p95_us=110.76|p99_us=119.06|min_us=55.49|mean_us=89.54|max_us=154.52|stddev_us=13.10|p999_us=131.28|tail_ratio=1.33|cv=0.15|samples=4000
RESULT|suite=compare|case=quinn_h3_client_to_courierust|layer=client|protocol=h3|client=quinn+h3|server=courierust-h3|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=quinn_single_connection|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=425.235|rps=9406.6|response_mbps=9.632|p50_us=103.56|p75_us=106.88|p90_us=111.93|p95_us=118.01|p99_us=142.35|min_us=88.02|mean_us=106.26|max_us=1277.57|stddev_us=39.43|p999_us=739.06|tail_ratio=1.37|cv=0.37|samples=4000
RESULT|suite=compare|case=courierust_h3_client_to_courierust|layer=client|protocol=h3|client=courierust-h3|server=courierust-h3|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=2218.369|rps=1803.1|response_mbps=118.170|p50_us=540.38|p75_us=549.64|p90_us=561.02|p95_us=642.75|p99_us=909.01|min_us=488.64|mean_us=554.56|max_us=1959.55|stddev_us=80.83|p999_us=1593.05|tail_ratio=1.68|cv=0.15|samples=4000
RESULT|suite=compare|case=quinn_h3_client_to_courierust|layer=client|protocol=h3|client=quinn+h3|server=courierust-h3|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=quinn_single_connection|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=2417.106|rps=1654.9|response_mbps=108.454|p50_us=635.15|p75_us=662.21|p90_us=674.93|p95_us=681.44|p99_us=693.58|min_us=472.14|mean_us=604.21|max_us=2274.55|stddev_us=75.66|p999_us=1092.83|tail_ratio=1.09|cv=0.13|samples=4000
total: complete
~~~

### Concurrency
~~~text
CONCURRENCY|case=idle_partial_herd|model=event|platform=linux|status=probe_ok|event_enabled=true|connections=200|worker_threads=2|probe_us=190.21
CONCURRENCY|case=idle_partial_herd|model=pool|platform=linux|status=probe_blocked|event_enabled=false|connections=200|worker_threads=2|probe_us=na|error=read: Resource temporarily unavailable (os error 11)
CONCURRENCY|case=slow_sender_herd|model=event|platform=linux|status=ok|event_enabled=true|connections=16|worker_threads=2|completed=16|probe_status=probe_ok|probe_us=493.17|byte_delay_us=10000|wall_ms=394.04
CONCURRENCY|suite=complete
~~~

### HTTP/3 (QUIC)
~~~text
RESULT|suite=h3|case=h3_connect|protocol=h3|mode=connect|payload=empty|bytes=0|workers=1|requests=1|connect_ms=4.070
RESULT|suite=h3|case=h3_sequential|protocol=h3|mode=reuse|payload=empty|bytes=0|workers=1|status=ok|requests=1000|elapsed_ms=73.446|rps=13615.4|p50_us=71.6|p75_us=74.1|p90_us=87.0|p99_us=93.8|min_us=57.37|mean_us=73.41|max_us=110.11|stddev_us=7.37|p999_us=102.55|tail_ratio=1.31|cv=0.10|samples=1000
RESULT|suite=h3|case=h3_parallel|protocol=h3|mode=reuse|payload=empty|bytes=0|workers=8|status=ok|requests=1000|elapsed_ms=24.258|rps=41224.3|p50_us=189.9|p75_us=203.6|p90_us=219.9|p99_us=260.4|min_us=114.92|mean_us=192.02|max_us=413.45|stddev_us=24.97|p999_us=411.83|tail_ratio=1.37|cv=0.13|samples=1000
~~~

### Reactor / Connection / Stream Evidence
~~~text
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=1k|workers=1|connections_accepted=1|connections_active=0|event_poll_syscalls=2|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=4253|h2_write_syscalls=4003|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=1k|workers=1|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=4003|h2_write_syscalls=4253|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=1k|workers=8|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=1270|h2_write_syscalls=1093|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=1k|workers=8|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=1004|h2_write_syscalls=1746|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=1k|workers=32|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=490|h2_write_syscalls=341|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=1k|workers=32|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=401|h2_write_syscalls=683|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=64k|workers=1|connections_accepted=1|connections_active=0|event_poll_syscalls=2|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=8004|h2_write_syscalls=4004|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=64k|workers=1|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=20008|h2_write_syscalls=8005|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=64k|workers=8|connections_accepted=1|connections_active=0|event_poll_syscalls=2|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=1617|h2_write_syscalls=1027|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=64k|workers=8|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=16626|h2_write_syscalls=1756|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=64k|workers=32|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=581|h2_write_syscalls=469|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=64k|workers=32|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=16141|h2_write_syscalls=792|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
~~~

### Cross-Machine
~~~text
NETWORK|role=client|status=not_configured|target_scope=remote|reason=COURIERUST_REMOTE_URL_not_set
~~~

### Fuzz
~~~text
FUZZ|target=h2_frame|status=ok|runs=smoke|duration_s=70|corpus=fuzz/corpus/h2_frame|reason=command_exit_0
FUZZ|target=hpack_block|status=ok|runs=smoke|duration_s=21|corpus=fuzz/corpus/hpack_block|reason=command_exit_0
FUZZ|target=h1_request|status=ok|runs=smoke|duration_s=22|corpus=fuzz/corpus/h1_request|reason=command_exit_0
FUZZ|target=h2_connection|status=ok|runs=smoke|duration_s=23|corpus=fuzz/corpus/h2_connection|reason=command_exit_0
FUZZ|target=ws_frame|status=ok|runs=smoke|duration_s=22|corpus=fuzz/corpus/ws_frame|reason=command_exit_0
FUZZ|target=ws_handshake|status=ok|runs=smoke|duration_s=21|corpus=fuzz/corpus/ws_handshake|reason=command_exit_0
FUZZ|target=ws_session|status=ok|runs=smoke|duration_s=22|corpus=fuzz/corpus/ws_session|reason=command_exit_0
~~~

### Interop Validation
~~~text
courierust vs mainstream HTTP stack — interop validation
INTEROP|case=courierust_client_h1_to_hyper_h1|ok
INTEROP|case=courierust_client_h2c_to_hyper_h2|ok
INTEROP|case=hyper_client_h1_to_courierust_h1|ok
INTEROP|case=hyper_client_h2c_to_courierust_h2|ok
INTEROP|case=reqwest_h1_to_courierust_h1|ok
INTEROP|case=reqwest_h2c_to_courierust_h2|ok
INTEROP|case=courierust_h2c_large_body_to_hyper_h2|ok
INTEROP|case=courierust_h1_slow_reader_to_hyper_h1|ok
INTEROP|case=tls_rejects_untrusted_certificate|ok
INTEROP|case=tls_rejects_hostname_mismatch|ok
INTEROP|case=tls_alpn_downgrade_to_h1|ok
INTEROP|case=tls_h2_alpn_rejected|ok
INTEROP|case=h1_connection_close_honored|ok
INTEROP|case=courierust_h2_client_survives_peer_goaway|ok
INTEROP|case=h3_self_roundtrip|ok
INTEROP|case=h3_self_connection_reuse|ok
INTEROP|case=h3_self_large_body_flow_control|ok
INTEROP|case=h3_self_multiplex_concurrent|ok
INTEROP|all_cases_passed
~~~
### TLS Interop
~~~text
No output was captured for this benchmark.
~~~
