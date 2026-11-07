# Protocol Benchmark Evidence

Generated from the supplied benchmark logs; see suite status and environment provenance.

## Run

- Commit: 8de1d04e048c44a4a642ed82619bb7656792177c
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
- Workflow run: [42363756942](https://github.com/blueokanna/Courierust/actions/runs/42363756942)

## Evidence Rules

- gRPC, TLS and WebSocket tables retain every repetition. Compare rows only with the same protocol, workload, security settings and one unchanged peer. No aggregate winner is computed.
- Latencies use the nearest-rank estimator. Fewer than 1000 samples makes P99 exploratory; even a larger sample is not an SLA or a confidence interval. Closed-loop traffic does not measure overload or correct coordinated omission.
- gRPC uses the same generated protobuf codec on both sides, four messages per streaming RPC, one connection, identity compression and verified final status. This finite-stream workload does not prove interactive full-duplex behavior or bounded memory under backpressure.
- TLS comparison rows pin AES-128-GCM, certificate verification, ALPN and key exchange (P-256 for TLS 1.2, X25519 for TLS 1.3). Full-handshake rows include TCP connection setup and disable resumption; record rows use a pre-established connection.
- WebSocket comparison rows use one persistent connection, binary echo, TCP_NODELAY, no compression and full payload checks. Async-client rows include the synchronous caller runtime-entry cost. Codec and raw-TCP diagnostic rows are not WebSocket end-to-end baselines.
- Rows marked `invalid`, `diagnostic` or `not_available` are retained for auditability and excluded from speed ratios.
- The `*_h2c_large_body_to_hyper` rows measure a 1 MiB POST against the same hyper h2 server. Both clients are paced by the server 64 KiB initial flow-control window (WINDOW_UPDATE round trips), and reqwest retains a large fixed wait even in the async client — these rows are NOT valid for ratio claims.
- `quinn_h3_client_to_courierust` is reported `not_available` until the independent quinn+rustls QUIC/TLS handshake completes against the Courierust H3 server (a genuine interop gap, never faked).
- Loopback is not cross-machine evidence. The cross-machine table is evidence only when `target_scope=remote` and `status=ok`.
- TLS rows measure the built-in TLS 1.2/1.3 path; certificate, hostname, and ALPN checks must pass for the case to be valid. `negotiated_alpn` is reported; `session_resumption=n/a` because each TLSVERIFY row is a single handshake that does not measure resumption (the stack does implement TLS 1.3 session tickets).
- Fuzz status is evidence only for the recorded target, run count, and duration; an unconfigured target is not a pass.
- The `STATS` table is the reactor/connection/stream/syscall evidence behind the throughput rows (especially the h2 multi-worker scaling).
- The complexity tables are scaling evidence, not a speed claim: the class is fitted from the largest measured sizes, and the paired `ratio` is only meaningful within one run.

## Reading the numbers (correct interpretation)

- Change one implementation at a time: compare clients against the same server, or servers with the same client. Keep protocol, payload, concurrency and security policy fixed. Do not compute ratios across protocols.
- Pool limits have different meanings: reqwest pool_max_idle_per_host caps idle connections; Courierust max_connections_per_host caps active connections. Equal numeric limits do not make concurrent connection policies equivalent. Runtime and pool costs are included; this report does not attribute them without profiling.
- Large H3 tail ratios warrant repeat measurements and profiling. Reactor scheduling, packet queues, congestion control and runner load are possible causes; a single run cannot identify the cause or establish a general H3-versus-H2 ranking.
- The H1 server is built for event-driven protection (incomplete headers, idle keep-alive, slow senders); hyper is a mature async architecture. A short-request microbenchmark cannot dismiss the scheduling value — the concurrency/slow-connection rows measure production usability and resource isolation.
- H3 connection reuse plus cross-implementation interop (quinn+h3 → Courierust server) is stronger evidence than Courierust-to-Courierust.

## Throughput

| Case | Protocol | Mode | Payload | Workers | Server threads | Requests | RPS | Resp MB/s | P50 us | P75 us | P90 us | P95 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| h1_sequential | h1 | sequential | empty | 1 | 4 | 4000 | 15126.0 | 0.000 | 61.28 | 66.91 | 73.32 | 80.88 | 93.36 | 50.94 | 64.05 | 107.76 | 7.94 | 106.85 | 1.52 | 2000 |
| h1_sequential | h1 | sequential | 1k | 1 | 4 | 4000 | 15001.9 | 15.362 | 65.22 | 66.41 | 72.19 | 81.00 | 88.50 | 53.38 | 66.06 | 101.86 | 6.16 | 95.65 | 1.36 | 2000 |
| h1_sequential | h1 | sequential | 64k | 1 | 4 | 4000 | 10510.1 | 688.790 | 95.04 | 102.47 | 107.70 | 113.55 | 127.43 | 68.49 | 95.08 | 139.35 | 10.81 | 136.60 | 1.34 | 2000 |
| h1_parallel_w1 | h1 | parallel | 1k | 1 | 4 | 4000 | 15232.6 | 15.598 | 64.92 | 69.22 | 74.62 | 83.84 | 94.01 | 51.94 | 66.18 | 113.53 | 8.25 | 108.08 | 1.45 | 2000 |
| h1_parallel_w4 | h1 | parallel | 1k | 4 | 4 | 4000 | 35284.8 | 36.132 | 95.07 | 123.20 | 163.44 | 192.00 | 279.31 | 26.72 | 103.98 | 448.01 | 48.17 | 413.78 | 2.94 | 2000 |
| h1_parallel_w8 | h1 | parallel | 1k | 8 | 8 | 4000 | 46273.7 | 47.384 | 128.76 | 198.59 | 294.43 | 390.33 | 630.14 | 26.00 | 159.34 | 1723.01 | 127.26 | 1114.68 | 4.89 | 2000 |
| h2_multiplex_w1 | h2c | multiplex | 1k | 1 | 4 | 4000 | 13515.7 | 13.840 | 71.92 | 75.34 | 86.68 | 93.52 | 104.23 | 64.34 | 74.42 | 118.31 | 8.60 | 117.76 | 1.45 | 2000 |
| h2_multiplex_w8 | h2c | multiplex | 1k | 8 | 4 | 4000 | 43801.5 | 44.853 | 176.68 | 187.51 | 200.15 | 215.91 | 304.87 | 103.91 | 181.46 | 349.77 | 28.12 | 326.59 | 1.73 | 2000 |
| h2_multiplex_w32 | h2c | multiplex | 1k | 32 | 4 | 4000 | 61138.7 | 62.606 | 483.30 | 520.01 | 600.49 | 792.35 | 1002.55 | 157.13 | 514.38 | 1234.04 | 112.95 | 1227.72 | 2.07 | 2016 |
| h2_multiplex_w1 | h2c | multiplex | 64k | 1 | 4 | 4000 | 7792.8 | 510.709 | 126.82 | 131.22 | 144.70 | 150.38 | 160.10 | 116.42 | 128.31 | 199.47 | 10.43 | 190.63 | 1.26 | 2000 |
| h2_multiplex_w8 | h2c | multiplex | 64k | 8 | 4 | 4000 | 15937.5 | 1044.481 | 467.63 | 566.76 | 731.73 | 788.53 | 876.51 | 159.64 | 498.06 | 1209.58 | 148.70 | 1177.36 | 1.87 | 2000 |
| h2_multiplex_w32 | h2c | multiplex | 64k | 32 | 4 | 4000 | 21657.0 | 1419.311 | 1465.16 | 1540.45 | 1635.95 | 1766.46 | 3271.52 | 481.57 | 1471.90 | 3710.42 | 277.28 | 3680.88 | 2.23 | 2016 |
| https_h2_sequential | https+h2 | sequential | empty | 1 | 4 | 2000 | 13241.1 | 0.000 | 73.47 | 77.73 | 86.30 | 94.58 | 106.65 | 63.22 | 75.46 | 135.32 | 8.80 | 121.20 | 1.45 | 2000 |
| https_h2_sequential | https+h2 | sequential | 1k | 1 | 4 | 2000 | 11477.0 | 11.752 | 83.98 | 89.01 | 99.86 | 107.95 | 120.61 | 75.00 | 87.08 | 133.90 | 9.24 | 131.35 | 1.44 | 2000 |
| https_h2_sequential | https+h2 | sequential | 64k | 1 | 4 | 2000 | 2001.4 | 131.161 | 500.20 | 511.89 | 518.20 | 522.53 | 532.51 | 474.26 | 499.60 | 602.70 | 15.38 | 565.65 | 1.06 | 2000 |

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
| raw_tcp_floor | transport | h1 | std_tcp | std_tcp | 4b | 1 | 1 | raw_tcp | 1 | 1 | valid | - | 2000 | 33311.4 | 0.133 | 29.13 | 29.45 | 30.11 | 36.26 | 49.18 | 22.41 | 29.96 | 65.40 | 3.48 | 55.69 | 1.69 | 2000 |
| courierust_client_to_hyper | client | h1 | courierust | hyper | 1k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 19381.5 | 19.847 | 55.33 | 56.86 | 58.56 | 63.27 | 81.60 | 29.90 | 51.53 | 108.87 | 8.57 | 89.48 | 1.47 | 4000 |
| reqwest_client_to_hyper | client | h1 | reqwest | hyper | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 10857.0 | 11.118 | 86.22 | 95.36 | 110.15 | 112.81 | 127.42 | 82.84 | 92.01 | 146.32 | 10.84 | 142.56 | 1.48 | 4000 |
| reqwest_client_to_courierust | server | h1 | reqwest | courierust | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 7867.6 | 8.056 | 125.30 | 129.74 | 144.01 | 151.11 | 160.63 | 108.11 | 127.00 | 389.41 | 12.03 | 181.62 | 1.28 | 4000 |
| reqwest_client_to_hyper | server | h1 | reqwest | hyper | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 10068.8 | 10.310 | 95.99 | 109.53 | 112.47 | 123.51 | 136.38 | 78.68 | 99.22 | 163.50 | 13.55 | 145.52 | 1.42 | 4000 |
| courierust_client_to_hyper | client | h1 | courierust | hyper | 1k | 8 | 4 | courierust_max_connections_per_host | 8 | 2 | valid | - | 4000 | 67002.4 | 68.610 | 96.56 | 136.42 | 179.04 | 202.65 | 329.06 | 35.35 | 112.03 | 1786.50 | 78.45 | 981.61 | 3.41 | 4000 |
| reqwest_client_to_hyper | client | h1 | reqwest | hyper | 1k | 8 | 4 | reqwest_pool_max_idle_per_host | 8 | 2 | valid | - | 4000 | 25261.7 | 25.868 | 318.84 | 342.11 | 361.34 | 374.70 | 432.46 | 104.65 | 312.69 | 986.59 | 58.40 | 899.57 | 1.36 | 4000 |
| courierust_client_to_hyper | client | h1 | courierust | hyper | 64k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 9389.3 | 615.334 | 103.28 | 105.11 | 120.11 | 125.32 | 131.62 | 79.47 | 106.43 | 174.76 | 7.80 | 152.52 | 1.27 | 4000 |
| reqwest_client_to_hyper | client | h1 | reqwest | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 6482.1 | 424.811 | 150.77 | 158.77 | 172.26 | 178.93 | 193.30 | 127.04 | 154.19 | 258.55 | 12.64 | 214.76 | 1.28 | 4000 |
| reqwest_client_to_courierust | server | h1 | reqwest | courierust | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 5498.7 | 360.365 | 178.76 | 187.71 | 200.42 | 208.54 | 228.75 | 158.82 | 181.78 | 282.36 | 13.78 | 260.27 | 1.28 | 4000 |
| reqwest_client_to_hyper | server | h1 | reqwest | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 6344.7 | 415.805 | 155.72 | 168.69 | 178.00 | 187.35 | 198.13 | 128.15 | 157.54 | 269.57 | 17.21 | 219.55 | 1.27 | 4000 |
| courierust_client_to_hyper | client | h2c | courierust | hyper | 1k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 10646.1 | 10.902 | 93.13 | 96.09 | 108.82 | 114.14 | 125.13 | 80.29 | 93.87 | 139.10 | 9.89 | 136.73 | 1.34 | 4000 |
| reqwest_client_to_hyper | client | h2c | reqwest | hyper | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 7639.2 | 7.822 | 126.86 | 138.96 | 147.68 | 154.65 | 167.97 | 103.21 | 130.83 | 190.67 | 11.98 | 184.92 | 1.32 | 4000 |
| reqwest_client_to_courierust | server | h2c | reqwest | courierust | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 8782.9 | 8.994 | 111.07 | 116.81 | 130.36 | 135.11 | 145.05 | 86.13 | 113.78 | 174.52 | 10.53 | 158.54 | 1.31 | 4000 |
| reqwest_client_to_hyper | server | h2c | reqwest | hyper | 1k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 7649.1 | 7.833 | 126.92 | 139.07 | 147.15 | 153.50 | 164.18 | 105.30 | 130.66 | 213.67 | 11.39 | 173.79 | 1.29 | 4000 |
| courierust_h2_conn1xw32 | client | h2c | courierust | hyper | 1k | 32 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 42246.9 | 43.261 | 712.26 | 841.89 | 975.50 | 1094.26 | 1405.82 | 104.66 | 723.86 | 2008.57 | 219.75 | 1890.49 | 1.97 | 4000 |
| courierust_h2_conn4xw8 | client | h2c | courierust | hyper | 1k | 32 | 4 | courierust_max_connections_per_host | 4 | 2 | valid | - | 4000 | 50016.8 | 51.217 | 557.78 | 742.28 | 948.56 | 1073.40 | 1420.42 | 88.88 | 593.98 | 2620.61 | 270.28 | 1941.95 | 2.55 | 4000 |
| courierust_h2_conn8xw4 | client | h2c | courierust | hyper | 1k | 32 | 4 | courierust_max_connections_per_host | 8 | 2 | valid | - | 4000 | 46657.5 | 47.777 | 602.63 | 801.56 | 1009.06 | 1155.45 | 1531.54 | 89.85 | 634.46 | 2437.14 | 294.02 | 2192.73 | 2.54 | 4000 |
| courierust_client_to_hyper | client | h2c | courierust | hyper | 1k | 8 | 4 | courierust_max_connections_per_host | 8 | 2 | valid | - | 4000 | 34118.1 | 34.937 | 209.91 | 271.86 | 342.48 | 400.60 | 599.03 | 72.30 | 228.41 | 925.70 | 98.81 | 811.36 | 2.85 | 4000 |
| reqwest_client_to_hyper | client | h2c | reqwest | hyper | 1k | 8 | 4 | reqwest_pool_max_idle_per_host | 8 | 2 | valid | - | 4000 | 23456.7 | 24.020 | 326.95 | 391.78 | 456.93 | 502.45 | 592.91 | 111.39 | 336.60 | 894.55 | 92.91 | 759.17 | 1.81 | 4000 |
| courierust_client_to_hyper | client | h2c | courierust | hyper | 64k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 5764.4 | 377.775 | 168.88 | 185.78 | 195.94 | 204.39 | 217.85 | 138.19 | 173.42 | 244.64 | 16.55 | 239.64 | 1.29 | 4000 |
| reqwest_client_to_hyper | client | h2c | reqwest | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 4969.6 | 325.688 | 197.09 | 208.09 | 220.51 | 227.36 | 240.19 | 174.12 | 201.16 | 278.71 | 13.13 | 262.58 | 1.22 | 4000 |
| reqwest_client_to_courierust | server | h2c | reqwest | courierust | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 5225.4 | 342.449 | 187.33 | 197.89 | 209.93 | 215.62 | 228.10 | 162.61 | 191.32 | 268.61 | 12.69 | 247.03 | 1.22 | 4000 |
| reqwest_client_to_hyper | server | h2c | reqwest | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | valid | - | 4000 | 4934.7 | 323.402 | 197.58 | 208.91 | 223.03 | 230.35 | 245.60 | 176.53 | 202.59 | 361.40 | 14.03 | 277.73 | 1.24 | 4000 |
| courierust_h2c_large_body_to_hyper | client | h2c | courierust | hyper | 64k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | diagnostic | flow_control_workload_not_a_speed_ratio | 64 | 358.6 | 23.502 | 2791.44 | 2838.43 | 2876.37 | 2893.89 | 2917.52 | 2591.58 | 2788.49 | 2917.52 | 71.85 | 2917.52 | 1.05 | 64 |
| reqwest_async_h2c_large_body_to_hyper | client | h2c | reqwest-async | hyper | 64k | 1 | 4 | reqwest_pool_max_idle_per_host | 1 | 2 | diagnostic | flow_control_workload_not_a_speed_ratio | 64 | 402.3 | 26.364 | 2612.08 | 2793.81 | 2882.39 | 2926.95 | 3182.01 | 2070.48 | 2485.75 | 3182.01 | 340.89 | 3182.01 | 1.22 | 64 |
| courierust_h3_client_to_courierust | client | h3 | courierust-h3 | courierust-h3 | 1k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 4301.2 | 4.404 | 226.86 | 251.95 | 283.43 | 307.72 | 390.21 | 126.85 | 232.37 | 1809.39 | 77.19 | 1648.69 | 1.72 | 4000 |
| quinn_h3_client_to_courierust | client | h3 | quinn+h3 | courierust-h3 | 1k | 1 | 4 | quinn_single_connection | 1 | 2 | valid | - | 4000 | 4397.4 | 4.503 | 221.88 | 235.87 | 249.89 | 258.81 | 302.20 | 190.83 | 227.32 | 1773.41 | 40.22 | 700.98 | 1.36 | 4000 |
| courierust_h3_client_to_courierust | client | h3 | courierust-h3 | courierust-h3 | 64k | 1 | 4 | courierust_max_connections_per_host | 1 | 2 | valid | - | 4000 | 1139.3 | 74.665 | 857.57 | 873.18 | 898.03 | 1098.73 | 1156.75 | 726.51 | 877.63 | 2793.25 | 99.07 | 2116.18 | 1.35 | 4000 |
| quinn_h3_client_to_courierust | client | h3 | quinn+h3 | courierust-h3 | 64k | 1 | 4 | quinn_single_connection | 1 | 2 | valid | - | 4000 | 958.4 | 62.811 | 1125.83 | 1164.45 | 1186.29 | 1198.90 | 1224.25 | 762.93 | 1043.27 | 1464.14 | 154.52 | 1273.53 | 1.09 | 4000 |

## gRPC: Courierust / tonic

| Protocol | Case | Client | Server | Mode | Bytes/message | Workers | Repeat | Warmup | Completed | RPS | P50 us | P95 us | P99 us | Samples | Tail evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| grpc-h2 | Unary | courierust | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 24.39 | 40999.01 | 41055.71 | 41072.35 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 24.38 | 41002.56 | 41042.55 | 41057.81 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 24.39 | 41000.43 | 41043.97 | 41072.42 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 24.39 | 40998.26 | 41059.05 | 41080.32 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 24.39 | 41000.18 | 41045.71 | 41064.25 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 24.38 | 40997.34 | 41050.16 | 41088.82 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 24.39 | 40999.52 | 41041.24 | 41047.82 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 24.38 | 40998.41 | 41046.43 | 41064.23 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 24.39 | 40998.11 | 41047.93 | 41055.25 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 24.39 | 40999.19 | 41056.52 | 41073.39 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 24.39 | 41002.21 | 41050.59 | 41061.09 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 24.39 | 41000.58 | 41036.50 | 41075.27 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 24.38 | 41000.72 | 41041.96 | 41970.61 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 24.39 | 40999.71 | 41053.32 | 41068.17 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 24.64 | 41000.17 | 41058.14 | 41080.57 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 24.39 | 41001.66 | 41049.23 | 41072.23 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 23.09 | 41017.96 | 47031.35 | 48018.88 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 24.39 | 40996.61 | 41060.61 | 41072.88 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 24.39 | 40999.54 | 41063.72 | 41074.72 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 24.21 | 41002.78 | 41073.89 | 47013.25 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 22.53 | 46963.86 | 47048.32 | 47989.83 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 24.39 | 40999.93 | 41056.10 | 41060.06 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 24.38 | 40998.59 | 41070.55 | 41099.43 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 22.81 | 41045.34 | 47025.36 | 47971.27 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 24.39 | 40999.39 | 41064.88 | 41088.92 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 1024 | 1 | 1 | 4 | 100 | 24.39 | 40999.21 | 41058.43 | 41093.13 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 24.38 | 41000.07 | 41048.77 | 41989.75 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 1024 | 1 | 2 | 4 | 100 | 24.39 | 41000.26 | 41055.04 | 41077.52 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 24.39 | 40998.50 | 41050.28 | 41066.75 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 1024 | 1 | 3 | 4 | 100 | 24.39 | 41000.68 | 41066.27 | 41074.60 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 24.39 | 40999.06 | 41050.68 | 41065.17 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 1024 | 1 | 4 | 4 | 100 | 24.39 | 40997.07 | 41051.18 | 41097.53 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 30.35 | 40988.71 | 41418.65 | 41462.12 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 25.41 | 41000.01 | 41053.80 | 41086.92 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 25.14 | 40995.04 | 41068.89 | 41094.62 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 30.38 | 40986.21 | 41399.88 | 41466.51 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 30.35 | 40995.12 | 41382.92 | 41404.08 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 26.51 | 40992.65 | 41058.78 | 41076.23 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 25.41 | 40996.76 | 41059.13 | 41087.46 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 30.40 | 40995.58 | 41394.91 | 41495.42 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 96.35 | 657.67 | 41286.75 | 41495.12 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 27.18 | 41023.25 | 41982.42 | 42027.06 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 28.90 | 41000.87 | 41173.65 | 41277.64 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 43.67 | 40785.47 | 41360.77 | 41543.01 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 60.78 | 764.59 | 41427.31 | 41585.71 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 28.21 | 40992.68 | 41266.69 | 42001.01 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 29.22 | 40993.52 | 41286.21 | 41963.46 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 52.01 | 747.84 | 41355.62 | 41420.66 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 38.22 | 7205.12 | 47802.71 | 48005.78 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 37.71 | 40972.25 | 41359.45 | 41392.36 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 41.55 | 40827.62 | 41372.53 | 41483.07 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 43.71 | 6246.44 | 47072.34 | 47904.13 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 48.10 | 6188.66 | 47021.19 | 47955.76 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 34.98 | 40994.15 | 41271.34 | 41461.17 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 32.25 | 40999.12 | 41256.90 | 41371.27 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 29.86 | 46633.44 | 47990.07 | 48043.72 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 54.68 | 1025.10 | 41982.28 | 42025.36 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 65536 | 1 | 1 | 4 | 100 | 33.03 | 41005.97 | 41957.73 | 41972.68 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 37.08 | 40987.45 | 41429.62 | 41933.30 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 65536 | 1 | 2 | 4 | 100 | 44.72 | 40970.74 | 41994.40 | 42037.06 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 79.66 | 845.60 | 41542.39 | 41734.61 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 65536 | 1 | 3 | 4 | 100 | 33.00 | 41012.86 | 41979.43 | 42008.66 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 27.37 | 41048.85 | 41994.29 | 42009.75 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | tonic | reuse | 65536 | 1 | 4 | 4 | 100 | 51.18 | 1132.87 | 41952.02 | 42049.92 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 4626.61 | 209.90 | 253.64 | 264.10 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 3372.27 | 294.10 | 336.36 | 356.42 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 3326.77 | 296.74 | 332.21 | 346.58 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 4672.25 | 207.15 | 253.81 | 267.57 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 4657.01 | 209.30 | 254.75 | 266.97 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 3365.60 | 296.03 | 335.73 | 351.71 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 3357.46 | 295.40 | 334.73 | 346.33 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 4554.01 | 216.38 | 254.95 | 282.09 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 4387.99 | 224.95 | 262.89 | 278.01 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 3422.10 | 294.21 | 328.93 | 348.10 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 3440.71 | 287.50 | 322.86 | 333.24 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 4361.54 | 223.71 | 274.94 | 299.27 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 4352.78 | 222.94 | 272.26 | 288.33 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 3397.93 | 294.72 | 329.94 | 344.81 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 3415.95 | 288.38 | 329.55 | 339.75 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 4363.95 | 225.22 | 255.48 | 280.06 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 482.47 | 252.22 | 6002.38 | 6282.64 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 3398.29 | 287.52 | 332.77 | 352.64 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 3391.69 | 291.37 | 326.04 | 358.62 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 487.16 | 247.66 | 6524.09 | 7217.30 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 440.59 | 254.11 | 6528.21 | 7010.94 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 3325.94 | 299.98 | 340.55 | 352.98 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 3385.87 | 295.12 | 329.38 | 347.76 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 2266.81 | 260.86 | 299.83 | 6136.27 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 1958.04 | 267.79 | 331.16 | 6277.11 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 3363.06 | 292.86 | 335.64 | 342.06 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 3372.03 | 291.34 | 335.58 | 359.65 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 1030.79 | 274.25 | 6178.62 | 6976.36 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 1354.28 | 265.76 | 5731.61 | 7101.90 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 3325.41 | 296.89 | 345.92 | 362.41 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 2793.49 | 295.07 | 338.47 | 403.69 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 704.73 | 261.15 | 6253.55 | 7184.13 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 2943.77 | 336.97 | 380.76 | 398.65 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 2512.55 | 391.84 | 454.91 | 468.17 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 2559.81 | 382.08 | 438.18 | 458.99 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 2908.17 | 338.87 | 381.56 | 395.28 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 3003.43 | 326.57 | 363.61 | 382.61 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 2485.78 | 396.81 | 451.76 | 476.63 | 100 | exploratory | ok |
| grpc-h2 | Unary | tonic | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 2453.19 | 408.78 | 456.94 | 470.57 | 100 | exploratory | ok |
| grpc-h2 | Unary | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 2964.08 | 335.96 | 369.39 | 378.93 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 2176.29 | 453.65 | 496.46 | 559.18 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 1934.15 | 510.00 | 577.61 | 602.01 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 1748.59 | 509.80 | 556.67 | 572.28 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 2195.05 | 450.30 | 491.14 | 516.77 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 2218.37 | 446.03 | 490.38 | 506.27 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 1692.98 | 529.13 | 579.01 | 593.53 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | tonic | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 1930.39 | 515.63 | 565.77 | 580.29 | 100 | exploratory | ok |
| grpc-h2 | ServerStream | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 2184.50 | 452.57 | 506.40 | 527.37 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 205.33 | 6872.91 | 7989.53 | 8124.62 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 918.21 | 1122.75 | 1174.25 | 1226.16 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 902.97 | 1131.31 | 1173.61 | 1190.37 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 261.32 | 1231.61 | 7984.62 | 8061.04 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 290.45 | 1215.92 | 7775.98 | 8054.80 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 862.24 | 1084.83 | 1369.41 | 1891.98 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | tonic | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 882.75 | 1087.06 | 1325.63 | 1445.37 | 100 | exploratory | ok |
| grpc-h2 | ClientStream | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 252.62 | 1243.53 | 7860.44 | 8058.50 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 158.98 | 6998.18 | 8022.79 | 8026.12 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 858.80 | 1096.68 | 1279.78 | 1323.16 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 875.42 | 1133.19 | 1282.93 | 1308.70 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 160.00 | 6996.33 | 7946.86 | 8029.12 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 152.90 | 7000.14 | 7999.07 | 8021.99 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 917.58 | 1065.33 | 1257.25 | 1292.08 | 100 | exploratory | ok |
| grpc-h2 | Bidi | tonic | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 894.50 | 1104.60 | 1261.43 | 1289.68 | 100 | exploratory | ok |
| grpc-h2 | Bidi | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 179.86 | 6998.82 | 8012.50 | 8026.65 | 100 | exploratory | ok |

## TLS: Courierust / rustls (aws-lc-rs)

| Protocol | Case | Client | Server | Mode | Bytes/message | Workers | Repeat | Warmup | Completed | RPS | P50 us | P95 us | P99 us | Samples | Tail evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 1 | 4 | 100 | 365.90 | 2729.78 | 2762.70 | 2816.83 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 1 | 4 | 100 | 1818.85 | 551.55 | 575.05 | 584.52 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 2 | 4 | 100 | 1827.63 | 548.43 | 571.03 | 580.44 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 2 | 4 | 100 | 363.80 | 2746.08 | 2798.64 | 2835.25 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 3 | 4 | 100 | 365.15 | 2733.48 | 2787.52 | 2800.99 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 3 | 4 | 100 | 1831.60 | 547.21 | 570.98 | 573.45 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 4 | 4 | 100 | 1835.00 | 545.33 | 563.19 | 573.31 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 4 | 4 | 100 | 362.71 | 2750.89 | 2784.80 | 2907.50 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 1 | 4 | 100 | 10533.74 | 92.13 | 111.59 | 117.57 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 1 | 4 | 100 | 24383.35 | 36.52 | 56.31 | 61.90 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 2 | 4 | 100 | 26012.75 | 36.32 | 47.78 | 55.63 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 2 | 4 | 100 | 9858.33 | 102.72 | 118.69 | 145.75 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 3 | 4 | 100 | 10554.24 | 91.98 | 109.98 | 118.07 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 3 | 4 | 100 | 26311.24 | 36.46 | 46.32 | 57.07 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 4 | 4 | 100 | 26400.81 | 36.29 | 46.92 | 58.67 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 4 | 4 | 100 | 10275.80 | 93.04 | 118.97 | 125.23 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 1 | 4 | 100 | 312.51 | 3196.96 | 3233.48 | 3253.85 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 1 | 4 | 100 | 6129.76 | 159.30 | 181.74 | 187.29 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 2 | 4 | 100 | 6230.77 | 156.36 | 181.30 | 189.27 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 2 | 4 | 100 | 313.29 | 3188.63 | 3223.89 | 3233.87 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 3 | 4 | 100 | 310.84 | 3206.38 | 3260.41 | 3488.33 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 3 | 4 | 100 | 6148.15 | 158.25 | 181.08 | 185.68 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 4 | 4 | 100 | 6268.03 | 156.26 | 176.16 | 185.44 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 4 | 4 | 100 | 313.10 | 3189.91 | 3217.39 | 3234.14 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | courierust | connect | 0 | 1 | 1 | 4 | 100 | 264.16 | 3783.55 | 3827.64 | 3851.70 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 1 | 4 | 100 | 622.80 | 1595.99 | 1650.17 | 1750.88 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 2 | 4 | 100 | 626.71 | 1595.18 | 1625.35 | 1647.83 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | courierust | connect | 0 | 1 | 2 | 4 | 100 | 263.58 | 3790.24 | 3828.78 | 3847.91 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | courierust | connect | 0 | 1 | 3 | 4 | 100 | 263.58 | 3780.02 | 3853.05 | 3934.39 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 3 | 4 | 100 | 625.10 | 1595.19 | 1628.56 | 1647.04 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 4 | 4 | 100 | 627.38 | 1593.59 | 1619.42 | 1628.13 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | full_handshake | courierust | courierust | connect | 0 | 1 | 4 | 4 | 100 | 264.03 | 3774.14 | 3820.11 | 4170.94 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 6233.52 | 155.90 | 182.86 | 183.92 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 10554.61 | 91.76 | 110.93 | 121.56 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 10620.24 | 91.88 | 104.58 | 117.38 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 6602.85 | 147.66 | 165.53 | 174.25 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 6592.57 | 147.50 | 172.18 | 179.17 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 10583.83 | 91.65 | 109.88 | 114.98 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 10530.92 | 91.94 | 107.12 | 119.96 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 6559.40 | 147.75 | 174.73 | 184.78 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 154.78 | 6465.03 | 6679.45 | 6693.30 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 313.05 | 3189.66 | 3220.78 | 3242.16 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 312.64 | 3191.37 | 3236.14 | 3308.22 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 160.03 | 6227.65 | 6416.21 | 6534.05 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 141.97 | 6519.43 | 8877.02 | 9005.01 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 312.01 | 3199.97 | 3232.67 | 3273.85 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 312.84 | 3188.72 | 3220.57 | 3256.63 | 100 | exploratory | ok |
| tls1.2-aes128gcm-p256 | record_echo | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 154.83 | 6476.85 | 6670.37 | 6700.05 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 1 | 4 | 100 | 496.66 | 2006.37 | 2063.39 | 2082.43 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 1 | 4 | 100 | 2145.63 | 469.51 | 491.40 | 497.17 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 2 | 4 | 100 | 2143.92 | 463.81 | 494.08 | 512.68 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 2 | 4 | 100 | 491.42 | 2030.82 | 2077.64 | 2083.06 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 3 | 4 | 100 | 491.22 | 2034.74 | 2061.17 | 2072.23 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 3 | 4 | 100 | 2130.77 | 470.86 | 496.78 | 503.71 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | rustls-aws-lc | connect | 0 | 1 | 4 | 4 | 100 | 2134.08 | 469.36 | 497.19 | 511.04 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | rustls-aws-lc | connect | 0 | 1 | 4 | 4 | 100 | 492.95 | 2026.08 | 2073.05 | 2099.92 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 1 | 4 | 100 | 11289.24 | 84.86 | 106.67 | 118.25 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 1 | 4 | 100 | 26442.96 | 36.13 | 48.91 | 57.18 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 2 | 4 | 100 | 26490.20 | 36.54 | 41.49 | 58.30 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 2 | 4 | 100 | 11560.87 | 84.12 | 102.24 | 108.13 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 3 | 4 | 100 | 11529.64 | 84.65 | 98.06 | 103.64 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 3 | 4 | 100 | 26324.54 | 36.49 | 42.89 | 66.13 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 1024 | 1 | 4 | 4 | 100 | 26646.27 | 36.31 | 43.95 | 58.45 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 1024 | 1 | 4 | 4 | 100 | 11425.08 | 84.74 | 101.20 | 109.56 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 1 | 4 | 100 | 315.15 | 3170.34 | 3200.51 | 3221.42 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 1 | 4 | 100 | 6191.43 | 156.38 | 185.55 | 202.84 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 2 | 4 | 100 | 6316.03 | 154.38 | 175.92 | 188.74 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 2 | 4 | 100 | 315.81 | 3163.43 | 3185.77 | 3223.09 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 3 | 4 | 100 | 315.72 | 3164.83 | 3192.49 | 3219.10 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 3 | 4 | 100 | 6231.89 | 155.54 | 184.11 | 189.87 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | rustls-aws-lc | reuse | 65536 | 1 | 4 | 4 | 100 | 6240.85 | 155.31 | 182.31 | 195.12 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | rustls-aws-lc | reuse | 65536 | 1 | 4 | 4 | 100 | 315.87 | 3163.27 | 3189.26 | 3194.57 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | courierust | connect | 0 | 1 | 1 | 4 | 100 | 399.83 | 2501.83 | 2558.50 | 2564.55 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 1 | 4 | 100 | 1059.73 | 944.42 | 978.62 | 987.12 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 2 | 4 | 100 | 1084.12 | 914.26 | 969.82 | 985.44 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | courierust | connect | 0 | 1 | 2 | 4 | 100 | 401.37 | 2479.16 | 2555.38 | 2563.92 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | courierust | connect | 0 | 1 | 3 | 4 | 100 | 401.76 | 2480.16 | 2548.51 | 2563.40 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 3 | 4 | 100 | 1053.46 | 957.82 | 989.20 | 998.67 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | rustls-aws-lc | courierust | connect | 0 | 1 | 4 | 4 | 100 | 1060.02 | 949.44 | 981.99 | 989.66 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | full_handshake | courierust | courierust | connect | 0 | 1 | 4 | 4 | 100 | 400.61 | 2489.01 | 2530.21 | 2536.43 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 7204.45 | 133.71 | 163.96 | 167.98 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 1 | 4 | 100 | 11371.31 | 85.40 | 100.35 | 114.92 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 11315.35 | 85.26 | 107.76 | 117.38 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 1024 | 1 | 2 | 4 | 100 | 7301.34 | 133.51 | 153.24 | 164.40 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 7255.29 | 133.66 | 159.60 | 166.43 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 3 | 4 | 100 | 11320.16 | 85.51 | 103.70 | 116.73 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 11392.08 | 85.21 | 106.17 | 116.93 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 1024 | 1 | 4 | 4 | 100 | 7190.67 | 133.56 | 160.06 | 201.59 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 155.65 | 6454.24 | 6620.92 | 6629.22 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 1 | 4 | 100 | 314.02 | 3176.51 | 3220.41 | 3242.71 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 313.25 | 3184.35 | 3227.83 | 3253.59 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 65536 | 1 | 2 | 4 | 100 | 155.44 | 6447.61 | 6638.56 | 6688.78 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 155.14 | 6454.55 | 6638.91 | 6661.52 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 3 | 4 | 100 | 314.19 | 3175.88 | 3210.47 | 3280.11 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | rustls-aws-lc | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 314.54 | 3174.40 | 3208.44 | 3239.92 | 100 | exploratory | ok |
| tls1.3-aes128gcm-x25519 | record_echo | courierust | courierust | reuse | 65536 | 1 | 4 | 4 | 100 | 155.76 | 6389.31 | 6650.57 | 6741.71 | 100 | exploratory | ok |

## WebSocket: Courierust / tungstenite / tokio-tungstenite

| Protocol | Case | Client | Server | Mode | Bytes/message | Workers | Repeat | Warmup | Completed | RPS | P50 us | P95 us | P99 us | Samples | Tail evidence | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ws | binary_echo | courierust | tungstenite | reuse | 64 | 1 | 1 | 16 | 1000 | 29655.57 | 32.55 | 40.84 | 52.41 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 64 | 1 | 1 | 16 | 1000 | 25618.50 | 40.59 | 52.83 | 64.82 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 64 | 1 | 1 | 16 | 1000 | 19113.99 | 50.38 | 63.97 | 77.38 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 64 | 1 | 2 | 16 | 1000 | 19589.38 | 48.99 | 66.89 | 77.38 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 64 | 1 | 2 | 16 | 1000 | 23928.20 | 40.32 | 53.66 | 61.72 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 64 | 1 | 2 | 16 | 1000 | 29331.34 | 32.56 | 43.52 | 53.91 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 64 | 1 | 3 | 16 | 1000 | 29808.49 | 32.47 | 41.41 | 53.28 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 64 | 1 | 3 | 16 | 1000 | 24100.47 | 40.38 | 55.34 | 63.02 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 64 | 1 | 3 | 16 | 1000 | 19706.45 | 48.90 | 64.98 | 78.56 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 64 | 1 | 4 | 16 | 1000 | 19557.78 | 49.45 | 63.77 | 75.98 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 64 | 1 | 4 | 16 | 1000 | 31066.75 | 31.09 | 38.35 | 52.38 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 64 | 1 | 4 | 16 | 1000 | 29652.96 | 32.63 | 41.55 | 52.20 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 1024 | 1 | 1 | 16 | 1000 | 29016.65 | 33.45 | 39.10 | 52.49 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 1024 | 1 | 1 | 16 | 1000 | 27312.31 | 33.51 | 46.20 | 57.28 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 1024 | 1 | 1 | 16 | 1000 | 19713.92 | 48.65 | 64.68 | 76.36 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 1024 | 1 | 2 | 16 | 1000 | 19760.61 | 48.91 | 62.36 | 73.94 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 1024 | 1 | 2 | 16 | 1000 | 23453.95 | 40.56 | 55.82 | 65.40 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 1024 | 1 | 2 | 16 | 1000 | 27948.53 | 34.03 | 45.12 | 56.65 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 1024 | 1 | 3 | 16 | 1000 | 28159.98 | 33.81 | 44.56 | 57.33 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 1024 | 1 | 3 | 16 | 1000 | 24026.93 | 40.27 | 50.79 | 65.39 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 1024 | 1 | 3 | 16 | 1000 | 19987.43 | 48.41 | 61.21 | 74.25 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 1024 | 1 | 4 | 16 | 1000 | 19946.54 | 48.27 | 61.59 | 75.43 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 1024 | 1 | 4 | 16 | 1000 | 30678.62 | 31.31 | 42.06 | 50.12 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 1024 | 1 | 4 | 16 | 1000 | 28837.81 | 33.27 | 43.18 | 55.78 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 16384 | 1 | 1 | 16 | 1000 | 22840.49 | 42.41 | 54.25 | 61.74 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 16384 | 1 | 1 | 16 | 1000 | 19423.85 | 49.86 | 62.85 | 73.93 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 16384 | 1 | 1 | 16 | 1000 | 17055.46 | 56.86 | 71.43 | 82.83 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 16384 | 1 | 2 | 16 | 1000 | 16991.40 | 56.79 | 72.22 | 83.17 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 16384 | 1 | 2 | 16 | 1000 | 24603.51 | 40.37 | 46.67 | 59.31 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 16384 | 1 | 2 | 16 | 1000 | 23159.82 | 42.90 | 49.81 | 63.34 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 16384 | 1 | 3 | 16 | 1000 | 21804.89 | 42.97 | 55.85 | 67.18 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 16384 | 1 | 3 | 16 | 1000 | 19918.96 | 48.57 | 62.19 | 74.04 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 16384 | 1 | 3 | 16 | 1000 | 16245.97 | 59.85 | 75.23 | 83.24 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 16384 | 1 | 4 | 16 | 1000 | 16451.34 | 59.39 | 74.06 | 85.89 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 16384 | 1 | 4 | 16 | 1000 | 24227.61 | 40.66 | 50.88 | 62.74 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 16384 | 1 | 4 | 16 | 1000 | 22739.39 | 42.61 | 53.86 | 63.82 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 262144 | 1 | 1 | 16 | 1000 | 2322.99 | 427.52 | 452.77 | 473.20 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 262144 | 1 | 1 | 16 | 1000 | 3185.45 | 307.51 | 343.83 | 365.66 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 262144 | 1 | 1 | 16 | 1000 | 4618.85 | 220.78 | 245.51 | 258.29 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 262144 | 1 | 2 | 16 | 1000 | 4427.46 | 230.88 | 253.61 | 263.93 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 262144 | 1 | 2 | 16 | 1000 | 6410.55 | 154.07 | 175.33 | 184.36 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 262144 | 1 | 2 | 16 | 1000 | 5348.79 | 166.58 | 247.38 | 258.01 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 262144 | 1 | 3 | 16 | 1000 | 5802.14 | 165.17 | 230.46 | 247.45 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 262144 | 1 | 3 | 16 | 1000 | 6663.32 | 145.80 | 172.01 | 191.77 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 262144 | 1 | 3 | 16 | 1000 | 5151.18 | 188.32 | 226.22 | 245.39 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | tungstenite | reuse | 262144 | 1 | 4 | 16 | 1000 | 5018.38 | 198.14 | 220.27 | 230.91 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | tungstenite | reuse | 262144 | 1 | 4 | 16 | 1000 | 6543.90 | 149.14 | 171.18 | 182.60 | 1000 | sampled | ok |
| ws | binary_echo | courierust | tungstenite | reuse | 262144 | 1 | 4 | 16 | 1000 | 5936.26 | 164.44 | 189.28 | 197.22 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 64 | 1 | 1 | 16 | 1000 | 30078.28 | 32.46 | 36.09 | 51.12 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 64 | 1 | 1 | 16 | 1000 | 31375.39 | 30.91 | 38.44 | 51.29 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 64 | 1 | 1 | 16 | 1000 | 20067.09 | 47.83 | 62.07 | 74.69 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 64 | 1 | 2 | 16 | 1000 | 18071.35 | 51.99 | 72.79 | 84.33 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 64 | 1 | 2 | 16 | 1000 | 24196.67 | 40.05 | 53.58 | 65.87 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 64 | 1 | 2 | 16 | 1000 | 30165.83 | 32.27 | 37.85 | 52.11 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 64 | 1 | 3 | 16 | 1000 | 24144.88 | 41.04 | 50.76 | 60.77 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 64 | 1 | 3 | 16 | 1000 | 30716.23 | 30.68 | 41.41 | 52.29 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 64 | 1 | 3 | 16 | 1000 | 20188.54 | 47.74 | 62.59 | 75.75 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 64 | 1 | 4 | 16 | 1000 | 19733.52 | 49.45 | 63.40 | 71.31 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 64 | 1 | 4 | 16 | 1000 | 30989.58 | 30.97 | 42.07 | 50.99 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 64 | 1 | 4 | 16 | 1000 | 30134.23 | 32.20 | 40.38 | 51.28 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 1024 | 1 | 1 | 16 | 1000 | 29140.07 | 33.33 | 39.50 | 51.16 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 1024 | 1 | 1 | 16 | 1000 | 30933.62 | 31.44 | 36.09 | 49.86 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 1024 | 1 | 1 | 16 | 1000 | 19892.81 | 48.66 | 61.90 | 72.34 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 1024 | 1 | 2 | 16 | 1000 | 19981.44 | 48.23 | 61.98 | 74.33 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 1024 | 1 | 2 | 16 | 1000 | 30731.27 | 31.61 | 36.60 | 50.41 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 1024 | 1 | 2 | 16 | 1000 | 23110.98 | 41.93 | 53.96 | 66.29 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 1024 | 1 | 3 | 16 | 1000 | 28682.89 | 33.62 | 40.90 | 53.41 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 1024 | 1 | 3 | 16 | 1000 | 24335.27 | 40.01 | 48.26 | 64.19 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 1024 | 1 | 3 | 16 | 1000 | 19331.46 | 50.52 | 63.98 | 74.75 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 1024 | 1 | 4 | 16 | 1000 | 20117.49 | 48.29 | 61.26 | 76.36 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 1024 | 1 | 4 | 16 | 1000 | 25001.43 | 39.86 | 50.92 | 62.93 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 1024 | 1 | 4 | 16 | 1000 | 28979.39 | 33.45 | 39.15 | 51.45 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 16384 | 1 | 1 | 16 | 1000 | 21862.57 | 44.62 | 54.44 | 62.21 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 16384 | 1 | 1 | 16 | 1000 | 22897.54 | 42.21 | 52.53 | 65.94 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 16384 | 1 | 1 | 16 | 1000 | 16510.12 | 58.88 | 75.13 | 85.49 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 16384 | 1 | 2 | 16 | 1000 | 16577.31 | 59.18 | 72.08 | 84.27 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 16384 | 1 | 2 | 16 | 1000 | 23306.85 | 41.70 | 51.04 | 65.07 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 16384 | 1 | 2 | 16 | 1000 | 21962.60 | 44.37 | 54.72 | 64.82 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 16384 | 1 | 3 | 16 | 1000 | 21822.42 | 44.28 | 55.86 | 66.76 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 16384 | 1 | 3 | 16 | 1000 | 20619.79 | 50.37 | 59.32 | 72.92 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 16384 | 1 | 3 | 16 | 1000 | 16008.58 | 60.86 | 76.88 | 87.64 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 16384 | 1 | 4 | 16 | 1000 | 16693.78 | 57.94 | 73.36 | 84.85 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 16384 | 1 | 4 | 16 | 1000 | 19108.39 | 51.29 | 65.27 | 74.78 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 16384 | 1 | 4 | 16 | 1000 | 18663.22 | 52.85 | 66.86 | 77.29 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 262144 | 1 | 1 | 16 | 1000 | 4936.74 | 184.29 | 258.13 | 269.02 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 262144 | 1 | 1 | 16 | 1000 | 3990.02 | 238.18 | 300.46 | 307.33 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 262144 | 1 | 1 | 16 | 1000 | 4456.38 | 227.24 | 252.08 | 267.00 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 262144 | 1 | 2 | 16 | 1000 | 4377.81 | 228.64 | 253.17 | 267.29 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 262144 | 1 | 2 | 16 | 1000 | 6035.73 | 162.60 | 185.52 | 200.90 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 262144 | 1 | 2 | 16 | 1000 | 5774.05 | 170.42 | 191.20 | 201.23 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 262144 | 1 | 3 | 16 | 1000 | 5778.71 | 169.57 | 191.30 | 200.94 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 262144 | 1 | 3 | 16 | 1000 | 6192.77 | 159.85 | 179.75 | 192.49 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 262144 | 1 | 3 | 16 | 1000 | 4718.95 | 216.54 | 251.88 | 270.58 | 1000 | sampled | ok |
| ws | binary_echo | tokio-tungstenite | courierust | reuse | 262144 | 1 | 4 | 16 | 1000 | 4616.13 | 222.55 | 241.55 | 248.17 | 1000 | sampled | ok |
| ws | binary_echo | tungstenite | courierust | reuse | 262144 | 1 | 4 | 16 | 1000 | 6059.77 | 160.37 | 215.28 | 232.60 | 1000 | sampled | ok |
| ws | binary_echo | courierust | courierust | reuse | 262144 | 1 | 4 | 16 | 1000 | 4941.61 | 181.37 | 258.67 | 270.81 | 1000 | sampled | ok |

## Build and machine provenance

~~~text
Sat Nov  7 10:23:44 UTC 2026
8de1d04e048c44a4a642ed82619bb7656792177c
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
Model name:                              AMD EPYC 7763 64-Core Processor
CPU family:                              25
Model:                                   1
Thread(s) per core:                      2
Core(s) per socket:                      2
Socket(s):                               1
Stepping:                                1
BogoMIPS:                                4890.87
Flags:                                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl tsc_reliable nonstop_tsc cpuid extd_apicid aperfmperf tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy svm cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves user_shstk clzero xsaveerptr rdpru arat npt nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold v_vmsave_vmload umip vaes vpclmulqdq rdpid fsrm
Virtualization:                          AMD-V
Hypervisor vendor:                       Microsoft
Virtualization type:                     full
L1d cache:                               64 KiB (2 instances)
L1i cache:                               64 KiB (2 instances)
L2 cache:                                1 MiB (2 instances)
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
Vulnerability Tsa:                       Vulnerable: No microcode
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
| idle_partial_herd | event | linux | probe_ok | true | 200 | 2 | 2106.85 | - | - | - | - |
| idle_partial_herd | pool | linux | probe_blocked | false | 200 | 2 | na | - | - | - | - |
| slow_sender_herd | event | linux | ok | true | 16 | 2 | 150.81 | probe_ok | 10000 | 16 | 395.03 |

## HTTP/3 (QUIC)

- `h3_connect` is a cold request: QUIC handshake + TLS 1.3 + server Retry address validation on a fresh connection.
- `h3_sequential` and `h3_parallel` reuse the pooled per-authority QUIC connection (`mode=reuse`), so they measure the warm per-request cost of connection reuse.

| Case | Mode | Workers | Requests | Elapsed ms | Connect ms | RPS | P50 us | P75 us | P90 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| h3_connect | connect | 1 | 1 | - | 6.629 | - | - | - | - | - | - | - | - | - | - | - | - |
| h3_sequential | reuse | 1 | 1000 | 160.944 | - | 6213.3 | 154.5 | 174.6 | 182.4 | 214.2 | 118.11 | 160.85 | 254.38 | 17.87 | 247.05 | 1.39 | 1000 |
| h3_parallel | reuse | 8 | 1000 | 45.732 | - | 21866.5 | 347.4 | 380.3 | 411.1 | 470.2 | 195.64 | 355.06 | 524.21 | 41.88 | 517.41 | 1.35 | 1000 |

## Complexity (time and space)

- Complexity diagnostics retain their existing minimum-of-three estimator at several input sizes. This lower-envelope measurement is not a typical-latency or tail estimate; scheduling and frequency changes can affect the fitted curve.
- `class` is named by `median k`, the median of the adjacent-pair exponents, so the label describes the *typical* growth factor per 16× inside the measured range; `max k` is the worst pair, so one noisy pair cannot pass as a trend. `slope b` is the per-unit cost and `fixed a` the per-operation cost that does not scale with the input; R² is the fit quality (1.0 = exact).
- A range whose fixed term dwarfs its per-unit term is labelled `fixed-cost dominated` instead of quoting a sublinear-looking exponent that is really the constant; for those families read `slope b` (for example nanoseconds per extra header).
- Space is attributed per operation by a counting allocator compiled into the bench binary (allocation bytes and allocation calls), and per connection by a live-bytes/RSS delta between 1 and 65 idle keep-alive connections — the fixed process/runtime cost cancels out of a delta.
- `ratio` is Courierust divided by the reference at the same size: below 1 means Courierust is cheaper. Rows are comparable only within one run.

| family | implementation | operation | metric | fitted class | median k | max k | slope b | fixed a | R² | points |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|
| codec | courierust | encode_unmasked | time_ns | O(n^1.25) | 1.249 | 1.303 | 0.035945 | -667.0111 | 0.9947 | 5 |
| codec | courierust | encode_unmasked | alloc_bytes | O(1) | 0.000 | 0.000 | 0.000000 | 0.0000 | 1.0000 | 5 |
| codec | tungstenite | encode_unmasked | time_ns | O(n^1.24) | 1.243 | 1.258 | 0.033678 | -604.1104 | 0.9948 | 5 |
| codec | tungstenite | encode_unmasked | alloc_bytes | O(1) | 0.000 | 0.000 | 0.000000 | 0.0000 | 1.0000 | 5 |
| codec | courierust | encode_masked | time_ns | O(n) | 1.075 | 1.132 | 0.075172 | -769.4196 | 0.9982 | 5 |
| codec | courierust | encode_masked | alloc_bytes | O(1) | 0.000 | 0.000 | 0.000000 | 0.0000 | 1.0000 | 5 |
| codec | tungstenite | encode_masked | time_ns | O(n) | 1.092 | 1.142 | 0.086872 | -707.8484 | 0.9991 | 5 |
| codec | tungstenite | encode_masked | alloc_bytes | O(n) | 1.000 | 1.000 | 1.000000 | 0.0000 | 1.0000 | 5 |
| http | courierust | get_roundtrip | time_ns | O(n^0.25) | 0.249 | 1.623 | 1.253065 | -9104.4083 | 0.9643 | 4 |
| http | courierust | get_roundtrip | alloc_bytes | O(n) | 0.969 | 0.997 | 1.999788 | 3147.3498 | 1.0000 | 4 |
| http | reqwest_hyper | get_roundtrip | time_ns | O(n^0.27) | 0.272 | 0.443 | 0.292963 | 111101.0394 | 0.9756 | 4 |
| http | reqwest_hyper | get_roundtrip | alloc_bytes | O(n) | 0.907 | 0.983 | 2.606055 | 39723.0075 | 0.9989 | 4 |
| headers | courierust | get_with_headers | time_ns | O(n^0.39) | 0.387 | 0.387 | 1171.210179 | 62556.5700 | 0.9996 | 3 |
| headers | courierust | get_with_headers | alloc_bytes | O(n^0.85) | 0.846 | 0.846 | 980.512381 | 5350.8267 | 1.0000 | 3 |
| headers | reqwest_hyper | get_with_headers | time_ns | O(1) | 0.070 | 0.070 | 304.086071 | 103700.0483 | 0.9404 | 3 |
| headers | reqwest_hyper | get_with_headers | alloc_bytes | O(n^0.60) | 0.596 | 0.596 | 1168.000000 | 24970.6400 | 1.0000 | 3 |
| deflate | courierust | deflate_reused_compressible | time_ns | O(n) | 0.995 | 0.995 | 0.817922 | 662.4754 | 1.0000 | 3 |
| deflate | courierust | deflate_reused_compressible | alloc_bytes | O(1) | 0.000 | 0.000 | 0.000000 | 0.0000 | 1.0000 | 3 |
| deflate | courierust | deflate_fresh_compressible | time_ns | O(n) | 0.992 | 0.992 | 0.899669 | 1815.9408 | 1.0000 | 3 |
| deflate | courierust | deflate_fresh_compressible | alloc_bytes | O(n) | 0.867 | 0.867 | 4.093389 | 131406.3313 | 1.0000 | 3 |
| deflate | courierust | inflate_compressible | time_ns | O(n^0.83) | 0.826 | 0.826 | 0.126016 | 5530.8578 | 1.0000 | 3 |
| deflate | courierust | inflate_compressible | alloc_bytes | fixed-cost dominated | 0.000 | 0.000 | 0.000000 | 29.0000 | 1.0000 | 3 |
| deflate | courierust | deflate_reused_incompressible | time_ns | O(n^1.23) | 1.234 | 1.234 | 23.152906 | -41632.5201 | 1.0000 | 3 |
| deflate | courierust | deflate_reused_incompressible | alloc_bytes | O(1) | 0.000 | 0.000 | 0.000000 | 0.0000 | 1.0000 | 3 |
| deflate | courierust | deflate_fresh_incompressible | time_ns | O(n^1.17) | 1.170 | 1.170 | 26.928264 | -171582.0399 | 0.9999 | 3 |
| deflate | courierust | deflate_fresh_incompressible | alloc_bytes | O(n) | 0.960 | 0.960 | 16.000000 | 131048.0000 | 1.0000 | 3 |

### Constant factors (paired at the same size)

| family | operation | metric | n | courierust | reference | ratio (ours/reference) |
|---|---|---|---:|---:|---:|---:|
| codec | encode_unmasked | time_ns | 64 | 11.3987 | 17.2825 | 0.660 |
| codec | encode_unmasked | alloc_bytes | 64 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 64 | 29.9485 | 34.9327 | 0.857 |
| codec | encode_masked | alloc_bytes | 64 | 0.0000 | 64.0000 | 0.000 |
| codec | encode_unmasked | time_ns | 1024 | 20.9290 | 26.4395 | 0.792 |
| codec | encode_unmasked | alloc_bytes | 1024 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 1024 | 72.6010 | 71.9650 | 1.009 |
| codec | encode_masked | alloc_bytes | 1024 | 0.0000 | 1024.0000 | 0.000 |
| codec | encode_unmasked | time_ns | 16384 | 179.3350 | 192.1600 | 0.933 |
| codec | encode_unmasked | alloc_bytes | 16384 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 16384 | 831.4550 | 842.7750 | 0.987 |
| codec | encode_masked | alloc_bytes | 16384 | 0.0000 | 16384.0000 | 0.000 |
| codec | encode_unmasked | time_ns | 262144 | 6649.2000 | 6284.0000 | 1.058 |
| codec | encode_unmasked | alloc_bytes | 262144 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 262144 | 16373.3750 | 19994.9250 | 0.819 |
| codec | encode_masked | alloc_bytes | 262144 | 0.0000 | 262144.0000 | 0.000 |
| codec | encode_unmasked | time_ns | 1048576 | 37546.2500 | 35190.8500 | 1.067 |
| codec | encode_unmasked | alloc_bytes | 1048576 | 0.0000 | 0.0000 | NaN |
| codec | encode_masked | time_ns | 1048576 | 78688.2000 | 90899.0500 | 0.866 |
| codec | encode_masked | alloc_bytes | 1048576 | 0.0000 | 1048576.0000 | 0.000 |
| codec | utf8_validate | time_ns | 4608 | 1596.6070 | 1603.7005 | 0.996 |
| http | get_roundtrip | time_ns | 1024 | 66236.9174 | 97031.9085 | 0.683 |
| http | get_roundtrip | alloc_bytes | 1024 | 5287.7025 | 26714.0796 | 0.198 |
| http | get_roundtrip | time_ns | 16384 | 71280.5905 | 104540.3429 | 0.682 |
| http | get_roundtrip | alloc_bytes | 16384 | 35928.1810 | 51458.8381 | 0.698 |
| http | get_roundtrip | time_ns | 262144 | 142171.9600 | 221950.4400 | 0.641 |
| http | get_roundtrip | alloc_bytes | 262144 | 527235.0800 | 784404.8800 | 0.672 |
| http | get_roundtrip | time_ns | 1048576 | 1348124.1600 | 409973.8000 | 3.288 |
| http | get_roundtrip | alloc_bytes | 1048576 | 2100112.9200 | 2757488.4000 | 0.762 |
| headers | get_with_headers | time_ns | 4 | 67852.7450 | 102794.0650 | 0.660 |
| headers | get_with_headers | time_ns | 16 | 80531.7650 | 111218.3350 | 0.724 |
| headers | get_with_headers | time_ns | 64 | 137666.8550 | 122630.9750 | 1.123 |
| deflate | fresh_vs_reused_compressible | time_ns | 1024 | 3049.1050 | 1347.9750 | 2.262 |
| deflate | fresh_vs_reused_compressible | time_ns | 65536 | 60444.3000 | 54427.8250 | 1.111 |
| deflate | fresh_vs_reused_compressible | time_ns | 1048576 | 945208.1000 | 858305.6000 | 1.101 |
| deflate | fresh_vs_reused_incompressible | time_ns | 1024 | 10994.2100 | 8534.3650 | 1.288 |
| deflate | fresh_vs_reused_incompressible | time_ns | 65536 | 1428014.9750 | 1447521.7000 | 0.987 |
| deflate | fresh_vs_reused_incompressible | time_ns | 1048576 | 28074921.3000 | 24237685.5000 | 1.158 |

### Space: cost of one idle connection

| implementation | connections | live KiB/conn | RSS KiB/conn |
|---|---:|---:|---:|
| courierust_event | 65 | 10.06 | 0.75 |
| courierust_blocking | 65 | 32.70 | 16.44 |
| hyper_tokio | 65 | 18.91 | 10.50 |

### Time: selected scaling points

| family | implementation | operation | n (bytes) | ns/op |
|---|---|---|---:|---:|
| codec | courierust | encode_unmasked | 64 | 11.3987 |
| codec | tungstenite | encode_unmasked | 64 | 17.2825 |
| codec | courierust | encode_masked | 64 | 29.9485 |
| codec | tungstenite | encode_masked | 64 | 34.9327 |
| codec | courierust | encode_unmasked | 1024 | 20.9290 |
| codec | tungstenite | encode_unmasked | 1024 | 26.4395 |
| codec | courierust | encode_masked | 1024 | 72.6010 |
| codec | tungstenite | encode_masked | 1024 | 71.9650 |
| codec | courierust | encode_unmasked | 16384 | 179.3350 |
| codec | tungstenite | encode_unmasked | 16384 | 192.1600 |
| codec | courierust | encode_masked | 16384 | 831.4550 |
| codec | tungstenite | encode_masked | 16384 | 842.7750 |
| codec | courierust | encode_unmasked | 262144 | 6649.2000 |
| codec | tungstenite | encode_unmasked | 262144 | 6284.0000 |
| codec | courierust | encode_masked | 262144 | 16373.3750 |
| codec | tungstenite | encode_masked | 262144 | 19994.9250 |
| codec | courierust | encode_unmasked | 1048576 | 37546.2500 |
| codec | tungstenite | encode_unmasked | 1048576 | 35190.8500 |
| codec | courierust | encode_masked | 1048576 | 78688.2000 |
| codec | tungstenite | encode_masked | 1048576 | 90899.0500 |
| http | courierust | get_roundtrip | 1024 | 66236.9174 |
| http | reqwest_hyper | get_roundtrip | 1024 | 97031.9085 |
| http | courierust | get_roundtrip | 16384 | 71280.5905 |
| http | reqwest_hyper | get_roundtrip | 16384 | 104540.3429 |
| http | courierust | get_roundtrip | 262144 | 142171.9600 |
| http | reqwest_hyper | get_roundtrip | 262144 | 221950.4400 |
| http | courierust | get_roundtrip | 1048576 | 1348124.1600 |
| http | reqwest_hyper | get_roundtrip | 1048576 | 409973.8000 |

## Reactor / Connection / Stream Evidence

| Protocol | Case | Payload | Workers | Accepted conns | Active conns | Poll syscalls | Wakeups | Queue peak | H1 conns | H1 read | H1 write | H2 conns | H2 active | H2 streams | H2 stream peak | H2 stream/conn peak | H2 read | H2 write | H3 conns | H3 active | H3 streams | H3 active streams | H3 stream peak | H3 stream/conn peak | H3 queue peak | H3 UDP recv | H3 UDP send |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| h2c | h2_multiplex_w1 | 1k | 1 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 1 | 1 | 4254 | 4003 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w1 | 1k | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 1 | 1 | 4003 | 4253 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w8 | 1k | 8 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 8 | 8 | 784 | 533 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w8 | 1k | 8 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 8 | 8 | 533 | 783 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w32 | 1k | 32 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 32 | 32 | 265 | 136 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w32 | 1k | 32 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 32 | 32 | 377 | 264 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w1 | 64k | 1 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 1 | 1 | 8006 | 4004 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w1 | 64k | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 1 | 1 | 20008 | 8005 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w8 | 64k | 8 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 8 | 8 | 1346 | 677 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w8 | 64k | 8 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 8 | 8 | 16680 | 1346 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w32 | 64k | 32 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 32 | 32 | 612 | 504 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| h2c | h2_multiplex_w32 | 64k | 32 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 4001 | 32 | 32 | 16141 | 755 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Cross-Machine

| Role | Status | Scope | Protocol | Workers | Max connections | Requests | Bytes | RPS | Resp MB/s | P50 us | P95 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| client | not_configured | remote | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | COURIERUST_REMOTE_URL_not_set |

## Fuzz

| Target | Status | Runs | Duration s | Corpus | Reason |
| --- | --- | --- | --- | --- | --- |
| h2_frame | ok | smoke | 86 | fuzz/corpus/h2_frame | command_exit_0 |
| hpack_block | ok | smoke | 21 | fuzz/corpus/hpack_block | command_exit_0 |
| h1_request | ok | smoke | 22 | fuzz/corpus/h1_request | command_exit_0 |
| h2_connection | ok | smoke | 24 | fuzz/corpus/h2_connection | command_exit_0 |
| ws_frame | ok | smoke | 21 | fuzz/corpus/ws_frame | command_exit_0 |
| ws_handshake | ok | smoke | 22 | fuzz/corpus/ws_handshake | command_exit_0 |
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
INTEROP|case=grpc_status_both_clients_to_tonic|ok
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=4100.020|rps=24.39|p50_us=40999.01|p95_us=41055.71|p99_us=41072.35|samples=100|min_us=40922.67|mean_us=41000.06|max_us=41083.23|stddev_us=31.57|p999_us=41083.23|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=4101.088|rps=24.38|p50_us=41002.56|p95_us=41042.55|p99_us=41057.81|samples=100|min_us=40941.07|mean_us=41010.72|max_us=41975.24|stddev_us=100.37|p999_us=41975.24|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4099.969|rps=24.39|p50_us=41000.43|p95_us=41043.97|p99_us=41072.42|samples=100|min_us=40920.75|mean_us=40999.55|max_us=41074.52|stddev_us=31.91|p999_us=41074.52|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4099.968|rps=24.39|p50_us=40998.26|p95_us=41059.05|p99_us=41080.32|samples=100|min_us=40913.65|mean_us=40999.56|max_us=41099.91|stddev_us=33.05|p999_us=41099.91|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=4100.015|rps=24.39|p50_us=41000.18|p95_us=41045.71|p99_us=41064.25|samples=100|min_us=40915.19|mean_us=41000.00|max_us=41082.00|stddev_us=28.54|p999_us=41082.00|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=4101.013|rps=24.38|p50_us=40997.34|p95_us=41050.16|p99_us=41088.82|samples=100|min_us=40925.41|mean_us=41009.97|max_us=41921.03|stddev_us=96.36|p999_us=41921.03|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=4099.926|rps=24.39|p50_us=40999.52|p95_us=41041.24|p99_us=41047.82|samples=100|min_us=40936.95|mean_us=40999.10|max_us=41059.47|stddev_us=28.03|p999_us=41059.47|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=4100.950|rps=24.38|p50_us=40998.41|p95_us=41046.43|p99_us=41064.23|samples=100|min_us=40935.09|mean_us=41009.37|max_us=41979.03|stddev_us=101.04|p999_us=41979.03|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=4100.058|rps=24.39|p50_us=40998.11|p95_us=41047.93|p99_us=41055.25|samples=100|min_us=40943.52|mean_us=41000.42|max_us=41069.28|stddev_us=26.52|p999_us=41069.28|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=4100.014|rps=24.39|p50_us=40999.19|p95_us=41056.52|p99_us=41073.39|samples=100|min_us=40914.35|mean_us=40999.99|max_us=41073.69|stddev_us=33.88|p999_us=41073.69|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4099.980|rps=24.39|p50_us=41002.21|p95_us=41050.59|p99_us=41061.09|samples=100|min_us=40904.99|mean_us=40999.65|max_us=41063.11|stddev_us=33.08|p999_us=41063.11|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4100.039|rps=24.39|p50_us=41000.58|p95_us=41036.50|p99_us=41075.27|samples=100|min_us=40922.05|mean_us=41000.24|max_us=41108.77|stddev_us=27.69|p999_us=41108.77|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=4101.984|rps=24.38|p50_us=41000.72|p95_us=41041.96|p99_us=41970.61|samples=100|min_us=40880.94|mean_us=41019.68|max_us=41999.47|stddev_us=140.60|p999_us=41999.47|tail_ratio=1.02|cv=0.00
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=4100.048|rps=24.39|p50_us=40999.71|p95_us=41053.32|p99_us=41068.17|samples=100|min_us=40918.68|mean_us=41000.32|max_us=41069.53|stddev_us=32.61|p999_us=41069.53|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=4059.008|rps=24.64|p50_us=41000.17|p95_us=41058.14|p99_us=41080.57|samples=100|min_us=276.17|mean_us=40589.93|max_us=41091.22|stddev_us=4051.91|p999_us=41091.22|tail_ratio=1.00|cv=0.10
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=4100.093|rps=24.39|p50_us=41001.66|p95_us=41049.23|p99_us=41072.23|samples=100|min_us=40913.80|mean_us=41000.79|max_us=41085.36|stddev_us=31.66|p999_us=41085.36|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=4330.005|rps=23.09|p50_us=41017.96|p95_us=47031.35|p99_us=48018.88|samples=100|min_us=40933.68|mean_us=43299.91|max_us=48038.06|stddev_us=2945.87|p999_us=48038.06|tail_ratio=1.17|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=4100.017|rps=24.39|p50_us=40996.61|p95_us=41060.61|p99_us=41072.88|samples=100|min_us=40919.92|mean_us=41000.01|max_us=41080.98|stddev_us=36.11|p999_us=41080.98|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4100.026|rps=24.39|p50_us=40999.54|p95_us=41063.72|p99_us=41074.72|samples=100|min_us=40908.08|mean_us=41000.10|max_us=41084.95|stddev_us=35.31|p999_us=41084.95|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4129.991|rps=24.21|p50_us=41002.78|p95_us=41073.89|p99_us=47013.25|samples=100|min_us=40938.52|mean_us=41299.77|max_us=47035.33|stddev_us=1306.81|p999_us=47035.33|tail_ratio=1.15|cv=0.03
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=4438.015|rps=22.53|p50_us=46963.86|p95_us=47048.32|p99_us=47989.83|samples=100|min_us=40938.90|mean_us=44380.04|max_us=48030.56|stddev_us=3000.40|p999_us=48030.56|tail_ratio=1.02|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=4099.972|rps=24.39|p50_us=40999.93|p95_us=41056.10|p99_us=41060.06|samples=100|min_us=40924.43|mean_us=40999.56|max_us=41075.26|stddev_us=34.18|p999_us=41075.26|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=4100.996|rps=24.38|p50_us=40998.59|p95_us=41070.55|p99_us=41099.43|samples=100|min_us=40881.03|mean_us=41009.81|max_us=41939.03|stddev_us=101.24|p999_us=41939.03|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=4384.016|rps=22.81|p50_us=41045.34|p95_us=47025.36|p99_us=47971.27|samples=100|min_us=40945.43|mean_us=43840.03|max_us=47976.56|stddev_us=3019.16|p999_us=47976.56|tail_ratio=1.17|cv=0.07
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=4100.107|rps=24.39|p50_us=40999.39|p95_us=41064.88|p99_us=41088.92|samples=100|min_us=40907.32|mean_us=41000.95|max_us=41090.76|stddev_us=37.92|p999_us=41090.76|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=4099.987|rps=24.39|p50_us=40999.21|p95_us=41058.43|p99_us=41093.13|samples=100|min_us=40924.44|mean_us=40999.71|max_us=41096.90|stddev_us=34.62|p999_us=41096.90|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4101.944|rps=24.38|p50_us=41000.07|p95_us=41048.77|p99_us=41989.75|samples=100|min_us=40926.29|mean_us=41019.27|max_us=42027.36|stddev_us=144.18|p999_us=42027.36|tail_ratio=1.02|cv=0.00
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=4099.998|rps=24.39|p50_us=41000.26|p95_us=41055.04|p99_us=41077.52|samples=100|min_us=40902.81|mean_us=40999.85|max_us=41106.77|stddev_us=35.39|p999_us=41106.77|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=4100.019|rps=24.39|p50_us=40998.50|p95_us=41050.28|p99_us=41066.75|samples=100|min_us=40924.56|mean_us=41000.06|max_us=41070.28|stddev_us=31.64|p999_us=41070.28|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=4100.030|rps=24.39|p50_us=41000.68|p95_us=41066.27|p99_us=41074.60|samples=100|min_us=40910.39|mean_us=41000.13|max_us=41074.67|stddev_us=36.49|p999_us=41074.67|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=4100.025|rps=24.39|p50_us=40999.06|p95_us=41050.68|p99_us=41065.17|samples=100|min_us=40931.75|mean_us=41000.09|max_us=41082.89|stddev_us=31.70|p999_us=41082.89|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=4099.968|rps=24.39|p50_us=40997.07|p95_us=41051.18|p99_us=41097.53|samples=100|min_us=40898.87|mean_us=40999.54|max_us=41138.57|stddev_us=35.70|p999_us=41138.57|tail_ratio=1.00|cv=0.00
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=3294.990|rps=30.35|p50_us=40988.71|p95_us=41418.65|p99_us=41462.12|samples=100|min_us=424.64|mean_us=32949.78|max_us=41998.28|stddev_us=16203.62|p999_us=41998.28|tail_ratio=1.01|cv=0.49
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=3936.018|rps=25.41|p50_us=41000.01|p95_us=41053.80|p99_us=41086.92|samples=100|min_us=394.16|mean_us=39359.99|max_us=41095.49|stddev_us=7943.44|p999_us=41095.49|tail_ratio=1.00|cv=0.20
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=3977.049|rps=25.14|p50_us=40995.04|p95_us=41068.89|p99_us=41094.62|samples=100|min_us=392.31|mean_us=39770.31|max_us=41134.14|stddev_us=6920.17|p999_us=41134.14|tail_ratio=1.00|cv=0.17
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=3291.973|rps=30.38|p50_us=40986.21|p95_us=41399.88|p99_us=41466.51|samples=100|min_us=412.65|mean_us=32919.63|max_us=41501.77|stddev_us=16196.54|p999_us=41501.77|tail_ratio=1.01|cv=0.49
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3294.923|rps=30.35|p50_us=40995.12|p95_us=41382.92|p99_us=41404.08|samples=100|min_us=465.93|mean_us=32949.12|max_us=41448.72|stddev_us=16192.82|p999_us=41448.72|tail_ratio=1.01|cv=0.49
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3771.939|rps=26.51|p50_us=40992.65|p95_us=41058.78|p99_us=41076.23|samples=100|min_us=343.36|mean_us=37719.22|max_us=41166.71|stddev_us=10998.58|p999_us=41166.71|tail_ratio=1.00|cv=0.29
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3935.972|rps=25.41|p50_us=40996.76|p95_us=41059.13|p99_us=41087.46|samples=100|min_us=364.59|mean_us=39359.55|max_us=41090.43|stddev_us=7942.23|p999_us=41090.43|tail_ratio=1.00|cv=0.20
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3289.884|rps=30.40|p50_us=40995.58|p95_us=41394.91|p99_us=41495.42|samples=100|min_us=315.85|mean_us=32898.70|max_us=41535.60|stddev_us=16211.38|p999_us=41535.60|tail_ratio=1.01|cv=0.49
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=1037.924|rps=96.35|p50_us=657.67|p95_us=41286.75|p99_us=41495.12|samples=100|min_us=554.05|mean_us=10379.13|max_us=41541.36|stddev_us=17270.61|p999_us=41541.36|tail_ratio=63.09|cv=1.66
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=3679.021|rps=27.18|p50_us=41023.25|p95_us=41982.42|p99_us=42027.06|samples=100|min_us=785.27|mean_us=36790.07|max_us=42032.19|stddev_us=12615.48|p999_us=42032.19|tail_ratio=1.02|cv=0.34
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=3459.908|rps=28.90|p50_us=41000.87|p95_us=41173.65|p99_us=41277.64|samples=100|min_us=737.95|mean_us=34598.98|max_us=41290.24|stddev_us=14722.43|p999_us=41290.24|tail_ratio=1.01|cv=0.43
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=2289.829|rps=43.67|p50_us=40785.47|p95_us=41360.77|p99_us=41543.01|samples=100|min_us=603.02|mean_us=22898.18|max_us=41609.51|stddev_us=20066.00|p999_us=41609.51|tail_ratio=1.02|cv=0.88
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=1645.287|rps=60.78|p50_us=764.59|p95_us=41427.31|p99_us=41585.71|samples=100|min_us=563.67|mean_us=16452.78|max_us=41594.86|stddev_us=19719.52|p999_us=41594.86|tail_ratio=54.39|cv=1.20
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3544.909|rps=28.21|p50_us=40992.68|p95_us=41266.69|p99_us=42001.01|samples=100|min_us=761.41|mean_us=35448.95|max_us=42012.37|stddev_us=13947.11|p999_us=42012.37|tail_ratio=1.02|cv=0.39
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3422.015|rps=29.22|p50_us=40993.52|p95_us=41286.21|p99_us=41963.46|samples=100|min_us=698.61|mean_us=34220.04|max_us=41976.15|stddev_us=15092.96|p999_us=41976.15|tail_ratio=1.02|cv=0.44
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=1922.791|rps=52.01|p50_us=747.84|p95_us=41355.62|p99_us=41420.66|samples=100|min_us=525.06|mean_us=19227.82|max_us=41465.80|stddev_us=20160.67|p999_us=41465.80|tail_ratio=55.39|cv=1.05
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=2616.169|rps=38.22|p50_us=7205.12|p95_us=47802.71|p99_us=48005.78|samples=100|min_us=5841.73|mean_us=26161.59|max_us=48048.63|stddev_us=20020.27|p999_us=48048.63|tail_ratio=6.66|cv=0.77
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=2651.968|rps=37.71|p50_us=40972.25|p95_us=41359.45|p99_us=41392.36|samples=100|min_us=428.12|mean_us=26519.53|max_us=41406.67|stddev_us=19408.07|p999_us=41406.67|tail_ratio=1.01|cv=0.73
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=2406.741|rps=41.55|p50_us=40827.62|p95_us=41372.53|p99_us=41483.07|samples=100|min_us=417.49|mean_us=24067.27|max_us=41580.22|stddev_us=19963.65|p999_us=41580.22|tail_ratio=1.02|cv=0.83
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=2288.006|rps=43.71|p50_us=6246.44|p95_us=47072.34|p99_us=47904.13|samples=100|min_us=5891.89|mean_us=22879.96|max_us=47990.72|stddev_us=20027.09|p999_us=47990.72|tail_ratio=7.67|cv=0.88
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=2079.141|rps=48.10|p50_us=6188.66|p95_us=47021.19|p99_us=47955.76|samples=100|min_us=5918.35|mean_us=20791.31|max_us=47994.33|stddev_us=19659.97|p999_us=47994.33|tail_ratio=7.75|cv=0.95
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=2858.422|rps=34.98|p50_us=40994.15|p95_us=41271.34|p99_us=41461.17|samples=100|min_us=636.49|mean_us=28584.05|max_us=41544.26|stddev_us=18634.77|p999_us=41544.26|tail_ratio=1.01|cv=0.65
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3101.025|rps=32.25|p50_us=40999.12|p95_us=41256.90|p99_us=41371.27|samples=100|min_us=626.42|mean_us=31010.08|max_us=41853.74|stddev_us=17431.91|p999_us=41853.74|tail_ratio=1.01|cv=0.56
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3349.018|rps=29.86|p50_us=46633.44|p95_us=47990.07|p99_us=48043.72|samples=100|min_us=5823.70|mean_us=33490.07|max_us=48078.47|stddev_us=18348.34|p999_us=48078.47|tail_ratio=1.03|cv=0.55
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=1828.863|rps=54.68|p50_us=1025.10|p95_us=41982.28|p99_us=42025.36|samples=100|min_us=717.92|mean_us=18288.53|max_us=42032.22|stddev_us=20037.84|p999_us=42032.22|tail_ratio=41.00|cv=1.10
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=3027.205|rps=33.03|p50_us=41005.97|p95_us=41957.73|p99_us=41972.68|samples=100|min_us=560.80|mean_us=30271.88|max_us=42048.11|stddev_us=17988.21|p999_us=42048.11|tail_ratio=1.02|cv=0.59
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=2696.640|rps=37.08|p50_us=40987.45|p95_us=41429.62|p99_us=41933.30|samples=100|min_us=562.10|mean_us=26966.24|max_us=41941.86|stddev_us=19269.50|p999_us=41941.86|tail_ratio=1.02|cv=0.71
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=2236.008|rps=44.72|p50_us=40970.74|p95_us=41994.40|p99_us=42037.06|samples=100|min_us=731.11|mean_us=22359.96|max_us=42076.14|stddev_us=20209.28|p999_us=42076.14|tail_ratio=1.03|cv=0.90
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=1255.306|rps=79.66|p50_us=845.60|p95_us=41542.39|p99_us=41734.61|samples=100|min_us=694.93|mean_us=12552.96|max_us=41788.77|stddev_us=18318.96|p999_us=41788.77|tail_ratio=49.36|cv=1.46
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3030.097|rps=33.00|p50_us=41012.86|p95_us=41979.43|p99_us=42008.66|samples=100|min_us=569.67|mean_us=30300.79|max_us=42019.26|stddev_us=17985.26|p999_us=42019.26|tail_ratio=1.02|cv=0.59
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3653.954|rps=27.37|p50_us=41048.85|p95_us=41994.29|p99_us=42009.75|samples=100|min_us=787.80|mean_us=36539.37|max_us=42022.74|stddev_us=13170.40|p999_us=42022.74|tail_ratio=1.02|cv=0.36
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=tonic|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=1954.062|rps=51.18|p50_us=1132.87|p95_us=41952.02|p99_us=42049.92|samples=100|min_us=710.02|mean_us=19540.51|max_us=42058.66|stddev_us=20146.27|p999_us=42058.66|tail_ratio=37.12|cv=1.03
INTEROP|case=grpc_status_both_clients_to_courierust|ok
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=21.614|rps=4626.61|p50_us=209.90|p95_us=253.64|p99_us=264.10|samples=100|min_us=191.07|mean_us=216.05|max_us=266.60|stddev_us=17.54|p999_us=266.60|tail_ratio=1.26|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=29.654|rps=3372.27|p50_us=294.10|p95_us=336.36|p99_us=356.42|samples=100|min_us=249.02|mean_us=296.44|max_us=411.25|stddev_us=22.27|p999_us=411.25|tail_ratio=1.21|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=30.059|rps=3326.77|p50_us=296.74|p95_us=332.21|p99_us=346.58|samples=100|min_us=259.69|mean_us=300.50|max_us=349.90|stddev_us=19.83|p999_us=349.90|tail_ratio=1.17|cv=0.07
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=21.403|rps=4672.25|p50_us=207.15|p95_us=253.81|p99_us=267.57|samples=100|min_us=192.43|mean_us=213.94|max_us=289.04|stddev_us=19.21|p999_us=289.04|tail_ratio=1.29|cv=0.09
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=21.473|rps=4657.01|p50_us=209.30|p95_us=254.75|p99_us=266.97|samples=100|min_us=192.36|mean_us=214.65|max_us=274.05|stddev_us=17.78|p999_us=274.05|tail_ratio=1.28|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=29.712|rps=3365.60|p50_us=296.03|p95_us=335.73|p99_us=351.71|samples=100|min_us=243.30|mean_us=297.03|max_us=356.93|stddev_us=20.71|p999_us=356.93|tail_ratio=1.19|cv=0.07
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=29.784|rps=3357.46|p50_us=295.40|p95_us=334.73|p99_us=346.33|samples=100|min_us=262.07|mean_us=297.75|max_us=354.67|stddev_us=18.05|p999_us=354.67|tail_ratio=1.17|cv=0.06
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=21.959|rps=4554.01|p50_us=216.38|p95_us=254.95|p99_us=282.09|samples=100|min_us=192.05|mean_us=219.50|max_us=287.98|stddev_us=18.68|p999_us=287.98|tail_ratio=1.30|cv=0.09
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=22.789|rps=4387.99|p50_us=224.95|p95_us=262.89|p99_us=278.01|samples=100|min_us=195.72|mean_us=227.81|max_us=282.49|stddev_us=18.29|p999_us=282.49|tail_ratio=1.24|cv=0.08
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=29.222|rps=3422.10|p50_us=294.21|p95_us=328.93|p99_us=348.10|samples=100|min_us=254.21|mean_us=292.13|max_us=353.34|stddev_us=20.69|p999_us=353.34|tail_ratio=1.18|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=29.064|rps=3440.71|p50_us=287.50|p95_us=322.86|p99_us=333.24|samples=100|min_us=256.86|mean_us=290.52|max_us=383.35|stddev_us=20.43|p999_us=383.35|tail_ratio=1.16|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=22.928|rps=4361.54|p50_us=223.71|p95_us=274.94|p99_us=299.27|samples=100|min_us=197.09|mean_us=229.19|max_us=299.75|stddev_us=21.31|p999_us=299.75|tail_ratio=1.34|cv=0.09
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=22.974|rps=4352.78|p50_us=222.94|p95_us=272.26|p99_us=288.33|samples=100|min_us=196.30|mean_us=229.66|max_us=289.10|stddev_us=21.05|p999_us=289.10|tail_ratio=1.29|cv=0.09
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=29.430|rps=3397.93|p50_us=294.72|p95_us=329.94|p99_us=344.81|samples=100|min_us=256.59|mean_us=294.20|max_us=346.08|stddev_us=20.57|p999_us=346.08|tail_ratio=1.17|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=29.274|rps=3415.95|p50_us=288.38|p95_us=329.55|p99_us=339.75|samples=100|min_us=261.40|mean_us=292.65|max_us=341.70|stddev_us=19.11|p999_us=341.70|tail_ratio=1.18|cv=0.07
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=22.915|rps=4363.95|p50_us=225.22|p95_us=255.48|p99_us=280.06|samples=100|min_us=210.84|mean_us=229.06|max_us=288.19|stddev_us=15.85|p999_us=288.19|tail_ratio=1.24|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=207.265|rps=482.47|p50_us=252.22|p95_us=6002.38|p99_us=6282.64|samples=100|min_us=226.90|mean_us=2072.57|max_us=6285.46|stddev_us=2607.78|p999_us=6285.46|tail_ratio=24.91|cv=1.26
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=29.427|rps=3398.29|p50_us=287.52|p95_us=332.77|p99_us=352.64|samples=100|min_us=265.45|mean_us=294.17|max_us=396.47|stddev_us=22.25|p999_us=396.47|tail_ratio=1.23|cv=0.08
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=29.484|rps=3391.69|p50_us=291.37|p95_us=326.04|p99_us=358.62|samples=100|min_us=262.09|mean_us=294.75|max_us=367.21|stddev_us=21.34|p999_us=367.21|tail_ratio=1.23|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=205.270|rps=487.16|p50_us=247.66|p95_us=6524.09|p99_us=7217.30|samples=100|min_us=229.21|mean_us=2052.61|max_us=7299.18|stddev_us=2713.88|p999_us=7299.18|tail_ratio=29.14|cv=1.32
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=226.970|rps=440.59|p50_us=254.11|p95_us=6528.21|p99_us=7010.94|samples=100|min_us=227.77|mean_us=2269.62|max_us=7015.02|stddev_us=2766.82|p999_us=7015.02|tail_ratio=27.59|cv=1.22
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=30.067|rps=3325.94|p50_us=299.98|p95_us=340.55|p99_us=352.98|samples=100|min_us=263.61|mean_us=300.55|max_us=362.19|stddev_us=21.35|p999_us=362.19|tail_ratio=1.18|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=29.535|rps=3385.87|p50_us=295.12|p95_us=329.38|p99_us=347.76|samples=100|min_us=250.42|mean_us=295.25|max_us=347.96|stddev_us=20.57|p999_us=347.96|tail_ratio=1.18|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=44.115|rps=2266.81|p50_us=260.86|p95_us=299.83|p99_us=6136.27|samples=100|min_us=244.37|mean_us=441.05|max_us=6257.72|stddev_us=997.57|p999_us=6257.72|tail_ratio=23.52|cv=2.26
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=51.071|rps=1958.04|p50_us=267.79|p95_us=331.16|p99_us=6277.11|samples=100|min_us=248.06|mean_us=510.62|max_us=6305.94|stddev_us=1170.90|p999_us=6305.94|tail_ratio=23.44|cv=2.29
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=29.735|rps=3363.06|p50_us=292.86|p95_us=335.64|p99_us=342.06|samples=100|min_us=266.49|mean_us=297.25|max_us=357.42|stddev_us=19.29|p999_us=357.42|tail_ratio=1.17|cv=0.06
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=29.656|rps=3372.03|p50_us=291.34|p95_us=335.58|p99_us=359.65|samples=100|min_us=255.61|mean_us=296.46|max_us=359.92|stddev_us=22.67|p999_us=359.92|tail_ratio=1.23|cv=0.08
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=97.013|rps=1030.79|p50_us=274.25|p95_us=6178.62|p99_us=6976.36|samples=100|min_us=238.79|mean_us=970.04|max_us=7189.12|stddev_us=1901.21|p999_us=7189.12|tail_ratio=25.44|cv=1.96
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=73.840|rps=1354.28|p50_us=265.76|p95_us=5731.61|p99_us=7101.90|samples=100|min_us=240.24|mean_us=738.31|max_us=7199.62|stddev_us=1599.82|p999_us=7199.62|tail_ratio=26.72|cv=2.17
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=30.072|rps=3325.41|p50_us=296.89|p95_us=345.92|p99_us=362.41|samples=100|min_us=264.68|mean_us=300.58|max_us=363.48|stddev_us=23.02|p999_us=363.48|tail_ratio=1.22|cv=0.08
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=35.798|rps=2793.49|p50_us=295.07|p95_us=338.47|p99_us=403.69|samples=100|min_us=264.70|mean_us=357.88|max_us=6263.17|stddev_us=593.98|p999_us=6263.17|tail_ratio=1.37|cv=1.66
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=141.899|rps=704.73|p50_us=261.15|p95_us=6253.55|p99_us=7184.13|samples=100|min_us=232.53|mean_us=1418.90|max_us=7196.46|stddev_us=2328.94|p999_us=7196.46|tail_ratio=27.51|cv=1.64
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=33.970|rps=2943.77|p50_us=336.97|p95_us=380.76|p99_us=398.65|samples=100|min_us=306.34|mean_us=339.61|max_us=444.33|stddev_us=23.91|p999_us=444.33|tail_ratio=1.18|cv=0.07
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=39.800|rps=2512.55|p50_us=391.84|p95_us=454.91|p99_us=468.17|samples=100|min_us=340.13|mean_us=397.90|max_us=498.42|stddev_us=30.27|p999_us=498.42|tail_ratio=1.19|cv=0.08
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=39.065|rps=2559.81|p50_us=382.08|p95_us=438.18|p99_us=458.99|samples=100|min_us=349.28|mean_us=390.56|max_us=484.12|stddev_us=29.23|p999_us=484.12|tail_ratio=1.20|cv=0.07
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=34.386|rps=2908.17|p50_us=338.87|p95_us=381.56|p99_us=395.28|samples=100|min_us=312.00|mean_us=343.77|max_us=444.97|stddev_us=20.28|p999_us=444.97|tail_ratio=1.17|cv=0.06
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=33.295|rps=3003.43|p50_us=326.57|p95_us=363.61|p99_us=382.61|samples=100|min_us=307.94|mean_us=332.87|max_us=395.76|stddev_us=18.32|p999_us=395.76|tail_ratio=1.17|cv=0.06
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=40.229|rps=2485.78|p50_us=396.81|p95_us=451.76|p99_us=476.63|samples=100|min_us=360.18|mean_us=402.19|max_us=477.13|stddev_us=28.42|p999_us=477.13|tail_ratio=1.20|cv=0.07
COMPARISON|protocol=grpc-h2|case=Unary|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=40.763|rps=2453.19|p50_us=408.78|p95_us=456.94|p99_us=470.57|samples=100|min_us=350.77|mean_us=407.54|max_us=730.53|stddev_us=44.26|p999_us=730.53|tail_ratio=1.15|cv=0.11
COMPARISON|protocol=grpc-h2|case=Unary|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=33.737|rps=2964.08|p50_us=335.96|p95_us=369.39|p99_us=378.93|samples=100|min_us=299.79|mean_us=337.29|max_us=380.26|stddev_us=18.52|p999_us=380.26|tail_ratio=1.13|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=45.950|rps=2176.29|p50_us=453.65|p95_us=496.46|p99_us=559.18|samples=100|min_us=433.66|mean_us=459.40|max_us=569.52|stddev_us=24.64|p999_us=569.52|tail_ratio=1.23|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=51.702|rps=1934.15|p50_us=510.00|p95_us=577.61|p99_us=602.01|samples=100|min_us=475.40|mean_us=516.91|max_us=614.03|stddev_us=27.81|p999_us=614.03|tail_ratio=1.18|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=57.189|rps=1748.59|p50_us=509.80|p95_us=556.67|p99_us=572.28|samples=100|min_us=458.33|mean_us=571.77|max_us=6363.92|stddev_us=582.55|p999_us=6363.92|tail_ratio=1.12|cv=1.02
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=45.557|rps=2195.05|p50_us=450.30|p95_us=491.14|p99_us=516.77|samples=100|min_us=423.66|mean_us=455.48|max_us=537.62|stddev_us=20.88|p999_us=537.62|tail_ratio=1.15|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=45.078|rps=2218.37|p50_us=446.03|p95_us=490.38|p99_us=506.27|samples=100|min_us=423.21|mean_us=450.68|max_us=507.40|stddev_us=20.38|p999_us=507.40|tail_ratio=1.14|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=59.067|rps=1692.98|p50_us=529.13|p95_us=579.01|p99_us=593.53|samples=100|min_us=471.53|mean_us=590.56|max_us=6424.59|stddev_us=587.08|p999_us=6424.59|tail_ratio=1.12|cv=0.99
COMPARISON|protocol=grpc-h2|case=ServerStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=51.803|rps=1930.39|p50_us=515.63|p95_us=565.77|p99_us=580.29|samples=100|min_us=454.38|mean_us=517.92|max_us=647.23|stddev_us=27.25|p999_us=647.23|tail_ratio=1.13|cv=0.05
COMPARISON|protocol=grpc-h2|case=ServerStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=45.777|rps=2184.50|p50_us=452.57|p95_us=506.40|p99_us=527.37|samples=100|min_us=426.29|mean_us=457.68|max_us=553.62|stddev_us=23.60|p999_us=553.62|tail_ratio=1.17|cv=0.05
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=487.016|rps=205.33|p50_us=6872.91|p95_us=7989.53|p99_us=8124.62|samples=100|min_us=895.63|mean_us=4870.07|max_us=8131.98|stddev_us=2942.84|p999_us=8131.98|tail_ratio=1.18|cv=0.60
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=108.908|rps=918.21|p50_us=1122.75|p95_us=1174.25|p99_us=1226.16|samples=100|min_us=918.20|mean_us=1088.97|max_us=1236.49|stddev_us=80.58|p999_us=1236.49|tail_ratio=1.09|cv=0.07
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=110.746|rps=902.97|p50_us=1131.31|p95_us=1173.61|p99_us=1190.37|samples=100|min_us=937.24|mean_us=1107.35|max_us=1200.47|stddev_us=63.50|p999_us=1200.47|tail_ratio=1.05|cv=0.06
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=382.670|rps=261.32|p50_us=1231.61|p95_us=7984.62|p99_us=8061.04|samples=100|min_us=947.81|mean_us=3826.61|max_us=8200.74|stddev_us=3003.93|p999_us=8200.74|tail_ratio=6.55|cv=0.79
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=344.297|rps=290.45|p50_us=1215.92|p95_us=7775.98|p99_us=8054.80|samples=100|min_us=936.33|mean_us=3442.88|max_us=8125.08|stddev_us=2886.73|p999_us=8125.08|tail_ratio=6.62|cv=0.84
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=115.977|rps=862.24|p50_us=1084.83|p95_us=1369.41|p99_us=1891.98|samples=100|min_us=965.08|mean_us=1159.66|max_us=2903.13|stddev_us=234.80|p999_us=2903.13|tail_ratio=1.74|cv=0.20
COMPARISON|protocol=grpc-h2|case=ClientStream|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=113.282|rps=882.75|p50_us=1087.06|p95_us=1325.63|p99_us=1445.37|samples=100|min_us=979.91|mean_us=1132.71|max_us=1465.34|stddev_us=104.79|p999_us=1465.34|tail_ratio=1.33|cv=0.09
COMPARISON|protocol=grpc-h2|case=ClientStream|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=395.849|rps=252.62|p50_us=1243.53|p95_us=7860.44|p99_us=8058.50|samples=100|min_us=884.83|mean_us=3958.40|max_us=8110.25|stddev_us=2982.56|p999_us=8110.25|tail_ratio=6.48|cv=0.75
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=629.015|rps=158.98|p50_us=6998.18|p95_us=8022.79|p99_us=8026.12|samples=100|min_us=1025.53|mean_us=6290.05|max_us=8035.06|stddev_us=2155.25|p999_us=8035.06|tail_ratio=1.15|cv=0.34
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=116.442|rps=858.80|p50_us=1096.68|p95_us=1279.78|p99_us=1323.16|samples=100|min_us=960.67|mean_us=1164.30|max_us=6937.07|stddev_us=588.97|p999_us=6937.07|tail_ratio=1.21|cv=0.51
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=114.231|rps=875.42|p50_us=1133.19|p95_us=1282.93|p99_us=1308.70|samples=100|min_us=978.01|mean_us=1142.20|max_us=1309.47|stddev_us=96.50|p999_us=1309.47|tail_ratio=1.15|cv=0.08
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=624.999|rps=160.00|p50_us=6996.33|p95_us=7946.86|p99_us=8029.12|samples=100|min_us=1066.54|mean_us=6249.89|max_us=8037.58|stddev_us=2042.50|p999_us=8037.58|tail_ratio=1.15|cv=0.33
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=654.031|rps=152.90|p50_us=7000.14|p95_us=7999.07|p99_us=8021.99|samples=100|min_us=1041.78|mean_us=6540.21|max_us=8021.99|stddev_us=1776.13|p999_us=8021.99|tail_ratio=1.15|cv=0.27
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=108.982|rps=917.58|p50_us=1065.33|p95_us=1257.25|p99_us=1292.08|samples=100|min_us=959.52|mean_us=1089.71|max_us=1313.41|stddev_us=92.06|p999_us=1313.41|tail_ratio=1.21|cv=0.08
COMPARISON|protocol=grpc-h2|case=Bidi|client=tonic|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=111.795|rps=894.50|p50_us=1104.60|p95_us=1261.43|p99_us=1289.68|samples=100|min_us=958.59|mean_us=1117.84|max_us=1292.36|stddev_us=93.99|p999_us=1292.36|tail_ratio=1.17|cv=0.08
COMPARISON|protocol=grpc-h2|case=Bidi|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=555.984|rps=179.86|p50_us=6998.82|p95_us=8012.50|p99_us=8026.65|samples=100|min_us=1073.38|mean_us=5559.75|max_us=8038.59|stddev_us=2782.58|p999_us=8038.59|tail_ratio=1.15|cv=0.50
~~~

### tls.log
~~~text
META|suite=tls|layer=tls_over_tcp|alpn=courierust-benchmark|verify=true|resumption=disabled|certificate=bench_h3_p256|courierust_clienthello=chrome_profile_with_pinned_crypto|rustls_provider=aws_lc_rs|nodelay=true|timeout_s=5|connections=1|load=closed_loop|validation=negotiated_parameters_and_full_payload|order=alternating
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=273.297|rps=365.90|p50_us=2729.78|p95_us=2762.70|p99_us=2816.83|samples=100|min_us=2690.89|mean_us=2732.85|max_us=2846.70|stddev_us=23.56|p999_us=2846.70|tail_ratio=1.03|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=54.980|rps=1818.85|p50_us=551.55|p95_us=575.05|p99_us=584.52|samples=100|min_us=526.46|mean_us=549.72|max_us=589.58|stddev_us=15.45|p999_us=589.58|tail_ratio=1.06|cv=0.03
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=54.716|rps=1827.63|p50_us=548.43|p95_us=571.03|p99_us=580.44|samples=100|min_us=525.61|mean_us=547.08|max_us=587.28|stddev_us=13.97|p999_us=587.28|tail_ratio=1.06|cv=0.03
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=274.880|rps=363.80|p50_us=2746.08|p95_us=2798.64|p99_us=2835.25|samples=100|min_us=2691.78|mean_us=2748.67|max_us=2910.64|stddev_us=30.07|p999_us=2910.64|tail_ratio=1.03|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=273.862|rps=365.15|p50_us=2733.48|p95_us=2787.52|p99_us=2800.99|samples=100|min_us=2693.65|mean_us=2738.50|max_us=2802.82|stddev_us=23.96|p999_us=2802.82|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=54.597|rps=1831.60|p50_us=547.21|p95_us=570.98|p99_us=573.45|samples=100|min_us=525.32|mean_us=545.89|max_us=578.11|stddev_us=13.31|p999_us=578.11|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=54.496|rps=1835.00|p50_us=545.33|p95_us=563.19|p99_us=573.31|samples=100|min_us=524.21|mean_us=544.88|max_us=576.70|stddev_us=12.38|p999_us=576.70|tail_ratio=1.05|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=275.701|rps=362.71|p50_us=2750.89|p95_us=2784.80|p99_us=2907.50|samples=100|min_us=2700.18|mean_us=2756.88|max_us=3114.61|stddev_us=42.48|p999_us=3114.61|tail_ratio=1.06|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=9.493|rps=10533.74|p50_us=92.13|p95_us=111.59|p99_us=117.57|samples=100|min_us=90.60|mean_us=94.88|max_us=120.75|stddev_us=6.46|p999_us=120.75|tail_ratio=1.28|cv=0.07
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=4.101|rps=24383.35|p50_us=36.52|p95_us=56.31|p99_us=61.90|samples=100|min_us=35.13|mean_us=40.96|max_us=63.85|stddev_us=6.77|p999_us=63.85|tail_ratio=1.69|cv=0.17
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=3.844|rps=26012.75|p50_us=36.32|p95_us=47.78|p99_us=55.63|samples=100|min_us=35.35|mean_us=38.40|max_us=75.18|stddev_us=5.46|p999_us=75.18|tail_ratio=1.53|cv=0.14
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=10.144|rps=9858.33|p50_us=102.72|p95_us=118.69|p99_us=145.75|samples=100|min_us=90.88|mean_us=101.38|max_us=155.52|stddev_us=11.75|p999_us=155.52|tail_ratio=1.42|cv=0.12
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=9.475|rps=10554.24|p50_us=91.98|p95_us=109.98|p99_us=118.07|samples=100|min_us=90.92|mean_us=94.70|max_us=118.86|stddev_us=6.37|p999_us=118.86|tail_ratio=1.28|cv=0.07
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3.801|rps=26311.24|p50_us=36.46|p95_us=46.32|p99_us=57.07|samples=100|min_us=35.55|mean_us=37.96|max_us=62.77|stddev_us=4.56|p999_us=62.77|tail_ratio=1.57|cv=0.12
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3.788|rps=26400.81|p50_us=36.29|p95_us=46.92|p99_us=58.67|samples=100|min_us=35.28|mean_us=37.83|max_us=59.04|stddev_us=4.72|p999_us=59.04|tail_ratio=1.62|cv=0.12
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=9.732|rps=10275.80|p50_us=93.04|p95_us=118.97|p99_us=125.23|samples=100|min_us=90.78|mean_us=97.27|max_us=129.92|stddev_us=8.75|p999_us=129.92|tail_ratio=1.35|cv=0.09
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=319.991|rps=312.51|p50_us=3196.96|p95_us=3233.48|p99_us=3253.85|samples=100|min_us=3168.10|mean_us=3199.83|max_us=3260.25|stddev_us=15.98|p999_us=3260.25|tail_ratio=1.02|cv=0.00
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=16.314|rps=6129.76|p50_us=159.30|p95_us=181.74|p99_us=187.29|samples=100|min_us=154.28|mean_us=163.07|max_us=205.04|stddev_us=9.52|p999_us=205.04|tail_ratio=1.18|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=16.049|rps=6230.77|p50_us=156.36|p95_us=181.30|p99_us=189.27|samples=100|min_us=154.17|mean_us=160.42|max_us=191.08|stddev_us=8.80|p999_us=191.08|tail_ratio=1.21|cv=0.05
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=319.192|rps=313.29|p50_us=3188.63|p95_us=3223.89|p99_us=3233.87|samples=100|min_us=3164.36|mean_us=3191.84|max_us=3252.86|stddev_us=14.37|p999_us=3252.86|tail_ratio=1.01|cv=0.00
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=321.704|rps=310.84|p50_us=3206.38|p95_us=3260.41|p99_us=3488.33|samples=100|min_us=3167.62|mean_us=3216.95|max_us=3496.56|stddev_us=47.12|p999_us=3496.56|tail_ratio=1.09|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=16.265|rps=6148.15|p50_us=158.25|p95_us=181.08|p99_us=185.68|samples=100|min_us=154.22|mean_us=162.47|max_us=208.51|stddev_us=9.17|p999_us=208.51|tail_ratio=1.17|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=15.954|rps=6268.03|p50_us=156.26|p95_us=176.16|p99_us=185.44|samples=100|min_us=152.14|mean_us=159.47|max_us=194.35|stddev_us=8.12|p999_us=194.35|tail_ratio=1.19|cv=0.05
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=319.388|rps=313.10|p50_us=3189.91|p95_us=3217.39|p99_us=3234.14|samples=100|min_us=3175.18|mean_us=3193.80|max_us=3245.02|stddev_us=12.87|p999_us=3245.02|tail_ratio=1.01|cv=0.00
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=378.563|rps=264.16|p50_us=3783.55|p95_us=3827.64|p99_us=3851.70|samples=100|min_us=3746.56|mean_us=3785.50|max_us=3910.21|stddev_us=22.41|p999_us=3910.21|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=160.565|rps=622.80|p50_us=1595.99|p95_us=1650.17|p99_us=1750.88|samples=100|min_us=1569.02|mean_us=1605.53|max_us=1836.27|stddev_us=34.45|p999_us=1836.27|tail_ratio=1.10|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=159.562|rps=626.71|p50_us=1595.18|p95_us=1625.35|p99_us=1647.83|samples=100|min_us=1567.73|mean_us=1595.50|max_us=1653.44|stddev_us=18.26|p999_us=1653.44|tail_ratio=1.03|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=379.387|rps=263.58|p50_us=3790.24|p95_us=3828.78|p99_us=3847.91|samples=100|min_us=3756.36|mean_us=3793.74|max_us=3885.28|stddev_us=20.73|p999_us=3885.28|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=379.394|rps=263.58|p50_us=3780.02|p95_us=3853.05|p99_us=3934.39|samples=100|min_us=3733.86|mean_us=3793.81|max_us=4281.73|stddev_us=59.42|p999_us=4281.73|tail_ratio=1.04|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=159.974|rps=625.10|p50_us=1595.19|p95_us=1628.56|p99_us=1647.04|samples=100|min_us=1570.09|mean_us=1599.62|max_us=1660.80|stddev_us=19.10|p999_us=1660.80|tail_ratio=1.03|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=159.394|rps=627.38|p50_us=1593.59|p95_us=1619.42|p99_us=1628.13|samples=100|min_us=1566.20|mean_us=1593.81|max_us=1632.29|stddev_us=15.58|p999_us=1632.29|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=378.739|rps=264.03|p50_us=3774.14|p95_us=3820.11|p99_us=4170.94|samples=100|min_us=3733.62|mean_us=3787.27|max_us=4553.92|stddev_us=89.25|p999_us=4553.92|tail_ratio=1.11|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=16.042|rps=6233.52|p50_us=155.90|p95_us=182.86|p99_us=183.92|samples=100|min_us=154.19|mean_us=160.36|max_us=184.60|stddev_us=9.11|p999_us=184.60|tail_ratio=1.18|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=9.475|rps=10554.61|p50_us=91.76|p95_us=110.93|p99_us=121.56|samples=100|min_us=90.88|mean_us=94.70|max_us=122.59|stddev_us=6.59|p999_us=122.59|tail_ratio=1.32|cv=0.07
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=9.416|rps=10620.24|p50_us=91.88|p95_us=104.58|p99_us=117.38|samples=100|min_us=90.85|mean_us=94.11|max_us=119.23|stddev_us=5.42|p999_us=119.23|tail_ratio=1.28|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=15.145|rps=6602.85|p50_us=147.66|p95_us=165.53|p99_us=174.25|samples=100|min_us=145.75|mean_us=151.40|max_us=177.14|stddev_us=7.36|p999_us=177.14|tail_ratio=1.18|cv=0.05
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=15.169|rps=6592.57|p50_us=147.50|p95_us=172.18|p99_us=179.17|samples=100|min_us=145.94|mean_us=151.63|max_us=186.45|stddev_us=8.69|p999_us=186.45|tail_ratio=1.21|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=9.448|rps=10583.83|p50_us=91.65|p95_us=109.88|p99_us=114.98|samples=100|min_us=90.78|mean_us=94.44|max_us=121.35|stddev_us=6.28|p999_us=121.35|tail_ratio=1.25|cv=0.07
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=9.496|rps=10530.92|p50_us=91.94|p95_us=107.12|p99_us=119.96|samples=100|min_us=90.53|mean_us=94.91|max_us=143.19|stddev_us=7.51|p999_us=143.19|tail_ratio=1.30|cv=0.08
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=15.245|rps=6559.40|p50_us=147.75|p95_us=174.73|p99_us=184.78|samples=100|min_us=146.04|mean_us=152.41|max_us=195.87|stddev_us=9.74|p999_us=195.87|tail_ratio=1.25|cv=0.06
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=646.090|rps=154.78|p50_us=6465.03|p95_us=6679.45|p99_us=6693.30|samples=100|min_us=6175.62|mean_us=6460.80|max_us=6708.19|stddev_us=127.32|p999_us=6708.19|tail_ratio=1.04|cv=0.02
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=319.437|rps=313.05|p50_us=3189.66|p95_us=3220.78|p99_us=3242.16|samples=100|min_us=3175.21|mean_us=3194.28|max_us=3254.33|stddev_us=13.34|p999_us=3254.33|tail_ratio=1.02|cv=0.00
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=319.852|rps=312.64|p50_us=3191.37|p95_us=3236.14|p99_us=3308.22|samples=100|min_us=3177.16|mean_us=3198.42|max_us=3352.98|stddev_us=24.37|p999_us=3352.98|tail_ratio=1.04|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=624.881|rps=160.03|p50_us=6227.65|p95_us=6416.21|p99_us=6534.05|samples=100|min_us=6201.22|mean_us=6248.70|max_us=6596.33|stddev_us=67.86|p999_us=6596.33|tail_ratio=1.05|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=704.374|rps=141.97|p50_us=6519.43|p95_us=8877.02|p99_us=9005.01|samples=100|min_us=6197.90|mean_us=7043.64|max_us=9049.91|stddev_us=1012.11|p999_us=9049.91|tail_ratio=1.38|cv=0.14
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=320.499|rps=312.01|p50_us=3199.97|p95_us=3232.67|p99_us=3273.85|samples=100|min_us=3178.42|mean_us=3204.88|max_us=3274.15|stddev_us=17.77|p999_us=3274.15|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=319.648|rps=312.84|p50_us=3188.72|p95_us=3220.57|p99_us=3256.63|samples=100|min_us=3174.65|mean_us=3196.38|max_us=3412.78|stddev_us=26.24|p999_us=3412.78|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.2-aes128gcm-p256|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=645.872|rps=154.83|p50_us=6476.85|p95_us=6670.37|p99_us=6700.05|samples=100|min_us=6191.23|mean_us=6458.62|max_us=6713.14|stddev_us=127.76|p999_us=6713.14|tail_ratio=1.03|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=201.343|rps=496.66|p50_us=2006.37|p95_us=2063.39|p99_us=2082.43|samples=100|min_us=1978.21|mean_us=2013.32|max_us=2093.21|stddev_us=25.87|p999_us=2093.21|tail_ratio=1.04|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=46.606|rps=2145.63|p50_us=469.51|p95_us=491.40|p99_us=497.17|samples=100|min_us=444.67|mean_us=465.97|max_us=500.72|stddev_us=15.05|p999_us=500.72|tail_ratio=1.06|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=46.644|rps=2143.92|p50_us=463.81|p95_us=494.08|p99_us=512.68|samples=100|min_us=445.20|mean_us=466.34|max_us=515.56|stddev_us=15.65|p999_us=515.56|tail_ratio=1.11|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=203.493|rps=491.42|p50_us=2030.82|p95_us=2077.64|p99_us=2083.06|samples=100|min_us=1979.91|mean_us=2034.82|max_us=2108.12|stddev_us=23.00|p999_us=2108.12|tail_ratio=1.03|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=203.573|rps=491.22|p50_us=2034.74|p95_us=2061.17|p99_us=2072.23|samples=100|min_us=1989.65|mean_us=2035.62|max_us=2115.21|stddev_us=17.49|p999_us=2115.21|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=46.931|rps=2130.77|p50_us=470.86|p95_us=496.78|p99_us=503.71|samples=100|min_us=445.59|mean_us=469.21|max_us=505.19|stddev_us=15.67|p999_us=505.19|tail_ratio=1.07|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=46.859|rps=2134.08|p50_us=469.36|p95_us=497.19|p99_us=511.04|samples=100|min_us=445.10|mean_us=468.48|max_us=527.81|stddev_us=16.00|p999_us=527.81|tail_ratio=1.09|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=rustls-aws-lc|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=202.861|rps=492.95|p50_us=2026.08|p95_us=2073.05|p99_us=2099.92|samples=100|min_us=1984.75|mean_us=2028.50|max_us=2167.08|stddev_us=26.75|p999_us=2167.08|tail_ratio=1.04|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=8.858|rps=11289.24|p50_us=84.86|p95_us=106.67|p99_us=118.25|samples=100|min_us=83.63|mean_us=88.53|max_us=161.82|stddev_us=10.38|p999_us=161.82|tail_ratio=1.39|cv=0.12
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=3.782|rps=26442.96|p50_us=36.13|p95_us=48.91|p99_us=57.18|samples=100|min_us=35.36|mean_us=37.77|max_us=61.74|stddev_us=4.61|p999_us=61.74|tail_ratio=1.58|cv=0.12
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=3.775|rps=26490.20|p50_us=36.54|p95_us=41.49|p99_us=58.30|samples=100|min_us=35.88|mean_us=37.70|max_us=68.28|stddev_us=4.31|p999_us=68.28|tail_ratio=1.60|cv=0.11
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=8.650|rps=11560.87|p50_us=84.12|p95_us=102.24|p99_us=108.13|samples=100|min_us=83.27|mean_us=86.45|max_us=108.93|stddev_us=5.70|p999_us=108.93|tail_ratio=1.29|cv=0.07
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=8.673|rps=11529.64|p50_us=84.65|p95_us=98.06|p99_us=103.64|samples=100|min_us=83.37|mean_us=86.68|max_us=105.69|stddev_us=4.95|p999_us=105.69|tail_ratio=1.22|cv=0.06
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=3.799|rps=26324.54|p50_us=36.49|p95_us=42.89|p99_us=66.13|samples=100|min_us=35.64|mean_us=37.94|max_us=67.55|stddev_us=5.40|p999_us=67.55|tail_ratio=1.81|cv=0.14
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=3.753|rps=26646.27|p50_us=36.31|p95_us=43.95|p99_us=58.45|samples=100|min_us=35.41|mean_us=37.48|max_us=60.14|stddev_us=4.24|p999_us=60.14|tail_ratio=1.61|cv=0.11
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=8.753|rps=11425.08|p50_us=84.74|p95_us=101.20|p99_us=109.56|samples=100|min_us=83.54|mean_us=87.48|max_us=114.53|stddev_us=6.11|p999_us=114.53|tail_ratio=1.29|cv=0.07
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=317.311|rps=315.15|p50_us=3170.34|p95_us=3200.51|p99_us=3221.42|samples=100|min_us=3145.36|mean_us=3173.02|max_us=3265.44|stddev_us=16.89|p999_us=3265.44|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=16.151|rps=6191.43|p50_us=156.38|p95_us=185.55|p99_us=202.84|samples=100|min_us=152.73|mean_us=161.43|max_us=204.52|stddev_us=11.50|p999_us=204.52|tail_ratio=1.30|cv=0.07
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=15.833|rps=6316.03|p50_us=154.38|p95_us=175.92|p99_us=188.74|samples=100|min_us=150.79|mean_us=158.25|max_us=191.22|stddev_us=8.22|p999_us=191.22|tail_ratio=1.22|cv=0.05
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=316.648|rps=315.81|p50_us=3163.43|p95_us=3185.77|p99_us=3223.09|samples=100|min_us=3139.73|mean_us=3166.40|max_us=3244.24|stddev_us=14.58|p999_us=3244.24|tail_ratio=1.02|cv=0.00
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=316.740|rps=315.72|p50_us=3164.83|p95_us=3192.49|p99_us=3219.10|samples=100|min_us=3138.71|mean_us=3167.32|max_us=3241.91|stddev_us=14.65|p999_us=3241.91|tail_ratio=1.02|cv=0.00
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=16.046|rps=6231.89|p50_us=155.54|p95_us=184.11|p99_us=189.87|samples=100|min_us=152.82|mean_us=160.39|max_us=191.89|stddev_us=9.66|p999_us=191.89|tail_ratio=1.22|cv=0.06
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=16.023|rps=6240.85|p50_us=155.31|p95_us=182.31|p99_us=195.12|samples=100|min_us=150.87|mean_us=160.16|max_us=207.71|stddev_us=10.33|p999_us=207.71|tail_ratio=1.26|cv=0.06
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=rustls-aws-lc|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=316.589|rps=315.87|p50_us=3163.27|p95_us=3189.26|p99_us=3194.57|samples=100|min_us=3140.19|mean_us=3165.81|max_us=3205.99|stddev_us=12.56|p999_us=3205.99|tail_ratio=1.01|cv=0.00
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=250.107|rps=399.83|p50_us=2501.83|p95_us=2558.50|p99_us=2564.55|samples=100|min_us=2424.99|mean_us=2500.94|max_us=2585.76|stddev_us=35.12|p999_us=2585.76|tail_ratio=1.03|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=94.363|rps=1059.73|p50_us=944.42|p95_us=978.62|p99_us=987.12|samples=100|min_us=887.08|mean_us=943.52|max_us=997.90|stddev_us=26.55|p999_us=997.90|tail_ratio=1.05|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=92.241|rps=1084.12|p50_us=914.26|p95_us=969.82|p99_us=985.44|samples=100|min_us=873.90|mean_us=922.31|max_us=993.20|stddev_us=28.50|p999_us=993.20|tail_ratio=1.08|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=249.150|rps=401.37|p50_us=2479.16|p95_us=2555.38|p99_us=2563.92|samples=100|min_us=2421.18|mean_us=2491.36|max_us=2595.12|stddev_us=40.71|p999_us=2595.12|tail_ratio=1.03|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=248.905|rps=401.76|p50_us=2480.16|p95_us=2548.51|p99_us=2563.40|samples=100|min_us=2415.18|mean_us=2488.92|max_us=2564.81|stddev_us=38.92|p999_us=2564.81|tail_ratio=1.03|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=94.925|rps=1053.46|p50_us=957.82|p95_us=989.20|p99_us=998.67|samples=100|min_us=889.62|mean_us=949.14|max_us=998.83|stddev_us=28.30|p999_us=998.83|tail_ratio=1.04|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=rustls-aws-lc|server=courierust|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=94.338|rps=1060.02|p50_us=949.44|p95_us=981.99|p99_us=989.66|samples=100|min_us=881.75|mean_us=943.27|max_us=996.59|stddev_us=27.21|p999_us=996.59|tail_ratio=1.04|cv=0.03
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=full_handshake|client=courierust|server=courierust|mode=connect|bytes=0|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=249.621|rps=400.61|p50_us=2489.01|p95_us=2530.21|p99_us=2536.43|samples=100|min_us=2442.58|mean_us=2496.08|max_us=2537.92|stddev_us=23.89|p999_us=2537.92|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=13.880|rps=7204.45|p50_us=133.71|p95_us=163.96|p99_us=167.98|samples=100|min_us=132.30|mean_us=138.75|max_us=174.76|stddev_us=9.59|p999_us=174.76|tail_ratio=1.26|cv=0.07
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=8.794|rps=11371.31|p50_us=85.40|p95_us=100.35|p99_us=114.92|samples=100|min_us=84.25|mean_us=87.89|max_us=117.11|stddev_us=6.40|p999_us=117.11|tail_ratio=1.35|cv=0.07
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=8.838|rps=11315.35|p50_us=85.26|p95_us=107.76|p99_us=117.38|samples=100|min_us=83.88|mean_us=88.33|max_us=127.15|stddev_us=7.97|p999_us=127.15|tail_ratio=1.38|cv=0.09
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=13.696|rps=7301.34|p50_us=133.51|p95_us=153.24|p99_us=164.40|samples=100|min_us=132.14|mean_us=136.91|max_us=167.60|stddev_us=7.51|p999_us=167.60|tail_ratio=1.23|cv=0.05
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=13.783|rps=7255.29|p50_us=133.66|p95_us=159.60|p99_us=166.43|samples=100|min_us=131.86|mean_us=137.78|max_us=169.00|stddev_us=8.36|p999_us=169.00|tail_ratio=1.25|cv=0.06
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=8.834|rps=11320.16|p50_us=85.51|p95_us=103.70|p99_us=116.73|samples=100|min_us=84.33|mean_us=88.29|max_us=122.51|stddev_us=7.08|p999_us=122.51|tail_ratio=1.37|cv=0.08
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=8.778|rps=11392.08|p50_us=85.21|p95_us=106.17|p99_us=116.93|samples=100|min_us=83.84|mean_us=87.73|max_us=121.11|stddev_us=6.92|p999_us=121.11|tail_ratio=1.37|cv=0.08
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=13.907|rps=7190.67|p50_us=133.56|p95_us=160.06|p99_us=201.59|samples=100|min_us=132.28|mean_us=139.02|max_us=212.13|stddev_us=13.47|p999_us=212.13|tail_ratio=1.51|cv=0.10
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=642.473|rps=155.65|p50_us=6454.24|p95_us=6620.92|p99_us=6629.22|samples=100|min_us=6161.32|mean_us=6424.64|max_us=6655.90|stddev_us=122.23|p999_us=6655.90|tail_ratio=1.03|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=1|warmup=4|status=ok|requests=100|elapsed_ms=318.453|rps=314.02|p50_us=3176.51|p95_us=3220.41|p99_us=3242.71|samples=100|min_us=3163.59|mean_us=3184.43|max_us=3323.45|stddev_us=21.43|p999_us=3323.45|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=319.237|rps=313.25|p50_us=3184.35|p95_us=3227.83|p99_us=3253.59|samples=100|min_us=3178.35|mean_us=3192.26|max_us=3274.98|stddev_us=17.57|p999_us=3274.98|tail_ratio=1.02|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=2|warmup=4|status=ok|requests=100|elapsed_ms=643.348|rps=155.44|p50_us=6447.61|p95_us=6638.56|p99_us=6688.78|samples=100|min_us=6149.60|mean_us=6433.38|max_us=6768.14|stddev_us=129.53|p999_us=6768.14|tail_ratio=1.04|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=644.561|rps=155.14|p50_us=6454.55|p95_us=6638.91|p99_us=6661.52|samples=100|min_us=6151.33|mean_us=6445.51|max_us=6672.97|stddev_us=121.31|p999_us=6672.97|tail_ratio=1.03|cv=0.02
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=3|warmup=4|status=ok|requests=100|elapsed_ms=318.278|rps=314.19|p50_us=3175.88|p95_us=3210.47|p99_us=3280.11|samples=100|min_us=3163.37|mean_us=3182.68|max_us=3331.44|stddev_us=22.11|p999_us=3331.44|tail_ratio=1.03|cv=0.01
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=rustls-aws-lc|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=317.921|rps=314.54|p50_us=3174.40|p95_us=3208.44|p99_us=3239.92|samples=100|min_us=3160.12|mean_us=3179.11|max_us=3241.79|stddev_us=15.37|p999_us=3241.79|tail_ratio=1.02|cv=0.00
COMPARISON|protocol=tls1.3-aes128gcm-x25519|case=record_echo|client=courierust|server=courierust|mode=reuse|bytes=65536|workers=1|repetition=4|warmup=4|status=ok|requests=100|elapsed_ms=641.994|rps=155.76|p50_us=6389.31|p95_us=6650.57|p99_us=6741.71|samples=100|min_us=6163.45|mean_us=6419.85|max_us=6755.29|stddev_us=138.21|p999_us=6755.29|tail_ratio=1.06|cv=0.02
~~~

### ws.log
~~~text
META|suite=ws|protocol=ws|tls=off|compression=off|connections=1|nodelay=true|timeout=none|load=closed_loop|validation=opcode_and_full_payload|order=alternating
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=33.720|rps=29655.57|p50_us=32.55|p95_us=40.84|p99_us=52.41|samples=1000|min_us=31.54|mean_us=33.65|max_us=60.64|stddev_us=3.71|p999_us=57.74|tail_ratio=1.61|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=39.034|rps=25618.50|p50_us=40.59|p95_us=52.83|p99_us=64.82|samples=1000|min_us=27.75|mean_us=38.95|max_us=89.08|stddev_us=7.47|p999_us=69.96|tail_ratio=1.60|cv=0.19
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=52.318|rps=19113.99|p50_us=50.38|p95_us=63.97|p99_us=77.38|samples=1000|min_us=47.66|mean_us=52.25|max_us=94.28|stddev_us=5.52|p999_us=83.46|tail_ratio=1.54|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=51.048|rps=19589.38|p50_us=48.99|p95_us=66.89|p99_us=77.38|samples=1000|min_us=46.00|mean_us=50.98|max_us=109.94|stddev_us=6.54|p999_us=98.27|tail_ratio=1.58|cv=0.13
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=41.792|rps=23928.20|p50_us=40.32|p95_us=53.66|p99_us=61.72|samples=1000|min_us=37.83|mean_us=41.69|max_us=82.42|stddev_us=5.02|p999_us=78.61|tail_ratio=1.53|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=34.093|rps=29331.34|p50_us=32.56|p95_us=43.52|p99_us=53.91|samples=1000|min_us=31.55|mean_us=34.03|max_us=64.05|stddev_us=4.39|p999_us=61.38|tail_ratio=1.66|cv=0.13
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=33.547|rps=29808.49|p50_us=32.47|p95_us=41.41|p99_us=53.28|samples=1000|min_us=31.40|mean_us=33.48|max_us=74.28|stddev_us=3.94|p999_us=62.90|tail_ratio=1.64|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=41.493|rps=24100.47|p50_us=40.38|p95_us=55.34|p99_us=63.02|samples=1000|min_us=30.28|mean_us=41.40|max_us=69.02|stddev_us=6.16|p999_us=68.23|tail_ratio=1.56|cv=0.15
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=50.745|rps=19706.45|p50_us=48.90|p95_us=64.98|p99_us=78.56|samples=1000|min_us=45.50|mean_us=50.68|max_us=89.89|stddev_us=6.10|p999_us=89.49|tail_ratio=1.61|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=51.131|rps=19557.78|p50_us=49.45|p95_us=63.77|p99_us=75.98|samples=1000|min_us=46.30|mean_us=51.06|max_us=97.47|stddev_us=5.73|p999_us=93.01|tail_ratio=1.54|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=32.189|rps=31066.75|p50_us=31.09|p95_us=38.35|p99_us=52.38|samples=1000|min_us=29.88|mean_us=32.13|max_us=77.55|stddev_us=4.07|p999_us=66.38|tail_ratio=1.68|cv=0.13
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=33.723|rps=29652.96|p50_us=32.63|p95_us=41.55|p99_us=52.20|samples=1000|min_us=31.43|mean_us=33.66|max_us=60.36|stddev_us=3.65|p999_us=60.02|tail_ratio=1.60|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=34.463|rps=29016.65|p50_us=33.45|p95_us=39.10|p99_us=52.49|samples=1000|min_us=31.72|mean_us=34.39|max_us=67.19|stddev_us=3.74|p999_us=66.58|tail_ratio=1.57|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=36.614|rps=27312.31|p50_us=33.51|p95_us=46.20|p99_us=57.28|samples=1000|min_us=30.23|mean_us=36.54|max_us=69.80|stddev_us=6.03|p999_us=68.05|tail_ratio=1.71|cv=0.16
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=50.726|rps=19713.92|p50_us=48.65|p95_us=64.68|p99_us=76.36|samples=1000|min_us=44.81|mean_us=50.66|max_us=97.69|stddev_us=6.50|p999_us=92.46|tail_ratio=1.57|cv=0.13
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=50.606|rps=19760.61|p50_us=48.91|p95_us=62.36|p99_us=73.94|samples=1000|min_us=45.01|mean_us=50.52|max_us=91.68|stddev_us=5.70|p999_us=90.56|tail_ratio=1.51|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=42.637|rps=23453.95|p50_us=40.56|p95_us=55.82|p99_us=65.40|samples=1000|min_us=32.73|mean_us=42.53|max_us=91.85|stddev_us=6.05|p999_us=75.36|tail_ratio=1.61|cv=0.14
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=35.780|rps=27948.53|p50_us=34.03|p95_us=45.12|p99_us=56.65|samples=1000|min_us=32.55|mean_us=35.72|max_us=66.80|stddev_us=4.78|p999_us=66.74|tail_ratio=1.66|cv=0.13
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=35.511|rps=28159.98|p50_us=33.81|p95_us=44.56|p99_us=57.33|samples=1000|min_us=32.43|mean_us=35.45|max_us=67.81|stddev_us=4.51|p999_us=66.25|tail_ratio=1.70|cv=0.13
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=41.620|rps=24026.93|p50_us=40.27|p95_us=50.79|p99_us=65.39|samples=1000|min_us=32.06|mean_us=41.52|max_us=79.24|stddev_us=4.91|p999_us=71.00|tail_ratio=1.62|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=50.031|rps=19987.43|p50_us=48.41|p95_us=61.21|p99_us=74.25|samples=1000|min_us=44.96|mean_us=49.96|max_us=82.25|stddev_us=5.27|p999_us=78.97|tail_ratio=1.53|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=50.134|rps=19946.54|p50_us=48.27|p95_us=61.59|p99_us=75.43|samples=1000|min_us=44.58|mean_us=50.07|max_us=96.33|stddev_us=5.87|p999_us=85.52|tail_ratio=1.56|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=32.596|rps=30678.62|p50_us=31.31|p95_us=42.06|p99_us=50.12|samples=1000|min_us=29.85|mean_us=32.54|max_us=64.66|stddev_us=4.05|p999_us=59.55|tail_ratio=1.60|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=34.677|rps=28837.81|p50_us=33.27|p95_us=43.18|p99_us=55.78|samples=1000|min_us=32.11|mean_us=34.62|max_us=67.21|stddev_us=4.29|p999_us=67.19|tail_ratio=1.68|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=43.782|rps=22840.49|p50_us=42.41|p95_us=54.25|p99_us=61.74|samples=1000|min_us=40.86|mean_us=43.72|max_us=68.68|stddev_us=4.06|p999_us=67.93|tail_ratio=1.46|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=51.483|rps=19423.85|p50_us=49.86|p95_us=62.85|p99_us=73.93|samples=1000|min_us=47.09|mean_us=51.38|max_us=89.84|stddev_us=4.94|p999_us=82.39|tail_ratio=1.48|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=58.632|rps=17055.46|p50_us=56.86|p95_us=71.43|p99_us=82.83|samples=1000|min_us=54.27|mean_us=58.57|max_us=96.87|stddev_us=5.53|p999_us=87.83|tail_ratio=1.46|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=58.853|rps=16991.40|p50_us=56.79|p95_us=72.22|p99_us=83.17|samples=1000|min_us=53.01|mean_us=58.79|max_us=103.01|stddev_us=6.13|p999_us=100.92|tail_ratio=1.46|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=40.645|rps=24603.51|p50_us=40.37|p95_us=46.67|p99_us=59.31|samples=1000|min_us=36.63|mean_us=40.58|max_us=67.42|stddev_us=3.86|p999_us=63.41|tail_ratio=1.47|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=43.178|rps=23159.82|p50_us=42.90|p95_us=49.81|p99_us=63.34|samples=1000|min_us=39.50|mean_us=43.11|max_us=81.63|stddev_us=4.36|p999_us=77.56|tail_ratio=1.48|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=45.861|rps=21804.89|p50_us=42.97|p95_us=55.85|p99_us=67.18|samples=1000|min_us=40.89|mean_us=45.79|max_us=77.00|stddev_us=5.53|p999_us=75.55|tail_ratio=1.56|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=50.203|rps=19918.96|p50_us=48.57|p95_us=62.19|p99_us=74.04|samples=1000|min_us=39.88|mean_us=50.09|max_us=81.83|stddev_us=5.38|p999_us=80.21|tail_ratio=1.52|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=61.554|rps=16245.97|p50_us=59.85|p95_us=75.23|p99_us=83.24|samples=1000|min_us=53.45|mean_us=61.48|max_us=91.71|stddev_us=5.46|p999_us=88.02|tail_ratio=1.39|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=60.785|rps=16451.34|p50_us=59.39|p95_us=74.06|p99_us=85.89|samples=1000|min_us=54.43|mean_us=60.71|max_us=100.25|stddev_us=5.82|p999_us=95.90|tail_ratio=1.45|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=41.275|rps=24227.61|p50_us=40.66|p95_us=50.88|p99_us=62.74|samples=1000|min_us=36.74|mean_us=41.21|max_us=87.85|stddev_us=4.78|p999_us=69.10|tail_ratio=1.54|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=43.977|rps=22739.39|p50_us=42.61|p95_us=53.86|p99_us=63.82|samples=1000|min_us=40.90|mean_us=43.91|max_us=92.13|stddev_us=4.44|p999_us=74.12|tail_ratio=1.50|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=430.480|rps=2322.99|p50_us=427.52|p95_us=452.77|p99_us=473.20|samples=1000|min_us=411.41|mean_us=430.34|max_us=506.52|stddev_us=13.50|p999_us=492.97|tail_ratio=1.11|cv=0.03
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=313.928|rps=3185.45|p50_us=307.51|p95_us=343.83|p99_us=365.66|samples=1000|min_us=251.48|mean_us=313.85|max_us=392.56|stddev_us=14.30|p999_us=390.03|tail_ratio=1.19|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=216.504|rps=4618.85|p50_us=220.78|p95_us=245.51|p99_us=258.29|samples=1000|min_us=175.47|mean_us=216.40|max_us=276.13|stddev_us=20.52|p999_us=274.13|tail_ratio=1.17|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=225.863|rps=4427.46|p50_us=230.88|p95_us=253.61|p99_us=263.93|samples=1000|min_us=172.96|mean_us=225.76|max_us=313.58|stddev_us=21.68|p999_us=290.81|tail_ratio=1.14|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=155.993|rps=6410.55|p50_us=154.07|p95_us=175.33|p99_us=184.36|samples=1000|min_us=144.37|mean_us=155.91|max_us=218.43|stddev_us=9.19|p999_us=200.81|tail_ratio=1.20|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=186.958|rps=5348.79|p50_us=166.58|p95_us=247.38|p99_us=258.01|samples=1000|min_us=160.11|mean_us=186.86|max_us=290.58|stddev_us=31.84|p999_us=282.05|tail_ratio=1.55|cv=0.17
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=172.350|rps=5802.14|p50_us=165.17|p95_us=230.46|p99_us=247.45|samples=1000|min_us=159.18|mean_us=172.25|max_us=275.20|stddev_us=18.27|p999_us=264.73|tail_ratio=1.50|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=150.075|rps=6663.32|p50_us=145.80|p95_us=172.01|p99_us=191.77|samples=1000|min_us=141.98|mean_us=149.99|max_us=234.13|stddev_us=10.91|p999_us=233.89|tail_ratio=1.32|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=194.130|rps=5151.18|p50_us=188.32|p95_us=226.22|p99_us=245.39|samples=1000|min_us=175.45|mean_us=194.05|max_us=281.12|stddev_us=15.09|p999_us=265.97|tail_ratio=1.30|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=199.267|rps=5018.38|p50_us=198.14|p95_us=220.27|p99_us=230.91|samples=1000|min_us=173.91|mean_us=199.18|max_us=251.00|stddev_us=10.78|p999_us=248.37|tail_ratio=1.17|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=152.814|rps=6543.90|p50_us=149.14|p95_us=171.18|p99_us=182.60|samples=1000|min_us=142.83|mean_us=152.72|max_us=206.83|stddev_us=8.62|p999_us=193.24|tail_ratio=1.22|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=tungstenite|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=168.456|rps=5936.26|p50_us=164.44|p95_us=189.28|p99_us=197.22|samples=1000|min_us=159.52|mean_us=168.37|max_us=221.38|stddev_us=8.95|p999_us=217.33|tail_ratio=1.20|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=33.247|rps=30078.28|p50_us=32.46|p95_us=36.09|p99_us=51.12|samples=1000|min_us=31.25|mean_us=33.18|max_us=66.51|stddev_us=3.38|p999_us=64.79|tail_ratio=1.57|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=31.872|rps=31375.39|p50_us=30.91|p95_us=38.44|p99_us=51.29|samples=1000|min_us=29.61|mean_us=31.81|max_us=69.26|stddev_us=3.70|p999_us=59.41|tail_ratio=1.66|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=49.833|rps=20067.09|p50_us=47.83|p95_us=62.07|p99_us=74.69|samples=1000|min_us=45.41|mean_us=49.76|max_us=104.52|stddev_us=5.85|p999_us=91.81|tail_ratio=1.56|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=55.336|rps=18071.35|p50_us=51.99|p95_us=72.79|p99_us=84.33|samples=1000|min_us=45.69|mean_us=55.27|max_us=156.07|stddev_us=9.55|p999_us=97.51|tail_ratio=1.62|cv=0.17
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=41.328|rps=24196.67|p50_us=40.05|p95_us=53.58|p99_us=65.87|samples=1000|min_us=37.94|mean_us=41.25|max_us=87.07|stddev_us=4.96|p999_us=76.67|tail_ratio=1.64|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=64|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=33.150|rps=30165.83|p50_us=32.27|p95_us=37.85|p99_us=52.11|samples=1000|min_us=31.24|mean_us=33.09|max_us=57.63|stddev_us=3.41|p999_us=56.59|tail_ratio=1.61|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=41.417|rps=24144.88|p50_us=41.04|p95_us=50.76|p99_us=60.77|samples=1000|min_us=31.58|mean_us=41.34|max_us=341.59|stddev_us=11.05|p999_us=93.30|tail_ratio=1.48|cv=0.27
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=32.556|rps=30716.23|p50_us=30.68|p95_us=41.41|p99_us=52.29|samples=1000|min_us=29.59|mean_us=32.49|max_us=95.82|stddev_us=5.08|p999_us=66.84|tail_ratio=1.70|cv=0.16
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=49.533|rps=20188.54|p50_us=47.74|p95_us=62.59|p99_us=75.75|samples=1000|min_us=45.96|mean_us=49.47|max_us=89.98|stddev_us=5.75|p999_us=88.56|tail_ratio=1.59|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=50.675|rps=19733.52|p50_us=49.45|p95_us=63.40|p99_us=71.31|samples=1000|min_us=45.44|mean_us=50.61|max_us=81.95|stddev_us=4.77|p999_us=78.35|tail_ratio=1.44|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=32.269|rps=30989.58|p50_us=30.97|p95_us=42.07|p99_us=50.99|samples=1000|min_us=29.94|mean_us=32.21|max_us=69.90|stddev_us=4.13|p999_us=61.38|tail_ratio=1.65|cv=0.13
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=64|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=33.185|rps=30134.23|p50_us=32.20|p95_us=40.38|p99_us=51.28|samples=1000|min_us=31.37|mean_us=33.13|max_us=70.52|stddev_us=3.75|p999_us=64.38|tail_ratio=1.59|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=34.317|rps=29140.07|p50_us=33.33|p95_us=39.50|p99_us=51.16|samples=1000|min_us=32.52|mean_us=34.26|max_us=65.45|stddev_us=3.35|p999_us=57.30|tail_ratio=1.53|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=32.327|rps=30933.62|p50_us=31.44|p95_us=36.09|p99_us=49.86|samples=1000|min_us=30.00|mean_us=32.27|max_us=67.67|stddev_us=3.64|p999_us=61.93|tail_ratio=1.59|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=50.269|rps=19892.81|p50_us=48.66|p95_us=61.90|p99_us=72.34|samples=1000|min_us=45.14|mean_us=50.20|max_us=81.73|stddev_us=5.04|p999_us=81.32|tail_ratio=1.49|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=50.046|rps=19981.44|p50_us=48.23|p95_us=61.98|p99_us=74.33|samples=1000|min_us=45.46|mean_us=49.97|max_us=93.94|stddev_us=5.48|p999_us=80.89|tail_ratio=1.54|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=32.540|rps=30731.27|p50_us=31.61|p95_us=36.60|p99_us=50.41|samples=1000|min_us=30.30|mean_us=32.48|max_us=68.80|stddev_us=3.64|p999_us=67.42|tail_ratio=1.59|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=43.269|rps=23110.98|p50_us=41.93|p95_us=53.96|p99_us=66.29|samples=1000|min_us=40.65|mean_us=43.20|max_us=71.46|stddev_us=4.35|p999_us=69.67|tail_ratio=1.58|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=34.864|rps=28682.89|p50_us=33.62|p95_us=40.90|p99_us=53.41|samples=1000|min_us=32.76|mean_us=34.79|max_us=69.83|stddev_us=3.87|p999_us=67.16|tail_ratio=1.59|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=41.093|rps=24335.27|p50_us=40.01|p95_us=48.26|p99_us=64.19|samples=1000|min_us=37.34|mean_us=41.01|max_us=78.64|stddev_us=4.58|p999_us=78.44|tail_ratio=1.60|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=51.729|rps=19331.46|p50_us=50.52|p95_us=63.98|p99_us=74.75|samples=1000|min_us=45.59|mean_us=51.67|max_us=79.90|stddev_us=5.05|p999_us=79.57|tail_ratio=1.48|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=49.708|rps=20117.49|p50_us=48.29|p95_us=61.26|p99_us=76.36|samples=1000|min_us=45.01|mean_us=49.64|max_us=88.38|stddev_us=5.36|p999_us=85.41|tail_ratio=1.58|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=39.998|rps=25001.43|p50_us=39.86|p95_us=50.92|p99_us=62.93|samples=1000|min_us=30.04|mean_us=39.92|max_us=81.01|stddev_us=5.89|p999_us=77.53|tail_ratio=1.58|cv=0.15
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=1024|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=34.507|rps=28979.39|p50_us=33.45|p95_us=39.15|p99_us=51.45|samples=1000|min_us=32.67|mean_us=34.44|max_us=67.16|stddev_us=3.59|p999_us=63.50|tail_ratio=1.54|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=45.740|rps=21862.57|p50_us=44.62|p95_us=54.44|p99_us=62.21|samples=1000|min_us=42.86|mean_us=45.67|max_us=77.33|stddev_us=3.82|p999_us=69.76|tail_ratio=1.39|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=43.673|rps=22897.54|p50_us=42.21|p95_us=52.53|p99_us=65.94|samples=1000|min_us=40.03|mean_us=43.61|max_us=83.07|stddev_us=4.77|p999_us=78.60|tail_ratio=1.56|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=60.569|rps=16510.12|p50_us=58.88|p95_us=75.13|p99_us=85.49|samples=1000|min_us=55.36|mean_us=60.50|max_us=93.37|stddev_us=5.60|p999_us=88.89|tail_ratio=1.45|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=60.323|rps=16577.31|p50_us=59.18|p95_us=72.08|p99_us=84.27|samples=1000|min_us=54.62|mean_us=60.26|max_us=92.99|stddev_us=5.57|p999_us=92.40|tail_ratio=1.42|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=42.906|rps=23306.85|p50_us=41.70|p95_us=51.04|p99_us=65.07|samples=1000|min_us=39.65|mean_us=42.84|max_us=77.82|stddev_us=4.32|p999_us=72.34|tail_ratio=1.56|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=45.532|rps=21962.60|p50_us=44.37|p95_us=54.72|p99_us=64.82|samples=1000|min_us=42.50|mean_us=45.47|max_us=80.46|stddev_us=4.07|p999_us=67.51|tail_ratio=1.46|cv=0.09
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=45.824|rps=21822.42|p50_us=44.28|p95_us=55.86|p99_us=66.76|samples=1000|min_us=42.43|mean_us=45.76|max_us=165.77|stddev_us=5.88|p999_us=77.61|tail_ratio=1.51|cv=0.13
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=48.497|rps=20619.79|p50_us=50.37|p95_us=59.32|p99_us=72.92|samples=1000|min_us=39.98|mean_us=48.41|max_us=91.30|stddev_us=6.69|p999_us=78.55|tail_ratio=1.45|cv=0.14
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=62.467|rps=16008.58|p50_us=60.86|p95_us=76.88|p99_us=87.64|samples=1000|min_us=55.53|mean_us=62.40|max_us=92.40|stddev_us=6.35|p999_us=92.30|tail_ratio=1.44|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=59.903|rps=16693.78|p50_us=57.94|p95_us=73.36|p99_us=84.85|samples=1000|min_us=55.83|mean_us=59.83|max_us=106.90|stddev_us=5.72|p999_us=89.50|tail_ratio=1.46|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=52.333|rps=19108.39|p50_us=51.29|p95_us=65.27|p99_us=74.78|samples=1000|min_us=41.13|mean_us=52.24|max_us=87.79|stddev_us=6.02|p999_us=80.29|tail_ratio=1.46|cv=0.12
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=16384|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=53.581|rps=18663.22|p50_us=52.85|p95_us=66.86|p99_us=77.29|samples=1000|min_us=43.05|mean_us=53.51|max_us=96.86|stddev_us=6.06|p999_us=86.00|tail_ratio=1.46|cv=0.11
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=202.563|rps=4936.74|p50_us=184.29|p95_us=258.13|p99_us=269.02|samples=1000|min_us=162.36|mean_us=202.47|max_us=283.63|stddev_us=34.99|p999_us=281.62|tail_ratio=1.46|cv=0.17
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=250.625|rps=3990.02|p50_us=238.18|p95_us=300.46|p99_us=307.33|samples=1000|min_us=224.94|mean_us=250.54|max_us=340.47|stddev_us=25.93|p999_us=329.33|tail_ratio=1.29|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=1|warmup=16|status=ok|requests=1000|elapsed_ms=224.397|rps=4456.38|p50_us=227.24|p95_us=252.08|p99_us=267.00|samples=1000|min_us=176.32|mean_us=224.30|max_us=288.35|stddev_us=18.94|p999_us=279.99|tail_ratio=1.17|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=228.425|rps=4377.81|p50_us=228.64|p95_us=253.17|p99_us=267.29|samples=1000|min_us=185.00|mean_us=228.33|max_us=297.27|stddev_us=15.45|p999_us=283.47|tail_ratio=1.17|cv=0.07
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=165.680|rps=6035.73|p50_us=162.60|p95_us=185.52|p99_us=200.90|samples=1000|min_us=149.86|mean_us=165.59|max_us=224.95|stddev_us=10.35|p999_us=211.11|tail_ratio=1.24|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=2|warmup=16|status=ok|requests=1000|elapsed_ms=173.189|rps=5774.05|p50_us=170.42|p95_us=191.20|p99_us=201.23|samples=1000|min_us=161.87|mean_us=173.09|max_us=227.49|stddev_us=8.92|p999_us=226.73|tail_ratio=1.18|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=173.049|rps=5778.71|p50_us=169.57|p95_us=191.30|p99_us=200.94|samples=1000|min_us=161.40|mean_us=172.96|max_us=215.31|stddev_us=8.64|p999_us=213.96|tail_ratio=1.18|cv=0.05
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=161.479|rps=6192.77|p50_us=159.85|p95_us=179.75|p99_us=192.49|samples=1000|min_us=148.93|mean_us=161.38|max_us=249.12|stddev_us=9.38|p999_us=232.40|tail_ratio=1.20|cv=0.06
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=3|warmup=16|status=ok|requests=1000|elapsed_ms=211.912|rps=4718.95|p50_us=216.54|p95_us=251.88|p99_us=270.58|samples=1000|min_us=175.00|mean_us=211.82|max_us=388.69|stddev_us=27.99|p999_us=298.31|tail_ratio=1.25|cv=0.13
COMPARISON|protocol=ws|case=binary_echo|client=tokio-tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=216.632|rps=4616.13|p50_us=222.55|p95_us=241.55|p99_us=248.17|samples=1000|min_us=175.74|mean_us=216.54|max_us=267.87|stddev_us=17.24|p999_us=267.05|tail_ratio=1.12|cv=0.08
COMPARISON|protocol=ws|case=binary_echo|client=tungstenite|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=165.023|rps=6059.77|p50_us=160.37|p95_us=215.28|p99_us=232.60|samples=1000|min_us=149.21|mean_us=164.93|max_us=245.00|stddev_us=16.78|p999_us=239.77|tail_ratio=1.45|cv=0.10
COMPARISON|protocol=ws|case=binary_echo|client=courierust|server=courierust|mode=reuse|bytes=262144|workers=1|repetition=4|warmup=16|status=ok|requests=1000|elapsed_ms=202.363|rps=4941.61|p50_us=181.37|p95_us=258.67|p99_us=270.81|samples=1000|min_us=161.19|mean_us=202.27|max_us=307.26|stddev_us=36.88|p999_us=290.61|tail_ratio=1.49|cv=0.18
~~~
### Throughput
~~~text
courierust throughput suite (loopback)
META|suite=throughput|requests=4000|server_threads=4|max_samples=2048
RESULT|suite=throughput|case=h1_sequential|protocol=h1|mode=sequential|payload=empty|bytes=0|workers=1|server_threads=4|requests=4000|elapsed_ms=264.445|rps=15126.0|response_mbps=0.000|p50_us=61.28|p75_us=66.91|p90_us=73.32|p95_us=80.88|p99_us=93.36|min_us=50.94|mean_us=64.05|max_us=107.76|stddev_us=7.94|p999_us=106.85|tail_ratio=1.52|cv=0.12|samples=2000
RESULT|suite=throughput|case=h1_sequential|protocol=h1|mode=sequential|payload=1k|bytes=1024|workers=1|server_threads=4|requests=4000|elapsed_ms=266.633|rps=15001.9|response_mbps=15.362|p50_us=65.22|p75_us=66.41|p90_us=72.19|p95_us=81.00|p99_us=88.50|min_us=53.38|mean_us=66.06|max_us=101.86|stddev_us=6.16|p999_us=95.65|tail_ratio=1.36|cv=0.09|samples=2000
RESULT|suite=throughput|case=h1_sequential|protocol=h1|mode=sequential|payload=64k|bytes=65536|workers=1|server_threads=4|requests=4000|elapsed_ms=380.586|rps=10510.1|response_mbps=688.790|p50_us=95.04|p75_us=102.47|p90_us=107.70|p95_us=113.55|p99_us=127.43|min_us=68.49|mean_us=95.08|max_us=139.35|stddev_us=10.81|p999_us=136.60|tail_ratio=1.34|cv=0.11|samples=2000
RESULT|suite=throughput|case=h1_parallel_w1|protocol=h1|mode=parallel|payload=1k|bytes=1024|workers=1|server_threads=4|requests=4000|elapsed_ms=262.596|rps=15232.6|response_mbps=15.598|p50_us=64.92|p75_us=69.22|p90_us=74.62|p95_us=83.84|p99_us=94.01|min_us=51.94|mean_us=66.18|max_us=113.53|stddev_us=8.25|p999_us=108.08|tail_ratio=1.45|cv=0.12|samples=2000
RESULT|suite=throughput|case=h1_parallel_w4|protocol=h1|mode=parallel|payload=1k|bytes=1024|workers=4|server_threads=4|requests=4000|elapsed_ms=113.363|rps=35284.8|response_mbps=36.132|p50_us=95.07|p75_us=123.20|p90_us=163.44|p95_us=192.00|p99_us=279.31|min_us=26.72|mean_us=103.98|max_us=448.01|stddev_us=48.17|p999_us=413.78|tail_ratio=2.94|cv=0.46|samples=2000
RESULT|suite=throughput|case=h1_parallel_w8|protocol=h1|mode=parallel|payload=1k|bytes=1024|workers=8|server_threads=8|requests=4000|elapsed_ms=86.442|rps=46273.7|response_mbps=47.384|p50_us=128.76|p75_us=198.59|p90_us=294.43|p95_us=390.33|p99_us=630.14|min_us=26.00|mean_us=159.34|max_us=1723.01|stddev_us=127.26|p999_us=1114.68|tail_ratio=4.89|cv=0.80|samples=2000
RESULT|suite=throughput|case=h2_multiplex_w1|protocol=h2c|mode=multiplex|payload=1k|bytes=1024|workers=1|server_threads=4|requests=4000|elapsed_ms=295.952|rps=13515.7|response_mbps=13.840|p50_us=71.92|p75_us=75.34|p90_us=86.68|p95_us=93.52|p99_us=104.23|min_us=64.34|mean_us=74.42|max_us=118.31|stddev_us=8.60|p999_us=117.76|tail_ratio=1.45|cv=0.12|samples=2000
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=1k|workers=1|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=1|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=4254|h2_write_syscalls=4003|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=1k|workers=1|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=4003|h2_write_syscalls=4253|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w8|protocol=h2c|mode=multiplex|payload=1k|bytes=1024|workers=8|server_threads=4|requests=4000|elapsed_ms=91.321|rps=43801.5|response_mbps=44.853|p50_us=176.68|p75_us=187.51|p90_us=200.15|p95_us=215.91|p99_us=304.87|min_us=103.91|mean_us=181.46|max_us=349.77|stddev_us=28.12|p999_us=326.59|tail_ratio=1.73|cv=0.15|samples=2000
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=1k|workers=8|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=1|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=784|h2_write_syscalls=533|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=1k|workers=8|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=533|h2_write_syscalls=783|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w32|protocol=h2c|mode=multiplex|payload=1k|bytes=1024|workers=32|server_threads=4|requests=4000|elapsed_ms=65.425|rps=61138.7|response_mbps=62.606|p50_us=483.30|p75_us=520.01|p90_us=600.49|p95_us=792.35|p99_us=1002.55|min_us=157.13|mean_us=514.38|max_us=1234.04|stddev_us=112.95|p999_us=1227.72|tail_ratio=2.07|cv=0.22|samples=2016
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=1k|workers=32|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=1|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=265|h2_write_syscalls=136|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=1k|workers=32|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=377|h2_write_syscalls=264|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w1|protocol=h2c|mode=multiplex|payload=64k|bytes=65536|workers=1|server_threads=4|requests=4000|elapsed_ms=513.295|rps=7792.8|response_mbps=510.709|p50_us=126.82|p75_us=131.22|p90_us=144.70|p95_us=150.38|p99_us=160.10|min_us=116.42|mean_us=128.31|max_us=199.47|stddev_us=10.43|p999_us=190.63|tail_ratio=1.26|cv=0.08|samples=2000
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=64k|workers=1|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=8006|h2_write_syscalls=4004|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=64k|workers=1|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=20008|h2_write_syscalls=8005|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w8|protocol=h2c|mode=multiplex|payload=64k|bytes=65536|workers=8|server_threads=4|requests=4000|elapsed_ms=250.980|rps=15937.5|response_mbps=1044.481|p50_us=467.63|p75_us=566.76|p90_us=731.73|p95_us=788.53|p99_us=876.51|min_us=159.64|mean_us=498.06|max_us=1209.58|stddev_us=148.70|p999_us=1177.36|tail_ratio=1.87|cv=0.30|samples=2000
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=64k|workers=8|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=1346|h2_write_syscalls=677|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=64k|workers=8|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=16680|h2_write_syscalls=1346|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=h2_multiplex_w32|protocol=h2c|mode=multiplex|payload=64k|bytes=65536|workers=32|server_threads=4|requests=4000|elapsed_ms=184.698|rps=21657.0|response_mbps=1419.311|p50_us=1465.16|p75_us=1540.45|p90_us=1635.95|p95_us=1766.46|p99_us=3271.52|min_us=481.57|mean_us=1471.90|max_us=3710.42|stddev_us=277.28|p999_us=3680.88|tail_ratio=2.23|cv=0.19|samples=2016
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=64k|workers=32|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=612|h2_write_syscalls=504|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=64k|workers=32|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=16141|h2_write_syscalls=755|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
RESULT|suite=throughput|case=https_h2_sequential|protocol=https+h2|mode=sequential|payload=empty|bytes=0|workers=1|server_threads=4|requests=2000|elapsed_ms=151.045|rps=13241.1|response_mbps=0.000|p50_us=73.47|p75_us=77.73|p90_us=86.30|p95_us=94.58|p99_us=106.65|min_us=63.22|mean_us=75.46|max_us=135.32|stddev_us=8.80|p999_us=121.20|tail_ratio=1.45|cv=0.12|samples=2000
TLSVERIFY|protocol=https+h2|cert_verified=true|hostname_verified=true|negotiated_alpn=h2|session_resumption=n/a|cipher_suite=0x1303
RESULT|suite=throughput|case=https_h2_sequential|protocol=https+h2|mode=sequential|payload=1k|bytes=1024|workers=1|server_threads=4|requests=2000|elapsed_ms=174.261|rps=11477.0|response_mbps=11.752|p50_us=83.98|p75_us=89.01|p90_us=99.86|p95_us=107.95|p99_us=120.61|min_us=75.00|mean_us=87.08|max_us=133.90|stddev_us=9.24|p999_us=131.35|tail_ratio=1.44|cv=0.11|samples=2000
TLSVERIFY|protocol=https+h2|cert_verified=true|hostname_verified=true|negotiated_alpn=h2|session_resumption=n/a|cipher_suite=0x1303
RESULT|suite=throughput|case=https_h2_sequential|protocol=https+h2|mode=sequential|payload=64k|bytes=65536|workers=1|server_threads=4|requests=2000|elapsed_ms=999.325|rps=2001.4|response_mbps=131.161|p50_us=500.20|p75_us=511.89|p90_us=518.20|p95_us=522.53|p99_us=532.51|min_us=474.26|mean_us=499.60|max_us=602.70|stddev_us=15.38|p999_us=565.65|tail_ratio=1.06|cv=0.03|samples=2000
TLSVERIFY|protocol=https+h2|cert_verified=true|hostname_verified=true|negotiated_alpn=h2|session_resumption=n/a|cipher_suite=0x1303
total: complete
~~~

### Cross-Library Comparison
~~~text
courierust comparison suite (loopback, shared-peer matrix)
META|suite=compare|requests_per_repetition=2000|parallel_requests_per_repetition=2000|parallel_workers=8|repetitions=2|max_samples=2048
RESULT|suite=compare|case=raw_tcp_floor|layer=transport|protocol=h1|client=std_tcp|server=std_tcp|payload=4b|bytes=4|workers=1|server_threads=1|pool_policy=raw_tcp|pool_value=1|repetitions=1|status=valid|reason=-|requests=2000|elapsed_ms=60.040|rps=33311.4|response_mbps=0.133|p50_us=29.13|p75_us=29.45|p90_us=30.11|p95_us=36.26|p99_us=49.18|min_us=22.41|mean_us=29.96|max_us=65.40|stddev_us=3.48|p999_us=55.69|tail_ratio=1.69|cv=0.12|samples=2000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h1|client=courierust|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=206.383|rps=19381.5|response_mbps=19.847|p50_us=55.33|p75_us=56.86|p90_us=58.56|p95_us=63.27|p99_us=81.60|min_us=29.90|mean_us=51.53|max_us=108.87|stddev_us=8.57|p999_us=89.48|tail_ratio=1.47|cv=0.17|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h1|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=368.426|rps=10857.0|response_mbps=11.118|p50_us=86.22|p75_us=95.36|p90_us=110.15|p95_us=112.81|p99_us=127.42|min_us=82.84|mean_us=92.01|max_us=146.32|stddev_us=10.84|p999_us=142.56|tail_ratio=1.48|cv=0.12|samples=4000
RESULT|suite=compare|case=reqwest_client_to_courierust|layer=server|protocol=h1|client=reqwest|server=courierust|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=508.414|rps=7867.6|response_mbps=8.056|p50_us=125.30|p75_us=129.74|p90_us=144.01|p95_us=151.11|p99_us=160.63|min_us=108.11|mean_us=127.00|max_us=389.41|stddev_us=12.03|p999_us=181.62|tail_ratio=1.28|cv=0.09|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=server|protocol=h1|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=397.266|rps=10068.8|response_mbps=10.310|p50_us=95.99|p75_us=109.53|p90_us=112.47|p95_us=123.51|p99_us=136.38|min_us=78.68|mean_us=99.22|max_us=163.50|stddev_us=13.55|p999_us=145.52|tail_ratio=1.42|cv=0.14|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h1|client=courierust|server=hyper|payload=1k|bytes=1024|workers=8|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=59.699|rps=67002.4|response_mbps=68.610|p50_us=96.56|p75_us=136.42|p90_us=179.04|p95_us=202.65|p99_us=329.06|min_us=35.35|mean_us=112.03|max_us=1786.50|stddev_us=78.45|p999_us=981.61|tail_ratio=3.41|cv=0.70|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h1|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=8|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=158.342|rps=25261.7|response_mbps=25.868|p50_us=318.84|p75_us=342.11|p90_us=361.34|p95_us=374.70|p99_us=432.46|min_us=104.65|mean_us=312.69|max_us=986.59|stddev_us=58.40|p999_us=899.57|tail_ratio=1.36|cv=0.19|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h1|client=courierust|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=426.019|rps=9389.3|response_mbps=615.334|p50_us=103.28|p75_us=105.11|p90_us=120.11|p95_us=125.32|p99_us=131.62|min_us=79.47|mean_us=106.43|max_us=174.76|stddev_us=7.80|p999_us=152.52|tail_ratio=1.27|cv=0.07|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h1|client=reqwest|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=617.084|rps=6482.1|response_mbps=424.811|p50_us=150.77|p75_us=158.77|p90_us=172.26|p95_us=178.93|p99_us=193.30|min_us=127.04|mean_us=154.19|max_us=258.55|stddev_us=12.64|p999_us=214.76|tail_ratio=1.28|cv=0.08|samples=4000
RESULT|suite=compare|case=reqwest_client_to_courierust|layer=server|protocol=h1|client=reqwest|server=courierust|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=727.441|rps=5498.7|response_mbps=360.365|p50_us=178.76|p75_us=187.71|p90_us=200.42|p95_us=208.54|p99_us=228.75|min_us=158.82|mean_us=181.78|max_us=282.36|stddev_us=13.78|p999_us=260.27|tail_ratio=1.28|cv=0.08|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=server|protocol=h1|client=reqwest|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=630.449|rps=6344.7|response_mbps=415.805|p50_us=155.72|p75_us=168.69|p90_us=178.00|p95_us=187.35|p99_us=198.13|min_us=128.15|mean_us=157.54|max_us=269.57|stddev_us=17.21|p999_us=219.55|tail_ratio=1.27|cv=0.11|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=375.724|rps=10646.1|response_mbps=10.902|p50_us=93.13|p75_us=96.09|p90_us=108.82|p95_us=114.14|p99_us=125.13|min_us=80.29|mean_us=93.87|max_us=139.10|stddev_us=9.89|p999_us=136.73|tail_ratio=1.34|cv=0.11|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h2c|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=523.618|rps=7639.2|response_mbps=7.822|p50_us=126.86|p75_us=138.96|p90_us=147.68|p95_us=154.65|p99_us=167.97|min_us=103.21|mean_us=130.83|max_us=190.67|stddev_us=11.98|p999_us=184.92|tail_ratio=1.32|cv=0.09|samples=4000
RESULT|suite=compare|case=reqwest_client_to_courierust|layer=server|protocol=h2c|client=reqwest|server=courierust|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=455.432|rps=8782.9|response_mbps=8.994|p50_us=111.07|p75_us=116.81|p90_us=130.36|p95_us=135.11|p99_us=145.05|min_us=86.13|mean_us=113.78|max_us=174.52|stddev_us=10.53|p999_us=158.54|tail_ratio=1.31|cv=0.09|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=server|protocol=h2c|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=522.939|rps=7649.1|response_mbps=7.833|p50_us=126.92|p75_us=139.07|p90_us=147.15|p95_us=153.50|p99_us=164.18|min_us=105.30|mean_us=130.66|max_us=213.67|stddev_us=11.39|p999_us=173.79|tail_ratio=1.29|cv=0.09|samples=4000
RESULT|suite=compare|case=courierust_h2_conn1xw32|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=32|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=94.682|rps=42246.9|response_mbps=43.261|p50_us=712.26|p75_us=841.89|p90_us=975.50|p95_us=1094.26|p99_us=1405.82|min_us=104.66|mean_us=723.86|max_us=2008.57|stddev_us=219.75|p999_us=1890.49|tail_ratio=1.97|cv=0.30|samples=4000
RESULT|suite=compare|case=courierust_h2_conn4xw8|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=32|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=4|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=79.973|rps=50016.8|response_mbps=51.217|p50_us=557.78|p75_us=742.28|p90_us=948.56|p95_us=1073.40|p99_us=1420.42|min_us=88.88|mean_us=593.98|max_us=2620.61|stddev_us=270.28|p999_us=1941.95|tail_ratio=2.55|cv=0.46|samples=4000
RESULT|suite=compare|case=courierust_h2_conn8xw4|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=32|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=85.731|rps=46657.5|response_mbps=47.777|p50_us=602.63|p75_us=801.56|p90_us=1009.06|p95_us=1155.45|p99_us=1531.54|min_us=89.85|mean_us=634.46|max_us=2437.14|stddev_us=294.02|p999_us=2192.73|tail_ratio=2.54|cv=0.46|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h2c|client=courierust|server=hyper|payload=1k|bytes=1024|workers=8|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=117.240|rps=34118.1|response_mbps=34.937|p50_us=209.91|p75_us=271.86|p90_us=342.48|p95_us=400.60|p99_us=599.03|min_us=72.30|mean_us=228.41|max_us=925.70|stddev_us=98.81|p999_us=811.36|tail_ratio=2.85|cv=0.43|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h2c|client=reqwest|server=hyper|payload=1k|bytes=1024|workers=8|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=8|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=170.527|rps=23456.7|response_mbps=24.020|p50_us=326.95|p75_us=391.78|p90_us=456.93|p95_us=502.45|p99_us=592.91|min_us=111.39|mean_us=336.60|max_us=894.55|stddev_us=92.91|p999_us=759.17|tail_ratio=1.81|cv=0.28|samples=4000
RESULT|suite=compare|case=courierust_client_to_hyper|layer=client|protocol=h2c|client=courierust|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=693.915|rps=5764.4|response_mbps=377.775|p50_us=168.88|p75_us=185.78|p90_us=195.94|p95_us=204.39|p99_us=217.85|min_us=138.19|mean_us=173.42|max_us=244.64|stddev_us=16.55|p999_us=239.64|tail_ratio=1.29|cv=0.10|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=client|protocol=h2c|client=reqwest|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=804.893|rps=4969.6|response_mbps=325.688|p50_us=197.09|p75_us=208.09|p90_us=220.51|p95_us=227.36|p99_us=240.19|min_us=174.12|mean_us=201.16|max_us=278.71|stddev_us=13.13|p999_us=262.58|tail_ratio=1.22|cv=0.07|samples=4000
RESULT|suite=compare|case=reqwest_client_to_courierust|layer=server|protocol=h2c|client=reqwest|server=courierust|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=765.497|rps=5225.4|response_mbps=342.449|p50_us=187.33|p75_us=197.89|p90_us=209.93|p95_us=215.62|p99_us=228.10|min_us=162.61|mean_us=191.32|max_us=268.61|stddev_us=12.69|p999_us=247.03|tail_ratio=1.22|cv=0.07|samples=4000
RESULT|suite=compare|case=reqwest_client_to_hyper|layer=server|protocol=h2c|client=reqwest|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=810.582|rps=4934.7|response_mbps=323.402|p50_us=197.58|p75_us=208.91|p90_us=223.03|p95_us=230.35|p99_us=245.60|min_us=176.53|mean_us=202.59|max_us=361.40|stddev_us=14.03|p999_us=277.73|tail_ratio=1.24|cv=0.07|samples=4000
RESULT|suite=compare|case=courierust_h2c_large_body_to_hyper|layer=client|protocol=h2c|client=courierust|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=diagnostic|reason=flow_control_workload_not_a_speed_ratio|requests=64|elapsed_ms=178.470|rps=358.6|response_mbps=23.502|p50_us=2791.44|p75_us=2838.43|p90_us=2876.37|p95_us=2893.89|p99_us=2917.52|min_us=2591.58|mean_us=2788.49|max_us=2917.52|stddev_us=71.85|p999_us=2917.52|tail_ratio=1.05|cv=0.03|samples=64
RESULT|suite=compare|case=reqwest_async_h2c_large_body_to_hyper|layer=client|protocol=h2c|client=reqwest-async|server=hyper|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=reqwest_pool_max_idle_per_host|pool_value=1|repetitions=2|status=diagnostic|reason=flow_control_workload_not_a_speed_ratio|requests=64|elapsed_ms=159.092|rps=402.3|response_mbps=26.364|p50_us=2612.08|p75_us=2793.81|p90_us=2882.39|p95_us=2926.95|p99_us=3182.01|min_us=2070.48|mean_us=2485.75|max_us=3182.01|stddev_us=340.89|p999_us=3182.01|tail_ratio=1.22|cv=0.14|samples=64
RESULT|suite=compare|case=courierust_h3_client_to_courierust|layer=client|protocol=h3|client=courierust-h3|server=courierust-h3|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=929.975|rps=4301.2|response_mbps=4.404|p50_us=226.86|p75_us=251.95|p90_us=283.43|p95_us=307.72|p99_us=390.21|min_us=126.85|mean_us=232.37|max_us=1809.39|stddev_us=77.19|p999_us=1648.69|tail_ratio=1.72|cv=0.33|samples=4000
RESULT|suite=compare|case=quinn_h3_client_to_courierust|layer=client|protocol=h3|client=quinn+h3|server=courierust-h3|payload=1k|bytes=1024|workers=1|server_threads=4|pool_policy=quinn_single_connection|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=909.639|rps=4397.4|response_mbps=4.503|p50_us=221.88|p75_us=235.87|p90_us=249.89|p95_us=258.81|p99_us=302.20|min_us=190.83|mean_us=227.32|max_us=1773.41|stddev_us=40.22|p999_us=700.98|tail_ratio=1.36|cv=0.18|samples=4000
RESULT|suite=compare|case=courierust_h3_client_to_courierust|layer=client|protocol=h3|client=courierust-h3|server=courierust-h3|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=courierust_max_connections_per_host|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=3510.918|rps=1139.3|response_mbps=74.665|p50_us=857.57|p75_us=873.18|p90_us=898.03|p95_us=1098.73|p99_us=1156.75|min_us=726.51|mean_us=877.63|max_us=2793.25|stddev_us=99.07|p999_us=2116.18|tail_ratio=1.35|cv=0.11|samples=4000
RESULT|suite=compare|case=quinn_h3_client_to_courierust|layer=client|protocol=h3|client=quinn+h3|server=courierust-h3|payload=64k|bytes=65536|workers=1|server_threads=4|pool_policy=quinn_single_connection|pool_value=1|repetitions=2|status=valid|reason=-|requests=4000|elapsed_ms=4173.534|rps=958.4|response_mbps=62.811|p50_us=1125.83|p75_us=1164.45|p90_us=1186.29|p95_us=1198.90|p99_us=1224.25|min_us=762.93|mean_us=1043.27|max_us=1464.14|stddev_us=154.52|p999_us=1273.53|tail_ratio=1.09|cv=0.15|samples=4000
total: complete
~~~

### Concurrency
~~~text
CONCURRENCY|case=idle_partial_herd|model=event|platform=linux|status=probe_ok|event_enabled=true|connections=200|worker_threads=2|probe_us=2106.85
CONCURRENCY|case=idle_partial_herd|model=pool|platform=linux|status=probe_blocked|event_enabled=false|connections=200|worker_threads=2|probe_us=na|error=read: Resource temporarily unavailable (os error 11)
CONCURRENCY|case=slow_sender_herd|model=event|platform=linux|status=ok|event_enabled=true|connections=16|worker_threads=2|completed=16|probe_status=probe_ok|probe_us=150.81|byte_delay_us=10000|wall_ms=395.03
CONCURRENCY|suite=complete
~~~

### HTTP/3 (QUIC)
~~~text
RESULT|suite=h3|case=h3_connect|protocol=h3|mode=connect|payload=empty|bytes=0|workers=1|requests=1|connect_ms=6.629
RESULT|suite=h3|case=h3_sequential|protocol=h3|mode=reuse|payload=empty|bytes=0|workers=1|status=ok|requests=1000|elapsed_ms=160.944|rps=6213.3|p50_us=154.5|p75_us=174.6|p90_us=182.4|p99_us=214.2|min_us=118.11|mean_us=160.85|max_us=254.38|stddev_us=17.87|p999_us=247.05|tail_ratio=1.39|cv=0.11|samples=1000
RESULT|suite=h3|case=h3_parallel|protocol=h3|mode=reuse|payload=empty|bytes=0|workers=8|status=ok|requests=1000|elapsed_ms=45.732|rps=21866.5|p50_us=347.4|p75_us=380.3|p90_us=411.1|p99_us=470.2|min_us=195.64|mean_us=355.06|max_us=524.21|stddev_us=41.88|p999_us=517.41|tail_ratio=1.35|cv=0.12|samples=1000
~~~

### Reactor / Connection / Stream Evidence
~~~text
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=1k|workers=1|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=1|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=4254|h2_write_syscalls=4003|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=1k|workers=1|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=4003|h2_write_syscalls=4253|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=1k|workers=8|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=1|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=784|h2_write_syscalls=533|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=1k|workers=8|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=533|h2_write_syscalls=783|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=1k|workers=32|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=1|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=265|h2_write_syscalls=136|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=1k|workers=32|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=377|h2_write_syscalls=264|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=64k|workers=1|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=8006|h2_write_syscalls=4004|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w1|payload=64k|workers=1|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=1|h2_streams_per_connection_peak=1|h2_read_syscalls=20008|h2_write_syscalls=8005|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=64k|workers=8|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=1346|h2_write_syscalls=677|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w8|payload=64k|workers=8|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=8|h2_streams_per_connection_peak=8|h2_read_syscalls=16680|h2_write_syscalls=1346|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=64k|workers=32|connections_accepted=1|connections_active=0|event_poll_syscalls=1|event_wakeups=1|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=612|h2_write_syscalls=504|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
STATS|suite=throughput|protocol=h2c|case=h2_multiplex_w32|payload=64k|workers=32|connections_accepted=0|connections_active=0|event_poll_syscalls=0|event_wakeups=0|event_wait_errors=0|event_queue_depth_peak=0|h1_connections=0|h1_read_syscalls=0|h1_write_syscalls=0|h2_connections=1|h2_connections_active=1|h2_streams_total=4001|h2_streams_timed_out=0|h2_streams_active=0|h2_streams_active_peak=32|h2_streams_per_connection_peak=32|h2_read_syscalls=16141|h2_write_syscalls=755|h3_connections=0|h3_connections_active=0|h3_streams_total=0|h3_streams_active=0|h3_streams_active_peak=0|h3_streams_per_connection_peak=0|h3_queue_depth_peak=0|h3_udp_recv_syscalls=0|h3_udp_send_syscalls=0|h3_ack_deferred=0|h3_credit_stalls=0
~~~

### Cross-Machine
~~~text
NETWORK|role=client|status=not_configured|target_scope=remote|reason=COURIERUST_REMOTE_URL_not_set
~~~

### Fuzz
~~~text
FUZZ|target=h2_frame|status=ok|runs=smoke|duration_s=86|corpus=fuzz/corpus/h2_frame|reason=command_exit_0
FUZZ|target=hpack_block|status=ok|runs=smoke|duration_s=21|corpus=fuzz/corpus/hpack_block|reason=command_exit_0
FUZZ|target=h1_request|status=ok|runs=smoke|duration_s=22|corpus=fuzz/corpus/h1_request|reason=command_exit_0
FUZZ|target=h2_connection|status=ok|runs=smoke|duration_s=24|corpus=fuzz/corpus/h2_connection|reason=command_exit_0
FUZZ|target=ws_frame|status=ok|runs=smoke|duration_s=21|corpus=fuzz/corpus/ws_frame|reason=command_exit_0
FUZZ|target=ws_handshake|status=ok|runs=smoke|duration_s=22|corpus=fuzz/corpus/ws_handshake|reason=command_exit_0
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
