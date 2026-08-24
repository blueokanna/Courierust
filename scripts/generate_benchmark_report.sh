#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 4 ]]; then
    throughput_log=$1
    compare_log=$2
    interop_log=$3
    output=$4
    concurrency_log=''
    network_log=''
    fuzz_log=''
    h3_log=''
    tls_interop_log=''
elif [[ $# -eq 7 ]]; then
    throughput_log=$1
    compare_log=$2
    concurrency_log=$3
    interop_log=$4
    network_log=$5
    fuzz_log=$6
    output=$7
    h3_log=''
    tls_interop_log=''
elif [[ $# -eq 8 ]]; then
    throughput_log=$1
    compare_log=$2
    concurrency_log=$3
    interop_log=$4
    network_log=$5
    fuzz_log=$6
    h3_log=$7
    output=$8
    tls_interop_log=''
elif [[ $# -eq 9 ]]; then
    throughput_log=$1
    compare_log=$2
    concurrency_log=$3
    interop_log=$4
    network_log=$5
    fuzz_log=$6
    h3_log=$7
    tls_interop_log=$8
    output=$9
else
    printf 'usage: %s THROUGHPUT_LOG COMPARE_LOG [CONCURRENCY_LOG] INTEROP_LOG [NETWORK_LOG] [FUZZ_LOG] [H3_LOG] [TLS_INTEROP_LOG] OUTPUT\n' "$0" >&2
    exit 2
fi

extract_lines() {
    local pattern=$1
    local file=$2

    if [[ -n "$file" && -s "$file" ]]; then
        grep -E "$pattern" "$file" || true
    fi
}

result_field() {
    local line=$1
    local wanted=$2
    local field
    local -a fields

    IFS='|' read -r -a fields <<< "$line"
    for field in "${fields[@]}"; do
        if [[ "$field" == "$wanted="* ]]; then
            printf '%s' "${field#*=}"
            return
        fi
    done
    printf '%s' '-'
}

write_throughput_table() {
    local lines=$1
    local line

    if [[ -z "$lines" ]]; then
        printf '| _No benchmark result captured_ | | | | | | | | | | | | | | | | | | | | |\n'
        return
    fi

    printf '| Case | Protocol | Mode | Payload | Workers | Server threads | Requests | RPS | Resp MB/s | P50 us | P75 us | P90 us | P95 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples |\n'
    printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$(result_field "$line" case)" \
            "$(result_field "$line" protocol)" \
            "$(result_field "$line" mode)" \
            "$(result_field "$line" payload)" \
            "$(result_field "$line" workers)" \
            "$(result_field "$line" server_threads)" \
            "$(result_field "$line" requests)" \
            "$(result_field "$line" rps)" \
            "$(result_field "$line" response_mbps)" \
            "$(result_field "$line" p50_us)" \
            "$(result_field "$line" p75_us)" \
            "$(result_field "$line" p90_us)" \
            "$(result_field "$line" p95_us)" \
            "$(result_field "$line" p99_us)" \
            "$(result_field "$line" min_us)" \
            "$(result_field "$line" mean_us)" \
            "$(result_field "$line" max_us)" \
            "$(result_field "$line" stddev_us)" \
            "$(result_field "$line" p999_us)" \
            "$(result_field "$line" tail_ratio)" \
            "$(result_field "$line" samples)"
    done <<< "$lines"
}

write_compare_table() {
    local lines=$1
    local line

    if [[ -z "$lines" ]]; then
        printf '| _No benchmark result captured_ | | | | | | | | | | | | | | | | | | | | | | | | | | | |\n'
        return
    fi

    printf '| Case | Layer | Protocol | Client | Server | Payload | Workers | Server threads | Pool policy | Pool value | Reps | Status | Reason | Requests | RPS | Resp MB/s | P50 us | P75 us | P90 us | P95 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples |\n'
    printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$(result_field "$line" case)" \
            "$(result_field "$line" layer)" \
            "$(result_field "$line" protocol)" \
            "$(result_field "$line" client)" \
            "$(result_field "$line" server)" \
            "$(result_field "$line" payload)" \
            "$(result_field "$line" workers)" \
            "$(result_field "$line" server_threads)" \
            "$(result_field "$line" pool_policy)" \
            "$(result_field "$line" pool_value)" \
            "$(result_field "$line" repetitions)" \
            "$(result_field "$line" status)" \
            "$(result_field "$line" reason)" \
            "$(result_field "$line" requests)" \
            "$(result_field "$line" rps)" \
            "$(result_field "$line" response_mbps)" \
            "$(result_field "$line" p50_us)" \
            "$(result_field "$line" p75_us)" \
            "$(result_field "$line" p90_us)" \
            "$(result_field "$line" p95_us)" \
            "$(result_field "$line" p99_us)" \
            "$(result_field "$line" min_us)" \
            "$(result_field "$line" mean_us)" \
            "$(result_field "$line" max_us)" \
            "$(result_field "$line" stddev_us)" \
            "$(result_field "$line" p999_us)" \
            "$(result_field "$line" tail_ratio)" \
            "$(result_field "$line" samples)"
    done <<< "$lines"
}

write_concurrency_table() {
    local lines=$1
    local line

    if [[ -z "$lines" ]]; then
        printf '| _No concurrency result captured_ | | | | | | | | | | | | |\n'
        return
    fi

    printf '| Case | Model | Platform | Status | Event enabled | Connections | Worker threads | Probe us | Probe status | Byte delay us | Completed | Wall ms |\n'
    printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" == *'suite=complete'* ]] && continue
        local connections
        connections=$(result_field "$line" connections)
        if [[ "$connections" == "-" ]]; then
            local idle_connections
            local slow_connections
            idle_connections=$(result_field "$line" idle_connections)
            slow_connections=$(result_field "$line" slow_connections)
            if [[ "$idle_connections" != "-" ]]; then
                connections="idle=$idle_connections"
            elif [[ "$slow_connections" != "-" ]]; then
                connections="slow=$slow_connections"
            fi
        fi
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$(result_field "$line" case)" \
            "$(result_field "$line" model)" \
            "$(result_field "$line" platform)" \
            "$(result_field "$line" status)" \
            "$(result_field "$line" event_enabled)" \
            "$connections" \
            "$(result_field "$line" worker_threads)" \
            "$(result_field "$line" probe_us)" \
            "$(result_field "$line" probe_status)" \
            "$(result_field "$line" byte_delay_us)" \
            "$(result_field "$line" completed)" \
            "$(result_field "$line" wall_ms)"
    done <<< "$lines"
}

write_tlsverify_table() {
    local lines=$1
    local line

    if [[ -z "$lines" ]]; then
        printf '| _No TLS verification evidence captured_ | | | | | | |\n'
        return
    fi

    printf '| Protocol | Cert verified | Hostname verified | Negotiated ALPN | Session resumption | Cipher suite | Error |\n'
    printf '| --- | --- | --- | --- | --- | --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '| %s | %s | %s | %s | %s | %s | %s |\n' \
            "$(result_field "$line" protocol)" \
            "$(result_field "$line" cert_verified)" \
            "$(result_field "$line" hostname_verified)" \
            "$(result_field "$line" negotiated_alpn)" \
            "$(result_field "$line" session_resumption)" \
            "$(result_field "$line" cipher_suite)" \
            "$(result_field "$line" error)"
    done <<< "$lines"
}

write_network_table() {
    local lines=$1
    local line

    if [[ -z "$lines" ]]; then
        printf '| _No cross-machine result captured_ | | | | | | | | | | | | | | | | | | | | |\n'
        return
    fi

    printf '| Role | Status | Scope | Protocol | Workers | Max connections | Requests | Bytes | RPS | Resp MB/s | P50 us | P95 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples | Reason |\n'
    printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$(result_field "$line" role)" \
            "$(result_field "$line" status)" \
            "$(result_field "$line" target_scope)" \
            "$(result_field "$line" protocol)" \
            "$(result_field "$line" workers)" \
            "$(result_field "$line" max_connections)" \
            "$(result_field "$line" requests)" \
            "$(result_field "$line" bytes)" \
            "$(result_field "$line" rps)" \
            "$(result_field "$line" response_mbps)" \
            "$(result_field "$line" p50_us)" \
            "$(result_field "$line" p95_us)" \
            "$(result_field "$line" p99_us)" \
            "$(result_field "$line" min_us)" \
            "$(result_field "$line" mean_us)" \
            "$(result_field "$line" max_us)" \
            "$(result_field "$line" stddev_us)" \
            "$(result_field "$line" p999_us)" \
            "$(result_field "$line" tail_ratio)" \
            "$(result_field "$line" samples)" \
            "$(result_field "$line" reason)"
    done <<< "$lines"
}

write_fuzz_table() {
    local lines=$1
    local line

    if [[ -z "$lines" ]]; then
        printf '| _No fuzz result captured_ | | | | | |\n'
        return
    fi

    printf '| Target | Status | Runs | Duration s | Corpus | Reason |\n'
    printf '| --- | --- | --- | --- | --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '| %s | %s | %s | %s | %s | %s |\n' \
            "$(result_field "$line" target)" \
            "$(result_field "$line" status)" \
            "$(result_field "$line" runs)" \
            "$(result_field "$line" duration_s)" \
            "$(result_field "$line" corpus)" \
            "$(result_field "$line" reason)"
    done <<< "$lines"
}

write_h3_table() {
    local lines=$1
    local line

    if [[ -z "$lines" ]]; then
        printf '| _No HTTP/3 result captured_ | | | | | | | | | | | | | | | | | |\n'
        return
    fi

    printf '| Case | Mode | Workers | Requests | Elapsed ms | Connect ms | RPS | P50 us | P75 us | P90 us | P99 us | Min us | Mean us | Max us | Stddev us | P99.9 us | Tail | Samples |\n'
    printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$(result_field "$line" case)" \
            "$(result_field "$line" mode)" \
            "$(result_field "$line" workers)" \
            "$(result_field "$line" requests)" \
            "$(result_field "$line" elapsed_ms)" \
            "$(result_field "$line" connect_ms)" \
            "$(result_field "$line" rps)" \
            "$(result_field "$line" p50_us)" \
            "$(result_field "$line" p75_us)" \
            "$(result_field "$line" p90_us)" \
            "$(result_field "$line" p99_us)" \
            "$(result_field "$line" min_us)" \
            "$(result_field "$line" mean_us)" \
            "$(result_field "$line" max_us)" \
            "$(result_field "$line" stddev_us)" \
            "$(result_field "$line" p999_us)" \
            "$(result_field "$line" tail_ratio)" \
            "$(result_field "$line" samples)"
    done <<< "$lines"
}

write_stats_table() {
    local lines=$1
    local line

    if [[ -z "$lines" ]]; then
        printf '%s' '| _No reactor evidence captured_'
        for ((i = 1; i < 28; i++)); do printf ' |'; done
        printf '\n'
        return
    fi

    printf '| Protocol | Case | Payload | Workers | Accepted conns | Active conns | Poll syscalls | Wakeups | Queue peak | H1 conns | H1 read | H1 write | H2 conns | H2 active | H2 streams | H2 stream peak | H2 stream/conn peak | H2 read | H2 write | H3 conns | H3 active | H3 streams | H3 active streams | H3 stream peak | H3 stream/conn peak | H3 queue peak | H3 UDP recv | H3 UDP send |\n'
    printf '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
            "$(result_field "$line" protocol)" \
            "$(result_field "$line" case)" \
            "$(result_field "$line" payload)" \
            "$(result_field "$line" workers)" \
            "$(result_field "$line" connections_accepted)" \
            "$(result_field "$line" connections_active)" \
            "$(result_field "$line" event_poll_syscalls)" \
            "$(result_field "$line" event_wakeups)" \
            "$(result_field "$line" event_queue_depth_peak)" \
            "$(result_field "$line" h1_connections)" \
            "$(result_field "$line" h1_read_syscalls)" \
            "$(result_field "$line" h1_write_syscalls)" \
            "$(result_field "$line" h2_connections)" \
            "$(result_field "$line" h2_connections_active)" \
            "$(result_field "$line" h2_streams_total)" \
            "$(result_field "$line" h2_streams_active_peak)" \
            "$(result_field "$line" h2_streams_per_connection_peak)" \
            "$(result_field "$line" h2_read_syscalls)" \
            "$(result_field "$line" h2_write_syscalls)" \
            "$(result_field "$line" h3_connections)" \
            "$(result_field "$line" h3_connections_active)" \
            "$(result_field "$line" h3_streams_total)" \
            "$(result_field "$line" h3_streams_active)" \
            "$(result_field "$line" h3_streams_active_peak)" \
            "$(result_field "$line" h3_streams_per_connection_peak)" \
            "$(result_field "$line" h3_queue_depth_peak)" \
            "$(result_field "$line" h3_udp_recv_syscalls)" \
            "$(result_field "$line" h3_udp_send_syscalls)"
    done <<< "$lines"
}

write_interop_table() {
    local lines=$1
    local line
    local case_name
    local status

    if [[ -z "$lines" ]]; then
        printf '| _No interop result captured_ | |\n'
        return
    fi

    printf '| Case | Result |\n'
    printf '| --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        case_name=$(result_field "$line" case)
        status=${line##*|}
        if [[ "$case_name" == "-" ]]; then
            case_name=suite
        fi
        printf '| %s | %s |\n' "$case_name" "${status//|/\\|}"
    done <<< "$lines"
}

write_tlsinterop_table() {
    local lines=$1
    local line
    local role peer tls proto status detail

    if [[ -z "$lines" ]]; then
        printf '| _No TLS interop evidence captured_ | | | | | |\n'
        return
    fi

    printf '| Direction | Peer | TLS | Protocol | Status | Detail |\n'
    printf '| --- | --- | --- | --- | --- | --- |\n'
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Only run rows carry a status; binary/suite markers are skipped.
        [[ "$line" != *'status='* ]] && continue
        role=$(result_field "$line" role)
        peer=$(result_field "$line" peer)
        tls=$(result_field "$line" tls)
        proto=$(result_field "$line" protocol)
        status=$(result_field "$line" status)
        detail=$(result_field "$line" http)
        if [[ "$detail" != "-" ]]; then
            detail="http=$detail"
        else
            detail=$(result_field "$line" negotiated)
            if [[ "$detail" != "-" ]]; then
                detail="negotiated=$detail"
            else
                detail=$(result_field "$line" saw)
                if [[ "$detail" != "-" ]]; then
                    detail=${detail//|/\\|}
                else
                    detail="-"
                fi
            fi
        fi
        printf '| %s | %s | %s | %s | %s | %s |\n' "$role" "$peer" "$tls" "$proto" "$status" "$detail"
    done <<< "$lines"
}

write_raw_block() {
    local file=$1
    local pattern=$2

    if [[ -n "$file" && -s "$file" ]]; then
        grep -E "$pattern" "$file" || true
    else
        printf 'No output was captured for this benchmark.\n'
    fi
}

sha=${GITHUB_SHA:-local}
run_id=${GITHUB_RUN_ID:-local}
ref=${GITHUB_REF_NAME:-local}
runner=${RUNNER_OS:-$(uname -s)}
throughput_status=${BENCHMARK_THROUGHPUT_EXIT:-not-recorded}
compare_status=${BENCHMARK_COMPARE_EXIT:-not-recorded}
concurrency_status=${BENCHMARK_CONCURRENCY_EXIT:-not-recorded}
interop_status=${BENCHMARK_INTEROP_EXIT:-not-recorded}
network_status=${BENCHMARK_NETWORK_EXIT:-not-recorded}
fuzz_status=${BENCHMARK_FUZZ_EXIT:-not-recorded}
h3_status=${BENCHMARK_H3_EXIT:-not-recorded}

throughput_results=$(extract_lines '^RESULT\|suite=throughput' "$throughput_log")
tlsverify_results=$(extract_lines '^TLSVERIFY\|' "$throughput_log")
compare_results=$(extract_lines '^RESULT\|suite=compare' "$compare_log")
concurrency_results=$(extract_lines '^CONCURRENCY\|' "$concurrency_log")
interop_results=$(extract_lines '^INTEROP\|' "$interop_log")
network_results=$(extract_lines '^NETWORK\|' "$network_log")
fuzz_results=$(extract_lines '^FUZZ\|' "$fuzz_log")
h3_results=$(extract_lines '^RESULT\|suite=h3' "$h3_log")
stats_results=$(extract_lines '^STATS\|' "$throughput_log")
tlsinterop_results=$(extract_lines '^TLSINTEROP\|' "$tls_interop_log")

{
    printf '# GitHub Action Benchmark\n\n'
    printf 'Generated by the benchmark workflow.\n\n'
    printf '%s\n\n' '## Run'
    printf -- '- Commit: %s\n' "$sha"
    printf -- '- Ref: %s\n' "$ref"
    printf -- '- Runner: %s\n' "$runner"
    printf -- '- Throughput exit code: %s\n' "$throughput_status"
    printf -- '- Comparison exit code: %s\n' "$compare_status"
    printf -- '- Concurrency exit code: %s\n' "$concurrency_status"
    printf -- '- Interop exit code: %s\n' "$interop_status"
    printf -- '- HTTP/3 exit code: %s\n' "$h3_status"
    printf -- '- Cross-machine exit code: %s\n' "$network_status"
    printf -- '- Fuzz exit code: %s\n' "$fuzz_status"
    if [[ -n "${GITHUB_SERVER_URL:-}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]]; then
        printf -- '- Workflow run: [%s](%s/%s/actions/runs/%s)\n' "$run_id" "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID"
    else
        printf -- '- Workflow run: %s\n' "$run_id"
    fi

    printf '\n%s\n\n' '## Evidence Rules'
    printf '%s\n' '- Rows marked `invalid` are retained for auditability but are excluded from performance conclusions.'
    printf '%s\n' '- The `*_h2c_large_body_to_hyper` rows measure a 1 MiB POST against the same hyper h2 server. Both clients are paced by the server 64 KiB initial flow-control window (WINDOW_UPDATE round trips), and reqwest retains a large fixed wait even in the async client — these rows are NOT valid for ratio claims.'
    printf '%s\n' '- `quinn_h3_client_to_courierust` is reported `not_available` until the independent quinn+rustls QUIC/TLS handshake completes against the Courierust H3 server (a genuine interop gap, never faked).'
    printf '%s\n' '- Loopback is not cross-machine evidence. The cross-machine table is evidence only when `target_scope=remote` and `status=ok`.'
    printf '%s\n' '- TLS rows measure the built-in TLS 1.3 path; certificate, hostname, and ALPN checks must pass for the case to be valid. `negotiated_alpn` is reported; `session_resumption=n/a` because each TLSVERIFY row is a single handshake that does not measure resumption (the stack does implement TLS 1.3 session tickets).'
    printf '%s\n' '- Fuzz status is evidence only for the recorded target, run count, and duration; an unconfigured target is not a pass.'
    printf '%s\n' '- The `STATS` table is the reactor/connection/stream/syscall evidence behind the throughput rows (especially the h2 multi-worker scaling).'

    printf '\n%s\n\n' '## Reading the numbers (correct interpretation)'
    printf '%s\n' '- RPS and median latency are comparable only within a paired row (same client, server, payload, concurrency). Never divide across rows, clients or protocols to claim "N× faster".'
    printf '%s\n' '- reqwest pays for a general async runtime, rich extensions (proxies, cookies, encodings, swappable connector/TLS backends) and a different pool policy: `pool_max_idle_per_host=N` caps idle *pooled* connections, not live ones — equivalent to Courierust `max_connections_per_host=N` only under sequential load.'
    printf '%s\n' '- An H3 concurrent row whose P99/P99.9/tail_ratio sits far above its median (e.g. P99 jumping from ~200 µs to ms) is a signal to track, not noise. Candidates: UDP reactor, packet queue, congestion-window/ACK timers, QPACK/control flow, worker→reactor handoff, CI-runner scheduling. One run cannot localize the root cause, but it proves the H3 tail is not yet as tight as H2.'
    printf '%s\n' '- The H1 server is built for event-driven protection (incomplete headers, idle keep-alive, slow senders); hyper is a mature async architecture. A short-request microbenchmark cannot dismiss the scheduling value — the concurrency/slow-connection rows measure production usability and resource isolation.'
    printf '%s\n' '- H3 connection reuse plus cross-implementation interop (quinn+h3 → Courierust server) is stronger evidence than Courierust-to-Courierust.'

    printf '\n%s\n\n' '## Throughput'
    write_throughput_table "$throughput_results"
    printf '\n%s\n\n' '## TLS Verification Evidence'
    write_tlsverify_table "$tlsverify_results"
    printf '\n%s\n\n' '## Cross-Library Comparison'
    write_compare_table "$compare_results"
    printf '\n%s\n\n' '## Concurrency and Slow Connections'
    printf '%s\n' '- These rows measure production usability and resource isolation: an event-driven scheduler must keep idle/partial/slow (Slowloris-style) connections off the worker pool while a fast probe still completes. The `pool` row is the diagnostic counter-model.'
    write_concurrency_table "$concurrency_results"
    printf '\n%s\n\n' '## HTTP/3 (QUIC)'
    printf '%s\n' '- `h3_connect` is a cold request: QUIC handshake + TLS 1.3 + server Retry address validation on a fresh connection.'
    printf '%s\n' '- `h3_sequential` and `h3_parallel` reuse the pooled per-authority QUIC connection (`mode=reuse`), so they measure the warm per-request cost of connection reuse.'
    write_h3_table "$h3_results"
    printf '\n%s\n\n' '## Reactor / Connection / Stream Evidence'
    write_stats_table "$stats_results"
    printf '\n%s\n\n' '## Cross-Machine'
    write_network_table "$network_results"
    printf '\n%s\n\n' '## Fuzz'
    write_fuzz_table "$fuzz_results"
    printf '\n%s\n\n' '## Interop Validation'
    write_interop_table "$interop_results"
    printf '\n%s\n\n' '## TLS Interop Matrix'
    write_tlsinterop_table "$tlsinterop_results"

    printf '\n%s\n\n' '## Captured Benchmark Output'
    printf '%s\n' '### Throughput'
    printf '%s\n' '~~~text'
    write_raw_block "$throughput_log" '^(courierust throughput suite|META\|suite=throughput|RESULT\|suite=throughput|STATS\||TLSVERIFY\||total:)'
    printf '%s\n\n' '~~~'
    printf '%s\n' '### Cross-Library Comparison'
    printf '%s\n' '~~~text'
    write_raw_block "$compare_log" '^(courierust comparison suite|META\|suite=compare|RESULT\|suite=compare|total:)'
    printf '%s\n\n' '~~~'
    printf '%s\n' '### Concurrency'
    printf '%s\n' '~~~text'
    write_raw_block "$concurrency_log" '^(CONCURRENCY\|)'
    printf '%s\n\n' '~~~'
    printf '%s\n' '### HTTP/3 (QUIC)'
    printf '%s\n' '~~~text'
    write_raw_block "$h3_log" '^(RESULT\|suite=h3)'
    printf '%s\n\n' '~~~'
    printf '%s\n' '### Reactor / Connection / Stream Evidence'
    printf '%s\n' '~~~text'
    write_raw_block "$throughput_log" '^(STATS\|)'
    printf '%s\n\n' '~~~'
    printf '%s\n' '### Cross-Machine'
    printf '%s\n' '~~~text'
    write_raw_block "$network_log" '^(NETWORK\|)'
    printf '%s\n\n' '~~~'
    printf '%s\n' '### Fuzz'
    printf '%s\n' '~~~text'
    write_raw_block "$fuzz_log" '^(FUZZ\|)'
    printf '%s\n\n' '~~~'
    printf '%s\n' '### Interop Validation'
    printf '%s\n' '~~~text'
    write_raw_block "$interop_log" '^(courierust vs mainstream|INTEROP\|)'
    printf '%s\n' '~~~'
    printf '%s\n' '### TLS Interop'
    printf '%s\n' '~~~text'
    write_raw_block "$tls_interop_log" '^(TLSINTEROP\|)'
    printf '%s\n' '~~~'
} > "$output"

printf 'Wrote %s\n' "$output"
