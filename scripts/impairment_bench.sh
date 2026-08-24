#!/usr/bin/env bash
# Controlled network-impairment benchmark for Courierust (Linux tc netem).
#
# Injects a real kernel-level impairment on the loopback interface — fixed
# RTT, loss, bandwidth — then runs the `network` bench across it. The
# client sees a genuine lossy/latent/constrained path: retransmits,
# congestion control and flow control all engage, unlike an in-process
# sleep/throttle.
#
# Usage: scripts/impairment_bench.sh [bench-dir] [delay_ms] [loss_pct]
#                                    [rate_mbit] [requests]
#   bench-dir  where the built `network` bench binary lives
#              (default: benches/target/release)
# Requires: Linux, root (tc), the `network` bench binary.
#
# The impairment is removed on exit (trap), so a failed run cannot leak a
# broken loopback qdisc.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/find_bench_bin.sh"

BENCH_DIR="${1:-benches/target/release}"
DELAY_MS="${2:-20}"
LOSS_PCT="${3:-1}"
RATE_MBIT="${4:-10}"
REQUESTS="${5:-1000}"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: impairment benchmark requires Linux (tc netem)" >&2
    exit 2
fi
if ! command -v tc >/dev/null 2>&1; then
    echo "error: tc (iproute2) not found" >&2
    exit 2
fi
if [[ "$(id -u)" -ne 0 && -z "${SUDO_USER:-}" ]]; then
    echo "error: needs root to configure tc netem (run with sudo)" >&2
    exit 2
fi

NET="$(find_bench_bin "$BENCH_DIR" network)"
if [[ -z "$NET" ]]; then
    echo "error: network bench binary not found under $BENCH_DIR" >&2
    exit 1
fi
if tc qdisc show dev lo | grep -q 'qdisc netem'; then
    echo "error: netem is already active on lo" >&2
    exit 2
fi

PORT=$((30000 + RANDOM % 20000))
SERVER_ADDR="127.0.0.1:$PORT"

# Real kernel-level impairment on loopback.
tc qdisc add dev lo root netem delay "${DELAY_MS}ms" loss "${LOSS_PCT}%" rate "${RATE_MBIT}mbit"
trap 'tc qdisc del dev lo root 2>/dev/null || true' EXIT
echo "netem active on lo: delay=${DELAY_MS}ms loss=${LOSS_PCT}% rate=${RATE_MBIT}mbit"

COURIERUST_NETWORK_ROLE=server COURIERUST_NETWORK_BIND="$SERVER_ADDR" \
    COURIERUST_NETWORK_PAYLOAD=4096 "$NET" > impairment_server.log 2>&1 &
SRV=$!
sleep 1

COURIERUST_NETWORK_URL="http://$SERVER_ADDR/" COURIERUST_NETWORK_PROTOCOL=h1 \
    COURIERUST_NETWORK_WORKERS=1 COURIERUST_NETWORK_MAX_CONNECTIONS=1 \
    COURIERUST_NETWORK_REQUESTS="$REQUESTS" COURIERUST_NETWORK_PAYLOAD=4096 \
    COURIERUST_NETWORK_TAG="netem-${DELAY_MS}ms-${LOSS_PCT}pct-${RATE_MBIT}mbit" \
    "$NET"

kill "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
echo "netem removed from lo"
