#!/usr/bin/env bash
# External TLS-stack interop for Courierust (TLS 1.2 + 1.3 matrix).
#
# Self-interop only proves Courierust agrees with itself. Here the TLS layer
# is checked against mainstream independent stacks, both directions:
#   A. Courierust client  -> OpenSSL s_server      (TLS 1.3 / 1.2, h1)
#   B. Courierust server  <- curl / s_client       (TLS 1.3 / 1.2, h1+h2, ALPN)
#   C. Courierust h2 client -> nginx               (TLS 1.3 / 1.2, when present)
# Throwaway CA + leaf generated locally; no network, no long-lived servers.
#
# Usage: scripts/tls_interop.sh [bench-target-dir] [logfile]
set -euo pipefail

BENCH_DIR="${1:-benches/target/release}"
LOGFILE="${2:-tls_interop.log}"
# Resolve BOTH to absolute paths before we cd into the temp dir below —
# otherwise the relative `$BENCH_DIR/deps/<name>` paths that `find_bin`
# returns would resolve against the temp dir and every spawned binary
# would fail with "No such file or directory".
case "$BENCH_DIR" in
  /*) : ;;
  *) BENCH_DIR="$PWD/$BENCH_DIR" ;;
esac
case "$LOGFILE" in
  /*) : ;;
  *) LOGFILE="$PWD/$LOGFILE" ;;
esac
OPENSSL_BIN="${OPENSSL:-openssl}"
CURL_BIN="${CURL:-curl}"
NGINX_BIN="${NGINX:-nginx}"
# Some environments (e.g. Windows machines with a stale OPENSSL_CONF
# pointing at a missing file) ship a broken openssl.cnf. Fall back to the
# compiled-in default so certificate generation cannot fail for that
# reason.
if [[ -n "${OPENSSL_CONF:-}" && ! -f "$OPENSSL_CONF" ]]; then
  unset OPENSSL_CONF
fi
: > "$LOGFILE"

# Bench artifacts carry a hash under `deps/`; the shared locator handles
# both layouts (see scripts/find_bench_bin.sh).
source "$(dirname "${BASH_SOURCE[0]}")/find_bench_bin.sh"
TLS_INTEROP_BIN="$(find_bench_bin "$BENCH_DIR" tls_interop || true)"
NETWORK_BIN="$(find_bench_bin "$BENCH_DIR" network || true)"
if [[ -z "$TLS_INTEROP_BIN" || -z "$NETWORK_BIN" ]]; then
  echo "error: built tls_interop/network bench binaries not found under $BENCH_DIR" >&2
  echo "searched: $BENCH_DIR/<name> and $BENCH_DIR/deps/<name>-*" >&2
  echo "deps dir listing:" >&2
  ls -la "$BENCH_DIR/deps/" 2>/dev/null | grep -E 'tls_interop|network' || true
  exit 1
fi
# Re-verify at use time and log the pick, so a stale/pruned artifact is
# visible in CI instead of a bare "No such file or directory".
require_bin() {
  local path="$1" role="$2"
  if [[ ! -f "$path" || ! -x "$path" ]]; then
    echo "error: $role binary not usable: $path" >&2
    exit 1
  fi
  echo "TLSINTEROP|binary|$role|$path"
}
require_bin "$TLS_INTEROP_BIN" "tls_interop"
require_bin "$NETWORK_BIN" "network"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

record() {
  printf '%s\n' "$1" >> "$LOGFILE"
  printf '%s\n' "$1"
}

fail=0
mark_fail() {
  fail=1
}

wait_port() {
  local port="$1" tries="${2:-100}"
  for _ in $(seq 1 "$tries"); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&- 3<&- 2>/dev/null || true
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# --- 0. Throwaway Ed25519 identity: one self-signed cert doubles as server
# identity AND trust root (SAN localhost+127.0.0.1, serverAuth, CA:TRUE) —
# the same shape the integration tests use, so the exercised cert paths
# match those covered by `cargo test`.
"$OPENSSL_BIN" req -x509 -newkey ed25519 -keyout server.key -out server.pem \
  -days 2 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "basicConstraints=critical,CA:TRUE" >/dev/null 2>&1
cp server.pem ca.pem
"$OPENSSL_BIN" x509 -in ca.pem -outform DER -out ca.der
"$OPENSSL_BIN" x509 -in server.pem -outform DER -out server_cert.der
"$OPENSSL_BIN" pkcs8 -topk8 -nocrypt -in server.key -outform DER -out server_key.der

# --- A. Courierust client -> OpenSSL s_server, one run per TLS version ---
client_vs_s_server() {
  local version="$1" flag="$2"
  local port=$((30000 + RANDOM % 20000))
  # Pin the client's offered window to the forced server version: a TLS
  # 1.2-only peer must not see a supported_versions extension advertising
  # TLS 1.3 (OpenSSL rejects such a ClientHello with protocol_version).
  if [[ "$version" == "TLSv1.2" ]]; then
    export COURIERUST_TLS_MIN_VERSION="TLSv1.2"
    export COURIERUST_TLS_MAX_VERSION="TLSv1.2"
  else
    unset COURIERUST_TLS_MIN_VERSION COURIERUST_TLS_MAX_VERSION 2>/dev/null || true
  fi
  "$OPENSSL_BIN" s_server -accept "127.0.0.1:$port" -cert server.pem -key server.key \
    "$flag" -www -quiet > s_server.log 2>&1 &
  local pid=$!
  if wait_port "$port"; then
    if COURIERUST_TLS_URL="https://localhost:$port/" \
       COURIERUST_TLS_ROOT="$WORK/ca.der" \
       COURIERUST_TLS_PROTO="h1" \
       "$TLS_INTEROP_BIN" > tls_s_server.log 2>&1; then
      cat tls_s_server.log
      record "TLSINTEROP|role=client|peer=openssl_s_server|tls=$version|protocol=h1|status=ok"
    else
      echo "--- s_server client log ---"
      cat tls_s_server.log 2>/dev/null || true
      record "TLSINTEROP|role=client|peer=openssl_s_server|tls=$version|protocol=h1|status=failed"
      mark_fail
    fi
  else
    echo "--- s_server did not listen; log ---"
    cat s_server.log 2>/dev/null || true
    record "TLSINTEROP|role=client|peer=openssl_s_server|tls=$version|protocol=h1|status=no_listen"
    mark_fail
  fi
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
client_vs_s_server "TLSv1.3" -tls1_3
client_vs_s_server "TLSv1.2" -tls1_2

# --- B. Courierust TLS server <- curl / s_client, one run per TLS version ---
curl_vs_server() {
  local version="$1" flag="$2" http2="$3"
  local proto="h1" extra=()
  [[ "$http2" == 1 ]] && { proto="h2"; extra+=(--http2); }
  # Report the *actually negotiated* TLS version (%{ssl_version}) — a
  # forced --tlsv1.2 can still be answered with TLS 1.3 by a peer that
  # refuses 1.2, and recording the requested value would fake the row.
  local http actual
  http=$("$CURL_BIN" -sS --cacert ca.pem --max-time 15 "${extra[@]}" "$flag" \
    -w '%{http_code} %{ssl_version}' -o curl_body.txt "https://127.0.0.1:$PORT_B/bench" 2>curl_err.txt || true)
  actual="${http##* }"
  http="${http%% *}"
  if [[ "$http" == "200" ]]; then
    record "TLSINTEROP|role=server|peer=curl|tls=$version|negotiated=$actual|protocol=$proto|status=ok|http=200"
  else
    echo "--- curl $proto error ---"
    cat curl_err.txt 2>/dev/null || true
    record "TLSINTEROP|role=server|peer=curl|tls=$version|protocol=$proto|status=failed|http=${http:-none}"
    mark_fail
  fi
}

s_client_alpn() {
  local version="$1" flag="$2"
  local output alpn protocol
  # One handshake, two facts: the ALPN we advertise must be picked, and the
  # protocol line must match the TLS version the caller asked for — proving
  # the server negotiated the exact requested version.
  output=$("$OPENSSL_BIN" s_client -connect "127.0.0.1:$PORT_B" -CAfile ca.pem \
    "$flag" -alpn h2 -servername localhost </dev/null 2>/dev/null || true)
  alpn=$(printf '%s\n' "$output" | grep -i 'ALPN protocol' | tail -1 || true)
  protocol=$(printf '%s\n' "$output" | grep -iE '^Protocol[[:space:]]*:' | tail -1 || true)
  if [[ "$alpn" == *h2* ]]; then
    record "TLSINTEROP|role=server|peer=openssl_s_client|tls=$version|protocol=alpn|status=ok|negotiated=h2|saw=$protocol"
  else
    record "TLSINTEROP|role=server|peer=openssl_s_client|tls=$version|protocol=alpn|status=failed|negotiated=${alpn:-none}"
    mark_fail
  fi
}

PORT_B=$((30000 + RANDOM % 20000))
COURIERUST_NETWORK_ROLE=server \
COURIERUST_NETWORK_BIND="127.0.0.1:$PORT_B" \
COURIERUST_NETWORK_TLS=1 \
COURIERUST_NETWORK_HTTP2=1 \
COURIERUST_NETWORK_CERT_DER="$WORK/server_cert.der" \
COURIERUST_NETWORK_KEY_DER="$WORK/server_key.der" \
COURIERUST_NETWORK_PAYLOAD=64 \
  "$NETWORK_BIN" > tls_server.log 2>&1 &
SRV_PID=$!

if wait_port "$PORT_B"; then
  curl_vs_server "TLSv1.3" --tlsv1.3 0
  curl_vs_server "TLSv1.2" --tlsv1.2 0
  curl_vs_server "TLSv1.3" --tlsv1.3 1
  curl_vs_server "TLSv1.2" --tlsv1.2 1
  s_client_alpn "TLSv1.3" -tls1_3
  s_client_alpn "TLSv1.2" -tls1_2
else
  echo "--- courierust network server did not listen; log ---"
  cat tls_server.log 2>/dev/null || true
  record "TLSINTEROP|role=server|peer=curl|protocol=h1|status=no_listen"
  record "TLSINTEROP|role=server|peer=openssl_s_client|protocol=alpn|status=no_listen"
  mark_fail
fi
kill "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true

# --- C. Courierust h2 client -> nginx (ALPN h2), one run per TLS version ---
if command -v "$NGINX_BIN" >/dev/null 2>&1; then
  client_vs_nginx() {
    local version="$1"
    local port=$((30000 + RANDOM % 20000))
    if [[ "$version" == "TLSv1.2" ]]; then
      export COURIERUST_TLS_MIN_VERSION="TLSv1.2"
      export COURIERUST_TLS_MAX_VERSION="TLSv1.2"
    else
      unset COURIERUST_TLS_MIN_VERSION COURIERUST_TLS_MAX_VERSION 2>/dev/null || true
    fi
    cat > nginx.conf <<EOF
worker_processes 1;
pid $WORK/nginx.pid;
error_log $WORK/nginx_error.log;
events { worker_connections 64; }
http {
  access_log off;
  server {
    listen 127.0.0.1:$port ssl http2;
    server_name localhost;
    ssl_certificate $WORK/server.pem;
    ssl_certificate_key $WORK/server.key;
    ssl_protocols $version;
    location / { return 200 'ok'; add_header Content-Type text/plain; }
  }
}
EOF
    "$NGINX_BIN" -p "$WORK" -c "$WORK/nginx.conf" > nginx_start.log 2>&1 &
    local pid=$!
    if wait_port "$port"; then
      if COURIERUST_TLS_URL="https://localhost:$port/" \
         COURIERUST_TLS_ROOT="$WORK/ca.der" \
         COURIERUST_TLS_PROTO="h2" \
         "$TLS_INTEROP_BIN" > tls_nginx.log 2>&1; then
        cat tls_nginx.log
        record "TLSINTEROP|role=client|peer=nginx|tls=$version|protocol=h2|status=ok"
      else
        echo "--- courierust client vs nginx log ---"
        cat tls_nginx.log 2>/dev/null || true
        record "TLSINTEROP|role=client|peer=nginx|tls=$version|protocol=h2|status=failed"
        mark_fail
      fi
    else
      echo "--- nginx did not listen; log ---"
      cat nginx_start.log nginx_error.log 2>/dev/null || true
      record "TLSINTEROP|role=client|peer=nginx|tls=$version|protocol=h2|status=no_listen"
      mark_fail
    fi
    "$NGINX_BIN" -p "$WORK" -c "$WORK/nginx.conf" -s stop >/dev/null 2>&1 || \
      kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  }
  client_vs_nginx "TLSv1.3"
  client_vs_nginx "TLSv1.2"
else
  record "TLSINTEROP|role=client|peer=nginx|protocol=h2|status=skipped(nginx_not_found)"
fi

record "TLSINTEROP|suite=complete|fail=$fail"
exit "$fail"
