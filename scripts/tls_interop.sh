#!/usr/bin/env bash
# Real external TLS-stack interop for Courierust.
#
# The self-interop suite (benches/src/interop.rs) only proves that
# Courierust's TLS client and server agree with each other. This script
# proves the TLS layer against a *mainstream, independently implemented*
# stack, in both directions:
#
#   A. Courierust client  ->  OpenSSL s_server (TLS 1.3, HTTP/1.1)
#   B. Courierust server  <-  curl / OpenSSL s_client (independent stack
#                             validates our server: cert, ALPN, h1, h2)
#   C. Courierust h2 client -> nginx (TLS + HTTP/2 via ALPN), when nginx
#                             is installed
#
# Everything is generated locally (a throwaway CA + leaf) so the job
# needs no network and no long-lived test servers.
#
# Usage: scripts/tls_interop.sh [bench-target-dir]
#   bench-target-dir  where the built `tls_interop` and `network` bench
#                     binaries live (default: benches/target/release)
#
# Results are printed as `TLSINTEROP|...` lines (and appended to
# tls_interop.log when a logfile path is given as the second argument).
set -euo pipefail

BENCH_DIR="${1:-benches/target/release}"
LOGFILE="${2:-tls_interop.log}"
# Resolve to an absolute path before we cd into the temp dir.
case "$LOGFILE" in
  /*) : ;;
  *) LOGFILE="$PWD/$LOGFILE" ;;
esac
OPENSSL_BIN="${OPENSSL:-openssl}"
CURL_BIN="${CURL:-curl}"
NGINX_BIN="${NGINX:-nginx}"
: > "$LOGFILE"

# Locate a bench binary: prefer `$BENCH_DIR/<name>`, else the newest
# `$BENCH_DIR/deps/<name>-*` (the output location of `cargo bench
# --no-run`, whose artifact names carry a hash).
find_bin() {
  local name="$1"
  if [[ -x "$BENCH_DIR/$name" ]]; then
    printf '%s\n' "$BENCH_DIR/$name"
    return 0
  fi
  ls -t "$BENCH_DIR"/deps/${name}-* 2>/dev/null | head -1
}
TLS_INTEROP_BIN="$(find_bin tls_interop)"
NETWORK_BIN="$(find_bin network)"
if [[ -z "$TLS_INTEROP_BIN" || -z "$NETWORK_BIN" ]]; then
  echo "error: built tls_interop/network bench binaries not found under $BENCH_DIR" >&2
  exit 1
fi

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

# ---------------------------------------------------------------------
# 0. Throwaway CA + server certificate (RSA 2048, SAN localhost).
#    Both OpenSSL and curl/nginx must accept the leaf, so it is signed by
#    a real CA rather than being self-signed.
# ---------------------------------------------------------------------
"$OPENSSL_BIN" req -x509 -newkey rsa:2048 -keyout ca.key -out ca.pem \
  -days 2 -nodes -subj "/CN=Courierust CI CA" >/dev/null 2>&1
"$OPENSSL_BIN" req -newkey rsa:2048 -keyout server.key -out server.csr \
  -nodes -subj "/CN=localhost" >/dev/null 2>&1
"$OPENSSL_BIN" x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 2 \
  -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n') \
  >/dev/null 2>&1
"$OPENSSL_BIN" x509 -in ca.pem -outform DER -out ca.der
"$OPENSSL_BIN" x509 -in server.pem -outform DER -out server_cert.der
"$OPENSSL_BIN" pkcs8 -topk8 -nocrypt -in server.key -outform DER -out server_key.der

# ---------------------------------------------------------------------
# A. Courierust client -> OpenSSL s_server (TLS 1.3, HTTP/1.1, -www).
# ---------------------------------------------------------------------
PORT_A=$((30000 + RANDOM % 20000))
"$OPENSSL_BIN" s_server -accept "127.0.0.1:$PORT_A" -cert server.pem -key server.key \
  -tls1_3 -www -quiet > s_server.log 2>&1 &
SS_PID=$!
if wait_port "$PORT_A"; then
  if COURIERUST_TLS_URL="https://localhost:$PORT_A/" \
     COURIERUST_TLS_ROOT="$WORK/ca.der" \
     COURIERUST_TLS_PROTO="h1" \
     "$TLS_INTEROP_BIN" > tls_s_server.log 2>&1; then
    cat tls_s_server.log
    record "TLSINTEROP|role=client|peer=openssl_s_server|protocol=h1|status=ok"
  else
    record "TLSINTEROP|role=client|peer=openssl_s_server|protocol=h1|status=failed"
    mark_fail
  fi
else
  record "TLSINTEROP|role=client|peer=openssl_s_server|protocol=h1|status=no_listen"
  mark_fail
fi
kill "$SS_PID" 2>/dev/null || true
wait "$SS_PID" 2>/dev/null || true

# ---------------------------------------------------------------------
# B. Courierust TLS server (h1 + h2) <- curl and OpenSSL s_client.
# ---------------------------------------------------------------------
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
  # B1. curl (independent TLS stack) over HTTP/1.1.
  HTTP=$("$CURL_BIN" -sS --cacert ca.pem --max-time 15 -o curl_body.txt -w '%{http_code}' \
    "https://127.0.0.1:$PORT_B/bench" 2>curl_err.txt || true)
  if [[ "$HTTP" == "200" ]]; then
    record "TLSINTEROP|role=server|peer=curl|protocol=h1|status=ok|http=200"
  else
    record "TLSINTEROP|role=server|peer=curl|protocol=h1|status=failed|http=${HTTP:-none}"
    mark_fail
  fi
  # B2. curl over HTTP/2 (ALPN h2) when the build supports it.
  HTTP2=$("$CURL_BIN" -sS --http2 --cacert ca.pem --max-time 15 -o curl2_body.txt -w '%{http_code}' \
    "https://127.0.0.1:$PORT_B/bench" 2>curl2_err.txt || true)
  if [[ "$HTTP2" == "200" ]]; then
    record "TLSINTEROP|role=server|peer=curl_http2|protocol=h2|status=ok|http=200"
  else
    record "TLSINTEROP|role=server|peer=curl_http2|protocol=h2|status=failed|http=${HTTP2:-none}"
    mark_fail
  fi
  # B3. OpenSSL s_client: independent stack must complete a handshake
  #     and see our ALPN offer (h2 first).
  ALPN=$("$OPENSSL_BIN" s_client -connect "127.0.0.1:$PORT_B" -CAfile ca.pem \
    -alpn h2 -servername localhost </dev/null 2>/dev/null | grep -i 'ALPN protocol' | tail -1 || true)
  if [[ "$ALPN" == *h2* ]]; then
    record "TLSINTEROP|role=server|peer=openssl_s_client|protocol=alpn|status=ok|negotiated=h2"
  else
    record "TLSINTEROP|role=server|peer=openssl_s_client|protocol=alpn|status=failed|negotiated=${ALPN:-none}"
    mark_fail
  fi
else
  record "TLSINTEROP|role=server|peer=curl|protocol=h1|status=no_listen"
  record "TLSINTEROP|role=server|peer=openssl_s_client|protocol=alpn|status=no_listen"
  mark_fail
fi
kill "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true

# ---------------------------------------------------------------------
# C. Courierust h2 client -> nginx (TLS + HTTP/2), when nginx exists.
# ---------------------------------------------------------------------
if command -v "$NGINX_BIN" >/dev/null 2>&1; then
  PORT_C=$((30000 + RANDOM % 20000))
  cat > nginx.conf <<EOF
worker_processes 1;
pid $WORK/nginx.pid;
error_log $WORK/nginx_error.log;
events { worker_connections 64; }
http {
  access_log off;
  server {
    listen 127.0.0.1:$PORT_C ssl http2;
    server_name localhost;
    ssl_certificate $WORK/server.pem;
    ssl_certificate_key $WORK/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / { return 200 'ok'; add_header Content-Type text/plain; }
  }
}
EOF
  "$NGINX_BIN" -p "$WORK" -c "$WORK/nginx.conf" > nginx_start.log 2>&1 &
  NGX_PID=$!
  if wait_port "$PORT_C"; then
    if COURIERUST_TLS_URL="https://localhost:$PORT_C/" \
       COURIERUST_TLS_ROOT="$WORK/ca.der" \
       COURIERUST_TLS_PROTO="h2" \
       "$TLS_INTEROP_BIN" > tls_nginx.log 2>&1; then
      cat tls_nginx.log
      record "TLSINTEROP|role=client|peer=nginx|protocol=h2|status=ok"
    else
      record "TLSINTEROP|role=client|peer=nginx|protocol=h2|status=failed"
      mark_fail
    fi
  else
    record "TLSINTEROP|role=client|peer=nginx|protocol=h2|status=no_listen"
    mark_fail
  fi
  "$NGINX_BIN" -p "$WORK" -c "$WORK/nginx.conf" -s stop >/dev/null 2>&1 || \
    kill "$NGX_PID" 2>/dev/null || true
  wait "$NGX_PID" 2>/dev/null || true
else
  record "TLSINTEROP|role=client|peer=nginx|protocol=h2|status=skipped(nginx_not_found)"
fi

record "TLSINTEROP|suite=complete|fail=$fail"
exit "$fail"
