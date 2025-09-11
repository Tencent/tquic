#!/usr/bin/env bash
set -euo pipefail

# Simple ACK_FREQUENCY demo launcher.
# Requirements: built binaries tquic_server / tquic_client (cargo build --release)
# This script starts a server and then a client with ACK_FREQUENCY parameters, collects output.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="${ROOT_DIR}/target/release"
LOG_DIR="${ROOT_DIR}/demo/ack_frequency/logs"
QLOG_DIR_SERVER="${LOG_DIR}/qlog_server"
QLOG_DIR_CLIENT="${LOG_DIR}/qlog_client"

mkdir -p "${LOG_DIR}" "${QLOG_DIR_SERVER}" "${QLOG_DIR_CLIENT}"

SERVER_BIN="${BIN_DIR}/tquic_server"
CLIENT_BIN="${BIN_DIR}/tquic_client"

# Auto build if binaries missing or FORCE_REBUILD=1
if [[ "${FORCE_REBUILD:-0}" == "1" || ! -x "${SERVER_BIN}" || ! -x "${CLIENT_BIN}" ]]; then
  echo "[INFO] Building (FORCE_REBUILD=${FORCE_REBUILD:-0}) cargo build --release ..." >&2
  (cd "${ROOT_DIR}" && cargo build --release --quiet -p tquic_tools) || { echo "[ERR] cargo build failed" >&2; exit 1; }
fi

if [[ ! -x "${SERVER_BIN}" || ! -x "${CLIENT_BIN}" ]]; then
  echo "[ERR] Binaries still missing after build. Check build errors." >&2
  exit 1
fi

# Tunable parameters via env / default values
: "${ACK_FREQ_THRESHOLD:=32}"      # Ack-eliciting threshold N
: "${ACK_FREQ_MAX_DELAY_US:=16000}" # Requested max ack delay (us) (<16384 per spec constraint)
: "${ACK_FREQ_REORDERING:=0}"       # Reordering threshold
: "${IMMEDIATE_ACK_INTERVAL_MS:=30}" # Periodic immediate ack interval (ms) (enable default for demo)
: "${MAX_REQUESTS_PER_CONN:=0}"      # 0 = unlimited (reuse single connection)
: "${MIN_ACK_DELAY_US:=}"           # If set, advertise min_ack_delay transport parameter (us) enabling ACK_FREQUENCY send
: "${DURATION:=10}"                 # Benchmark duration (s)
: "${REQS:=100}"                    # Total requests per thread
: "${THREADS:=1}"                   # Client threads
: "${CONNS:=1}"                     # Connections per thread
: "${URL:=https://127.0.0.1:4433/README.md}" # Test URL (可被 BIG_FILE_MB 自动覆盖)
: "${BIG_FILE_MB:=}"             # 若设置 (>0) 则生成指定大小测试文件并自动替换 URL（除非用户已自定义 URL）

SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"

# Build optional min_ack_delay CLI piece (empty if unset)
if [[ -n "${MIN_ACK_DELAY_US}" ]]; then
  MIN_ACK_DELAY_OPT="${MIN_ACK_DELAY_US}"
else
  MIN_ACK_DELAY_OPT=""
fi

# Kill background jobs on exit
cleanup() {
  [[ -n "${SERVER_PID:-}" && -d "/proc/${SERVER_PID}" ]] && kill ${SERVER_PID} 2>/dev/null || true
}
trap cleanup EXIT

# 可选：生成大文件（只在 BIG_FILE_MB>0 且用户仍使用默认 URL 时自动替换）
if [[ -n "${BIG_FILE_MB}" && "${BIG_FILE_MB}" =~ ^[0-9]+$ && ${BIG_FILE_MB} -gt 0 ]]; then
  BIG_FILE_PATH="${ROOT_DIR}/big_${BIG_FILE_MB}m.bin"
  if [[ ! -f "${BIG_FILE_PATH}" ]]; then
    echo "[INFO] Generating ${BIG_FILE_MB}MB test file at ${BIG_FILE_PATH}" >&2
    # 使用 /dev/urandom 生成随机内容；体积较大时可改用 head -c 与 openssl rand。
    dd if=/dev/urandom of="${BIG_FILE_PATH}" bs=1m count="${BIG_FILE_MB}" status=none || {
      echo "[WARN] /dev/urandom 生成失败，改用 zeros" >&2
      dd if=/dev/zero of="${BIG_FILE_PATH}" bs=1m count="${BIG_FILE_MB}" status=none
    }
  else
    echo "[INFO] Reusing existing file ${BIG_FILE_PATH}" >&2
  fi
  # 仅当 URL 仍为默认 README.md 时自动切换
  if [[ "${URL}" == "https://127.0.0.1:4433/README.md" ]]; then
    URL="https://127.0.0.1:4433/$(basename "${BIG_FILE_PATH}")"
    echo "[INFO] Auto-set URL=${URL}" >&2
  fi
fi

# Launch server
"${SERVER_BIN}" \
  --listen 0.0.0.0:4433 \
  --cert "${ROOT_DIR}/fuzz/conf/cert.crt" \
  --key  "${ROOT_DIR}/fuzz/conf/cert.key" \
  --qlog-dir "${QLOG_DIR_SERVER}" \
  ${MIN_ACK_DELAY_US:+--min-ack-delay-us ${MIN_ACK_DELAY_US}} \
  --ack-freq-threshold "${ACK_FREQ_THRESHOLD}" \
  --ack-freq-max-delay "${ACK_FREQ_MAX_DELAY_US}" \
  --ack-freq-reordering "${ACK_FREQ_REORDERING}" \
  --log-level INFO >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
echo "[INFO] Server started (pid=${SERVER_PID})"

sleep 1

# Launch client
"${CLIENT_BIN}" \
  --connect-to 127.0.0.1:4433 \
  --qlog-dir "${QLOG_DIR_CLIENT}" \
  --threads "${THREADS}" \
  --max-concurrent-conns "${CONNS}" \
  --max-concurrent-requests 1 \
  --max-requests-per-conn "${MAX_REQUESTS_PER_CONN}" \
  --total-requests-per-thread "${REQS}" \
  --duration "${DURATION}" \
  --ack-freq-threshold "${ACK_FREQ_THRESHOLD}" \
  --ack-freq-max-delay "${ACK_FREQ_MAX_DELAY_US}" \
  --ack-freq-reordering "${ACK_FREQ_REORDERING}" \
  --immediate-ack-interval "${IMMEDIATE_ACK_INTERVAL_MS}" \
  ${MIN_ACK_DELAY_OPT:+--min-ack-delay-us ${MIN_ACK_DELAY_OPT}} \
  --log-level INFO \
  "${URL}" >"${CLIENT_LOG}" 2>&1

# After client finishes, give a moment for tail thread flush
sleep 1

# Summary extraction
ACK_LINES=$(grep -E "ACK_FREQUENCY sent|发送 ACK_FREQUENCY|qlog parsed" "${CLIENT_LOG}" || true)
REQ_RATE=$(grep -E "req/s" "${CLIENT_LOG}" || true)
INTERVAL_STATS=$(grep -E "ACK interval us" "${CLIENT_LOG}" || true)

cat <<EOF
================ Demo Summary ================
Ack Params: threshold=${ACK_FREQ_THRESHOLD} max_delay_us=${ACK_FREQ_MAX_DELAY_US} reordering=${ACK_FREQ_REORDERING} immediate_ack_interval_ms=${IMMEDIATE_ACK_INTERVAL_MS}
${REQ_RATE}
${ACK_LINES}
${INTERVAL_STATS}
QLOG(server): ${QLOG_DIR_SERVER}
QLOG(client): ${QLOG_DIR_CLIENT}
Logs saved:   ${LOG_DIR}
==============================================
EOF
