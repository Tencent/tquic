#!/usr/bin/env bash
# Lightweight pf + dummynet network condition emulator for local tquic client/server tests.
# REQUIRE: macOS (pf + dnctl). Needs sudo. Use only on a dev box; restores previous pf rules on clear.
#
# Features:
#  - Configure delay / packet loss / bandwidth using a dummynet pipe.
#  - Target specific UDP ports (both directions) on lo0 (local tests).
#  - Backup & restore existing pf rules.
#
# Usage examples:
#   sudo ./scripts/ackfreq_net.sh apply --ports 443,8443 --delay 50ms --loss 0.01 --bw 20Mbit/s
#   sudo ./scripts/ackfreq_net.sh apply --ports 443 --delay 80ms --bw 10Mbit/s
#   sudo ./scripts/ackfreq_net.sh status
#   sudo ./scripts/ackfreq_net.sh clear
#
# Parameters:
#   --ports  Comma separated UDP port list (mandatory for apply)
#   --delay  One-way delay (e.g. 40ms, 2ms) default: 0ms
#   --loss   Packet loss rate (plr) in [0,1) default: 0
#   --bw     Bandwidth limit (e.g. 20Mbit/s, 5Mbit/s) default: unlimited
#   --pipe   Pipe number (default 501) – keep in a high range to avoid clashes
#
# Notes:
# 1. For round-trip latency ≈ 2 * delay (since applied on both directions if rules match both ways).
# 2. Bandwidth unit must be accepted by dnctl (e.g. 10Mbit/s, 500Kbit/s).
# 3. We only shape UDP traffic; extend rule for TCP if needed.
# 4. If you already have a complex pf setup, inspect merged rules before applying.
#
set -euo pipefail
CMD=${1:-}
shift || true
ORIG_FILE="scripts/.pf.rules.orig"   # 保存最初系统/用户 pf 规则 (首次 apply 创建)
MERGED_FILE="scripts/.pf.rules.merged" # 我们合成后的规则文件
TAG_BEGIN="# TQUIC_ACKFREQ_BEGIN"
TAG_END="# TQUIC_ACKFREQ_END"
PIPE_ID=501
DELAY="0ms"
LOSS="0"
BW=""
PORTS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ports) PORTS="$2"; shift 2;;
    --delay) DELAY="$2"; shift 2;;
    --loss) LOSS="$2"; shift 2;;
    --bw) BW="$2"; shift 2;;
    --pipe) PIPE_ID="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

require_root() { if [[ $EUID -ne 0 ]]; then echo "Need sudo/root" >&2; exit 1; fi }

pf_enabled() { pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; }

apply() {
  require_root
  [[ -n "$PORTS" ]] || { echo "--ports required" >&2; exit 1; }
  IFS=',' read -r -a port_arr <<<"$PORTS"
  # Configure pipe
  cfg_cmd=(dnctl pipe $PIPE_ID config delay $DELAY plr $LOSS)
  if [[ -n "$BW" ]]; then cfg_cmd+=(bw $BW); fi
  echo "[+] Configuring dummynet pipe: ${cfg_cmd[*]}" >&2
  "${cfg_cmd[@]}"
  # 仅首次保存原始规则
  if [[ ! -f "$ORIG_FILE" ]]; then
    echo "[+] Saving original pf rules -> $ORIG_FILE" >&2
    pfctl -sr > "$ORIG_FILE" || true
  fi

  # 基于原始规则构建新的合成规则文件 (删除旧标记块)
  if [[ -f "$ORIG_FILE" ]]; then
    grep -v "$TAG_BEGIN" "$ORIG_FILE" | grep -v "$TAG_END" > "$MERGED_FILE" || true
  else
    : > "$MERGED_FILE"
  fi

  # Build rule lines: 加入 in / out 方向确保合法语法 & 双向整形
  {
    echo "$TAG_BEGIN"
    for p in "${port_arr[@]}"; do
      echo "dummynet in  quick on lo0 proto udp from any to any port $p pipe $PIPE_ID"
      echo "dummynet out quick on lo0 proto udp from any to any port $p pipe $PIPE_ID"
    done
    echo "$TAG_END"
  } >> "$MERGED_FILE"

  echo "[+] Loading merged pf rules ($MERGED_FILE)" >&2
  pfctl -f "$MERGED_FILE"
  if ! pf_enabled; then
    echo "[+] Enabling pf" >&2
    pfctl -E >/dev/null
  fi
  echo "[✓] Applied shaping: ports=$PORTS delay=$DELAY loss=$LOSS bw=${BW:-unlimited} pipe=$PIPE_ID" >&2
}

clear_rules() {
  require_root
  echo "[+] Flushing dummynet pipe $PIPE_ID (ignore errors if unused)" >&2
  dnctl pipe delete $PIPE_ID 2>/dev/null || true
  if [[ -f $ORIG_FILE ]]; then
    echo "[+] Restoring original pf rules from $ORIG_FILE" >&2
    pfctl -f "$ORIG_FILE" || true
  else
    echo "[!] Original rules file not found; leaving pf as-is" >&2
  fi
  echo "[✓] Cleared shaping" >&2
}

status() {
  echo "[pf status]"; pfctl -s info | grep Status || true
  echo "[active rules matching TQUIC tag]"; pfctl -sr | sed -n "/$TAG_BEGIN/,/$TAG_END/p" || true
  echo "[dummynet pipes]"; dnctl list 2>/dev/null || true
}

case "$CMD" in
  apply) apply ;;
  clear) clear_rules ;;
  status) status ;;
  *) echo "Usage: sudo $0 {apply|clear|status} [--ports 443,8443] [--delay 50ms] [--loss 0.01] [--bw 20Mbit/s] [--pipe 501]" >&2; exit 1;;
 esac
