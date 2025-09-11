#!/usr/bin/env bash
# Batch ACK_FREQUENCY evaluation harness.
# 依赖: scripts/ackfreq_net.sh 以及 demo/ack_frequency/run_ack_freq_demo.sh
# 用途: 按“网络档位 x ACK 频率策略”矩阵自动跑多轮测试, 生成结构化结果。
# 注意: 需 sudo (pf + dummynet), 本脚本会修改本机 pf 规则; 请在干净开发机使用。
# 输出: out/ackfreq/results.jsonl 及每轮的日志/ qlog 目录。

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_SH="${ROOT_DIR}/demo/ack_frequency/run_ack_freq_demo.sh"
NET_SH="${ROOT_DIR}/scripts/ackfreq_net.sh"

# =============== 运行目录与防覆盖逻辑 =================
# 每次运行创建独立目录: out/ackfreq/run-<timestamp>[-tag]
# 可通过 RUN_TAG 指定自定义标签; 通过 APPEND=1 追加到最近一次 (latest) 目录。
BASE_OUT_DIR="${ROOT_DIR}/out/ackfreq"
mkdir -p "${BASE_OUT_DIR}"

RUN_TAG=${RUN_TAG:-""}
APPEND=${APPEND:-0}

if [[ $APPEND -eq 1 && -L "${BASE_OUT_DIR}/latest" && -d "${BASE_OUT_DIR}/$(readlink "${BASE_OUT_DIR}/latest")" ]]; then
  # 追加模式: 使用 latest 指向的目录
  OUT_REL="$(readlink "${BASE_OUT_DIR}/latest")"
  OUT_DIR="${BASE_OUT_DIR}/${OUT_REL}"
  echo "[INFO] APPEND=1, 复用目录 ${OUT_DIR}" >&2
else
  TS=$(date +%Y%m%d-%H%M%S)
  RUN_ID="run-${TS}${RUN_TAG:+-$RUN_TAG}"
  OUT_DIR="${BASE_OUT_DIR}/${RUN_ID}"
  if [[ -d "${OUT_DIR}" ]]; then
    # 罕见: 时间戳冲突, 加序号
    i=1
    while [[ -d "${OUT_DIR}.$i" ]]; do i=$((i+1)); done
    OUT_DIR="${OUT_DIR}.$i"
  fi
  mkdir -p "${OUT_DIR}"
  ln -sfn "$(basename "${OUT_DIR}")" "${BASE_OUT_DIR}/latest"
  echo "[INFO] 新建运行目录 ${OUT_DIR} (latest -> $(basename "${OUT_DIR}"))" >&2
fi

RESULT_FILE="${OUT_DIR}/results.jsonl"
META_FILE="${OUT_DIR}/meta.env"

# 保存本次运行的环境参数 (便于复现)
{
  echo "# Recorded parameters"; echo "RUN_TAG=${RUN_TAG}"; echo "APPEND=${APPEND}";
} > "${META_FILE}"

# 可以通过环境变量选择子集: TIERS="BASE M60" MODES="DEF MID" RUNS=3
TIERS=${TIERS:-"BASE L20 M60 H200 H200L"}
# 默认增加 RAW(完全不启用扩展) 作为真实基线；DEF=带扩展的低阈值配置
MODES=${MODES:-"RAW DEF HI MID LOW ADAPT"}
RUNS=${RUNS:-3}              # 每个 (tier,mode) 重复次数
WARMUP=${WARMUP:-1}          # 可选预热轮数 (不记录)
URL=${URL:-"https://127.0.0.1:4433/README.md"}
THREADS=${THREADS:-1}
CONNS=${CONNS:-1}
REQS=${REQS:-200}
DURATION=${DURATION:-15}
PIPE_ID=${PIPE_ID:-501}
SKIP_BASE_SHAPING=${SKIP_BASE_SHAPING:-0} # 1=对 BASE 档位不做 pf/dummynet (免 sudo 基线)
# 额外：可将 min_ack_delay 作为单独实验维度，空则维持原行为。
MIN_ACK_SERIES=${MIN_ACK_SERIES:-""}   # 例如: "4000 8000 12000"
ACK_MAX_CAP_US=${ACK_MAX_CAP_US:-25000} # 安全上限默认提升到 25000us (仍低于 2^14 ms=16384ms≈16384000us 规范上限换算时需注意单位差异)
# TIME_STATS=1 时使用 /usr/bin/time -l 记录资源 (macOS)；若不存在则忽略。
TIME_STATS=${TIME_STATS:-0}

# 策略参数映射: mode -> (ACK_FREQ_THRESHOLD ACK_FREQ_MAX_DELAY_US ACK_FREQ_REORDERING MIN_ACK_DELAY_US IMMEDIATE_ACK_INTERVAL_MS)
# RAW: 不发送 ACK_FREQUENCY 扩展 (保持实现默认 ACK 行为)。
# DEF(重定义): threshold=1, max_ack_delay=25000us (25ms), reordering=1, min_ack_delay=0, immediate=0
#   表示启用 ACK_FREQUENCY 但近似“即时” ACK 支持 (min_ack=0)；用于与自定义档位对比。
# 说明: 若设置 MIN_ACK_SERIES, 会覆盖模式内的 min_ack_delay 形成独立维度。
# 其它模式保持实验用低/中/高稀疏度阶梯。
mode_params() {
  case "$1" in
  RAW)  echo "";;                 # 特殊: 返回空串 -> 不启用扩展
  DEF)  echo "1 25000 1 0 0";;
  HI)   echo "2 10000 1 3000 0";;      # 2 packets 或 3ms 超时触发 ACK, max_ack_delay 10ms
  MID)  echo "4 12000 2 5000 0";;      # 4 packets / 5ms, max_ack_delay 12ms
  LOW)  echo "8 15000 4 7000 0";;      # 8 packets / 7ms, max_ack_delay 15ms
  ADAPT) echo "4 12000 2 5000 0";;     # 初始等同 MID (未来可动态调整)
  # 实验：阈值敏感性（保持其余参数基本一致）
  # 固定: max_ack_delay=10000us, reordering=2, min_ack=3000us
  T2)  echo "2 10000 2 3000 0";;
  T4)  echo "4 10000 2 3000 0";;
  T10) echo "10 10000 2 3000 0";;
  # 阈值固定 2，测试不同 max_ack_delay。统一 min_ack=1000us，reordering=2
  A10) echo "2 10000 2 1000 0";;
  A6)  echo "2 6000  2 1000 0";;
  A4)  echo "2 4000  2 1000 0";;
  A2)  echo "2 2000  2 1000 0";;
  # ACK 粒度对比: 每包 ACK vs 每10包 ACK (保持较小 max_ack_delay 以便阈值生效)
  PK1)  echo "1 4000 1 1000 0";;   # threshold=1 (内部+1编码前), 近似每个 ack-eliciting 包 ACK
  PK10) echo "10 4000 2 1000 0";;  # threshold=10
    *) echo "unknown mode $1" >&2; exit 1;;
  esac
}

# 网络档位 -> (delay loss bw)
# 单向 delay, 往返≈2x; H200* 档位延迟 100ms 单向
tier_params() {
  case "$1" in
    BASE)  echo "0ms 0 unlimited";;
    L20)   echo "10ms 0 unlimited";;
    M60)   echo "30ms 0 200Mbit/s";;
    H200)  echo "100ms 0 100Mbit/s";;
    H200L) echo "100ms 0.001 100Mbit/s";;
    H200LL) echo "100ms 0.01 100Mbit/s";;
  # High RTT + constrained bandwidth variants (low bandwidth, no extra loss):
  # H200B20: 100ms one-way (≈200ms RTT) 20Mbit/s
  # H200B5 : 100ms one-way 5Mbit/s
  # H200B1 : 100ms one-way 1Mbit/s (very tight pipe)
  # H400B5 : 200ms one-way (≈400ms RTT) 5Mbit/s
  H200B20) echo "100ms 0 20Mbit/s";;
  H200B5)  echo "100ms 0 5Mbit/s";;
  H200B1)  echo "100ms 0 1Mbit/s";;
  H400B5)  echo "200ms 0 5Mbit/s";;
    *) echo "unknown tier $1" >&2; exit 1;;
  esac
}

log_json() {
  # key=value ... -> JSON line (简单转义, 不含特殊字符)
  local kv json="{"
  for kv in "$@"; do
    local k=${kv%%=*}; local v=${kv#*=}
    json+="\"$k\":\"$v\","
  done
  json=${json%,}"}"
  echo "$json" >> "$RESULT_FILE"
}

echo "# Writing results to $RESULT_FILE" > /dev/null
if [[ $APPEND -ne 1 ]]; then
  : > "$RESULT_FILE"  # 新运行覆盖该目录内旧文件 (目录新建故不会影响历史)
fi

apply_net() {
  local tier=$1
  read -r delay loss bw < <(tier_params "$tier")
  echo "[NET] tier=$tier delay=$delay loss=$loss bw=$bw" >&2
  sudo "$NET_SH" apply --ports 4433 --delay "$delay" --loss "$loss" ${bw:+--bw "$bw"} --pipe "$PIPE_ID"
}

clear_net() { sudo "$NET_SH" clear || true; }
trap clear_net EXIT

run_one() {
  local tier=$1 mode=$2 idx=$3 min_override=${4:-""}
  local start_ns end_ns
  local ack_threshold ack_max ack_reorder min_ack immediate_int
  local params="$(mode_params "$mode")"
  local have_ext=0
  if [[ -n "$params" ]]; then
    read -r ack_threshold ack_max ack_reorder min_ack immediate_int <<<"$params"
    have_ext=1
  fi

  # 覆盖 min_ack (独立维度)
  if [[ $have_ext -eq 1 && -n "$min_override" ]]; then
    min_ack=$min_override
  fi

  # 钳制 / 自适应校正: 确保 ack_max 不低于 min_ack, 且不超过上限
  if [[ $have_ext -eq 1 ]]; then
    if [[ -n "$ack_max" && -n "$min_ack" && $ack_max -lt $min_ack ]]; then
      echo "[ADJ] mode=$mode rep=$idx raise ack_max_delay_us from $ack_max to min_ack $min_ack" >&2
      ack_max=$min_ack
    fi
    if [[ -n "$ack_max" && $ack_max -gt $ACK_MAX_CAP_US ]]; then
      echo "[CAP] mode=$mode rep=$idx clamp ack_max_delay_us $ack_max -> $ACK_MAX_CAP_US" >&2
      ack_max=$ACK_MAX_CAP_US
    fi
  fi

  local file_suffix=""
  if [[ $have_ext -eq 1 && -n "$min_ack" ]]; then
    file_suffix="_m${min_ack}"
  fi

  echo "[RUN] tier=$tier mode=$mode${file_suffix} rep=$idx" >&2
  START=$(date +%s%N)
  local time_file="$OUT_DIR/${tier}_${mode}${file_suffix}_${idx}.time"
  if [[ $have_ext -eq 1 ]]; then
    if [[ $TIME_STATS -eq 1 && -x /usr/bin/time ]]; then
      /usr/bin/time -l -o "$time_file" \
        env ACK_FREQ_THRESHOLD=$ack_threshold \
        ACK_FREQ_MAX_DELAY_US=$ack_max \
        ACK_FREQ_REORDERING=$ack_reorder \
        MIN_ACK_DELAY_US=$min_ack \
        IMMEDIATE_ACK_INTERVAL_MS=$immediate_int \
        URL=$URL THREADS=$THREADS CONNS=$CONNS REQS=$REQS DURATION=$DURATION \
        bash "$DEMO_SH" >"$OUT_DIR/${tier}_${mode}${file_suffix}_${idx}.demo.log" 2>&1 || true
    else
      ACK_FREQ_THRESHOLD=$ack_threshold \
      ACK_FREQ_MAX_DELAY_US=$ack_max \
      ACK_FREQ_REORDERING=$ack_reorder \
      MIN_ACK_DELAY_US=$min_ack \
      IMMEDIATE_ACK_INTERVAL_MS=$immediate_int \
      URL=$URL THREADS=$THREADS CONNS=$CONNS REQS=$REQS DURATION=$DURATION \
      bash "$DEMO_SH" >"$OUT_DIR/${tier}_${mode}${file_suffix}_${idx}.demo.log" 2>&1 || true
    fi
  else
    if [[ $TIME_STATS -eq 1 && -x /usr/bin/time ]]; then
      /usr/bin/time -l -o "$time_file" \
        env URL=$URL THREADS=$THREADS CONNS=$CONNS REQS=$REQS DURATION=$DURATION \
        bash "$DEMO_SH" >"$OUT_DIR/${tier}_${mode}_${idx}.demo.log" 2>&1 || true
    else
      URL=$URL THREADS=$THREADS CONNS=$CONNS REQS=$REQS DURATION=$DURATION \
      bash "$DEMO_SH" >"$OUT_DIR/${tier}_${mode}_${idx}.demo.log" 2>&1 || true
    fi
  fi
  END=$(date +%s%N)

  local log_file="$OUT_DIR/${tier}_${mode}${file_suffix}_${idx}.demo.log"
  # 预处理：某些日志在固定列宽被硬换行 (例如 "total_r" 换行后续行以 "x_tx=")；
  # 使用 awk 合并以下模式：
  # 1) 以 "ACK_FREQUENCY sent:" 开头 —— 将后续紧接的最多两行若含 x_tx= 或 IMMEDIATE_ACK 拼接。
  # 2) 以 "qlog parsed:" 开头 —— 若下一行含 "interval samples=" 拼接。
  local norm_log="$log_file.norm"
  awk '
   function flush_line(){ if(cur!=""){ print cur; cur="" } }
   BEGIN{cur=""}
   /^ACK_FREQUENCY sent:/ {
     cur=$0; getline nxt;
     if(nxt ~ /x_tx=|IMMEDIATE_ACK sent:/){ cur=cur" "nxt; }
     else { print cur; cur=""; print nxt; next }
     # 尝试再读一行（极端三折行情况）
     getline nxt2;
     if(nxt2 ~ /IMMEDIATE_ACK sent:/ && cur !~ /IMMEDIATE_ACK sent:/){ cur=cur" "nxt2; }
     print cur; cur=""; next
   }
   /^qlog parsed:/ {
     cur=$0; getline nxt;
     if(nxt ~ /interval samples=/){ cur=cur" "nxt; print cur; cur=""; next } else { print cur; cur=""; print nxt; next }
   }
   { print $0 }
  ' "$log_file" > "$norm_log" 2>/dev/null || cp "$log_file" "$norm_log"
  log_file="$norm_log"
  # --- 指标解析扩展 ---
  local req_rate
  req_rate=$(grep -E "req/s" "$log_file" | tail -1 | sed -E 's/.* ([0-9]+\.[0-9]+) req\/s.*/\1/' || true)
  [[ $req_rate =~ ^[0-9]+\.[0-9]+$ ]] || req_rate=NA

  # ACK_FREQUENCY / IMMEDIATE_ACK 行 (更精确来自汇总行)
    local af_line af_sent af_rx af_tx af_total ia_sent
    af_line=$(grep -E "ACK_FREQUENCY sent:" "$log_file" | tail -1 || true)
    if [[ -n "$af_line" ]]; then
      read -r af_sent af_rx af_tx af_total ia_sent < <(
        echo "$af_line" | sed -n 's/.*ACK_FREQUENCY sent: *\([0-9]\+\) *(rx=\([0-9]\+\) tx=\([0-9]\+\) total_rx_tx=\([0-9]\+\)), *IMMEDIATE_ACK sent: *\([0-9]\+\).*/\1 \2 \3 \4 \5/p'
      )
      af_sent=${af_sent:-NA}; af_rx=${af_rx:-NA}; af_tx=${af_tx:-NA}; af_total=${af_total:-NA}; ia_sent=${ia_sent:-NA}
    fi

  # qlog parsed 行 (ACK 框数 + 样本数)
  local qlog_line ack_frames_seen ack_freq_frames_seen ack_interval_samples
  qlog_line=$(grep -E "qlog parsed: ack_frames_seen=" "$log_file" | tail -1 || true)
  if [[ -n "$qlog_line" ]]; then
    ack_frames_seen=$(echo "$qlog_line" | sed -n 's/.*ack_frames_seen=\([0-9]\+\), ack_frequency_frames_seen=.*/\1/p')
    ack_freq_frames_seen=$(echo "$qlog_line" | sed -n 's/.*ack_frequency_frames_seen=\([0-9]\+\) (interval samples=.*/\1/p')
    ack_interval_samples=$(echo "$qlog_line" | sed -n 's/.*interval samples=\([0-9]\+\)).*/\1/p')
  fi

  # ACK 间隔统计
    local ack_interval_line ack_min ack_p50 ack_p90 ack_p99 ack_max ack_mean
    ack_interval_line=$(grep -E "ACK interval us:" "$log_file" | tail -1 || true)
    if [[ -n "$ack_interval_line" ]]; then
      read -r ack_min ack_p50 ack_p90 ack_p99 ack_max ack_mean < <(
        echo "$ack_interval_line" | sed -n 's/.*ACK interval us: *min=\([0-9]\+\) p50=\([0-9]\+\) p90=\([0-9]\+\) p99=\([0-9]\+\) max=\([0-9]\+\) mean=\([0-9\.]*\).*/\1 \2 \3 \4 \5 \6/p'
      )
      ack_min=${ack_min:-NA}; ack_p50=${ack_p50:-NA}; ack_p90=${ack_p90:-NA}; ack_p99=${ack_p99:-NA}; ack_max=${ack_max:-NA}; ack_mean=${ack_mean:-NA}
    fi

  # 包/字节统计
    local pkt_line bytes_line recv_pkts sent_pkts lost_pkts recv_bytes sent_bytes lost_bytes
    recv_pkts=""; sent_pkts=""; lost_pkts=""; recv_bytes=""; sent_bytes=""; lost_bytes=""
    pkt_line=$(grep -E "recv pkts:" "$log_file" | tail -1 || true)
    if [[ -n "$pkt_line" ]]; then
      read -r recv_pkts sent_pkts lost_pkts < <(
        echo "$pkt_line" | sed -n 's/.*recv pkts: *\([0-9]\+\), sent pkts: *\([0-9]\+\), lost pkts: *\([0-9]\+\).*/\1 \2 \3/p'
      )
      recv_pkts=${recv_pkts:-NA}; sent_pkts=${sent_pkts:-NA}; lost_pkts=${lost_pkts:-NA}
    fi
    bytes_line=$(grep -E "recv bytes:" "$log_file" | tail -1 || true)
    if [[ -n "$bytes_line" ]]; then
      read -r recv_bytes sent_bytes lost_bytes < <(
        echo "$bytes_line" | sed -n 's/.*recv bytes: *\([0-9]\+\), sent bytes: *\([0-9]\+\), lost bytes: *\([0-9]\+\).*/\1 \2 \3/p'
      )
      recv_bytes=${recv_bytes:-NA}; sent_bytes=${sent_bytes:-NA}; lost_bytes=${lost_bytes:-NA}
    fi

  # 推导估算: 吞吐 Mbps (根据 sent_bytes, 传输方向可调整) 与 ACK/接收包比
  local duration_s throughput_mbps ack_per_recv_pkt
  duration_s=$(python - <<PY 2>/dev/null || echo 0
import sys
start=${START}
end=${END}
print((end-start)/1e9)
PY
)
  if [[ -n "${sent_bytes}" && -n "${duration_s}" && ${duration_s} != 0 ]]; then
    throughput_mbps=$(python - <<PY 2>/dev/null || echo NA
import math
bytes=${sent_bytes}
dur=${duration_s}
print(f"{(bytes*8/1e6)/dur:.3f}")
PY
)
  else
    throughput_mbps=NA
  fi
  if [[ -n "$af_sent" && -n "$recv_pkts" && "$recv_pkts" != "0" ]]; then
    ack_per_recv_pkt=$(python - <<PY 2>/dev/null || echo NA
af=${af_sent}; rp=${recv_pkts}
print(f"{af/rp:.4f}")
PY
)
  else
    ack_per_recv_pkt=NA
  fi

  # /usr/bin/time 资源 (macOS: 最大常驻集 尾部行为 "maximum resident set size"; user/system time) 简单解析
  local cpu_user cpu_sys max_rss
  if [[ $TIME_STATS -eq 1 && -f "$time_file" ]]; then
    cpu_user=$(grep -i "user" "$time_file" 2>/dev/null | sed -n 's/\t*//p' | awk '{print $1}' | head -1 || true)
    cpu_sys=$(grep -i "system" "$time_file" 2>/dev/null | sed -n 's/\t*//p' | awk '{print $1}' | head -1 || true)
    max_rss=$(grep -i "maximum resident set size" "$time_file" 2>/dev/null | awk '{print $1}' | head -1 || true)
  fi

  log_json tier=$tier mode=$mode rep=$idx have_ext=$have_ext ack_threshold=${ack_threshold:-NA} ack_max_delay_us=${ack_max:-NA} reorder=${ack_reorder:-NA} min_ack=${min_ack:-NA} delay_injected=$(tier_params "$tier" | awk '{print $1}') req_per_s=$req_rate ack_freq_sent=${af_sent:-NA} ack_freq_rx=${af_rx:-NA} ack_freq_tx=${af_tx:-NA} ack_freq_total=${af_total:-NA} immediate_ack_sent=${ia_sent:-NA} ack_frames_seen=${ack_frames_seen:-NA} ack_frequency_frames_seen=${ack_freq_frames_seen:-NA} ack_interval_samples=${ack_interval_samples:-NA} ack_interval_min=${ack_min:-NA} ack_interval_p50=${ack_p50:-NA} ack_interval_p90=${ack_p90:-NA} ack_interval_p99=${ack_p99:-NA} ack_interval_max=${ack_max:-NA} ack_interval_mean=${ack_mean:-NA} recv_pkts=${recv_pkts:-NA} sent_pkts=${sent_pkts:-NA} lost_pkts=${lost_pkts:-NA} recv_bytes=${recv_bytes:-NA} sent_bytes=${sent_bytes:-NA} lost_bytes=${lost_bytes:-NA} throughput_mbps=${throughput_mbps:-NA} ack_per_recv_pkt=${ack_per_recv_pkt:-NA} duration_s=${duration_s:-NA} cpu_user=${cpu_user:-NA} cpu_sys=${cpu_sys:-NA} max_rss=${max_rss:-NA} start_ns=$START end_ns=$END
}

for tier in $TIERS; do
  SHAPED=1
  if [[ "$tier" == "BASE" && $SKIP_BASE_SHAPING -eq 1 ]]; then
    echo "[NET] skip shaping for BASE (SKIP_BASE_SHAPING=1)" >&2
    SHAPED=0
  else
    apply_net "$tier"
  fi
  # 预热
  for ((w=1; w<=WARMUP; w++)); do
    run_one "$tier" "DEF" "warm$w" >/dev/null 2>&1 || true
  done
  for mode in $MODES; do
    if [[ -n "$MIN_ACK_SERIES" && "$mode" != "DEF" ]]; then
      for minv in $MIN_ACK_SERIES; do
        for ((r=1; r<=RUNS; r++)); do
          run_one "$tier" "$mode" "$r" "$minv"
        done
      done
    else
      for ((r=1; r<=RUNS; r++)); do
        run_one "$tier" "$mode" "$r"
      done
    fi
  done
  if [[ $SHAPED -eq 1 ]]; then
    clear_net
  fi
done

echo "# Done. Consolidated JSON lines in $RESULT_FILE" >&2
echo "[INFO] 历史 run 列表: $(ls -1 ${BASE_OUT_DIR} | grep '^run-' | wc -l) 个" >&2
echo "[INFO] 最新符号链接: ${BASE_OUT_DIR}/latest -> $(readlink ${BASE_OUT_DIR}/latest)" >&2
