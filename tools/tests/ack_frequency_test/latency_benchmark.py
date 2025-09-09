#!/usr/bin/env python3

# ============================================================================
# TQUIC Latency Benchmark Runner (Python)
# ============================================================================
# This script is designed to measure and compare request/response latency
# under different concurrency levels. It parses all statistics (latency, ACKs)
# directly from the client's standard output for accuracy.
# ============================================================================

import os
import subprocess
import time
import sys
import json
import re
from collections import defaultdict
from datetime import datetime

# ============================================================================
# Configuration
# ============================================================================

TEST_ITERATIONS = 10
TQUIC_BIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../target/release"))
TEST_FILE_SIZE = "1K"
REQUEST_COUNT = 10000
LOG_LEVEL = "off" 

MIN_ACK_DELAYS = [0, 2000]

# ============================================================================
# Helper Functions
# ============================================================================

def parse_size(size_str):
    size_str = size_str.upper()
    if size_str.endswith('K'): return int(size_str[:-1]) * 1024
    elif size_str.endswith('M'): return int(size_str[:-1]) * 1024 * 1024
    return int(size_str)

def generate_cert(cert_dir):
    os.makedirs(cert_dir, exist_ok=True)
    key_path = os.path.join(cert_dir, "cert.key")
    crt_path = os.path.join(cert_dir, "cert.crt")
    if os.path.exists(crt_path):
        return
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", 
                    "-keyout", key_path, "-out", crt_path, 
                    "-days", "365", "-nodes", 
                    "-subj", "/C=CN/ST=beijing/O=tquic/CN=example.org"], capture_output=True)

def generate_file(data_dir, size_str):
    os.makedirs(data_dir, exist_ok=True)
    file_path = os.path.join(data_dir, size_str)
    if os.path.exists(file_path):
        return
    byte_size = parse_size(size_str)
    with open(file_path, 'wb') as f:
        f.write(os.urandom(byte_size))

def parse_stats_from_stdout(stdout_str):
    """Parses latency and ACK statistics from the tquic_client standard output."""
    metrics = {}
    print(stdout_str)
    try:
        # Latency parsing
        mean_match = re.search(r"mean: (\d+\.\d+)", stdout_str)
        median_match = re.search(r"median: (\d+\.\d+)", stdout_str)
        p90_match = re.search(r"p90: (\d+\.\d+)", stdout_str)
        p99_match = re.search(r"p99: (\d+\.\d+)", stdout_str)
        
        if mean_match: metrics["avg_us"] = float(mean_match.group(1))
        if median_match: metrics["p50_us"] = float(median_match.group(1))
        if p90_match: metrics["p90_us"] = float(p90_match.group(1))
        if p99_match: metrics["p99_us"] = float(p99_match.group(1))

        # ACK packet parsing
        ack_match = re.search(r"total acks: (\d+)", stdout_str)
        if ack_match:
            metrics["ack_packets"] = int(ack_match.group(1))
        else:
            metrics["ack_packets"] = 0 # Default to 0 if not found

        return metrics if "avg_us" in metrics else None
    except Exception as e:
        print(f"  ERROR: Failed to parse stats from stdout: {e}")
        return None

def run_command(command, allowed_exit_codes=None, **kwargs):
    if allowed_exit_codes is None: allowed_exit_codes = {0}
    else: allowed_exit_codes = set(allowed_exit_codes)
    kwargs.pop('check', None)
    try:
        result = subprocess.run(command, **kwargs)
        if result.returncode not in allowed_exit_codes:
            return None
        return result
    except FileNotFoundError:
        return None

# ============================================================================
# Core Test Logic
# ============================================================================

def run_single_test_iteration(cc_algo, concurrency):
    iteration_results = []
    test_dir = f"./test-latency-{datetime.now().strftime('%Y%m%d%H%M%S')}-{os.getpid()}"
    os.makedirs(test_dir, exist_ok=True)

    cert_dir = os.path.join(test_dir, "cert")
    data_dir = os.path.join(test_dir, "data")
    generate_cert(cert_dir)
    generate_file(data_dir, TEST_FILE_SIZE)

    server_cmd = [
        "ip", "netns", "exec", "server_ns", 
        os.path.join(TQUIC_BIN_PATH, "tquic_server"),
        "-l", "10.0.0.2:8443", "--cert", os.path.join(cert_dir, "cert.crt"),
        "--key", os.path.join(cert_dir, "cert.key"), "--root", data_dir,
        "--log-level", LOG_LEVEL, "--congestion-control-algor", cc_algo
    ]
    server_proc = subprocess.Popen(server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)

    for min_ack_delay in MIN_ACK_DELAYS:
        test_label = f"min_ack_delay={min_ack_delay}us" if min_ack_delay > 0 else "Baseline"
        print(f"  Running test: {REQUEST_COUNT} requests for {TEST_FILE_SIZE}, {cc_algo}, {test_label}")

        cpu_log = os.path.join(test_dir, f"cpu_{min_ack_delay}.txt")
        time_cmd = ["/usr/bin/time", "-f", '{"user": "%U", "sys": "%S", "cpu_percent": "%P"}', "-o", cpu_log]

        client_cmd_base = [
            "ip", "netns", "exec", "client_ns",
            os.path.join(TQUIC_BIN_PATH, "tquic_client"),
            "-c", "10.0.0.2:8443", "--log-level", LOG_LEVEL,
            "--total-requests-per-thread", str(REQUEST_COUNT),
            "--max-requests-per-conn", "0", "--max-concurrent-requests", str(concurrency),
            f"https://example.org/{TEST_FILE_SIZE}"
        ]
        if min_ack_delay > 0:
            client_cmd_base.extend(["--min-ack-delay", str(min_ack_delay)])
        
        client_result = run_command(time_cmd + client_cmd_base, capture_output=True, text=True)

        metrics = {}
        if client_result and client_result.stdout:
            parsed_metrics = parse_stats_from_stdout(client_result.stdout)
            if parsed_metrics:
                metrics.update(parsed_metrics)

        try:
            with open(cpu_log, 'r') as f:
                cpu_stats = json.loads(f.read())
                metrics["cpu_percent"] = float(cpu_stats.get("cpu_percent", "0%").replace('%', ''))
        except (IOError, json.JSONDecodeError): 
            metrics["cpu_percent"] = 0
        
        if metrics.get("avg_us") is not None:
            metrics['min_ack_delay'] = min_ack_delay
            print(f"  Finished test. Avg Latency: {metrics.get('avg_us', 0):.2f} us, ACKs: {metrics.get('ack_packets', 0)}")
            iteration_results.append(metrics)
        else:
            print("  Finished test but could not retrieve latency metrics.")

    server_proc.kill()
    server_proc.wait()
    subprocess.run(["rm", "-rf", test_dir])
    return iteration_results

# ============================================================================
# Main Runner Logic
# ============================================================================

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} [log_file] [cc_algorithm] [concurrency]")
        sys.exit(1)

    log_file = sys.argv[1]
    cc_algo = sys.argv[2]
    concurrency = sys.argv[3]

    totals = defaultdict(lambda: defaultdict(float))
    counts = defaultdict(int)

    for i in range(TEST_ITERATIONS):
        print(f"..Iteration: {i + 1} of {TEST_ITERATIONS}")
        results = run_single_test_iteration(cc_algo, concurrency)
        for r in results:
            key = r['min_ack_delay']
            counts[key] += 1
            for metric, value in r.items():
                if isinstance(value, (int, float)):
                    totals[key][metric] += value

    header_format = "% -26s | %-18s | %-15s | %-15s | %-15s | %-15s | %-12s"
    header = header_format % ("Test Case", "Avg Latency (us)", "p50 (us)", "p90 (us)", "p99 (us)", "Avg CPU (%)", "Avg ACKs")
    separator = "-" * len(header)

    with open(log_file, 'a') as f:
        f.write(f"\n--- Results for Concurrency: {concurrency} ---\n")
        f.write(separator + "\n")
        f.write(header + "\n")
        f.write(separator + "\n")

        for key in sorted(totals.keys()):
            count = counts[key]
            if count == 0: continue
            avg = {metric: total / count for metric, total in totals[key].items()}
            
            label = f"Baseline (ACK Freq Off)" if key == 0 else f"min_ack_delay={key}us"
            
            row_data = (
                label,
                avg.get('avg_us', 0),
                avg.get('p50_us', 0),
                avg.get('p90_us', 0),
                avg.get('p99_us', 0),
                avg.get('cpu_percent', 0),
                avg.get('ack_packets', 0)
            )
            row_format = "% -26s | %18.2f | %15.2f | %15.2f | %15.2f | %15.2f | %12.0f"
            f.write(row_format % row_data + "\n")
        f.write(separator + "\n")

if __name__ == "__main__":
    main()
