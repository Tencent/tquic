#!/usr/bin/env python3

# ============================================================================
# TQUIC Performance Benchmark Runner (Python)
# ============================================================================
# This script measures throughput and other performance metrics.
# It now parses ACK counts directly from stdout for improved accuracy.
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
TEST_FILES = ["1M", "10M", "100M", "1000M"]
MIN_ACK_DELAYS = [0, 2000]
LOG_LEVEL = "off"

# ============================================================================
# Helper Functions
# ============================================================================

def parse_size(size_str):
    size_str = size_str.upper()
    if size_str.endswith('K'): return int(size_str[:-1]) * 1024
    elif size_str.endswith('M'): return int(size_str[:-1]) * 1024 * 1024
    elif size_str.endswith('G'): return int(size_str[:-1]) * 1024 * 1024 * 1024
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

def parse_acks_from_stdout(stdout_str):
    """Parses total acks from the tquic_client standard output."""
    try:
        ack_match = re.search(r"total acks: (\d+)", stdout_str)
        if ack_match:
            return int(ack_match.group(1))
    except (ValueError, AttributeError):
        pass
    return 0

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

def run_single_test_iteration(cc_algo):
    iteration_results = []
    test_dir = f"./test-{datetime.now().strftime('%Y%m%d%H%M%S')}-{os.getpid()}"
    os.makedirs(test_dir, exist_ok=True)

    cert_dir = os.path.join(test_dir, "cert")
    data_dir = os.path.join(test_dir, "data")
    dump_dir = os.path.join(test_dir, "dump")
    os.makedirs(dump_dir, exist_ok=True)

    generate_cert(cert_dir)
    for file_size_str in TEST_FILES:
        generate_file(data_dir, file_size_str)

    for file_size_str in TEST_FILES:
        for min_ack_delay in MIN_ACK_DELAYS:
            test_label = f"min_ack_delay={min_ack_delay}us" if min_ack_delay > 0 else "Baseline"
            print(f"\n  Running test: {file_size_str}, {cc_algo}, {test_label}")

            server_cmd = [
                "ip", "netns", "exec", "server_ns", 
                os.path.join(TQUIC_BIN_PATH, "tquic_server"),
                "-l", "10.0.0.2:8443", "--cert", os.path.join(cert_dir, "cert.crt"),
                "--key", os.path.join(cert_dir, "cert.key"), "--root", data_dir,
                "--log-level", LOG_LEVEL, "--congestion-control-algor", cc_algo
            ]
            server_proc = subprocess.Popen(server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(2)

            cpu_log = os.path.join(test_dir, f"cpu_{file_size_str}_{min_ack_delay}.txt")
            time_cmd = ["/usr/bin/time", "-f", '{"user": "%U", "sys": "%S", "cpu_percent": "%P"}', "-o", cpu_log]
            
            client_cmd_base = [
                "ip", "netns", "exec", "client_ns",
                os.path.join(TQUIC_BIN_PATH, "tquic_client"),
                "-c", "10.0.0.2:8443", "--log-level", LOG_LEVEL,
                "--dump-dir", dump_dir, f"https://example.org/{file_size_str}"
            ]
            if min_ack_delay > 0:
                client_cmd_base.extend(["--min-ack-delay", str(min_ack_delay)])

            client_cmd = time_cmd + client_cmd_base

            start_time = time.monotonic()
            client_result = run_command(client_cmd, capture_output=True, text=True)
            elapsed = time.monotonic() - start_time

            server_proc.kill()
            server_proc.wait()

            metrics = {"file_size": file_size_str, "min_ack_delay": min_ack_delay, "cc_algo": cc_algo}
            metrics["transfer_time"] = elapsed

            try:
                with open(cpu_log, 'r') as f:
                    cpu_stats = json.loads(f.read())
                    metrics["user_cpu"] = float(cpu_stats.get("user", 0))
                    metrics["sys_cpu"] = float(cpu_stats.get("sys", 0))
                    metrics["total_cpu"] = metrics["user_cpu"] + metrics["sys_cpu"]
                    metrics["cpu_percent"] = float(cpu_stats.get("cpu_percent", "0%").replace('%', ''))
            except (IOError, json.JSONDecodeError):
                metrics["user_cpu"] = metrics["sys_cpu"] = metrics["total_cpu"] = metrics["cpu_percent"] = 0

            file_size_bytes = parse_size(file_size_str)
            if elapsed > 0:
                metrics["throughput"] = (file_size_bytes * 8) / (elapsed * 1000 * 1000) # Mbps
            else:
                metrics["throughput"] = 0

            if client_result and client_result.stdout:
                metrics["ack_packets"] = parse_acks_from_stdout(client_result.stdout)
            else:
                metrics["ack_packets"] = 0

            iteration_results.append(metrics)
            print(f"  Finished test. Throughput: {metrics['throughput']:.2f} Mbps, ACKs: {metrics['ack_packets']}")

    subprocess.run(["rm", "-rf", test_dir])
    return iteration_results

# ============================================================================
# Main Runner Logic
# ============================================================================

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} [log_file] [cc_algorithm]")
        sys.exit(1)

    log_file = sys.argv[1]
    cc_algo = sys.argv[2]

    print("=" * 50)
    print("TQUIC ACK Frequency Performance Benchmark (Python)")
    print("=" * 50)
    print(f"Configuration:")
    print(f"  - Iterations: {TEST_ITERATIONS}")
    print(f"  - Congestion Control: {cc_algo}")
    print(f"  - Log File: {log_file}")
    print("=" * 50)

    totals = defaultdict(lambda: defaultdict(float))
    counts = defaultdict(int)

    for i in range(TEST_ITERATIONS):
        print(f"\n--- Starting Test Iteration: {i + 1} of {TEST_ITERATIONS} ---")
        results = run_single_test_iteration(cc_algo)
        for r in results:
            key = (r['file_size'], r['min_ack_delay'])
            counts[key] += 1
            for metric, value in r.items():
                if isinstance(value, (int, float)):
                    totals[key][metric] += value
        print(f"--- Finished Test Iteration: {i + 1} ---")

    print("\nCalculating averages and writing results...")
    
    header_format = "%-" + "12s | %-" + "27s | %-" + "15s | %-" + "15s | %-" + "15s | %-" + "15s | %-" + "15s | %-" + "12s | %-" + "12s"
    header = header_format % ("File Size", "Test Case", "Avg Time (s)", "Avg Tput (Mbps)", "Avg CPU (s)",
                              "Avg User (s)", "Avg Sys (s)", "Avg CPU (%)", "Avg ACKs")
    separator = "-" * len(header)

    with open(log_file, 'w') as f:
        f.write(f"ACK Frequency Performance Test Results\n")
        f.write("="+"*"*40+"\n")
        f.write(f"Congestion Control: {cc_algo}\n")
        f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(header + "\n")
        f.write(separator + "\n")

        sorted_keys = sorted(totals.keys(), key=lambda k: (parse_size(k[0]), k[1]))

        for key in sorted_keys:
            file_size, min_ack_delay = key
            count = counts[key]
            avg = {metric: total / count for metric, total in totals[key].items()}

            delay_label = "Baseline (no ACK frequency)" if min_ack_delay == 0 else f"min_ack_delay={min_ack_delay}us"

            row_data = (
                file_size,
                delay_label,
                avg['transfer_time'],
                avg['throughput'],
                avg['total_cpu'],
                avg['user_cpu'],
                avg['sys_cpu'],
                avg['cpu_percent'],
                avg['ack_packets']
            )
            row_format = "%-" + "12s | %-" + "27s | %15.3f | %15.2f | %15.3f | %15.3f | %15.3f | %12.2f | %12.0f"
            f.write(row_format % row_data + "\n")

    print(f"\nBenchmark Complete! Results saved to: {log_file}")

if __name__ == "__main__":
    main()