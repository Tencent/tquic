#!/usr/bin/env python3

# ============================================================================
# Network Latency Test Orchestrator (Python) 
# ============================================================================
# Purpose: Orchestrate comprehensive network latency tests across
#          different network environments, congestion control algorithms,
#          and concurrency levels.
# ============================================================================

import os
import subprocess
import time
from datetime import datetime

# ============================================================================
# Configuration
# ============================================================================

NETWORK_TYPES = ["home", "mobile"]
CC_ALGOS = ["Bbr", "Bbr3", "Cubic", "Copa"]
CONCURRENCY_LEVELS = [10,100,1000,2000,3000,4000,5000]

RESULT_DIR = "result-latency"
INTER_TEST_DELAY = 5
SET_ENV_SCRIPT = "./set_network_env.sh"
BENCHMARK_RUNNER_SCRIPT = "./latency_benchmark.py"


def check_prerequisites():
    """Verify that required scripts exist and are executable."""
    scripts = [SET_ENV_SCRIPT, BENCHMARK_RUNNER_SCRIPT]
    for script in scripts:
        if not os.path.exists(script):
            print(f"ERROR: Required script '{script}' is missing.")
            return False
        if not os.access(script, os.X_OK):
            print(f"WARNING: Script '{script}' is not executable.")
            print(f"  Consider running: chmod +x {script}")
    return True

def main():
    """Main function to orchestrate the test execution."""
    if not check_prerequisites():
        exit(1)

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    os.makedirs(RESULT_DIR, exist_ok=True)

    print("=" * 60)
    print("Network Latency Performance Test Suite")
    print("=" * 60)
    print(f"  - Network Environments: {', '.join(NETWORK_TYPES)}")
    print(f"  - Congestion Control Algorithms: {', '.join(CC_ALGOS)}")
    print(f"  - Concurrency Levels: {', '.join(map(str, CONCURRENCY_LEVELS))}")
    print(f"  - Results Directory: {RESULT_DIR}")
    print("=" * 60)

    for network in NETWORK_TYPES:
        print(f"\n{'=' * 60}")
        print(f"NETWORK ENVIRONMENT: {network}")
        print(f"{ '=' * 60}")
        
        try:
            subprocess.run(["bash", SET_ENV_SCRIPT, network], check=True)
        except subprocess.CalledProcessError:
            print(f"ERROR: Failed to set up {network} environment. Skipping...")
            continue

        print(f"Network environment '{network}' successfully configured.")

        for cc_algo in CC_ALGOS:
            result_file = os.path.join(RESULT_DIR, f"result_{network}_{cc_algo}_{timestamp}.txt")
            print(f"\n  {'=' * 50}")
            print(f"  Congestion Control: {cc_algo} -> Output: {result_file}")
            print(f"  {'=' * 50}")

            # Open file once to write header
            with open(result_file, 'w') as f:
                f.write(f"Latency Test Results for {cc_algo} on {network} network\n")
                f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            for concurrency in CONCURRENCY_LEVELS:
                print(f"\n  {'-' * 48}")
                print(f"  Testing with Concurrency: {concurrency}")
                print(f"  {'-' * 48}")

                try:
                    # Append results to the same file
                    subprocess.run(["python3", BENCHMARK_RUNNER_SCRIPT, result_file, cc_algo, str(concurrency)], check=True)
                    print("\n  ✓ Test completed successfully")
                except subprocess.CalledProcessError:
                    print("\n  ✗ Test failed or completed with errors")

                if concurrency != CONCURRENCY_LEVELS[-1]:
                    time.sleep(INTER_TEST_DELAY)

    print(f"\n{'=' * 60}")
    print("LATENCY TEST SUITE COMPLETED")
    print(f"Results are in: {RESULT_DIR}")
    print(f"{ '=' * 60}")

if __name__ == "__main__":
    main()