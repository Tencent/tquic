#!/usr/bin/env python3

# This tool is used to analyze TQUIC debug logs and produce a time-cwnd figure
# for the specified QUIC connection.

import re

from datetime import datetime
import argparse
import matplotlib.pyplot as plt


def parse_log(log_file, id):
    with open(log_file, "r") as file:
        log_data = file.readlines()

    timestamps = []
    inflights = []
    cwnds = []

    # Refine the regular expression to match timestamps and cwnds
    timestamp_pattern = re.compile(r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z")
    cwnd_format = r"{} [a-zA-Z]* BEGIN_ACK inflight=(\d+) cwnd=(\d+)"
    cwnd_pattern = re.compile(cwnd_format.format(id))

    for line in log_data:
        timestamp_match = timestamp_pattern.search(line)
        if not timestamp_match:
            continue

        cwnd_match = cwnd_pattern.search(line)
        if not cwnd_match:
            continue

        timestamp_str = timestamp_match.group(1)
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
        inflight = int(cwnd_match.group(1))
        cwnd = int(cwnd_match.group(2))
        timestamps.append(timestamp)
        inflights.append(inflight)
        cwnds.append(cwnd)

    return timestamps, inflights, cwnds


def plot_offsets(timestamps, inflights, cwnds, connection_path_id):
    # Set output file name
    ids = connection_path_id.split("-")
    cid = ids[1]
    pid = ids[2]
    output_file_name = "tquic_time_cwnd_{}_{}.png".format(cid, pid)

    plt.figure(figsize=(20, 6))
    plt.plot(timestamps, inflights, label="inflight", linestyle="-", linewidth=0.5)
    plt.plot(timestamps, cwnds, label="cwnd", linestyle="-", linewidth=0.5)
    plt.xlabel("Time")
    plt.ylabel("Cwnd/Inflight")
    plt.title(f"Congestion window by Time in Connection {cid} Path {pid}")
    plt.legend()
    plt.gca().xaxis.set_major_formatter(
        plt.matplotlib.dates.DateFormatter("%H:%M:%S.%f")
    )
    plt.savefig(output_file_name)
    print("Found %d items, figure %s" % (len(timestamps), output_file_name))


if __name__ == "__main__":
    # Set up the command line argument parser
    parser = argparse.ArgumentParser(
        description="Analyze TQUIC logs to get the relationship between cwnd/inflight and time."
    )
    parser.add_argument(
        "-l",
        "--log_file",
        type=str,
        help="path to the TQUIC debug log file",
        required=True,
    )
    parser.add_argument(
        "-c",
        "--connection_path_id",
        type=str,
        help="connection path id, eg. SERVER-c6d45bc005585f42-0",
        required=True,
    )
    args = parser.parse_args()

    # Calling with command-line arguments
    timestamps, inflights, cwnds = parse_log(args.log_file, args.connection_path_id)
    plot_offsets(timestamps, inflights, cwnds, args.connection_path_id)
