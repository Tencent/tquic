#!/usr/bin/env python3

# This tool is used to analyze TQUIC debug logs and produce a time-offset figure
# for the specified QUIC stream.

import re

from datetime import datetime
import argparse
import matplotlib.pyplot as plt

STREAM_SEND_FORMAT = (
    r"{} sent packet OneRTT.*?STREAM id={} off=(\d+) len=\d+ fin=(?:true|false)"
)
STREAM_RECV_FORMAT = r"{} recv frame STREAM id={} off=(\d+) len=\d+ fin=(?:true|false)"


def parse_log(log_file, cid, stream_id, recv):
    with open(log_file, "r") as file:
        log_data = file.readlines()

    timestamps = []
    offsets = []

    # Refine the regular expression to match timestamps and stream offsets
    timestamp_pattern = re.compile(r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})Z")
    stream_format = STREAM_RECV_FORMAT if recv else STREAM_SEND_FORMAT
    connection_stream_pattern = re.compile(stream_format.format(cid, stream_id))

    for line in log_data:
        timestamp_match = timestamp_pattern.search(line)
        if not timestamp_match:
            continue

        connection_stream_frame_match = connection_stream_pattern.search(line)
        if not connection_stream_frame_match:
            continue

        timestamp_str = timestamp_match.group(1)
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
        current_offset = int(connection_stream_frame_match.group(1))
        timestamps.append(timestamp)
        offsets.append(current_offset)

    return timestamps, offsets


def plot_offsets(timestamps, offsets, connection_trace_id, stream_id):
    # Get connection id and set output file name
    cid = connection_trace_id.split("-")[1]
    output_file_name = "tquic_time_offset_{}_{}.png".format(cid, stream_id)

    plt.figure(figsize=(20, 6))
    plt.plot(timestamps, offsets, marker=".", linewidth=0.5)
    plt.xlabel("Time")
    plt.ylabel("Stream Offset")
    plt.title(f"Stream {stream_id} Offset by Time in Connection {cid}")
    plt.gca().xaxis.set_major_formatter(
        plt.matplotlib.dates.DateFormatter("%H:%M:%S.%f")
    )
    plt.savefig(output_file_name)
    print("Found %d items, figure %s" % (len(timestamps), output_file_name))


if __name__ == "__main__":
    # Set up the command line argument parser
    parser = argparse.ArgumentParser(
        description="Analyze TQUIC logs to get the relationship between stream offset and time."
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
        "--connection_trace_id",
        type=str,
        help="connection trace id, eg. SERVER-c6d45bc005585f42",
        required=True,
    )
    parser.add_argument(
        "-s",
        "--stream_id",
        type=int,
        help="stream id (default 0), eg. 0",
        default=0,
    )
    parser.add_argument(
        "-r",
        "--recv",
        type=bool,
        help="recv side instead of send side (default false)",
        default=False,
    )
    args = parser.parse_args()

    # Calling with command-line arguments
    timestamps, offsets = parse_log(
        args.log_file, args.connection_trace_id, args.stream_id, args.recv
    )
    plot_offsets(timestamps, offsets, args.connection_trace_id, args.stream_id)
