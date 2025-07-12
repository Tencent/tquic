#!/bin/bash

# Copyright (c) 2024 The TQUIC Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This simple script contains additional end-to-end test cases for tquic tools.
# When conditions permit, it's plan to implement all of the following test cases
# in the `github.com/tquic-group/quic-interop-runner` repo.

set -e

BIN_DIR="./"
TEST_DIR="./test-`date +%Y%m%d%H%M%S`"
TEST_CASES="multipath_minrtt,multipath_roundrobin,multipath_redundant,range_request"
TEST_PID="$$"
TEST_FILE="10M"
PATH_NUM=4
LOG_LEVEL="debug"
CLI_OPTIONS=""
SRV_OPTIONS=""
EXIT_CODE=0
server_pid=""

cleanup() {
    set +e
    if [ -n "$server_pid" ]; then
        kill $server_pid 2>/dev/null
    fi
    pkill -P $TEST_PID # Clean up any other stray processes
    echo "exit with" $EXIT_CODE
    exit $EXIT_CODE
}

show_help() {
    echo "Usage: $0 [options]"
    echo "  -b, Set the directory of tquic_client/tquic_server."
    echo "  -w, Set the workring directory for testing."
    echo "  -l, List all supported test cases."
    echo "  -t, Run the specified test cases."
    echo "  -f, File size for test cases, eg. 10M"
    echo "  -p, Path number for test cases, eg. 4"
    echo "  -g, Log level, eg. debug"
    echo "  -c, Extra tquic_client options, eg. ~~cid-len 10"
    echo "  -s, Extra tquic_server options, eg. ~~cid-len 10"
    echo "  -h, Display this help and exit."
}

while getopts ":b:w:t:f:p:g:c:s:lh" opt; do
    case $opt in
        b)
            BIN_DIR="$OPTARG"
            ;;
        w)
            TEST_DIR="$OPTARG"
            ;;
        t)
            TEST_CASES="$OPTARG"
            ;;
        f)
            TEST_FILE="$OPTARG"
            ;;
        p)
            PATH_NUM="$OPTARG"
            ;;
        g)
            LOG_LEVEL="$OPTARG"
            ;;
        c)
            CLI_OPTIONS="${OPTARG//\~/-}"
            ;;
        s)
            SRV_OPTIONS="${OPTARG//\~/-}"
            ;;
        l)
            echo $TEST_CASES
            exit 0
            ;;
        h)
            show_help
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            show_help
            exit 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            exit 1
            ;;
    esac
done

# Ensure that all child processes have exited.
trap 'cleanup' EXIT

if [[ ! -f "$BIN_DIR/tquic_client" || ! -f "$BIN_DIR/tquic_server" ]]; then
    echo "Not found tquic_client/tquic_server. Please specify the directory for them by '-b' option."
    show_help
    exit
fi

CID_LIMIT=$(( $PATH_NUM * 2 ))

generate_cert() {
    local cert_dir="$1/cert"
    mkdir -p $cert_dir
    openssl genpkey -algorithm RSA -out $cert_dir/cert.key -pkeyopt rsa_keygen_bits:2048 -quiet
    openssl req -new -key $cert_dir/cert.key -out $cert_dir/cert.csr -subj "/C=CN/ST=beijing/O=tquic/CN=example.org"
    openssl x509 -req -in $cert_dir/cert.csr -signkey $cert_dir/cert.key -out $cert_dir/cert.crt
}

generate_files() {
    local data_dir="$1/data"
    mkdir -p $data_dir
    dd if=/dev/urandom of=$data_dir/$TEST_FILE bs=$TEST_FILE count=1
}

test_multipath() {
    local test_dir=$1
    local algor=$2
    echo "[-] Running multipath test for $algor"

    # prepare environment
    local cert_dir="$test_dir/cert"
    local data_dir="$test_dir/data"
    local dump_dir="$test_dir/dump"
    local qlog_dir="$test_dir/qlog"

    generate_cert $test_dir
    generate_files $test_dir

    # start tquic server
    RUST_BACKTRACE=1 $BIN_DIR/tquic_server -l 127.0.8.8:8443 --enable-multipath --multipath-algor $algor \
        --cert $cert_dir/cert.crt --key $cert_dir/cert.key --root $data_dir \
        --active-cid-limit $CID_LIMIT --log-file $test_dir/server.log --log-level $LOG_LEVEL \
        $SRV_OPTIONS &
    server_pid=$!

    # start tquic client
    mkdir -p $dump_dir
    local_addresses=`seq -s, -f "127.0.0.%g" 1 $PATH_NUM`
    RUST_BACKTRACE=1 $BIN_DIR/tquic_client -c 127.0.8.8:8443 --enable-multipath --multipath-algor $algor \
        --local-addresses $local_addresses --active-cid-limit $CID_LIMIT \
        --qlog-dir $qlog_dir --log-file $test_dir/client.log --log-level $LOG_LEVEL \
        --dump-dir $dump_dir $CLI_OPTIONS \
        https://example.org/$TEST_FILE

    # check files
    if ! cmp -s $dump_dir/$TEST_FILE $data_dir/$TEST_FILE; then
        echo "Files not same $dump_dir/$TEST_FILE:$data_dir/$TEST_FILE"
        EXIT_CODE=100
        exit $EXIT_CODE
    fi

    # check packets received
    pnum=`grep "recv packet OneRTT" $test_dir/client.log | grep "local=.*" -o | sort | uniq -c | tee /dev/stderr | wc -l`
    if [ $pnum != $PATH_NUM ]; then
        echo "Not all path ($pnum/$PATH_NUM) received packets"
        EXIT_CODE=101
        exit $EXIT_CODE
    fi

    # clean up
    kill $server_pid
    server_pid=""
    echo -e "Test $algor OK\n"
}

run_range_test_case() {
    local test_name=$1
    local range_header=$2
    local expected_status=$3
    local expected_size=$4
    local original_file=$5
    local dump_dir=$6
    local test_dir=$7

    echo "    -- Running test case: $test_name"

    local downloaded_file="$dump_dir/$TEST_FILE"
    rm -f "$downloaded_file" # Clean up previous download

    local client_log="$test_dir/client_${test_name}.log"
    local client_output=$($BIN_DIR/tquic_client -c 127.0.8.8:8443         --log-file $client_log --log-level $LOG_LEVEL         --dump-dir $dump_dir --range="$range_header" --print-res $CLI_OPTIONS         https://example.org/$TEST_FILE 2>&1)

    # Check HTTP status code
    local status_code=$(echo "$client_output" | grep ':status:' | awk '{print $2}')
    if [ "$status_code" != "$expected_status" ]; then
        echo "    [FAIL] $test_name: Incorrect status code."
        echo "           Expected $expected_status, but got $status_code."
        EXIT_CODE=110
        exit $EXIT_CODE
    fi

    # Check file size
    local downloaded_size=0
    if [ -f "$downloaded_file" ]; then
        downloaded_size=$(stat -c%s "$downloaded_file")
    fi
    if [ "$downloaded_size" -ne "$expected_size" ]; then
        echo "    [FAIL] $test_name: Incorrect file size."
        echo "           Expected $expected_size, but got $downloaded_size."
        EXIT_CODE=111
        exit $EXIT_CODE
    fi

    # Check content if the file is not empty
    if [ "$expected_size" -ne 0 ]; then
        local start_byte=$(echo $range_header | cut -d'-' -f1)
        local count_bytes=$expected_size
        # Handle suffix range for dd
        if [[ "$range_header" == -* ]]; then
            local suffix_len=$(echo $range_header | cut -d'-' -f2)
            start_byte=$(($(stat -c%s "$original_file") - $suffix_len))
        fi

        local expected_content_file="$test_dir/expected_content"
        dd if="$original_file" of="$expected_content_file" bs=1 count=$count_bytes skip=$start_byte status=none

        if ! cmp -s "$downloaded_file" "$expected_content_file"; then
            echo "    [FAIL] $test_name: File content mismatch."
            EXIT_CODE=112
            exit $EXIT_CODE
        fi
    fi

    echo "    [OK] $test_name"
}

test_range_request() {
    local test_dir=$1
    echo "[-] Running comprehensive range request tests"

    # prepare environment
    local cert_dir="$test_dir/cert"
    local data_dir="$test_dir/data"
    local dump_dir="$test_dir/dump"
    mkdir -p $dump_dir

    generate_cert $test_dir
    generate_files $test_dir
    local original_file="$data_dir/$TEST_FILE"
    local file_size=$(stat -c%s "$original_file")

    # start tquic server
    RUST_BACKTRACE=1 $BIN_DIR/tquic_server -l 127.0.8.8:8443         --cert $cert_dir/cert.crt --key $cert_dir/cert.key --root $data_dir         --log-file $test_dir/server.log --log-level $LOG_LEVEL         $SRV_OPTIONS &
    server_pid=$!
    sleep 1 # Wait for server to be ready

    # --- Run all test cases ---
    run_range_test_case "middle_segment"      "100-199"         206 100    "$original_file" "$dump_dir" "$test_dir"
    run_range_test_case "from_start"          "0-99"            206 100    "$original_file" "$dump_dir" "$test_dir"
    run_range_test_case "to_end_open"         "$(($file_size-100))-" 206 100    "$original_file" "$dump_dir" "$test_dir"
    run_range_test_case "suffix_range"        "-100"            206 100    "$original_file" "$dump_dir" "$test_dir"
    run_range_test_case "single_byte"         "50-50"           206 1      "$original_file" "$dump_dir" "$test_dir"
    run_range_test_case "entire_file"         "0-$(($file_size-1))" 206 $file_size "$original_file" "$dump_dir" "$test_dir"
    run_range_test_case "start_out_of_bounds" "$file_size-"     416 0      "$original_file" "$dump_dir" "$test_dir"
    run_range_test_case "start_gt_end"        "200-100"         416 0      "$original_file" "$dump_dir" "$test_dir"
    run_range_test_case "multipart_range"     "0-99,200-299"    200 $file_size "$original_file" "$dump_dir" "$test_dir"

    # --- Cleanup ---
    kill $server_pid
    server_pid=""
    echo -e "Test range_request OK\n"
}

for TEST_CASE in ${TEST_CASES//,/ }; do
    case $TEST_CASE in
        multipath_minrtt)
            test_multipath "$TEST_DIR/minrtt" minrtt
            ;;
        multipath_redundant)
            test_multipath "$TEST_DIR/redundant" redundant
            ;;
        multipath_roundrobin)
            test_multipath "$TEST_DIR/roundrobin" roundrobin
            ;;
        range_request)
            test_range_request "$TEST_DIR/range"
            ;;
        *)
            echo "[x] Unknown test case $TEST_CASE"
            ;;
    esac
done

