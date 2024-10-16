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
TEST_CASES="multipath_minrtt,multipath_roundrobin,multipath_redundant"
TEST_PID="$$"
TEST_FILE="10M"
PATH_NUM=4
LOG_LEVEL="debug"
CLI_OPTIONS=""
SRV_OPTIONS=""
EXIT_CODE=0

cleanup() {
    set +e
    pkill -P $TEST_PID
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
    echo -e "Test $algor OK\n"
}

echo "$TEST_CASES" | sed 's/,/\n/g' | while read -r TEST_CASE; do
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
        *)
            echo "[x] Unknown test case $TEST_CASE"
            ;;
    esac
done

