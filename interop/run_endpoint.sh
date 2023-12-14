#!/bin/bash

# Copyright (c) 2023 The TQUIC Authors.
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

set -e
set -x

# Set up the routing needed for the simulation.
/setup.sh

case "$TESTCASE" in
handshake|http3|resumption|ipv6|goodput|crosstraffic|transfer|transferloss|transfercorruption|multiplexing|longrtt|chacha20|blackhole|retry|handshakeloss|handshakecorruption|multiconnect)
    ;;
zerortt|chacha20)
    if [ "$ROLE" == "client" ]; then
        exit 127
    fi
    ;;
keyupdate|ecn|amplificationlimit|v2)
    exit 127
    ;;
*)
    exit 127
    ;;
esac

TQUIC_DIR="/tquic"
TQUIC_CLIENT="tquic_client"
TQUIC_SERVER="tquic_server"
ROOT_DIR="/www"
DOWNLOAD_DIR="/downloads"
LOG_DIR="/logs"

CC_ALGOR="CUBIC"
case ${CONGESTION^^} in
BBR)
    CC_ALGOR="BBR"
    ;;
BBR3)
    CC_ALGOR="BBR3"
    ;;
COPA)
    CC_ALGOR="COPA"
    ;;
*)
    ;;
esac

COMMON_ARGS="--keylog-file $SSLKEYLOGFILE --log-level TRACE --idle-timeout 30000 --handshake-timeout 30000 --congestion-control-algor $CC_ALGOR"

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30

    REQS=($REQUESTS)

    CLIENT_ARGS="$COMMON_ARGS --dump-path ${DOWNLOAD_DIR} --max-concurrent-requests ${#REQS[@]}"
    CLIENT_ALPN="--alpn hq-interop"
    case $TESTCASE in
    resumption)
        CLIENT_ARGS="$CLIENT_ARGS --session-file=session.bin"
        ;;
    zerortt)
        CLIENT_ARGS="$CLIENT_ARGS --session-file=session.bin --enable-early-data"
        ;;
    http3)
        CLIENT_ALPN="--alpn h3"
        ;;
    *)
        ;;
    esac
    CLIENT_ARGS="$CLIENT_ARGS $CLIENT_ALPN"

    case $TESTCASE in
    multiconnect|resumption)
        CLIENT_ARGS="$CLIENT_ARGS --initial-rtt 100"
        for REQ in $REQUESTS
        do
            $TQUIC_DIR/$TQUIC_CLIENT $CLIENT_ARGS $REQ >> $LOG_DIR/$ROLE.log 2>&1
        done
        ;;
    zerortt)
        $TQUIC_DIR/$TQUIC_CLIENT $CLIENT_ARGS ${REQS[0]} > $LOG_DIR/$ROLE.log 2>&1
        $TQUIC_DIR/$TQUIC_CLIENT $CLIENT_ARGS ${REQS[@]:1} >> $LOG_DIR/$ROLE.log 2>&1
        ;;
    *)
        $TQUIC_DIR/$TQUIC_CLIENT $CLIENT_ARGS $REQUESTS > $LOG_DIR/$ROLE.log 2>&1
        ;;
    esac
elif [ "$ROLE" == "server" ]; then
    SERVER_ARGS="$COMMON_ARGS -c /certs/cert.pem -k /certs/priv.key --listen [::]:443 --root $ROOT_DIR"
    case $TESTCASE in
    retry)
        SERVER_ARGS="$SERVER_ARGS --enable-retry"
        ;;
    multiconnect)
        SERVER_ARGS="$SERVER_ARGS --initial-rtt 100"
        ;;
    *)
        ;;
    esac
    $TQUIC_DIR/$TQUIC_SERVER $SERVER_ARGS > $LOG_DIR/$ROLE.log 2>&1
fi
