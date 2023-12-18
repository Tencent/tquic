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

# QUIC docker image for interoperability testing.
# See: https://github.com/marten-seemann/quic-interop-runner

FROM rust:1.70 as build

WORKDIR /build

COPY . ./

RUN apt-get update && apt-get install -y cmake && rm -rf /var/lib/apt/lists/*

RUN cargo build --release --manifest-path tools/Cargo.toml


FROM martenseemann/quic-network-simulator-endpoint:latest as tquic-interop

WORKDIR /tquic

COPY --from=build \
     /build/target/release/tquic_client \
     /build/target/release/tquic_server \
     /build/interop/run_endpoint.sh \
     ./

RUN chmod u+x ./run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
