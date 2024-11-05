<!--
This changelog should always be read on `master` branch. Its contents on other branches
does not necessarily reflect the changes.
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [v1.4.0] - 2024-10-28

### Added
- Add `qlog` feature flag to reduce the size of complied library
- Optimize pacing for acknowledgement packets
- Minor tweaks for tquic_time_offset.py

### Fixed
- Fix checking packet header under disable_1rtt_encryption mode
- Fix the length of trancated packet number
- Some fixes for tquic_tools_test.sh


## [v1.3.1] - 2024-10-11

### Added
- Use ohrs to build tquic for HarmaryOS
- Support building for HarmonyOS on arm/x86_64 architecture


## [v1.3.0] - 2024-10-10

### Added
- Support building for HarmonyOS on aarch64 architecture
- Support disable_1rtt_encryption transport parameter
- Support sending 1-RTT packets on the server before handshake completion
- Resolve new issues found by cargo clippy


## [v1.2.0] - 2024-09-26

### Added
- Improve acknowledgement strategy
- Optimize pacing for small packets
- Add quic_tls_config_set_session_timeout() and change default session timeout
- Add config API for copa algorithm
- Add FFI set_anti_amplification_factor
- Add a tool for analyzing TQUIC debug logs and produce a time-offset figure


## [v1.1.0] - 2024-08-20

### Added
- Buffer undecryptable Handshake and OneRtt packets during the handshake phase
- Update some comments about stream

### Fixed
- Fix the closure of the stream that was reset by the peer
- Fix the suboptimal performance in multipath transmission caused by pacing


## [v1.0.0] - 2024-08-01

### Added
- Support building on Windows
- Optimize the initial RTT of the newly validated path
- Add API for deferring idle timeout

### Changed
- Rename PathStats to quic_path_stats_t in FFI
- Change prototype of quic_set_logger in FFI


## [v0.15.0] - 2024-07-18

### Added
- Support building for the `aarch64-apple-ios-sim` target
- Support customized connection id generators
- Add `quic_packet_header_info()` to extract cid-related info from quic packets
- Add `quic_conn_path_stats` to get path level stats
- Add configuration for pacing granularity
- Tweak packet number encoding

### Fixed
- Replace the hashlru crate with the lru crate


## [v0.14.0] - 2024-07-11

### Added
- Update config API for congestion control
- Update cbindgen.toml and the generated header file
- Tweak comments for application protos in FFI

### Changed
- Rename enum members of `quic_multipath_algorithm` in `tquic.h`

### Fixed
- Fix stream operations that should mark conn as tickable
- Fix the issue with sending MAX_DATA frames
- Fix the issue with pacer timer that occasionally leads to a connection timeout error


## [v0.13.0] - 2024-06-25

### Added
- Add pacing to smooth the flow of packets sent onto the network
- Add more C APIs for the quic connection
- Tweak maximum MTU for paths using IPv4-mapped IPv6 addresses

### Removed
- Remove useless sfv flag in ffi

### Fixed
- Update `stream_bidi_new`/`stream_uni_new` to work like `stream_new`


## [v0.12.0] - 2024-05-27
### Added
- Buffer disordered zero rtt packets on the server endpoint
- Add dummy congestion controller for testing and expriments
- Tweak configurations and initialization of flow control
- Improve comments of bbr congestion control algorithm
- Add workflow and plot tools for benchmarking
- tquic_tools: add the `version` option

### Fixed
- Fix dropping datagrams from unknown connections on the client endpoint
- Fix handling restart from idle for bbr/bbr3 algorithms
- tquic_tools: resolve minor issues


## [v0.11.0] - 2024-05-08

### Added
- tquic_tools: group different options by category and prioritize commonly used options
- Add the header file of BoringSSL library in tquic.h
- Resolve new issues found by cargo clippy
- Add integration testing for multipath
- Update run_endpoint.sh to enable keyupdate/chacha20 testcase for server

### Changed
- tquic_tools: rename `max_requests_per_thread` to `total_requests_per_thread`

### Fixed
- Fix RangeSet::filter() used by Redundant multipath scheduler
- Fix injected stream frames for Redundant multipath scheduler


## [v0.10.0] - 2024-04-26

### Added
- Add support for responding to key updates
- Add datagram packetization layer PMTU discovery
- Improve API for stream creation
- Limit configuration value of type varint
- Add pacing_rate to PathStats
- tquic_server: output stats when server connection is closed
- Add workflow and plot tools for fct testing

### Fixed
- Fix the issue where bbr3 cannot exit slow start due to high packet loss rate

### Security
- Limit memory consumption for tracking closed stream ids


## [v0.9.0] - 2024-04-10

### Added
- Improve FFI for quic_tls_config_t
- Update the handling of probe timeout to conform with RFC 9002
- Update limit of the output buffer for Connection::send()
- Add plot tools for goodput and interop testing

### Changed
- Change `quic_config_set_tls_config()` in FFI
- Change `quic_tls_config_select_methods_t` in FFI

### Fixed
- Fix NewToken frame in qlog
- Fix the unit test case `conn_write_qlog` that fails with low probability

### Security
- limit the number of queued RETIRE_CONNECTION_ID frames


## [v0.8.1] - 2024-03-18

### Removed
- Remove the sfv feature flag from h3 (to resolve a build issue at docs.rs)


## [v0.8.0] - 2024-03-15

### Added
- Support anti-amplification limit for server
- Support customized config when initiating a connection
- Add callback based FFI for writing the keylog and qlog
- Support compiling dynamic library for C language
- Update the processing of LossDetection timeout in multipath mode
- Update crate docs about PathStats/TlsConfig/TlsConfigSelector

### Security
- Discard old Path Challenges received if needed


## [v0.7.0] - 2024-02-02

### Added
- Add support for building on FreeBSD
- Add more path level metrics
- Add more quic and recovery events in qlog
- Add tquic_qvis.sh to convert qlog files to be compatible with qvis
- Update MultipathScheduler interface for some advanced schedulers
- Add tquic_tools_test.sh for additional end-to-end testing
- tquic_client: support early data
- tquic_tools: use millisecond precision for log timestamp
- tquic_tools: add `log-file` option to write logs to specified file
- tquic_tools: add `active-cid-limit` option to allow more paths

### Changed
- tquic_tools: change the `qlog-log` option to the `qlog-dir` option
- tquic_tools: change the `dump-path` option to the `dump-dir` option
- tquic_tools: update default pto linear factor
- tquic_client: change the `local_addresses` option to allow the os to choose available ports
- tquic_client: use `local_addresses` option to specify the addresses to bind in both singlepath and multipath mode.

### Fixed
- Fix record separator of qlog in json-seq format


## [v0.6.0] - 2024-01-17

### Added
- Support the latest version of qlog (v0.4)
- Add `cid_len` option to tquic tools
- Ignore undecrypted packets with invalid format

### Changed
- Move website dir to tquic-group/tquic-website repo

### Fixed
- Fix the selected MTU for the sending path
- Fix anti-deadlock PTO during handshake
- Fix the assertion of negotiated parameters in TLS unit tests


## [v0.5.0] - 2024-01-03

### Added
- Add support for building on MacOS
- Add support for stateless reset
- Release tls_conf_selector as soon as the handshake is completed.
- Add linear mode and upper limit for probe timeout
- Add FFI enable_multipath()/set_multipath_algorithm()
- Add RoundRobin multipath scheduler
- Add more units test for multipath transport
- tquic_client: stop trying and exit if it fails to reconnect the server multiple times.
- tquic_client: output the stats first and then exit when it receives an SIGINT signal.

### Changed
- Simplify FFI quic_set_logger() to avoid from return unnecessary errors
- Rename set_multipath() in Config to enable_multipath()
- Rename set_multipath_algor() in Config to set_multipath_algorithm()
- Change default congestion control algorithm to BBR

### Fixed
- Fix stream scheduling for multiple incredmental streams
- Fix reinjection for multipath transport


## [v0.4.0] - 2023-12-18

### Added
- Add config API for initial_congestion_window/min_congestion_window
- Add congestion_control_algor option for tquic_client/tquic_server
- Add initial_congestion_window/min_congestion_window option for tquic_client/tquic_server
- Add more unittest cases for delivery_rate/minmax
- Simplify ffi feature in tls module
- Add typos.toml and fix all typos
- Add a workflow for goodput measurements

### Changed
- Rename tquic_apps to tquic_tools
- Move examples to `tquic-group/tquic-examples-*` repos

### Fixed
- Keep cc unchanged for non-data packets (e.g., Initial and Handshake)
- Update the LICENSE file


## [v0.3.0] - 2023-12-01

### Added
- Simplify the usage of Endpoint
- Add config API for stateless retry
- Add config API for initial RTT
- Add quic_conn_index() for getting connection index
- tquic_client: create the output directory if it does not exist
- tquic_client: convert unspecified address to localhost address
- tquic_client: prompt help messages for wrong command args
- tquic_client: print statistics at the end of execution
- Improve unit testing
- Improve static analysis

### Changed
- endpoint: change Endpoint.close() to support forcily close the endpoint
- endpoint: quic_endpoint_new() no longer takes ownership of the resources provides by the C caller
- tquic_client: change `-p` option to write the response header and body to stdout

### Fixed
- Ignore packets with unknown dcid
- Fix bandwidth over-estimation issue
- Improve interop testing and resolve new found issues


## [v0.2.0] - 2023-11-09

### Added
- Optimize the writing of stream frames
- Improve fuzz testing

### Security
- Fix frame issues found by fuzz testing


## [v0.1.0] - 2023-11-01

### Added

- Support QUIC v1 and HTTP/3 protocols.
- Support congestion control algorithms such as CUBIC, BBR, BBRv3, and COPA.
- Provide experimental support for Multipath Transport, including MinRTT and Redundant algorithms.
- Provide APIs for Rust, C, and C++.
- Provide example clients and servers.


[v1.4.0]: https://github.com/tencent/tquic/compare/v1.3.1...v1.4.0
[v1.3.1]: https://github.com/tencent/tquic/compare/v1.3.0...v1.3.1
[v1.3.0]: https://github.com/tencent/tquic/compare/v1.2.0...v1.3.0
[v1.2.0]: https://github.com/tencent/tquic/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/tencent/tquic/compare/v1.0.0...v1.1.0
[v1.0.0]: https://github.com/tencent/tquic/compare/v0.15.0...v1.0.0
[v0.15.0]: https://github.com/tencent/tquic/compare/v0.14.0...v0.15.0
[v0.14.0]: https://github.com/tencent/tquic/compare/v0.13.0...v0.14.0
[v0.13.0]: https://github.com/tencent/tquic/compare/v0.12.0...v0.13.0
[v0.12.0]: https://github.com/tencent/tquic/compare/v0.11.0...v0.12.0
[v0.11.0]: https://github.com/tencent/tquic/compare/v0.10.0...v0.11.0
[v0.10.0]: https://github.com/tencent/tquic/compare/v0.9.0...v0.10.0
[v0.9.0]: https://github.com/tencent/tquic/compare/v0.8.1...v0.9.0
[v0.8.1]: https://github.com/tencent/tquic/compare/v0.8.0...v0.8.1
[v0.8.0]: https://github.com/tencent/tquic/compare/v0.7.0...v0.8.0
[v0.7.0]: https://github.com/tencent/tquic/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/tencent/tquic/compare/v0.5.0...v0.6.0
[v0.5.0]: https://github.com/tencent/tquic/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/tencent/tquic/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/tencent/tquic/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/tencent/tquic/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/tencent/tquic/releases/tag/v0.1.0
