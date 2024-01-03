<!--
This changelog should always be read on `master` branch. Its contents on other branches
does not necessarily reflect the changes.
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


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
- Simplify FFI quic_set_logger() to avoid from return unnessary errors
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


[v0.5.0]: https://github.com/tencent/tquic/compare/v0.4.0...v0.5.0
[v0.4.0]: https://github.com/tencent/tquic/compare/v0.3.0...v0.4.0
[v0.3.0]: https://github.com/tencent/tquic/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/tencent/tquic/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/tencent/tquic/releases/tag/v0.1.0
