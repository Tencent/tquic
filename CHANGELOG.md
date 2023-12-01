<!--
This changelog should always be read on `master` branch. Its contents on other branches
does not necessarily reflect the changes.
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [v0.3.0] - 2023-12-01

### Added
- Simplify the usage of Endpoint
- Add config API for stateless retry
- Add config API for initial RTT
- Add quic_conn_index() for getting connection index
- tquic_client: create the output directory if it does not exist
- tquic_client: convert unspecified address to localhost address
- tquic_client: prompt help messages for wrong command args -
- tquic_client: print statistics at the end of execution
- Improve unit testing
- Improve static analysis

### Changed
- endpoint: change Endpoint.close() to support forcily close the endpint
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

[v0.3.0]: https://github.com/tencent/tquic/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/tencent/tquic/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/tencent/tquic/releases/tag/v0.1.0
