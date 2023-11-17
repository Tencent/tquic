# TQUIC

[![License](https://img.shields.io/badge/license-Apache%202.0-green)](https://github.com/Tencent/tquic/blob/develop/LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tencent/tquic/rust.yml)](https://github.com/Tencent/tquic/actions/workflows/rust.yml)
[![docs.rs](https://docs.rs/tquic/badge.svg)](https://docs.rs/tquic)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8010/badge)](https://www.bestpractices.dev/projects/8010)

English | [中文](README-CN.md)

TQUIC is a high-performance, lightweight, and cross-platform library for the [IETF QUIC](https://datatracker.ietf.org/wg/quic/about/) protocol. 


## Advantages

* **High performance**: TQUIC is designed for high performance and low latency. Relevant details can be found in the [benchmark result](https://tquic.net/docs/further_readings/benchmark).

* **Pluggable congestion control**: TQUIC supports various congestion control algorithms, including CUBIC, BBR, BBRv3, and COPA.

* **Multipath QUIC**: TQUIC supports Multipath to enable the simultaneous usage of multiple paths for a single connection.

* **Easy to Use**: TQUIC is easy to use. It supports flexible settings and detailed observability.

* **Cross platform**: TQUIC runs on almost anything to which Rust compiles. It provides APIs for Rust/C/C++.

* **Powered by Rust**: TQUIC is written in a memory safety language and immune to Buffer Overflow vulnerability and other memory-related bugs.

* **High quality**: Extensive automated testing, including unit testing, fuzz testing, integration testing, performance benchmarking, interoperability testing, and more.

* **Protocol Compliance**: TQUIC has been verified by formal specification using the Ivy tool. It has also passed IETF interoperability tests.

* **Rich features**: TQUIC supports all big features conforming with QUIC, HTTP/3 RFCs.


## Getting Started
- [Build and run](https://tquic.net/docs/getting_started/installation)


## Running the tests
- See [Build and run](https://tquic.net/docs/getting_started/installation)


## Documentation

- [English version](https://tquic.net/docs/intro)
- [Chinese version](https://tquic.net/zh/docs/intro)


## Contributing
- Please create an issue in [issue list](http://github.com/tencent/tquic/issues).
- Contact Committers/Owners for further discussion if needed.
- See the [CONTRIBUTING](https://tquic.net/docs/category/contributing/) file for details.


## Communication

- [TQUIC community on github](https://github.com/tencent/tquic/discussions)
- TQUIC developer group on WeChat: [Send a request mail](mailto:iyangsj@gmail.com) with your WeChat ID and a contribution you've made to TQUIC(such as a PR/Issue). We will invite you right away.


## License

TQUIC is under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
