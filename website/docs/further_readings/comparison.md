---
title: Comparison
sidebar_position: 1
---

# Comparison to alternatives

The industry currently offers numerous available [QUIC implementations](https://github.com/quicwg/base-drafts/wiki/Implementations). However, we have selected only a few for comparative analysis. The main reasons behind our choice are as follows:

- **Open source project**: This facilitates the establishment of a test environment and also enables further code analysis. For instance, we didn't choose AppleQUIC or F5 QUIC.
- **Written in a system programming language**: Some implementations may not be aimed at high performance and therefore cannot be fairly compared to those based on system programming languages. We didn't choose implementations based on Python/Haskell/Java etc.
- **Widely used**: It is used by well-known open-source projects or large-scale network service providers.

:::tip
The following analysis may not be accurate as each project is currently under active development. The document may be updated or supplemented with new implementations at a later time.
:::


## Basic information

| Category | QUICHE-G | NGINX-QUIC | QUICHE-CF | LSQUIC | TQUIC |
| ------------- | ---------- | ------ | ----- | ---- | ------------- |
| Primary maintainers | Google | NGINX Community | Cloudflare | LiteSpeed | TQUIC Community |
| Code repository | [google/quiche](https://github.com/google/quiche) | [quic](https://github.com/nginx/nginx/tree/master/src/event/quic) | [cloudflare/quiche](https://github.com/cloudflare/quiche) | [lsquic](https://github.com/litespeedtech/lsquic) | [tquic](https://github.com/tencent/tquic) |
| Programming language | C++ | C | RUST | C | RUST |
| Lines of code | About 150,000 | About 20,000 | About 40,000 | About 100,000 | About 50,000 |
| Typical Use Cases | Chromium, Envoy | Nginx | Cloudflare edge network | LiteSpeed WebServer, Web ADC | Tencent Cloud EdgeOne |

The implementations selected for the comparison with TQUIC are shown in the table above. Two of them are used by well-known open source projects([Envoy](https://www.envoyproxy.io/)/[Nginx](https://nginx.org/)) and two are used by popular CDN vendors([Cloudflare](https://www.cloudflare.com/)/[LiteSpeed](https://www.litespeedtech.com/)). They are all written in high-performance systems programming languages.

The NGINX-QUIC codebase, despite having the fewest lines of code, currently lacks comments, unit tests, and certain important features. In contrast, the TQUIC codebase has extensive unit tests and detailed comments that make up approximately half of its total lines of code. This makes it easier for contributors to participate.


## Performance and throughput

| Category | QUICHE-G | NGINX-QUIC | QUICHE-CF | LSQUIC | TQUIC |
| ------------- | ---------- | ------ | ----- | ---- | ---- |
| Performance | Normal | Good | Good | Better | Best |
| Congestion control | CUBIC, BBR, BBRv2, Reno | Reno | CUBIC, BBR | CUBIC, BBR | CUBIC, BBR, BBRv3, COPA |
| Multipath | Not supported | Not supported | Not supported | Not supported | Support Multipath QUIC |


The performance of TQUIC surpasses that of the other implementations significantly. For further details on the benchmark methodology and results, please refer to the [benchmark report](benchmark.md).

Popular congestion control algorithms are supported by all these implementations, except for NGINX-QUIC.

TQUIC is the only one of these implementations that supports multipath QUIC, thereby enhancing both throughput and reliability. Some other libraries, including QUICHE-CF, are currently in development to provide support for multipath QUIC.


## Quality and stability

| Category | QUICHE-G | NGINX-QUIC | QUICHE-CF | LSQUIC | TQUIC |
| ------------- | ---------- | ------ | ----- | ---- | ---- |
| Testing | Extensive unit tests | No unit tests; Few integration tests | Extensive unit tests | Many unit tests, but limited for high-level components | Extensive unit tests |
| Memory safety | Not supported | Not supported | Supported | Not supported | Supported |

Most implementations have extensive unit tests, whereas NGINX-QUIC, as mentioned earlier, lacks them and only a limited number of integration tests for QUIC can be found in a [separate repository](https://hg.nginx.org/nginx-tests/file/tip).

TQUIC and QUICHE-CF are written in a memory-safe language, making them immune to Buffer Overflow vulnerability and other memory-related bugs. In contrast, LSQUIC, a C-based library that was open-sourced in 2017, has been consistently [identifying and resolving memory-related bugs](https://github.com/litespeedtech/lsquic/blob/master/CHANGELOG) throughout the years. This is very common for implementations written in C or C++.


## Usability and observability

| Category | QUICHE-G | NGINX-QUIC | QUICHE-CF | LSQUIC | TQUIC |
| ------------- | ---------- | ------ | ----- | ---- | ---- |
| Library APIs | C++ | C | Rust/C/C++ | C | Rust/C/C++ |
| API documentation | No documentation | No documentation | Detailed for RUST; Limited for C/C++ | Very detailed | Very detailed |
| SSL Keylog | Not supported | Supported | Supported | Supported | Supported |
| QLOG | Not supported | Not supported | Supported | Not supported | Supported |

The APIs for both TQUIC and QUICHE-CF are available in multiple languages, along with detailed API documentation. The absence of comprehensive API documentation for QUICHE-G poses challenges for average users. Currently, NGINX-QUIC is not a standalone QUIC library and only works with Nginx.

The absence of an SSL Keylog or QLOG can make certain implementations (QUICHE-G/NGINX-QUIC/LSQUIC) less convenient for troubleshooting purposes.


:::tip
The document is open-source. Please help improve it by filing issues or pull requests.
:::

