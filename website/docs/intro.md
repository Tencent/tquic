---
sidebar_position: 1
---


# Introduction

## What is QUIC?

When [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Historical_origin) was first developed in the 1970s, it's unlikely anyone could have predicted that we would still be relying on it 50 years later. While TCP has undergone numerous changes over the years, many experts believe that it might be nearing the end of the road. As society becomes increasingly dependent on the internet, [TCP is unfortunately not keeping up with the ever-increasing demands](https://dl.acm.org/doi/10.1145/3098822.3098842).

[QUIC](https://datatracker.ietf.org/doc/html/rfc9000) is a new general-purpose, secured, multiplexed transport-layer protocol. It offers several enhancements, aiming to eventually replace TCP, which could enable Internet transport to continue evolving and solve many of the problems plaguing the Internet. With QUIC being chosen as the foundation for [HTTP/3](https://datatracker.ietf.org/doc/html/rfc9114), it is reasonable to expect that the protocol will carry a significantly larger share of Internet traffic.

The following are some of the key features of QUIC:
- Zero RTT Connection establishment
- Multiplexing without head-of-line blocking
- Improved [transmission machinery](https://datatracker.ietf.org/doc/html/rfc9002#section-4)
- Connection migration
- Optional unreliable or partially reliable delivery
- Multipath for better performance and resilience to link failures
- User space implementation that makes development, testing, and iteration cycles faster and easier
- Resilient to protocol ossification


## What is TQUIC?

TQUIC is an implementation of the IETF QUIC protocol. It is a high-performance, lightweight, and cross-platform QUIC library.


## Features and Advantages

* **Rich features**:
TQUIC supports all big features conforming with [QUIC, HTTP/3 RFCs](https://quicwg.org/).

* **High performance**:
TQUIC is designed for high performance and low latency. Relevant details can be found in the [benchmark result](further_readings/benchmark).

* **Pluggable congestion control**:
TQUIC supports various congestion control algorithms, including [CUBIC](https://datatracker.ietf.org/doc/html/rfc8312), [BBR](https://dl.acm.org/doi/pdf/10.1145/3009824), [BBRv3](https://datatracker.ietf.org/meeting/117/materials/slides-117-ccwg-bbrv3-algorithm-bug-fixes-and-public-internet-deployment-00), and [COPA](https://www.usenix.org/conference/nsdi18/presentation/arun).

* **Multipath QUIC**:
TQUIC supports [Multipath](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath) to enable the simultaneous usage of multiple paths for a single connection.

* **Easy to Use**
TQUIC is easy to use. It supports flexible settings and detailed observability.

* **Cross platform**:
TQUIC runs on almost anything to which Rust compiles. It provides [APIs for Rust/C/C++](category/api-reference).

* **Powered by Rust**:
TQUIC is written in a memory safety language and immune to Buffer Overflow vulnerability and other memory-related bugs.

* **High quality**:
Extensive automated testing, including unit testing, fuzz testing, integration testing, performance benchmarking, interoperability testing, and more.

* **Protocol Compliance**:
TQUIC has been [verified by formal specification using the Ivy tool](further_readings/conformance). It has also passed [IETF interoperability tests](https://github.com/marten-seemann/quic-interop-runner).


:::note
Some advanced features will be open sourced in subsequent releases. Please refer to the [Release Notes](https://github.com/tencent/tquic/releases).
:::
