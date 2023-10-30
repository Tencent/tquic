---
slug: TQUIC is open source
title: Announcing TQUIC open source project
authors: [iyangsj]
tags: [tquic, quic, rust, open source]
---


# Introduction

TQUIC is a QUIC protocol implementation written in the Rust language, aiming to create a high-performance, high-throughput, and high-quality transport protocol library with continuous technological influence.

<!--truncate-->

# Why Open source?

QUIC is a new general-purpose, secured, multiplexed transport-layer protocol. It offers several enhancements, aiming to eventually replace TCP, which could enable Internet transport to continue evolving and solve many of the problems plaguing the Internet. 

With QUIC being chosen as the foundation for HTTP/3, it is reasonable to expect that the protocol will carry a significantly larger share of Internet traffic.

Due to QUIC's extensibility, longevity, and innovativeness, we have decided to make our TQUIC protocol library open-source. We aim to leverage this opportunity of  open source for technology exchange with colleagues and the promotion of transport layer development.


# Features and Advantages

The advantages of TQUIC are as follows.	

**High Throughput**: The TQUIC library offers the industry's most comprehensive collection of congestion control algorithms, consistently meeting RFC standards and outperforming similar open source projects by 2%-30% on weak networks and in specific scenarios.

**High performance**： The performance of TQUIC surpasses that of similar open-source projects by 5% in most test scenarios, and by 20% in some scenarios.

**High Quality**: The QUIC protocol stack comprises over 10 core RFC standards or drafts, covering the transport layer, security layer, and application layer. It is considerably more complex compared to TCP. The TQUIC protocol has achieved an impressive unit test coverage of over 95% and has successfully passed interoperability tests with four leading QUIC implementations in the industry. Additionally, a rigorous test method based on formal specifications (SIGCOMM2019 paper) is employed to ensure strict protocol conformance.

**Easy to Use**: TQUIC is easy to use, supporting flexible configuration and detailed observability. It offers APIs for Rust/C/C++, with plans to  expand its support to Kotlin/Swift, etc.

**Powered by Rust**： TQUIC is written in a memory-safe language, making it immune to Buffer Overflow vulnerability and other memory-related bugs.

**Rich Features**： TQUIC supports all big features conforming with QUIC, HTTP/3 RFCs.

The TQUIC project website, available at https://tquic.net/zh/docs/intro, offers a comprehensive introduction to TQUIC.


# Roadmap

* Integrating open source technology ecosystem, expanding TQUIC application scenarios, and further enhancing user experience with TQUIC
* Publishing relevant papers and gradually releasing more advanced TQUIC features and algorithms as open-source
* Tracking the evolution and innovation of the QUIC protocol, while continuously enhancing the core capabilities of TQUIC


# Conclusion

The open source of TQUIC is just the beginning. We look forward to receiving everyone's feedback and encourage participation in the development of transport technology ecology. Interested parties are welcome to reach out and engage with us.

**TQUIC Website**：https://tquic.net

**TQUIC Repository**：https://github.com/tencent/tquic

