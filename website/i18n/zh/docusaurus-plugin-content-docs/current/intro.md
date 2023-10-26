---
title: 介绍
sidebar_position: 1
---

# 介绍

## 什么是QUIC

[TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Historical_origin)最早设计于20世纪70年代，几乎没有人能想象到50年后我们仍然还在依赖这个协议。虽然TCP多年来经历了无数改进，但许多专家认为TCP可能即将走到尽头。随着社会对互联网的依赖程度越来越高，TCP已经[不能满足日益增长的需求](https://dl.acm.org/doi/10.1145/3098822.3098842)。

[QUIC](https://datatracker.ietf.org/doc/html/rfc9000)是一种新的通用、安全、多路复用的传输层协议。它提供了大量增强功能，旨在最终取代TCP，从而推动互联网传输继续发展并解决困扰互联网的许多问题。随着QUIC被选为[HTTP/3](https://datatracker.ietf.org/doc/html/rfc9114)的底层传输协议，我们有理由期待QUIC协议将占据更大的互联网流量份额。

QUIC的一些关键特性包括：
* 零RTT连接建立 
* 无队首阻塞的多路复用 
* 改进的[传输策略](https://datatracker.ietf.org/doc/html/rfc9002#name-relevant-differences-betwee)
* 连接迁移 
* 可选的不可靠或半可靠的传输
* 多路径，利用多条冗余路径提高性能及可靠性
* 用户态实现，使开发、测试和迭代周期更高效更简单
* 有效避免协议僵化


## 什么是TQUIC

TQUIC是IETF QUIC协议的实现。它是一个高性能、轻量级、跨平台的QUIC库。


## 特性和优势

* **丰富的功能**：TQUIC 支持所有[QUIC、HTTP/3规范](https://quicwg.org/)中的重大功能。

* **高性能**：TQUIC是为高性能和低延迟而设计的。相关细节可以参考[基准测试结果](further_readings/benchmark)。

* **可插拔拥塞控制**：TQUIC支持多种拥塞控制算法，包括[CUBIC](https://datatracker.ietf.org/doc/html/rfc8312)，[BBR](https://dl.acm.org/doi/pdf/10.1145/3009824)，[BBRv3](https://datatracker.ietf.org/meeting/117/materials/slides-117-ccwg-bbrv3-algorithm-bug-fixes-and-public-internet-deployment-00)，[COPA](https://www.usenix.org/conference/nsdi18/presentation/arun)。

* **多路径**：TQUIC支持[多路径](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath)，一个连接可同时使用多个路径提高性能及可靠性。

* **易用性**：TQUIC提供易用的接口，支持灵活的配置参数，提供丰富的可观测性。

* **跨平台**：TQUIC可运行在Rust语言支持的各种平台，同时提供了[Rust/C/C++语言接口](category/api-reference)。

* **基于Rust**：TQUIC基于用内存安全语言编写，可避免缓冲区溢出漏洞和其他内存相关错误的影响。

* **高质量**：TQUIC包括充分的自动化测试，包括单元测试、模糊测试、集成测试、性能基准测试、互操作性测试等。

* **协议一致性**：TQUIC已通过[基于Ivy的形式化规范验证](further_readings/conformance)。同时通过了IETF互操作性测试。

:::note
一些高级特性将在随后版本中逐步开源，详见[版本记录](https://github.com/tencent/tquic/releases)。
:::
