# TQUIC

[![License](https://img.shields.io/badge/license-Apache%202.0-green)](https://github.com/Tencent/tquic/blob/develop/LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tencent/tquic/rust.yml)](https://github.com/Tencent/tquic/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/tencent/tquic/graph/badge.svg)](https://codecov.io/gh/tencent/tquic)
[![docs.rs](https://docs.rs/tquic/badge.svg)](https://docs.rs/tquic)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/8010/badge)](https://www.bestpractices.dev/projects/8010)

[English](README.md) | 中文

TQUIC是IETF QUIC协议的实现。它是一个高性能、轻量级、跨平台的QUIC库。


## 特性及优点

* **高性能**：TQUIC是为高性能和低延迟而设计的。相关细节可以参考[基准测试结果](https://tquic.net/zh/docs/further_readings/benchmark)。

* **可插拔拥塞控制**：TQUIC支持多种拥塞控制算法，包括CUBIC，BBR，BBRv3，COPA。

* **多路径传输**：TQUIC支持多路径，一个连接可同时使用多个路径提高性能及可靠性。

* **易用性**：TQUIC提供易用的接口，支持灵活的配置参数，提供丰富的可观测性。

* **跨平台**：TQUIC可运行在Rust语言支持的各种平台，同时提供了Rust/C/C++语言接口。

* **基于Rust**：TQUIC基于用内存安全语言编写，可避免缓冲区溢出漏洞和其他内存相关错误的影响。

* **高质量**：TQUIC包括充分的自动化测试，包括单元测试、模糊测试、集成测试、性能基准测试、互操作性测试等。

* **协议一致性**：TQUIC已通过基于Ivy的形式化规范验证。同时通过了IETF互操作性测试。

* **丰富的功能**：TQUIC 支持所有QUIC、HTTP/3规范中的重大功能。


## 开始使用
- [编译及运行](https://tquic.net/zh/docs/getting_started/installation)


## 运行测试
- 请参考[编译及运行](https://tquic.net/zh/docs/getting_started/installation)


## 文档

- [英文版](https://tquic.net/docs/intro)
- [中文版](https://tquic.net/zh/docs/intro)


## 参与贡献

- 请首先在[issue列表](http://github.com/tencent/tquic/issues)中创建一个issue
- 如有必要，请联系项目维护者/负责人进行进一步讨论
- 详情请参阅[参与贡献指南](https://tquic.net/zh/docs/category/contributing/)


## 社区交流

- [开源TQUIC用户论坛](https://github.com/tencent/tquic/discussions)
- 开源TQUIC开发者微信群: [发送邮件](mailto:iyangsj@gmail.com)说明您的微信号及贡献(例如PR/Issue)，我们将及时邀请您加入


## 许可

TQUIC基于Apache 2.0许可证，详见[LICENSE](LICENSE)文件说明
