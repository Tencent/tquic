---
title: 类似项目比较
sidebar_position: 1
---

# 类似项目比较

业界目前包括很多的[QUIC实现](https://github.com/quicwg/base-drafts/wiki/Implementations)。但是，我们只选取了其中部分进行比较。我们选择的依据主要如下:

- **开源项目**：这有助于搭建测试环境以及进一步的代码分析。例如，我们没有选择AppleQUIC或F5 QUIC。
- **基于系统编程语言**：有些实现的定位可能不是高性能，因此与基于系统编程语言的实现相比并不公平。我们没有选择基于Python/Haskell/Java等语言的实现。
- **广泛使用**：项目被知名开源项目使用，或者被大规模网络服务提供商使用。

:::tip
由于各项目目前正在活跃开发中，下文分析可能过期不再准确。本文可能在后续进行更新或补充新的实现进行对比。
:::


## 基本信息

| 类别 | QUICHE-G | NGINX-QUIC | QUICHE-CF | LSQUIC | TQUIC |
| ------------- | ---------- | ------ | ----- | ---- | ------------- |
| 主要维护者 | Google | NGINX | Cloudflare | LiteSpeed | TQUIC社区 |
| 代码库 | [google/quiche](https://github.com/google/quiche) | [quic](https://github.com/nginx/nginx/tree/master/src/event/quic) | [cloudflare/quiche](https://github.com/cloudflare/quiche) | [lsquic](https://github.com/litespeedtech/lsquic) | [tquic](https://github.com/tencent/tquic) |
| 编程语言 | C++ | C | RUST | C | RUST |
| 代码行数 | 约15万 | 约2万 | 约4万 | 约10万 | 约5万 |
| 典型应用案例 | Chromium、Envoy | Nginx | Cloudflare edge network | LiteSpeed WebServer/Web ADC | Tencent Cloud EdgeOne |

我们选择的与TQUIC进行比较的实现如上表所示。其中，两个实现被知名的开源项目([Envoy](https://www.envoyproxy.io/)/[Nginx](https://nginx.org/))使用，另外两个实现被流行的CDN厂商([Cloudflare](https://www.cloudflare.com/)/[LiteSpeed](https://www.litespeedtech.com/))使用。它们都是采用高性能的系统编程语言开发。

NGINX-QUIC代码库，尽管代码行数最少，但目前缺乏注释、单元测试和某些重要功能。相比之下，TQUIC代码库具有完备的单元测试和详细的注释，约占代码总行数的一半。这对开源贡献者更友好，使得他们容易参与项目。


## 性能和吞吐

| 类别 | QUICHE-G | NGINX-QUIC | QUICHE-CF | LSQUIC | TQUIC |
| ------------- | ---------- | ------ | ----- | ---- | ---- |
| 性能 | 一般 | 好 | 好 | 较好 | 最好 |
| 拥塞控制算法 | CUBIC/BBR/BBRv2/Reno | Reno | CUBIC/BBR | CUBIC/BBR | CUBIC/BBR/BBRv3/COPA |
| 多路径传输 | 不支持 | 不支持 | 不支持 | 不支持 | 支持 |


TQUIC的性能明显优于其他实现。有关基准测试方法和测试结果的更多细节，请参阅[基准测试报告](benchmark.md)。

除了NGINX-QUIC，所有的实现都支持主流的拥塞控制算法。

TQUIC是这些实现中唯一一个支持多路径QUIC的实现，从而进一步提高吞吐量和可靠性。其他一些实现，例如 QUICHE-CF，目前正在开发以支持多路径 QUIC。


## 质量和稳定性

| 类别 | QUICHE-G | NGINX-QUIC | QUICHE-CF | LSQUIC | TQUIC |
| ------------- | ---------- | ------ | ----- | ---- | ---- |
| 测试 | 丰富完备的单元测试 | 没有单元测试；少量集成测试 | 丰富完备的单元测试 | 有很多的单元测试，单高层级组件的单元测试很少 | 丰富完备的单元测试 |
| 内存安全 | 不支持 | 不支持 | 支持 | 不支持 | 支持 |

大多数实现都有丰富的单元测试，而NGINX-QUIC，如前所述缺乏单元测试，只在[单独代码库](https://hg.nginx.org/nginx-tests/file/tip)中包含少量QUIC集成测试。

TQUIC和QUICHE-CF是基于内存安全语言编写的，不受缓冲区溢出漏洞和其他与内存相关的bug影响。相比之下，例如LSQUIC，一个早在2017年开源的基于C语言的库，多年来仍一直[发现和解决内存相关的bug](https://github.com/litespeedtech/lsquic/blob/master/CHANGELOG)。对于C或C++语言的实现，这其实是很常见的。


## 易用性和可观测性

| 类别 | QUICHE-G | NGINX-QUIC | QUICHE-CF | LSQUIC | TQUIC |
| ------------- | ---------- | ------ | ----- | ---- | ---- |
| 库接口 | C++ | C | Rust/C/C++ | C | Rust/C/C++ |
| 接口文档 | 没有文档 | 没有文档 | RUST文档非常详细；C/C++文档比较有限 | 非常详细 | 非常详细 |
| SSL Keylog | 不支持 | 支持 | 支持 | 支持 | 支持 |
| QLOG | 不支持 | 不支持 | 支持 | 不支持 | 支持 |

TQUIC和QUICHE-CF均提供多语言的API以及详细的API文档。QUICHE-G缺乏详细API文档，这对普通用户使用它可能会是个挑战。NGINX-QUIC目前并不是一个独立的QUIC协议库，只适用于Nginx。

一些实现(QUICHE-G/NGINX-QUIC/LSQUIC)缺失SSL Keylog或QLOG，会给故障诊断带来不变。


:::tip
这份文档是开源的。你可以通过提交Issue或Pull request来一起改进它。
:::

