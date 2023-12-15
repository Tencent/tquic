---
title: 开发指南
sidebar_position: 3
---

# 开发指南


## 项目顶级目录结构

TQUIC项目的顶级目录如下:

| 目录 | 说明 |
| --------- | ----------- |
| src/       | TQUIC实现 |
| tools/      | TQUIC示例工具 |
| benches/   | 基准测试 |
| fuzz/      | 模糊测试 |
| interop/   | 互操作性测试 |
| include/   | 自动生成的C/C++头文件 |
| website/   | TQUIC文档网站 |

:::tip
如果对`src/ffi.rs`进行了修改，应该更新头文件 `include/tquic.h`。
头文件可以使用如下命令自动来生成:
```
cbindgen -o include/tquic.h
```
:::


## TQUIC实现目录结构

| 目录或文件 | 说明 |
| -------------- | ----------- |
| src/connection/          | QUIC协议核心实现 |
| src/congestion_control/  | 各种拥塞控制算法实现 |
| src/multipath_scheduler/ | 各种多路径调度算法实现 |
| src/tls/                 | 基于boringssl/rustls的封装 |
| src/h3/                  | HTTP/3协议 |
| src/qlog/                | Qlog |
| src/ffi.rs               | C/C++语言的封装接口 |
| src/build.rs             | boringssl库的编译 |
| src/\*.rs                | TQUIC协议库的基础组件 |



## 单元测试

* 如何查看单元测试的日志输出

```
# 请将`test_name`替换为测试用例的名称
RUST_LOG=trace cargo test test_name -- --nocapture
```

* 如何查看单元测试覆盖率

建议使用I`tarpaulin`生成单元测试覆盖率报告：

```
# 安装tarpaulin
cargo install cargo-tarpaulin

# 在项目基目录执行
cargo tarpaulin --exclude-files "deps/*" -o html
```


## 模糊测试

* 如何安装模糊测试工具[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
```
rustup install nightly
rustup default nightly
cargo install cargo-fuzz
```

* 如果查看已有模糊测试用例
```
cargo fuzz list
```

* 如果执行指定模糊测试用例
```
cargo fuzz run <target_name> -- -max_total_time=30
```

更多用法参见[cargo-fuzz文档](https://rust-fuzz.github.io/book/cargo-fuzz.html)。



## 一致性测试

我们使用[Ivy语言](http://microsoft.github.io/ivy/)定义了[QUIC v1](https://datatracker.ietf.org/doc/html/rfc9000)协议的形式化规范。基于该规范，使用[基于组合规范的测试方法](https://dl.acm.org/doi/10.1145/3341302.3342087)可以测试QUIC实现的一致性。

欲了解更多信息，请参阅[文档](../further_readings/conformance)。


## 互操作性测试

我们使用[quic-interop-runner](https://github.com/marten-seemann/quic-interop-runner/tree/master)执行自动化的、持续的互操作测试。测试结果公布在这个[网页](https://interop.seemann.io/)上。


## Rust文档

* 如何构建[tquic](https://docs.rs/tquic)的文档

```
cargo doc --no-deps
```
