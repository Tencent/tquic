---
title: 问题定位相关
sidebar_position: 4
---

# 问题定位相关


## 如何分析加密的QUIC流量?

可以使用示例工具的`--keylog-file`选项保存TLS密钥日志，或者在你自己的程序中使用[keylog API](../api_reference/c_quic#connection-logging-and-tracing)来保存TLS密钥日志。
该密钥日志文件可以用来在Wireshark中解密QUIC流量。

:::tip
在wireshake中，依次打开`Edit-> Preferences-> Protocols-> TLS`，然后将`(Pre)-Master-Secret log filename preference`设置为TLS密钥日志文件路径
:::

