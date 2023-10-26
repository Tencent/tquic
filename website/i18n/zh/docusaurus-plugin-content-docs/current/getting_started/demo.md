---
title: 示例工具
sidebar_position: 2
---

# 示例工具

:::tip
请在`cargo build`命令后添加`--all`参数来编译示例工具，编译的示例工具位于目录`./target/release/`。
:::


## Server

### 运行quic server
```bash
./tquic_server -c cert.crt -k cert.key -l 127.0.0.1:8443
```

服务端监听地址是`127.0.0.1:8443`，作为HTTP/3文件服务器。

测试证书`cert.crt`和私钥`cert.key`可以在目录`./src/tls/testdata/`中找到。也可以直接使用如下命令生成:
```
openssl genpkey -algorithm RSA -out cert.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key cert.key -out cert.csr -subj "/C=CN/ST=beijing/L=beijing/O=tquic/CN=example.org"
openssl x509 -req -in cert.csr -signkey cert.key -out cert.crt
```

### 更多选项

你可以尝试不同的选项，使用`-h`参数查看帮助信息。

```bash
./tquic_server -h
```

输出信息如下:

```
Usage: tquic_server [OPTIONS]

Options:
  -c, --cert <FILE>              TLS certificate in PEM format [default: ./cert.crt]
  -k, --key <FILE>               TLS private key in PEM format [default: ./cert.key]
      --log-level <LOG_LEVEL>    Log level, support OFF/ERROR/WARN/INFO/DEBUG/TRACE [default: TRACE]
  -l, --listen <ADDR>            Address to listen [default: 0.0.0.0:4433]
      --root <DIR>               Document root directory [default: ./]
      --index <FILE>             Index file name [default: index.html]
      --ticket-key <STR>         Session ticket key
      --address-token-key <STR>  Key for generating address token
      --handshake-only           Handshake only
      --handshake-timeout <MS>   Handshake timeout in microseconds [default: 5000]
      --keylog-file <FILE>       Save TLS key log into the given file
  -h, --help                     Print help
```


## Client

### 运行quic client

```bash
./tquic_client --connect-to 127.0.0.1:8443 https://example.org
```

### 更多选项

可以使用`-h`选项查看帮助信息:

```bash
./tquic_client -h
```

输出信息如下:

```
Usage: tquic_client [OPTIONS] [URLS]...

Arguments:
  [URLS]...  Request URLs. The host of the first one is used as SNI in Client Hello

Options:
      --log-level <LOG_LEVEL>   Log level, support OFF/ERROR/WARN/INFO/DEBUG/TRACE [default: TRACE]
      --connect-to <ADDR>       Override server's address
      --alpn <STR>              ALPN, support "http/0.9", "hq-interop" and "h3", separated by "," [default: h3]
      --dump-path <DIR>         Dump response body into the given directory
      --session-file <FILE>     File used for session resumption
      --enable-early-data       Enable early data
      --handshake-only          Handshake only
      --handshake-timeout <MS>  Handshake timeout in microseconds [default: 5000]
      --keylog-file <FILE>      Save TLS key log into the given file
  -h, --help                    Print help
```
