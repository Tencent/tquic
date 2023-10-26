---
title: Example tools
sidebar_position: 2
---

# Example tools

:::tip

The example tools are built by adding an option `--all` to the `cargo build` command. They are generated and saved in the directory `./target/release/`.
:::


## Server

### Run the quic server
```bash
./tquic_server -c cert.crt -k cert.key -l 127.0.0.1:8443
```

The server is configured to listen on the address `127.0.0.1:8443` and act as an HTTP/3 file server.

The test certificate `cert.crt` and private key `cert.key` can be found in the directory `./src/tls/testdata/`. They can also be generated using the following commands:
```
openssl genpkey -algorithm RSA -out cert.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key cert.key -out cert.csr -subj "/C=CN/ST=beijing/L=beijing/O=tquic/CN=example.org"
openssl x509 -req -in cert.csr -signkey cert.key -out cert.crt
```

### More options

You can explore different options by using the `-h` option for help information.
```bash
./tquic_server -h
```

The output is as follows:
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

### Run the quic client

```bash
./tquic_client --connect-to 127.0.0.1:8443 https://example.org
```

### More options

Use the `-h` option for help information.

```bash
./tquic_client -h
```

The output is as follows:

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
