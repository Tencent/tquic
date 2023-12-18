---
title: 使用Rust语言接口
sidebar_position: 2
---

# 使用Rust语言接口

本文介绍应用程序如何使用RUST语言的TQUIC接口。

:::tip
本文的完整示例代码可在GitHub [TQUIC RUST示例](https://github.com/tquic-group/tquic-example-rust)代码库找到：
* [simple_client.rs](https://github.com/tquic-group/tquic-example-rust/blob/main/src/bin/simple_client.rs)
* [simple_server.rs](https://github.com/tquic-group/tquic-example-rust/blob/main/src/bin/simple_server.rs)
:::


## 创建端点

Endpoint用于管理QUIC连接、处理入报文和调度发送出报文。使用Endpoint的`new`方法来创建Endpoint实例。`new`方法的各个参数详见下文说明。

```rust
pub fn new(
    config: Box<crate::Config>,
    is_server: bool,
    handler: Box<dyn TransportHandler>,
    sender: Rc<dyn PacketSendHandler>,
) -> Self
```

:::note
需要注意的是，TQUIC采用不同的方法来接收和发送报文，它并不依赖于套接字。相反，TQUIC通过用户提供的回调来实现。此外，TQUIC没有强加任何特定的事件循环要求。它提供了帮助用户调度事件的函数。TQUIC的灵活性使得易于在各种系统中的定制和集成。
:::


### 端点的配置

`Config`维护了各种连接参数的配置。使用Config的`new`方法创建默认配置，并可以使用各类设置方法来进一步定制配置。

```rust
// 创建默认配置
let mut config = Config::new()?;

// 设置连接闲置超时
config.set_max_idle_timeout(30000);

// 设置应用协议
let mut tls_config = TlsConfig::new()?;
tls_config.set_application_protos(vec![b"h3".to_vec()]);
config.set_tls_config(tls_config);
```
更多配置项说明请参考[Config文档](https://docs.rs/tquic/latest/tquic/struct.Config.html)。


### 端点工作模式

Endpoint区分客户端/服务端模式，可以通过`is_server`参数来指定角色。

如果应用程序同时需要QUIC客户端和服务端功能，建议实例化两个单独的端点。


### 传输回调函数

Endpoint通过调用`TransportHandler`中的回调函数，通知应用层处理相关的QUIC连接/流事件。

```
pub trait TransportHandler {
    // 在新连接创建时调用。该回调函数在端点中连接对象创建后、握手完成之前调用。
    // 客户端可以在连接上发送0RTT数据。
    fn on_conn_created(&mut self, conn: &mut Connection);

    // 在连接握手完成时调用
    fn on_conn_established(&mut self, conn: &mut Connection);

    // 在连接关闭时调用。此回调函数返回后，连接将不再可访问。此时可以清理连接上下文。
    fn on_conn_closed(&mut self, conn: &mut Connection);

    // 在流创建时调用
    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64);

    // 在流可读时调用。当流上有数据需要读取或有错误发送时，会调用此回调函数。
    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64);

    // 在流可写时调用
    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64);

    // 当流关闭时调用。流在此回调函数返回后将不再可访问。在此函数中可以清理流的上下文。
    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64);

    // 当客户端接收到NEW_TOKEN帧时调用
    fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>);
}
```


### 报文发送回调函数

Endpoint通过`PacketSendHandler`来完成报文的发送。`PacketSendHandler`中包含了回调函数`on_packets_send`，用于发送指定的多个UDP报文到网络中。

```
pub trait PacketSendHandler {
    // 批量发送报文
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> Result<usize>;
}
```
你在稍后可以看到示例的实现。



## 接收报文

应用程序接收的UDP报文，通过Endpoint的`recv`方法递交给Endpoint进行处理，示例如下：

```rust
// 读取UDP数据报
let (len, remote) = match socket.recv_from(&mut recv_buf) {
    Ok(v) => v,
    Err(e) => {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            break;
        }
        // 处理错误
    }
};

// 构造报文及其元信息
let pkt_buf = &mut recv_buf[..len];
let pkt_info = PacketInfo {
    src: remote, // 报文来源地址
    dst: socket.local_addr()?, // 报文目的地址
    time: Instant::now(), // 报文接收时间
};

// 递交至Endpoint处理
match self.endpoint.recv(pkt_buf, &pkt_info) {
    Ok(_) => {}
    Err(e) => {
        // 错误处理
    }
};
```


## 发送报文
`on_packets_send`负责将报文批量发送到网络中。`on_packet_send`应返回成功发送的报文数。如果存在错误未成功发送的报文，Endpoint后续会重试发送失败的报文。

```rust
fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
    let mut count = 0;

    for (pkt, info) in pkts {
        if let Err(e) = self.socket.send_to(pkt, info.dst) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(count);
            }
            // 错误处理
        }
        count += 1;
    }
    Ok(count)
}
```
:::tip
这个简单的示例采用了recv_from/send_to来逐一接收/发送报文。建议应用程序采用更高效的机制来批量接收/发送报文。
:::


## 处理连接
在以下情况，端点需要调用`process_connections`批量对连接进行后置处理：

- **处理接收的报文**：通过Endpoint的`recv`方法处理了入报文
- **处理超时事件**：通过Endpoint的`on_timeout`方法处理了超时事件
- **发起客户端连接**：客户端通过Endpoint的`connect`方法发起连接

如下示例代码采用[mio Poll](https://docs.rs/mio/latest/mio/struct.Poll.html)作为事件处理框架：

```rust
// 客户端向发送端发起连接（仅限客户端）
endpoint.connect(local, remote, server_name, session, token)?;

// 执行事件循环
let mut events = mio::Events::with_capacity(1024);
loop {
    endpoint.process_connections()?;

    // 获取最早超时时间
    let timeout = endpoint.timeout();

    // 等待超时或IO事件发生
    poll.poll(&mut events, timeout)?;

    // 处理超时事件
    if events.is_empty() {
        endpoint.on_timeout(Instant::now());
        continue;
    }

    // 处理IO事件
    for event in events.iter() {
        if event.is_readable() {
            process_read_event()?;
        }
    }
}
```


## 发起客户端连接

客户端使用Endpoint的`connect`方法创建到服务器的连接。

```
pub fn connect(
    &mut self,
    local: SocketAddr,
    remote: SocketAddr,
    server_name: Option<&str>,
    session: Option<&[u8]>,
    token: Option<&[u8]>
) -> Result<u64>
```

为了最小化建立新连接所需的时间，客户端可以提供`session`/`token`参数来创建0RTT连接。关于如何获取`session`/`token`，请参阅[“0RTT Connection”章节](#0rtt建立连接)。 
 
在服务器端，当连接创建时，Endpoint调用`on_conn_created`方法来通知应用程序进行处理。


## 流的使用

### 流创建

QUIC协议允许客户端或服务端创建流。应用程序使用Connection的`stream_new`方法创建流。

```
pub fn stream_new(
    &mut self,
    stream_id: u64,
    urgency: u8,
    incremental: bool
) -> Result<()>
```

其对端在流创建时，Endpoint会调用`on_stream_created`回调函数通知其进行处理。


### 流数据写入

当流可写时，Endpoint会调用`on_stream_writable`通知应用程序进行处理。应用程序可以通过Connection的`stream_write`方法发送数据。

```
pub fn stream_write(
    &mut self,
    stream_id: u64,
    buf: Bytes,
    fin: bool
) -> Result<usize>

```

如果`stream_write`返回`Error::Done`错误，说明由于流量控制限制无法写入更多的数据。应用程序可以在下次流可写时, 继续发送数据。


### 流数据读取

当流可读或发送错误时，Endpoint会调用`on_stream_readable`通知应用程序进行处理。应用程序可以通过Connection的`stream_read`方法读取数据或获取错误信息。
```
pub fn stream_read(
    &mut self,
    stream_id: u64,
    out: &mut [u8]
) -> Result<(usize, bool)>
```

`stream_read`返回已读取字节数及流是否结束标志。如果`stream_read`返回`Error::Done`错误，说明当前已无可读取数据。应用程序可以在下次流可读时, 继续读取数据。

更多流相关的操作接口详见[TQUIC接口文档](https://docs.rs/tquic/latest/tquic/struct.Connection.html)。


## 0RTT建立连接

为了减少建立新连接所需的时间，客户端可以缓存此前到服务端的连接的某些参数，并用于后续与服务器建立0-RTT连接。客户端可以立即发送数据，而无需等待握手完成。

具体来说，客户端需要保持此前访问连接的会话状态信息及地址令牌信息。并在新建连接时提供这些信息。示例如下：

```rust
fn on_conn_closed(&mut self, conn: &mut Connection) {
    if let Some(session_file) = &self.session_file {
        // 获取会话信息并保存，包含了TLS会话信息及QUIC传输参数信息
        if let Some(session) = conn.session() {
            std::fs::write(session_file, session).ok();
        }
    }
}


fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>);
    if let Some(token_file) = &self.token_file {
        // 保存地址令牌信息
        std::fs::write(token_file, &token).ok()
    }
}
```


```rust
// Client try to create a 0RTT connection.
let c = endpoint.connect(self, local, remote, server_name, session, token)?;
```



## 多证书支持

TQUIC支持根据SNI选择不同的`TLSConfig`，应用程序可以实现`TlsConfigSelector`特征来选择自定义的证书：

```rust
pub trait TlsConfigSelector: Send + Sync {
    // 获取默认TLS配置
    fn get_default(&self) -> Option<&TlsConfig>;

    // 根据SNI选择TLS配置
    fn select(&self, server_name: &str) -> Option<&TlsConfig>;
}
```
然后，通过Config的`set_tls_config_selector`方法来设置自定义TLSConfig选择器。


## 报文解密分析

TQUIC支持以[NSS key log](https://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format)格式导出TLS密钥，以便[Wireshark](https://www.wireshark.org/)等工具对QUIC报文解密及分析。

可以通过Connection的`set_keylog`方法来指定密钥日志文件的输出，示例如下：

```rust
fn on_conn_created(&mut self, conn: &mut Connection) {
    // 设置密钥日志
    if let Some(keylog_file) = &self.keylog_file {
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_file)
        {
            conn.set_keylog(Box::new(file));
        }
    }
}
```

