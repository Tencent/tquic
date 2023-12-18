---
title: Using the Rust API
sidebar_position: 1
---

# Using the RUST API

This tutorial describes how to use the TQUIC RUST API.

:::tip
The complete example code for this article can be found in the [TQUIC RUST example](https://github.com/tquic-group/tquic-example-rust) repository on GitHub:
* [simple_client.rs](https://github.com/tquic-group/tquic-example-rust/blob/main/src/bin/simple_client.rs)
* [simple_server.rs](https://github.com/tquic-group/tquic-example-rust/blob/main/src/bin/simple_server.rs)
:::


## Endpoint Instantiation

The Endpoint is responsible for managing connections, processing incoming packets, and scheduling outgoing packets.
To create an `Endpoint` instance, simply use the `new` method provided by the `Endpoint` struct. Further explanation of the parameters for this method can be found below.

```rust
pub fn new(
    config: Box<crate::Config>,
    is_server: bool,
    handler: Box<dyn TransportHandler>,
    sender: Rc<dyn PacketSendHandler>,
) -> Self
```

:::note
It is important to notice that the TQUIC library takes a different approach in receiving and sending packets - it doesn't rely on sockets for this purpose. Instead, it delegates these responsibilities to the callbacks provided by the user. Moreover, the library doesn't impose any specific event loop requirement but rather offers functions that assist users in scheduling events. This flexibility enables enhanced customization and seamless integration across various systems.
:::


### Configurations
The `Config` maintains various connection parameters. You can use the Config's `new` method to create an Config instance, and use various setter methods to further customize the configurations.

```rust
// Create default configurations.
let mut config = Config::new()?;

// Set connection idle timeout
config.set_max_idle_timeout(30000);

// Set application level protocol 
let mut tls_config = TlsConfig::new()?;
tls_config.set_application_protos(vec![b"h3".to_vec()]);
config.set_tls_config(tls_config);
```
Refer to the [Config documentation](https://docs.rs/tquic/latest/tquic/struct.Config.html) for more configuration options.


### Work mode 

The Endpoint can works in either server or client mode, which can be specified using the `is_server` parameter.

If your program requires both QUIC client and server functionality, it is recommended to instantiate two separate endpoints.


### TransportHandler
The Endpoint notifies the application layer to handle relevant QUIC connection/stream events by invoking the callback functions listed in `TransportHandler`.


```
pub trait TransportHandler {
    // Called when a new connection has been created. This callback is called
    // as soon as connection object is created inside the endpoint, but
    // before the handshake is done. The connection has progressed enough to
    // send early data if possible.
    fn on_conn_created(&mut self, conn: &mut Connection);

    // Called when the handshake is completed.
    fn on_conn_established(&mut self, conn: &mut Connection);

    // Called when the connection is closed. The connection is no longer
    // accessible after this callback returns. It is a good time to clean up
    // the connection context.
    fn on_conn_closed(&mut self, conn: &mut Connection);

    // Called when the stream is created.
    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64);

    // Called when the stream is readable. This callback is called when either
    // there are bytes to be read or an error is ready to be collected.
    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64);

    // Called when the stream is writable.
    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64);

    // Called when the stream is closed. The stream is no longer accessible
    // after this callback returns. It is a good time to clean up the stream
    // context.
    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64);

    // Called when client receives a token in NEW_TOKEN frame.
    fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>);
}
```

### PacketSendHandler

The Endpoint utilizes the `PacketSendHandler` to send packets. Within the PacketSendHandler, there is a callback function called `on_packets_send`, which is responsible for sending a batch of UDP packets to the network.

```
pub trait PacketSendHandler {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> Result<usize>;
}
```
The example implementation of PacketSendHandler can be found further down in this article.


## Receiving packets

The application receives UDP packets and delivers them to TQUIC by invoking the Endpoint's `recv` method, as demonstrated in the following example.

```rust
// Receive an incoming UDP datagram
let (len, remote) = match socket.recv_from(&mut recv_buf) {
    Ok(v) => v,
    Err(e) => {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            break;
        }
        // Error handling
    }
};

// Build a PacketInfo
let pkt_buf = &mut recv_buf[..len];
let pkt_info = PacketInfo {
    src: remote, // Source address of the packet 
    dst: socket.local_addr()?, // Destination address of the packet
    time: Instant::now(), // Arriaval time of the packet
};

// Delivery the incoming packet to the endpoint
match self.endpoint.recv(pkt_buf, &pkt_info) {
    Ok(_) => {}
    Err(e) => {
        // Error handling
    }
};
```


## Sending packets
The `on_packets_send` function is responsible for sending a batch of UDP packets to the network. It should return the number of packets that were successfully sent. In case there are any packets that fail to be sent, the Endpoint will handle their retry at a later time.

```rust
fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
    let mut count = 0;
    for (pkt, info) in pkts {
        if let Err(e) = self.socket.send_to(pkt, info.dst) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(count);
            }
            // Error handling
        }
        count += 1;
    }
    Ok(count)
}
```

:::tip
The simple example demonstrated the use of `recv_from` and `send_to` to read and send packets one by one. However, it is recommended that applications use more efficient methods available to read and send packets in batches.
:::


## Process connections
The `process_connections()` function must be called to postprocess connections in the following cases:
- When some incoming packets have been processed by using the `recv` method of Endpoint. 
- When timeout events have been handled by calling the `on_timeout` method of Endpoint. 
- When new connections have been initiated by the client through calling the `connect` method of Endpoint.

The code example below utilizes [Mio Poll](https://docs.rs/mio/latest/mio/struct.Poll.html) as the event framework:

```rust
// Connect to a server (client)
endpoint.connect(local, remote, server_name, session, token)?;

// Do event loop
let mut events = mio::Events::with_capacity(1024);
loop {
    endpoint.process_connections()?;

    // Get the the earliest timeout on the endpoint
    let timeout = endpoint.timeout();

    // Wait for timeout or IO events
    poll.poll(&mut events, timeout)?;

    // Process timeout events
    if events.is_empty() {
        endpoint.on_timeout(Instant::now());
        continue;
    }

    // Process IO events
    for event in events.iter() {
        if event.is_readable() {
            process_read_event()?;
        }
    }
}
```

## Client connection initiation

The client utilizes the connect method of the Endpoint to establish a connection with a server.

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
The client can provide `session`/`token` parameters to create a 0RTT connection, which helps reduce the time needed for establishing a new connection. Please refer to the ["0RTT Connection"](#0rtt-connection) section for instructions on obtaining the `session`/`token`.

On the server-side, when a connection is created, the Endpoint invokes the `on_conn_created` callback function to notify the application.


## Using Stream

### Creating streams

QUIC allows either endpoint to create streams. The application invokes the `stream_new()` function on a connection to create a new stream.

```
pub fn stream_new(
    &mut self,
    stream_id: u64,
    urgency: u8,
    incremental: bool
) -> Result<()>
```

On the peer side, when a stream is created, the Endpoint invokes the `on_stream_created` callback function to notify the application.


### Writing to streams

When the stream is writable, the Endpoint invokes the `on_stream_writable` callback function to notify the application. The application can send data via the Connection's `stream_write` method.

```
pub fn stream_write(
    &mut self,
    stream_id: u64,
    buf: Bytes,
    fin: bool
) -> Result<usize>
```

If `stream_write` returns an `Error::Done` error, no more data could be written due to flow control restrictions. The application can continue sending data the next time when the stream becomes writable.


### Reading from streams

When the stream is readable or encounters an error, the Endpoint invokes `on_stream_readable` callback function to notify the application. The application can use the Connection's `stream_read` method to read data or collect error information.

```
pub fn stream_read(
    &mut self,
    stream_id: u64,
    out: &mut [u8]
) -> Result<(usize, bool)>
```

If `stream_read` returns an `Error::Done` error, no more data could be read. The application can continue reading data the next time when the stream becomes readable.

See the [TQUIC API documentation](https://docs.rs/tquic/latest/tquic/struct.Connection.html) for more stream related operations.


## 0RTT Connection

In order to minimize the time required to establish a new connection, a client that has previously connected to a server may cache certain parameters from that connection and subsequently initiate a 0-RTT connection with the server. This allows the client to send data immediately, without waiting for a handshake to complete.

To be specific, the client needs to maintain session state and address token for previously connections, and utilize those parameters to establish a new connection. An example is as follows:

```rust
fn on_conn_closed(&mut self, conn: &mut Connection) {
    if let Some(session_file) = &self.session_file {
        // Save the session data (including TLS session data
        // and QUIC transport parameters)
        if let Some(session) = conn.session() {
            std::fs::write(session_file, session).ok();
        }
    }
}

fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>);
    if let Some(token_file) = &self.token_file {
        // Save the address token
        std::fs::write(token_file, &token).ok()
    }
}
```

```rust
// Client try to create a 0RTT connection.
let c = endpoint.connect(self, local, remote, server_name, session, token)?;
```


## Using multiply cerificates

TQUIC supports selecting different `TLSConfig`s based on SNI. An applications can implement the `TlsConfigSelector` trait for selecting custom certificates:

```rust
pub trait TlsConfigSelector: Send + Sync {
    // Get default TLSConfig
    fn get_default(&self) -> Option<&TlsConfig>;

    // Get the TLSConfig based on SNI
    fn select(&self, server_name: &str) -> Option<&TlsConfig>;
}
```

Then, it calls Config's `set_tls_config_selector` method to activate the custom TLSConfig selector.



## Packets decryption

TQUIC supports exporting TLS keys in [NSS key log](https://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format) format, which allows [Wireshark](https://www.wireshark.org/) and other tools to decrypt and analyze QUIC packets.

You can specify the output of the keylog file using the Connection's `set_keylog` method, as shown below:

```rust
fn on_conn_created(&mut self, conn: &mut Connection) {
    // Set key log for the connection.
    if let Some(keylog_file) = &self.keylog_file {
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_file)
        {
            conn.set_keylog(Box::new(file));
        } else {
            error!("{} set key log failed", conn.trace_id());
        }
    }
}
```
