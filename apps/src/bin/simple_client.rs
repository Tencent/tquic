// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::cell::RefCell;
use std::cmp;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Instant;

use bytes::Bytes;
use clap::Parser;
use log::debug;
use log::error;
use mio::event::Event;

use tquic::Config;
use tquic::Connection;
use tquic::Endpoint;
use tquic::Error;
use tquic::PacketInfo;
use tquic::TlsConfig;
use tquic::TransportHandler;
use tquic::TIMER_GRANULARITY;
use tquic_apps::alpns;
use tquic_apps::QuicSocket;
use tquic_apps::Result;

#[derive(Parser, Debug, Clone)]
#[clap(name = "client")]
pub struct ClientOpt {
    /// Log level, support OFF/ERROR/WARN/INFO/DEBUG/TRACE.
    #[clap(long, default_value = "DEBUG", value_name = "STR")]
    pub log_level: log::LevelFilter,

    /// Override server's address.
    #[clap(short, long, value_name = "ADDR")]
    pub connect_to: SocketAddr,

    /// Connection idle timeout in microseconds.
    #[clap(long, default_value = "5000", value_name = "TIME")]
    pub idle_timeout: u64,

    /// File used for session resumption.
    #[clap(long, value_name = "FILE")]
    pub session_file: Option<String>,

    /// Save TLS key log into the given file.
    #[clap(long, value_name = "FILE")]
    pub keylog_file: Option<String>,

    /// Save QUIC qlog into the given file.
    #[clap(long, value_name = "FILE")]
    pub qlog_file: Option<String>,
}

const MAX_BUF_SIZE: usize = 65536;

// A simple http/0.9 client over QUIC.
struct Client {
    /// QUIC endpoint.
    endpoint: Endpoint,

    /// Event poll.
    poll: mio::Poll,

    /// Socket connecting to server.
    sock: Rc<QuicSocket>,

    /// Client context.
    context: Rc<RefCell<ClientContext>>,

    /// Packet read buffer.
    recv_buf: Vec<u8>,
}

impl Client {
    fn new(option: &ClientOpt) -> Result<Self> {
        let mut config = Config::new()?;
        config.set_max_idle_timeout(option.idle_timeout);

        let tls_config = TlsConfig::new_client_config(vec![b"http/0.9".to_vec()], false)?;
        config.set_tls_config(tls_config);

        let context = Rc::new(RefCell::new(ClientContext { finish: false }));
        let handlers = ClientHandler::new(option, context.clone());

        let poll = mio::Poll::new()?;
        let registry = poll.registry();
        let sock = Rc::new(QuicSocket::new_client_socket(
            option.connect_to.is_ipv4(),
            registry,
        )?);

        Ok(Client {
            endpoint: Endpoint::new(Box::new(config), false, Box::new(handlers), sock.clone()),
            poll,
            sock,
            context,
            recv_buf: vec![0u8; MAX_BUF_SIZE],
        })
    }

    fn finish(&self) -> bool {
        let context = self.context.borrow();
        context.finish()
    }

    fn process_read_event(&mut self, event: &Event) -> Result<()> {
        loop {
            if self.context.borrow().finish() {
                break;
            }
            // Read datagram from the socket.
            let (len, local, remote) = match self.sock.recv_from(&mut self.recv_buf, event.token())
            {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("socket recv would block");
                        break;
                    }
                    return Err(format!("socket recv error: {:?}", e).into());
                }
            };
            debug!("socket recv recv {} bytes from {:?}", len, remote);

            let pkt_buf = &mut self.recv_buf[..len];
            let pkt_info = PacketInfo {
                src: remote,
                dst: local,
                time: Instant::now(),
            };

            // Process the incoming packet.
            match self.endpoint.recv(pkt_buf, &pkt_info) {
                Ok(_) => {}
                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue;
                }
            };
        }

        Ok(())
    }
}

struct ClientContext {
    finish: bool,
}

impl ClientContext {
    fn set_finish(&mut self, finish: bool) {
        self.finish = finish
    }

    fn finish(&self) -> bool {
        self.finish
    }
}

struct ClientHandler {
    session_file: Option<String>,
    keylog_file: Option<String>,
    qlog_file: Option<String>,
    context: Rc<RefCell<ClientContext>>,
    buf: Vec<u8>,
}

impl ClientHandler {
    fn new(option: &ClientOpt, context: Rc<RefCell<ClientContext>>) -> Self {
        Self {
            session_file: option.session_file.clone(),
            keylog_file: option.keylog_file.clone(),
            qlog_file: option.qlog_file.clone(),
            context,
            buf: vec![0; MAX_BUF_SIZE],
        }
    }
}

impl TransportHandler for ClientHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        debug!("{} connection is created", conn.trace_id());

        if let Some(session_file) = &self.session_file {
            if let Ok(session) = std::fs::read(session_file) {
                if conn.set_session(&session).is_err() {
                    error!("{} session resumption failed", conn.trace_id());
                }
            }
        }

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

        if let Some(qlog_file) = &self.qlog_file {
            if let Ok(qlog) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(qlog_file)
            {
                conn.set_qlog(
                    Box::new(qlog),
                    "client qlog".into(),
                    format!("id={}", conn.trace_id()),
                );
            } else {
                error!("{} set qlog failed", conn.trace_id());
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        debug!("{} connection is established", conn.trace_id());

        let app_proto = conn.application_proto();
        if !alpns::HTTP_09.contains(&app_proto) {
            unreachable!();
        }

        match conn.stream_write(0, Bytes::from_static(b"GET /\r\n"), true) {
            Ok(_) | Err(Error::Done) => {}
            Err(e) => {
                error!("stream send failed {:?}", e);
            }
        };
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        debug!("{} connection is closed", conn.trace_id());
        let mut context = self.context.try_borrow_mut().unwrap();
        context.set_finish(true);
        if let Some(session_file) = &self.session_file {
            if let Some(session) = conn.session() {
                std::fs::write(session_file, session).ok();
            }
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is created", conn.trace_id(), stream_id);
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        match conn.stream_read(stream_id, &mut self.buf) {
            Ok((n, fin)) => {
                debug!(
                    "{} read {} bytes from stream {}",
                    conn.trace_id(),
                    n,
                    stream_id
                );
                if fin {
                    match conn.close(true, 0x00, b"ok") {
                        Ok(_) | Err(Error::Done) => (),
                        Err(e) => panic!("error closing conn: {:?}", e),
                    }
                }
            }
            Err(Error::Done) => {}
            Err(e) => {
                error!(
                    "{} read from stream {} error {}",
                    conn.trace_id(),
                    stream_id,
                    e
                );
            }
        }
    }

    fn on_stream_writable(&mut self, _conn: &mut Connection, _stream_id: u64) {}

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is closed", conn.trace_id(), stream_id,);
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}

fn main() -> Result<()> {
    let option = ClientOpt::parse();

    // Initialize logging.
    env_logger::builder().filter_level(option.log_level).init();

    // Create client.
    let mut client = Client::new(&option)?;

    // Connect to server.
    client.endpoint.connect(
        client.sock.local_addr(),
        option.connect_to,
        None,
        None,
        None,
    )?;

    // Run event loop.
    let mut events = mio::Events::with_capacity(1024);
    loop {
        // Process connections.
        client.endpoint.process_connections()?;
        if client.finish() {
            break;
        }

        let timeout = cmp::min(client.endpoint.timeout(), Some(TIMER_GRANULARITY));
        client.poll.poll(&mut events, timeout)?;

        // Process timeout events
        if events.is_empty() {
            client.endpoint.on_timeout(Instant::now());
            continue;
        }

        // Process IO events
        for event in events.iter() {
            if event.is_readable() {
                client.process_read_event(event)?;
            }
        }
    }
    Ok(())
}
