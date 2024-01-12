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

//! An QUIC server based on the high level endpoint API.

use std::cmp;
use std::collections::HashMap;
use std::fs::File;
use std::net::SocketAddr;
use std::path;
use std::rc::Rc;
use std::time::Instant;

use bytes::Bytes;
use clap::Parser;
use log::debug;
use log::error;
use mio::event::Event;
use rustc_hash::FxHashMap;

use tquic::h3::connection::Http3Connection;
use tquic::h3::Header;
use tquic::h3::Http3Config;
use tquic::h3::NameValue;
use tquic::Config;
use tquic::CongestionControlAlgorithm;
use tquic::Connection;
use tquic::Endpoint;
use tquic::Error;
use tquic::MultipathAlgorithm;
use tquic::PacketInfo;
use tquic::TlsConfig;
use tquic::TransportHandler;
use tquic::TIMER_GRANULARITY;
use tquic_tools::ApplicationProto;
use tquic_tools::QuicSocket;
use tquic_tools::Result;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct ServerOpt {
    /// TLS certificate in PEM format.
    #[clap(
        short,
        long = "cert",
        default_value = "./cert.crt",
        value_name = "FILE"
    )]
    pub cert_file: String,

    /// TLS private key in PEM format.
    #[clap(short, long = "key", default_value = "./cert.key", value_name = "FILE")]
    pub key_file: String,

    /// Log level, support OFF/ERROR/WARN/INFO/DEBUG/TRACE.
    #[clap(long, default_value = "INFO")]
    pub log_level: log::LevelFilter,

    /// Address to listen.
    #[clap(short, long, default_value = "0.0.0.0:4433", value_name = "ADDR")]
    pub listen: SocketAddr,

    /// Document root directory.
    #[clap(long, default_value = "./", value_name = "DIR")]
    pub root: String,

    /// Session ticket key.
    #[clap(long, default_value = "tquic key", value_name = "STR")]
    pub ticket_key: String,

    /// Key for generating address token.
    #[clap(long, value_name = "STR")]
    pub address_token_key: Option<String>,

    /// Enable stateless retry.
    #[clap(long)]
    pub enable_retry: bool,

    /// Disable stateless reset.
    #[clap(long)]
    pub disable_stateless_reset: bool,

    /// Congestion control algorithm.
    #[clap(long, default_value = "BBR")]
    pub congestion_control_algor: CongestionControlAlgorithm,

    /// Initial congestion window in packets.
    #[clap(long, default_value = "32", value_name = "NUM")]
    pub initial_congestion_window: u64,

    /// Minimum congestion window in packets.
    #[clap(long, default_value = "4", value_name = "NUM")]
    pub min_congestion_window: u64,

    /// Enable multipath transport.
    #[clap(long)]
    pub enable_multipath: bool,

    /// Multipath scheduling algorithm
    #[clap(long, default_value = "MINRTT")]
    pub multipath_algor: MultipathAlgorithm,

    /// Set max_udp_payload_size transport parameter.
    #[clap(long, default_value = "65527", value_name = "NUM")]
    pub recv_udp_payload_size: u16,

    /// Set the maximum outgoing UDP payload size.
    #[clap(long, default_value = "1200", value_name = "NUM")]
    pub send_udp_payload_size: usize,

    /// Handshake timeout in microseconds.
    #[clap(long, default_value = "10000", value_name = "TIME")]
    pub handshake_timeout: u64,

    /// Connection idle timeout in microseconds.
    #[clap(long, default_value = "30000", value_name = "TIME")]
    pub idle_timeout: u64,

    /// Initial RTT in milliseconds.
    #[clap(long, default_value = "333", value_name = "TIME")]
    pub initial_rtt: u64,

    /// Linear factor for calculating the probe timeout.
    #[clap(long, default_value = "3", value_name = "NUM")]
    pub pto_linear_factor: u64,

    /// Upper limit of probe timeout in microseconds.
    #[clap(long, default_value = "10000", value_name = "TIME")]
    pub max_pto: u64,

    /// Save TLS key log into the given file.
    #[clap(long, value_name = "FILE")]
    pub keylog_file: Option<String>,

    /// Save QUIC qlog into the given file.
    #[clap(long, value_name = "FILE")]
    pub qlog_file: Option<String>,

    /// Length of connection id in bytes.
    #[clap(long, default_value = "8", value_name = "NUM")]
    pub cid_len: usize,

    /// Batch size for sending packets.
    #[clap(long, default_value = "16", value_name = "NUM")]
    pub send_batch_size: usize,
}

const MAX_BUF_SIZE: usize = 65536;

/// An HTTP file Server which support HTTP/3 and HTTP/0.9 over QUIC.
struct Server {
    /// QUIC endpoint
    endpoint: Endpoint,

    /// Event poll
    poll: mio::Poll,

    /// Listen socket
    sock: Rc<QuicSocket>,

    /// Packet read buffer
    recv_buf: Vec<u8>,
}

impl Server {
    fn new(option: &ServerOpt) -> Result<Self> {
        let mut config = Config::new()?;
        config.set_recv_udp_payload_size(option.recv_udp_payload_size);
        config.set_send_udp_payload_size(option.send_udp_payload_size);
        config.set_max_handshake_timeout(option.handshake_timeout);
        config.enable_retry(option.enable_retry);
        config.enable_stateless_reset(!option.disable_stateless_reset);
        config.set_max_handshake_timeout(option.handshake_timeout);
        config.set_max_idle_timeout(option.idle_timeout);
        config.set_initial_rtt(option.initial_rtt);
        config.set_pto_linear_factor(option.pto_linear_factor);
        config.set_max_pto(option.max_pto);
        config.set_cid_len(option.cid_len);
        config.set_send_batch_size(option.send_batch_size);
        config.set_congestion_control_algorithm(option.congestion_control_algor);
        config.set_initial_congestion_window(option.initial_congestion_window);
        config.set_min_congestion_window(option.min_congestion_window);
        config.enable_multipath(option.enable_multipath);
        config.set_multipath_algorithm(option.multipath_algor);

        if let Some(address_token_key) = &option.address_token_key {
            let address_token_key = convert_address_token_key(address_token_key);
            config.set_address_token_key(vec![address_token_key])?;
        }

        let application_protos = vec![b"h3".to_vec(), b"http/0.9".to_vec(), b"hq-interop".to_vec()];
        let mut tls_config = TlsConfig::new_server_config(
            &option.cert_file,
            &option.key_file,
            application_protos,
            true,
        )?;
        let mut ticket_key = option.ticket_key.clone().into_bytes();
        ticket_key.resize(48, 0);
        tls_config.set_ticket_key(&ticket_key)?;
        config.set_tls_config(tls_config);

        let poll = mio::Poll::new()?;
        let registry = poll.registry();

        let handlers = ServerHandler::new(option)?;
        let sock = Rc::new(QuicSocket::new(&option.listen, registry)?);

        Ok(Server {
            endpoint: Endpoint::new(Box::new(config), true, Box::new(handlers), sock.clone()),
            poll,
            sock,
            recv_buf: vec![0u8; MAX_BUF_SIZE],
        })
    }

    fn process_read_event(&mut self, event: &Event) -> Result<()> {
        loop {
            // Read datagram from the socket.
            // TODO: support recvmmsg
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
            debug!("socket recv {} bytes from {:?}", len, remote);

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

fn convert_address_token_key(key: &str) -> [u8; 16] {
    let mut key_data = key.to_owned().into_bytes();
    key_data.resize(16, 0);

    let mut token_key = [0_u8; 16];
    token_key.copy_from_slice(&key_data[..]);
    token_key
}

struct Response {
    headers: Option<Vec<tquic::h3::Header>>,
    body: Bytes,
    body_written: usize,
}

#[derive(Default)]
struct ConnectionHandler {
    /// Application protocol.
    app_proto: ApplicationProto,

    /// File root directory.
    root: String,

    /// Number of processed requests.
    processed_requests: u64,

    /// Mapping stream id to http/0.9 request line data, only used in http/0.9 mode.
    http09_requests: HashMap<u64, Vec<u8>>,

    /// H3 connection, only used in h3 mode.
    h3_conn: Option<Http3Connection>,

    /// Mapping stream id to response.
    responses: HashMap<u64, Response>,
}

impl ConnectionHandler {
    fn generate_file_path(uri: &str, root: &str) -> path::PathBuf {
        let uri = path::Path::new(uri);
        let mut path = path::PathBuf::from(root);

        for c in uri.components() {
            if let path::Component::Normal(v) = c {
                path.push(v)
            }
        }

        path
    }

    fn process_http09_request(
        &mut self,
        request_line: &[u8],
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<()> {
        self.http09_requests.remove(&stream_id);

        let uri = &request_line[4..request_line.len() - 2];
        let uri = String::from_utf8(uri.to_vec())?;
        let uri = match uri.lines().next() {
            Some(uri) => uri,
            None => return Err(format!("request format error {:?}", request_line).into()),
        };
        let path = Self::generate_file_path(uri, &self.root);
        debug!(
            "{} got GET request for {:?} on stream {}",
            conn.trace_id(),
            path,
            stream_id
        );

        let body = std::fs::read(path.as_path()).unwrap_or_else(|_| b"Not Found!\r\n".to_vec());
        debug!(
            "{} sending response of size {} on stream {}",
            conn.trace_id(),
            body.len(),
            stream_id
        );
        let body = Bytes::from(body);

        let written = match conn.stream_write(stream_id, body.clone(), true) {
            Ok(v) => v,
            Err(tquic::error::Error::Done) => 0,
            Err(e) => {
                error!("{} stream write failed {:?}", conn.trace_id(), e);
                return Ok(());
            }
        };
        if written < body.len() {
            _ = conn.stream_want_write(stream_id, true);

            let response = Response {
                headers: None,
                body,
                body_written: written,
            };

            self.responses.insert(stream_id, response);
        }

        Ok(())
    }

    fn recv_http09_request(&mut self, buf: &mut [u8], conn: &mut Connection, stream_id: u64) {
        if !self.http09_requests.contains_key(&stream_id) {
            debug!("{} stream {} not exists", conn.trace_id(), stream_id);
            return;
        }

        while let Ok((read, fin)) = conn.stream_read(stream_id, buf) {
            let request_line = &buf[..read];
            debug!(
                "{} stream {} has {} bytes (fin? {})",
                conn.trace_id(),
                stream_id,
                request_line.len(),
                fin
            );

            let request_line = if let Some(request_data) = self.http09_requests.get_mut(&stream_id)
            {
                request_data.extend_from_slice(request_line);

                if !request_data.ends_with(b"\r\n") {
                    return;
                }

                request_data.clone()
            } else {
                if !request_line.ends_with(b"\r\n") {
                    self.http09_requests
                        .insert(stream_id, request_line.to_vec());
                    return;
                }

                request_line.to_vec()
            };

            if !request_line.starts_with(b"GET ")
                || self
                    .process_http09_request(&request_line, conn, stream_id)
                    .is_err()
            {
                error!("{} request[{}] format error", conn.trace_id(), stream_id);
                match conn.close(true, 0x00, b"bad request") {
                    Ok(_) | Err(Error::Done) => (),
                    Err(e) => debug!("{} connection close error {:?}", conn.trace_id(), e),
                }
            }
        }
    }

    fn build_h3_response(&self, headers: &[Header]) -> (Vec<Header>, Bytes) {
        let mut path = "";
        for header in headers {
            if header.name() == b":path" {
                path = std::str::from_utf8(header.value()).unwrap();
            }
        }
        let path = Self::generate_file_path(path, &self.root);

        let (status, body) = {
            match std::fs::read(path.as_path()) {
                Ok(data) => (200, data),
                Err(_) => (404, b"Not Found!".to_vec()),
            }
        };

        let headers = vec![
            tquic::h3::Header::new(b":status", status.to_string().as_bytes()),
            tquic::h3::Header::new(b"server", b"tquic"),
            tquic::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        (headers, Bytes::from(body))
    }

    fn process_h3_request(
        &mut self,
        headers: &[Header],
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<()> {
        conn.stream_shutdown(stream_id, tquic::Shutdown::Read, 0)?;
        self.processed_requests = std::cmp::max(self.processed_requests, stream_id);

        let (headers, body) = self.build_h3_response(headers);
        let h3_conn = self.h3_conn.as_mut().unwrap();
        match h3_conn.send_headers(conn, stream_id, &headers, false) {
            Ok(v) => v,
            Err(tquic::h3::Http3Error::StreamBlocked) => {
                let response = Response {
                    headers: Some(headers),
                    body,
                    body_written: 0,
                };

                self.responses.insert(stream_id, response);
                return Ok(());
            }
            Err(e) => {
                return Err(format!("{} stream send failed {:?}", conn.trace_id(), e).into());
            }
        }

        let written = match h3_conn.send_body(conn, stream_id, body.clone(), true) {
            Ok(v) => v,
            Err(tquic::h3::Http3Error::Done) => 0,
            Err(e) => {
                return Err(format!("{} stream send failed {:?}", conn.trace_id(), e).into());
            }
        };
        if written < body.len() {
            _ = conn.stream_want_write(stream_id, true);

            let response = Response {
                headers: None,
                body,
                body_written: written,
            };

            self.responses.insert(stream_id, response);
        }

        Ok(())
    }

    fn process_goaway(&mut self, conn: &mut Connection, goaway_id: u64) {
        debug!("{} got GOAWAY with ID {} ", conn.trace_id(), goaway_id);
        let h3_conn = self.h3_conn.as_mut().unwrap();
        _ = h3_conn.send_goaway(conn, self.processed_requests);
    }

    fn recv_h3_request(&mut self, conn: &mut Connection) {
        loop {
            match self.h3_conn.as_mut().unwrap().poll(conn) {
                Ok((stream_id, tquic::h3::Http3Event::Headers { headers, .. })) => {
                    debug!(
                        "{} got request {:?} on stream id {}",
                        conn.trace_id(),
                        headers,
                        stream_id
                    );
                    if let Err(e) = self.process_h3_request(&headers, conn, stream_id) {
                        error!("{:?}", e);
                        break;
                    }
                }
                Ok((stream_id, tquic::h3::Http3Event::Data)) => {
                    debug!("{} got data on stream id {}", conn.trace_id(), stream_id);
                }
                Ok((_, tquic::h3::Http3Event::Finished)) => (),
                Ok((_, tquic::h3::Http3Event::Reset { .. })) => (),
                Ok((_, tquic::h3::Http3Event::PriorityUpdate)) => (),
                Ok((goaway_id, tquic::h3::Http3Event::GoAway)) => {
                    self.process_goaway(conn, goaway_id);
                }
                Err(tquic::h3::Http3Error::Done) => {
                    break;
                }
                Err(e) => {
                    error!("{} h3 error {:?}", conn.trace_id(), e);
                    return;
                }
            }
        }
    }

    fn recv_request(&mut self, buf: &mut [u8], conn: &mut Connection, stream_id: u64) {
        match self.app_proto {
            ApplicationProto::Interop | ApplicationProto::Http09 => {
                self.recv_http09_request(buf, conn, stream_id)
            }
            ApplicationProto::H3 => self.recv_h3_request(conn),
        }
    }

    fn send_http09_response(&mut self, conn: &mut Connection, stream_id: u64) {
        let response = self.responses.get_mut(&stream_id).unwrap();
        let written = match conn.stream_write(
            stream_id,
            response.body.slice(response.body_written..),
            true,
        ) {
            Ok(v) => v,
            Err(tquic::error::Error::Done) => 0,
            Err(e) => {
                self.responses.remove(&stream_id);
                error!("{} stream write failed {:?}", conn.trace_id(), e);
                return;
            }
        };
        response.body_written += written;
        if response.body_written == response.body.len() {
            self.responses.remove(&stream_id);
        }
    }

    fn send_h3_response(&mut self, conn: &mut Connection, stream_id: u64) {
        let h3_conn = self.h3_conn.as_mut().unwrap();
        let response = self.responses.get_mut(&stream_id).unwrap();
        if let Some(ref headers) = response.headers {
            match h3_conn.send_headers(conn, stream_id, headers, false) {
                Ok(_) => (),
                Err(tquic::h3::Http3Error::StreamBlocked) => {
                    debug!("{} stream blocked", conn.trace_id());
                    return;
                }
                Err(e) => {
                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return;
                }
            }
        }
        response.headers = None;

        let written = match h3_conn.send_body(
            conn,
            stream_id,
            response.body.slice(response.body_written..),
            true,
        ) {
            Ok(v) => v,
            Err(tquic::h3::Http3Error::Done) => 0,
            Err(e) => {
                self.responses.remove(&stream_id);
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            }
        };
        response.body_written += written;
        if response.body_written == response.body.len() {
            self.responses.remove(&stream_id);
        }
    }

    fn send_responses(&mut self, conn: &mut Connection, stream_id: u64) {
        if !self.responses.contains_key(&stream_id) {
            return;
        }

        _ = conn.stream_want_write(stream_id, true);

        match self.app_proto {
            ApplicationProto::Interop | ApplicationProto::Http09 => {
                self.send_http09_response(conn, stream_id)
            }
            ApplicationProto::H3 => self.send_h3_response(conn, stream_id),
        }
    }
}

struct ServerHandler {
    /// File root directory.
    root: String,

    /// HTTP connections
    conns: FxHashMap<u64, ConnectionHandler>,

    /// Read buffer
    buf: Vec<u8>,

    /// SSL key logger
    keylog: Option<File>,

    /// Qlog file
    qlog: Option<File>,
}

impl ServerHandler {
    fn new(option: &ServerOpt) -> Result<Self> {
        let keylog = match &option.keylog_file {
            Some(keylog_file) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(keylog_file)?,
            ),
            None => None,
        };

        let qlog = match &option.qlog_file {
            Some(qlog_file) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(qlog_file)?,
            ),
            None => None,
        };

        Ok(Self {
            root: option.root.clone(),
            buf: vec![0; MAX_BUF_SIZE],
            conns: FxHashMap::default(),
            keylog,
            qlog,
        })
    }

    fn try_new_conn_handler(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap();
        if self.conns.get_mut(&index).is_some() {
            return;
        }

        debug!("{} new connection handler", conn.trace_id());
        let mut conn_handler = ConnectionHandler {
            app_proto: ApplicationProto::from_slice(conn.application_proto()),
            root: self.root.clone(),
            ..Default::default()
        };

        if conn_handler.app_proto == ApplicationProto::H3 {
            conn_handler.h3_conn = Some(
                Http3Connection::new_with_quic_conn(conn, &Http3Config::new().unwrap()).unwrap(),
            );
        }

        self.conns.insert(index, conn_handler);
    }
}

impl TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        debug!("{} connection is created", conn.trace_id());
        if let Some(keylog) = &mut self.keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }

        if let Some(qlog) = &mut self.qlog {
            if let Ok(qlog) = qlog.try_clone() {
                conn.set_qlog(
                    Box::new(qlog),
                    "server qlog".into(),
                    format!("id={}", conn.trace_id()),
                );
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        debug!("{} connection is established", conn.trace_id());
        self.try_new_conn_handler(conn);
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        log::debug!("connection[{:?}] is closed", conn.trace_id());

        let index = conn.index().unwrap();
        self.conns.remove(&index);
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is created", conn.trace_id(), stream_id);

        // Stream may be created before connection is established because the arriving of early data.
        self.try_new_conn_handler(conn);

        let index = conn.index().unwrap();
        let conn_handler = self.conns.get_mut(&index).unwrap();
        if conn_handler.app_proto == ApplicationProto::Interop
            || conn_handler.app_proto == ApplicationProto::Http09
        {
            conn_handler.http09_requests.insert(stream_id, b"".to_vec());
        }
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap();
        let conn_handler = self.conns.get_mut(&index).unwrap();
        conn_handler.recv_request(&mut self.buf, conn, stream_id);
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        _ = conn.stream_want_write(stream_id, false);

        let index = conn.index().unwrap();
        let conn_handler = self.conns.get_mut(&index).unwrap();
        conn_handler.send_responses(conn, stream_id);
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is closed", conn.trace_id(), stream_id,);
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}

fn main() -> Result<()> {
    let option = ServerOpt::parse();

    // Initialize logging.
    env_logger::builder().filter_level(option.log_level).init();

    // Initialize HTTP file server.
    let mut server = Server::new(&option)?;

    // Run event loop.
    let mut events = mio::Events::with_capacity(1024);
    loop {
        if let Err(e) = server.endpoint.process_connections() {
            error!("process connections error: {:?}", e);
        }

        let timeout = server
            .endpoint
            .timeout()
            .map(|v| cmp::max(v, TIMER_GRANULARITY));
        debug!("{} timeout: {:?}", server.endpoint.trace_id(), timeout);

        server.poll.poll(&mut events, timeout)?;

        // Process timeout events
        if events.is_empty() {
            server.endpoint.on_timeout(Instant::now());
            continue;
        }

        // Process IO events
        for event in events.iter() {
            if event.is_readable() {
                server.process_read_event(event)?;
            }
        }
    }
}
