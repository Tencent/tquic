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
use std::cell::RefMut;
use std::cmp;
use std::cmp::max;
use std::fs::create_dir_all;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Instant;

use bytes::Bytes;
use clap::error::ErrorKind;
use clap::CommandFactory;
use clap::Parser;
use log::debug;
use log::error;
use log::info;
use log::warn;
use mio::event::Event;
use rand::Rng;
use rustc_hash::FxHashMap;
use statrs::statistics::Data;
use statrs::statistics::Distribution;
use statrs::statistics::Max;
use statrs::statistics::Min;
use statrs::statistics::OrderStatistics;
use tquic::h3::NameValue;
use url::Url;

use tquic::connection::ConnectionStats;
use tquic::error::Error;
use tquic::h3::connection::Http3Connection;
use tquic::h3::Header;
use tquic::h3::Http3Config;
use tquic::Config;
use tquic::CongestionControlAlgorithm;
use tquic::Connection;
use tquic::Endpoint;
use tquic::MultipathAlgorithm;
use tquic::PacketInfo;
use tquic::TlsConfig;
use tquic::TransportHandler;
use tquic::TIMER_GRANULARITY;
use tquic_tools::ApplicationProto;
use tquic_tools::QuicSocket;
use tquic_tools::Result;

#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Parser, Debug, Clone)]
#[clap(name = "client")]
pub struct ClientOpt {
    /// Request URLs. The host of the first one is used as SNI in Client Hello.
    #[clap(value_delimiter = ' ')]
    pub urls: Vec<Url>,

    /// Number of threads.
    #[clap(short, long, default_value = "1", value_name = "NUM")]
    pub threads: u32,

    /// Number of concurrent connections per thread.
    #[clap(long, default_value = "1", value_name = "NUM")]
    pub max_concurrent_conns: u32,

    /// Number of requests per thread. "0" means infinity mode.
    #[clap(long, default_value = "1", value_name = "NUM")]
    pub max_requests_per_thread: u64,

    /// Number of max requests per connection. "0" means infinity mode.
    #[clap(long, default_value = "1", value_name = "NUM")]
    pub max_requests_per_conn: u64,

    /// Number of max concurrent requests per connection.
    #[clap(long, default_value = "1", value_name = "NUM")]
    pub max_concurrent_requests: u64,

    /// Benchmarking duration in seconds. "0" means infinity mode.
    /// Client will exit if either the max_requests or duration is reached.
    #[clap(short, long, default_value = "0", value_name = "TIME")]
    pub duration: u64,

    /// Client will exit if consecutive failure reaches the threshold at the beginning.
    #[clap(long, default_value = "10", value_name = "NUM")]
    pub connection_failure_threshold: u64,

    /// Number of max samples per thread used for request time statistics.
    #[clap(long, default_value = "100000", value_name = "NUM")]
    pub max_sample: usize,

    /// Print response header and body to stdout.
    #[clap(short, long)]
    pub print_res: bool,

    /// Log level, support OFF/ERROR/WARN/INFO/DEBUG/TRACE.
    #[clap(long, default_value = "INFO", value_name = "STR")]
    pub log_level: log::LevelFilter,

    /// Log file path. If no file is specified, logs will be written to `stderr`.
    #[clap(long, value_name = "FILE")]
    pub log_file: Option<String>,

    /// Override server's address.
    #[clap(short, long, value_name = "ADDR")]
    pub connect_to: Option<SocketAddr>,

    /// ALPN, separated by ",".
    #[clap(
        short,
        long,
        value_delimiter = ',',
        default_value = "h3,http/0.9,hq-interop",
        value_name = "STR"
    )]
    pub alpn: Vec<ApplicationProto>,

    /// Dump response body into the given directory.
    /// If the specified directory does not exist, a new directory will be created.
    #[clap(long, value_name = "DIR")]
    pub dump_dir: Option<String>,

    /// File used for session resumption.
    #[clap(short, long, value_name = "FILE")]
    pub session_file: Option<String>,

    /// Enable early data.
    #[clap(short, long)]
    pub enable_early_data: bool,

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

    /// Multipath scheduling algorithm.
    #[clap(long, default_value = "MINRTT")]
    pub multipath_algor: MultipathAlgorithm,

    /// Optional local IP addresses for client. e.g 192.168.1.10,192.168.2.20
    #[clap(long, value_delimiter = ',', value_name = "ADDR")]
    pub local_addresses: Vec<IpAddr>,

    /// Set active_connection_id_limit transport parameter. Values lower than 2 will be ignored.
    #[clap(long, default_value = "2", value_name = "NUM")]
    pub active_cid_limit: u64,

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
    #[clap(long, default_value = "10", value_name = "NUM")]
    pub pto_linear_factor: u64,

    /// Upper limit of probe timeout in microseconds.
    #[clap(long, default_value = "10000", value_name = "TIME")]
    pub max_pto: u64,

    /// Save TLS key log into the given file.
    #[clap(short, long, value_name = "FILE")]
    pub keylog_file: Option<String>,

    /// Save qlog file (<trace_id>.qlog) into the given directory.
    #[clap(long, value_name = "DIR")]
    pub qlog_dir: Option<String>,

    /// Length of connection id in bytes.
    #[clap(long, default_value = "8", value_name = "NUM")]
    pub cid_len: usize,

    /// Batch size for sending packets.
    #[clap(long, default_value = "1", value_name = "NUM")]
    pub send_batch_size: usize,
}

const MAX_BUF_SIZE: usize = 65536;

/// Multi-threads QUIC client.
struct Client {
    /// Client option.
    option: ClientOpt,

    /// Context shared between threads.
    context: Arc<Mutex<ClientContext>>,

    /// Client start time.
    start_time: Instant,

    /// If terminated by system signal.
    terminated: Arc<AtomicBool>,
}

impl Client {
    /// Create a new multi-threads client.
    pub fn new(option: ClientOpt) -> Result<Self> {
        let client_ctx = Arc::new(Mutex::new(ClientContext::default()));
        let terminated = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&terminated))?;

        Ok(Self {
            option,
            context: client_ctx,
            start_time: Instant::now(),
            terminated,
        })
    }

    /// Start the client.
    pub fn start(&mut self) {
        self.start_time = Instant::now();
        let mut threads = vec![];
        for _ in 0..self.option.threads {
            let client_opt = self.option.clone();
            let client_ctx = self.context.clone();
            let terminated = self.terminated.clone();
            let thread = thread::spawn(move || {
                let mut worker = Worker::new(client_opt, client_ctx, terminated).unwrap();
                worker.start().unwrap();
            });
            threads.push(thread);
        }

        for thread in threads {
            thread.join().unwrap();
        }

        self.finish();
    }

    fn finish(&self) {
        // Print stats.
        self.stats();

        // Write session resumption file.
        let context = self.context.lock().unwrap();
        if let Some(session) = &context.session {
            if let Some(session_file) = &self.option.session_file {
                std::fs::write(session_file, session).ok();
            }
        }
    }

    fn stats(&self) {
        let context = self.context.lock().unwrap();
        let d = context.end_time.unwrap() - self.start_time;

        // TODO: support more statistical items.
        println!();
        println!(
            "finished in {:?}, {:.2} req/s",
            d,
            context.request_success as f64 / d.as_millis() as f64 * 1000.0
        );
        println!(
            "conns: total {}, finish {}, success {}, failure {}",
            context.conn_total,
            context.conn_finish,
            context.conn_finish_success,
            context.conn_finish_failed,
        );
        println!(
            "requests: sent {}, finish {}, success {}",
            context.request_sent, context.request_done, context.request_success,
        );

        let mut s = Data::new(context.request_time_samples.clone());
        println!("time for request(µs):");
        println!(
            "\tmin: {:.2}, max: {:.2}, mean: {:.2}, sd: {:.2}",
            s.min(),
            s.max(),
            s.mean().unwrap(),
            s.std_dev().unwrap(),
        );
        println!(
            "\tmedian: {:.2}, p80: {:.2}, p90: {:.2}, p99: {:.2}",
            s.median(),
            s.percentile(80),
            s.percentile(90),
            s.percentile(99),
        );

        println!(
            "recv pkts: {}, sent pkts: {}, lost pkts: {}",
            context.conn_stats.recv_count,
            context.conn_stats.sent_count,
            context.conn_stats.lost_count
        );
        println!(
            "recv bytes: {}, sent bytes: {}, lost bytes: {}",
            context.conn_stats.recv_bytes,
            context.conn_stats.sent_bytes,
            context.conn_stats.lost_bytes
        );
        println!();
    }
}

/// Context used for single thread client.
#[derive(Default)]
struct ClientContext {
    session: Option<Vec<u8>>,
    request_sent: u64,
    request_done: u64,
    request_success: u64,
    request_time_samples: Vec<f64>,
    conn_total: u64,
    conn_handshake_success: u64,
    conn_finish: u64,
    conn_finish_success: u64,
    conn_finish_failed: u64,
    end_time: Option<Instant>,
    conn_stats: ConnectionStats,
}

fn update_conn_stats(total: &mut ConnectionStats, one: &ConnectionStats) {
    total.recv_count += one.recv_count;
    total.sent_count += one.sent_count;
    total.lost_count += one.lost_count;
    total.recv_bytes += one.recv_bytes;
    total.sent_bytes += one.sent_bytes;
    total.lost_bytes += one.lost_bytes;
}

/// Client worker with single thread.
struct Worker {
    /// Client option.
    option: ClientOpt,

    /// QUIC endpoint.
    endpoint: Endpoint,

    /// Event poll.
    poll: mio::Poll,

    /// Remote socket address.
    remote: SocketAddr,

    /// Socket connecting to server.
    sock: Rc<QuicSocket>,

    /// Worker context.
    worker_ctx: Rc<RefCell<WorkerContext>>,

    /// Context shared between workers.
    client_ctx: Arc<Mutex<ClientContext>>,

    /// Request senders.
    senders: Rc<RefCell<FxHashMap<u64, RequestSender>>>,

    /// Packet read buffer.
    recv_buf: Vec<u8>,

    /// Worker start time.
    start_time: Instant,

    /// Worker end time.
    end_time: Option<Instant>,

    /// If terminated by system signal.
    terminated: Arc<AtomicBool>,
}

impl Worker {
    /// Create a new single thread client.
    pub fn new(
        option: ClientOpt,
        client_ctx: Arc<Mutex<ClientContext>>,
        terminated: Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut config = Config::new()?;
        config.enable_stateless_reset(!option.disable_stateless_reset);
        config.set_max_handshake_timeout(option.handshake_timeout);
        config.set_max_idle_timeout(option.idle_timeout);
        config.set_initial_rtt(option.initial_rtt);
        config.set_pto_linear_factor(option.pto_linear_factor);
        config.set_max_pto(option.max_pto);
        config.set_max_concurrent_conns(option.max_concurrent_conns);
        config.set_initial_max_streams_bidi(option.max_concurrent_requests);
        config.set_cid_len(option.cid_len);
        config.set_send_batch_size(option.send_batch_size);
        config.set_recv_udp_payload_size(option.recv_udp_payload_size);
        config.set_send_udp_payload_size(option.send_udp_payload_size);
        config.set_congestion_control_algorithm(option.congestion_control_algor);
        config.set_initial_congestion_window(option.initial_congestion_window);
        config.set_min_congestion_window(option.min_congestion_window);
        config.enable_multipath(option.enable_multipath);
        config.set_multipath_algorithm(option.multipath_algor);
        config.set_active_connection_id_limit(option.active_cid_limit);
        let tls_config = TlsConfig::new_client_config(
            ApplicationProto::convert_to_vec(&option.alpn),
            option.enable_early_data,
        )?;
        config.set_tls_config(tls_config);

        let poll = mio::Poll::new()?;
        let registry = poll.registry();
        let worker_ctx = Rc::new(RefCell::new(WorkerContext::with_option(&option)));
        let senders = Rc::new(RefCell::new(FxHashMap::default()));

        // Use unspecified local addr or the given local addr
        let remote = option.connect_to.unwrap();
        let local = if !option.local_addresses.is_empty() {
            SocketAddr::new(option.local_addresses[0], 0)
        } else {
            match remote.is_ipv4() {
                true => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                false => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            }
        };
        let mut sock = QuicSocket::new(&local, registry)?;

        let mut assigned_addrs = Vec::new();
        assigned_addrs.push(sock.local_addr());
        if let Some(addrs) = option.local_addresses.get(1..) {
            for local in addrs {
                let addr = sock.add(&SocketAddr::new(*local, 0), registry)?;
                assigned_addrs.push(addr);
            }
        }
        let sock = Rc::new(sock);

        let handlers = WorkerHandler::new(
            &option,
            &assigned_addrs,
            worker_ctx.clone(),
            senders.clone(),
        );

        Ok(Worker {
            option,
            endpoint: Endpoint::new(Box::new(config), false, Box::new(handlers), sock.clone()),
            poll,
            remote,
            sock,
            worker_ctx,
            client_ctx,
            senders,
            recv_buf: vec![0u8; MAX_BUF_SIZE],
            start_time: Instant::now(),
            end_time: None,
            terminated,
        })
    }

    /// Start the worker.
    pub fn start(&mut self) -> Result<()> {
        debug!("worker start, endpoint({:?})", self.endpoint.trace_id());

        self.start_time = Instant::now();
        let mut events = mio::Events::with_capacity(1024);
        loop {
            if self.process()? {
                debug!("worker tasks finished, exit");
                break;
            }

            let timeout = self
                .endpoint
                .timeout()
                .map(|v| cmp::max(v, TIMER_GRANULARITY));

            self.poll.poll(&mut events, timeout)?;

            // Process timeout events
            if events.is_empty() {
                self.endpoint.on_timeout(Instant::now());
                continue;
            }

            // Process IO events
            for event in events.iter() {
                if event.is_readable() {
                    self.process_read_event(event)?;
                }
            }
        }

        self.finish();

        Ok(())
    }

    fn should_exit(&self) -> bool {
        if self.terminated.load(Ordering::Relaxed) {
            info!("worker terminated by system signal and waiting for tasks to finish.");
            return true;
        }

        let worker_ctx = self.worker_ctx.borrow();
        debug!("worker concurrent conns {}", worker_ctx.concurrent_conns);

        if !worker_ctx.connected
            && worker_ctx.conn_finish_failed >= self.option.connection_failure_threshold
        {
            error!(
                "connect server[{:?}] failed",
                self.option.connect_to.unwrap()
            );
            return true;
        }

        if (self.option.duration > 0
            && (Instant::now() - self.start_time).as_secs() > self.option.duration)
            || (self.option.max_requests_per_thread > 0
                && worker_ctx.request_done >= self.option.max_requests_per_thread)
        {
            debug!(
                "worker should exit, concurrent conns {}, request sent {}, request done {}",
                worker_ctx.concurrent_conns, worker_ctx.request_sent, worker_ctx.request_done,
            );
            return true;
        }

        false
    }

    fn process(&mut self) -> Result<bool> {
        // Process connections.
        self.endpoint.process_connections()?;

        // Check exit.
        if self.should_exit() {
            // Close endpoint.
            self.endpoint.close(false);

            // Close connections.
            let mut senders = self.senders.borrow_mut();
            for (index, _) in senders.iter_mut() {
                let conn = self.endpoint.conn_get_mut(*index).unwrap();
                _ = conn.close(true, 0x00, b"ok");
            }

            // Update worker end time.
            if self.end_time.is_none() {
                debug!("all tasks finished, update the end time and wait for saving session.");
                self.end_time = Some(Instant::now());
            }

            if senders.len() == 0 {
                // All connections are closed.
                return Ok(true);
            }

            return Ok(false);
        }

        // Check and create new connections.
        self.create_new_conns()?;

        // Try to send requests.
        self.try_send_requests();

        Ok(false)
    }

    fn create_new_conns(&mut self) -> Result<()> {
        let mut worker_ctx = self.worker_ctx.borrow_mut();
        while worker_ctx.concurrent_conns < self.option.max_concurrent_conns {
            match self.endpoint.connect(
                self.sock.local_addr(),
                self.remote,
                self.option.urls[0].domain(),
                worker_ctx.session.as_deref(),
                None,
            ) {
                Ok(_) => {
                    worker_ctx.concurrent_conns += 1;
                    worker_ctx.conn_total += 1;
                }
                Err(e) => {
                    return Err(format!("connect error: {:?}", e).into());
                }
            };
        }

        Ok(())
    }

    fn try_send_requests(&mut self) {
        let mut senders = self.senders.borrow_mut();
        for (index, sender) in senders.iter_mut() {
            let conn = self.endpoint.conn_get_mut(*index).unwrap();
            sender.send_requests(conn);
        }
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

    fn finish(&mut self) {
        debug!("worker finished in {:?}", Instant::now() - self.start_time);

        let mut worker_ctx = self.worker_ctx.borrow_mut();
        let mut client_ctx = self.client_ctx.lock().unwrap();
        client_ctx.session = worker_ctx.session.clone();
        client_ctx.request_sent += worker_ctx.request_sent;
        client_ctx.request_done += worker_ctx.request_done;
        client_ctx.request_success += worker_ctx.request_success;
        client_ctx.conn_total += worker_ctx.conn_total;
        client_ctx.conn_handshake_success += worker_ctx.conn_handshake_success;
        client_ctx.conn_finish += worker_ctx.conn_finish;
        client_ctx.conn_finish_success += worker_ctx.conn_finish_success;
        client_ctx.conn_finish_failed += worker_ctx.conn_finish_failed;
        client_ctx
            .request_time_samples
            .append(&mut worker_ctx.request_time_samples);
        if self.end_time > client_ctx.end_time {
            client_ctx.end_time = self.end_time;
        }
        update_conn_stats(&mut client_ctx.conn_stats, &worker_ctx.conn_stats);
    }
}

/// Context used for single thread worker.
#[derive(Default)]
struct WorkerContext {
    session: Option<Vec<u8>>,
    request_sent: u64,
    request_done: u64,
    request_success: u64,
    max_sample: usize,
    request_time_samples: Vec<f64>,
    conn_total: u64,
    conn_handshake_success: u64,
    conn_finish: u64,
    conn_finish_success: u64,
    conn_finish_failed: u64,
    concurrent_conns: u32,
    conn_stats: ConnectionStats,
    connected: bool,
}

impl WorkerContext {
    fn with_option(option: &ClientOpt) -> Self {
        let mut worker_ctx = WorkerContext {
            max_sample: option.max_sample,
            ..Default::default()
        };

        if let Some(session_file) = &option.session_file {
            if let Ok(session_data) = std::fs::read(session_file) {
                worker_ctx.session = Some(session_data);
            } else {
                debug!("no session file {:?}", option.session_file);
            }
        }

        worker_ctx
    }
}

struct Request {
    url: Url,
    line: String,         // Used in http/0.9.
    headers: Vec<Header>, // Used in h3.
    response_writer: Option<std::io::BufWriter<std::fs::File>>,
    start_time: Option<Instant>,
}

impl Request {
    /// Make a response body writer.
    /// The name of file is same as the URL's last path segment.
    fn make_response_writer(url: &Url, target_path: &Option<String>) -> Option<BufWriter<File>> {
        if let Some(target_path) = target_path {
            let f = match url.path_segments().map(|c| c.collect::<Vec<_>>()) {
                Some(f) => f,
                None => {
                    error!("make response writer failed, url {:?}", url);
                    return None;
                }
            };
            let f = match f.iter().last() {
                Some(f) => f,
                None => {
                    error!("make response writer failed, url {:?}", url);
                    return None;
                }
            };

            let path = format!("{}/{}", target_path, f,);
            match File::create(path) {
                Ok(f) => Some(BufWriter::new(f)),
                Err(e) => {
                    error!("create file error {:?}, url {:?}", e, url);
                    None
                }
            }
        } else {
            None
        }
    }

    // TODO: support custom headers.
    fn new(method: &str, url: &Url, body: &Option<Vec<u8>>, dump_dir: &Option<String>) -> Self {
        let authority = match url.port() {
            Some(port) => format!("{}:{}", url.host_str().unwrap(), port),
            None => url.host_str().unwrap().to_string(),
        };

        let mut headers = vec![
            tquic::h3::Header::new(b":method", method.as_bytes()),
            tquic::h3::Header::new(b":scheme", url.scheme().as_bytes()),
            tquic::h3::Header::new(b":authority", authority.as_bytes()),
            tquic::h3::Header::new(b":path", url[url::Position::BeforePath..].as_bytes()),
            tquic::h3::Header::new(b"user-agent", b"tquic"),
        ];
        if body.is_some() {
            headers.push(tquic::h3::Header::new(
                b"content-length",
                body.as_ref().unwrap().len().to_string().as_bytes(),
            ));
        }
        Self {
            url: url.clone(),
            line: format!("GET {}\r\n", url.path()),
            headers,
            response_writer: Self::make_response_writer(url, dump_dir),
            start_time: None,
        }
    }
}

/// Used for sending http/0.9 or h3 requests. One connection has only one request sender.
struct RequestSender {
    /// Sender option.
    option: ClientOpt,

    /// Current index of URLs.
    current_url_idx: usize,

    /// Concurrent requests of this sender.
    concurrent_requests: u64,

    /// Requests already sent of this sender.
    request_sent: u64,

    /// Requests already done of this sender.
    request_done: u64,

    /// Read buffer.
    buf: Vec<u8>,

    /// Mapping stream id to request.
    streams: FxHashMap<u64, Request>,

    /// Worker context.
    worker_ctx: Rc<RefCell<WorkerContext>>,

    /// Application protocol, http/0.9 or h3.
    app_proto: ApplicationProto,

    /// Next available stream id, used in http/0.9 mode.
    next_stream_id: u64,

    /// H3 connection, used in h3 mode.
    h3_conn: Option<Http3Connection>,
}

impl RequestSender {
    /// Create a new request sender.
    pub fn new(
        option: &ClientOpt,
        conn: &mut Connection,
        worker_ctx: Rc<RefCell<WorkerContext>>,
    ) -> Self {
        let mut sender = Self {
            option: option.clone(),
            current_url_idx: 0,
            concurrent_requests: 0,
            request_sent: 0,
            request_done: 0,
            buf: vec![0; MAX_BUF_SIZE],
            streams: FxHashMap::default(),
            worker_ctx,
            app_proto: ApplicationProto::from_slice(conn.application_proto()),
            next_stream_id: 0,
            h3_conn: None,
        };

        if sender.app_proto == ApplicationProto::H3 {
            sender.h3_conn = Some(
                Http3Connection::new_with_quic_conn(conn, &Http3Config::new().unwrap()).unwrap(),
            );
        }

        sender
    }

    /// Send requests.
    pub fn send_requests(&mut self, conn: &mut Connection) {
        debug!(
            "{} send requests {} {} {} {}",
            conn.trace_id(),
            self.concurrent_requests,
            self.option.max_concurrent_requests,
            self.request_sent,
            self.option.max_requests_per_conn
        );

        while self.concurrent_requests < self.option.max_concurrent_requests
            && (self.option.max_requests_per_conn == 0
                || self.request_sent < self.option.max_requests_per_conn)
        {
            if let Err(e) = self.send_request(conn) {
                error!("{} send request error {}", conn.trace_id(), e);
                break;
            }
        }
    }

    /// Receive responses.
    pub fn recv_responses(&mut self, conn: &mut Connection, stream_id: u64) {
        if self.streams.get_mut(&stream_id).is_none() {
            debug!("{} stream {} request not exist", conn.trace_id(), stream_id);
            return;
        }

        _ = conn.stream_want_read(stream_id, true);

        match self.app_proto {
            ApplicationProto::Interop | ApplicationProto::Http09 => {
                self.recv_http09_responses(conn, stream_id)
            }
            ApplicationProto::H3 => self.recv_h3_responses(conn, stream_id),
        }
    }

    fn send_request(&mut self, conn: &mut Connection) -> Result<()> {
        let url = &self.option.urls[self.current_url_idx];
        let mut request = Request::new("GET", url, &None, &self.option.dump_dir);
        debug!(
            "{} send request {} current index {}",
            conn.trace_id(),
            url,
            self.current_url_idx
        );

        let s = match self.app_proto {
            ApplicationProto::Interop | ApplicationProto::Http09 => {
                self.send_http09_request(conn, &request)?
            }
            ApplicationProto::H3 => self.send_h3_request(conn, &request)?,
        };

        request.start_time = Some(Instant::now());
        self.streams.insert(s, request);
        self.current_url_idx += 1;
        if self.current_url_idx == self.option.urls.len() {
            self.current_url_idx = 0;
        }
        self.concurrent_requests += 1;
        self.request_sent += 1;
        let mut worker_ctx = self.worker_ctx.borrow_mut();
        worker_ctx.request_sent += 1;

        Ok(())
    }

    fn send_http09_request(&mut self, conn: &mut Connection, request: &Request) -> Result<u64> {
        let s = self.next_stream_id;
        match conn.stream_write(
            self.next_stream_id,
            Bytes::copy_from_slice(request.line.as_bytes()),
            true,
        ) {
            Ok(v) => v,
            Err(tquic::error::Error::StreamLimitError) => {
                return Err("stream limit reached".to_string().into());
            }
            Err(e) => {
                return Err(
                    format!("failed to send request {:?}, error: {:?}", request.url, e).into(),
                );
            }
        };
        self.next_stream_id += 4;
        Ok(s)
    }

    fn send_h3_request(&mut self, conn: &mut Connection, request: &Request) -> Result<u64> {
        let s = match self.h3_conn.as_mut().unwrap().stream_new(conn) {
            Ok(v) => v,
            Err(tquic::h3::Http3Error::TransportError(Error::StreamLimitError)) => {
                return Err("stream limit reached".to_string().into());
            }
            Err(e) => {
                return Err(
                    format!("failed to create stream {:?}, error: {:?}", request.url, e).into(),
                );
            }
        };

        match self
            .h3_conn
            .as_mut()
            .unwrap()
            .send_headers(conn, s, &request.headers, true)
        {
            Ok(v) => v,
            Err(tquic::h3::Http3Error::StreamBlocked) => {
                return Err("stream is blocked".to_string().into());
            }
            Err(e) => {
                return Err(
                    format!("failed to send request {:?}, error: {:?}", request.url, e).into(),
                );
            }
        };

        Ok(s)
    }

    fn sample_request_time(request: &Request, worker_ctx: &mut RefMut<WorkerContext>) {
        if let Some(start_time) = request.start_time {
            let request_time = Instant::now() - start_time;
            if worker_ctx.request_time_samples.len() < worker_ctx.max_sample {
                worker_ctx
                    .request_time_samples
                    .push(request_time.as_micros() as f64);
                return;
            }

            if rand::thread_rng().gen_range(0..=1) == 0 {
                return;
            }

            let n = rand::thread_rng().gen_range(0..worker_ctx.request_time_samples.len());
            worker_ctx.request_time_samples[n] = request_time.as_micros() as f64;
        }
    }

    fn print_headers(headers: &Vec<Header>) {
        for header in headers {
            let k = String::from_utf8(header.name().to_vec());
            let v = String::from_utf8(header.value().to_vec());
            if k.is_err() || v.is_err() {
                continue;
            }
            println!("{}: {}", k.unwrap(), v.unwrap());
        }
    }

    fn print_body(buf: &[u8]) {
        if let Ok(data) = String::from_utf8(buf.to_vec()) {
            print!("{}", data);
        }
    }

    fn recv_http09_responses(&mut self, conn: &mut Connection, stream_id: u64) {
        let mut worker_ctx = self.worker_ctx.borrow_mut();
        while let Ok((read, fin)) = conn.stream_read(stream_id, &mut self.buf) {
            debug!("{} received {} bytes", conn.trace_id(), read);

            let stream_buf = &self.buf[..read];
            debug!(
                "{} stream {} has {} bytes (fin? {})",
                conn.trace_id(),
                stream_id,
                stream_buf.len(),
                fin
            );

            let request = self.streams.get_mut(&stream_id).unwrap();
            if let Some(writer) = &mut request.response_writer {
                _ = writer.write_all(&self.buf[..read]);
            }
            if self.option.print_res {
                Self::print_body(&self.buf[..read]);
            }

            if stream_id % 4 == 0 && fin {
                debug!(
                    "{} done requests {}, total {}",
                    conn.trace_id(),
                    self.request_done,
                    self.option.max_requests_per_conn
                );

                self.request_done += 1;
                self.concurrent_requests -= 1;
                worker_ctx.request_success += 1;
                worker_ctx.request_done += 1;
                Self::sample_request_time(request, &mut worker_ctx);
                self.streams.remove(&stream_id);
            }
        }
    }

    fn recv_h3_responses(&mut self, conn: &mut Connection, _stream_id: u64) {
        let mut worker_ctx = self.worker_ctx.borrow_mut();
        let h3_conn = self.h3_conn.as_mut().unwrap();
        loop {
            match h3_conn.poll(conn) {
                Ok((stream_id, tquic::h3::Http3Event::Headers { headers, .. })) => {
                    debug!(
                        "{} got response headers {:?} on stream id {}",
                        conn.trace_id(),
                        headers,
                        stream_id
                    );
                    if self.option.print_res {
                        Self::print_headers(&headers);
                    }
                }
                Ok((stream_id, tquic::h3::Http3Event::Data)) => {
                    while let Ok(read) = h3_conn.recv_body(conn, stream_id, &mut self.buf) {
                        debug!(
                            "{} got {} bytes of response data on stream {}",
                            conn.trace_id(),
                            read,
                            stream_id
                        );

                        let request = self.streams.get_mut(&stream_id).unwrap();
                        if let Some(writer) = &mut request.response_writer {
                            _ = writer.write_all(&self.buf[..read]);
                        }
                        if self.option.print_res {
                            Self::print_body(&self.buf[..read]);
                        }
                    }
                }
                Ok((stream_id, tquic::h3::Http3Event::Finished)) => {
                    debug!(
                        "{} done requests {}, total {}",
                        conn.trace_id(),
                        self.request_done,
                        self.option.max_requests_per_conn
                    );

                    self.request_done += 1;
                    self.concurrent_requests -= 1;
                    worker_ctx.request_success += 1;
                    worker_ctx.request_done += 1;
                    let request = self.streams.get_mut(&stream_id).unwrap();
                    Self::sample_request_time(request, &mut worker_ctx);
                    self.streams.remove(&stream_id);
                }
                Ok((stream_id, tquic::h3::Http3Event::Reset(e))) => {
                    error!(
                        "{} request was reset by peer with {}, close connection, done requests {}, total {}",
                        conn.trace_id(),
                        e,
                        self.request_done,
                        self.option.max_requests_per_conn
                    );

                    self.request_done += 1;
                    self.concurrent_requests -= 1;
                    worker_ctx.request_done += 1;
                    worker_ctx.concurrent_conns -= 1;
                    self.streams.remove(&stream_id);

                    match conn.close(true, 0x00, b"stream reset") {
                        Ok(_) | Err(Error::Done) => (),
                        Err(e) => panic!("error closing conn: {:?}", e),
                    }
                    return;
                }
                Ok((prioritized_element_id, tquic::h3::Http3Event::PriorityUpdate)) => {
                    debug!(
                        "{} PRIORITY_UPDATE triggered for element ID={}",
                        conn.trace_id(),
                        prioritized_element_id
                    );
                }
                Ok((goaway_id, tquic::h3::Http3Event::GoAway)) => {
                    debug!("{} got GOAWAY with ID {} ", conn.trace_id(), goaway_id);
                }
                Err(tquic::h3::Http3Error::Done) => {
                    return;
                }
                Err(e) => {
                    error!("{} HTTP/3 processing failed: {:?}", conn.trace_id(), e);
                    return;
                }
            }
        }
    }
}

struct WorkerHandler {
    /// Worker option.
    option: ClientOpt,

    /// Worker context.
    worker_ctx: Rc<RefCell<WorkerContext>>,

    /// Mapping connection index to request sender.
    senders: Rc<RefCell<FxHashMap<u64, RequestSender>>>,

    /// Remote server.
    remote: SocketAddr,

    /// Local address list
    local_addresses: Vec<SocketAddr>,
}

impl WorkerHandler {
    fn new(
        option: &ClientOpt,
        local_addresses: &[SocketAddr],
        worker_ctx: Rc<RefCell<WorkerContext>>,
        senders: Rc<RefCell<FxHashMap<u64, RequestSender>>>,
    ) -> Self {
        Self {
            option: option.clone(),
            worker_ctx,
            senders,
            remote: option.connect_to.unwrap(),
            local_addresses: local_addresses.to_owned(),
        }
    }

    fn try_new_request_sender(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap();
        let mut senders = self.senders.borrow_mut();
        let sender = senders.get(&index);
        if sender.is_some() {
            return;
        }

        let sender = RequestSender::new(&self.option, conn, self.worker_ctx.clone());
        senders.insert(index, sender);
    }

    fn try_close_conn(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap();
        let senders = self.senders.borrow_mut();
        let sender = senders.get(&index);
        if let Some(s) = sender {
            if s.request_done == s.option.max_requests_per_conn && !conn.is_closing() {
                let mut worker_ctx = self.worker_ctx.borrow_mut();
                worker_ctx.concurrent_conns -= 1;
                debug!(
                    "{} all requests finished, close connection",
                    conn.trace_id()
                );
                match conn.close(true, 0x00, b"ok") {
                    Ok(_) | Err(Error::Done) => (),
                    Err(e) => panic!("error closing conn: {:?}", e),
                }
            }
        }
    }

    fn try_send_request(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap();
        let mut senders = self.senders.borrow_mut();
        let sender = senders.get_mut(&index);
        if let Some(s) = sender {
            s.send_requests(conn);
        } else {
            error!("{} sender not exist", conn.trace_id());
        }
    }
}

impl TransportHandler for WorkerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        debug!("{} connection is created", conn.trace_id());

        if let Some(keylog_file) = &self.option.keylog_file {
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

        if let Some(qlog_dir) = &self.option.qlog_dir {
            let qlog_file = format!("{}.qlog", conn.trace_id());
            let qlog_file = Path::new(qlog_dir).join(qlog_file);
            if let Ok(qlog) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(qlog_file.as_path())
            {
                conn.set_qlog(
                    Box::new(qlog),
                    "client qlog".into(),
                    format!("id={}", conn.trace_id()),
                );
            } else {
                error!("{} set qlog {:?} failed", conn.trace_id(), qlog_file);
            }
        }

        if conn.is_in_early_data() {
            self.try_new_request_sender(conn);
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        debug!(
            "{} connection is established, is_resumed: {}",
            conn.trace_id(),
            conn.is_resumed()
        );
        {
            let mut worker_ctx = self.worker_ctx.borrow_mut();
            worker_ctx.conn_handshake_success += 1;
            worker_ctx.connected = true;
        }

        // Try to add additional paths
        if let Some(addrs) = self.local_addresses.get(1..) {
            for local in addrs {
                match conn.add_path(*local, self.remote) {
                    Ok(_) => debug!(
                        "{} add new path {}-{}",
                        conn.trace_id(),
                        *local,
                        self.remote
                    ),
                    Err(e) => debug!(
                        "{} fail to add path {}-{}: {}",
                        conn.trace_id(),
                        *local,
                        self.remote,
                        e
                    ),
                }
            }
        }

        self.try_new_request_sender(conn);
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        debug!("{} connection is closed", conn.trace_id());

        let mut worker_ctx = self.worker_ctx.borrow_mut();
        update_conn_stats(&mut worker_ctx.conn_stats, conn.stats());

        let mut senders = self.senders.borrow_mut();
        senders.remove(&conn.index().unwrap());

        if self.option.session_file.is_some() {
            debug!(
                "{} session resumption enabled, save session to context",
                conn.trace_id()
            );
            if let Some(session) = conn.session() {
                worker_ctx.session = Some(session.to_vec());
            }
        }
        worker_ctx.conn_finish += 1;

        if conn.local_error().is_some() && conn.local_error().unwrap().is_app {
            // If connection is closed by local, concurrent_conns counter
            // is already decreased when connection close() is called.
            worker_ctx.conn_finish_success += 1;
            return;
        }

        if conn.peer_error().is_some() && conn.peer_error().unwrap().is_app {
            worker_ctx.concurrent_conns -= 1;
            worker_ctx.conn_finish_success += 1;
            return;
        }

        debug!(
            "{} connection failed, local error: {:?}, peer error: {:?}, idle timeout {}, handshake timeout {}",
            conn.trace_id(),
            conn.local_error(),
            conn.peer_error(),
            conn.is_idle_timeout(),
            conn.is_handshake_timeout()
        );
        worker_ctx.conn_finish_failed += 1;
        worker_ctx.concurrent_conns -= 1;
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is created", conn.trace_id(), stream_id);
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        _ = conn.stream_want_read(stream_id, false);

        let index = conn.index().unwrap();
        let mut senders = self.senders.borrow_mut();
        let sender = senders.get_mut(&index);
        if let Some(s) = sender {
            s.recv_responses(conn, stream_id);
        } else {
            debug!("{} stream {} sender not exist", conn.trace_id(), stream_id);
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        _ = conn.stream_want_write(stream_id, false);
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is closed", conn.trace_id(), stream_id);

        self.try_send_request(conn);
        self.try_close_conn(conn);
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}

fn process_connect_address(option: &mut ClientOpt) {
    if option.connect_to.is_none() {
        option.connect_to = option.urls[0].to_socket_addrs().unwrap().next();
    }

    let remote = option.connect_to.as_mut().unwrap();
    if remote.is_ipv4() && remote.ip() == Ipv4Addr::UNSPECIFIED {
        remote.set_ip(Ipv4Addr::LOCALHOST.into());
    } else if remote.is_ipv6() && remote.ip() == Ipv6Addr::UNSPECIFIED {
        remote.set_ip(Ipv6Addr::LOCALHOST.into());
    }
}

fn parse_option() -> std::result::Result<ClientOpt, clap::error::Error> {
    let mut option = ClientOpt::parse();

    if option.urls.is_empty() {
        return Err(ClientOpt::command().error(
            ErrorKind::MissingRequiredArgument,
            "Specify at least one request URL",
        ));
    }

    if option.max_requests_per_conn != 0 {
        option.max_requests_per_conn = max(option.max_requests_per_conn, option.urls.len() as u64);
    }

    if option.max_requests_per_thread != 0 {
        option.max_requests_per_thread =
            max(option.max_requests_per_thread, option.urls.len() as u64);
    }

    Ok(option)
}

fn process_option(option: &mut ClientOpt) -> Result<()> {
    env_logger::builder()
        .target(tquic_tools::log_target(&option.log_file)?)
        .filter_level(option.log_level)
        .format_timestamp_millis()
        .init();

    if let Some(dump_dir) = &option.dump_dir {
        if let Err(e) = create_dir_all(dump_dir) {
            warn!("create dump directory {} error: {:?}", dump_dir, e);
            return Err(Box::new(e));
        }
    }

    if let Some(qlog_dir) = &option.qlog_dir {
        if let Err(e) = create_dir_all(qlog_dir) {
            warn!("create qlog directory {} error: {:?}", qlog_dir, e);
            return Err(Box::new(e));
        }
    }

    process_connect_address(option);
    Ok(())
}

fn main() -> Result<()> {
    // Parse client option.
    let mut option = match parse_option() {
        Ok(option) => option,
        Err(e) => e.exit(),
    };

    // Process client option.
    process_option(&mut option)?;

    // Create client.
    let mut client = Client::new(option)?;

    // Start client.
    client.start();

    Ok(())
}
