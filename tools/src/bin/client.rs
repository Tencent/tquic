use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use clap::Parser;
use log::{debug, error, info};
use mio::{Events, Poll, Token};

use tquic::{
    Config, CongestionControlAlgorithm, Connection, Endpoint, PacketInfo, TlsConfig,
    TransportHandler,
};
use tquic_tools::QuicSocket;
use tquic_tools::Result;
const CLIENT_TOKEN: Token = Token(0);

#[derive(Parser, Debug)]
#[clap(
    name = "datagram_client",
    version = "1.0",
    author = "The TQUIC Authors"
)]
struct Args {
    /// Server's address.
    #[clap(short, default_value = "127.0.0.1:4433", long, value_name = "ADDR")]
    pub connect_to: Option<SocketAddr>,

    /// Local address to bind to. e.g. 0.0.0.0:0
    #[clap(long, default_value = "0.0.0.0:0")]
    local_addr: SocketAddr,

    // --- Protocol Settings ---
    #[clap(help_heading = "Protocol")]
    /// ALPN, separated by ",". e.g. echo,quic-datagram
    #[clap(
        long,
        value_delimiter = ',',
        default_value = "echo",
        value_name = "STR"
    )]
    alpn: Vec<String>,

    #[clap(help_heading = "Protocol")]
    /// Connection idle timeout in milliseconds.
    #[clap(long, default_value = "30000", value_name = "TIME")]
    idle_timeout: u64,

    #[clap(help_heading = "Protocol")]
    /// Handshake timeout in milliseconds.
    #[clap(long, default_value = "10000", value_name = "TIME")]
    handshake_timeout: u64,

    #[clap(help_heading = "Protocol")]
    /// Initial RTT in milliseconds.
    #[clap(long, default_value = "100", value_name = "TIME")]
    initial_rtt: u64,

    #[clap(help_heading = "Protocol")]
    /// Set max_datagram_frame_size transport parameter.
    #[clap(long, default_value = "1200", value_name = "NUM")]
    max_datagram_frame_size: u64,

    #[clap(help_heading = "Protocol")]
    /// Congestion control algorithm.
    #[clap(long, value_enum, default_value = "bbr")]
    congestion_control_algor: CongestionControlAlgorithm,

    // --- Datagram Control ---
    #[clap(help_heading = "Datagram Control")]
    /// Total number of datagrams to send.
    #[clap(long, default_value = "10", value_name = "NUM")]
    message_count: usize,

    #[clap(help_heading = "Datagram Control")]
    /// Interval between sending datagrams in milliseconds.
    #[clap(long, default_value = "1000", value_name = "TIME")]
    message_interval: u64,

    // --- Output ---
    #[clap(help_heading = "Output")]
    /// Log level.
    #[clap(long, value_enum, default_value = "info")]
    log_level: log::LevelFilter,

    #[clap(help_heading = "Output")]
    /// Save TLS key log into the given file.
    #[clap(long, value_name = "FILE")]
    keylog_file: Option<String>,

    #[clap(help_heading = "Output")]
    /// Directory to save qlog files.
    #[clap(long, value_name = "DIR")]
    qlog_dir: Option<String>,

    #[clap(help_heading = "Session Resumption")]
    /// File to read/write session resumption data.
    #[clap(long, value_name = "FILE")]
    session_file: Option<String>,

    // --- Packet Loss Test ---
    #[clap(help_heading = "Packet Loss Test")]
    /// Enable packet loss test mode.
    #[clap(long)]
    test_loss: bool,

    #[clap(help_heading = "Packet Loss Test")]
    /// Number of test packets to expect (default: 1000).
    #[clap(long, default_value = "1000", value_name = "NUM")]
    test_count: usize,

    #[clap(help_heading = "Packet Loss Test")]
    /// Use stream instead of datagram for test.
    #[clap(long)]
    test_stream: bool,

    #[clap(help_heading = "Packet Loss Test")]
    /// Test packet send interval in milliseconds (default: 50).
    #[clap(long, default_value = "50", value_name = "TIME")]
    test_interval: u64,

    // --- Priority Test ---
    #[clap(help_heading = "Priority Test")]
    /// Enable priority test mode.
    #[clap(long)]
    test_priority: bool,
}

struct DatagramClient {
    endpoint: Endpoint,
    poll: Poll,
    socket: Rc<QuicSocket>,
    recv_buf: Vec<u8>,
    conn_id: u64,
    // Store control parameters directly from Args
    message_count: usize,
    message_interval: Duration,
    // Packet loss test parameters
    test_loss: bool,
    test_stream: bool,
    // Priority test parameters
    test_priority: bool,
}

impl DatagramClient {
    fn new(args: &Args) -> Result<Self> {
        let mut quic_config = Config::new()?;

        // Apply settings from command-line arguments
        quic_config.set_max_idle_timeout(args.idle_timeout);
        quic_config.set_max_handshake_timeout(args.handshake_timeout);
        quic_config.set_initial_rtt(args.initial_rtt);
        quic_config.set_max_datagram_frame_size(args.max_datagram_frame_size);
        quic_config.set_congestion_control_algorithm(args.congestion_control_algor);

        let alpns: Vec<Vec<u8>> = args.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        debug!("Using ALPNs: {:?}", args.alpn);

        let tls_config = TlsConfig::new_client_config(alpns, true)?;
        quic_config.set_tls_config(tls_config);

        let poll = Poll::new()?;
        let socket_rc = Rc::new(QuicSocket::new(&args.local_addr, poll.registry())?);

        // Pass qlog and keylog options to the handler
        let handler = if args.test_priority {
            ClientHandler::new_priority_mode(
                args.qlog_dir.clone(),
                args.keylog_file.clone(),
                args.session_file.clone(),
            )
        } else if args.test_loss {
            ClientHandler::new_test_mode(
                args.qlog_dir.clone(),
                args.keylog_file.clone(),
                args.session_file.clone(),
                args.test_stream,
            )
        } else {
            ClientHandler::new(
                args.qlog_dir.clone(),
                args.keylog_file.clone(),
                args.session_file.clone(),
            )
        };
        let mut endpoint = Endpoint::new(
            Box::new(quic_config),
            false,
            Box::new(handler),
            socket_rc.clone(),
        );

        // Read session data from file if 0-RTT is enabled and session file exists
        let session_data = if let Some(ref session_file) = args.session_file {
            match std::fs::read(session_file) {
                Ok(data) => {
                    info!("Loaded session data from {}", session_file);
                    Some(data)
                }
                Err(e) => {
                    debug!("Could not read session file {}: {}", session_file, e);
                    None
                }
            }
        } else {
            None
        };

        let remote = args.connect_to.unwrap();
        let conn_id = endpoint
            .connect(
                socket_rc.local_addr(),
                remote,
                Some("localhost"), // Use a fixed SNI for simplicity
                session_data.as_deref(),
                None,
                None,
            )
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Failed to connect: {}", e))
            })?;

        debug!(
            "Connecting to {} from {} with conn_id {}",
            args.connect_to.unwrap(),
            socket_rc.local_addr(),
            conn_id
        );

        Ok(Self {
            endpoint,
            poll,
            socket: socket_rc,
            recv_buf: vec![0u8; 65536],
            conn_id,
            message_count: args.message_count,
            message_interval: Duration::from_millis(args.message_interval),
            test_loss: args.test_loss,
            test_stream: args.test_stream,
            test_priority: args.test_priority,
        })
    }

    fn run(&mut self) -> Result<()> {
        let mut events = Events::with_capacity(1024);
        let mut messages_sent = 0;
        let start_time = Instant::now();
        let mut next_send_time = Instant::now();

        loop {
            // Drive the QUIC engine state machine
            if let Err(e) = self.endpoint.process_connections() {
                error!("Error processing connections: {}", e);
                break;
            }

            let now = Instant::now();

            let endpoint_timeout = self.endpoint.timeout();
            let timeout = match (
                endpoint_timeout,
                Some(next_send_time.saturating_duration_since(now)),
            ) {
                (Some(ep_timeout), Some(send_timeout)) => Some(ep_timeout.min(send_timeout)),
                (Some(ep_timeout), None) => Some(ep_timeout),
                (None, Some(send_timeout)) => Some(send_timeout),
                (None, None) => None,
            };

            // Wait for events
            self.poll.poll(&mut events, timeout)?;

            // Process I/O events
            for event in events.iter() {
                if event.token() == CLIENT_TOKEN && event.is_readable() {
                    self.handle_readable_event()?;
                }
            }

            // Process timeout events
            self.endpoint.on_timeout(Instant::now());

            if let Some(conn) = self.endpoint.conn_get_mut(self.conn_id) {
                if conn.is_closed() {
                    debug!("Connection closed, exiting gracefully.");
                    break;
                }

                // Try to send a datagram if we're in early data mode or connected and the interval has passed
                if messages_sent < self.message_count
                    && now >= next_send_time
                    && conn.is_datagram_enabled()
                {
                    let payload = format!("Datagram {}", messages_sent + 1).into_bytes();

                    let payload_bytes = Bytes::from(payload);
                    let len = payload_bytes.len();
                    match conn.send_datagram(payload_bytes) {
                        Ok(datagram_id) => {
                            info!(
                                "Sent datagram {} ({} bytes) - time: {:?} id {}",
                                messages_sent + 1,
                                len,
                                start_time.elapsed(),
                                datagram_id
                            );
                            messages_sent += 1;
                            next_send_time = now + self.message_interval;
                        }
                        Err(e) => {
                            error!("Failed to send datagram: {}", e);
                            break;
                        }
                    }
                }

                // Process received datagrams
                while let Some(dgram) = conn.recv_datagram() {
                    info!(
                        "Received echo datagram ({} bytes): {}",
                        dgram.len(),
                        String::from_utf8_lossy(&dgram).trim_end_matches('\0')
                    );
                }

                // After sending all messages and emptying the queue, close the connection
                if messages_sent == self.message_count
                    && conn.datagram_stats().outgoing_queue_size == 0
                {
                    if !conn.is_closing() {
                        debug!("All datagrams sent from queue, closing connection.");
                        conn.close(true, 0x00, b"done").ok();
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_readable_event(&mut self) -> io::Result<()> {
        loop {
            match self.socket.recv_from(&mut self.recv_buf, CLIENT_TOKEN) {
                Ok((len, local, remote)) => {
                    let pkt_info = PacketInfo {
                        src: remote,
                        dst: local,
                        time: Instant::now(),
                    };
                    if let Err(e) = self.endpoint.recv(&mut self.recv_buf[..len], &pkt_info) {
                        debug!("Failed to process packet: {}", e);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("Socket recv error: {}", e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn run_packet_loss_test(&mut self) -> Result<()> {
        let mut events = Events::with_capacity(1024);

        info!(
            "Starting packet loss test mode (expecting {} data)",
            if self.test_stream {
                "stream"
            } else {
                "datagram"
            }
        );

        loop {
            // Drive the QUIC engine state machine
            if let Err(e) = self.endpoint.process_connections() {
                error!("Error processing connections: {}", e);
                break;
            }

            let endpoint_timeout = self.endpoint.timeout();

            // Wait for events
            self.poll.poll(&mut events, endpoint_timeout)?;

            // Process I/O events
            for event in events.iter() {
                if event.token() == CLIENT_TOKEN && event.is_readable() {
                    self.handle_readable_event()?;
                }
            }

            // Process timeout events
            self.endpoint.on_timeout(Instant::now());

            if let Some(conn) = self.endpoint.conn_get_mut(self.conn_id) {
                if conn.is_closed() {
                    debug!("Connection closed, exiting gracefully.");
                    break;
                }
                // All data processing is now handled by the ClientHandler
            }
        }

        info!("Packet loss test completed.");
        Ok(())
    }

    fn run_priority_test(&mut self) -> Result<()> {
        let mut events = Events::with_capacity(1024);

        info!("Starting priority test mode (expecting datagram data with priorities)");

        loop {
            // Drive the QUIC engine state machine
            if let Err(e) = self.endpoint.process_connections() {
                error!("Error processing connections: {}", e);
                break;
            }

            let endpoint_timeout = self.endpoint.timeout();

            // Wait for events
            self.poll.poll(&mut events, endpoint_timeout)?;

            // Process I/O events
            for event in events.iter() {
                if event.token() == CLIENT_TOKEN && event.is_readable() {
                    self.handle_readable_event()?;
                }
            }

            // Process timeout events
            self.endpoint.on_timeout(Instant::now());

            if let Some(conn) = self.endpoint.conn_get_mut(self.conn_id) {
                if conn.is_closed() {
                    debug!("Connection closed, exiting gracefully.");
                    break;
                }
                // All data processing is now handled by the ClientHandler
            }
        }

        info!("Priority test completed.");
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TestPacketInfo {
    packet_num: u32,
    send_timestamp: u64,
    recv_timestamp: u64,
    delay: u64,
}

struct ClientHandler {
    qlog_dir: Option<String>,
    keylog_file: Option<String>,
    session_file: Option<String>,
    // Test mode fields
    test_mode: bool,
    test_stream: bool,
    test_priority: bool,
    output_file: Option<fs::File>,
    first_packet_received: bool,
    packets_received: usize,
    // Statistics collection
    received_packets: HashMap<u32, TestPacketInfo>,
    // Priority test specific
    high_priority_packets: Vec<TestPacketInfo>,
    low_priority_packets: Vec<TestPacketInfo>,
}

impl ClientHandler {
    fn new(
        qlog_dir: Option<String>,
        keylog_file: Option<String>,
        session_file: Option<String>,
    ) -> Self {
        Self {
            qlog_dir,
            keylog_file,
            session_file,
            test_mode: false,
            test_stream: false,
            test_priority: false,
            output_file: None,
            first_packet_received: false,
            packets_received: 0,
            received_packets: HashMap::new(),
            high_priority_packets: Vec::new(),
            low_priority_packets: Vec::new(),
        }
    }

    fn new_test_mode(
        qlog_dir: Option<String>,
        keylog_file: Option<String>,
        session_file: Option<String>,
        test_stream: bool,
    ) -> Self {
        Self {
            qlog_dir,
            keylog_file,
            session_file,
            test_mode: true,
            test_stream,
            test_priority: false,
            output_file: None,
            first_packet_received: false,
            packets_received: 0,
            received_packets: HashMap::new(),
            high_priority_packets: Vec::new(),
            low_priority_packets: Vec::new(),
        }
    }

    fn new_priority_mode(
        qlog_dir: Option<String>,
        keylog_file: Option<String>,
        session_file: Option<String>,
    ) -> Self {
        Self {
            qlog_dir,
            keylog_file,
            session_file,
            test_mode: false,
            test_stream: false,
            test_priority: true,
            output_file: None,
            first_packet_received: false,
            packets_received: 0,
            received_packets: HashMap::new(),
            high_priority_packets: Vec::new(),
            low_priority_packets: Vec::new(),
        }
    }

    fn parse_packet_data(&self, data: &str) -> Option<(u32, u64)> {
        // Parse "Packet N Timestamp T" format
        let parts: Vec<&str> = data.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == "Packet" && parts[2] == "Timestamp" {
            if let (Ok(packet_num), Ok(timestamp)) =
                (parts[1].parse::<u32>(), parts[3].parse::<u64>())
            {
                return Some((packet_num, timestamp));
            }
        }
        None
    }

    fn generate_statistics(&self, total_sent: u32) -> String {
        let mut stats = String::new();

        // Basic statistics
        let received_count = self.received_packets.len();
        let lost_count = total_sent as usize - received_count;
        let loss_rate = if total_sent > 0 {
            (lost_count as f64 / total_sent as f64) * 100.0
        } else {
            0.0
        };

        stats.push_str(&format!("\n=== Packet Loss Test Statistics ===\n"));
        stats.push_str(&format!("Total packets sent: {}\n", total_sent));
        stats.push_str(&format!("Total packets received: {}\n", received_count));
        stats.push_str(&format!("Total packets lost: {}\n", lost_count));
        stats.push_str(&format!("Packet loss rate: {:.2}%\n", loss_rate));

        if !self.received_packets.is_empty() {
            // Delay statistics with packet sequence numbers
            let mut min_delay = u64::MAX;
            let mut max_delay = 0u64;
            let mut min_delay_seq = 0u32;
            let mut max_delay_seq = 0u32;
            let mut total_delay = 0u64;

            for (&seq, packet) in &self.received_packets {
                total_delay += packet.delay;
                if packet.delay < min_delay {
                    min_delay = packet.delay;
                    min_delay_seq = seq;
                }
                if packet.delay > max_delay {
                    max_delay = packet.delay;
                    max_delay_seq = seq;
                }
            }

            let avg_delay = total_delay as f64 / self.received_packets.len() as f64;

            stats.push_str(&format!(
                "Min delay: {}ms (Packet #{})\n",
                min_delay, min_delay_seq
            ));
            stats.push_str(&format!(
                "Max delay: {}ms (Packet #{})\n",
                max_delay, max_delay_seq
            ));
            stats.push_str(&format!("Average delay: {:.2}ms\n", avg_delay));

            // Missing packets
            let mut missing_packets = Vec::new();
            for i in 1..=total_sent {
                if !self.received_packets.contains_key(&i) {
                    missing_packets.push(i);
                }
            }

            if !missing_packets.is_empty() {
                stats.push_str(&format!("Missing packets: {:?}\n", missing_packets));
            }
        }

        stats.push_str("=====================================\n");
        stats
    }

    fn generate_priority_statistics(&self, high_sent: u32, low_sent: u32) -> String {
        let mut stats = String::new();

        // Basic statistics
        let high_received = self.high_priority_packets.len();
        let low_received = self.low_priority_packets.len();
        let total_sent = high_sent + low_sent;
        let total_received = high_received + low_received;

        let high_loss_rate = if high_sent > 0 {
            ((high_sent as usize - high_received) as f64 / high_sent as f64) * 100.0
        } else {
            0.0
        };

        let low_loss_rate = if low_sent > 0 {
            ((low_sent as usize - low_received) as f64 / low_sent as f64) * 100.0
        } else {
            0.0
        };

        stats.push_str(&format!("\n=== Priority Test Statistics ===\n"));
        stats.push_str(&format!(
            "Total packets sent: {} (High: {}, Low: {})\n",
            total_sent, high_sent, low_sent
        ));
        stats.push_str(&format!(
            "Total packets received: {} (High: {}, Low: {})\n",
            total_received, high_received, low_received
        ));
        stats.push_str(&format!(
            "High priority loss rate: {:.2}%\n",
            high_loss_rate
        ));
        stats.push_str(&format!("Low priority loss rate: {:.2}%\n", low_loss_rate));

        // Delay statistics for high priority packets
        if !self.high_priority_packets.is_empty() {
            let mut min_high_delay = u64::MAX;
            let mut max_high_delay = 0u64;
            let mut min_high_seq = 0u32;
            let mut max_high_seq = 0u32;
            let mut total_high_delay = 0u64;

            for packet in &self.high_priority_packets {
                total_high_delay += packet.delay;
                if packet.delay < min_high_delay {
                    min_high_delay = packet.delay;
                    min_high_seq = packet.packet_num;
                }
                if packet.delay > max_high_delay {
                    max_high_delay = packet.delay;
                    max_high_seq = packet.packet_num;
                }
            }

            let avg_high_delay = total_high_delay as f64 / self.high_priority_packets.len() as f64;

            stats.push_str(&format!(
                "High priority delays - Min: {}ms (Packet #{}), Max: {}ms (Packet #{}), Avg: {:.2}ms\n",
                min_high_delay, min_high_seq, max_high_delay, max_high_seq, avg_high_delay
            ));
        }

        // Delay statistics for low priority packets
        if !self.low_priority_packets.is_empty() {
            let mut min_low_delay = u64::MAX;
            let mut max_low_delay = 0u64;
            let mut min_low_seq = 0u32;
            let mut max_low_seq = 0u32;
            let mut total_low_delay = 0u64;

            for packet in &self.low_priority_packets {
                total_low_delay += packet.delay;
                if packet.delay < min_low_delay {
                    min_low_delay = packet.delay;
                    min_low_seq = packet.packet_num;
                }
                if packet.delay > max_low_delay {
                    max_low_delay = packet.delay;
                    max_low_seq = packet.packet_num;
                }
            }

            let avg_low_delay = total_low_delay as f64 / self.low_priority_packets.len() as f64;

            stats.push_str(&format!(
                "Low priority delays - Min: {}ms (Packet #{}), Max: {}ms (Packet #{}), Avg: {:.2}ms\n",
                min_low_delay, min_low_seq, max_low_delay, max_low_seq, avg_low_delay
            ));
        }

        stats.push_str("=====================================\n");
        stats
    }
}

impl TransportHandler for ClientHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        // Set up qlog if a directory is specified
        if let Some(ref dir) = self.qlog_dir {
            let path = Path::new(dir).join(format!("{}.qlog", conn.trace_id()));
            match fs::File::create(&path) {
                Ok(file) => {
                    conn.set_qlog(
                        Box::new(file),
                        "datagram client qlog".into(),
                        format!("id={}", conn.trace_id()),
                    );
                    info!("Writing qlog to {}", path.display());
                }
                Err(e) => {
                    error!("Failed to create qlog file at {:?}: {}", path, e);
                }
            }
        }

        // Set up keylog if a file is specified
        if let Some(ref keylog_path) = self.keylog_file {
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(keylog_path)
            {
                conn.set_keylog(Box::new(file));
                info!("Writing keylog to {}", keylog_path);
            } else {
                error!("Failed to create keylog file at {}", keylog_path);
            }
        }
        debug!(
            "old max_datagram_size {}",
            conn.peer_max_datagram_frame_size()
        );
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        debug!("Connection established: {}", conn.trace_id());
        debug!(
            "new max_datagram_size {}",
            conn.peer_max_datagram_frame_size()
        );
        // Log 0-RTT information
        debug!("Early data status: {:?}", conn.early_data_reason());
        if let Ok(Some(reason)) = conn.early_data_reason_string() {
            debug!("Early data reason: {}", reason);
        }

        // Check if this is a resumed connection
        if conn.is_resumed() {
            info!("Connection resumed successfully");
        } else {
            debug!("New connection (not resumed)");
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        info!("Connection closed: {}", conn.trace_id());
    }

    fn on_datagram_received(&mut self, conn: &mut Connection, len: u64) {
        debug!(
            "Datagram received on connection: {} len: {}",
            conn.trace_id(),
            len
        );

        // Priority test mode
        if self.test_priority {
            while let Some(dgram) = conn.recv_datagram() {
                let received_data = String::from_utf8_lossy(&dgram);
                let data_str = received_data.trim();

                // Check if this is a "finished" message
                if data_str.starts_with("finished") {
                    info!("Received finished message: {}", data_str);

                    let recv_timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis();

                    // Parse high and low priority counts from finished message
                    // Format: "finished high_count low_count"
                    let parts: Vec<&str> = data_str.split_whitespace().collect();
                    let (high_count, low_count) = if parts.len() >= 3 {
                        (
                            parts[1].parse::<u32>().unwrap_or(0),
                            parts[2].parse::<u32>().unwrap_or(0),
                        )
                    } else {
                        (0, 0)
                    };

                    // Generate priority statistics
                    let stats = self.generate_priority_statistics(high_count, low_count);

                    // Write the finished message and statistics to file if file is open
                    if let Some(ref mut file) = self.output_file {
                        let output_line = format!("{} {}\n", data_str, recv_timestamp);
                        let _ = file.write_all(output_line.as_bytes());
                        let _ = file.write_all(stats.as_bytes());
                        let _ = file.flush();
                    }
                    self.output_file = None;

                    // Close the connection
                    conn.close(true, 0x00, b"test completed").ok();
                    return;
                }

                // Parse priority packet: "sequence priority send_timestamp hello world..."
                let recv_timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();

                let parts: Vec<&str> = data_str.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let (Ok(seq), Ok(priority), Ok(send_timestamp)) = (
                        parts[0].parse::<u32>(),
                        parts[1].parse::<u8>(),
                        parts[2].parse::<u64>(),
                    ) {
                        // Create output file on first packet
                        if !self.first_packet_received {
                            let filename = format!("priority_{}.txt", recv_timestamp);
                            match fs::File::create(&filename) {
                                Ok(file) => {
                                    self.output_file = Some(file);
                                    info!("Created output file: {}", filename);
                                    self.first_packet_received = true;
                                }
                                Err(e) => {
                                    error!("Failed to create output file: {}", e);
                                    return;
                                }
                            }
                        }

                        // Write to file: sequence priority send_timestamp recv_timestamp
                        if let Some(ref mut file) = self.output_file {
                            let output_line = format!(
                                "{} {} {} {}\n",
                                seq, priority, send_timestamp, recv_timestamp
                            );
                            if let Err(e) = file.write_all(output_line.as_bytes()) {
                                error!("Failed to write to file: {}", e);
                            } else {
                                let _ = file.flush();
                            }
                        }

                        // Store packet info for statistics
                        let recv_timestamp_u64 = recv_timestamp as u64;
                        let delay = recv_timestamp_u64.saturating_sub(send_timestamp);
                        let packet_info = TestPacketInfo {
                            packet_num: seq,
                            send_timestamp,
                            recv_timestamp: recv_timestamp_u64,
                            delay,
                        };

                        if priority == 0 {
                            self.high_priority_packets.push(packet_info);
                        } else if priority == 255 {
                            self.low_priority_packets.push(packet_info);
                        }

                        self.packets_received += 1;
                        debug!(
                            "Received priority packet {}: priority={}, seq={}",
                            self.packets_received, priority, seq
                        );
                    }
                }
            }
            return;
        }

        // In test mode and using datagram, process the received datagram
        if self.test_mode && !self.test_stream {
            while let Some(dgram) = conn.recv_datagram() {
                let received_data = String::from_utf8_lossy(&dgram);
                let data_str = received_data.trim();

                // Check if this is a "finished" message
                if data_str.starts_with("finished") {
                    info!("Received finished message: {}", data_str);

                    let recv_timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis();

                    // Parse total sent packets from finished message
                    let parts: Vec<&str> = data_str.split_whitespace().collect();
                    let total_sent = if parts.len() >= 2 {
                        parts[1].parse::<u32>().unwrap_or(0)
                    } else {
                        0
                    };

                    // Generate statistics first
                    let stats = self.generate_statistics(total_sent);

                    // Write the finished message and statistics to file if file is open
                    if let Some(ref mut file) = self.output_file {
                        let output_line = format!("{} {}\n", data_str, recv_timestamp);
                        let _ = file.write_all(output_line.as_bytes());
                        let _ = file.write_all(stats.as_bytes());
                        let _ = file.flush();
                    }
                    self.output_file = None;

                    // Close the connection
                    conn.close(true, 0x00, b"test completed").ok();
                    return;
                }

                let recv_timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();

                // Create output file on first packet
                if !self.first_packet_received {
                    let filename = format!("datagram_{}.txt", recv_timestamp);
                    match fs::File::create(&filename) {
                        Ok(file) => {
                            self.output_file = Some(file);
                            info!("Created output file: {}", filename);
                            self.first_packet_received = true;
                        }
                        Err(e) => {
                            error!("Failed to create output file: {}", e);
                            return;
                        }
                    }
                }

                // Parse and store packet information for statistics
                if let Some((packet_num, send_timestamp)) = self.parse_packet_data(data_str) {
                    let packet_info = TestPacketInfo {
                        packet_num,
                        send_timestamp,
                        recv_timestamp: recv_timestamp as u64,
                        delay: (recv_timestamp as u64).saturating_sub(send_timestamp),
                    };
                    self.received_packets.insert(packet_num, packet_info);
                }

                // Write to file
                if let Some(ref mut file) = self.output_file {
                    let output_line = format!("{} {}\n", data_str, recv_timestamp);
                    if let Err(e) = file.write_all(output_line.as_bytes()) {
                        error!("Failed to write to file: {}", e);
                    } else {
                        // Flush immediately to ensure data is saved
                        let _ = file.flush();
                    }
                }

                self.packets_received += 1;
                debug!("Received packet {}: {}", self.packets_received, data_str);
            }
        }
    }

    // Unused handlers
    fn on_stream_created(&mut self, _conn: &mut Connection, _stream_id: u64) {}

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        if !self.test_mode || !self.test_stream {
            return;
        }

        let mut stream_buf = vec![0u8; 4096]; // Increased buffer size
        match conn.stream_read(stream_id, &mut stream_buf) {
            Ok((len, _fin)) => {
                if len > 0 {
                    let received_data = String::from_utf8_lossy(&stream_buf[..len]);

                    // Split by newlines to handle multiple packets in one read
                    for line in received_data.lines() {
                        let data_str = line.trim();
                        if data_str.is_empty() {
                            continue;
                        }

                        // Check if this is a "finished" message
                        if data_str.starts_with("finished") {
                            info!("Received finished message: {}", data_str);

                            let recv_timestamp = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis();

                            // Parse total sent packets from finished message
                            let parts: Vec<&str> = data_str.split_whitespace().collect();
                            let total_sent = if parts.len() >= 2 {
                                parts[1].parse::<u32>().unwrap_or(0)
                            } else {
                                0
                            };

                            // Generate statistics first
                            let stats = self.generate_statistics(total_sent);

                            // Write the finished message and statistics to file if file is open
                            if let Some(ref mut file) = self.output_file {
                                let output_line = format!("{} {}\n", data_str, recv_timestamp);
                                let _ = file.write_all(output_line.as_bytes());
                                let _ = file.write_all(stats.as_bytes());
                                let _ = file.flush();
                            }
                            self.output_file = None;

                            // Close the connection
                            let _ = conn.close(false, 0, b"test finished");
                            return;
                        } else {
                            // Regular test packet
                            let recv_timestamp = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis();

                            // Create output file on first packet
                            if !self.first_packet_received {
                                let filename = format!("stream_{}.txt", recv_timestamp);
                                match fs::File::create(&filename) {
                                    Ok(file) => {
                                        self.output_file = Some(file);
                                        info!("Created output file: {}", filename);
                                        self.first_packet_received = true;
                                    }
                                    Err(e) => {
                                        error!("Failed to create output file: {}", e);
                                        continue;
                                    }
                                }
                            }

                            // Parse and store packet information for statistics
                            if let Some((packet_num, send_timestamp)) =
                                self.parse_packet_data(data_str)
                            {
                                let packet_info = TestPacketInfo {
                                    packet_num,
                                    send_timestamp,
                                    recv_timestamp: recv_timestamp as u64,
                                    delay: (recv_timestamp as u64).saturating_sub(send_timestamp),
                                };
                                self.received_packets.insert(packet_num, packet_info);
                            }

                            // Write to file
                            if let Some(ref mut file) = self.output_file {
                                let output_line = format!("{} {}\n", data_str, recv_timestamp);
                                if let Err(e) = file.write_all(output_line.as_bytes()) {
                                    error!("Failed to write to file: {}", e);
                                } else {
                                    // Flush immediately to ensure data is saved
                                    let _ = file.flush();
                                }
                            }

                            self.packets_received += 1;
                            debug!(
                                "Received stream packet {}: {}",
                                self.packets_received, data_str
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to read from stream: {}", e);
            }
        }
    }

    fn on_stream_writable(&mut self, _conn: &mut Connection, _stream_id: u64) {}
    fn on_stream_closed(&mut self, _conn: &mut Connection, _stream_id: u64) {}
    fn on_new_token(&mut self, conn: &mut Connection, _token: Vec<u8>) {
        //save the session
        debug!("session_file {:?}", self.session_file);
        // Save session data before closing
        if let Some(ref session_file) = self.session_file {
            if let Some(session_data) = conn.session() {
                if let Err(e) = std::fs::write(session_file, session_data) {
                    error!("Failed to save session data to {}: {}", session_file, e);
                } else {
                    info!("Saved session data to {}", session_file);
                }
            } else {
                error!("no session now");
            }
        }
    }

    fn on_datagram_acked(&mut self, conn: &mut Connection, datagram_id: u64) {
        debug!(
            "Datagram with ID {} has been acked on connection {}",
            datagram_id,
            conn.trace_id()
        );
    }

    fn on_datagram_lost(&mut self, conn: &mut Connection, datagram_id: u64) {
        debug!(
            "Datagram with ID {} has been lost on connection {}",
            datagram_id,
            conn.trace_id()
        );
    }

    fn on_datagram_receiver_drop(&mut self, conn: &mut Connection, datagram_id: u64) {
        debug!(
            "Datagram with ID {} has been dropped on connection {}",
            datagram_id,
            conn.trace_id()
        );
    }

    fn on_datagram_sender_drop(&mut self, conn: &mut Connection, datagram_id: u64) {
        debug!(
            "Datagram with ID {} has been dropped on connection {}",
            datagram_id,
            conn.trace_id()
        );
    }
}

/// Helper function to process arguments like initializing the logger and creating directories.
fn process_args(args: &Args) -> Result<()> {
    env_logger::Builder::new()
        .filter_level(args.log_level)
        .format_timestamp_millis()
        .init();

    if let Some(ref dir) = args.qlog_dir {
        fs::create_dir_all(dir)?;
        info!("qlog directory set to: {}", dir);
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logger and create directories
    process_args(&args)?;

    // Create and run the client
    let mut client = DatagramClient::new(&args)?;

    if args.test_priority {
        info!("Running in priority test mode");
        client.run_priority_test()
    } else if args.test_loss {
        info!("Running in packet loss test mode");
        client.run_packet_loss_test()
    } else {
        info!("Running in normal datagram mode");
        client.run()
    }
}
