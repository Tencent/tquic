use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use clap::Parser;
use log::{debug, error, info, warn};
use mio::{event::Event, Events, Poll};
use rustc_hash::FxHashMap;

use tquic::connection::SendDatagramParams;
use tquic::{
    Config, CongestionControlAlgorithm, Connection, Endpoint, PacketInfo, TlsConfig,
    TransportHandler,
};
use tquic_tools::QuicSocket;
use tquic_tools::Result;

#[derive(Parser, Debug)]
#[clap(
    name = "datagram_server",
    version = "1.0",
    author = "The TQUIC Authors"
)]
struct Args {
    /// Address to listen on.
    #[clap(short, long, default_value = "127.0.0.1:4433", value_name = "ADDR")]
    listen: SocketAddr,

    /// TLS certificate in PEM format.
    #[clap(long = "cert", default_value = "cert.crt", value_name = "FILE")]
    cert_file: String,

    /// TLS private key in PEM format.
    #[clap(long = "key", default_value = "cert.key", value_name = "FILE")]
    key_file: String,

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

    /// Session ticket key.
    #[clap(
        short,
        long,
        default_value = "tquic key",
        value_name = "STR",
        help_heading = "Protocol"
    )]
    pub ticket_key: String,

    #[clap(help_heading = "Protocol")]
    /// Connection idle timeout in milliseconds.
    #[clap(long, default_value = "30000", value_name = "TIME")]
    idle_timeout: u64,

    #[clap(help_heading = "Protocol")]
    /// Handshake timeout in milliseconds.
    #[clap(long, default_value = "10000", value_name = "TIME")]
    handshake_timeout: u64,

    #[clap(help_heading = "Protocol")]
    /// Set max_datagram_frame_size transport parameter.
    #[clap(long, default_value = "1200", value_name = "NUM")]
    max_datagram_frame_size: u64,

    #[clap(help_heading = "Protocol")]
    /// Set max_ack_delay transport parameter.
    #[clap(long, default_value = "25", value_name = "NUM")]
    max_ack_delay: u64,

    #[clap(help_heading = "Protocol")]
    /// Congestion control algorithm.
    #[clap(long, value_enum, default_value = "bbr")]
    congestion_control_algor: CongestionControlAlgorithm,

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

    // --- Packet Loss Test ---
    #[clap(help_heading = "Packet Loss Test")]
    /// Enable packet loss test mode.
    #[clap(long)]
    test_loss: bool,

    #[clap(help_heading = "Packet Loss Test")]
    /// Number of test packets to send (default: 1000).
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

/// The main server struct holding the networking components.
struct DatagramServer {
    endpoint: Endpoint,
    poll: Poll,
    socket: Rc<QuicSocket>,
    recv_buf: Vec<u8>,
    // Test mode parameters
    test_loss: bool,
    test_priority: bool,
    test_stream: bool,
    test_count: usize,
    test_interval: Duration,
    // Test timing
    last_test_send: Instant,
    test_packets_sent: usize,
    // Priority test counters
    high_priority_sent: usize,
    low_priority_sent: usize,
    // Connection and stream management
    active_connections: FxHashMap<u64, bool>, // Use HashMap instead of Vec for better performance
    global_stream_id: Option<u64>,
}

impl DatagramServer {
    /// Create a new datagram server based on command-line arguments.
    fn new(args: &Args) -> Result<Self> {
        let mut quic_config = Config::new()?;

        // Apply settings from args
        quic_config.set_max_idle_timeout(args.idle_timeout);
        quic_config.set_max_handshake_timeout(args.handshake_timeout);
        quic_config.set_max_datagram_frame_size(args.max_datagram_frame_size);
        quic_config.set_congestion_control_algorithm(args.congestion_control_algor);
        quic_config.set_max_ack_delay(args.max_ack_delay);
        debug!(
            "args.max_datagram_frame_size {:?}",
            args.max_datagram_frame_size
        );
        let alpns: Vec<Vec<u8>> = args.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        debug!("Using ALPNs: {:?}", args.alpn);

        let mut tls_config =
            TlsConfig::new_server_config(&args.cert_file, &args.key_file, alpns, true)?;

        let mut ticket_key = args.ticket_key.clone().into_bytes();
        ticket_key.resize(48, 0);
        tls_config.set_ticket_key(&ticket_key)?;
        quic_config.set_tls_config(tls_config);

        let poll = Poll::new()?;
        let socket_rc = Rc::new(QuicSocket::new(&args.listen, poll.registry())?);

        let handler = if args.test_loss || args.test_priority {
            ServerHandler::new_test_mode(
                args.qlog_dir.clone(),
                args.keylog_file.clone(),
                args.test_stream,
                args.test_count,
                Duration::from_millis(args.test_interval),
            )
        } else {
            ServerHandler::new(args.qlog_dir.clone(), args.keylog_file.clone())
        };
        let endpoint = Endpoint::new(
            Box::new(quic_config),
            true,
            Box::new(handler),
            socket_rc.clone(),
        );

        Ok(Self {
            endpoint,
            poll,
            socket: socket_rc,
            recv_buf: vec![0u8; 65536],
            test_loss: args.test_loss,
            test_priority: args.test_priority,
            test_stream: args.test_stream,
            test_count: args.test_count,
            test_interval: Duration::from_millis(args.test_interval),
            last_test_send: Instant::now(),
            test_packets_sent: 0,
            high_priority_sent: 0,
            low_priority_sent: 0,
            active_connections: FxHashMap::default(),
            global_stream_id: None,
        })
    }

    fn add_connection(&mut self, conn_id: u64) {
        if !self.active_connections.contains_key(&conn_id) {
            self.active_connections.insert(conn_id, true);
            info!("Added new active connection: {}", conn_id);
        }
    }

    fn remove_connection(&mut self, conn_id: u64) {
        if self.active_connections.remove(&conn_id).is_some() {
            info!("Removed connection: {}", conn_id);
        }
        if self.active_connections.is_empty() {
            self.global_stream_id = None;
        }
    }

    fn update_active_connections(&mut self) {
        for conn_id in 0..10u64 {
            if let Some(conn) = self.endpoint.conn_get_mut(conn_id) {
                if !conn.is_closed() && !conn.is_closing() && conn.is_established() {
                    self.add_connection(conn_id);
                }
            }
        }

        let mut to_remove = Vec::new();
        for &conn_id in self.active_connections.keys() {
            if let Some(conn) = self.endpoint.conn_get_mut(conn_id) {
                if conn.is_closed() || conn.is_closing() {
                    to_remove.push(conn_id);
                }
            } else {
                to_remove.push(conn_id);
            }
        }

        for conn_id in to_remove {
            self.remove_connection(conn_id);
        }
    }

    /// Start the server's main event loop.
    fn run(&mut self) -> Result<()> {
        info!("Server started, listening on {}", self.socket.local_addr());
        let mut events = Events::with_capacity(1024);

        loop {
            // The handler will now manage datagram processing internally.
            // We just need to drive the main endpoint state machine.
            if let Err(e) = self.endpoint.process_connections() {
                error!("Error processing connections: {}", e);
            }

            // Update active connections list
            self.update_active_connections();

            // In test mode, send test data at regular intervals
            if self.test_loss || self.test_priority {
                let now = Instant::now();
                if now.duration_since(self.last_test_send) >= self.test_interval {
                    self.send_test_data_to_active_connections();
                    self.last_test_send = now;
                }
            }

            // Calculate timeout and wait for events
            let mut timeout = self.endpoint.timeout();

            // In test mode, ensure we wake up at least every test_interval
            if self.test_loss || self.test_priority {
                let test_timeout = Some(self.test_interval);
                timeout = match (timeout, test_timeout) {
                    (Some(t1), Some(t2)) => Some(t1.min(t2)),
                    (Some(t), None) | (None, Some(t)) => Some(t),
                    (None, None) => None,
                };
            }
            self.poll.poll(&mut events, timeout)?;

            // Process network I/O
            for event in events.iter() {
                if event.is_readable() {
                    self.handle_readable_event(event)?;
                }
            }

            // Process timeouts
            self.endpoint.on_timeout(Instant::now());
        }
    }

    /// Send test data to all active connections
    fn send_test_data_to_active_connections(&mut self) {
        if !self.test_loss && !self.test_priority {
            return;
        }

        if self.active_connections.is_empty() {
            return;
        }

        let payload = if self.test_packets_sent < self.test_count {
            if self.test_priority {
                // Priority test mode: send with priority and create 1024-byte payload
                let is_high_priority = self.test_packets_sent % 2 == 0; // Alternate between high and low
                let priority = if is_high_priority { 0u8 } else { 255u8 };
                let priority_str = if is_high_priority { "0" } else { "255" };

                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();

                let base_content = format!(
                    "{} {} {}",
                    self.test_packets_sent + 1,
                    priority_str,
                    timestamp
                );
                let filler = " hello world".repeat((1024 - base_content.len()) / 12);
                let mut full_content = format!("{}{}", base_content, filler);

                // Ensure exactly 1024 bytes
                full_content.truncate(1024);
                if full_content.len() < 1024 {
                    full_content.push_str(&"x".repeat(1024 - full_content.len()));
                }

                (full_content, Some(priority))
            } else {
                // Original test_loss mode
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();

                (
                    format!(
                        "Packet {} Timestamp {}",
                        self.test_packets_sent + 1,
                        timestamp
                    ),
                    None,
                )
            }
        } else {
            // Send finished message
            if self.test_priority {
                (
                    format!(
                        "finished {} {}",
                        self.high_priority_sent, self.low_priority_sent
                    ),
                    None,
                )
            } else {
                (format!("finished {}", self.test_packets_sent), None)
            }
        };

        let conn_ids: Vec<u64> = self.active_connections.keys().cloned().collect();
        for conn_id in conn_ids {
            if let Some(conn) = self.endpoint.conn_get_mut(conn_id) {
                if !conn.is_closed() && !conn.is_closing() {
                    if self.test_stream {
                        if self.global_stream_id.is_none() {
                            match conn.stream_bidi_new(0, false) {
                                Ok(stream_id) => {
                                    self.global_stream_id = Some(stream_id);
                                    info!(
                                        "Created global stream {} for ordered transmission",
                                        stream_id
                                    );
                                }
                                Err(e) => {
                                    error!("Failed to create global stream: {}", e);
                                    continue;
                                }
                            }
                        }

                        if let Some(stream_id) = self.global_stream_id {
                            // Add newline to separate packets in stream
                            let payload_with_newline = format!("{}\n", payload.0);
                            let payload_bytes = Bytes::from(payload_with_newline);
                            match conn.stream_write(stream_id, payload_bytes, false) {
                                Ok(_) => {
                                    self.log_sent_packet(&payload, true);
                                    return;
                                }
                                Err(e) => {
                                    error!("Failed to write to global stream: {}", e);
                                }
                            }
                        }
                    } else {
                        // Send via datagram
                        let payload_bytes = Bytes::from(payload.0.clone());
                        let result = if let Some(priority) = payload.1 {
                            // Priority test mode
                            let params = SendDatagramParams::with_priority(priority);
                            conn.send_datagram_with_param(payload_bytes, params)
                        } else {
                            // Normal mode
                            conn.send_datagram(payload_bytes)
                        };

                        match result {
                            Ok(_datagram_id) => {
                                self.log_sent_packet(&payload, false);
                                return;
                            }
                            Err(e) => {
                                error!("Failed to send datagram: {}", e);
                            }
                        }
                    }
                }
            } else {
                self.remove_connection(conn_id);
            }
        }
    }

    fn log_sent_packet(&mut self, payload: &(String, Option<u8>), is_stream: bool) {
        if self.test_packets_sent < self.test_count {
            if self.test_priority {
                let is_high_priority = self.test_packets_sent % 2 == 0;
                if is_high_priority {
                    self.high_priority_sent += 1;
                } else {
                    self.low_priority_sent += 1;
                }
                info!(
                    "Sent test {} packet {} (priority {}): {}",
                    if is_stream { "stream" } else { "datagram" },
                    self.test_packets_sent + 1,
                    if is_high_priority { "high" } else { "low" },
                    &payload.0[..50.min(payload.0.len())]
                );
            } else {
                info!(
                    "Sent test {} packet {}: {}",
                    if is_stream { "stream" } else { "datagram" },
                    self.test_packets_sent + 1,
                    payload.0
                );
            }
            self.test_packets_sent += 1;
        } else {
            info!(
                "Sent finished message via {}",
                if is_stream { "stream" } else { "datagram" }
            );
        }
    }

    /// Handle readable socket events by receiving packets and passing them to the endpoint.
    fn handle_readable_event(&mut self, event: &Event) -> io::Result<()> {
        loop {
            match self.socket.recv_from(&mut self.recv_buf, event.token()) {
                Ok((len, local, remote)) => {
                    debug!("Received {} bytes from {}", len, remote);
                    let packet_info = PacketInfo {
                        src: remote,
                        dst: local,
                        time: Instant::now(),
                    };
                    if let Err(e) = self.endpoint.recv(&mut self.recv_buf[..len], &packet_info) {
                        debug!("Failed to process packet: {}", e);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break, // No more data
                Err(e) => {
                    error!("Socket recv error: {}", e);
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

/// Handler for a single connection's state and logic.
#[derive(Debug)]
struct ConnectionHandler {
    datagrams_received: u64,
    datagrams_sent: u64,
    // Test mode fields
    test_mode: bool,
    test_stream: bool,
    test_count: usize,
    test_interval: Duration,
    packets_sent: usize,
    next_send_time: Instant,
    test_stream_id: Option<u64>,
}

impl ConnectionHandler {
    fn new() -> Self {
        Self {
            datagrams_received: 0,
            datagrams_sent: 0,
            test_mode: false,
            test_stream: false,
            test_count: 1000,
            test_interval: Duration::from_millis(50),
            packets_sent: 0,
            next_send_time: Instant::now(),
            test_stream_id: None,
        }
    }

    fn new_test_mode(test_stream: bool, test_count: usize, test_interval: Duration) -> Self {
        Self {
            datagrams_received: 0,
            datagrams_sent: 0,
            test_mode: true,
            test_stream,
            test_count,
            test_interval,
            packets_sent: 0,
            next_send_time: Instant::now(),
            test_stream_id: None,
        }
    }

    /// Process incoming datagrams for this specific connection.
    fn process_datagrams(&mut self, conn: &mut Connection) {
        if self.test_mode {
            // In test mode, we don't echo data or send test data here
            // All test data sending is handled in the main loop
            while let Some(datagram) = conn.recv_datagram() {
                let message = String::from_utf8_lossy(&datagram);
                debug!(
                    "Received datagram in test mode ({} bytes): {}",
                    datagram.len(),
                    message
                );
                self.datagrams_received += 1;
            }
        } else {
            // Normal echo mode
            while let Some(datagram) = conn.recv_datagram() {
                let message = String::from_utf8_lossy(&datagram);
                info!("Received datagram ({} bytes): {}", datagram.len(), message);
                self.datagrams_received += 1;

                // Echo the datagram back
                let response = format!("Echo from server: {}", message);
                let response_bytes = Bytes::from(response);

                match conn.send_datagram(response_bytes.clone()) {
                    Ok(datagram_id) => {
                        debug!(
                            "[Conn {}] Queued echo datagram for sending. {}",
                            conn.trace_id(),
                            datagram_id
                        );
                        self.datagrams_sent += 1;
                    }
                    Err(e) => {
                        warn!("[Conn {}] Failed to send datagram: {}", conn.trace_id(), e);
                    }
                }
            }
        }
    }

    fn send_test_data(&mut self, conn: &mut Connection) {
        let now = Instant::now();

        // Check if it's time to send the next packet
        if self.packets_sent < self.test_count && now >= self.next_send_time {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();

            let payload = format!("Packet {} Timestamp {}", self.packets_sent + 1, timestamp);

            if self.test_stream {
                // Send via stream
                if self.test_stream_id.is_none() {
                    // Create a new bidirectional stream for sending data
                    match conn.stream_bidi_new(0, false) {
                        Ok(stream_id) => {
                            self.test_stream_id = Some(stream_id);
                            info!(
                                "Created test stream {} for connection {}",
                                stream_id,
                                conn.trace_id()
                            );
                        }
                        Err(e) => {
                            error!("Failed to create stream: {}", e);
                            return;
                        }
                    }
                }

                if let Some(stream_id) = self.test_stream_id {
                    // Add newline to separate packets in stream
                    let payload_with_newline = format!("{}\n", payload);
                    let payload_bytes = Bytes::from(payload_with_newline);
                    match conn.stream_write(stream_id, payload_bytes, false) {
                        Ok(_) => {
                            self.packets_sent += 1;
                            self.next_send_time = now + self.test_interval;
                            info!("Sent test stream packet {}: {}", self.packets_sent, payload);
                        }
                        Err(e) => {
                            error!("Failed to write to stream: {}", e);
                        }
                    }
                }
            } else {
                // Send via datagram
                let payload_bytes = Bytes::from(payload.clone());
                match conn.send_datagram(payload_bytes) {
                    Ok(datagram_id) => {
                        self.packets_sent += 1;
                        self.next_send_time = now + self.test_interval;
                        info!(
                            "Sent test datagram {} (id {}): {}",
                            self.packets_sent, datagram_id, payload
                        );
                    }
                    Err(e) => {
                        error!("Failed to send datagram: {}", e);
                    }
                }
            }
        }

        // Continue sending if there are more packets to send
        // This creates a continuous loop of sending
        if self.packets_sent < self.test_count {
            // We need some way to re-trigger this method
            // For now, let's at least log that we want to continue
            debug!(
                "Sent {}/{} packets, will continue when triggered",
                self.packets_sent, self.test_count
            );
        }
    }
}

/// Top-level handler that manages all ConnectionHandlers.
struct ServerHandler {
    conns: FxHashMap<u64, ConnectionHandler>,
    qlog_dir: Option<String>,
    keylog_file: Option<String>,
    // Test mode fields
    test_mode: bool,
    test_stream: bool,
    test_count: usize,
    test_interval: Duration,
}

impl ServerHandler {
    fn new(qlog_dir: Option<String>, keylog_file: Option<String>) -> Self {
        Self {
            conns: FxHashMap::default(),
            qlog_dir,
            keylog_file,
            test_mode: false,
            test_stream: false,
            test_count: 1000,
            test_interval: Duration::from_millis(50),
        }
    }

    fn new_test_mode(
        qlog_dir: Option<String>,
        keylog_file: Option<String>,
        test_stream: bool,
        test_count: usize,
        test_interval: Duration,
    ) -> Self {
        Self {
            conns: FxHashMap::default(),
            qlog_dir,
            keylog_file,
            test_mode: true,
            test_stream,
            test_count,
            test_interval,
        }
    }
    // Create and store a handler for this new connection
    fn try_new_conn_handler(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap();
        if self.conns.get_mut(&index).is_some() {
            return;
        }
        //enable all the notify
        conn.enable_all_datagram_notifications();

        let conn_handler = if self.test_mode {
            ConnectionHandler::new_test_mode(self.test_stream, self.test_count, self.test_interval)
        } else {
            ConnectionHandler::new()
        };

        self.conns.insert(index, conn_handler);
    }
}

impl TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        debug!("New connection created: {}", conn.trace_id());

        // Set up qlog if a directory is specified
        if let Some(ref dir) = self.qlog_dir {
            let path = Path::new(dir).join(format!("{}.qlog", conn.trace_id()));
            match fs::File::create(&path) {
                Ok(file) => {
                    conn.set_qlog(
                        Box::new(file),
                        "datagram server qlog".into(),
                        format!("id={}", conn.trace_id()),
                    );
                    info!("Writing qlog for {} to {}", conn.trace_id(), path.display());
                }
                Err(e) => error!("Failed to create qlog file for {}: {}", conn.trace_id(), e),
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
                info!("Writing keylog for {} to {}", conn.trace_id(), keylog_path);
            } else {
                error!("Failed to open keylog file for {}", conn.trace_id());
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        debug!("{} connection is established", conn.trace_id());
        self.try_new_conn_handler(conn);

        // Log 0-RTT information
        debug!("Early data status: {:?}", conn.early_data_reason());
        if let Ok(Some(reason)) = conn.early_data_reason_string() {
            info!("Early data reason: {}", reason);
        }

        // Check if this is a resumed connection
        if conn.is_resumed() {
            info!("Connection resumed successfully");
        } else {
            debug!("New connection (not resumed)");
        }

        // Check for DATAGRAM extension support
        if conn.is_datagram_enabled() {
            debug!("DATAGRAM extension enabled for conn {}", conn.trace_id());
        } else {
            warn!(
                "DATAGRAM extension NOT enabled for conn {}",
                conn.trace_id()
            );
        }

        // In test mode, start sending test data immediately after connection establishment
        if self.test_mode {
            info!("Test mode enabled for connection {}", conn.trace_id());
            // Don't send data here - let the main loop handle all sending to avoid duplicates
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        debug!("Connection closed: {}", conn.trace_id());
        if let Some(error) = conn.local_error() {
            debug!("Reason (local): {:?}", error);
        }
        if let Some(error) = conn.peer_error() {
            debug!("Reason (peer): {:?}", error);
        }

        // Remove the handler for the closed connection
        if let Some(handler) = self.conns.remove(&conn.index().unwrap()) {
            debug!(
                "Stats for conn {}: {} dgrams received, {} dgrams sent",
                conn.trace_id(),
                handler.datagrams_received,
                handler.datagrams_sent
            );
        }
    }

    fn on_datagram_received(&mut self, conn: &mut Connection, _len: u64) {
        self.try_new_conn_handler(conn);

        // This callback is the trigger to process datagrams for a connection.
        if let Some(handler) = self.conns.get_mut(&conn.index().unwrap()) {
            handler.process_datagrams(conn);
        } else {
            error!(
                "Received datagram for unknown connection index {}",
                conn.index().unwrap()
            );
        }

        // Remove the test data sending trigger here to avoid duplication
        // All test data sending is now handled in the main loop
    }

    // Stream handlers
    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!(
            "Stream {} created for connection {}",
            stream_id,
            conn.trace_id()
        );
        self.try_new_conn_handler(conn);
    }

    fn on_stream_readable(&mut self, _conn: &mut Connection, _stream_id: u64) {
        // For server test mode, we don't need to read from streams
        // The client will handle reading our test data
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        // Remove the test data sending trigger here to avoid duplication
        // All test data sending is now handled in the main loop
        debug!(
            "Stream {} writable for connection {}",
            stream_id,
            conn.trace_id()
        );
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!(
            "Stream {} closed for connection {}",
            stream_id,
            conn.trace_id()
        );
    }
    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}

    fn on_datagram_acked(&mut self, conn: &mut Connection, datagram_id: u64) {
        debug!(
            "Datagram with ID {} has been acked on connection {}",
            datagram_id,
            conn.trace_id()
        );

        // Remove the trigger here to avoid duplicate sending
        // All test data sending is now handled in the main loop
    }

    fn on_datagram_lost(&mut self, conn: &mut Connection, datagram_id: u64) {
        info!(
            "Datagram with ID {} has been lost on connection {}",
            datagram_id,
            conn.trace_id()
        );
        info!(
            "Connection {} notifyFlags {:?} ",
            conn.trace_id(),
            conn.datagram_notification_flags()
        );
        conn.disable_all_datagram_notifications();
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
    process_args(&args)?;

    if args.test_loss {
        println!("QUIC Packet Loss Test Server");
        println!(
            "Using {} mode, sending {} packets every {}ms",
            if args.test_stream {
                "stream"
            } else {
                "datagram"
            },
            args.test_count,
            args.test_interval
        );
    } else if args.test_priority {
        println!("QUIC Priority Test Server");
        println!("Testing priority-based packet transmission (0=high, 255=low)");
        println!("Packet size: 1024 bytes");
    } else {
        println!("QUIC DATAGRAM Server Example");
    }
    println!("==============================");
    let mut server = DatagramServer::new(&args)?;
    server.run()
}
