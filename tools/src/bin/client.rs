use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

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
        let handler = ClientHandler::new(
            args.qlog_dir.clone(),
            args.keylog_file.clone(),
            args.session_file.clone(),
        );
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
                if messages_sent < self.message_count && now >= next_send_time {
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
}

struct ClientHandler {
    qlog_dir: Option<String>,
    keylog_file: Option<String>,
    session_file: Option<String>,
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
        }
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

    fn on_datagram_received(&mut self, conn: &mut Connection) {
        debug!("Datagram received on connection: {}", conn.trace_id());
    }

    // Unused handlers
    fn on_stream_created(&mut self, _conn: &mut Connection, _stream_id: u64) {}
    fn on_stream_readable(&mut self, _conn: &mut Connection, _stream_id: u64) {}
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
    client.run()
}
