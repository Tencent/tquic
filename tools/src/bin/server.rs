use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::time::Instant;

use bytes::Bytes;
use clap::Parser;
use log::{debug, error, info, warn};
use mio::{event::Event, Events, Poll};
use rustc_hash::FxHashMap;

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
}

/// The main server struct holding the networking components.
struct DatagramServer {
    endpoint: Endpoint,
    poll: Poll,
    socket: Rc<QuicSocket>,
    recv_buf: Vec<u8>,
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

        let handler = ServerHandler::new(args.qlog_dir.clone(), args.keylog_file.clone());
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
        })
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

            // Calculate timeout and wait for events
            self.poll.poll(&mut events, self.endpoint.timeout())?;

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
}

impl ConnectionHandler {
    fn new() -> Self {
        Self {
            datagrams_received: 0,
            datagrams_sent: 0,
        }
    }

    /// Process incoming datagrams for this specific connection.
    fn process_datagrams(&mut self, conn: &mut Connection) {
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

/// Top-level handler that manages all ConnectionHandlers.
struct ServerHandler {
    conns: FxHashMap<u64, ConnectionHandler>,
    qlog_dir: Option<String>,
    keylog_file: Option<String>,
}

impl ServerHandler {
    fn new(qlog_dir: Option<String>, keylog_file: Option<String>) -> Self {
        Self {
            conns: FxHashMap::default(),
            qlog_dir,
            keylog_file,
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
        self.conns.insert(index, ConnectionHandler::new());
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
            info!(
                "DATAGRAM extension NOT enabled for conn {}",
                conn.trace_id()
            );
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
    }

    // Unused handlers
    fn on_stream_created(&mut self, _conn: &mut Connection, _stream_id: u64) {}
    fn on_stream_readable(&mut self, _conn: &mut Connection, _stream_id: u64) {}
    fn on_stream_writable(&mut self, _conn: &mut Connection, _stream_id: u64) {}
    fn on_stream_closed(&mut self, _conn: &mut Connection, _stream_id: u64) {}
    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}

    fn on_datagram_acked(&mut self, conn: &mut Connection, datagram_id: u64) {
        info!(
            "Datagram with ID {} has been acked on connection {}",
            datagram_id,
            conn.trace_id()
        );
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

    println!("QUIC DATAGRAM Server Example");
    println!("==============================");
    let mut server = DatagramServer::new(&args)?;
    server.run()
}
