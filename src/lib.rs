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

//! TQUIC is an implementation of the [IETF QUIC protocol](https://quicwg.org/).
//! It is a high-performance, lightweight, and cross-platform QUIC library.
//!
//! ## Features and Advantages
//!
//! * **High Performance**: TQUIC is designed for high performance and low
//!   latency.
//! * **High Throughput**: TQUIC supports various congtestion control algorithms
//!   (CUBIC, BBR, COPA), and Multipath QUIC for utilizing multiple paths within
//!   a single connection.
//! * **High Quality**: TQUIC employs extensive testing techniques, including
//!   unit testing, fuzz testing, integration testing, benchmarking,
//!   interoperability testing, and protocol conformance testing.
//! * **Easy to Use**: TQUIC is easy to use, supporting flexible configuration
//!   and detailed observability. It offers APIs for Rust/C/C++.
//! * **Powered by Rust**: TQUIC is written in a memory-safe language, making it
//!   immune to Buffer Overflow vulnerability and other memory-related bugs.
//! * **Rich Features**: TQUIC supports all big features conforming with QUIC,
//!   HTTP/3 RFCs.
//!
//! The [TQUIC project website](https://tquic.net/docs/intro) offers a
//! comprehensive introduction to TQUIC.
//!
//! ## Get started
//!
//! See the [documents](https://tquic.net/docs/category/getting-started) and
//! [examples](https://github.com/tencent/tquic/tree/master/tools/) to get
//! started with TQUIC.
//!
//! ## Feature flags
//!
//! TQUIC defines several feature flags to reduce the amount of compiled code
//! and dependencies:
//!
//! * `ffi`: Build and expose the FFI API.

#![allow(unused_imports)]
#![allow(dead_code)]

use std::cmp;
use std::collections::VecDeque;
use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time;
use std::time::Duration;
use std::time::Instant;

use bytes::Buf;
use bytes::BufMut;
use rand::RngCore;
use ring::aead;
use ring::aead::LessSafeKey;
use ring::aead::UnboundKey;
use ring::hmac;
use rustc_hash::FxHashSet;

use crate::codec::VINT_MAX;
use crate::connection::stream;
use crate::tls::TlsSession;
use crate::token::ResetToken;
use crate::trans_param::TransportParams;

/// The current QUIC wire version.
pub const QUIC_VERSION: u32 = QUIC_VERSION_V1;

/// The QUIC Version 1
pub const QUIC_VERSION_V1: u32 = 0x0000_0001;

/// The Connection ID MUST NOT exceed 20 bytes in QUIC version 1.
/// See RFC 9000 Section 17.2
pub const MAX_CID_LEN: usize = 20;

/// Max number of cid that are allowed to advertised to the peer.
const MAX_CID_LIMIT: u64 = 8;

/// The Stateless Reset Token is a 16-byte value.
const RESET_TOKEN_LEN: usize = 16;

/// For the Stateless Reset to appear as a valid QUIC packet, the Unpredictable
/// Bits field needs to include at least 38 bits of data. The minimum length of
/// a Statless Reset Packet is 21 bytes.
const MIN_RESET_PACKET_LEN: usize = 21;

/// Assuming the maximum possible connection ID and packet number size, the 1RTT
/// packet size is:
/// 1 (header) + 20 (cid) + 4 (pkt num) + 1 (payload) + 16 (AEAD tag) = 42 bytes
const MAX_RESET_PACKET_LEN: usize = 42;

/// The encoded size of length field in long header.
const LENGTH_FIELD_LEN: usize = 2;

/// The minimum length of Initial packets sent by a client.
pub const MIN_CLIENT_INITIAL_LEN: usize = 1200;

const MIN_PAYLOAD_LEN: usize = 4;

/// Ensure the ACK frame can fit in a single minimum-MTU packet.
const MAX_ACK_RANGES: usize = 68;

/// Default outgoing udp datagram payloads size.
const DEFAULT_SEND_UDP_PAYLOAD_SIZE: usize = 1200;

/// The maximum number of undecryptable packets that can be buffered.
const MAX_UNDECRYPTABLE_PACKETS: usize = 10;

/// An endpoint MUST limit the amount of data it sends to the unvalidated
/// address to three times the amount of data received from that address.
const ANTI_AMPLIFICATION_FACTOR: usize = 3;

/// The RECOMMENDED value of the timer granularity is 1 millisecond.
/// See RFC 9002 Section 6.1
pub const TIMER_GRANULARITY: Duration = Duration::from_millis(1);

/// The largest count of streams for each type.
const MAX_STREAMS_PER_TYPE: u64 = 1 << 60;

/// Represents the minimum multiple by which the connection flow control window
/// needs to be greater than the stream flow control window.
const CONNECTION_WINDOW_FACTOR: f64 = 1.5;

/// Resumed connections over the same network MAY use the previous connection's
/// final smoothed RTT value as the resumed connection's initial RTT. When no
/// previous RTT is available, the initial RTT SHOULD be set to 333 milliseconds.
/// This results in handshakes starting with a PTO of 1 second, as recommended
/// for TCP's initial RTO
const INITIAL_RTT: Duration = Duration::from_millis(333);

/// Default handshake timeout is 30 seconds.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

///  Default linear factor for calculating the probe timeout.
const DEFAULT_PTO_LINEAR_FACTOR: u64 = 0;

/// Default upper limit of probe timeout.
const MAX_PTO: Duration = Duration::MAX;

/// Result type for quic operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Connection Id is an identifier used to identify a QUIC connection
/// at an endpoint.
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct ConnectionId {
    /// length of cid
    len: u8,
    /// octets of cid
    data: [u8; MAX_CID_LEN],
}

impl ConnectionId {
    /// Construct cid from byte slice
    pub fn new(bytes: &[u8]) -> Self {
        let len = cmp::min(bytes.len(), MAX_CID_LEN);
        let mut cid = Self {
            len: len as u8,
            data: [0; MAX_CID_LEN],
        };
        cid.data[..len].copy_from_slice(&bytes[..len]);
        cid
    }

    /// Construct a random cid.
    pub fn random() -> Self {
        Self {
            len: MAX_CID_LEN as u8,
            data: rand::random::<[u8; MAX_CID_LEN]>(),
        }
    }
}

impl std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.data[0..self.len as usize]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.iter() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Generate QUIC connection ID
pub trait ConnectionIdGenerator {
    /// Generate a new CID
    fn generate(&mut self) -> ConnectionId;

    /// Return the length of a CID
    fn cid_len(&self) -> usize;

    /// Generate a new CID and associated reset token.
    fn generate_cid_and_token(&mut self, reset_token_key: &hmac::Key) -> (ConnectionId, u128) {
        let scid = self.generate();
        let reset_token = ResetToken::generate(reset_token_key, &scid);
        (scid, reset_token.to_u128())
    }
}

/// Generates purely random connection IDs of a certain length
#[derive(Debug, Clone, Copy)]
pub struct RandomConnectionIdGenerator {
    cid_len: usize,
}

impl RandomConnectionIdGenerator {
    pub fn new(cid_len: usize) -> Self {
        Self {
            cid_len: cmp::min(cid_len, MAX_CID_LEN),
        }
    }
}

impl ConnectionIdGenerator for RandomConnectionIdGenerator {
    fn generate(&mut self) -> ConnectionId {
        let mut bytes = [0; MAX_CID_LEN];
        rand::thread_rng().fill_bytes(&mut bytes[..self.cid_len]);
        ConnectionId::new(&bytes[..self.cid_len])
    }

    fn cid_len(&self) -> usize {
        self.cid_len
    }
}

/// Meta information about a packet.
#[derive(Clone, Copy, Debug)]
pub struct PacketInfo {
    /// The source address of the packet
    pub src: SocketAddr,

    /// The destination address of the packet
    pub dst: SocketAddr,

    /// The time when the packet arrived or the time to send the packet
    pub time: time::Instant,
}

/// Address tuple.
#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone)]
pub struct FourTuple {
    /// The local address
    pub local: SocketAddr,

    /// The remote address
    pub remote: SocketAddr,
}

/// An iterator over FourTuple.
#[derive(Default)]
pub struct FourTupleIter {
    pub(crate) addrs: Vec<FourTuple>,
}

impl Iterator for FourTupleIter {
    type Item = FourTuple;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.addrs.pop()
    }
}

impl ExactSizeIterator for FourTupleIter {
    #[inline]
    fn len(&self) -> usize {
        self.addrs.len()
    }
}

/// Check whether the protocol version is supported.
fn version_is_supported(version: u32) -> bool {
    matches!(version, QUIC_VERSION_V1)
}

/// Configurations about QUIC endpoint.
#[derive(Clone)]
pub struct Config {
    /// QUIC transport configuration.
    local_transport_params: TransportParams,

    /// Handshake timeout in microseconds.
    max_handshake_timeout: time::Duration,

    /// Maximum number of concurrent connections.
    max_concurrent_conns: u32,

    /// Maximum size of the receiver connection flow control window.
    max_connection_window: u64,

    /// Maximum size of the receiver stream flow control window.
    max_stream_window: u64,

    /// Uses Retry packets to reduce load on servers by forcing the client to
    /// prove ownership of its address
    retry: bool,

    /// Enable stateless reset or not.
    stateless_reset: bool,

    /// Duration after a retry token was issued for which it's considered valid.
    address_token_lifetime: Duration,

    /// Key for address token generation.
    address_token_key: Vec<LessSafeKey>,

    /// Key for stateless reset token generation.
    reset_token_key: hmac::Key,

    /// Length of source cid.
    cid_len: usize,

    /// Anti-amplification factor.
    anti_amplification_factor: usize,

    /// Maximum numbers of packets sent in a batch.
    send_batch_size: usize,

    /// Buffer size for early incoming zero rtt packets, in packets.
    zerortt_buffer_size: usize,

    /// Configurations about loss recovery, congestion control, and pmtu discovery.
    recovery: RecoveryConfig,

    /// Multipath transport configurations.
    multipath: MultipathConfig,

    /// Find TLS config according to server name.
    tls_config_selector: Option<Arc<dyn tls::TlsConfigSelector>>,
}

impl Config {
    /// Create default configuration.
    ///
    /// The configuration may be customized by calling related set methods.
    ///
    /// ## Examples:
    ///
    /// ```
    /// let mut conf = tquic::Config::new()?;
    /// conf.set_max_idle_timeout(30000);
    /// let alpn =  vec![b"h3".to_vec()];
    /// let mut tls_config = tquic::TlsConfig::new_client_config(alpn, true)?;
    /// conf.set_tls_config(tls_config);
    /// # Ok::<(), tquic::error::Error>(())
    /// ```
    pub fn new() -> Result<Self> {
        // TODO: review default value
        let local_transport_params = TransportParams {
            initial_max_data: 10485760,
            initial_max_stream_data_bidi_local: 5242880,
            initial_max_stream_data_bidi_remote: 2097152,
            initial_max_stream_data_uni: 1048576,
            initial_max_streams_bidi: 200,
            initial_max_streams_uni: 100,
            ..TransportParams::default()
        };

        let reset_token_key = hmac::Key::new(hmac::HMAC_SHA256, &[]);

        Ok(Self {
            local_transport_params,
            max_handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_concurrent_conns: 1000000,
            max_connection_window: stream::MAX_CONNECTION_WINDOW,
            max_stream_window: stream::MAX_STREAM_WINDOW,
            retry: false,
            stateless_reset: true,
            address_token_lifetime: Duration::from_secs(86400),
            address_token_key: Self::rand_address_token_key()?,
            reset_token_key,
            cid_len: 8,
            anti_amplification_factor: ANTI_AMPLIFICATION_FACTOR,
            send_batch_size: 64,
            zerortt_buffer_size: 1000,
            recovery: RecoveryConfig::default(),
            multipath: MultipathConfig::default(),
            tls_config_selector: None,
        })
    }

    /// Set the `max_idle_timeout` transport parameter in milliseconds.
    /// Idle timeout is disabled by default.
    pub fn set_max_idle_timeout(&mut self, v: u64) {
        self.local_transport_params.max_idle_timeout = cmp::min(v, VINT_MAX);
    }

    /// Set handshake timeout in milliseconds. Zero turns the timeout off.
    pub fn set_max_handshake_timeout(&mut self, v: u64) {
        self.max_handshake_timeout = time::Duration::from_millis(v);
    }

    /// Set the `max_udp_payload_size` transport parameter in bytes. It limits
    /// the size of UDP payloads that the endpoint is willing to receive. The
    /// default value is `65527`.
    pub fn set_recv_udp_payload_size(&mut self, v: u16) {
        self.local_transport_params.max_udp_payload_size = cmp::min(v as u64, VINT_MAX);
    }

    /// Enable the Datagram Packetization Layer Path MTU Discovery
    /// default value is true.
    pub fn enable_dplpmtud(&mut self, v: bool) {
        self.recovery.enable_dplpmtud = v;
    }

    /// Set the maximum outgoing UDP payload size in bytes.
    /// It corresponds to the maximum datagram size that DPLPMTUD tries to discovery.
    /// The default value is `1200` which means let DPLPMTUD choose a value.
    pub fn set_send_udp_payload_size(&mut self, v: usize) {
        self.recovery.max_datagram_size = cmp::max(v, DEFAULT_SEND_UDP_PAYLOAD_SIZE);
    }

    /// Set the `initial_max_data` transport parameter. It means the initial
    /// value for the maximum amount of data that can be sent on the connection.
    /// The value is capped by the setting `max_connection_window`.
    /// The default value is `10485760`.
    pub fn set_initial_max_data(&mut self, v: u64) {
        self.local_transport_params.initial_max_data = cmp::min(v, self.max_connection_window);
    }

    /// Set the `initial_max_stream_data_bidi_local` transport parameter.
    /// The value is capped by the setting `max_stream_window`.
    /// The default value is `5242880`.
    pub fn set_initial_max_stream_data_bidi_local(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_local = cmp::min(v, self.max_stream_window);
    }

    /// Set the `initial_max_stream_data_bidi_remote` transport parameter.
    /// The value is capped by the setting `max_stream_window`.
    /// The default value is `2097152`.
    pub fn set_initial_max_stream_data_bidi_remote(&mut self, v: u64) {
        self.local_transport_params
            .initial_max_stream_data_bidi_remote = cmp::min(v, self.max_stream_window);
    }

    /// Set the `initial_max_stream_data_uni` transport parameter.
    /// The value is capped by the setting `max_stream_window`.
    /// The default value is `1048576`.
    pub fn set_initial_max_stream_data_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_stream_data_uni =
            cmp::min(v, self.max_stream_window);
    }

    /// Set the `initial_max_streams_bidi` transport parameter.
    /// The default value is `200`.
    pub fn set_initial_max_streams_bidi(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_bidi = cmp::min(v, VINT_MAX);
    }

    /// Set the `initial_max_streams_uni` transport parameter.
    /// The default value is `100`.
    pub fn set_initial_max_streams_uni(&mut self, v: u64) {
        self.local_transport_params.initial_max_streams_uni = cmp::min(v, VINT_MAX);
    }

    /// Set the `ack_delay_exponent` transport parameter.
    /// The default value is `3`.
    pub fn set_ack_delay_exponent(&mut self, v: u64) {
        self.local_transport_params.ack_delay_exponent = cmp::min(v, VINT_MAX);
    }

    /// Set the `max_ack_delay` transport parameter.
    /// The default value is `25`.
    pub fn set_max_ack_delay(&mut self, v: u64) {
        self.local_transport_params.max_ack_delay = cmp::min(v, VINT_MAX);
    }

    /// Set congestion control algorithm that the connection would use.
    /// The default value is Bbr.
    pub fn set_congestion_control_algorithm(&mut self, cca: CongestionControlAlgorithm) {
        self.recovery.congestion_control_algorithm = cca;
    }

    /// Set the initial congestion window in packets.
    /// The default value is 10.
    pub fn set_initial_congestion_window(&mut self, packets: u64) {
        self.recovery.initial_congestion_window = packets;
    }

    /// Set the minimal congestion window in packets.
    /// The default value is 2.
    pub fn set_min_congestion_window(&mut self, packets: u64) {
        self.recovery.min_congestion_window = packets
    }

    /// Set the threshold for slow start in packets.
    /// The default value is the maximum value of u64.
    pub fn set_slow_start_thresh(&mut self, packets: u64) {
        self.recovery.slow_start_thresh = packets
    }

    /// Set the minimum duration for BBR ProbeRTT state in milliseconds.
    /// The default value is 200 milliseconds.
    pub fn set_bbr_probe_rtt_duration(&mut self, millis: u64) {
        self.recovery.bbr_probe_rtt_duration =
            cmp::max(Duration::from_millis(millis), TIMER_GRANULARITY);
    }

    /// Enable using a cwnd based on bdp during ProbeRTT state.
    /// The default value is false.
    pub fn enable_bbr_probe_rtt_based_on_bdp(&mut self, v: bool) {
        self.recovery.bbr_probe_rtt_based_on_bdp = v;
    }

    /// Set the cwnd gain for BBR ProbeRTT state.
    /// This option is meaningful only when `bbr_probe_rtt_based_on_bdp` option
    /// is set to true.
    /// The default value is 0.75
    pub fn set_bbr_probe_rtt_cwnd_gain(&mut self, v: f64) {
        self.recovery.bbr_probe_rtt_cwnd_gain = v;
    }

    /// Set the length of the BBR RTProp min filter window in milliseconds.
    /// The default value is 10000 milliseconds.
    pub fn set_bbr_rtprop_filter_len(&mut self, millis: u64) {
        self.recovery.bbr_rtprop_filter_len =
            cmp::max(Duration::from_millis(millis), TIMER_GRANULARITY);
    }

    /// Set the cwnd gain for BBR ProbeBW state.
    /// The default value is 2.0
    pub fn set_bbr_probe_bw_cwnd_gain(&mut self, v: f64) {
        self.recovery.bbr_probe_bw_cwnd_gain = v;
    }

    /// Set the initial RTT in milliseconds. The default value is 333ms.
    ///
    /// The configuration should be changed with caution. Setting a value less than the default
    /// will cause retransmission of handshake packets to be more aggressive.
    pub fn set_initial_rtt(&mut self, millis: u64) {
        self.recovery.initial_rtt = cmp::max(Duration::from_millis(millis), TIMER_GRANULARITY);
    }

    /// Enable pacing to smooth the flow of packets sent onto the network.
    /// The default value is true.
    pub fn enable_pacing(&mut self, v: bool) {
        self.recovery.enable_pacing = v;
    }

    /// Set clock granularity used by the pacer.
    /// The default value is 1 milliseconds.
    pub fn set_pacing_granularity(&mut self, millis: u64) {
        self.recovery.pacing_granularity =
            cmp::max(Duration::from_millis(millis), TIMER_GRANULARITY);
    }

    /// Set the linear factor for calculating the probe timeout.
    /// The endpoint do not backoff the first `v` consecutive probe timeouts.
    /// The default value is `0`.
    /// The configuration should be changed with caution. Setting a value greater than the default
    /// will cause retransmission to be more aggressive.
    pub fn set_pto_linear_factor(&mut self, v: u64) {
        self.recovery.pto_linear_factor = v;
    }

    /// Set the upper limit of probe timeout in milliseconds.
    /// A Probe Timeout (PTO) triggers the sending of one or two probe datagrams and enables a
    /// connection to recover from loss of tail packets or acknowledgments.
    /// See RFC 9002 Section 6.2.
    pub fn set_max_pto(&mut self, millis: u64) {
        self.recovery.max_pto = cmp::max(Duration::from_millis(millis), TIMER_GRANULARITY);
    }

    /// Set the `active_connection_id_limit` transport parameter.
    /// The default value is `2`. Lower values will be ignored.
    pub fn set_active_connection_id_limit(&mut self, v: u64) {
        if v >= 2 {
            self.local_transport_params.active_conn_id_limit = cmp::min(v, VINT_MAX);
        }
    }

    /// Set the `enable_multipath` transport parameter.
    /// The default value is false. (Experimental)
    pub fn enable_multipath(&mut self, v: bool) {
        self.local_transport_params.enable_multipath = v;
    }

    /// Set the multipath scheduling algorithm
    /// The default value is MultipathAlgorithm::MinRtt
    pub fn set_multipath_algorithm(&mut self, v: MultipathAlgorithm) {
        self.multipath.multipath_algorithm = v;
    }

    /// Set the maximum size of the connection flow control window.
    /// The default value is MAX_CONNECTION_WINDOW (15 MB).
    pub fn set_max_connection_window(&mut self, v: u64) {
        self.max_connection_window = cmp::min(v, VINT_MAX);
    }

    /// Set the maximum size of the stream flow control window.
    /// The value should not be greater than the setting `max_connection_window`.
    /// The default value is MAX_STREAM_WINDOW (6 MB).
    pub fn set_max_stream_window(&mut self, v: u64) {
        self.max_stream_window = cmp::min(v, VINT_MAX);
    }

    /// Set the maximum number of concurrent connections.
    /// The default value is `1000000`
    pub fn set_max_concurrent_conns(&mut self, v: u32) {
        self.max_concurrent_conns = v;
    }

    /// Set the key for reset token generation.
    /// Applicable to Server only.
    pub fn set_reset_token_key(&mut self, v: [u8; 64]) {
        // HMAC-SHA256 use a 512-bit block length
        self.reset_token_key = hmac::Key::new(hmac::HMAC_SHA256, &v);
    }

    /// Set the lifetime of address token.
    /// Applicable to Server only.
    pub fn set_address_token_lifetime(&mut self, seconds: u64) {
        self.address_token_lifetime = Duration::from_secs(seconds);
    }

    /// Set the key for address token generation.
    /// Applicable to Server only.
    pub fn set_address_token_key(&mut self, keys: Vec<[u8; 16]>) -> Result<()> {
        if keys.is_empty() {
            return Err(Error::InvalidConfig("address token key empty".into()));
        }

        let mut address_token_key = vec![];
        for key in keys {
            // AES-128 uses a 128-bit key length
            let key = UnboundKey::new(&aead::AES_128_GCM, &key).map_err(|_| Error::CryptoFail)?;
            let key = LessSafeKey::new(key);
            address_token_key.push(key);
        }
        self.address_token_key = address_token_key;

        Ok(())
    }

    /// Set whether stateless retry is allowed. Default is not allowed.
    /// Applicable to Server only.
    pub fn enable_retry(&mut self, enable_retry: bool) {
        self.retry = enable_retry;
    }

    /// Set whether stateless reset is allowed.
    /// Applicable to Endpoint only.
    pub fn enable_stateless_reset(&mut self, enable_stateless_reset: bool) {
        self.stateless_reset = enable_stateless_reset;
    }

    /// Set the length of source cid.
    /// Applicable to Endpoint only.
    pub fn set_cid_len(&mut self, v: usize) {
        self.cid_len = cmp::min(v, MAX_CID_LEN);
    }

    /// Set the anti-amplification factor.
    ///
    /// The server limits the data sent to an unvalidated address to
    /// `anti_amplification_factor` times the received data.
    pub fn set_anti_amplification_factor(&mut self, v: usize) {
        self.anti_amplification_factor = cmp::max(v, ANTI_AMPLIFICATION_FACTOR);
    }

    /// Set the batch size for sending packets.
    /// Applicable to Endpoint only.
    pub fn set_send_batch_size(&mut self, v: usize) {
        self.send_batch_size = cmp::max(v, 1);
    }

    /// Set the buffer size for disordered zerortt packets on the server.
    /// The default value is `1000`. A value of 0 will be treated as default value.
    /// Applicable to Server only.
    pub fn set_zerortt_buffer_size(&mut self, v: usize) {
        if v > 0 {
            self.zerortt_buffer_size = v;
        } else {
            self.zerortt_buffer_size = 1000;
        }
    }

    /// Set TLS config.
    pub fn set_tls_config(&mut self, tls_config: tls::TlsConfig) {
        self.set_tls_config_selector(Arc::new(tls::DefaultTlsConfigSelector {
            tls_config: Arc::new(tls_config),
        }));
    }

    /// Set TLS config selector. Used for selecting TLS config according to SNI.
    pub fn set_tls_config_selector(
        &mut self,
        tls_config_selector: Arc<dyn tls::TlsConfigSelector>,
    ) {
        self.tls_config_selector = Some(tls_config_selector);
    }

    /// Generate random address token key.
    fn rand_address_token_key() -> Result<Vec<LessSafeKey>> {
        let mut key = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(vec![LessSafeKey::new(
            UnboundKey::new(&aead::AES_128_GCM, &key).map_err(|_| Error::CryptoFail)?,
        )])
    }

    /// Create new tls session.
    fn new_tls_session(&self, server_name: Option<&str>, is_server: bool) -> Result<TlsSession> {
        if self.tls_config_selector.is_none() {
            return Err(Error::TlsFail("tls config selector is not set".into()));
        }
        match self.tls_config_selector.as_ref().unwrap().get_default() {
            Some(tls_config) => tls_config.new_session(server_name, is_server),
            None => Err(Error::TlsFail("get tls config failed".into())),
        }
    }
}

/// Configurations about loss recovery, congestion control, and pmtu discovery.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Enable Datagram Packetization Layer Path MTU Discovery.
    pub enable_dplpmtud: bool,

    /// The maximum size of outgoing UDP payloads.
    pub max_datagram_size: usize,

    /// The maximum amount of time the endpoint intends to delay acknowledgments
    /// for packets in the Application Data packet number space.
    max_ack_delay: Duration,

    /// The congestion control algorithm used for a path.
    pub congestion_control_algorithm: CongestionControlAlgorithm,

    /// The minimal congestion window in packets.
    /// The RECOMMENDED value is 2 * max_datagram_size.
    /// See RFC 9002 Section 7.2
    pub min_congestion_window: u64,

    /// The initial congestion window in packets.
    /// Endpoints SHOULD use an initial congestion window of ten times the
    /// maximum datagram size (max_datagram_size), while limiting the window to
    /// the larger of 14,720 bytes or twice the maximum datagram size.
    /// See RFC 9002 Section 7.2
    pub initial_congestion_window: u64,

    /// The threshold for slow start in packets.
    pub slow_start_thresh: u64,

    /// The minimum duration for BBR ProbeRTT state
    pub bbr_probe_rtt_duration: Duration,

    /// Enable using a cwnd based on bdp during ProbeRTT state.
    pub bbr_probe_rtt_based_on_bdp: bool,

    /// The cwnd gain for BBR ProbeRTT state
    pub bbr_probe_rtt_cwnd_gain: f64,

    /// The length of the RTProp min filter window
    pub bbr_rtprop_filter_len: Duration,

    /// The cwnd gain for ProbeBW state
    pub bbr_probe_bw_cwnd_gain: f64,

    /// The initial rtt, used before real rtt is estimated.
    pub initial_rtt: Duration,

    /// Enable pacing to smooth the flow of packets sent onto the network.
    pub enable_pacing: bool,

    /// Clock granularity used by the pacer.
    pub pacing_granularity: Duration,

    /// Linear factor for calculating the probe timeout.
    pub pto_linear_factor: u64,

    /// Upper limit of probe timeout.
    pub max_pto: Duration,
}

impl Default for RecoveryConfig {
    fn default() -> RecoveryConfig {
        RecoveryConfig {
            enable_dplpmtud: true,
            max_datagram_size: DEFAULT_SEND_UDP_PAYLOAD_SIZE, // The upper limit is determined by DPLPMTUD
            max_ack_delay: time::Duration::from_millis(0),
            congestion_control_algorithm: CongestionControlAlgorithm::Bbr,
            min_congestion_window: 2_u64,
            initial_congestion_window: 10_u64,
            slow_start_thresh: u64::MAX,
            bbr_probe_rtt_duration: Duration::from_millis(200),
            bbr_probe_rtt_based_on_bdp: false,
            bbr_probe_rtt_cwnd_gain: 0.75,
            bbr_rtprop_filter_len: Duration::from_secs(10),
            bbr_probe_bw_cwnd_gain: 2.0,
            initial_rtt: INITIAL_RTT,
            enable_pacing: true,
            pacing_granularity: time::Duration::from_millis(1),
            pto_linear_factor: DEFAULT_PTO_LINEAR_FACTOR,
            max_pto: MAX_PTO,
        }
    }
}

/// Configurations about multipath transport.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct MultipathConfig {
    /// Multipath scheduling algorithm.
    multipath_algorithm: MultipathAlgorithm,
}

impl Default for MultipathConfig {
    fn default() -> MultipathConfig {
        MultipathConfig {
            multipath_algorithm: MultipathAlgorithm::MinRtt,
        }
    }
}

/// Events sent from a Connection to an Endpoint.
enum Event {
    /// The connection handshake is complete.
    ConnectionEstablished,

    /// The client connection has received a NEW_TOKEN frame.
    NewToken(Vec<u8>),

    /// The connection need to advertise new scids via NEW_CONNECTION_ID frame.
    ScidToAdvertise(u8),

    /// The connection has received a RETIRE_CONNECTION_ID frame.
    ScidRetired(ConnectionId),

    /// The connection has received a dcid via NEW_CONNECTION_ID frame.
    DcidAdvertised(ResetToken),

    /// The connection has send a RETIRE_CONNECTION_ID frame.
    DcidRetired(ResetToken),

    /// The client connection has received a stateless reset token from transport
    /// parameters extension.
    ResetTokenAdvertised(ResetToken),

    /// The stream is created.
    StreamCreated(u64),

    /// The stream is closed.
    StreamClosed(u64),
}

#[derive(Default)]
struct EventQueue(Option<VecDeque<Event>>);

impl EventQueue {
    /// Enable the event queue.
    fn enable(&mut self) {
        self.0 = Some(VecDeque::new());
    }

    /// Add an endpoint-faceing event.
    fn add(&mut self, e: Event) -> bool {
        if let Some(events) = &mut self.0 {
            events.push_back(e);
            return true;
        }
        false
    }

    /// Return an endpoint-facing event.
    fn poll(&mut self) -> Option<Event> {
        if let Some(events) = &mut self.0 {
            return events.pop_front();
        }
        None
    }

    /// Check whether the event queue is empty.
    fn is_empty(&self) -> bool {
        if let Some(events) = &self.0 {
            return events.is_empty();
        }
        true
    }
}

struct ConnectionQueues {
    /// Connections with timer or other events to process.
    tickable: FxHashSet<u64>,

    /// Connections with packets to be send.
    sendable: FxHashSet<u64>,
}

impl ConnectionQueues {
    fn new() -> Self {
        Self {
            tickable: FxHashSet::default(),
            sendable: FxHashSet::default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.tickable.is_empty() && self.sendable.is_empty()
    }

    fn tickable_next(&self) -> Option<u64> {
        self.tickable.iter().next().copied()
    }

    fn sendable_next(&self) -> Option<u64> {
        self.sendable.iter().next().copied()
    }
}

/// The TransportHandler lists the callbacks used by the endpoint to
/// communicate with the user application code.
pub trait TransportHandler {
    /// Called when a new connection has been created. This callback is called
    /// as soon as connection object is created inside the endpoint, but
    /// before the handshake is done. The connection has progressed enough to
    /// send early data if possible.
    fn on_conn_created(&mut self, conn: &mut Connection);

    /// Called when the handshake is completed.
    fn on_conn_established(&mut self, conn: &mut Connection);

    /// Called when the connection is closed. The connection is no longer
    /// accessible after this callback returns. It is a good time to clean up
    /// the connection context.
    fn on_conn_closed(&mut self, conn: &mut Connection);

    /// Called when the stream is created.
    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64);

    /// Called when the stream is readable. This callback is called when either
    /// there are bytes to be read or an error is ready to be collected.
    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64);

    /// Called when the stream is writable.
    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64);

    /// Called when the stream is closed. The stream is no longer accessible
    /// after this callback returns. It is a good time to clean up the stream
    /// context.
    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64);

    /// Called when client receives a token in NEW_TOKEN frame.
    fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>);
}

/// The PacketSendHandler lists the callbacks used by the endpoint to
/// send packet out.
pub trait PacketSendHandler {
    /// Called when the connection is sending packets out.
    ///
    /// On success, `on_packets_send()` returns the number of messages sent. If
    /// this is less than `pkts.len()`, the connection will retry with a further
    /// `on_packets_send()` call to send the remaining messages.
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> Result<usize>;
}

/// The stream's side to shutdown.
#[repr(C)]
#[derive(PartialEq, Eq)]
pub enum Shutdown {
    /// Stop receiving data on the stream.
    Read = 0,

    /// Stop sending data on the stream.
    Write = 1,
}

/// Important events about path
pub enum PathEvent {
    /// The path has been validated.
    Validated(usize),

    /// The path has been abandoned.
    Abandoned(usize),
}

/// Statistics about path
#[repr(C)]
#[derive(Default)]
pub struct PathStats {
    /// The number of QUIC packets received.
    pub recv_count: u64,

    /// The number of received bytes.
    pub recv_bytes: u64,

    /// The number of QUIC packets sent.
    pub sent_count: u64,

    /// The number of sent bytes.
    pub sent_bytes: u64,

    /// The number of QUIC packets lost.
    pub lost_count: u64,

    /// The number of lost bytes.
    pub lost_bytes: u64,

    /// Total number of packets acked.
    pub acked_count: u64,

    /// Total number of bytes acked.
    pub acked_bytes: u64,

    /// Initial congestion window in bytes.
    pub init_cwnd: u64,

    /// Final congestion window in bytes.
    pub final_cwnd: u64,

    /// Maximum congestion window in bytes.
    pub max_cwnd: u64,

    /// Minimum congestion window in bytes.
    pub min_cwnd: u64,

    /// Maximum inflight data in bytes.
    pub max_inflight: u64,

    /// Total loss events.
    pub loss_event_count: u64,

    /// Total congestion window limited events.
    pub cwnd_limited_count: u64,

    /// Total duration of congestion windowlimited events in microseconds.
    pub cwnd_limited_duration: u64,

    /* Note: the following fields are lazily updated from Recovery */
    /// Minimum roundtrip time in microseconds.
    pub min_rtt: u64,

    /// Maximum roundtrip time in microseconds.
    pub max_rtt: u64,

    /// Smoothed roundtrip time in microseconds.
    pub srtt: u64,

    /// Roundtrip time variation in microseconds.
    pub rttvar: u64,

    /// Whether the congestion controller is in slow start status.
    pub in_slow_start: bool,

    /// Pacing rate estimated by congestion control algorithm.
    pub pacing_rate: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ctor::ctor]
    fn init() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Trace)
            .format_timestamp_millis()
            .is_test(true)
            .init();
    }

    #[test]
    fn connection_id() {
        let mut cid_gen = RandomConnectionIdGenerator::new(8);
        let cid = cid_gen.generate();
        assert_eq!(cid.len(), cid_gen.cid_len());

        let cid = ConnectionId {
            len: 4,
            data: [0xa8; 20],
        };
        assert_eq!(format!("{}", cid), "a8a8a8a8");
    }

    #[test]
    fn initial_rtt() -> Result<()> {
        let mut config = Config::new()?;

        config.set_initial_rtt(0);
        assert_eq!(config.recovery.initial_rtt, TIMER_GRANULARITY);

        config.set_initial_rtt(100);
        assert_eq!(config.recovery.initial_rtt, Duration::from_millis(100));

        Ok(())
    }

    #[test]
    fn pto_linear_factor() -> Result<()> {
        let mut config = Config::new()?;
        assert_eq!(config.recovery.pto_linear_factor, DEFAULT_PTO_LINEAR_FACTOR);

        config.set_pto_linear_factor(0);
        assert_eq!(config.recovery.pto_linear_factor, 0);

        config.set_pto_linear_factor(100);
        assert_eq!(config.recovery.pto_linear_factor, 100);

        Ok(())
    }

    #[test]
    fn max_pto() -> Result<()> {
        let mut config = Config::new()?;
        assert_eq!(config.recovery.max_pto, MAX_PTO);

        config.set_max_pto(0);
        assert_eq!(config.recovery.max_pto, TIMER_GRANULARITY);

        config.set_max_pto(300000);
        assert_eq!(config.recovery.max_pto, Duration::from_millis(300000));

        Ok(())
    }

    #[test]
    fn initial_max_streams_bidi() -> Result<()> {
        let mut config = Config::new()?;
        config.set_initial_max_streams_bidi(u64::MAX);
        assert_eq!(
            config.local_transport_params.initial_max_streams_bidi,
            VINT_MAX
        );

        Ok(())
    }
}

pub use crate::congestion_control::CongestionControlAlgorithm;
pub use crate::connection::path::Path;
pub use crate::connection::Connection;
pub use crate::endpoint::Endpoint;
pub use crate::error::Error;
pub use crate::multipath_scheduler::MultipathAlgorithm;
pub use crate::packet::PacketHeader;
pub use crate::tls::TlsConfig;
pub use crate::tls::TlsConfigSelector;

#[path = "connection/connection.rs"]
pub mod connection;

#[path = "congestion_control/congestion_control.rs"]
mod congestion_control;

#[path = "multipath_scheduler/multipath_scheduler.rs"]
mod multipath_scheduler;

#[path = "tls/tls.rs"]
mod tls;

#[path = "h3/h3.rs"]
pub mod h3;

#[path = "qlog/qlog.rs"]
mod qlog;

#[cfg(feature = "ffi")]
mod ffi;

// Note: Workaround for the module path issue in cbindgen.
// DON'T enable this feature when building with cargo.
#[cfg(feature = "cbindgen")]
#[path = "h3/connection.rs"]
mod h3_connection;

mod codec;
pub mod endpoint;
pub mod error;
mod frame;
mod packet;
mod ranges;
#[doc(hidden)]
pub mod timer_queue;
mod token;
mod trans_param;
mod window;
