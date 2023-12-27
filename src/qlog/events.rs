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

//! Concrete qlog event definitions for QUIC, HTTP/3 and QPACK
//! - draft-ietf-quic-qlog-quic-events-06
//! - draft-ietf-quic-qlog-h3-events-05

use serde::Deserialize;
use serde::Serialize;
use smallvec::SmallVec;

/// Each event is specified as a generic object with a number of member fields
/// and their associated data.
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    /// The "time" field indicates the timestamp at which the event occurred.
    pub time: f32,

    /// The data field is a generic object. It contains the per-event metadata
    /// and its form and semantics are defined per specific sort of event.
    #[serde(flatten)]
    pub data: EventData,

    /// The employed format is indicated in the "time_format" field, which
    /// allows one of three values: "absolute", "delta" or "relative"
    pub time_format: Option<TimeFormat>,

    /// The "protocol_type" array field indicates to which protocols this event
    /// belongs. This allows a single qlog file to aggregate traces of different
    /// protocols
    pub protocol_type: Option<String>,

    /// A server implementation might choose to log events for all incoming
    /// connections in a single large (streamed) qlog file. As such, we need a
    /// method for splitting up events belonging to separate logical entities.
    /// The simplest way to perform this splitting is by associating a "group
    /// identifier" to each event that indicates to which conceptual "group"
    /// each event belongs.
    pub group_id: Option<String>,
}

impl Event {
    pub fn new(time: f32, data: EventData) -> Self {
        Event {
            time,
            data,
            time_format: Default::default(),
            protocol_type: Default::default(),
            group_id: Default::default(),
        }
    }

    /// Return the importance of the event.
    pub fn importance(&self) -> EventImportance {
        self.data.importance()
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Event) -> bool {
        self.time == other.time
            && self.data == other.data
            && self.protocol_type == other.protocol_type
            && self.group_id == other.group_id
            && self.time_format == other.time_format
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "name", content = "data")]
#[allow(clippy::large_enum_variant)]
pub enum EventData {
    /// Emitted when the server starts accepting connections.
    #[serde(rename = "connectivity:server_listening")]
    ConnectivityServerListening {
        ip_v4: Option<String>,
        ip_v6: Option<String>,
        port_v4: Option<u16>,
        port_v6: Option<u16>,
        retry_required: Option<bool>,
    },

    /// Used for both attempting (client-perspective) and accepting (server-perspective)
    /// new connections. Note that this event has overlap with connection_state_updated
    /// and this is a separate event mainly because of all the additional data that
    /// should be logged.
    #[serde(rename = "connectivity:connection_started")]
    ConnectivityConnectionStarted {
        ip_version: Option<String>, // "v4" or "v6"
        src_ip: String,
        dst_ip: String,
        protocol: Option<String>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        src_cid: Option<String>,
        dst_cid: Option<String>,
    },

    /// Used for logging when a connection was closed, typically when an error or
    /// timeout occurred. Note that this event has overlap with
    /// connectivity_connection_state_updated, as well as the CONNECTION_CLOSE frame.
    /// However, in practice, when analyzing large deployments, it can be useful to
    /// have a single event representing a connection_closed event, which also
    /// includes an additional reason field to provide additional information.
    /// Additionally, it is useful to log closures due to timeouts, which are
    /// difficult to reflect using the other options.
    #[serde(rename = "connectivity:connection_closed")]
    ConnectivityConnectionClosed {
        owner: Option<Owner>, // which side closed the connection
        connection_code: Option<ConnectionErrorCode>,
        application_code: Option<ApplicationErrorCode>,
        internal_code: Option<u32>,
        reason: Option<String>,
        trigger: Option<ConnectionClosedTrigger>,
    },

    /// This event is emitted when either party updates their current Connection ID.
    /// As this typically happens only sparingly over the course of a connection,
    /// this event allows loggers to be more efficient than logging the observed
    /// CID with each packet in the .header field of the "packet_sent" or
    /// "packet_received" events.
    #[serde(rename = "connectivity:connection_id_updated")]
    ConnectivityConnectionIdUpdated {
        owner: Option<Owner>,
        old: Option<String>,
        new: Option<String>,
    },

    /// To be emitted when the spin bit changes value. It SHOULD NOT be emitted if
    /// the spin bit is set without changing its value.
    #[serde(rename = "connectivity:spin_bit_updated")]
    ConnectivitySpinBitUpdated { state: bool },

    /// This event is used to track progress through QUIC's complex handshake and
    /// connection close procedures. It is intended to provide exhaustive options
    /// to log each state individually, but also provides a more basic, simpler
    /// set for implementations less interested in tracking each smaller state
    /// transition. As such, users should not expect to see -all- these states
    /// reflected in all qlogs and implementers should focus on support for the
    /// SimpleConnectionState set.
    #[serde(rename = "connectivity:connection_state_updated")]
    ConnectivityConnectionStateUpdated {
        old: Option<ConnectionState>,
        new: ConnectionState,
    },

    /// This event indicates that the estimated Path MTU was updated. This happens
    /// as part of the Path MTU discovery process.
    #[serde(rename = "connectivity:mtu_updated")]
    ConnectivityMtuUpdated {
        old: Option<u16>,
        new: u16,
        done: Option<bool>,
    },

    /// QUIC endpoints each have their own list of of QUIC versions they support.
    /// The client uses the most likely version in their first initial. If the
    /// server does support that version, it replies with a version_negotiation
    /// packet, containing supported versions. From this, the client selects a
    /// version. This event aggregates all this information in a single event type.
    /// It also allows logging of supported versions at an endpoint without actual
    /// version negotiation needing to happen.
    #[serde(rename = "quic:version_information")]
    QuicVersionInformation {
        server_versions: Option<Vec<String>>,
        client_versions: Option<Vec<String>>,
        chosen_version: Option<String>,
    },

    /// QUIC implementations each have their own list of application level
    /// protocols and versions thereof they support. The client includes a list of
    /// their supported options in its first initial as part of the TLS Application
    /// Layer Protocol Negotiation (alpn) extension. If there are common option(s),
    /// the server chooses the most optimal one and communicates this back to the
    /// client. If not, the connection is closed.
    #[serde(rename = "quic:alpn_information")]
    QuicAlpnInformation {
        server_alpns: Option<Vec<String>>,
        client_alpns: Option<Vec<String>>,
        chosen_alpn: Option<String>,
    },

    /// This event groups settings from several different sources (transport
    /// parameters, TLS ciphers, etc.) into a single event. This is done to
    /// minimize the amount of events and to decouple conceptual setting
    /// impacts from their underlying mechanism for easier high-level reasoning.
    #[serde(rename = "quic:parameters_set")]
    QuicParametersSet {
        owner: Option<Owner>,
        resumption_allowed: Option<bool>,
        early_data_enabled: Option<bool>,
        tls_cipher: Option<String>,
        original_destination_connection_id: Option<String>,
        initial_source_connection_id: Option<String>,
        retry_source_connection_id: Option<String>,
        stateless_reset_token: Option<String>,
        disable_active_migration: Option<bool>,
        max_idle_timeout: Option<u64>,
        max_udp_payload_size: Option<u32>,
        ack_delay_exponent: Option<u16>,
        max_ack_delay: Option<u16>,
        active_connection_id_limit: Option<u32>,
        initial_max_data: Option<u64>,
        initial_max_stream_data_bidi_local: Option<u64>,
        initial_max_stream_data_bidi_remote: Option<u64>,
        initial_max_stream_data_uni: Option<u64>,
        initial_max_streams_bidi: Option<u64>,
        initial_max_streams_uni: Option<u64>,
        preferred_address: Option<PreferredAddress>,
        max_datagram_frame_size: Option<u64>,
        grease_quic_bit: Option<bool>,
    },

    /// When using QUIC 0-RTT, clients are expected to remember and restore the
    /// server's transport parameters from the previous connection. This event is
    /// used to indicate which parameters were restored and to which values when
    /// utilizing 0-RTT. Note that not all transport parameters should be restored
    /// (many are even prohibited from being re-utilized). The ones listed here are
    /// the ones expected to be useful for correct 0-RTT usage.
    #[serde(rename = "quic:parameters_restored")]
    QuicParametersRestored {
        disable_active_migration: Option<bool>,
        max_idle_timeout: Option<u64>,
        max_udp_payload_size: Option<u32>,
        active_connection_id_limit: Option<u32>,
        initial_max_data: Option<u64>,
        initial_max_stream_data_bidi_local: Option<u64>,
        initial_max_stream_data_bidi_remote: Option<u64>,
        initial_max_stream_data_uni: Option<u64>,
        initial_max_streams_bidi: Option<u64>,
        initial_max_streams_uni: Option<u64>,
    },

    /// This event indicates a QUIC-level packet was sent.
    #[serde(rename = "quic:packet_sent")]
    QuicPacketSent {
        header: PacketHeader,
        is_coalesced: Option<bool>,
        retry_token: Option<Token>,
        stateless_reset_token: Option<String>,
        supported_versions: Option<Vec<String>>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        is_mtu_probe_packet: Option<bool>,
        trigger: Option<PacketSentTrigger>,
    },

    /// This event indicates a QUIC-level packet was received.
    #[serde(rename = "quic:packet_received")]
    QuicPacketReceived {
        header: PacketHeader,
        is_coalesced: Option<bool>,
        retry_token: Option<Token>,
        stateless_reset_token: Option<String>,
        supported_versions: Option<Vec<String>>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        trigger: Option<PacketReceivedTrigger>,
    },

    /// This event indicates a QUIC-level packet was dropped.
    #[serde(rename = "quic:packet_dropped")]
    QuicPacketDropped {
        header: Option<PacketHeader>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        details: Option<String>,
        trigger: Option<PacketDroppedTrigger>,
    },

    /// This event is emitted when a packet is buffered because it cannot be processed
    /// yet. Typically, this is because the packet cannot be parsed yet, and thus only
    /// the full packet contents can be logged when it was parsed in a packet_received
    /// event.
    #[serde(rename = "quic:packet_buffered")]
    QuicPacketBuffered {
        header: Option<PacketHeader>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        trigger: Option<PacketBufferedTrigger>,
    },

    /// This event is emitted when a (group of) sent packet(s) is acknowledged by the
    /// remote peer for the first time. This information could also be deduced from
    /// the contents of received ACK frames. However, ACK frames require additional
    /// processing logic to determine when a given packet is acknowledged for the
    /// first time, as QUIC uses ACK ranges which can include repeated ACKs.
    /// Additionally, this event can be used by implementations that do not log
    /// frame contents.
    #[serde(rename = "quic:version_information")]
    QuicPacketsAcked {
        packet_number_space: Option<PacketNumberSpace>,
        packet_numbers: Option<Vec<u64>>,
    },

    /// When one or more UDP-level datagrams are passed to the socket. This is
    /// useful for determining how QUIC packet buffers are drained to the OS.
    #[serde(rename = "quic:datagrams_sent")]
    QuicDatagramsSent {
        count: Option<u16>,        // To support passing multiple at once
        raw: Option<Vec<RawInfo>>, // Include only the UDP payload
        datagram_ids: Option<Vec<u32>>,
    },

    /// When one or more UDP-level datagrams are received from the socket. This is
    /// useful for determining how datagrams are passed to the user space stack
    /// from the OS.
    #[serde(rename = "quic:datagrams_received")]
    QuicDatagramsReceived {
        count: Option<u16>,
        raw: Option<Vec<RawInfo>>,
        ecn: Option<Vec<Ecn>>,
        datagram_ids: Option<Vec<u32>>,
    },

    /// When a UDP-level datagram is dropped. This is typically done if it does not
    /// contain a valid QUIC packet. If it does, but the QUIC packet is dropped for
    /// other reasons, packet_dropped (Section 5.7) should be used instead.
    #[serde(rename = "quic:datagram_dropped")]
    QuicDatagramDropped { raw: Option<RawInfo> },

    /// This event is emitted whenever the internal state of a QUIC stream is updated,
    /// as described in QUIC transport draft-23 section 3. Most of this can be
    /// inferred from several types of frames going over the wire, but it's much
    /// easier to have explicit signals for these state changes.
    #[serde(rename = "quic:stream_state_updated")]
    QuicStreamStateUpdated {
        stream_id: u64,
        stream_type: Option<StreamType>,
        old: Option<StreamState>,
        new: StreamState,
        stream_side: Option<StreamSide>,
    },

    /// This event's main goal is to prevent a large proliferation of specific
    /// purpose events (e.g., packets_acknowledged, flow_control_updated,
    /// stream_data_received). Implementations have the opportunity to
    /// (selectively) log this type of signal without having to log packet-level
    /// details (e.g., in packet_received). Since for almost all cases, the effects
    /// of applying a frame to the internal state of an implementation can be
    /// inferred from that frame's contents, these events are aggregated into this
    /// single "frames_processed" event.
    #[serde(rename = "quic:frames_processed")]
    QuicFramesProcessed {
        frames: Vec<QuicFrame>,
        packet_number: Option<u64>,
    },

    /// Used to indicate when data moves between the different layers (for example
    /// passing from the application protocol (e.g., HTTP) to QUIC stream buffers
    /// and vice versa) or between the application protocol (e.g., HTTP) and the
    /// actual user application on top (for example a browser engine). This helps
    /// make clear the flow of data, how long data remains in various buffers and
    /// the overheads introduced by individual layers.
    #[serde(rename = "quic:stream_data_moved")]
    QuicStreamDataMoved {
        stream_id: Option<u64>,
        offset: Option<u64>,
        length: Option<u64>,
        from: Option<DataRecipient>,
        to: Option<DataRecipient>,
        raw: Option<RawInfo>,
    },

    /// Used to indicate when QUIC Datagram Frame data (see [RFC9221]) moves
    /// between the different layers (for example passing from the application
    /// protocol (e.g., WebTransport) to QUIC Datagram Frame buffers and vice
    /// versa) or between the application protocol and the actual user
    /// application on top (for example a gaming engine or media playback
    /// software). This helps make clear the flow of data, how long data remains
    /// in various buffers and the overheads introduced by individual layers.
    #[serde(rename = "quic:datagram_data_moved")]
    QuicDatagramDataMoved {
        length: Option<u64>,
        from: Option<DataRecipient>,
        to: Option<DataRecipient>,
        raw: Option<RawInfo>,
    },

    /// This event indicates the 1RTT key was updated.
    #[serde(rename = "security:key_updated")]
    SecurityKeyUpdated {
        key_type: KeyType,
        old: Option<String>,
        new: String,
        generation: Option<u32>, // Needed for 1RTT key updates
        trigger: Option<KeyUpdateOrRetiredTrigger>,
    },

    /// This event indicates a key was discarded.
    #[serde(rename = "security:key_retired")]
    SecurityKeyDiscarded {
        key_type: KeyType,
        key: Option<String>,
        generation: Option<u32>,
        trigger: Option<KeyUpdateOrRetiredTrigger>, // Needed for 1RTT key updates
    },

    /// This event groups initial parameters from both loss detection and congestion
    /// control into a single event. All these settings are typically set once and
    /// never change. Implementation that do, for some reason, change these
    /// parameters during execution, MAY emit the parameters_set event twice.
    #[serde(rename = "recovery:parameters_set")]
    RecoveryParametersSet {
        reordering_threshold: Option<u16>,
        time_threshold: Option<f32>,
        timer_granularity: Option<u16>,
        initial_rtt: Option<f32>,
        max_datagram_size: Option<u32>,
        initial_congestion_window: Option<u64>,
        minimum_congestion_window: Option<u32>,
        loss_reduction_factor: Option<f32>,
        persistent_congestion_threshold: Option<u16>,
    },

    /// This event is emitted when one or more of the observable recovery metrics
    /// changes value. This event SHOULD group all possible metric updates that
    /// happen at or around the same time in a single event (e.g., if min_rtt
    /// and smoothed_rtt change at the same time, they should be bundled in a
    /// single metrics_updated entry, rather than split out into two).
    /// Consequently, a metrics_updated event is only guaranteed to contain at
    /// least one of the listed metrics.
    #[serde(rename = "recovery:metrics_updated")]
    RecoveryMetricsUpdated {
        min_rtt: Option<f32>,
        smoothed_rtt: Option<f32>,
        latest_rtt: Option<f32>,
        rtt_variance: Option<f32>,
        pto_count: Option<u16>,
        congestion_window: Option<u64>,
        bytes_in_flight: Option<u64>,
        ssthresh: Option<u64>,
        packets_in_flight: Option<u64>,
        pacing_rate: Option<u64>,
    },

    /// This event signifies when the congestion controller enters a significant
    /// new state and changes its behaviour. This event's definition is kept
    /// generic to support different Congestion Control algorithms. For example,
    /// for the algorithm defined in the Recovery draft ("enhanced" New Reno),
    /// the following states are defined:
    #[serde(rename = "recovery:congestion_state_updated")]
    RecoveryCongestionStateUpdated {
        old: Option<String>,
        new: String,
        trigger: Option<CongestionStateUpdatedTrigger>,
    },

    /// This event is emitted when a recovery loss timer changes state.
    #[serde(rename = "recovery:loss_timer_updated")]
    RecoveryLossTimerUpdated {
        timer_type: Option<TimerType>,
        packet_number_space: Option<PacketNumberSpace>,
        event_type: LossTimerEventType,
        delta: Option<f32>,
    },

    /// This event is emitted when a packet is deemed lost by loss detection.
    #[serde(rename = "recovery:packet_lost")]
    RecoveryPacketLost {
        header: Option<PacketHeader>,
        frames: Option<Vec<QuicFrame>>,
        is_mtu_probe_packet: Option<bool>,
        trigger: Option<PacketLostTrigger>,
    },

    /// This event indicates which data was marked for retransmit upon detecting a
    /// packet loss (see packet_lost). Similar to our reasoning for the
    /// "frames_processed" event, in order to keep the amount of different events
    /// low, this signal is grouped into in a single event based on existing QUIC
    /// frame definitions for all types of retransmittable data.
    #[serde(rename = "recovery:marked_for_retransmit")]
    RecoveryMarkedForRetransmit { frames: Vec<QuicFrame> },

    #[serde(rename = "recovery:ecn_state_updated")]
    RecoveryEcnStateUpdated {
        old: Option<EcnState>,
        new: EcnState,
    },

    /// This event contains HTTP/3 and QPACK-level settings, mostly those received
    /// from the HTTP/3 SETTINGS frame. All these parameters are typically set once
    /// and never change. However, they are typically set at different times during
    /// the connection, so there can be several instances of this event with
    /// different fields set.
    #[serde(rename = "h3:parameters_set")]
    H3ParametersSet {
        owner: Option<Owner>,
        #[serde(alias = "max_header_list_size")]
        max_field_section_size: Option<u64>,
        max_table_capacity: Option<u64>,
        blocked_streams_count: Option<u64>,
        enable_connect: Option<u64>,
        h3_datagram: Option<u64>,
        /// indicates whether this implementation waits for a SETTINGS frame before
        /// processing requests
        waits_for_settings: Option<bool>,
    },

    /// When using QUIC 0-RTT, HTTP/3 clients are expected to remember and reuse the
    /// server's SETTINGs from the previous connection. This event is used to
    /// indicate which HTTP/3 settings were restored and to which values when
    /// utilizing 0-RTT.
    #[serde(rename = "h3:parameters_restored")]
    H3ParametersRestored {
        #[serde(alias = "max_header_list_size")]
        max_field_section_size: Option<u64>,
        max_table_capacity: Option<u64>,
        blocked_streams_count: Option<u64>,
        enable_connect_protocol: Option<u64>,
        h3_datagram: Option<u64>,
    },

    /// Emitted when a stream's type becomes known. This is typically when a stream
    /// is opened and the stream's type indicator is sent or received.
    #[serde(rename = "h3:stream_type_set")]
    H3StreamTypeSet {
        owner: Option<Owner>,
        stream_id: u64,
        stream_type: Http3StreamType,
        stream_type_value: Option<u64>,
        associated_push_id: Option<u64>,
    },

    /// Emitted when the priority of a request stream or push stream is initialized
    /// or updated through mechanisms defined in [RFC9218].
    H3PriorityUpdated {
        stream_id: Option<u64>,
        push_id: Option<u64>,
        old: Option<String>,
        new: String,
    },

    /// This event is emitted when the HTTP/3 framing actually happens. This does
    /// not necessarily coincide with HTTP/3 data getting passed to the QUIC layer.
    /// For that, see the "data_moved" event in [QLOG-QUIC].
    #[serde(rename = "h3:frame_created")]
    H3FrameCreated {
        stream_id: u64,
        length: Option<u64>,
        frame: Http3Frame,
        raw: Option<RawInfo>,
    },

    /// This event is emitted when the HTTP/3 frame is parsed. Note: this is not
    /// necessarily the same as when the HTTP/3 data is actually received on the
    /// QUIC layer. For that, see the "data_moved" event in [QLOG-QUIC].
    #[serde(rename = "h3:frame_parsed")]
    H3FrameParsed {
        stream_id: u64,
        length: Option<u64>,
        frame: Http3Frame,
        raw: Option<RawInfo>,
    },

    /// This event is emitted when a pushed resource is successfully claimed (used)
    /// or, conversely, abandoned (rejected) by the application on top of HTTP/3
    /// (e.g., the web browser). This event is added to help debug problems with
    /// unexpected PUSH behaviour, which is commonplace with HTTP/2.
    #[serde(rename = "h3:push_resolved")]
    H3PushResolved {
        push_id: Option<u64>,
        stream_id: Option<u64>,
        decision: Http3PushDecision,
    },

    /// This event is emitted when one or more of the internal QPACK variables
    /// changes value. Note that some variables have two variations (one set locally,
    /// one requested by the remote peer). This is reflected in the "owner" field.
    /// As such, this field MUST be correct for all variables included a single event
    /// instance. If you need to log settings from two sides, you MUST emit two
    /// separate event instances.
    #[serde(rename = "qpack:state_updated")]
    QpackStateUpdated {
        owner: Option<Owner>,
        dynamic_table_capacity: Option<u64>,
        dynamic_table_size: Option<u64>,
        known_received_count: Option<u64>,
        current_insert_count: Option<u64>,
    },

    /// This event is emitted when a stream becomes blocked or unblocked by header
    /// decoding requests or QPACK instructions.
    #[serde(rename = "qpack:stream_state_updated")]
    QpackStreamStateUpdated {
        stream_id: u64,
        state: QpackStreamState,
    },

    /// This event is emitted when one or more entries are inserted or evicted from
    /// QPACK's dynamic table.
    #[serde(rename = "qpack:dynamic_table_updated")]
    QpackDynamicTableUpdated {
        owner: Owner,
        update_type: QpackUpdateType,
        entries: Vec<QpackDynamicTableEntry>,
    },

    /// This event is emitted when an uncompressed header block is encoded
    /// successfully.
    #[serde(rename = "qpack:headers_encoded")]
    QpackHeadersEncoded {
        stream_id: Option<u64>,
        headers: Option<HttpHeader>,
        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,
        raw: Option<RawInfo>,
    },

    /// This event is emitted when a compressed header block is decoded successfully.
    #[serde(rename = "qpack:headers_decoded")]
    QpackHeadersDecoded {
        stream_id: Option<u64>,
        headers: Option<HttpHeader>,
        block_prefix: QpackHeaderBlockPrefix,
        header_block: Vec<QpackHeaderBlockRepresentation>,
        raw: Option<RawInfo>,
    },

    /// This event is emitted when a QPACK instruction (both decoder and encoder)
    /// is created and added to the encoder/decoder stream.
    #[serde(rename = "qpack:instruction_created")]
    QpackInstructionCreated {
        instruction: QPackInstruction,
        raw: Option<RawInfo>,
    },

    /// This event is emitted when a QPACK instruction (both decoder and encoder)
    /// is read from the encoder/decoder stream.
    #[serde(rename = "qpack:instruction_parsed")]
    QpackInstructionParsed {
        instruction: QPackInstruction,
        raw: Option<RawInfo>,
    },

    /// Used to log details of an internal error that might not get reflected
    /// on the wire.
    #[serde(rename = "generic:internal_error")]
    GenericInternalError {
        code: Option<u64>,
        description: Option<String>,
    },

    /// Used to log details of an internal warning that might not get reflected
    /// on the wire.
    #[serde(rename = "generic:internal_warning")]
    GenericInternalWarning {
        code: Option<u64>,
        description: Option<String>,
    },

    /// Used mainly for implementations that want to use qlog as their one and
    /// only logging format but still want to support unstructured string messages.
    #[serde(rename = "generic:info")]
    GenericInternalInfo { message: String },

    /// Used mainly for implementations that want to use qlog as their one and
    /// only logging format but still want to support unstructured string messages.
    #[serde(rename = "generic:debug")]
    GenericInternalDebug { message: String },

    /// Used mainly for implementations that want to use qlog as their one and
    /// only logging format but still want to support unstructured string messages.
    #[serde(rename = "generic:verbose")]
    GenericInternalVerbose { message: String },

    /// Used to indicate when specific emulation conditions are triggered at set
    /// times
    #[serde(rename = "generic:marker")]
    SimulationMarker {
        marker_type: String,
        message: Option<String>,
    },
}

impl EventData {
    /// Return importance of the concrete event.
    pub fn importance(&self) -> EventImportance {
        use crate::qlog::EventData::*;
        match *self {
            ConnectivityServerListening { .. } => EventImportance::Extra,
            ConnectivityConnectionStarted { .. } => EventImportance::Base,
            ConnectivityConnectionIdUpdated { .. } => EventImportance::Base,
            ConnectivitySpinBitUpdated { .. } => EventImportance::Base,
            ConnectivityConnectionStateUpdated { .. } => EventImportance::Base,
            ConnectivityMtuUpdated { .. } => EventImportance::Extra,

            QuicParametersSet { .. } => EventImportance::Core,
            QuicDatagramsReceived { .. } => EventImportance::Extra,
            QuicDatagramsSent { .. } => EventImportance::Extra,
            QuicDatagramDropped { .. } => EventImportance::Extra,
            QuicPacketReceived { .. } => EventImportance::Core,
            QuicPacketSent { .. } => EventImportance::Core,
            QuicPacketDropped { .. } => EventImportance::Base,
            QuicPacketBuffered { .. } => EventImportance::Base,
            QuicStreamStateUpdated { .. } => EventImportance::Base,
            QuicFramesProcessed { .. } => EventImportance::Extra,
            QuicStreamDataMoved { .. } => EventImportance::Base,

            SecurityKeyUpdated { .. } => EventImportance::Base,
            SecurityKeyDiscarded { .. } => EventImportance::Base,

            RecoveryParametersSet { .. } => EventImportance::Base,
            RecoveryMetricsUpdated { .. } => EventImportance::Core,
            RecoveryCongestionStateUpdated { .. } => EventImportance::Base,
            RecoveryLossTimerUpdated { .. } => EventImportance::Extra,
            RecoveryPacketLost { .. } => EventImportance::Core,
            RecoveryMarkedForRetransmit { .. } => EventImportance::Extra,

            H3ParametersSet { .. } => EventImportance::Base,
            H3StreamTypeSet { .. } => EventImportance::Base,
            H3FrameCreated { .. } => EventImportance::Core,
            H3FrameParsed { .. } => EventImportance::Core,
            H3PushResolved { .. } => EventImportance::Extra,

            QpackStateUpdated { .. } => EventImportance::Base,
            QpackStreamStateUpdated { .. } => EventImportance::Base,
            QpackDynamicTableUpdated { .. } => EventImportance::Extra,
            QpackHeadersEncoded { .. } => EventImportance::Base,
            QpackHeadersDecoded { .. } => EventImportance::Base,
            QpackInstructionCreated { .. } => EventImportance::Base,
            QpackInstructionParsed { .. } => EventImportance::Base,

            _ => unimplemented!(),
        }
    }
}

/// An "importance indicator" in decreasing order of importance and expected
/// usage.
#[derive(Clone, PartialEq, PartialOrd)]
pub enum EventImportance {
    /// The "Core" events are the events that SHOULD be present in all qlog
    /// files for a given protocol.
    Core = 0,

    /// The "Base" events add additional debugging options and CAN be present
    /// in qlog files.
    Base = 1,

    /// The "Extra" events are considered mostly useful for low-level debugging
    /// of the implementation, rather than the protocol.
    Extra = 2,
}

impl EventImportance {
    /// Return true if this importance level is included by `other`.
    pub fn is_contained_in(&self, other: &EventImportance) -> bool {
        self <= other
    }
}

/// The "time" field indicates the timestamp at which the event occurred.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum TimeFormat {
    /// Include the full absolute timestamp with each event. This approach uses
    /// the largest amount of characters.
    Absolute,

    /// Delta-encode each time value on the previously logged value. The first
    /// event in a trace typically logs the full absolute timestamp. This
    /// approach uses the least amount of characters.
    Delta,

    /// Specify a full "reference_time" timestamp and include only
    /// relatively-encoded values based on this reference_time with each event.
    /// The "reference_time" value is typically the first absolute timestamp.
    /// This approach uses a medium amount of characters.
    Relative,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DataRecipient {
    User,
    Application,
    Transport,
    Network,
    Dropped,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RawInfo {
    pub length: Option<u64>,
    pub payload_length: Option<u64>,
    pub data: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum ConnectionErrorCode {
    TransportError(TransportError),
    CryptoError(CryptoError),
    Value(u64),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum ApplicationErrorCode {
    ApplicationError(ApplicationError),
    Value(u64),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CryptoError {
    Prefix,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionClosedTrigger {
    Clean,
    HandshakeTimeout,
    IdleTimeout,
    Error,
    StatelessReset,
    VersionMismatch,
    Application,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Attempted,
    PeerValidated,
    HandshakeStarted,
    EarlyWrite,
    HandshakeCompleted,
    HandshakeConfirmed,
    Closing,
    Draining,
    Closed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketType {
    Initial,
    Handshake,
    #[serde(rename = "0RTT")]
    ZeroRtt,
    #[serde(rename = "1RTT")]
    OneRtt,
    Retry,
    VersionNegotiation,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData,
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct PacketHeader {
    pub packet_type: PacketType,
    pub packet_number: u64,
    pub flags: Option<u8>,
    pub token: Option<Token>,
    pub length: Option<u16>,
    pub version: Option<String>,
    pub scil: Option<u8>,
    pub dcil: Option<u8>,
    pub scid: Option<String>,
    pub dcid: Option<String>,
}

impl PacketHeader {
    /// Creates a new PacketHeader.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packet_type: PacketType,
        packet_number: u64,
        flags: Option<u8>,
        token: Option<Token>,
        length: Option<u16>,
        version: Option<u32>,
        scid: Option<&[u8]>,
        dcid: Option<&[u8]>,
    ) -> Self {
        let (scil, scid) = match scid {
            Some(cid) => (Some(cid.len() as u8), Some(hex::encode(cid))),
            None => (None, None),
        };
        let (dcil, dcid) = match dcid {
            Some(cid) => (Some(cid.len() as u8), Some(hex::encode(cid))),
            None => (None, None),
        };
        let version = version.map(|v| format!("{v:x?}"));

        PacketHeader {
            packet_type,
            packet_number,
            flags,
            token,
            length,
            version,
            scil,
            dcil,
            scid,
            dcid,
        }
    }

    /// Creates a new PacketHeader.
    pub fn new_with_type(
        ty: PacketType,
        packet_number: u64,
        version: Option<u32>,
        scid: Option<&[u8]>,
        dcid: Option<&[u8]>,
    ) -> Self {
        match ty {
            // Not logging version, dcid and scid in OneRtt packet.
            PacketType::OneRtt => {
                PacketHeader::new(ty, packet_number, None, None, None, None, None, None)
            }
            _ => PacketHeader::new(ty, packet_number, None, None, None, version, scid, dcid),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Token {
    #[serde(rename(serialize = "type"))]
    pub token_type: Option<TokenType>,
    pub details: Option<String>,
    pub raw: Option<RawInfo>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Retry,
    Resumption,
}

#[allow(clippy::enum_variant_names)]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    ServerInitialSecret,
    ClientInitialSecret,
    ServerHandshakeSecret,
    ClientHandshakeSecret,
    #[serde(rename = "server_0rtt_secret")]
    Server0RttSecret,
    #[serde(rename = "client_0rtt_secret")]
    Client0RttSecret,
    #[serde(rename = "server_1rtt_secret")]
    Server1RttSecret,
    #[serde(rename = "client_1rtt_secret")]
    Client1RttSecret,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Ecn {
    #[serde(rename = "Not-ECT")]
    NotEct,
    #[serde(rename = "ECT(1)")]
    Ect1,
    #[serde(rename = "ECT(0)")]
    Ect0,
    #[serde(rename = "CE")]
    Ce,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Bidirectional,
    Unidirectional,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSpace {
    TransportError,
    ApplicationError,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    NoError,
    InternalError,
    ConnectionRefused,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIdLimitError,
    ProtocolViolation,
    InvalidToken,
    ApplicationError,
    CryptoBufferExceeded,
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketSentTrigger {
    RetransmitReordered,
    RetransmitTimeout,
    PtoProbe,
    RetransmitCrypto,
    CcBandwidthProbe,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketReceivedTrigger {
    KeysUnavailable,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketDroppedTrigger {
    InternalError,
    Rejected,
    Unsupported,
    Invalid,
    ConnectionUnknown,
    DecryptionFailure,
    General,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketBufferedTrigger {
    Backpressure,
    KeysUnavailable,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LossTimerEventType {
    Set,
    Expired,
    Cancelled,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum AckedRanges {
    Single(Vec<Vec<u64>>),
    Double(Vec<(u64, u64)>),
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QuicFrameTypeName {
    Padding,
    Ping,
    Ack,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    ApplicationClose,
    HandshakeDone,
    Datagram,
    Unknown,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "frame_type")]
#[serde(rename_all = "snake_case")]
pub enum QuicFrame {
    Padding,

    Ping,

    Ack {
        ack_delay: Option<f32>,
        acked_ranges: Option<AckedRanges>,
        ect1: Option<u64>,
        ect0: Option<u64>,
        ce: Option<u64>,
    },

    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    StopSending {
        stream_id: u64,
        error_code: u64,
    },

    Crypto {
        offset: u64,
        length: u64,
    },

    NewToken {
        token: Token,
    },

    Stream {
        stream_id: u64,
        offset: u64,
        length: u64,
        fin: Option<bool>,
        raw: Option<RawInfo>,
    },

    MaxData {
        maximum: u64,
    },

    MaxStreamData {
        stream_id: u64,
        maximum: u64,
    },

    MaxStreams {
        stream_type: StreamType,
        maximum: u64,
    },

    DataBlocked {
        limit: u64,
    },

    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },

    StreamsBlocked {
        stream_type: StreamType,
        limit: u64,
    },

    NewConnectionId {
        sequence_number: u32,
        retire_prior_to: u32,
        connection_id_length: Option<u8>,
        connection_id: String,
        stateless_reset_token: Option<String>,
    },

    RetireConnectionId {
        sequence_number: u32,
    },

    PathChallenge {
        data: Option<String>,
    },

    PathResponse {
        data: Option<String>,
    },

    ConnectionClose {
        error_space: Option<ErrorSpace>,
        error_code: Option<u64>,
        error_code_value: Option<u64>,
        reason: Option<String>,
        trigger_frame_type: Option<u64>,
    },

    HandshakeDone,

    Datagram {
        length: u64,
        raw: Option<String>,
    },

    Unknown {
        raw_frame_type: u64,
        frame_type_value: Option<u64>,
        raw: Option<RawInfo>,
    },
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QuicAlpnInformation {
    pub server_alpns: Option<Vec<String>>,
    pub client_alpns: Option<Vec<String>>,
    pub chosen_alpn: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PreferredAddress {
    pub ip_v4: String,
    pub ip_v6: String,
    pub port_v4: u16,
    pub port_v6: u16,
    pub connection_id: String,
    pub stateless_reset_token: String,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct QuicPacketSent {
    pub header: PacketHeader,
    pub is_coalesced: Option<bool>,
    pub retry_token: Option<Token>,
    pub stateless_reset_token: Option<String>,
    pub supported_versions: Option<Vec<String>>,
    pub raw: Option<RawInfo>,
    pub datagram_id: Option<u32>,
    pub trigger: Option<PacketSentTrigger>,
    pub send_at_time: Option<f32>,
    pub frames: Option<SmallVec<[QuicFrame; 1]>>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    // bidirectional stream states
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,

    // sending-side stream states
    Ready,
    Send,
    DataSent,
    ResetSent,
    ResetReceived,

    // receive-side stream states
    Receive,
    SizeKnown,
    DataRead,
    ResetRead,

    // both-side states
    DataReceived,

    // qlog-defined
    Destroyed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CongestionStateUpdatedTrigger {
    PersistentCongestion,
    Ecn,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum PacketLostTrigger {
    ReorderingThreshold,
    TimeThreshold,
    PtoExpired,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum KeyUpdateOrRetiredTrigger {
    Tls,
    RemoteUpdate,
    LocalUpdate,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EcnState {
    Testing,
    Unknown,
    Failed,
    Capable,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3StreamType {
    Request,
    Control,
    Push,
    Reserved,
    Unknown,
    QpackEncode,
    QpackDecode,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3PriorityTargetStreamType {
    Request,
    Push,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3EventType {
    ParametersSet,
    ParametersRestored,
    StreamTypeSet,
    FrameCreated,
    FrameParsed,
    PushResolved,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationError {
    HttpNoError,
    HttpGeneralProtocolError,
    HttpInternalError,
    HttpRequestCancelled,
    HttpIncompleteRequest,
    HttpConnectError,
    HttpFrameError,
    HttpExcessiveLoad,
    HttpVersionFallback,
    HttpIdError,
    HttpStreamCreationError,
    HttpClosedCriticalStream,
    HttpEarlyResponse,
    HttpMissingSettings,
    HttpUnexpectedFrame,
    HttpRequestRejection,
    HttpSettingsError,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Setting {
    pub name: String,
    pub value: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3FrameTypeName {
    Data,
    Headers,
    CancelPush,
    Settings,
    PushPromise,
    Goaway,
    MaxPushId,
    DuplicatePush,
    Reserved,
    Unknown,
}

// Strictly, the qlog spec says that all these frame types have a frame_type
// field. But instead of making that a rust object property, just use serde to
// ensure it goes out on the wire. This means that deserialization of frames
// also works automatically.
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(tag = "frame_type")]
#[serde(rename_all = "snake_case")]
pub enum Http3Frame {
    Data {
        raw: Option<RawInfo>,
    },

    Headers {
        headers: Vec<HttpHeader>,
    },

    CancelPush {
        push_id: u64,
    },

    Settings {
        settings: Vec<Setting>,
    },

    PushPromise {
        push_id: u64,
        headers: Vec<HttpHeader>,
    },

    Goaway {
        id: u64,
    },

    MaxPushId {
        push_id: u64,
    },

    PriorityUpdate {
        target_stream_type: Http3PriorityTargetStreamType,
        prioritized_element_id: u64,
        priority_field_value: String,
    },

    Reserved {
        length: Option<u64>,
    },

    Unknown {
        frame_type_value: u64,
        raw: Option<RawInfo>,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Http3PushDecision {
    Claimed,
    Abandoned,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackEventType {
    StateUpdated,
    StreamStateUpdated,
    DynamicTableUpdated,
    HeadersEncoded,
    HeadersDecoded,
    InstructionCreated,
    InstructionParsed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackUpdateType {
    Added,
    Evicted,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackDynamicTableEntry {
    pub index: u64,
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct QpackHeaderBlockPrefix {
    pub required_insert_count: u64,
    pub sign_bit: bool,
    pub delta_base: u64,
}

#[allow(clippy::enum_variant_names)]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackInstructionTypeName {
    SetDynamicTableCapacityInstruction,
    InsertWithNameReferenceInstruction,
    InsertWithoutNameReferenceInstruction,
    DuplicateInstruction,
    HeaderAcknowledgementInstruction,
    StreamCancellationInstruction,
    InsertCountIncrementInstruction,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackTableType {
    Static,
    Dynamic,
}

#[allow(clippy::enum_variant_names)]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum QPackInstruction {
    SetDynamicTableCapacityInstruction {
        instruction_type: QpackInstructionTypeName,
        capacity: u64,
    },

    InsertWithNameReferenceInstruction {
        instruction_type: QpackInstructionTypeName,
        table_type: QpackTableType,
        name_index: u64,
        huffman_encoded_value: bool,
        value_length: Option<u64>,
        value: Option<String>,
    },

    InsertWithoutNameReferenceInstruction {
        instruction_type: QpackInstructionTypeName,
        huffman_encoded_name: bool,
        name_length: Option<u64>,
        name: Option<String>,
        huffman_encoded_value: bool,
        value_length: Option<u64>,
        value: Option<String>,
    },

    DuplicateInstruction {
        instruction_type: QpackInstructionTypeName,
        index: u64,
    },

    HeaderAcknowledgementInstruction {
        instruction_type: QpackInstructionTypeName,
        stream_id: String,
    },

    StreamCancellationInstruction {
        instruction_type: QpackInstructionTypeName,
        stream_id: String,
    },

    InsertCountIncrementInstruction {
        instruction_type: QpackInstructionTypeName,
        increment: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackHeaderBlockRepresentationTypeName {
    IndexedHeaderField,
    LiteralHeaderFieldWithName,
    LiteralHeaderFieldWithoutName,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum QpackHeaderBlockRepresentation {
    IndexedHeaderField {
        header_field_type: QpackHeaderBlockRepresentationTypeName,
        table_type: QpackTableType,
        index: u64,
        is_post_base: Option<bool>,
    },

    LiteralHeaderFieldWithName {
        header_field_type: QpackHeaderBlockRepresentationTypeName,
        preserve_literal: bool,
        table_type: QpackTableType,
        name_index: u64,
        huffman_encoded_value: bool,
        value_length: Option<u64>,
        value: Option<String>,
        is_post_base: Option<bool>,
    },

    LiteralHeaderFieldWithoutName {
        header_field_type: QpackHeaderBlockRepresentationTypeName,
        preserve_literal: bool,
        huffman_encoded_name: bool,
        name_length: Option<u64>,
        name: Option<String>,
        huffman_encoded_value: bool,
        value_length: Option<u64>,
        value: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QpackStreamState {
    Blocked,
    Unblocked,
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn new_test_pkt_hdr(packet_type: PacketType) -> PacketHeader {
        PacketHeader::new(
            packet_type,
            0,
            None,
            None,
            None,
            Some(0x0000_0001),
            Some(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            Some(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]),
        )
    }

    #[test]
    fn serialize_packet_header() {
        let pkt_hdr = new_test_pkt_hdr(PacketType::Initial);
        assert_eq!(
            serde_json::to_string_pretty(&pkt_hdr).unwrap(),
            r#"{
  "packet_type": "initial",
  "packet_number": 0,
  "version": "1",
  "scil": 8,
  "dcil": 8,
  "scid": "0102030405060708",
  "dcid": "0807060504030201"
}"#
        );
    }

    #[test]
    fn serialize_quic_packet_sent_event() {
        let pkt_hdr = new_test_pkt_hdr(PacketType::Initial);
        let event_data = EventData::QuicPacketSent {
            header: pkt_hdr,
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(RawInfo {
                length: Some(1200),
                payload_length: Some(1173),
                data: None,
            }),
            datagram_id: None,
            is_mtu_probe_packet: None,
            trigger: None,
        };

        let event = Event::new(1234567000.0, event_data);
        assert_eq!(
            serde_json::to_string_pretty(&event).unwrap(),
            r#"{
  "time": 1234567000.0,
  "name": "quic:packet_sent",
  "data": {
    "header": {
      "packet_type": "initial",
      "packet_number": 0,
      "version": "1",
      "scil": 8,
      "dcil": 8,
      "scid": "0102030405060708",
      "dcid": "0807060504030201"
    },
    "raw": {
      "length": 1200,
      "payload_length": 1173
    }
  }
}"#
        );
    }
}
