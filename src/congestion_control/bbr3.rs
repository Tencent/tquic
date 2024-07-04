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

//! BBR Congestion Control
//!
//! VERSION 3
//!
//! BBR uses recent measurements of a transport connection's delivery rate
//! and round-trip time to build an explicit model that includes both the
//! maximum recent bandwidth available to that connection, and its
//! minimum recent round-trip delay.  BBR then uses this model to control
//! both how fast it sends data and the maximum amount of data it allows
//! in flight in the network at any time.
//!
//! See <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control-02>
//! and <https://datatracker.ietf.org/meeting/117/materials/slides-117-ccwg-bbrv3-algorithm-bug-fixes-and-public-internet-deployment-00>.

extern crate rand;

use std::time::{Duration, Instant};

use log::*;
use rand::Rng;

use super::delivery_rate::DeliveryRateEstimator;
use super::minmax::MinMax;
use super::{CongestionController, CongestionStats};
use crate::connection::rtt::RttEstimator;
use crate::connection::space::{RateSamplePacketState, SentPacket};
use crate::RecoveryConfig;

/// BBR configurable parameters.
#[derive(Debug)]
pub struct Bbr3Config {
    /// Minimal congestion window in bytes.
    min_cwnd: u64,

    /// Initial congestion window in bytes.
    initial_cwnd: u64,

    /// Initial Smoothed rtt.
    initial_rtt: Option<Duration>,

    /// Max datagram size in bytes.
    max_datagram_size: u64,

    /// Max count of bandwidth growth that is less than GROWTH_RATE.
    full_bw_count_threshold: u64,

    /// Bandwidth growth rate to check if pipe is filled. Default to `25%`.
    full_bw_growth_rate: f64,

    /// Probe RTT duration.
    probe_rtt_duration: Duration,

    /// Probe RTT interval.
    probe_rtt_interval: Duration,

    /// The maximum tolerated per-round-trip packet loss rate when probing for bandwidth.
    loss_threshold: f64,

    /// Loss marking events threshold in a recovery round.
    full_loss_count: u64,

    /// The default multiplicative decrease to make upon each round trip during which
    /// the connection detects packet loss.
    beta: f64,

    /// The multiplicative factor to apply to BBR.inflight_hi when attempting to leave
    /// free headroom in the path.
    headroom: f64,
}

impl Bbr3Config {
    pub fn from(conf: &RecoveryConfig) -> Self {
        let max_datagram_size = conf.max_datagram_size as u64;
        let min_cwnd = conf.min_congestion_window.saturating_mul(max_datagram_size);
        let initial_cwnd = conf
            .initial_congestion_window
            .saturating_mul(max_datagram_size);

        Self {
            min_cwnd,
            initial_cwnd,
            initial_rtt: Some(conf.initial_rtt),
            max_datagram_size,
            ..Self::default()
        }
    }
}

impl Default for Bbr3Config {
    fn default() -> Self {
        Self {
            min_cwnd: 4 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            initial_cwnd: 80 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            initial_rtt: Some(crate::INITIAL_RTT),
            max_datagram_size: crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            full_bw_count_threshold: FULL_BW_COUNT_THRESHOLD,
            full_bw_growth_rate: FULL_BW_GROWTH_RATE,
            probe_rtt_duration: PROBE_RTT_DURATION,
            probe_rtt_interval: PROBE_RTT_INTERVAL,
            loss_threshold: LOSS_THRESH,
            full_loss_count: FULL_LOSS_COUNT,
            beta: BETA,
            headroom: HEADROOM,
        }
    }
}

/// A constant specifying the minimum gain value
/// for calculating the pacing rate that will allow the sending rate to
/// double each round (`4*ln(2)` ~= `2.77`) [BBRStartupPacingGain]; used in
/// Startup mode for BBR.pacing_gain.
const STARTUP_PACING_GAIN: f64 = 2.77;

/// The static discount factor of `1%` used to scale BBR.bw to produce BBR.pacing_rate.
const PACING_MARGIN_PERCENT: f64 = 0.01;

/// BBRLossThresh: The maximum tolerated per-round-trip packet loss rate when probing
/// for bandwidth (the default is `2%`).
const LOSS_THRESH: f64 = 0.02;

/// Exit STARTUP if number of loss marking events in a Recovery round is >= N,
/// and loss rate is higher than bbr_loss_thresh. Disabled if `0`.
// Default to `6` rather than `8`, According to BBRv3 performance tuning in
// <https://datatracker.ietf.org/meeting/117/materials/slides-117-ccwg-bbrv3-algorithm-bug-fixes-and-public-internet-deployment-00>.
const FULL_LOSS_COUNT: u64 = 6;

/// BBRBeta: The default multiplicative decrease to make upon each round trip during
/// which the connection detects packet loss (the value is `0.7`).
const BETA: f64 = 0.7;

/// BBRHeadroom: The multiplicative factor to apply to BBR.inflight_hi when attempting
/// to leave free headroom in the path (e.g. free space in the bottleneck buffer or
/// free time slots in the bottleneck link) that can be used by cross traffic (the value
/// is `0.85`).
const HEADROOM: f64 = 0.85;

/// BBRMinPipeCwnd: The minimal cwnd value BBR targets, to allow pipelining with TCP
/// endpoints that follow an "ACK every other packet" delayed-ACK policy: 4 * SMSS.
const MIN_PIPE_CWND_IN_SMSS: u64 = 4;

/// BBRExtraAckedFilterLen = The window length of the BBR.ExtraACKedFilter max filter window.
/// Default to 10 (in units of packet-timed round trips).
const EXTRA_ACKED_FILTER_LEN: u64 = 10;

/// MinRTTFilterLen: A constant specifying the length of the BBR.min_rtt min filter window,
/// MinRTTFilterLen is `10` secs.
const MIN_RTT_FILTER_LEN: Duration = Duration::from_secs(10);

/// ProbeRTTDuration: A constant specifying the minimum duration for which ProbeRTT state
/// holds inflight to BBRMinPipeCwnd or fewer packets: `200 ms`.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// ProbeRTTInterval: A constant specifying the minimum time interval between ProbeRTT states: `5` secs.
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(5);

/// Max count of full bandwidth reached, before pipe is supposed to be filled.
/// This three-round threshold was validated by YouTube experimental data.
const FULL_BW_COUNT_THRESHOLD: u64 = 3;

/// Bandwidth growth rate before pipe got filled. (Percentage)
const FULL_BW_GROWTH_RATE: f64 = 0.25;

/// Max number of packet-timed rounds to wait before probing for bandwidth.
/// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-time-scale-for-bandwidth-pr>.
//
// If we want to tolerate 1% random loss per round, and not have this cut our
// inflight too much, we must probe for bw periodically on roughly this scale.
// If low, limits Reno/CUBIC coexistence; if high, limits loss tolerance.
// We aim to be fair with Reno/CUBIC up to a BDP of at least:
//  `BDP = 25Mbps * .030sec /(1514bytes) = 61.9 packets`
const PROBE_BW_MAX_ROUNDS: u64 = 63;

// Max amount of randomness to inject in round counting for Reno-coexistence.
const PROBE_BW_RAND_ROUNDS: u64 = 2;

/// Lower bound of ProbeBW time scale.
/// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-design-considerations-for-c>
const PROBE_BW_MIN_WAIT_TIME_IN_MSEC: u64 = 2000;

/// Upper bound of ProbeBW time scale.
/// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-design-considerations-for-c>.
const PROBE_BW_MAX_WAIT_TIME_IN_MSEC: u64 = 3000;

/// Pacing rate threshold for select different send quantum. Default `1.2Mbps`.
/// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-send-quantum-bbrsend_quantu>.
const SEND_QUANTUM_THRESHOLD_PACING_RATE: u64 = 1_200_000 / 8;

/// BBR State Machine.
/// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-state-machine>.
//          |
//          V
// +---> Startup  ------------+
// |        |                 |
// |        V                 |
// |     Drain  --------------+
// |        |                 |
// |        V                 |
// +---> ProbeBW_DOWN  -------+
// | ^      |                 |
// | |      V                 |
// | |   ProbeBW_CRUISE ------+
// | |      |                 |
// | |      V                 |
// | |   ProbeBW_REFILL  -----+
// | |      |                 |
// | |      V                 |
// | |   ProbeBW_UP  ---------+
// | |      |                 |
// | +------+                 |
// |                          |
// +---- ProbeRTT <-----------+
#[derive(Debug, PartialEq, Eq)]
enum State {
    Startup,
    Drain,
    ProbeBwDown,
    ProbeBwCruise,
    ProbeBwRefill,
    ProbeBwUp,
    ProbeRTT,
}

/// Round trip counter for tracking packet-timed round trips which starts
/// at the transmission of some segment, and then end at the ack of that segment.
#[derive(Debug, Default)]
struct RoundTripCounter {
    /// BBR.round_count: Count of packet-timed round trips.
    pub round_count: u64,

    /// BBR.round_start: A boolean that BBR sets to true once per packet-
    /// timed round trip, on ACKs that advance BBR.round_count.
    pub is_round_start: bool,

    /// BBR.next_round_delivered: packet.delivered value denoting the end of
    /// a packet-timed round trip.
    pub next_round_delivered: u64,
}

/// Full pipe estimator, used mainly during Startup mode.
#[derive(Debug, Default)]
struct FullPipeEstimator {
    /// BBR.filled_pipe: A boolean that records whether BBR estimates that it
    /// has ever fully utilized its available bandwidth ("filled the pipe").
    is_filled_pipe: bool,

    /// Baseline level delivery rate for full pipe estimator.
    full_bw: u64,

    /// The number of round for full pipe estimator without much growth.
    full_bw_count: u64,
}

/// Accumulate information from a single ACK/SACK.
#[derive(Debug)]
struct AckState {
    /// Ack time.
    now: Instant,

    /// Newly marked lost data size in bytes.
    newly_lost_bytes: u64,

    /// Newly acked data size in bytes.
    newly_acked_bytes: u64,

    /// The last P.delivered in bytes.
    packet_delivered: u64,

    /// The last P.sent_time to determine whether exit recovery.
    last_ack_packet_sent_time: Instant,

    /// The amount of data that was in flight before processing this ACK.
    prior_bytes_in_flight: u64,

    /// rs.tx_in_flight: The volume of data that was estimated to be in flight
    /// at the time of the transmission of the packet that has just been ACKed.
    tx_in_flight: u64,

    /// rs.lost: The volume of data that was declared lost between the transmission
    /// and acknowledgement of the packet that has just been ACKed.
    lost: u64,
}

impl Default for AckState {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            now,
            newly_lost_bytes: 0,
            newly_acked_bytes: 0,
            packet_delivered: 0,
            last_ack_packet_sent_time: now,
            prior_bytes_in_flight: 0,
            tx_in_flight: 0,
            lost: 0,
        }
    }
}

/// The BBR max bandwidth filter window
/// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-bbrmax_bw-max-filter>.
#[derive(Default, Debug)]
struct SimpleMaxFilter {
    /// The BBR.max_bw max filter window covers a time period extending over the past two ProbeBW cycles.
    /// bw[1] is the latest bandwidth, and bw[0] is the previous one.
    bw: [u64; 2],
}

impl SimpleMaxFilter {
    fn new() -> Self {
        Self {
            bw: [Default::default(); 2],
        }
    }

    fn max_bw(&self) -> u64 {
        self.bw[0].max(self.bw[1])
    }
}

/// Ack probe phase.
#[derive(Debug, PartialEq, Eq)]
enum AckProbePhase {
    /// Not probing; not getting probe feedback.
    Init,

    /// Sending at est_bw to fill pipe.
    Stopping,

    /// Inflight rising to probe bw.
    Refilling,

    /// Getting feedback from bw probing.
    Starting,

    // Stopped probing; still getting feedback.
    Feedback,
}

/// BBR Congestion Control Algorithm.
///
/// See <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control-02>.
#[derive(Debug)]
pub struct Bbr3 {
    /// Configurable parameters.
    config: Bbr3Config,

    /// Statistics.
    stats: CongestionStats,

    /// BBR.pacing_rate: The current pacing rate for a BBR flow, which
    /// controls inter-packet spacing.
    pacing_rate: u64,

    /// BBR.send_quantum: The maximum size of a data aggregate scheduled and
    /// transmitted together.
    send_quantum: u64,

    /// cwnd: The transport sender's congestion window, which limits the
    /// amount of data in flight.
    cwnd: u64,

    /// BBR.pacing_gain: The dynamic gain factor used to scale BBR.BtlBw to
    /// produce BBR.pacing_rate.
    pacing_gain: f64,

    /// BBR.cwnd_gain: The dynamic gain factor used to scale the estimated BDP
    /// to produce a congestion window (cwnd).
    cwnd_gain: f64,

    /// BBR.packet_conservation: A boolean indicating whether BBR is currently
    /// using packet conservation dynamics to bound cwnd.
    packet_conservation: bool,

    /// BBR.state: The current state of a BBR flow in the BBR state machine.
    state: State,

    /// Counter of packet-timed round trips.
    round: RoundTripCounter,

    /// BBR.idle_restart: A boolean that is true if and only if a connection is
    /// restarting after being idle.
    idle_restart: bool,

    /// BBR.max_bw: The windowed maximum recent bandwidth sample - obtained
    /// using the BBR delivery rate sampling algorithm - measured during the
    /// current or previous bandwidth probing cycle (or during Startup, if the
    /// flow is still in that state).
    max_bw: u64,

    /// BBR.bw_hi: The long-term maximum sending bandwidth that the algorithm
    /// estimates will produce acceptable queue pressure, based on signals in
    /// the current or previous bandwidth probing cycle, as measured by loss.
    bw_hi: u64,

    /// BBR.bw_lo: The short-term maximum sending bandwidth that the algorithm
    /// estimates is safe for matching the current network path delivery rate,
    /// based on any loss signals in the current bandwidth probing cycle. This
    /// is generally lower than max_bw or bw_hi (thus the name).
    bw_lo: u64,

    /// BBR.bw: The maximum sending bandwidth that the algorithm estimates is appropriate
    /// for matching the current network path delivery rate, given all available signals
    /// in the model, at any time scale. It is the min() of max_bw, bw_hi, and bw_lo.
    bw: u64,

    /// BBR.min_rtt: The windowed minimum round-trip time sample measured over the last
    /// MinRTTFilterLen = 10 seconds.
    min_rtt: Duration,

    /// BBR.bdp: The estimate of the network path's BDP (Bandwidth-Delay Product),
    /// computed as: BBR.bdp = BBR.bw * BBR.min_rtt.
    bdp: u64,

    /// BBR.extra_acked: A volume of data that is the estimate of the recent degree of
    /// aggregation in the network path.
    extra_acked: u64,

    /// BBR.offload_budget: The estimate of the minimum volume of data necessary to achieve full
    /// throughput when using sender (TSO/GSO) and receiver (LRO, GRO) host offload mechanisms.
    offload_budget: u64,

    /// BBR.max_inflight: The estimate of the volume of in-flight data required to fully
    /// utilize the bottleneck bandwidth available to the flow.
    max_inflight: u64,

    /// BBR.inflight_hi: the long-term maximum volume of in-flight data that the algorithm
    /// estimates will produce acceptable queue pressure, based on signals in the current
    /// or previous bandwidth probing cycle, as measured by loss.
    inflight_hi: u64,

    /// BBR.inflight_lo: the short-term maximum volume of in-flight data that the algorithm
    /// estimates is safe for matching the current network path delivery process, based on
    /// any loss signals in the current bandwidth probing cycle.
    inflight_lo: u64,

    /// BBR.bw_latest: a 1-round-trip max of delivered bandwidth (rs.delivery_rate).
    bw_latest: u64,

    /// BBR.inflight_latest: a 1-round-trip max of delivered volume of data (rs.delivered).
    inflight_latest: u64,

    /// BBR.MaxBwFilter: The filter for tracking the maximum recent rs.delivery_rate sample,
    /// for estimating BBR.max_bw.
    max_bw_filter: SimpleMaxFilter,

    /// BBR.cycle_count: The virtual time used by the BBR.max_bw filter window.
    cycle_count: u64,

    /// Last time when cycle_index is updated.
    cycle_stamp: Instant,

    /// BBR.ack_phase. ACK probing state.
    ack_phase: AckProbePhase,

    /// BBR.extra_acked_interval_start: the start of the time interval for estimating the
    /// excess amount of data acknowledged due to aggregation effects.
    extra_acked_interval_start: Option<Instant>,

    /// BBR.extra_acked_delivered: the volume of data marked as delivered since
    /// BBR.extra_acked_interval_start.
    extra_acked_delivered: u64,

    /// BBR.ExtraACKedFilter: the max filter tracking the recent maximum degree of aggregation in the path.
    extra_acked_filter: MinMax,

    /// Estimator of full pipe.
    full_pipe: FullPipeEstimator,

    /// BBR.min_rtt_stamp: The wall clock time at which the current BBR.min_rtt sample was obtained.
    min_rtt_stamp: Instant,

    /// BBR.probe_rtt_min_delay: The minimum RTT sample recorded in the last ProbeRTTInterval.
    probe_rtt_min_delay: Duration,

    /// BBR.probe_rtt_min_stamp: The wall clock time at which the current BBR.probe_rtt_min_delay sample was obtained.
    probe_rtt_min_stamp: Instant,

    /// BBR.probe_rtt_expired: A boolean recording whether the BBR.probe_rtt_min_delay has expired
    /// and is due for a refresh with an application idle period or a transition into ProbeRTT state.
    probe_rtt_expired: bool,

    /// Timestamp when ProbeRTT state ends.
    probe_rtt_done_stamp: Option<Instant>,

    /// Whether a roundtrip in ProbeRTT state ends.
    probe_rtt_round_done: bool,

    /// Delivery rate estimator.
    delivery_rate_estimator: DeliveryRateEstimator,

    /// Accumulate information from a single ACK/SACK.
    ack_state: AckState,

    /// Packet-timed rounds since probed bw.
    rounds_since_bw_probe: u64,

    /// T_bbr: BBR-native time-scale.
    bw_probe_wait: Duration,

    /// Packets delivered per inflight_hi incr.
    bw_probe_up_cnt: u64,

    /// Packets (S)ACKed since inflight_hi incr.
    bw_probe_up_acks: u64,

    /// Cwnd-limited rounds in PROBE_UP.
    bw_probe_up_rounds: u64,

    /// Whether rate samples reflect bw probing?
    bw_probe_samples: bool,

    /// Whether a loss round starts?
    loss_round_start: bool,

    /// Whether loss marked in this round?
    loss_in_round: bool,

    /// Cwnd before loss recovery.
    prior_cwnd: u64,

    /// Whether in the recovery mode.
    in_recovery: bool,

    /// Loss round ending.
    loss_round_delivered: u64,

    /// Losses in STARTUP round.
    loss_events_in_round: u64,

    /// Time of the last recovery event starts.
    recovery_epoch_start: Option<Instant>,
}

impl Bbr3 {
    pub fn new(config: Bbr3Config) -> Self {
        let now = Instant::now();
        let initial_cwnd = config.initial_cwnd;

        let mut bbr3 = Self {
            config,

            stats: Default::default(),

            pacing_rate: 0,

            send_quantum: 0,

            cwnd: initial_cwnd,

            pacing_gain: 2.77,

            cwnd_gain: 2.0,

            packet_conservation: false,

            state: State::Startup,

            round: Default::default(),

            idle_restart: false,

            max_bw: 0,

            bw_hi: 0,

            bw_lo: 0,

            bw: 0,

            min_rtt: Duration::MAX,

            bdp: 0,

            extra_acked: 0,

            offload_budget: 0,

            max_inflight: 0,

            inflight_hi: 0,

            inflight_lo: 0,

            bw_latest: 0,

            inflight_latest: 0,

            max_bw_filter: SimpleMaxFilter::new(),

            cycle_count: 0,

            cycle_stamp: now,

            ack_phase: AckProbePhase::Init,

            extra_acked_interval_start: Some(now),

            extra_acked_delivered: 0,

            extra_acked_filter: MinMax::new(EXTRA_ACKED_FILTER_LEN),

            full_pipe: Default::default(),

            min_rtt_stamp: now,

            probe_rtt_min_delay: Duration::MAX,

            probe_rtt_min_stamp: now,

            probe_rtt_expired: false,

            probe_rtt_done_stamp: Some(now),

            probe_rtt_round_done: false,

            delivery_rate_estimator: DeliveryRateEstimator::default(),

            ack_state: Default::default(),

            rounds_since_bw_probe: 0,

            bw_probe_wait: Duration::MAX,

            bw_probe_up_cnt: 0,

            bw_probe_up_acks: 0,

            bw_probe_up_rounds: 0,

            bw_probe_samples: false,

            loss_round_start: false,

            loss_in_round: false,

            prior_cwnd: 0,

            in_recovery: false,

            loss_round_delivered: 0,

            loss_events_in_round: 0,

            recovery_epoch_start: Some(now),
        };
        bbr3.init();

        bbr3
    }

    // Initialization Steps.
    // See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-initialization>.
    fn init(&mut self) {
        let now = Instant::now();

        // init windowed max filter - max bw filter
        self.min_rtt = std::cmp::max(
            self.config.initial_rtt.unwrap_or(crate::INITIAL_RTT),
            Duration::from_micros(1),
        );
        self.min_rtt_stamp = now;
        self.probe_rtt_done_stamp = None;
        self.probe_rtt_round_done = false;
        self.prior_cwnd = 0;
        self.idle_restart = false;
        self.extra_acked_interval_start = Some(now);
        self.extra_acked_delivered = 0;
        self.ack_phase = AckProbePhase::Init;
        self.bw_hi = u64::MAX;
        self.inflight_hi = u64::MAX;

        self.reset_congestion_signals();
        self.reset_lower_bounds();
        self.init_round_counting();
        self.init_full_pipe();
        self.init_pacing_rate();

        self.enter_startup();
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-bbrround_count-tracking-pac>.
    fn init_round_counting(&mut self) {
        self.round.next_round_delivered = 0;
        self.round.round_count = 0;
        self.round.is_round_start = false;
    }

    fn start_round(&mut self) {
        self.round.next_round_delivered = self.delivery_rate_estimator.delivered();
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-bbrround_count-tracking-pac>.
    fn update_round(&mut self) {
        if self.ack_state.packet_delivered >= self.round.next_round_delivered {
            self.start_round();
            self.round.round_count += 1;
            self.rounds_since_bw_probe += 1;
            self.round.is_round_start = true;
            // After one round-trip in Fast Recovery:
            //     BBR.packet_conservation = false
            self.packet_conservation = false;
        } else {
            self.round.is_round_start = false;
        }
    }

    /// Is pipe filled.
    pub fn is_filled_pipe(&self) -> bool {
        self.full_pipe.is_filled_pipe
    }

    /// Is round start.
    pub fn is_round_start(&self) -> bool {
        self.round.is_round_start
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-modulating-cwnd-in-loss-rec>.
    /// Remember cwnd.
    fn save_cwnd(&mut self) {
        self.prior_cwnd = if !self.in_recovery && self.state != State::ProbeRTT {
            self.cwnd
        } else {
            self.cwnd.max(self.prior_cwnd)
        }
    }

    /// Restore cwnd.
    fn restore_cwnd(&mut self) {
        self.cwnd = self.cwnd.max(self.prior_cwnd)
    }

    fn congestion_window(&self) -> u64 {
        self.cwnd.max(self.config.min_cwnd)
    }

    fn pacing_rate(&self) -> Option<u64> {
        Some(self.pacing_rate)
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_cwnd
    }

    fn minimal_window(&self) -> u64 {
        self.config.min_cwnd
    }

    fn in_recovery(&self, sent_time: Instant) -> bool {
        self.recovery_epoch_start.map_or(false, |t| sent_time <= t)
    }

    fn in_slow_start(&self) -> bool {
        self.state == State::Startup
    }

    fn stats(&self) -> &CongestionStats {
        &self.stats
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-per-ack-steps>.
    fn update_model_and_state(&mut self, now: Instant, bytes_in_flight: u64) {
        self.update_latest_delivery_signals();
        self.update_congestion_signals();
        self.update_ack_aggregation(now);
        self.check_startup_done();
        self.check_drain(now, bytes_in_flight);
        self.update_probe_bw_cycle_phase(now, bytes_in_flight);
        self.update_min_rtt(now);
        self.check_probe_rtt(now, bytes_in_flight);
        self.advance_latest_delivery_signals();
        self.bound_bw_for_model();
    }

    fn update_control_parameters(&mut self) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd();
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-per-ack-steps>.
    fn update_on_loss(&mut self, now: Instant, packet: &SentPacket) {
        self.handle_lost_packet(now, packet);
    }

    // Update cwnd gain and pacing gain.
    // See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-updating-control-parameters>.
    // +-----------------+--------+--------+------+--------+------------------+
    // | State           | Tactic | Pacing | Cwnd | Rate   | Volume           |
    // |                 |        | Gain   | Gain | Cap    | Cap              |
    // +-----------------+--------+--------+------+--------+------------------+
    // | Startup         | accel  | 2.77   | 2    |        |                  |
    // |                 |        |        |      |        |                  |
    // +-----------------+--------+--------+------+--------+------------------+
    // | Drain           | decel  | 0.5    | 2    | bw_hi, | inflight_hi,     |
    // |                 |        |        |      | bw_lo  | inflight_lo      |
    // +-----------------+--------+--------+------+--------+------------------+
    // | ProbeBW_DOWN    | decel  | 0.9    | 2    | bw_hi, | inflight_hi,     |
    // |                 |        |        |      | bw_lo  | inflight_lo      |
    // +-----------------+--------+--------+------+--------+------------------+
    // | ProbeBW_CRUISE  | cruise | 1.0    | 2    | bw_hi, | 0.85*inflight_hi |
    // |                 |        |        |      | bw_lo  | inflight_lo      |
    // +-----------------+--------+--------+------+--------+------------------+
    // | ProbeBW_REFILL  | accel  | 1.0    | 2    | bw_hi  | inflight_hi      |
    // |                 |        |        |      |        |                  |
    // +-----------------+--------+--------+------+--------+------------------+
    // | ProbeBW_UP      | accel  | 1.25   | 2    | bw_hi  | inflight_hi      |
    // |                 |        |        |      |        |                  |
    // +-----------------+--------+--------+------+--------+------------------+
    // | ProbeRTT        | decel  | 1.0    | 0.5  | bw_hi, | 0.85*inflight_hi |
    // |                 |        |        |      | bw_lo  | inflight_lo      |
    // +-----------------+--------+--------+------+--------+------------------+
    //
    // Adapt to BBRv3:
    // 1. BBRv3 Performance tuning changes:
    //   STARTUP cwnd gian: 2.89 => 2.0
    //   STARTUP pacing gain: 2.89 => 2.77
    // 2. Fix bw convergence without loss/ECN (in large buffer case, BBRv2 flows ofen did not converge to fair share)
    //   Increase cwnd gain from 2.0 to 2.25 when probing for bandwidth (ProbeBW_UP)
    //   Change pacing gain of 0.75x to 0.9x (ProbeBW_DOWN)
    //
    // See <https://datatracker.ietf.org/meeting/117/materials/slides-117-ccwg-bbrv3-algorithm-bug-fixes-and-public-internet-deployment-00>.
    fn update_gains(&mut self) {
        match self.state {
            State::Startup => {
                self.pacing_gain = 2.77;
                self.cwnd_gain = 2.0;
            }
            State::Drain => {
                self.pacing_gain = 0.5;
                self.cwnd_gain = 2.0;
            }
            State::ProbeBwDown => {
                self.pacing_gain = 0.9;
                self.cwnd_gain = 2.0;
            }
            State::ProbeBwCruise => {
                self.pacing_gain = 1.0;
                self.cwnd_gain = 2.0;
            }
            State::ProbeBwRefill => {
                self.pacing_gain = 1.0;
                self.cwnd_gain = 2.0;
            }
            State::ProbeBwUp => {
                self.pacing_gain = 1.25;
                self.cwnd_gain = 2.25;
            }
            State::ProbeRTT => {
                self.pacing_gain = 1.0;
                self.cwnd_gain = 0.5;
            }
        }
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-startup>.
    fn enter_startup(&mut self) {
        self.state = State::Startup;
        self.update_gains();
    }

    fn check_startup_done(&mut self) {
        self.check_startup_full_bandwidth();
        self.check_startup_high_loss();
        if self.state == State::Startup && self.full_pipe.is_filled_pipe {
            self.enter_drain();
        }
    }

    fn init_full_pipe(&mut self) {
        self.full_pipe.is_filled_pipe = false;
        self.full_pipe.full_bw = 0;
        self.full_pipe.full_bw_count = 0;
    }

    fn check_startup_full_bandwidth(&mut self) {
        // No need to check for a full pipe now.
        if self.is_filled_pipe()
            || !self.is_round_start()
            || self.delivery_rate_estimator.is_sample_app_limited()
        {
            return;
        }

        // still growing?
        if self.max_bw
            >= (self.full_pipe.full_bw as f64 * (1.0_f64 + self.config.full_bw_growth_rate)) as u64
        {
            // record new baseline level
            self.full_pipe.full_bw = self.max_bw;
            self.full_pipe.full_bw_count = 0;

            return;
        }

        // another round w/o much growth
        self.full_pipe.full_bw_count += 1;

        if self.full_pipe.full_bw_count >= self.config.full_bw_count_threshold {
            self.full_pipe.is_filled_pipe = true;
        }
    }

    fn handle_queue_too_high_in_startup(&mut self) {
        self.full_pipe.is_filled_pipe = true;

        // According to BBRv3 performance tuning in
        // <https://datatracker.ietf.org/meeting/117/materials/slides-117-ccwg-bbrv3-algorithm-bug-fixes-and-public-internet-deployment-00>.
        // When exiting STARTUP, set inflight_hi based on:
        //      max(estimated BDP, max number of packets delivered in last round trip)
        self.inflight_hi = self.inflight(1.0).max(self.inflight_latest);
    }

    /// Check if loss rate is too high in startup.
    // Exit STARTUP based on loss rate and loss gaps in round. Wait until
    // the end of the round in recovery to get a good estimate of how many packets
    // have been lost, and how many we need to drain with a low pacing rate.
    fn check_startup_high_loss(&mut self) {
        // If the following criteria are all met, exit startup and enter drain:
        // - The connection has been in fast recovery for at least one full round trip.
        // - The loss rate over the time scale of a single full round trip exceeds BBRLossThresh (2%).
        // - There are at least BBRStartupFullLossCnt=3 discontiguous sequence ranges lost in that round trip.
        if self.ack_state.lost > 0 && self.loss_events_in_round < 0xf {
            // Update saturating counter.
            self.loss_events_in_round += 1;
        }

        if self.loss_round_start
            && self.in_recovery
            && self.loss_events_in_round >= self.config.full_loss_count
            && self.is_inflight_too_high()
        {
            self.handle_queue_too_high_in_startup()
        }

        if self.loss_round_start {
            self.loss_events_in_round = 0;
        }
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-drain>.
    fn enter_drain(&mut self) {
        self.state = State::Drain;
        self.update_gains();
    }

    fn check_drain(&mut self, now: Instant, bytes_in_flight: u64) {
        if self.state == State::Drain && bytes_in_flight <= self.inflight(1.0) {
            // BBR estimates the queue was drained.
            self.enter_probe_bw(now);
        }
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-probebw>.
    fn check_time_to_probe_bw(&mut self, now: Instant) -> bool {
        // Is it time to transition from DOWN or CRUISE to REFILL?
        if self.has_elapsed_in_phase(now, self.bw_probe_wait)
            || self.is_reno_coexistence_probe_time()
        {
            self.start_probe_bw_refill();
            return true;
        }

        false
    }

    fn pick_probe_wait(&mut self) {
        // Randomized decision about how long to wait until
        // probing for bandwidth, using round count and wall clock.

        // Decide random round-trip bound for wait:  0 or 1
        self.rounds_since_bw_probe = rand::thread_rng().gen_range(0..PROBE_BW_RAND_ROUNDS);

        // Decide the random wall clock bound for wait: 2..3 sec
        self.bw_probe_wait = Duration::from_millis(
            rand::thread_rng()
                .gen_range(PROBE_BW_MIN_WAIT_TIME_IN_MSEC..PROBE_BW_MAX_WAIT_TIME_IN_MSEC),
        );
    }

    fn is_reno_coexistence_probe_time(&self) -> bool {
        // Random loss can shave some small percentage off of our inflight
        // in each round. To survive this, flows need robust periodic probes.
        let reno_rounds = self.target_inflight();
        let rounds = reno_rounds.min(PROBE_BW_MAX_ROUNDS);

        self.rounds_since_bw_probe >= rounds
    }

    fn target_inflight(&self) -> u64 {
        // How much data do we want in flight?
        // Our estimated BDP, unless congestion cut cwnd.
        self.bdp.min(self.cwnd)
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-probebw-algorithm-details>.
    fn enter_probe_bw(&mut self, now: Instant) {
        self.start_probe_bw_down(now);
    }

    fn start_probe_bw_down(&mut self, now: Instant) {
        self.reset_congestion_signals();
        self.bw_probe_up_cnt = u64::MAX;
        self.pick_probe_wait();
        // start wall clock
        self.cycle_stamp = now;
        self.ack_phase = AckProbePhase::Stopping;
        self.start_round();
        self.state = State::ProbeBwDown;
    }

    fn start_probe_bw_cruise(&mut self) {
        self.state = State::ProbeBwCruise;
    }

    fn start_probe_bw_refill(&mut self) {
        self.reset_lower_bounds();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acks = 0;
        self.ack_phase = AckProbePhase::Refilling;
        self.start_round();
        self.state = State::ProbeBwRefill;
    }

    fn start_probe_bw_up(&mut self, now: Instant) {
        self.ack_phase = AckProbePhase::Starting;
        self.start_round();

        self.full_pipe.full_bw = self.delivery_rate_estimator.delivery_rate();

        // Start wall clock.
        self.cycle_stamp = now;
        self.state = State::ProbeBwUp;
        self.raise_inflight_hi_slope();
    }

    /// The core state machine logic for ProbeBW.
    fn update_probe_bw_cycle_phase(&mut self, now: Instant, bytes_in_flight: u64) {
        if !self.filled_pipe() {
            // only handling steady-state behavior here.
            return;
        }

        self.adapt_upper_bounds(now);

        if !self.is_in_a_probe_bw_state() {
            // only handling ProbeBW states here.
            return;
        }

        match self.state {
            State::ProbeBwDown => {
                if self.check_time_to_probe_bw(now) {
                    // already decided state transition.
                    return;
                }

                if self.check_time_to_cruise(bytes_in_flight) {
                    self.start_probe_bw_cruise();
                }
            }
            State::ProbeBwCruise => {
                self.check_time_to_probe_bw(now);
            }
            State::ProbeBwRefill => {
                // After one round of REFILL, start UP.
                if self.is_round_start() {
                    self.bw_probe_samples = true;
                    self.start_probe_bw_up(now);
                }
            }

            // Exit conditions: The BBR flow ends ProbeBW_UP bandwidth probing and transitions to ProbeBW_DOWN
            // to try to drain the bottleneck queue when any of the following conditions are met:
            // - Estimated queue: The flow has been in ProbeBW_UP for at least 1*min_rtt, and the estimated queue
            //   is high enough that the flow judges it has robustly probed for available bandwidth
            //   (packets_in_flight > 1.25 * BBR.bdp).
            // - Loss: The current loss rate exceeds BBRLossThresh (2%).
            State::ProbeBwUp => {
                if self.has_elapsed_in_phase(now, self.min_rtt)
                    && bytes_in_flight > self.inflight(self.pacing_gain)
                {
                    self.start_probe_bw_down(now);
                }
            }
            _ => {}
        }
    }

    /// Is state a probe bw state?
    fn is_in_a_probe_bw_state(&self) -> bool {
        matches!(
            self.state,
            State::ProbeBwDown | State::ProbeBwCruise | State::ProbeBwRefill | State::ProbeBwUp
        )
    }

    /// Time to transition from DOWN to CRUISE?
    fn check_time_to_cruise(&mut self, bytes_in_flight: u64) -> bool {
        if bytes_in_flight > self.inflight_with_headroom() {
            // Not enough headroom.
            return false;
        }

        if bytes_in_flight <= self.inflight(1.0) {
            // inflight <= estimated BDP
            return true;
        }

        false
    }

    fn has_elapsed_in_phase(&self, now: Instant, interval: Duration) -> bool {
        now > self.cycle_stamp + interval
    }

    // Return a volume of data that tries to leave free
    // headroom in the bottleneck buffer or link for
    // other flows, for fairness convergence and lower
    // RTTs and loss.
    fn inflight_with_headroom(&self) -> u64 {
        if self.inflight_hi == u64::MAX {
            return u64::MAX;
        }

        let headroom = ((self.config.headroom * self.inflight_hi as f64) as u64).max(1);

        self.inflight_hi
            .saturating_sub(headroom)
            .max(self.config.min_cwnd)
    }

    /// Raise inflight_hi slope if appropriate.
    fn raise_inflight_hi_slope(&mut self) {
        // Calculate "slope": packets S/Acked per inflight_hi increment.
        let growth_this_round = 1 << self.bw_probe_up_rounds;
        self.bw_probe_up_rounds = self.bw_probe_up_rounds.saturating_add(1).min(30);
        self.bw_probe_up_cnt = (self.cwnd / growth_this_round).max(1);
    }

    /// Increase inflight_hi if appropriate.
    fn probe_inflight_hi_upward(&mut self, is_cwnd_limited: bool) {
        if !is_cwnd_limited || self.cwnd < self.inflight_hi {
            // not fully using inflight_hi, so don't grow it.
            return;
        }

        // For each bw_probe_up_cnt packets ACKed, increase inflight_hi by 1.
        self.bw_probe_up_acks += self.ack_state.newly_acked_bytes;
        if self.bw_probe_up_acks >= self.bw_probe_up_cnt {
            let delta = self.bw_probe_up_acks / self.bw_probe_up_cnt;
            self.bw_probe_up_acks = self
                .bw_probe_up_acks
                .saturating_sub(delta * self.bw_probe_up_cnt);
            self.inflight_hi = self
                .inflight_hi
                .saturating_add(delta * self.config.max_datagram_size);
        }

        if self.is_round_start() {
            self.raise_inflight_hi_slope();
        }
    }

    /// Track ACK state and update BBR.max_bw window and BBR.inflight_hi and BBR.bw_hi.
    fn adapt_upper_bounds(&mut self, now: Instant) {
        if self.ack_phase == AckProbePhase::Starting && self.is_round_start() {
            // starting to get bw probing samples.
            self.ack_phase = AckProbePhase::Feedback;
        }

        if self.ack_phase == AckProbePhase::Stopping && self.is_round_start() {
            // end of samples from bw probing phase.
            self.bw_probe_samples = false;
            self.ack_phase = AckProbePhase::Init;

            if self.is_in_a_probe_bw_state() && !self.is_app_limited() {
                self.advance_max_bw_filter();
            }
        }

        if !self.check_inflight_too_high(now) {
            // Loss rate is safe. Adjust upper bounds upward.
            if self.inflight_hi == u64::MAX {
                // no upper bounds to raise.
                return;
            }

            if self.ack_state.tx_in_flight > self.inflight_hi {
                self.inflight_hi = self.ack_state.tx_in_flight;
            }

            if self.delivery_rate_estimator.delivery_rate() > self.bw_hi {
                self.bw_hi = self.delivery_rate_estimator.delivery_rate();
            }

            if self.state == State::ProbeBwUp {
                self.probe_inflight_hi_upward(true);
            }
        }
    }

    fn is_app_limited(&self) -> bool {
        self.delivery_rate_estimator.is_app_limited()
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-probertt>.
    fn update_min_rtt(&mut self, now: Instant) {
        let sample_rtt = self.delivery_rate_estimator.sample_rtt();
        self.probe_rtt_expired = now.saturating_duration_since(self.probe_rtt_min_stamp)
            > self.config.probe_rtt_interval;

        if !sample_rtt.is_zero()
            && (sample_rtt <= self.probe_rtt_min_delay || self.probe_rtt_expired)
        {
            self.probe_rtt_min_delay = sample_rtt;
            self.probe_rtt_min_stamp = now;
        }

        let min_rtt_expired =
            now.saturating_duration_since(self.min_rtt_stamp) > MIN_RTT_FILTER_LEN;

        if self.probe_rtt_min_delay < self.min_rtt || min_rtt_expired {
            self.min_rtt = self.probe_rtt_min_delay;
            self.min_rtt_stamp = self.probe_rtt_min_stamp;
        }
    }

    fn check_probe_rtt(&mut self, now: Instant, bytes_in_flight: u64) {
        if self.state != State::ProbeRTT && self.probe_rtt_expired && !self.idle_restart {
            self.enter_probe_rtt();

            // Remember the last-known good cwnd and restore it when exiting probe-rtt.
            self.save_cwnd();
            self.probe_rtt_done_stamp = None;
            self.ack_phase = AckProbePhase::Stopping;
            self.start_round();
        }

        if self.state == State::ProbeRTT {
            self.handle_probe_rtt(now, bytes_in_flight);
        }

        if self.delivery_rate_estimator.delivered() > 0 {
            self.idle_restart = false;
        }
    }

    fn enter_probe_rtt(&mut self) {
        self.state = State::ProbeRTT;

        self.update_gains();
    }

    fn handle_probe_rtt(&mut self, now: Instant, bytes_in_flight: u64) {
        // Ignore low rate samples during ProbeRTT. MarkConnectionAppLimited.
        // C.app_limited = (BW.delivered + packets_in_flight) ? : 1
        self.mark_connection_app_limited();

        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp {
            if self.is_round_start() {
                self.probe_rtt_round_done = true;
            }

            if self.probe_rtt_round_done {
                self.check_probe_rtt_done(now);
            }
        } else if bytes_in_flight <= self.probe_rtt_cwnd() {
            // Wait for at least ProbeRTTDuration to elapse.
            self.probe_rtt_done_stamp = Some(now + self.config.probe_rtt_duration);
            // Wait for at least one round to elapse.
            self.probe_rtt_round_done = false;
            self.start_round();
        }
    }

    fn check_probe_rtt_done(&mut self, now: Instant) {
        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp {
            if now > probe_rtt_done_stamp {
                // Schedule next ProbeRtt.
                self.probe_rtt_min_stamp = now;
                self.restore_cwnd();
                self.exit_probe_rtt(now);
            }
        }
    }

    fn mark_connection_app_limited(&mut self) {
        self.delivery_rate_estimator.set_app_limited(true);
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-exiting-probertt>.
    fn exit_probe_rtt(&mut self, now: Instant) {
        self.reset_lower_bounds();

        if self.is_filled_pipe() {
            self.start_probe_bw_down(now);
            self.start_probe_bw_cruise();
        } else {
            self.enter_startup();
        }
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-restarting-from-idle>.
    fn handle_restart_from_idle(&mut self, now: Instant, bytes_in_flight: u64) {
        // When restarting from idle, BBR leaves its cwnd as-is and paces
        // packets at exactly BBR.BtlBw, aiming to return as quickly as possible
        // to its target operating point of rate balance and a full pipe.
        if bytes_in_flight == 0 && self.is_app_limited() {
            self.idle_restart = true;
            self.extra_acked_interval_start = Some(now);

            if self.is_in_a_probe_bw_state() {
                self.set_pacing_rate_with_gain(1.0);
            } else if self.state == State::ProbeRTT {
                self.check_probe_rtt_done(now);
            }
        }
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-updating-the-bbrmax_bw-max->.
    fn update_max_bw(&mut self) {
        let bw = self.delivery_rate_estimator.delivery_rate();

        self.update_round();

        if bw >= self.max_bw || !self.is_app_limited() {
            self.max_bw_filter.bw[1] = bw.max(self.max_bw_filter.bw[1]);
            self.max_bw = self.max_bw_filter.max_bw();
        }
    }

    fn advance_max_bw_filter(&mut self) {
        // BBR tracks time for the BBR.max_bw filter window using a virtual (non-wall-clock) time
        // tracked by counting the cyclical progression through ProbeBW cycles. The BBR.max_bw filter only
        // needs to track samples from two time slots: the previous ProbeBW cycle and the current ProbeBW cycle.
        self.cycle_count += 1;

        if self.max_bw_filter.bw[1] == 0 {
            // no samples in this window; remember old window
            return;
        }

        self.max_bw_filter.bw[0] = self.max_bw_filter.bw[1];
        self.max_bw_filter.bw[1] = 0;
    }

    // BBR.offload_budget is the estimate of the minimum volume of data necessary to achieve full
    // throughput using sender (TSO/GSO) and receiver (LRO, GRO) host offload mechanisms.
    //
    // See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-bbroffload_budget>.
    fn update_offload_budget(&mut self) {
        self.offload_budget = 3 * self.send_quantum;
    }

    // Estimates the windowed max degree of ack aggregation.
    // This is used to provision extra in-flight data to keep sending during
    // inter-ACK silences.
    //
    // Degree of ack aggregation is estimated as extra data acked beyond expected.
    //
    // max_extra_acked = "maximum recent excess data ACKed beyond max_bw * interval"
    // cwnd += max_extra_acked
    //
    // Max extra_acked is clamped by cwnd and bw * bbr_extra_acked_max_us (100 ms).
    // Max filter is an approximate sliding window of 5-10 (packet timed) round
    // trips for non-startup phase, and 1-2 round trips for startup.
    //
    // See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-bbrextra_acked>.
    fn update_ack_aggregation(&mut self, now: Instant) {
        // Find excess ACKed beyond expected amount over this interval.
        if let Some(extra_acked_interval_start) = self.extra_acked_interval_start {
            let interval = now.saturating_duration_since(extra_acked_interval_start);
            let mut expected_delivered =
                (self.bw as u128).saturating_mul(interval.as_micros()) as u64 / 1_000_000;

            // Reset interval if ACK rate is below expected rate.
            if self.extra_acked_delivered <= expected_delivered {
                self.extra_acked_delivered = 0;
                self.extra_acked_interval_start = Some(now);
                expected_delivered = 0;
            }

            // Compute excess data delivered, beyond what was expected.
            self.extra_acked_delivered = self
                .extra_acked_delivered
                .saturating_add(self.ack_state.newly_acked_bytes);

            let extra = self
                .extra_acked_delivered
                .saturating_sub(expected_delivered)
                .min(self.cwnd);

            self.extra_acked_filter
                .update_max(self.round.round_count, extra);
        } else {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = Some(now);
        }
    }

    // When a flow is in ProbeBW, and an ACK covers data sent in one of the accelerating
    // phases (REFILL or UP), and the ACK indicates that the loss rate over the past round
    // trip exceeds the queue pressure objective, and the flow is not application limited,
    // and has not yet responded to congestion signals from the most recent REFILL or UP
    // phase, then the flow estimates that the volume of data it allowed in flight exceeded
    // what matches the current delivery process on the path, and reduces BBR.inflight_hi.
    //
    // See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-updating-the-model-upon-pac>.
    fn check_inflight_too_high(&mut self, now: Instant) -> bool {
        // Do loss signals suggest inflight is too high? If so, react.
        if self.is_inflight_too_high() {
            if self.bw_probe_samples {
                self.handle_inflight_too_high(now);
            }

            // Inflight too high.
            return true;
        }

        // Inflight not too high.
        false
    }

    fn is_inflight_too_high(&self) -> bool {
        // The BBRBeta (0.7x) bound is to try to ensure that BBR does not
        // react more dramatically than CUBIC's 0.7x multiplicative decrease factor.
        self.ack_state.lost
            > (self.ack_state.tx_in_flight as f64 * self.config.loss_threshold) as u64
    }

    // Loss and/or ECN rate is too high while probing.
    // Adapt (once per bw probe) by cutting inflight_hi and then restarting cycle.
    fn handle_inflight_too_high(&mut self, now: Instant) {
        // Only react once per bw probe.
        self.bw_probe_samples = false;

        // If we are app-limited then we are not robustly probing the max volume of inflight data we think
        // might be safe (analogous to how app-limited bw samples are not known to be robustly probing bw).
        if !self.is_app_limited() {
            self.inflight_hi = ((self.target_inflight() as f64 * self.config.beta) as u64)
                .max(self.ack_state.tx_in_flight);
        }

        if self.state == State::ProbeBwUp {
            self.start_probe_bw_down(now);
        }
    }

    // BBR processes each loss detection event to more precisely estimate the volume of in-flight data
    // at which loss rates cross BBRLossThresh.
    //
    // See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-probing-for-bandwidth-in-pr>.
    fn handle_lost_packet(&mut self, now: Instant, packet: &SentPacket) {
        // In startup phase we need to update stats upon every ack reception
        if !self.bw_probe_samples && !self.in_slow_start() {
            // not a packet sent while probing bandwidth.
            return;
        }

        // Inflight at transmit.
        self.ack_state.tx_in_flight = packet.rate_sample_state.tx_in_flight;
        self.ack_state.lost = self.stats.bytes_lost_in_total - packet.rate_sample_state.lost;
        self.delivery_rate_estimator
            .set_app_limited(packet.rate_sample_state.is_app_limited);

        if self.is_inflight_too_high() {
            self.ack_state.tx_in_flight = self.inflight_hi_from_lost_packet(packet);
            self.handle_inflight_too_high(now);
        }
    }

    // Calculate the tx_in_flight level that corresponded to excessive loss.
    // To estimate this value, we can solve for "lost_prefix" in the following equation:
    //     lost                     /  inflight                     >= BBRLossThresh
    //    (lost_prev + lost_prefix) / (inflight_prev + lost_prefix) >= BBRLossThresh
    //    /* solving for lost_prefix we arrive at: */
    //    lost_prefix = (BBRLossThresh * inflight_prev - lost_prev) / (1 - BBRLossThresh)
    fn inflight_hi_from_lost_packet(&mut self, packet: &SentPacket) -> u64 {
        let size = packet.sent_size as u64;

        // What was in flight before this packet?
        let inflight_prev = packet.rate_sample_state.tx_in_flight.saturating_sub(size);

        // What was lost before this packet?
        let lost_prev = self.ack_state.lost.saturating_sub(size);
        let lost_prefix = (inflight_prev as f64 * self.config.loss_threshold - lost_prev as f64)
            / (1.0_f64 - self.config.loss_threshold);

        // At what inflight value did losses cross BBRLossThresh?
        inflight_prev.saturating_add(lost_prefix as u64)
    }

    // When not explicitly accelerating to probe for bandwidth (Drain, ProbeRTT, ProbeBW_DOWN,
    // ProbeBW_CRUISE), BBR responds to loss by slowing down to some extent. BBR flows implement
    // this response by reducing the short-term model parameters, BBR.bw_lo and BBR.inflight_lo as:
    //
    //       bw_lo     = max(       bw_latest, BBRBeta *       bw_lo )
    // inflight_lo     = max( inflight_latest, BBRBeta * inflight_lo )
    //
    // See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-when-not-probing-for-bandwi>.
    // Near start of ACK processing.
    fn update_latest_delivery_signals(&mut self) {
        self.loss_round_start = false;

        self.bw_latest = self
            .bw_latest
            .max(self.delivery_rate_estimator.delivery_rate());

        self.inflight_latest = self
            .inflight_latest
            .max(self.delivery_rate_estimator.sample_delivered());

        if self.delivery_rate_estimator.sample_prior_delivered() >= self.loss_round_delivered {
            self.loss_round_delivered = self.delivery_rate_estimator.delivered();
            self.loss_round_start = true;
        }
    }

    // Near end of ACK processing.
    fn advance_latest_delivery_signals(&mut self) {
        if self.loss_round_start {
            self.bw_latest = self.delivery_rate_estimator.delivery_rate();
            self.inflight_latest = self.delivery_rate_estimator.sample_delivered();
        }
    }

    // After bw probing (STARTUP/PROBE_UP), reset signals before entering a state
    // machine phase where we adapt our lower bound based on congestion signals.
    fn reset_congestion_signals(&mut self) {
        self.loss_in_round = false;
        self.bw_latest = 0;
        self.inflight_latest = 0;
    }

    // Update (most of) our congestion signals: track the recent rate and volume of
    // delivered data, presence of loss.
    fn update_congestion_signals(&mut self) {
        self.update_max_bw();

        if self.ack_state.lost > 0 {
            self.loss_in_round = true;
        }

        if !self.loss_round_start {
            // wait until end of round trip.
            return;
        }

        self.adapt_lower_bounds_from_congestion();
        self.loss_in_round = true;
    }

    fn is_probing_bw(&self) -> bool {
        matches!(
            self.state,
            State::Startup | State::ProbeBwRefill | State::ProbeBwUp
        )
    }

    fn adapt_lower_bounds_from_congestion(&mut self) {
        // We only use lower-bound estimates when not probing bw.
        // When probing we need to push inflight higher to probe bw.
        if self.is_probing_bw() {
            return;
        }

        if self.loss_in_round {
            self.init_lower_bounds();
            self.loss_lower_bounds();
        }
    }

    fn init_lower_bounds(&mut self) {
        if self.bw_lo == u64::MAX {
            self.bw_lo = self.max_bw;
        }

        if self.inflight_lo == u64::MAX {
            self.inflight_lo = self.cwnd;
        }
    }

    fn loss_lower_bounds(&mut self) {
        self.bw_lo = self
            .bw_latest
            .max((self.bw_lo as f64 * self.config.beta) as u64);
        self.inflight_lo = self
            .inflight_latest
            .max((self.inflight_lo as f64 * self.config.beta) as u64);
    }

    fn reset_lower_bounds(&mut self) {
        self.bw_lo = u64::MAX;
        self.inflight_lo = u64::MAX;
    }

    fn bound_bw_for_model(&mut self) {
        self.bw = self.max_bw.min(self.bw_lo).min(self.bw_hi);
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-pacing-rate-bbrpacing_rate>.
    fn init_pacing_rate(&mut self) {
        // When a BBR flow starts it has no BBR.BtlBw estimate.  So in this case
        // it sets an initial pacing rate based on the transport sender implementation's
        // initial congestion window, the initial SRTT (smoothed round-trip time) after the
        // first non-zero RTT sample.
        let srtt = match self.config.initial_rtt {
            Some(rtt) => rtt,
            _ => Duration::from_millis(1),
        };
        let nominal_bandwidth = self.config.initial_cwnd as f64 / srtt.as_secs_f64();
        self.pacing_rate = (self.pacing_gain * nominal_bandwidth) as u64;
    }

    fn set_pacing_rate_with_gain(&mut self, pacing_gain: f64) {
        let rate = (pacing_gain * self.bw as f64 * (1.0_f64 - PACING_MARGIN_PERCENT)) as u64;

        // on each data ACK BBR updates its pacing rate to
        // be proportional to BBR.BtlBw, as long as it estimates that it has
        // filled the pipe (BBR.filled_pipe is true; see the "Startup" section
        // below for details), or doing so increases the pacing rate.
        if self.is_filled_pipe() || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-pacing-rate-bbrpacing_rate>.
    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-send-quantum-bbrsend_quantu>.
    fn set_send_quantum(&mut self) {
        // A BBR implementation MAY use alternate approaches to select a
        // BBR.send_quantum, as appropriate for the CPU overheads anticipated
        // for senders and receivers, and buffering considerations anticipated
        // in the network path.  However, for the sake of the network and other
        // users, a BBR implementation SHOULD attempt to use the smallest
        // feasible quanta.
        // Adjust according to:
        // https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control-02
        let floor = if self.pacing_rate < SEND_QUANTUM_THRESHOLD_PACING_RATE {
            self.config.max_datagram_size
        } else {
            2 * self.config.max_datagram_size
        };

        // BBR.send_quantum = min(BBR.pacing_rate * 1ms, 64KBytes)
        // BBR.send_quantum = max(BBR.send_quantum, floor)
        self.send_quantum = (self.pacing_rate / 1000).clamp(floor, 64 * 1024);
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-computing-bbrmax_inflight>.
    fn bdp_multiple(&mut self, bw: u64, gain: f64) -> u64 {
        if self.min_rtt == Duration::MAX {
            // no valid RTT samples yet.
            return self.config.initial_cwnd;
        }

        let bdp = bw as f64 * self.min_rtt.as_secs_f64();
        self.bdp = bdp as u64;

        (gain * bdp) as u64
    }

    fn quantization_budget(&mut self, bytes_in_flight: u64) -> u64 {
        self.update_offload_budget();

        let mut inflight = bytes_in_flight
            .max(self.offload_budget)
            .max(self.config.min_cwnd);

        if self.state == State::ProbeBwUp {
            inflight = inflight.saturating_add(2 * self.config.max_datagram_size);
        }

        inflight
    }

    fn filled_pipe(&self) -> bool {
        self.full_pipe.is_filled_pipe
    }

    fn inflight(&mut self, gain: f64) -> u64 {
        let inflight = self.bdp_multiple(self.max_bw, gain);

        self.quantization_budget(inflight)
    }

    fn update_aggregation_budget(&mut self) {
        // Do nothing right now.
    }

    fn update_max_inflight(&mut self) {
        self.update_aggregation_budget();

        let mut inflight = self.bdp_multiple(self.max_bw, self.cwnd_gain);

        inflight = inflight.saturating_add(self.extra_acked_filter.get());

        self.max_inflight = self.quantization_budget(inflight);
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-modulating-cwnd-in-loss-rec>.
    fn enter_recovery(&mut self, now: Instant) {
        self.save_cwnd();

        self.recovery_epoch_start = Some(now);
        self.cwnd = self.stats.bytes_in_flight
            + self
                .ack_state
                .newly_acked_bytes
                .max(self.config.max_datagram_size);
        self.packet_conservation = true;
        self.in_recovery = true;

        // After one round-trip in Fast Recovery:
        //   BBR.packet_conservation = false
        self.start_round();
    }

    fn exit_recovery(&mut self) {
        // Upon exiting loss recovery (RTO recovery or Fast Recovery), either by
        // repairing all losses or undoing recovery, BBR restores the best-known
        // cwnd value we had upon entering loss recovery
        self.recovery_epoch_start = None;

        self.packet_conservation = false;
        self.in_recovery = false;

        self.restore_cwnd();
    }

    // In ProbeRTT state, BBR quickly reduce the volume of in-flight data and drain
    // the bottleneck queue, thereby allowing measurement of BBR.min_rtt.
    // See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-modulating-cwnd-in-probertt>.
    fn probe_rtt_cwnd(&mut self) -> u64 {
        self.bdp_multiple(self.bw, self.cwnd_gain)
            .max(self.config.min_cwnd)
    }

    fn bound_cwnd_for_probe_rtt(&mut self) {
        if self.state == State::ProbeRTT {
            self.cwnd = self.cwnd.min(self.probe_rtt_cwnd());
        }
    }

    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-modulating-cwnd-in-loss-rec>.
    fn modulate_cwnd_for_recovery(&mut self, bytes_in_flight: u64) {
        if self.ack_state.newly_lost_bytes > 0 {
            self.cwnd = self
                .cwnd
                .saturating_sub(self.ack_state.newly_lost_bytes)
                .max(self.config.min_cwnd);
        }

        if self.packet_conservation {
            self.cwnd = self
                .cwnd
                .max(bytes_in_flight + self.ack_state.newly_acked_bytes);
        }
    }

    // BBR uses a conservative strategy to deal with sudden dramatic traffic changes. When cwnd
    // is above the BBR.max_inflight derived from BBR's path model, BBR cuts the cwnd immediately
    // to the BBR.max_inflight. When cwnd is below BBR.max_inflight, BBR raises the cwnd gradually
    // and cautiously, increasing cwnd by no more than the amount of data acknowledged (cumulatively
    // or selectively) upon each ACK.
    //
    // See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-core-cwnd-adjustment-mechan>.
    fn set_cwnd(&mut self) {
        let bytes_in_flight = self.stats.bytes_in_flight;

        self.update_max_inflight();
        self.modulate_cwnd_for_recovery(bytes_in_flight);

        if !self.packet_conservation {
            if self.is_filled_pipe() {
                self.cwnd = self
                    .max_inflight
                    .min(self.cwnd + self.ack_state.newly_acked_bytes);
            } else if self.cwnd < self.max_inflight
                || self.delivery_rate_estimator.delivered() < self.config.initial_cwnd
            {
                self.cwnd = self.cwnd.saturating_add(self.ack_state.newly_acked_bytes);
            }
            self.cwnd = self.cwnd.max(self.config.min_cwnd);
        }

        self.bound_cwnd_for_probe_rtt();
        self.bound_cwnd_for_model();
    }

    /// BBR bounds the cwnd based on recent congestion.
    ///
    /// See <https://www.ietf.org/archive/id/draft-cardwell-iccrg-bbr-congestion-control-02.html#name-bounding-cwnd-based-on-rece>.
    fn bound_cwnd_for_model(&mut self) {
        let mut cap = u64::MAX;

        if self.is_in_a_probe_bw_state() && self.state != State::ProbeBwCruise {
            cap = self.inflight_hi;
        } else if self.state == State::ProbeRTT || self.state == State::ProbeBwCruise {
            cap = self.inflight_with_headroom();
        }

        // Apply inflight_lo (possibly infinite)
        cap = cap.min(self.inflight_lo);
        cap = cap.max(self.config.min_cwnd);
        self.cwnd = self.cwnd.min(cap);
    }
}

impl CongestionController for Bbr3 {
    fn name(&self) -> &str {
        "BBRv3"
    }

    fn congestion_window(&self) -> u64 {
        self.cwnd.max(self.config.min_cwnd)
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_cwnd
    }

    fn minimal_window(&self) -> u64 {
        self.config.min_cwnd
    }

    fn stats(&self) -> &CongestionStats {
        &self.stats
    }

    fn on_sent(&mut self, now: Instant, packet: &mut SentPacket, bytes_in_flight: u64) {
        self.delivery_rate_estimator.on_packet_sent(
            packet,
            self.stats.bytes_in_flight,
            self.stats.bytes_lost_in_total,
        );

        self.handle_restart_from_idle(now, self.stats.bytes_in_flight);
        self.stats.bytes_in_flight += packet.sent_size as u64;
    }

    fn begin_ack(&mut self, now: Instant, bytes_in_flight: u64) {
        self.ack_state.newly_acked_bytes = 0;
        self.ack_state.newly_lost_bytes = 0;
        self.ack_state.packet_delivered = 0;
        self.ack_state.last_ack_packet_sent_time = now;
        self.ack_state.prior_bytes_in_flight = self.stats.bytes_in_flight;
        self.ack_state.now = now;
        self.ack_state.tx_in_flight = 0;
        self.ack_state.lost = 0;
    }

    fn on_ack(
        &mut self,
        packet: &mut SentPacket,
        now: Instant,
        _app_limited: bool,
        _rtt: &RttEstimator,
        bytes_in_flight: u64,
    ) {
        // Update rate sample by each ack packet.
        self.delivery_rate_estimator.update_rate_sample(packet);

        // Update stats.
        self.stats.bytes_in_flight = self
            .stats
            .bytes_in_flight
            .saturating_sub(packet.sent_size as u64);
        self.stats.bytes_acked_in_total = self
            .stats
            .bytes_acked_in_total
            .saturating_add(packet.sent_size as u64);
        if self.in_slow_start() {
            self.stats.bytes_acked_in_slow_start = self
                .stats
                .bytes_acked_in_slow_start
                .saturating_add(packet.sent_size as u64);
        }

        // Update ack state.
        self.ack_state.newly_acked_bytes += packet.sent_size as u64;
        self.ack_state.last_ack_packet_sent_time = packet.time_sent;

        // Only remember the max P.delivered to determine whether a new round starts.
        self.ack_state.packet_delivered = self
            .ack_state
            .packet_delivered
            .max(packet.rate_sample_state.delivered);
    }

    fn end_ack(&mut self) {
        let bytes_in_flight: u64 = self.stats.bytes_in_flight;

        // Generate rate sample.
        self.delivery_rate_estimator.generate_rate_sample();

        // Check if exit recovery
        if self.in_recovery && !self.in_recovery(self.ack_state.last_ack_packet_sent_time) {
            self.exit_recovery();
        }

        // Update model and control parameters.
        self.update_model_and_state(self.ack_state.now, bytes_in_flight);
        self.update_gains();
        self.update_control_parameters();
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        packet: &SentPacket,
        in_persistent_congestion: bool,
        lost_bytes: u64,
        bytes_in_flight: u64,
    ) {
        self.stats.bytes_in_flight = self.stats.bytes_in_flight.saturating_sub(lost_bytes);
        self.stats.bytes_lost_in_total = self.stats.bytes_lost_in_total.saturating_add(lost_bytes);
        self.ack_state.newly_lost_bytes =
            self.ack_state.newly_lost_bytes.saturating_add(lost_bytes);

        self.update_on_loss(now, packet);

        // Refer to https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2
        // When persistent congestion is declared, the sender's congestion
        // window MUST be reduced to the minimum congestion window.
        match in_persistent_congestion {
            true => {
                self.cwnd = self.config.min_cwnd;
                self.recovery_epoch_start = None;
            }
            false => {
                if !self.in_recovery && !self.in_recovery(packet.time_sent) {
                    self.enter_recovery(now);
                }
            }
        }
    }

    fn pacing_rate(&self) -> Option<u64> {
        Some(self.pacing_rate)
    }
}

#[cfg(test)]
mod tests {}
