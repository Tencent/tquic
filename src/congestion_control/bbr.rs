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

//! BBR Congestion Control.
//!
//! BBR uses recent measurements of a transport connection's delivery rate
//! and round-trip time to build an explicit model that includes both the
//! maximum recent bandwidth available to that connection, and its
//! minimum recent round-trip delay.  BBR then uses this model to control
//! both how fast it sends data and the maximum amount of data it allows
//! in flight in the network at any time.
//!
//! See <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control-00>.

extern crate rand;

use std::time::{Duration, Instant};

use log::*;
use rand::Rng;

use super::delivery_rate::DeliveryRateEstimator;
use super::minmax::MinMax;
use super::{CongestionController, CongestionStats};
use crate::connection::rtt::RttEstimator;
use crate::connection::space::{RateSamplePacketState, SentPacket};

/// BBR configurable parameters.
#[derive(Debug)]
pub struct BbrConfig {
    /// Minimal congestion window in bytes.
    min_cwnd: u64,

    /// Initial congestion window in bytes.
    initial_cwnd: u64,

    /// Initial Smoothed rtt.
    initial_rtt: Option<Duration>,

    /// Max datagram size in bytes.
    max_datagram_size: u64,
}

impl BbrConfig {
    pub fn new(
        min_cwnd: u64,
        initial_cwnd: u64,
        initial_rtt: Option<Duration>,
        max_datagram_size: u64,
    ) -> Self {
        Self {
            min_cwnd,
            initial_cwnd,
            initial_rtt,
            max_datagram_size,
        }
    }
}

impl Default for BbrConfig {
    fn default() -> Self {
        Self {
            min_cwnd: 4 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            initial_cwnd: 80 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            initial_rtt: Some(crate::INITIAL_RTT),
            max_datagram_size: crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
        }
    }
}

/// BtlBwFilterLen: A constant specifying the length of the BBR.BtlBw max
/// filter window for BBR.BtlBwFilter, BtlBwFilterLen is `10` packet-timed
/// round trips.
const BTLBW_FILTER_LEN: u64 = 10;

/// RTpropFilterLen: A constant specifying the length of the RTProp min
/// filter window, RTpropFilterLen is `10` secs.
const RTPROP_FILTER_LEN: Duration = Duration::from_secs(10);

/// BBRHighGain: A constant specifying the minimum gain value that will
/// allow the sending rate to double each round (`2/ln(2)` ~= `2.89`), used
/// in Startup mode for both BBR.pacing_gain and BBR.cwnd_gain.
const HIGH_GAIN: f64 = 2.89;

/// Bandwidth growth rate before pipe got filled.
const BTLBW_GROWTH_RATE: f64 = 0.25;

/// Max count of full bandwidth reached, before pipe is supposed to be filled.
/// This three-round threshold was validated by YouTube experimental data.
const FULL_BW_COUNT_THRESHOLD: u64 = 3;

/// BBRGainCycleLen: the number of phases in the BBR ProbeBW gain cycle:
/// 8.
const GAIN_CYCLE_LEN: usize = 8;

/// Pacing Gain Cycles. Each phase normally lasts for roughly BBR.RTprop.
const PACING_GAIN_CYCLE: [f64; GAIN_CYCLE_LEN] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// ProbeRTTInterval: A constant specifying the minimum time interval
/// between ProbeRTT states: 10 secs.
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(10);

/// ProbeRTTDuration: A constant specifying the minimum duration for
/// which ProbeRTT state holds inflight to BBRMinPipeCwnd or fewer
/// packets: 200 ms.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);

/// Pacing rate threshold for select different send quantum. Default `1.2Mbps`.
const SEND_QUANTUM_THRESHOLD_PACING_RATE: u64 = 1_200_000 / 8;

/// BBR State Machine.
///
/// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 3.4.
#[derive(Debug, PartialEq, Eq)]
enum BbrStateMachine {
    Startup,
    Drain,
    ProbeBW,
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
        }
    }
}

/// BBR Congestion Control Algorithm.
///
/// See draft-cardwell-iccrg-bbr-congestion-control-00.
#[derive(Debug)]
pub struct Bbr {
    /// Configurable parameters.
    config: BbrConfig,

    /// Statistics.
    stats: CongestionStats,

    /// State.
    state: BbrStateMachine,

    /// BBR.pacing_rate: The current pacing rate for a BBR flow, which
    /// controls inter-packet spacing.
    pacing_rate: u64,

    /// BBR.send_quantum: The maximum size of a data aggregate scheduled and
    /// transmitted together.
    send_quantum: u64,

    /// Cwnd: The transport sender's congestion window, which limits the
    /// amount of data in flight.
    cwnd: u64,

    /// BBR.BtlBw: BBR's estimated bottleneck bandwidth available to the transport
    /// flow, estimated from the maximum delivery rate sample in a sliding window.
    btlbw: u64,

    /// BBR.BtlBwFilter: The max filter used to estimate BBR.BtlBw.
    btlbwfilter: MinMax,

    /// Delivery rate estimator.
    delivery_rate_estimator: DeliveryRateEstimator,

    /// BBR.RTprop: BBR's estimated two-way round-trip propagation delay of path,
    /// estimated from the windowed minimum recent round-trip delay sample.
    rtprop: Duration,

    /// BBR.rtprop_stamp: The wall clock time at which the current BBR.RTProp
    /// sample was obtained.
    rtprop_stamp: Instant,

    /// BBR.rtprop_expired: A boolean recording whether the BBR.RTprop has
    /// expired and is due for a refresh with an application idle period or a
    /// transition into ProbeRTT state.
    is_rtprop_expired: bool,

    /// BBR.pacing_gain: The dynamic gain factor used to scale BBR.BtlBw to
    /// produce BBR.pacing_rate.
    pacing_gain: f64,

    /// BBR.cwnd_gain: The dynamic gain factor used to scale the estimated
    /// BDP to produce a congestion window (cwnd).
    cwnd_gain: f64,

    /// Counter of packet-timed round trips.
    round: RoundTripCounter,

    /// Estimator of full pipe.
    full_pipe: FullPipeEstimator,

    /// Timestamp when ProbeRTT state ends.
    probe_rtt_done_stamp: Option<Instant>,

    /// Whether a roundtrip in ProbeRTT state ends.
    probe_rtt_round_done: bool,

    /// Whether in packet conservation mode.
    packet_conservation: bool,

    /// Cwnd before loss recovery.
    prior_cwnd: u64,

    /// Whether restarting from idle.
    is_idle_restart: bool,

    /// Last time when cycle_index is updated.
    cycle_stamp: Instant,

    /// Current index of pacing_gain_cycle[].
    cycle_index: usize,

    /// The upper bound on the volume of data BBR allows in flight.
    target_cwnd: u64,

    /// Whether in the recovery mode.
    in_recovery: bool,

    /// Accumulate information from a single ACK/SACK.
    ack_state: AckState,

    /// Time of the last recovery event starts.
    recovery_epoch_start: Option<Instant>,
}

impl Bbr {
    pub fn new(config: BbrConfig) -> Self {
        let now = Instant::now();
        let initial_cwnd = config.initial_cwnd;

        let mut bbr = Self {
            config,
            stats: Default::default(),
            state: BbrStateMachine::Startup,
            pacing_rate: 0,
            send_quantum: 0,
            cwnd: initial_cwnd,
            btlbw: 0,
            btlbwfilter: MinMax::new(BTLBW_FILTER_LEN),
            delivery_rate_estimator: DeliveryRateEstimator::default(),
            rtprop: Duration::MAX,
            rtprop_stamp: now,
            is_rtprop_expired: false,
            pacing_gain: HIGH_GAIN,
            cwnd_gain: HIGH_GAIN,
            round: Default::default(),
            full_pipe: Default::default(),
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            packet_conservation: false,
            prior_cwnd: 0,
            is_idle_restart: false,
            cycle_stamp: now,
            cycle_index: 0,
            target_cwnd: 0,
            in_recovery: false,
            ack_state: AckState::default(),
            recovery_epoch_start: None,
        };
        bbr.init();

        bbr
    }

    /// Initialization Steps.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.3.1.
    fn init(&mut self) {
        self.rtprop = self.config.initial_rtt.unwrap_or(Duration::MAX);
        self.rtprop_stamp = Instant::now();
        self.probe_rtt_done_stamp = None;
        self.probe_rtt_round_done = false;
        self.packet_conservation = false;

        self.prior_cwnd = 0;
        self.is_idle_restart = false;

        self.init_round_counting();
        self.init_full_pipe();
        self.init_pacing_rate();
        self.enter_startup();
    }

    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.1.1.3.
    fn init_round_counting(&mut self) {
        self.round.next_round_delivered = 0;
        self.round.round_count = 0;
        self.round.is_round_start = false;
    }

    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.3.2.2.
    fn init_full_pipe(&mut self) {
        self.full_pipe.is_filled_pipe = false;
        self.full_pipe.full_bw = 0;
        self.full_pipe.full_bw_count = 0;
    }

    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.1
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

    /// Enter the Startup state
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.3.2.1.
    fn enter_startup(&mut self) {
        self.state = BbrStateMachine::Startup;

        // To achieve this rapid probing in the smoothest possible fashion, upon
        // entry into Startup state BBR sets BBR.pacing_gain and BBR.cwnd_gain
        // to BBRHighGain, the minimum gain value that will allow the sending
        // rate to double each round.
        self.pacing_gain = HIGH_GAIN;
        self.cwnd_gain = HIGH_GAIN;
    }

    /// Estimate whether the pipe is full by looking for a plateau in the
    /// BBR.BtlBw estimate.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.3.2.2.
    fn check_full_pipe(&mut self) {
        // no need to check for a full pipe now
        if self.is_filled_pipe()
            || !self.is_round_start()
            || self.delivery_rate_estimator.is_sample_app_limited()
        {
            return;
        }

        // BBR.BtlBw still growing?
        if self.btlbw >= (self.full_pipe.full_bw as f64 * (1.0_f64 + BTLBW_GROWTH_RATE)) as u64 {
            // record new baseline level
            self.full_pipe.full_bw = self.btlbw;
            self.full_pipe.full_bw_count = 0;
            return;
        }

        // another round w/o much growth
        self.full_pipe.full_bw_count += 1;

        // BBR waits three rounds in order to have solid evidence that the
        // sender is not detecting a delivery-rate plateau that was temporarily
        // imposed by the receive window.
        // This three-round threshold was validated by YouTube experimental data.
        if self.full_pipe.full_bw_count >= FULL_BW_COUNT_THRESHOLD {
            self.full_pipe.is_filled_pipe = true;
        }
    }

    /// Update the virtual time tracked by BBR.round_count.
    ///
    /// BBR tracks time for the BBR.BtlBw filter window using a virtual time
    /// tracked by BBR.round_countt, a count of "packet-timed" round-trips.
    /// The BBR.round_count counts packet-timed round trips by recording state
    /// about a sentinel packet, and waiting for an ACK of any data packet that
    /// was sent after that sentinel packet.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.1.1.3.
    fn update_round(&mut self) {
        if self.ack_state.packet_delivered >= self.round.next_round_delivered {
            self.round.next_round_delivered = self.delivery_rate_estimator.delivered();
            self.round.round_count += 1;
            self.round.is_round_start = true;
            // After one round-trip in Fast Recovery, exit the packet conservation mode.
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

    /// Try to update the pacing rate using the given pacing_gain
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.1.
    fn set_pacing_rate_with_gain(&mut self, pacing_gain: f64) {
        let rate = (pacing_gain * self.btlbw as f64) as u64;

        // On each data ACK BBR updates its pacing rate to be proportional to
        // BBR.BtlBw, as long as it estimates that it has filled the pipe, or
        // doing so increases the pacing rate.
        if self.is_filled_pipe() || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    /// In Drain, BBR aims to quickly drain any queue created in Startup by
    /// switching to a pacing_gain well below 1.0.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.3.3.
    fn enter_drain(&mut self) {
        self.state = BbrStateMachine::Drain;

        // It uses a pacing_gain that is the inverse of the value used during
        // Startup, which drains the queue in one round.
        self.pacing_gain = 1.0 / HIGH_GAIN; // pace slowly
        self.cwnd_gain = HIGH_GAIN; // maintain cwnd
    }

    /// Calculate the target cwnd, which is the upper bound on the volume of data BBR
    /// allows in flight.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.3.2 Target cwnd.
    fn inflight(&self, gain: f64) -> u64 {
        if self.rtprop == Duration::MAX {
            // no valid RTT samples yet
            return self.config.initial_cwnd;
        }

        // The "quanta" term allows enough quanta in flight on the sending
        // and receiving hosts to reach full utilization even in high-throughput
        // environments using offloading mechanisms.
        let quanta = 3 * self.send_quantum;

        // The "estimated_bdp" term allows enough packets in flight to fully
        // utilize the estimated BDP of the path, by allowing the flow to send
        // at BBR.BtlBw for a duration of BBR.RTprop.
        let estimated_bdp = self.btlbw as f64 * self.rtprop.as_secs_f64();

        // Scaling up the BDP by cwnd_gain, selected by the BBR state machine to
        // be above 1.0 at all times, bounds in-flight data to a small multiple
        // of the BDP, in order to handle common network and receiver pathologies,
        // such as delayed, stretched, or aggregated ACKs.
        (gain * estimated_bdp) as u64 + quanta
    }

    /// On each ACK, BBR calculates the BBR.target_cwnd.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.3.2.
    fn update_target_cwnd(&mut self) {
        self.target_cwnd = self.inflight(self.cwnd_gain);
    }

    /// Check and try to enter or leave Drain state.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.3.3.
    fn check_drain(&mut self, bytes_in_flight: u64, now: Instant) {
        // In Startup, when the BBR "full pipe" estimator estimates that BBR has
        // filled the pipe, BBR switches to its Drain state.
        if self.state == BbrStateMachine::Startup && self.is_filled_pipe() {
            self.enter_drain();
        }

        // In Drain, when the number of packets in flight matches the estimated
        // BDP, meaning BBR estimates that the queue has been fully drained but
        // the pipe is still full, then BBR leaves Drain and enters ProbeBW.
        if self.state == BbrStateMachine::Drain && bytes_in_flight <= self.inflight(1.0) {
            // we estimate queue is drained
            self.enter_probe_bw(now);
        }
    }

    /// Enter the ProbeBW state.
    /// BBR flows spend the vast majority of their time in ProbeBW state,
    /// probing for bandwidth using an approach called gain cycling, which
    /// helps BBR flows reach high throughput, low queuing delay, and
    /// convergence to a fair share of bandwidth.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.3.4.3.
    fn enter_probe_bw(&mut self, now: Instant) {
        self.state = BbrStateMachine::ProbeBW;
        self.pacing_gain = 1.0;
        self.cwnd_gain = 2.0;

        // Gain Cycling Randomization.
        // To improve mixing and fairness, and to reduce queues when multiple
        // BBR flows share a bottleneck, BBR randomizes the phases of ProbeBW
        // gain cycling by randomly picking an initial phase, from among all but
        // the 3/4 phase, when entering ProbeBW.
        self.cycle_index = GAIN_CYCLE_LEN - 1 - rand::thread_rng().gen_range(0..GAIN_CYCLE_LEN - 1);
        self.advance_cycle_phase(now);
    }

    /// Check if it's time to advance to the next gain cycle phase.
    fn check_cycle_phase(&mut self, now: Instant) {
        if self.state == BbrStateMachine::ProbeBW && self.is_next_cycle_phase(now) {
            self.advance_cycle_phase(now);
        }
    }

    /// Advance cycle phase during ProbeBW state.
    fn advance_cycle_phase(&mut self, now: Instant) {
        // BBR flows spend the vast majority of their time in ProbeBW state,
        // probing for bandwidth using an approach called gain cycling, which
        // helps BBR flows reach high throughput, low queuing delay, and
        // convergence to a fair share of bandwidth.
        self.cycle_stamp = now;
        self.cycle_index = (self.cycle_index + 1) % GAIN_CYCLE_LEN;
        self.pacing_gain = PACING_GAIN_CYCLE[self.cycle_index];
    }

    /// Check if it's time to advance to the next gain cycle phase in ProbeBW state.
    fn is_next_cycle_phase(&mut self, now: Instant) -> bool {
        // Each cycle phase normally lasts for roughly BBR.RTprop.
        let is_full_length = now.saturating_duration_since(self.cycle_stamp) > self.rtprop;

        if self.pacing_gain > 1.0 {
            // Cycle gain = 5/4.
            // It does this until the elapsed time in the phase has
            // been at least BBR.RTprop and either inflight has reached
            // 5/4 * estimated_BDP (which may take longer than BBR.RTprop
            // if BBR.RTprop is low) or some packets have been lost.
            return is_full_length
                && (self.ack_state.newly_lost_bytes > 0
                    || self.ack_state.prior_bytes_in_flight >= self.inflight(self.pacing_gain));
        } else if self.pacing_gain < 1.0 {
            // Cycle gain = 3/4.
            // This phase lasts until either a full BBR.RTprop has elapsed or
            // inflight drops below estimated_BDP.
            return is_full_length || self.ack_state.prior_bytes_in_flight <= self.inflight(1.0);
        }

        // Cycle gain = 1.0, which lasts for roughly BBR.RTprop.
        is_full_length
    }

    /// When restarting from idle, BBR leaves its cwnd as-is and paces
    /// packets at exactly BBR.BtlBw, aiming to return as quickly as possible
    /// to its target operating point of rate balance and a full pipe.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.3.4.4.
    fn handle_restart_from_idle(&mut self, bytes_in_flight: u64) {
        // If the flow's BBR.state is ProbeBW, and the flow is
        // application-limited, and there are no packets in flight currently,
        // then at the moment the flow sends one or more packets BBR sets
        // BBR.pacing_rate to exactly BBR.BtlBw.
        if bytes_in_flight == 0 && self.delivery_rate_estimator.is_app_limited() {
            self.is_idle_restart = true;

            if self.state == BbrStateMachine::ProbeBW {
                self.set_pacing_rate_with_gain(1.0);
            }
        }
    }

    /// Remember cwnd.
    ///
    /// It helps remember and restore the last-known good cwnd (the latest cwnd
    /// unmodulated by loss recovery or ProbeRTT)
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.3.4.
    fn save_cwnd(&mut self) {
        self.prior_cwnd = if !self.in_recovery && self.state != BbrStateMachine::ProbeRTT {
            self.cwnd
        } else {
            self.cwnd.max(self.prior_cwnd)
        }
    }

    /// Restore cwnd.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.3.4.
    fn restore_cwnd(&mut self) {
        self.cwnd = self.cwnd.max(self.prior_cwnd)
    }

    /// Return cwnd for ProbeRTT state.
    fn probe_rtt_cwnd(&self) -> u64 {
        self.config.min_cwnd
    }

    /// Check and try to enter or leave ProbeRTT state.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.3.5.
    fn check_probe_rtt(&mut self, now: Instant, bytes_in_flight: u64) {
        // In any state other than ProbeRTT itself, if the RTProp estimate has
        // not been updated (i.e., by getting a lower RTT measurement) for more
        // than ProbeRTTInterval = 10 seconds, then BBR enters ProbeRTT and
        // reduces the cwnd to a minimal value, BBRMinPipeCwnd (four packets).
        if self.state != BbrStateMachine::ProbeRTT
            && self.is_rtprop_expired
            && !self.is_idle_restart
        {
            self.enter_probe_rtt();

            // Remember the last-known good cwnd and restore it when exiting probe-rtt.
            self.save_cwnd();
            self.probe_rtt_done_stamp = None;
        }

        if self.state == BbrStateMachine::ProbeRTT {
            self.handle_probe_rtt(now, bytes_in_flight);
        }

        self.is_idle_restart = false;
    }

    /// Enter the ProbeRTT state
    fn enter_probe_rtt(&mut self) {
        self.state = BbrStateMachine::ProbeRTT;

        self.pacing_gain = 1.0;
        self.cwnd_gain = 1.0;
    }

    /// Process for the ProbeRTT state
    fn handle_probe_rtt(&mut self, now: Instant, bytes_in_flight: u64) {
        // Ignore low rate samples during ProbeRTT. MarkConnectionAppLimited.
        // C.app_limited = (BW.delivered + packets_in_flight) ? : 1
        self.delivery_rate_estimator.set_app_limited(true);

        if let Some(probe_rtt_done_stamp) = self.probe_rtt_done_stamp {
            if self.is_round_start() {
                self.probe_rtt_round_done = true;
            }

            // After maintaining BBRMinPipeCwnd or fewer packets in flight for
            // at least ProbeRTTDuration (200 ms) and one round trip, BBR leaves
            // ProbeRTT.
            if self.probe_rtt_round_done && now >= probe_rtt_done_stamp {
                self.rtprop_stamp = now;
                self.restore_cwnd();
                self.exit_probe_rtt(now);
            }
        } else if bytes_in_flight <= self.probe_rtt_cwnd() {
            self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
            // ProbeRTT round passed.
            self.probe_rtt_round_done = false;
            self.round.next_round_delivered = self.delivery_rate_estimator.delivered();
        }
    }

    /// BBR leaves ProbeRTT and transitions to either Startup or ProbeBW,
    /// depending on whether it estimates the pipe was filled already.
    fn exit_probe_rtt(&mut self, now: Instant) {
        if self.is_filled_pipe() {
            self.enter_probe_bw(now);
        } else {
            self.enter_startup();
        }
    }

    /// On every ACK, the BBR updates its network path model and state machine
    fn update_model_and_state(&mut self, now: Instant) {
        self.update_btlbw();
        self.check_cycle_phase(now);
        self.check_full_pipe();
        self.check_drain(self.stats.bytes_in_flight, now);
        self.update_rtprop(now);
        self.check_probe_rtt(now, self.stats.bytes_in_flight);
    }

    /// BBR adjusts its control parameters to adapt to the updated model.
    fn update_control_parameters(&mut self) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd();
    }

    /// For every ACK that acknowledges some data packets as delivered, BBR
    /// update the BBR.BtlBw estimator as follows.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.1.1.5.
    fn update_btlbw(&mut self) {
        self.update_round();

        if self.delivery_rate_estimator.delivery_rate() >= self.btlbw
            || !self.delivery_rate_estimator.is_sample_app_limited()
        {
            self.btlbwfilter.update_max(
                self.round.round_count,
                self.delivery_rate_estimator.delivery_rate(),
            );
            self.btlbw = self.btlbwfilter.get();
        }
    }

    /// On every ACK that provides an RTT sample BBR updates the BBR.RTprop
    /// estimator as follows.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.1.2.3.
    fn update_rtprop(&mut self, now: Instant) {
        let sample_rtt = self.delivery_rate_estimator.sample_rtt();

        self.is_rtprop_expired =
            now.saturating_duration_since(self.rtprop_stamp) > RTPROP_FILTER_LEN;

        // Use the same state to track BBR.RTprop and ProbeRTT timing.
        // In section-4.1.2.3, a zero packet.rtt is allowed, but it makes no sense.
        if !sample_rtt.is_zero() && (sample_rtt <= self.rtprop || self.is_rtprop_expired) {
            self.rtprop = sample_rtt;
            self.rtprop_stamp = now;
        }
    }

    /// BBR updates the pacing rate on each ACK as follows.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.1.
    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    /// On each ACK, BBR runs BBRSetSendQuantum() to update BBR.send_quantum
    /// as follows.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.2.
    fn set_send_quantum(&mut self) {
        // A BBR implementation MAY use alternate approaches to select a
        // BBR.send_quantum, as appropriate for the CPU overheads anticipated
        // for senders and receivers, and buffering considerations anticipated
        // in the network path. However, for the sake of the network and other
        // users, a BBR implementation SHOULD attempt to use the smallest
        // feasible quanta.
        // Adjust according to draft-cardwell-iccrg-bbr-congestion-control-02
        let floor = if self.pacing_rate < SEND_QUANTUM_THRESHOLD_PACING_RATE {
            self.config.max_datagram_size
        } else {
            2 * self.config.max_datagram_size
        };

        // BBR.send_quantum = min(BBR.pacing_rate * 1ms, 64KBytes)
        // BBR.send_quantum = max(BBR.send_quantum, floor)
        self.send_quantum = (self.pacing_rate / 1000).clamp(floor, 64 * 1024);
    }

    /// Upon every ACK in Fast Recovery, run the following steps, which help
    /// ensure packet conservation on the first round of recovery, and sending
    /// at no more than twice the current delivery rate on later rounds of
    /// recovery.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.3.4.
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

    /// To quickly reduce the volume of in-flight data and drain the bottleneck
    /// queue, thereby allowing measurement of BBR.RTprop, BBR bounds the cwnd
    /// to BBRMinPipeCwnd, the minimal value that allows pipelining.
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.3.5.
    fn modulate_cwnd_for_probe_rtt(&mut self) {
        // BBR bounds the cwnd in ProbeRTT.
        if self.state == BbrStateMachine::ProbeRTT {
            self.cwnd = self.probe_rtt_cwnd();
        }
    }

    /// Adjust the congestion window
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.3.6
    fn set_cwnd(&mut self) {
        let bytes_in_flight = self.stats.bytes_in_flight;

        self.update_target_cwnd();
        self.modulate_cwnd_for_recovery(bytes_in_flight);

        if !self.packet_conservation {
            // If BBR has measured enough samples to achieve confidence that it
            // has filled the pipe, then it increases its cwnd based on the
            // number of packets delivered, while bounding its cwnd to be no
            // larger than the BBR.target_cwnd adapted to the estimated BDP.
            if self.is_filled_pipe() {
                self.cwnd = self
                    .target_cwnd
                    .min(self.cwnd + self.ack_state.newly_acked_bytes);
            } else if self.cwnd < self.target_cwnd
                || self.delivery_rate_estimator.delivered() < self.config.initial_cwnd
            {
                // Otherwise, if the cwnd is below the target, or the sender has
                // marked so little data delivered (less than InitialCwnd) that
                // it does not yet judge its BBR.BtlBw estimate and BBR.target_cwnd
                // as useful, then it increases cwnd without bounding it to be
                // below the target.
                self.cwnd += self.ack_state.newly_acked_bytes;
            }

            // Finally, BBR imposes a floor of BBRMinPipeCwnd in order to allow
            // pipelining even with small BDPs.
            self.cwnd = self.cwnd.max(self.config.min_cwnd);
        }

        self.modulate_cwnd_for_probe_rtt();
    }

    /// Enter loss recovery
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.3.4.
    fn enter_recovery(&mut self, now: Instant) {
        self.save_cwnd();

        self.recovery_epoch_start = Some(now);

        // Upon entering Fast Recovery, set cwnd to the number of packets still
        // in flight (allowing at least one for a fast retransmit):
        self.cwnd = self.stats.bytes_in_flight
            + self
                .ack_state
                .newly_acked_bytes
                .max(self.config.max_datagram_size);

        // Note: After one round-trip in Fast Recovery, BBR.packet_conservation
        // will reset to false
        self.packet_conservation = true;
        self.in_recovery = true;

        self.round.next_round_delivered = self.delivery_rate_estimator.delivered();
    }

    /// Exit loss recovery
    ///
    /// See draft-cardwell-iccrg-bbr-congestion-control-00 Section 4.2.3.4.
    fn exit_recovery(&mut self) {
        self.recovery_epoch_start = None;
        self.packet_conservation = false;
        self.in_recovery = false;

        // Upon exiting loss recovery (RTO recovery or Fast Recovery), either by
        // repairing all losses or undoing recovery, BBR restores the best-known
        // cwnd value we had upon entering loss recovery
        self.restore_cwnd();
    }
}

impl CongestionController for Bbr {
    fn name(&self) -> &str {
        "BBR"
    }

    fn on_sent(&mut self, now: Instant, packet: &mut SentPacket, bytes_in_flight: u64) {
        self.delivery_rate_estimator.on_packet_sent(
            packet,
            self.stats.bytes_in_flight,
            self.stats.bytes_lost_in_total,
        );

        self.handle_restart_from_idle(self.stats.bytes_in_flight);
        self.stats.bytes_in_flight += packet.sent_size as u64;
    }

    fn begin_ack(&mut self, now: Instant, bytes_in_flight: u64) {
        self.ack_state.newly_acked_bytes = 0;
        self.ack_state.newly_lost_bytes = 0;
        self.ack_state.packet_delivered = 0;
        self.ack_state.last_ack_packet_sent_time = now;
        self.ack_state.prior_bytes_in_flight = self.stats.bytes_in_flight;
        self.ack_state.now = now;
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
        // Generate rate sample.
        self.delivery_rate_estimator.generate_rate_sample();

        // Check if exit recovery
        if self.in_recovery && !self.in_recovery(self.ack_state.last_ack_packet_sent_time) {
            self.exit_recovery();
        }

        // Update model and control parameters.
        self.update_model_and_state(self.ack_state.now);
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

        // Refer to <https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2>.
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
        self.state == BbrStateMachine::Startup
    }

    fn stats(&self) -> &CongestionStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    // todo: unit test case
}
