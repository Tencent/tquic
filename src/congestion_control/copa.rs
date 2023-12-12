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

//! Copa: Practical Delay-Based Congestion Control for the Internet.
//!
//! Copa is an end-to-end congestion control algorithm that detect the presence
//! of buffer-fillers by observing the delay evolution, and respond with
//! additive-increase/multiplicative decrease on specified parameters. Experimental
//! results show that Copa can achieve low queueing delay and excellent fairness with
//! other congestion control algorithms.
//!
//! See <https://web.mit.edu/copa/>.

use std::time::Duration;
use std::time::Instant;

use log::*;

use super::minmax::MinMax;
use super::CongestionController;
use super::CongestionStats;
use crate::connection::rtt::RttEstimator;
use crate::connection::space::RateSamplePacketState;
use crate::connection::space::SentPacket;

/// Delta: determines how much to weigh delay compared to throughput.
const COPA_DELTA: f64 = 0.04;

/// Max count while cwnd grows with the same direction. Speed up if
/// the count exceeds threshold.
const SPEED_UP_THRESHOLD: u64 = 3;

/// Default standing rtt filter length.
const STANDING_RTT_FILTER_WINDOW: Duration = Duration::from_millis(100);

/// Default min rtt filter length.
const MIN_RTT_FILTER_WINDOW: Duration = Duration::from_secs(10);

/// Pacing gain to cope with ack compression.
const PACING_GAIN: u64 = 2;

/// Delay oscillation rate to check if queueing delay is nearly empty:
/// queueing_delay < 0.1 * (Rtt_max - Rtt_min)
/// Where Rtt_max and Rtt_min is the max and min RTT in the last 4 rounds.
const DELAY_OSCILLATION_THRESHOLD: f64 = 0.1;

/// Max loss rate in one round. If the loss rate exceeds the threshold, switch
/// the mode to competitive mode.
const LOSS_RATE_THRESHOLD: f64 = 0.1;

/// Copa configurable parameters.
#[derive(Debug)]
pub struct CopaConfig {
    /// Minimal congestion window in bytes.
    min_cwnd: u64,

    /// Initial congestion window in bytes.
    initial_cwnd: u64,

    /// Initial Smoothed rtt.
    initial_rtt: Option<Duration>,

    /// Max datagram size in bytes.
    max_datagram_size: u64,

    /// Delta in slow start. Delta determines how much to weigh delay compared to
    /// throughput. A larger delta signifies that lower packet delays are preferable.
    slow_start_delta: f64,

    /// Delta in steady state.
    steady_delta: f64,

    /// Use rtt standing or latest rtt to calculate queueing delay.
    use_standing_rtt: bool,
}

impl CopaConfig {
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
            slow_start_delta: COPA_DELTA,
            steady_delta: COPA_DELTA,
            use_standing_rtt: true,
        }
    }
}

impl Default for CopaConfig {
    fn default() -> Self {
        Self {
            min_cwnd: 4 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            initial_cwnd: 80 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            initial_rtt: Some(crate::INITIAL_RTT),
            max_datagram_size: crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            slow_start_delta: COPA_DELTA,
            steady_delta: COPA_DELTA,
            use_standing_rtt: true,
        }
    }
}

/// Copa congestion window growth direction.
#[derive(Eq, PartialEq, Debug)]
enum Direction {
    /// Cwnd increasing.
    Up,

    /// Cwnd decreasing.
    Down,
}

/// Copa competing mode with other flows.
#[derive(Eq, PartialEq, Debug)]
enum CompetingMode {
    /// Default mode, no competing flows.
    Default,

    /// Competitive mode, use adaptive delta.
    Competitive,
}

/// Velocity control states.
#[derive(Debug)]
struct Velocity {
    /// Cwnd growth direction.
    direction: Direction,

    /// Velocity coef.
    velocity: u64,

    /// Cwnd recorded at last time.
    last_cwnd: u64,

    /// Times while cwnd grows with the same direction. Speed up if cnt
    /// exceeds threshold.
    same_direction_cnt: u64,
}

impl Default for Velocity {
    fn default() -> Self {
        Self {
            direction: Direction::Up,
            velocity: 1,
            last_cwnd: 0,
            same_direction_cnt: 0,
        }
    }
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

    /// Largest acked packet number.
    largest_acked_pkt_num: u64,

    /// Minimum rtt in this ACK packet.
    min_rtt: Duration,

    /// The last smoothed rtt in the current ACK packet.
    last_srtt: Duration,
}

impl Default for AckState {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            now,
            newly_lost_bytes: 0,
            newly_acked_bytes: 0,
            largest_acked_pkt_num: 0,
            min_rtt: Duration::ZERO,
            last_srtt: Duration::ZERO,
        }
    }
}

/// Round trip counter for tracking packet-timed round trips which starts
/// at the transmission of some segment, and then ends at the ack of that segment.
#[derive(Debug, Default)]
struct RoundTripCounter {
    /// Count of packet-timed round trips.
    pub round_count: u64,

    /// A boolean that BBR sets to true once per packet-
    /// timed round trip, on ACKs that advance BBR.round_count.
    pub is_round_start: bool,

    /// Packet number denoting the end of
    /// a packet-timed round trip.
    pub round_end_pkt_num: u64,

    /// Total acked bytes when a new round starts.
    pub last_total_acked_bytes: u64,

    /// Total lost bytes when a new round starts.
    pub last_total_lost_bytes: u64,

    /// Lost rate in this round, calculated as `lost / (lost + acked)`.
    pub loss_rate: f64,
}

/// Copa: Practical Delay-Based Congestion Control for the Internet.
///
/// See <https://web.mit.edu/copa/>.
#[derive(Debug)]
pub struct Copa {
    /// Config
    config: CopaConfig,

    /// Statistics.
    stats: CongestionStats,

    /// The time origin point when Copa init, used for window filter updating.
    init_time: Instant,

    /// Competing mode.
    mode: CompetingMode,

    /// Is in slow start state.
    slow_start: bool,

    /// Congestion window/
    cwnd: u64,

    /// Velocity parameter, speeds-up convergence.
    velocity: Velocity,

    /// Weight factor for queueing delay. Use default value in default mode,
    /// and use an adaptive one in competitive mode.
    delta: f64,

    /// Minimum rtt in time window tau (srtt/2).
    standing_rtt_filter: MinMax,

    /// Minimum rtt in the last time period, e.g. 10s for default.
    min_rtt_filter: MinMax,

    /// Ack state in the current round.
    ack_state: AckState,

    /// Whether cwnd should be increased.
    increase_cwnd: bool,

    /// Target pacing rate.
    target_rate: u64,

    /// The last sent packet number.
    last_sent_pkt_num: u64,

    /// Round trip counter.
    round: RoundTripCounter,
}

impl Copa {
    pub fn new(config: CopaConfig) -> Self {
        let slow_start_delta = config.slow_start_delta;
        let initial_cwnd = config.initial_cwnd;

        Self {
            config,
            stats: Default::default(),
            init_time: Instant::now(),
            mode: CompetingMode::Default,
            slow_start: true,
            cwnd: initial_cwnd,
            velocity: Velocity::default(),
            delta: slow_start_delta,
            standing_rtt_filter: MinMax::new(STANDING_RTT_FILTER_WINDOW.as_micros() as u64),
            min_rtt_filter: MinMax::new(MIN_RTT_FILTER_WINDOW.as_micros() as u64),
            ack_state: Default::default(),
            increase_cwnd: false,
            target_rate: 0,
            last_sent_pkt_num: 0,
            round: Default::default(),
        }
    }

    /// Update velocity.
    // Once per window, the sender compares the current cwnd to the cwnd value at
    // the time that the latest acknowledged packet was sent (i.e., cwnd at the
    // start of the current window). If the current cwnd is larger, then set direction
    // to 'up'; if it is smaller, then set direction to 'down'. Now, if direction is
    // the same as in the previous window, then double v. If not, then reset v to 1.
    // However, start doubling v only after the direction has remained the same for three RTTs.
    fn update_velocity(&mut self) {
        // in the case that cwnd should increase in slow start, we do not need
        // to update velocity, since cwnd is always doubled.
        if self.slow_start && self.increase_cwnd {
            return;
        }

        // First time to run here.
        if self.velocity.last_cwnd == 0 {
            self.velocity.last_cwnd = self.cwnd.max(self.config.min_cwnd);
            self.velocity.velocity = 1;
            self.velocity.same_direction_cnt = 0;

            return;
        }

        // Update velocity at the beginning of each round.
        if !self.is_round_start() {
            return;
        }

        // Check cwnd growth direction.
        // if in slow start, and target rate is not reached, then increase cwnd anyway.
        // otherwise, check and update direction to determine cwnd growth in next steps.
        let new_direction = if self.cwnd > self.velocity.last_cwnd {
            Direction::Up
        } else {
            Direction::Down
        };

        if new_direction != self.velocity.direction {
            // Direction changes, reset velocity.
            self.velocity.velocity = 1;
            self.velocity.same_direction_cnt = 0;
        } else {
            // Same direction, check to speed up.
            self.velocity.same_direction_cnt = self.velocity.same_direction_cnt.saturating_add(1);

            if self.velocity.same_direction_cnt >= SPEED_UP_THRESHOLD {
                self.velocity.velocity = self.velocity.velocity.saturating_mul(2);
            }
        }

        // if our current rate is much different than target, we double v every
        // RTT. That could result in a high v at some point in time. If we
        // detect a sudden direction change here, while v is still very high but
        // meant for opposite direction, we should reset it to 1.
        //
        // e.g. cwnd < last_recorded_cwnd && rate < target_rate
        // cwnd < last_recorded_cwnd means that direction is still DOWN while velocity may be large
        // rate < target_rate means that cwnd is about to increase
        // so a switch point is produced, we hope copa switch to increase up as soon as possible。
        if self.increase_cwnd
            && self.velocity.direction != Direction::Up
            && self.velocity.velocity > 1
        {
            self.velocity.direction = Direction::Up;
            self.velocity.velocity = 1;
        } else if !self.increase_cwnd
            && self.velocity.direction != Direction::Down
            && self.velocity.velocity > 1
        {
            self.velocity.direction = Direction::Down;
            self.velocity.velocity = 1;
        }

        self.velocity.direction = new_direction;
        self.velocity.last_cwnd = self.cwnd;
    }

    /// Update mode and parameter delta.
    fn update_mode(&mut self) {
        // Check if loss rate exceeds threshold when a new round starts. If so,
        // We assume that Copa should switch to competitive mode, to competing with
        // other buffer-filling flows.
        self.mode = if self.round.loss_rate >= LOSS_RATE_THRESHOLD {
            CompetingMode::Competitive
        } else {
            CompetingMode::Default
        };

        match self.mode {
            CompetingMode::Default => {
                self.delta = if self.slow_start {
                    self.config.slow_start_delta
                } else {
                    self.config.steady_delta
                };
            }
            CompetingMode::Competitive => {
                // Double delta to slow down the target rate.
                self.delta *= 2.0_f64;
                self.delta = self.delta.min(0.5);
            }
        }
    }

    /// Update congestion window.
    fn update_cwnd(&mut self) {
        // Deal with the following cases:
        // 1. slow_start, cwnd to increase: double cwnd
        // 2. slow_start, cwnd to decrease: exiting slow_start and decrease cwnd
        // 3. not slow_start, cwnd to increase: increase cwnd
        // 4. not slow_start, cwnd to decrease: decrease cwnd

        // Exit slow start once cwnd begins to decrease, i.e. rate reaches target rate.
        if self.slow_start && !self.increase_cwnd {
            self.slow_start = false;
        }

        if self.slow_start {
            // Stay in slow start until the target rate is reached.
            if self.increase_cwnd {
                self.cwnd = self.cwnd.saturating_add(self.ack_state.newly_acked_bytes);
            }
        } else {
            let cwnd_delta = ((self.velocity.velocity
                * self.ack_state.newly_acked_bytes
                * self.config.max_datagram_size) as f64
                / (self.delta * (self.cwnd as f64))) as u64;

            // Not in slow start. Adjust cwnd.
            self.cwnd = if self.increase_cwnd {
                self.cwnd.saturating_add(cwnd_delta)
            } else {
                self.cwnd.saturating_sub(cwnd_delta)
            };

            if self.cwnd == 0 {
                trace!("{}. cwnd is zero!!!", self.name());

                self.cwnd = self.config.min_cwnd;
                self.velocity.velocity = 1;
            }
        }
    }

    /// Check if a new round starts and update round.
    fn update_round(&mut self) {
        if self.ack_state.largest_acked_pkt_num >= self.round.round_end_pkt_num {
            // Calculate loss rate first and then update round states.
            let bytes_lost_in_this_round = self
                .stats
                .bytes_lost_in_total
                .saturating_sub(self.round.last_total_lost_bytes);
            let bytes_acked_in_this_round = self
                .stats
                .bytes_acked_in_total
                .saturating_sub(self.round.last_total_acked_bytes);

            self.round.loss_rate = bytes_lost_in_this_round as f64
                / bytes_lost_in_this_round.saturating_add(bytes_acked_in_this_round) as f64;

            self.round.last_total_acked_bytes = self.stats.bytes_acked_in_total;
            self.round.last_total_lost_bytes = self.stats.bytes_lost_in_total;
            self.round.round_count = self.round.round_count.saturating_add(1);
            self.round.round_end_pkt_num = self.last_sent_pkt_num;
            self.round.is_round_start = true;
        } else {
            self.round.is_round_start = false;
        }
    }

    /// Check if a new round starts.
    fn is_round_start(&self) -> bool {
        self.round.is_round_start
    }

    /// Update Copa model driven by ACK packet.
    fn update_model(&mut self) {
        // COPA algorithm processing steps:
        // 1. update d_q and srtt;
        // 2. set lambda_t to 1/(delta * d_q);
        // 3. adjust cwnd according to the relationship of lambda and lambda_t
        // 4. update velocity
        //
        // d_q = RTT_standing - minRTT, where RTT_standing is the minimum during time window srtt/2

        // Update standing rtt and min rtt.
        if self.config.use_standing_rtt {
            self.standing_rtt_filter
                .set_window(self.ack_state.last_srtt.as_micros() as u64);
        } else {
            self.standing_rtt_filter
                .set_window(self.ack_state.last_srtt.as_micros() as u64 / 2);
        }

        if self.ack_state.min_rtt == Duration::ZERO {
            self.ack_state.min_rtt = if self.ack_state.last_srtt == Duration::ZERO {
                self.config.initial_rtt.unwrap_or(Duration::from_millis(20))
            } else {
                self.ack_state.last_srtt
            };
        }

        // Update min rtt in period of standing window and 10s respectly.
        let elapsed = self.ack_state.now.saturating_duration_since(self.init_time);
        self.min_rtt_filter.update_min(
            elapsed.as_micros() as u64,
            self.ack_state.min_rtt.as_micros() as u64,
        );
        self.standing_rtt_filter.update_min(
            elapsed.as_micros() as u64,
            self.ack_state.min_rtt.as_micros() as u64,
        );

        // Adjust delta.
        self.update_mode();

        let min_rtt = Duration::from_micros(self.min_rtt_filter.get());
        let standing_rtt = self.get_standing_rtt();

        trace!(
            "{}. round_min_rtt = {}us, elapsed = {}us, min_rtt = {}us, standing_rtt = {}us",
            self.name(),
            self.ack_state.min_rtt.as_micros(),
            elapsed.as_micros(),
            min_rtt.as_micros(),
            standing_rtt.as_micros(),
        );

        let current_rate: u64 = (self.cwnd as f64 / standing_rtt.as_secs_f64()) as u64;
        let queueing_delay = standing_rtt.saturating_sub(min_rtt);
        if queueing_delay.is_zero() {
            // taking care of inf targetRate case here, this happens in beginning where
            // we do want to increase cwnd, e.g. slow start or no queuing happens.
            self.increase_cwnd = true;

            trace!(
                "{}. queuing delay is zero. rtt_standing and min_rtt is the same: {}us",
                self.name(),
                min_rtt.as_micros()
            );

            self.target_rate = (self.cwnd as f64 / standing_rtt.as_secs_f64()) as u64;
        } else {
            // Limit queueing_delay in case it's too small and get a huge target rate.
            self.target_rate = (self.config.max_datagram_size as f64
                / self.delta
                / queueing_delay.max(Duration::from_micros(1)).as_secs_f64())
                as u64;

            trace!(
                "{}. target_rate = {}, delta = {}, max_datagram_size = {}",
                self.name(),
                self.target_rate,
                self.delta,
                self.config.max_datagram_size
            );

            self.increase_cwnd = self.target_rate >= current_rate;
        }

        self.update_velocity();
        self.update_cwnd();

        trace!(
            "{}. mode = {:?}, slow_start={}, delta={}, target_rate={}, current_rate={},
             increase_cwnd={}, queuing_delay={}us, rtt_standing={}us, cwnd={}",
            self.name(),
            self.mode,
            self.slow_start,
            self.delta,
            self.target_rate,
            current_rate,
            self.increase_cwnd,
            queueing_delay.as_micros(),
            standing_rtt.as_micros(),
            self.cwnd
        );
    }

    /// Get standing rtt.
    fn get_standing_rtt(&self) -> Duration {
        let standing_rtt = Duration::from_micros(self.standing_rtt_filter.get());
        if standing_rtt.is_zero() {
            return std::cmp::max(
                self.config.initial_rtt.unwrap_or(crate::INITIAL_RTT),
                Duration::from_micros(1),
            );
        }
        standing_rtt
    }
}

impl CongestionController for Copa {
    fn pacing_rate(&self) -> Option<u64> {
        let standing_rtt = self.get_standing_rtt();
        let current_rate = (self.cwnd as f64 / standing_rtt.as_secs_f64()) as u64;

        Some(PACING_GAIN * current_rate)
    }

    fn name(&self) -> &str {
        "COPA"
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

    fn in_slow_start(&self) -> bool {
        self.slow_start
    }

    fn stats(&self) -> &CongestionStats {
        &self.stats
    }

    fn on_sent(&mut self, now: Instant, packet: &mut SentPacket, bytes_in_flight: u64) {
        self.stats.bytes_in_flight = bytes_in_flight;
        self.stats.bytes_sent_in_total = self
            .stats
            .bytes_sent_in_total
            .saturating_add(packet.sent_size as u64);

        self.last_sent_pkt_num = packet.pkt_num;
    }

    fn begin_ack(&mut self, now: Instant, bytes_in_flight: u64) {
        self.ack_state.newly_acked_bytes = 0;
        self.ack_state.newly_lost_bytes = 0;
        self.ack_state.now = now;
        self.ack_state.min_rtt = Duration::ZERO;
        self.ack_state.last_srtt = Duration::ZERO;
        self.ack_state.largest_acked_pkt_num = 0;
    }

    fn on_ack(
        &mut self,
        packet: &mut SentPacket,
        now: Instant,
        _app_limited: bool,
        rtt: &RttEstimator,
        bytes_in_flight: u64,
    ) {
        // Update stats.
        let sent_time = packet.time_sent;
        let acked_bytes = packet.sent_size as u64;

        self.stats.bytes_in_flight = self.stats.bytes_in_flight.saturating_sub(acked_bytes);
        self.stats.bytes_acked_in_total =
            self.stats.bytes_acked_in_total.saturating_add(acked_bytes);
        if self.in_slow_start() {
            self.stats.bytes_acked_in_slow_start = self
                .stats
                .bytes_acked_in_slow_start
                .saturating_add(acked_bytes);
        }

        self.ack_state.newly_acked_bytes =
            self.ack_state.newly_acked_bytes.saturating_add(acked_bytes);

        self.ack_state.largest_acked_pkt_num =
            self.ack_state.largest_acked_pkt_num.max(packet.pkt_num);
        self.ack_state.last_srtt = rtt.smoothed_rtt();

        // Since all the ack frames in a packet share the same ack_time and 'now_time',
        // we record only the minimum rtt and its corresponding time which will be
        // processed at the stage of end_ack.
        if self.ack_state.min_rtt.is_zero() || self.ack_state.min_rtt >= rtt.latest_rtt() {
            trace!(
                "{}. Got a smaller rtt: {}us -> {}us",
                self.name(),
                self.ack_state.min_rtt.as_micros(),
                rtt.latest_rtt().as_micros()
            );

            self.ack_state.min_rtt = rtt.latest_rtt();
        }

        trace!(
            "{}. ON_ACK. latest_rtt = {}us, srtt = {}us, newly_acked = {}, total_acked = {}",
            self.name(),
            rtt.latest_rtt().as_micros(),
            rtt.smoothed_rtt().as_micros(),
            self.ack_state.newly_acked_bytes,
            self.stats.bytes_acked_in_total,
        )
    }

    fn end_ack(&mut self) {
        self.update_round();
        trace!(
            "{}. END_ACK. round_start = {:?}, round_count = {}, end_pkt = {}, loss_rate = {}, last_acked = {}, last_lost = {}",
            self.name(),
            self.is_round_start(),
            self.round.round_count,
            self.round.round_end_pkt_num,
            self.round.loss_rate,
            self.round.last_total_acked_bytes,
            self.round.last_total_lost_bytes,
        );

        self.update_model();
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        packet: &SentPacket,
        in_persistent_congestion: bool,
        lost_bytes: u64,
        bytes_in_flight: u64,
    ) {
        // Statistics.
        self.stats.bytes_lost_in_total = self.stats.bytes_lost_in_total.saturating_add(lost_bytes);
        self.stats.bytes_in_flight = bytes_in_flight;

        if self.in_slow_start() {
            self.stats.bytes_lost_in_slow_start = self
                .stats
                .bytes_lost_in_slow_start
                .saturating_add(lost_bytes);
        }
    }
}
