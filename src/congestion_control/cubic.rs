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

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use log::*;

use super::CongestionController;
use super::CongestionStats;
use super::HystartPlusPlus;
use crate::connection::rtt::RttEstimator;
use crate::connection::space::SentPacket;
use crate::RecoveryConfig;

/// Cubic constant C.
///
/// Constant that determines the aggressiveness of CUBIC in competing with
/// other congestion control algorithms in high-BDP networks. Default to 0.4.
///
/// See <https://www.rfc-editor.org/rfc/rfc9438.html#name-constants-of-interest>.
const C: f64 = 0.4;

/// Cubic constant beta.
///
/// Beta_cubic is the CUBIC multiplication decrease factor, that
/// is, when a congestion event is detected, CUBIC reduces its cwnd to
/// W_cubic(0) = W_max * beta_cubic. Default to 0.7.
///
/// See <https://www.rfc-editor.org/rfc/rfc9438.html#name-constants-of-interest>.
const BETA: f64 = 0.7;

/// Cubic constant alpha.
///
/// CUBIC additive increase factor used in the Reno-friendly region.
/// Default to 3 * (1 - beta) / (1 + beta)
/// as <https://www.rfc-editor.org/rfc/rfc9438.html#Reno-friendly>.
///
/// See <https://www.rfc-editor.org/rfc/rfc9438.html#name-constants-of-interest>.
const ALPHA: f64 = 3.0 * (1.0 - BETA) / (1.0 + BETA);

/// Cubic Configuration.
#[derive(Debug)]
pub struct CubicConfig {
    /// Constant C.
    c: f64,

    /// Beta.
    beta: f64,

    /// Minimal congestion window in bytes.
    min_congestion_window: u64,

    /// Initial congestion window in bytes.
    initial_congestion_window: u64,

    /// The threshold for slow start in bytes.
    slow_start_thresh: u64,

    /// Max datagram size in bytes.
    max_datagram_size: u64,

    /// Enable Hystart++, default to true.
    hystart_enabled: bool,

    /// Enable fast convergence, default to true.
    fast_convergence_enabled: bool,

    /// Initial rtt.
    initial_rtt: Option<Duration>,
}

impl CubicConfig {
    pub fn from(conf: &RecoveryConfig) -> Self {
        let max_datagram_size = conf.max_datagram_size as u64;
        let min_congestion_window = conf.min_congestion_window.saturating_mul(max_datagram_size);
        let initial_congestion_window = conf
            .initial_congestion_window
            .saturating_mul(max_datagram_size);
        let slow_start_thresh = conf.slow_start_thresh.saturating_mul(max_datagram_size);
        let initial_rtt = Some(conf.initial_rtt);

        Self {
            c: C,
            beta: BETA,
            min_congestion_window,
            initial_congestion_window,
            slow_start_thresh,
            initial_rtt,
            max_datagram_size,
            hystart_enabled: true,
            fast_convergence_enabled: true,
        }
    }

    /// Update C.
    fn set_c(&mut self, c: f64) -> &mut Self {
        self.c = c;
        self
    }

    /// Update beta.
    fn set_beta(&mut self, beta: f64) -> &mut Self {
        self.beta = beta;
        self
    }

    /// Enable hystart.
    fn enable_hystart(&mut self, enable: bool) -> &mut Self {
        self.hystart_enabled = enable;
        self
    }

    /// Enable fast_convergence.
    fn enable_fast_convergence(&mut self, enable: bool) -> &mut Self {
        self.fast_convergence_enabled = enable;
        self
    }

    /// Update min congestion window.
    fn set_min_congestion_window(&mut self, min_congestion_window: u64) -> &mut Self {
        self.min_congestion_window = min_congestion_window;
        self
    }

    /// Update initial congestion window.
    fn set_initial_congestion_window(&mut self, initial_congestion_window: u64) -> &mut Self {
        self.initial_congestion_window = initial_congestion_window;
        self
    }

    /// Update max datagram size.
    fn set_max_datagram_size(&mut self, max_datagram_size: u64) -> &mut Self {
        self.max_datagram_size = max_datagram_size;
        self
    }
}

impl Default for CubicConfig {
    fn default() -> Self {
        Self {
            c: C,
            beta: BETA,
            min_congestion_window: 2 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            initial_congestion_window: 10 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            slow_start_thresh: u64::MAX,
            initial_rtt: Some(crate::INITIAL_RTT),
            max_datagram_size: crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
            hystart_enabled: true,
            fast_convergence_enabled: true,
        }
    }
}

/// Cubic congestion control algorithm.
///
/// See <https://www.rfc-editor.org/rfc/rfc9438.html>.
#[derive(Debug)]
pub struct Cubic {
    /// Configuration.
    config: CubicConfig,

    /// Hystart++ object.
    hystart: HystartPlusPlus,

    /// Congestion window in bytes.
    cwnd: u64,

    /// Slow start thresh in bytes.
    ssthresh: u64,

    /// The window size just before the window is reduced in the last congestion event.
    w_max: f64,

    /// The time period that W_cubic takes to increase the current window
    /// size to W_max if there are no further congestion events.
    k: f64,

    /// CUBIC additive increase factor used in the Reno-friendly region.
    alpha: f64,

    /// Estimated window to achieve the same average window size as Standard TCP.
    w_est: f64,

    /// Cwnd increment during congestion avoidance.
    cwnd_inc: u64,

    /// Time of the last recovery event starts.
    recovery_epoch_start: Option<Instant>,

    /// Sent time of the last packet.
    last_sent_time: Option<Instant>,

    /// Congestion statistics.
    stats: CongestionStats,

    /// Pacing rate
    pacing_rate: u64,

    /// Initial rtt.
    initial_rtt: Duration,
}

impl Cubic {
    pub fn new(config: CubicConfig) -> Self {
        let initial_cwnd = config.initial_congestion_window;
        let ssthresh = config.slow_start_thresh;
        let initial_rtt = std::cmp::max(
            config.initial_rtt.unwrap_or(crate::INITIAL_RTT),
            Duration::from_micros(1),
        );
        let pacing_rate = (initial_cwnd as f64 / initial_rtt.as_secs_f64()) as u64;
        let hystart_enabled = config.hystart_enabled;
        let alpha = 3.0 * (1.0 - config.beta) / (1.0 + config.beta);
        Self {
            config,
            hystart: HystartPlusPlus::new(hystart_enabled),
            cwnd: initial_cwnd,
            ssthresh,
            w_max: 0_f64,
            k: 0_f64,
            alpha,
            w_est: 0_f64,
            cwnd_inc: 0_u64,
            recovery_epoch_start: None,
            last_sent_time: None,
            stats: Default::default(),
            pacing_rate,
            initial_rtt,
        }
    }

    /// Calculate window increase during congestion avoidance.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9438.html#name-window-increase-function>.
    fn w_cubic(&self, t: Duration, max_datagram_size: u64) -> f64 {
        // W_cubic(t) = C*(t-K)^3 + W_max
        self.config.c * (t.as_secs_f64() - self.k).powi(3) * max_datagram_size as f64 + self.w_max
    }

    /// Calculate window estimation to achieves approximately the same average window size as Reno.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9438.html#name-reno-friendly-region>.
    fn w_est(&self, acked_bytes: u64, max_datagram_size: u64) -> f64 {
        // W_est = W_est + [3*(1-beta_cubic)/(1+beta_cubic)] * (segments_acked/cwnd)
        self.w_est + self.alpha * acked_bytes as f64 / self.cwnd as f64 * max_datagram_size as f64
    }

    /// Calculate parameter K.
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc9438.html#name-window-increase-function>.
    fn cubic_k(&self, cwnd: u64, max_datagram_size: u64) -> f64 {
        // K = cubic_root((W_max - cwnd_epoch)/C).
        if self.w_max > cwnd as f64 {
            ((self.w_max - cwnd as f64) / max_datagram_size as f64 / self.config.c).cbrt()
        } else {
            0.0
        }
    }
}

impl CongestionController for Cubic {
    fn name(&self) -> &str {
        "CUBIC"
    }

    fn on_sent(&mut self, now: Instant, packet: &mut SentPacket, bytes_in_flight: u64) {
        // Better follow cubic curve after idle period.
        // See <https://github.com/torvalds/linux/commit/30927520dbae297182990bb21d08762bcc35ce1d>.
        if bytes_in_flight == 0 {
            if let Some(last_sent_time) = self.last_sent_time {
                if let Some(recovery_epoch_start) = self.recovery_epoch_start {
                    // Shifted later in time by the amount of the idle period.
                    self.recovery_epoch_start = Some(
                        recovery_epoch_start
                            + packet.time_sent.saturating_duration_since(last_sent_time),
                    );
                }
            }
        }

        self.last_sent_time = Some(packet.time_sent);
        self.hystart.on_sent(packet.pkt_num);

        // Statistics.
        let sent_bytes = packet.sent_size as u64;

        self.stats.bytes_in_flight = bytes_in_flight;
        self.stats.bytes_sent_in_total = self.stats.bytes_sent_in_total.saturating_add(sent_bytes);

        if self.in_slow_start() {
            self.stats.bytes_sent_in_slow_start = self
                .stats
                .bytes_sent_in_slow_start
                .saturating_add(sent_bytes);
        }
    }

    fn begin_ack(&mut self, now: Instant, bytes_in_flight: u64) {
        // Do nothing.
    }

    fn on_ack(
        &mut self,
        packet: &mut SentPacket,
        now: Instant,
        app_limited: bool,
        rtt: &RttEstimator,
        bytes_in_flight: u64,
    ) {
        // Statistics.
        let sent_time = packet.time_sent;
        let acked_bytes = packet.sent_size as u64;

        self.stats.bytes_in_flight = bytes_in_flight;
        self.stats.bytes_acked_in_total =
            self.stats.bytes_acked_in_total.saturating_add(acked_bytes);
        if self.in_slow_start() {
            self.stats.bytes_acked_in_slow_start = self
                .stats
                .bytes_acked_in_slow_start
                .saturating_add(acked_bytes);
        }

        if app_limited || self.in_recovery(sent_time) || rtt.smoothed_rtt().is_zero() {
            return;
        }

        if self.in_slow_start() {
            // In slow start
            self.cwnd = self.cwnd.saturating_add(
                self.hystart
                    .cwnd_increment(acked_bytes, self.config.max_datagram_size),
            );

            self.hystart
                .on_ack(packet.pkt_num, acked_bytes, rtt.latest_rtt());
        } else {
            // Congestion avoidance.
            let duration_since_recovery: Duration;

            if let Some(recovery_start) = self.recovery_epoch_start {
                // Congestion event happened.
                duration_since_recovery = now.saturating_duration_since(recovery_start);
            } else {
                // No congestion event happened. Initialize here.
                self.recovery_epoch_start = Some(now);
                self.w_max = self.cwnd as f64;
                self.k = 0_f64;
                self.w_est = self.cwnd as f64;
                self.alpha = ALPHA;

                duration_since_recovery = Duration::ZERO;
            }

            // Update W_cubic and target:
            //  `target = W_cubic(t+RTT).clamp(cwnd, 1.5*cwnd)`
            // as <https://www.rfc-editor.org/rfc/rfc9438.html#name-window-increase-function>.
            let mut target = self.w_cubic(
                duration_since_recovery.saturating_add(rtt.smoothed_rtt()),
                self.config.max_datagram_size,
            );

            target = target.clamp(self.cwnd as f64, 1.5 * self.cwnd as f64);

            // Update w_est
            // as <https://www.rfc-editor.org/rfc/rfc9438.html#name-reno-friendly-region>.
            self.w_est = self.w_est(acked_bytes, self.config.max_datagram_size);

            // Once West has grown to reach the cwnd at the time of most recently setting ssthresh
            // -- that is, West >= cwnd_prior -- the sender SHOULD set alpha_cubic to 1 to ensure
            // that it can achieve the same congestion window increment rate as Reno.
            if self.w_est >= self.w_max {
                self.alpha = 1.0_f64;
            }

            let mut cwnd = self.cwnd;

            let w_cubic_t = self.w_cubic(duration_since_recovery, self.config.max_datagram_size);

            if w_cubic_t < self.w_est {
                // See <https://www.rfc-editor.org/rfc/rfc9438.html#name-reno-friendly-region>.
                // When receiving a new ACK in congestion avoidance (where cwnd could be greater than or
                // less than Wmax), CUBIC checks whether Wcubic(t) is less than West. If so, CUBIC is in
                // the Reno-friendly region and cwnd SHOULD be set to West at each reception of a new ACK
                cwnd = cwnd.max(self.w_est as u64);
            } else {
                // Increment in concave and convex region is calculated as:
                //  (target - cwnd)/cwnd
                // See <https://www.rfc-editor.org/rfc/rfc9438.html#name-concave-region>.
                let cubic_inc =
                    (target - cwnd as f64) / cwnd as f64 * self.config.max_datagram_size as f64;

                cwnd += cubic_inc as u64;
            }

            // Update the increment and increase cwnd by max datagram size.
            self.cwnd_inc += cwnd - self.cwnd;
            self.cwnd +=
                self.cwnd_inc / self.config.max_datagram_size * self.config.max_datagram_size;
            self.cwnd_inc %= self.config.max_datagram_size;
        }

        self.pacing_rate = if rtt.smoothed_rtt().is_zero() {
            (self.cwnd as u128 * 1_000_000 / self.initial_rtt.as_micros()) as u64
        } else {
            (self.cwnd as u128 * 1_000_000 / rtt.smoothed_rtt().as_micros()) as u64
        };
    }

    fn end_ack(&mut self) {
        if !self.hystart.has_exited() {
            self.hystart.end_ack();

            // Check if hystart++ has exited
            if self.hystart.has_exited() {
                self.ssthresh = self.cwnd;
            }
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        packet: &SentPacket,
        is_persistent_congestion: bool,
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

        let sent_time = packet.time_sent;

        if self.in_recovery(sent_time) {
            return;
        }

        // Enter recovery mode.
        self.recovery_epoch_start = Some(now);

        // Fast convergence.
        // See <https://www.rfc-editor.org/rfc/rfc9438.html#name-fast-convergence>.
        if self.config.fast_convergence_enabled {
            self.w_max = if (self.cwnd as f64) < self.w_max {
                self.cwnd as f64 * (1.0 + self.config.beta) / 2.0
            } else {
                self.cwnd as f64
            };
        }

        // Update ssthresh
        // as <https://www.rfc-editor.org/rfc/rfc9438.html#name-multiplicative-decrease>.
        self.ssthresh = (self.cwnd as f64 * self.config.beta) as u64;
        self.ssthresh = self.ssthresh.max(2 * self.config.max_datagram_size);
        self.cwnd = self.ssthresh.max(2 * self.config.max_datagram_size);

        self.k = self.cubic_k(self.cwnd, self.config.max_datagram_size);

        self.cwnd_inc = (self.cwnd_inc as f64 * self.config.beta) as u64;

        // W_est is set equal to cwnd_epoch at the start of the congestion avoidance stage,
        // see <https://www.rfc-editor.org/rfc/rfc9438.html#name-reno-friendly-region>.
        self.w_est = self.cwnd as f64;
        self.alpha = ALPHA;

        self.hystart.on_congestion_event();

        // See <https://www.rfc-editor.org/rfc/rfc9002#section-7.6.2>.
        // When persistent congestion is declared, the sender's congestion
        // window MUST be reduced to the minimum congestion window.
        if is_persistent_congestion {
            self.recovery_epoch_start = None;
            self.w_max = self.cwnd as f64;
            self.ssthresh = self
                .config
                .min_congestion_window
                .max((self.cwnd as f64 * self.config.beta) as u64);
            self.cwnd_inc = 0;
            self.cwnd = self.config.min_congestion_window;
        }
    }

    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    fn in_recovery(&self, sent_time: Instant) -> bool {
        self.recovery_epoch_start.map_or(false, |t| sent_time <= t)
    }

    fn congestion_window(&self) -> u64 {
        self.cwnd.max(self.config.min_congestion_window)
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_congestion_window
    }

    fn minimal_window(&self) -> u64 {
        self.config.min_congestion_window
    }

    fn stats(&self) -> &CongestionStats {
        &self.stats
    }

    fn pacing_rate(&self) -> Option<u64> {
        Some(self.pacing_rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet;

    #[test]
    fn cubic_calc_k() {
        let cubic_cfg = CubicConfig::default();
        let mut cubic = Cubic::new(cubic_cfg);
        let max_datagram_size = 1000;

        cubic.w_max = 10240.0;

        // Default settings.
        assert_eq!(
            cubic.minimal_window(),
            2 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64
        );
        assert_eq!(
            cubic.initial_window(),
            10 * crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64
        );

        // Valid cwnd.
        let cwnd = 7040;
        assert_eq!(cubic.cubic_k(cwnd, max_datagram_size), 2.0);

        // Invalid cwnd (larger than w_max).
        let cwnd = 20000;
        assert_eq!(cubic.cubic_k(cwnd, max_datagram_size), 0.0);
    }

    #[test]
    fn cubic_on_sent() {
        let cubic_cfg = CubicConfig::default();
        let mut cubic = Cubic::new(cubic_cfg);
        let now = Instant::now();
        let mut pkts: Vec<SentPacket> = Vec::new(); // let mut pkts_part3: Vec<SentPacket> = Vec::new();
        let bytes_lost = 0;
        let mut bytes_in_flight = 0;
        let pkt_size: u64 = 240;
        let n_pkts = 6;

        // Packets for sample 1.
        for n in 0..n_pkts {
            pkts.push(SentPacket {
                pkt_num: n,
                frames: Vec::new(),
                // Sent timestamp differs.
                time_sent: now + Duration::from_millis(10 * (n / (n_pkts / 2))),
                time_acked: Some(now + Duration::from_millis(20 + n)),
                time_lost: None,
                ack_eliciting: true,
                in_flight: true,
                has_data: false,
                sent_size: pkt_size as usize,
                rate_sample_state: Default::default(),
                ..SentPacket::default()
            });
        }

        for i in 0..(n_pkts / 2) {
            bytes_in_flight += pkt_size;
            cubic.on_sent(now, &mut pkts[i as usize], bytes_in_flight);
        }
        assert_eq!(cubic.last_sent_time.unwrap(), now);
        assert_eq!(cubic.in_slow_start(), true);
        assert_eq!(
            cubic.stats().bytes_sent_in_slow_start,
            n_pkts / 2 * pkt_size
        );
        assert_eq!(cubic.stats().bytes_sent_in_total, n_pkts / 2 * pkt_size);
        assert_eq!(cubic.stats().bytes_in_flight, n_pkts / 2 * pkt_size);

        // Assume all sent packets are acked, and recovery epoch starts.
        bytes_in_flight = 0;
        cubic.recovery_epoch_start = Some(now + Duration::from_millis(5));

        for i in (n_pkts / 2)..n_pkts {
            cubic.on_sent(now, &mut pkts[i as usize], bytes_in_flight);
            bytes_in_flight += pkt_size;
        }

        assert_eq!(
            cubic.last_sent_time.unwrap(),
            now + Duration::from_millis(10)
        );
        assert_eq!(cubic.in_slow_start(), true);
        assert_eq!(cubic.stats().bytes_sent_in_slow_start, n_pkts * pkt_size);
        assert_eq!(cubic.stats().bytes_sent_in_total, n_pkts * pkt_size);
        // recovery_epoch_start would be delayed to follow better cubic curve.
        assert_eq!(
            cubic.recovery_epoch_start,
            Some(now + Duration::from_millis(5) + Duration::from_millis(10))
        );
    }

    #[test]
    fn cubic_ack() {
        let cubic_cfg = CubicConfig::default();
        let mut cubic = Cubic::new(cubic_cfg);
        let now = Instant::now();
        let mut pkts: Vec<SentPacket> = Vec::new(); // let mut pkts_part3: Vec<SentPacket> = Vec::new();
        let rtt = RttEstimator::new(Duration::from_millis(20));
        let bytes_lost = 0;
        let pkt_size: u64 = 240;
        let n_pkts = 6;

        // Packets for sample 1.
        for n in 0..n_pkts {
            pkts.push(SentPacket {
                pkt_num: n,
                frames: Vec::new(),
                // Sent timestamp differs.
                time_sent: now + Duration::from_millis(n),
                time_acked: Some(now + Duration::from_millis(20)),
                time_lost: None,
                ack_eliciting: true,
                in_flight: true,
                has_data: false,
                sent_size: pkt_size as usize,
                rate_sample_state: Default::default(),
                ..SentPacket::default()
            });
        }

        // In slow start.
        let mut time_acked = now + Duration::from_millis(20);
        let mut cwnd = cubic.congestion_window();
        cubic.begin_ack(time_acked, pkt_size);
        for i in 0..(n_pkts - 3) {
            cubic.on_ack(&mut pkts[i as usize], time_acked, false, &rtt, 0);
        }
        cubic.end_ack();
        assert_eq!(cubic.hystart.has_exited(), false);
        assert_eq!(cubic.in_slow_start(), true);
        assert_eq!(cubic.congestion_window(), cwnd + (n_pkts - 3) * pkt_size);

        // Congestion event.
        cwnd = cubic.congestion_window();
        cubic.on_congestion_event(time_acked, &pkts[(n_pkts - 3) as usize], false, pkt_size, 0);
        assert_eq!(cubic.w_max, cwnd as f64);
        assert_eq!(cubic.ssthresh, (cwnd as f64 * cubic.config.beta) as u64);
        assert_eq!(cubic.cwnd, cubic.ssthresh);

        cwnd = cubic.congestion_window();
        pkts[(n_pkts - 2) as usize].time_sent = time_acked + Duration::from_millis(5);
        cubic.on_congestion_event(
            time_acked + Duration::from_millis(20),
            &pkts[(n_pkts - 2) as usize],
            false,
            pkt_size,
            0,
        );
        assert_eq!(cubic.w_max, cwnd as f64 * (1.0 + cubic.config.beta) / 2.0);
        assert_eq!(cubic.ssthresh, (cwnd as f64 * cubic.config.beta) as u64);
        assert_eq!(cubic.cwnd, cubic.ssthresh);

        // In congestion avoidance.
        assert_eq!(cubic.in_slow_start(), false);
        assert_eq!(cubic.hystart.has_exited(), true);
        pkts[(n_pkts - 1) as usize].time_sent = time_acked + Duration::from_millis(25);
        time_acked += Duration::from_millis(30);
        cubic.begin_ack(time_acked, 0);
        cubic.on_ack(&mut pkts[(n_pkts - 1) as usize], time_acked, false, &rtt, 0);
        cubic.end_ack();
        assert!(cubic.cwnd >= cubic.ssthresh);
    }

    #[test]
    fn cubic_in_recovery() {
        let cubic_cfg = CubicConfig::default();
        let mut cubic = Cubic::new(cubic_cfg);
        let now = Instant::now();

        cubic.recovery_epoch_start = Some(now + Duration::from_millis(10));
        assert_eq!(cubic.in_recovery(now), true);
        assert_eq!(cubic.in_recovery(now + Duration::from_millis(15)), false);
    }

    #[test]
    fn cubic_new_config() {
        let max_datagram_size: u64 = 1000;
        let min_cwnd: u64 = 4 * max_datagram_size;
        let initial_cwnd: u64 = 10 * max_datagram_size;
        let mut cubic_config = CubicConfig::default();

        cubic_config.set_c(0.7);
        assert_eq!(cubic_config.c, 0.7);

        cubic_config.set_beta(0.4);
        assert_eq!(cubic_config.beta, 0.4);

        cubic_config.enable_hystart(true);
        assert_eq!(cubic_config.hystart_enabled, true);

        cubic_config.enable_fast_convergence(true);
        assert_eq!(cubic_config.fast_convergence_enabled, true);

        cubic_config.set_initial_congestion_window(initial_cwnd);
        assert_eq!(cubic_config.initial_congestion_window, initial_cwnd);

        cubic_config.set_min_congestion_window(min_cwnd);
        assert_eq!(cubic_config.min_congestion_window, min_cwnd);

        cubic_config.set_max_datagram_size(max_datagram_size);
        assert_eq!(cubic_config.max_datagram_size, max_datagram_size);
    }
}
