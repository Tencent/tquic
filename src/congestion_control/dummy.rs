// Copyright (c) 2024 The TQUIC Authors.
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

#![allow(unused_variables)]

use std::time::Instant;

use super::CongestionController;
use super::CongestionStats;
use crate::connection::rtt::RttEstimator;
use crate::connection::space::SentPacket;

/// Dummy is a simple congestion controller with a static congestion window.
/// It is intended to be used for testing and experiments.
#[derive(Debug)]
pub struct Dummy {
    /// Congestion window in bytes.
    cwnd: u64,

    /// Congestion statistics.
    stats: CongestionStats,
}

impl Dummy {
    pub fn new(initial_cwnd: u64) -> Self {
        Self {
            cwnd: initial_cwnd,
            stats: Default::default(),
        }
    }
}

impl CongestionController for Dummy {
    fn name(&self) -> &str {
        "DUMMY"
    }

    fn on_sent(&mut self, now: Instant, packet: &mut SentPacket, bytes_in_flight: u64) {
        let sent_bytes = packet.sent_size as u64;
        self.stats.bytes_in_flight = bytes_in_flight;
        self.stats.bytes_sent_in_total = self.stats.bytes_sent_in_total.saturating_add(sent_bytes);
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
        let acked_bytes = packet.sent_size as u64;
        self.stats.bytes_in_flight = bytes_in_flight;
        self.stats.bytes_acked_in_total =
            self.stats.bytes_acked_in_total.saturating_add(acked_bytes);
    }

    fn end_ack(&mut self) {
        // Do nothing.
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        packet: &SentPacket,
        is_persistent_congestion: bool,
        lost_bytes: u64,
        bytes_in_flight: u64,
    ) {
        self.stats.bytes_lost_in_total = self.stats.bytes_lost_in_total.saturating_add(lost_bytes);
        self.stats.bytes_in_flight = bytes_in_flight;
    }

    fn in_slow_start(&self) -> bool {
        false
    }

    fn in_recovery(&self, sent_time: Instant) -> bool {
        false
    }

    fn congestion_window(&self) -> u64 {
        self.cwnd
    }

    fn initial_window(&self) -> u64 {
        self.cwnd
    }

    fn minimal_window(&self) -> u64 {
        self.cwnd
    }

    fn stats(&self) -> &CongestionStats {
        &self.stats
    }

    fn pacing_rate(&self) -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn dummy_init() {
        let d = Dummy::new(1200 * 10);
        assert_eq!(d.name(), "DUMMY");
        assert_eq!(d.congestion_window(), 1200 * 10);
        assert_eq!(d.initial_window(), 1200 * 10);
        assert_eq!(d.minimal_window(), 1200 * 10);

        assert_eq!(d.in_slow_start(), false);
        assert_eq!(d.in_recovery(Instant::now()), false);
        assert_eq!(d.stats().bytes_in_flight, 0);
        assert_eq!(d.pacing_rate(), None);
    }

    #[test]
    fn dummy_stats() {
        let mut d = Dummy::new(1200 * 10);
        let rtt = Duration::from_millis(100);
        let rtt_estimator = RttEstimator::new(rtt);
        let now = Instant::now();

        // Sent and acked a packet
        let mut pkt = SentPacket {
            pkt_num: 0,
            ack_eliciting: true,
            in_flight: true,
            sent_size: 1200,
            ..SentPacket::default()
        };
        d.on_sent(now, &mut pkt, 1200);
        assert_eq!(d.stats().bytes_in_flight, 1200);
        assert_eq!(d.stats().bytes_sent_in_total, 1200);

        let now = now + rtt;
        d.begin_ack(now, 1200);
        d.on_ack(&mut pkt, now, true, &rtt_estimator, 0);
        d.end_ack();
        assert_eq!(d.stats().bytes_in_flight, 0);
        assert_eq!(d.stats().bytes_acked_in_total, 1200);

        // Sent and lost a packet
        let mut pkt = SentPacket {
            pkt_num: 0,
            ack_eliciting: true,
            in_flight: true,
            sent_size: 1400,
            ..SentPacket::default()
        };
        d.on_sent(now, &mut pkt, 1400);
        assert_eq!(d.stats().bytes_in_flight, 1400);
        assert_eq!(d.stats().bytes_sent_in_total, 2600);

        d.on_congestion_event(now, &pkt, false, 1400, 0);
        assert_eq!(d.stats().bytes_in_flight, 0);
        assert_eq!(d.stats().bytes_lost_in_total, 1400);
    }
}
