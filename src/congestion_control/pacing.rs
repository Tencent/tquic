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

use std::time::{Duration, Instant};

use crate::RecoveryConfig;

/// The pacing granurality in milliseconds
///
/// Packet is sendable if it can be sent out in a gralarity
/// from now, or it should be blocked
const PACING_GRANULARITY: Duration = Duration::from_millis(1);

/// The lower bound of burst packet number.
///
/// A lower bound is necessary to enable GSO and to avoid extremely small capacity.
const MIN_BURST_PACKET_NUM: u64 = 10;

/// The upper bound of burst packet number.
///
/// Used to restrict capacity. An extremely large capacity is meaningless.
const MAX_BURST_PACKET_NUM: u64 = 128;

/// A simple token-bucket pacer
///
/// See RFC 9002 Section 7.7
#[derive(Debug)]
pub struct Pacer {
    /// Enable pacing or not.
    enabled: bool,

    /// Bucket capacity (bytes). Bytes that could burst during a pacing granularity
    capacity: u64,

    /// available tokens, bytes
    tokens: u64,

    /// last congestion window, bytes
    last_cwnd: u64,

    /// last schedule time
    last_sched_time: Instant,

    /// Pacing granularity
    granularity: Duration,
}

impl Pacer {
    /// Generate a pacer (for each path)
    pub fn new(
        enabled: bool,
        srtt: Duration,
        cwnd: u64,
        mtu: u64,
        now: Instant,
        granularity: Duration,
    ) -> Self {
        let mut pacer = Pacer {
            enabled,
            capacity: 0,
            tokens: 0,
            last_cwnd: cwnd,
            last_sched_time: now,
            granularity,
        };
        pacer.update_capacity(cwnd, srtt, mtu);
        pacer.tokens = pacer.capacity;
        pacer
    }

    /// Build a pacer controller.
    pub fn build_pacer_controller(conf: &RecoveryConfig) -> Self {
        Pacer::new(
            true,
            conf.initial_rtt,
            conf.initial_congestion_window
                .saturating_mul(conf.max_datagram_size as u64),
            conf.max_datagram_size as u64,
            Instant::now(),
            conf.pacing_granularity,
        )
    }

    /// check whether pacing is enabled
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Consume tokens after a packet is actually sent.
    /// Called after schedule and send operations.
    pub fn on_sent(&mut self, bytes_sent: u64) {
        if self.enabled {
            self.tokens = self.tokens.saturating_sub(bytes_sent)
        }
    }

    /// Schedule and return the timestamp for the packet to send
    ///
    /// Return None if packet can be send immediately, or return
    /// scheduled timestamp if packet is supposed to wait.
    pub fn schedule(
        &mut self,
        bytes_to_send: u64,
        pacing_rate: u64,
        srtt: Duration,
        cwnd: u64,
        mtu: u64,
        now: Instant,
    ) -> Option<Instant> {
        if !self.enabled || srtt.is_zero() || cwnd == 0 || pacing_rate == 0 {
            return None;
        }

        // Update capacity and tokens if necessary
        if cwnd != self.last_cwnd {
            self.update_capacity(cwnd, srtt, mtu);
            self.tokens = self.capacity.min(self.tokens);
            self.last_cwnd = cwnd;
        }

        // If tokens are enough, no need to wait and update
        if self.tokens >= bytes_to_send {
            return None;
        }

        // Tokens are refilled at the rate of pacing_rate
        let elapsed = now.saturating_duration_since(self.last_sched_time);
        self.tokens = self
            .tokens
            .saturating_add((pacing_rate as u128 * elapsed.as_nanos() / 1_000_000_000) as u64)
            .min(self.capacity);
        self.last_sched_time = now;

        if bytes_to_send <= self.tokens {
            return None;
        }

        // If tokens are not enough, calculate the time to wait for enough tokens.
        let time_to_wait =
            bytes_to_send.saturating_sub(self.tokens) * 1_000_000_000 / pacing_rate.max(1);
        Some(self.last_sched_time + Duration::from_nanos(time_to_wait))
    }

    fn update_capacity(&mut self, cwnd: u64, srtt: Duration, mtu: u64) {
        // Note: the bound operation would limit the average pacing rate to
        //   [MIN_BURST_PACKET_NUM * mtu / srtt, MAX_BURST_PACKET_NUM * mtu / srtt]
        // the minimal pacing rate may be too large in some cases.
        let capacity =
            (cwnd as u128 * self.granularity.as_nanos() / srtt.as_nanos().max(1_000_000)) as u64;
        self.capacity = capacity.clamp(MIN_BURST_PACKET_NUM * mtu, MAX_BURST_PACKET_NUM * mtu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_new() {
        let srtt = Duration::from_millis(1);
        let mtu: u64 = 1500;
        let enabled: bool = true;
        let now = Instant::now();

        let cwnd: u64 = 20 * mtu;
        let p = Pacer::new(enabled, srtt, cwnd, mtu, now, PACING_GRANULARITY);
        assert!(p.enabled() == true);
        assert_eq!(p.capacity, p.tokens);
        assert_eq!(
            p.capacity,
            cwnd * PACING_GRANULARITY.as_nanos() as u64 / srtt.as_nanos() as u64
        );

        let cwnd: u64 = 1 * mtu;
        let p = Pacer::new(enabled, srtt, cwnd, mtu, now, PACING_GRANULARITY);
        assert!(p.enabled() == true);
        assert_eq!(p.capacity, p.tokens);
        assert_eq!(p.capacity, MIN_BURST_PACKET_NUM * mtu);

        let cwnd: u64 = 200 * mtu;
        let p = Pacer::new(enabled, srtt, cwnd, mtu, now, PACING_GRANULARITY);
        assert!(p.enabled() == true);
        assert_eq!(p.capacity, p.tokens);
        assert_eq!(p.capacity, MAX_BURST_PACKET_NUM * mtu);
    }

    #[test]
    fn pacer_disabled() {
        let srtt = Duration::from_millis(1);
        let mtu: u64 = 1500;
        let cwnd: u64 = 20 * 1500;
        let enabled: bool = false;
        let now = Instant::now();
        let bytes_to_send: u64 = 1000;
        let pacing_rate: u64 = 1000000;

        let mut p = Pacer::new(enabled, srtt, cwnd, mtu, now, PACING_GRANULARITY);

        assert_eq!(p.enabled(), false);
        assert_eq!(p.capacity, 20 * 1500);

        let next_sched_time = p.schedule(bytes_to_send, pacing_rate, srtt, cwnd, mtu, now);
        assert_eq!(next_sched_time, None);
        p.on_sent(bytes_to_send);
        assert_eq!(p.capacity, p.tokens);
    }

    #[test]
    fn pacer_schedule_and_send() {
        let srtt = Duration::from_millis(1);
        let mtu: u64 = 1000; // For convenience
        let cwnd: u64 = 10 * mtu;
        let enabled: bool = true;
        let now = Instant::now();
        let bytes_to_send = mtu;
        let pacing_rate: u64 = 1000000;

        // Abnormal input
        assert_eq!(
            Pacer::new(enabled, srtt, cwnd, mtu, now, PACING_GRANULARITY).schedule(
                bytes_to_send,
                pacing_rate,
                Duration::ZERO,
                cwnd,
                mtu,
                now
            ),
            None
        );
        assert_eq!(
            Pacer::new(enabled, srtt, cwnd, mtu, now, PACING_GRANULARITY).schedule(
                bytes_to_send,
                pacing_rate,
                srtt,
                0,
                mtu,
                now
            ),
            None
        );

        // Congestion window changes
        let mut p = Pacer::new(enabled, srtt, cwnd, mtu, now, PACING_GRANULARITY);
        assert_eq!(p.capacity, cwnd);
        assert_eq!(p.capacity, p.tokens);

        assert_eq!(
            p.schedule(bytes_to_send, pacing_rate, srtt, 2 * cwnd, mtu, now),
            None
        );
        assert_eq!(p.capacity, 2 * cwnd);
        assert_eq!(p.tokens, cwnd); // do not change tokens

        // Schedule and wait cases
        let mut p = Pacer::new(enabled, srtt, cwnd, mtu, now, PACING_GRANULARITY);
        assert_eq!(p.capacity, 10 * mtu);
        assert_eq!(p.tokens, 10 * mtu);

        let packet_num = p.capacity / mtu;
        for _ in 0..packet_num {
            assert_eq!(
                p.schedule(bytes_to_send, pacing_rate, srtt, cwnd, mtu, now),
                None
            );
            p.on_sent(mtu);
        }
        assert_eq!(p.tokens, 0);

        // Tokens ran out, further schedule leads to delay
        let time_expected_to_wait = (bytes_to_send) * 1_000_000 / pacing_rate;
        assert_eq!(
            p.schedule(bytes_to_send, pacing_rate, srtt, cwnd, mtu, now)
                .unwrap()
                .duration_since(now)
                .as_micros() as u64,
            time_expected_to_wait
        );

        // Wait for token refill and try to schedule again
        let time_to_refill_tokens_for_a_packet =
            (bytes_to_send - p.tokens) * 1_000_000 / pacing_rate;
        assert_eq!(
            p.schedule(
                bytes_to_send,
                pacing_rate,
                srtt,
                cwnd,
                mtu,
                now + Duration::from_micros(time_to_refill_tokens_for_a_packet)
            ),
            None
        );
        p.on_sent(bytes_to_send);
        assert_eq!(p.tokens, 0);
    }
}
