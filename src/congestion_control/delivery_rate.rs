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

//! A generic algorithm for a transport protocol sender to estimate the current
//! delivery rate of its data on the fly.
//!
//! See
//! <https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02>.

use std::time::Duration;
use std::time::Instant;

use crate::connection::space::AckedPacket;
use crate::connection::space::{RateSamplePacketState, SentPacket};

/// Rate sample output.
///
/// See
/// <https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02#section-3.1.3>.
#[derive(Debug, Default)]
struct RateSample {
    /// rs.delivery_rate: The delivery rate sample (in most cases rs.delivered / rs.interval).
    delivery_rate: u64,

    /// rs.is_app_limited: The P.is_app_limited from the most recent packet delivered;
    /// indicates whether the rate sample is application-limited.
    is_app_limited: bool,

    /// rs.interval: The length of the sampling interval.
    interval: Duration,

    /// rs.delivered: The amount of data marked as delivered over the sampling interval.
    delivered: u64,

    /// rs.prior_delivered: The P.delivered count from the most recent packet delivered.
    prior_delivered: u64,

    /// rs.prior_time: The P.delivered_time from the most recent packet delivered.
    prior_time: Option<Instant>,

    /// rs.send_elapsed: Send time interval calculated from the most recent packet delivered.
    send_elapsed: Duration,

    /// rs.ack_elapsed: ACK time interval calculated from the most recent packet delivered.
    ack_elapsed: Duration,

    /// sample rtt.
    rtt: Duration,
}

/// Delivery rate estimator.
///
/// <https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02#section-3.1.1>.
#[derive(Debug)]
pub struct DeliveryRateEstimator {
    /// C.delivered: The total amount of data (measured in octets or in packets) delivered
    /// so far over the lifetime of the transport connection. This does not include pure ACK packets.
    delivered: u64,

    /// C.delivered_time: The wall clock time when C.delivered was last updated.
    delivered_time: Instant,

    /// C.first_sent_time: If packets are in flight, then this holds the send time of the packet that
    /// was most recently marked as delivered. Else, if the connection was recently idle, then this
    /// holds the send time of most recently sent packet.
    first_sent_time: Instant,

    /// C.app_limited: The index of the last transmitted packet marked as application-limited,
    /// or 0 if the connection is not currently application-limited.
    last_app_limited_pkt_num: u64,

    /// Record largest acked packet number to determine if app-limited state exits.
    largest_acked_pkt_num: u64,

    /// The last sent packet number.
    /// If application-limited occurs, it will be the end of last_app_limited_pkt_num.
    last_sent_pkt_num: u64,

    /// Rate sample.
    rate_sample: RateSample,
}

impl DeliveryRateEstimator {
    /// Upon each packet transmission.
    /// See <https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02#section-3.2>.
    pub fn on_packet_sent(
        &mut self,
        packet: &mut SentPacket,
        bytes_in_flight: u64,
        bytes_lost: u64,
    ) {
        // no packets in flight yet?
        if bytes_in_flight == 0 {
            self.first_sent_time = packet.time_sent;
            self.delivered_time = packet.time_sent;
        }

        packet.rate_sample_state.first_sent_time = Some(self.first_sent_time);
        packet.rate_sample_state.delivered_time = Some(self.delivered_time);
        packet.rate_sample_state.delivered = self.delivered;
        packet.rate_sample_state.is_app_limited = self.is_app_limited();
        packet.rate_sample_state.tx_in_flight = bytes_in_flight;
        packet.rate_sample_state.lost = bytes_lost;

        self.last_sent_pkt_num = packet.pkt_num;
    }

    /// Update rate sampler (rs) when a packet is SACKed or ACKed.
    /// See <https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02#section-3.3>.
    pub fn update_rate_sample(&mut self, packet: &mut SentPacket) {
        if packet.rate_sample_state.delivered_time.is_none() || packet.time_acked.is_none() {
            // Packet already SACKed or packet not acked
            return;
        }

        self.delivered = self.delivered.saturating_add(packet.sent_size as u64);
        // note: Update rate sample after P.time_acked got update. The default Instant::now() is
        // not accurate for estimating ack_elapsed.
        self.delivered_time = packet.time_acked.unwrap_or(Instant::now());

        // Update info using the newest packet:
        if self.rate_sample.prior_time.is_none()
            || packet.rate_sample_state.delivered > self.rate_sample.prior_delivered
        {
            self.rate_sample.prior_delivered = packet.rate_sample_state.delivered;
            self.rate_sample.prior_time = packet.rate_sample_state.delivered_time;
            self.rate_sample.is_app_limited = packet.rate_sample_state.is_app_limited;
            self.rate_sample.send_elapsed = packet.time_sent.saturating_duration_since(
                packet
                    .rate_sample_state
                    .first_sent_time
                    .unwrap_or(packet.time_sent),
            );
            self.rate_sample.ack_elapsed = self.delivered_time.saturating_duration_since(
                packet
                    .rate_sample_state
                    .delivered_time
                    .unwrap_or(packet.time_sent),
            );
            self.rate_sample.rtt = self
                .delivered_time
                .saturating_duration_since(packet.time_sent);
            self.first_sent_time = packet.time_sent;
        }

        self.rate_sample.delivered = self
            .delivered
            .saturating_sub(self.rate_sample.prior_delivered);

        // Mark the packet as delivered once it's SACKed to
        // avoid being used again when it's cumulatively acked.
        packet.rate_sample_state.delivered_time = None;

        self.largest_acked_pkt_num = packet.pkt_num.max(self.largest_acked_pkt_num);
    }

    /// Upon receiving ACK, fill in delivery rate sample rs.
    /// See <https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02#section-3.3>'
    pub fn generate_rate_sample(&mut self) {
        // For each newly SACKed or ACKed packet P,
        //     `UpdateRateSample(P, rs)`
        // It's done before generate_rate_sample is called.

        // Clear app-limited field if bubble is ACKed and gone.
        if self.is_app_limited() && self.largest_acked_pkt_num > self.last_app_limited_pkt_num {
            self.set_app_limited(false);
        }

        // Nothing delivered on this ACK.
        if self.rate_sample.prior_time.is_none() {
            return;
        }

        // Use the longer of the send_elapsed and ack_elapsed.
        self.rate_sample.interval = self
            .rate_sample
            .send_elapsed
            .max(self.rate_sample.ack_elapsed);

        self.rate_sample.delivered = self
            .delivered
            .saturating_sub(self.rate_sample.prior_delivered);

        if self.rate_sample.interval.is_zero() {
            return;
        }

        self.rate_sample.delivery_rate = self.rate_sample.delivered * 1_000_000_u64
            / self.rate_sample.interval.as_micros() as u64;
    }

    /// Set app limited status and record the latest packet num as end of app limited mode.
    pub fn set_app_limited(&mut self, is_app_limited: bool) {
        self.last_app_limited_pkt_num = if is_app_limited {
            self.last_sent_pkt_num.max(1)
        } else {
            0
        }
    }

    /// Check if application limited.
    /// See <https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02#section-3.4>.
    pub fn is_app_limited(&self) -> bool {
        self.last_app_limited_pkt_num != 0
    }

    /// C.delivered.
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// rs.delivered.
    pub fn sample_delivered(&self) -> u64 {
        self.rate_sample.delivered
    }

    /// rs.prior_delivered.
    pub fn sample_prior_delivered(&self) -> u64 {
        self.rate_sample.prior_delivered
    }

    /// Delivery rate.
    pub fn delivery_rate(&self) -> u64 {
        self.rate_sample.delivery_rate
    }

    /// Get rate sample rtt.
    pub fn sample_rtt(&self) -> Duration {
        self.rate_sample.rtt
    }

    /// Check whether the current rate sample is application limited.
    pub fn is_sample_app_limited(&self) -> bool {
        self.rate_sample.is_app_limited
    }
}

impl Default for DeliveryRateEstimator {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            delivered: 0,
            delivered_time: now,
            first_sent_time: now,
            last_app_limited_pkt_num: 0,
            largest_acked_pkt_num: 0,
            last_sent_pkt_num: 0,
            rate_sample: RateSample::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // todo: add unit test cases
}
