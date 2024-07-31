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

use std::cmp;
use std::time::Duration;

use crate::TIMER_GRANULARITY;

/// RTT estimation for a network path
/// See RFC 9001 Section 5
pub struct RttEstimator {
    /// The most recent RTT sample.
    latest_rtt: Duration,

    /// The smoothed RTT of the path is an exponentially weighted moving average
    /// of an endpoint's RTT samples
    smoothed_rtt: Option<Duration>,

    /// The RTT variance estimates the variation in the RTT samples using a
    /// mean variation
    rttvar: Duration,

    /// The minimum RTT observed on the path, ignoring ack delay.
    /// It is used by loss detection to reject implausibly small RTT samples.
    min_rtt: Duration,

    /// The maximum RTT observed on the path, ignoring ack delay.
    max_rtt: Duration,
}

/// An statistical description of the network path's RTT
impl RttEstimator {
    pub fn new(initial_rtt: Duration) -> Self {
        Self {
            latest_rtt: initial_rtt,
            smoothed_rtt: None,
            rttvar: initial_rtt / 2,
            min_rtt: initial_rtt,
            max_rtt: initial_rtt,
        }
    }

    /// Return the current best RTT estimation.
    pub fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(self.latest_rtt)
    }

    /// Return the latest rtt sample
    pub fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }

    /// Return the Minimum RTT observed so far for this estimator.
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// Return the variation in the RTT samples using a mean variation.
    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    /// Return the Maximum RTT observed so far for this estimator.
    pub fn max_rtt(&self) -> Duration {
        self.max_rtt
    }

    /// Return the PTO computed as described in RFC 9002 Section 6.2.1
    pub fn pto_base(&self) -> Duration {
        self.smoothed_rtt() + cmp::max(4 * self.rttvar, TIMER_GRANULARITY)
    }

    /// Try to set the initial RTT if no RTT samples have been updated.
    ///
    /// The API is generally used in the following scenarios:
    /// - A connection MAY use the delay between sending a PATH_CHALLENGE and
    ///   receiving a PATH_RESPONSE to set the initial RTT for a new path, but the
    ///   delay SHOULD NOT be considered an RTT sample.
    /// - Resumed connections over the same network MAY use the previous connection's
    ///   final smoothed RTT value as the resumed connection's initial RTT.
    pub fn try_set_init_rtt(&mut self, init_rtt: Duration) {
        // Only set init_rtt when no rtt sample.
        if self.smoothed_rtt.is_some() {
            return;
        }

        self.latest_rtt = init_rtt;
        self.smoothed_rtt = None;
        self.rttvar = init_rtt / 2;
        self.min_rtt = init_rtt;
        self.max_rtt = init_rtt;
    }

    /// Update estimator with the given RTT sample
    pub fn update(&mut self, ack_delay: Duration, rtt: Duration) {
        self.latest_rtt = rtt;
        self.min_rtt = cmp::min(self.min_rtt, self.latest_rtt);
        self.max_rtt = cmp::max(self.max_rtt, self.latest_rtt);

        if let Some(smoothed_rtt) = self.smoothed_rtt {
            // The endpoint MUST NOT subtract the acknowledgment delay from the
            // RTT sample if the resulting value is smaller than the min_rtt.
            let adjusted_rtt = if self.min_rtt + ack_delay <= self.latest_rtt {
                self.latest_rtt - ack_delay
            } else {
                self.latest_rtt
            };

            let var_sample = if smoothed_rtt > adjusted_rtt {
                smoothed_rtt - adjusted_rtt
            } else {
                adjusted_rtt - smoothed_rtt
            };

            self.rttvar = (3 * self.rttvar + var_sample) / 4;
            self.smoothed_rtt = Some((7 * smoothed_rtt + adjusted_rtt) / 8);
        } else {
            self.smoothed_rtt = Some(self.latest_rtt);
            self.rttvar = self.latest_rtt / 2;
            self.min_rtt = self.latest_rtt;
            self.max_rtt = self.latest_rtt;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time;

    #[test]
    fn initial() {
        let initial_rtt = time::Duration::from_millis(200);
        let r = RttEstimator::new(initial_rtt);
        assert_eq!(r.latest_rtt(), initial_rtt);
        assert_eq!(r.min_rtt(), initial_rtt);
        assert_eq!(r.max_rtt(), initial_rtt);
        assert_eq!(r.rttvar(), initial_rtt / 2);
        assert_eq!(r.smoothed_rtt(), initial_rtt);
        assert_eq!(r.pto_base(), initial_rtt * 3);
    }

    #[test]
    fn update() {
        let initial_rtt = time::Duration::from_millis(200);
        let mut r = RttEstimator::new(initial_rtt);

        // Try set init_rtt before get RTT sample
        let initial_rtt_before_sample = time::Duration::from_millis(100);
        r.try_set_init_rtt(initial_rtt_before_sample);
        assert_eq!(r.latest_rtt(), initial_rtt_before_sample);
        assert_eq!(r.min_rtt(), initial_rtt_before_sample);
        assert_eq!(r.max_rtt(), initial_rtt_before_sample);
        assert_eq!(r.rttvar(), initial_rtt_before_sample / 2);
        assert_eq!(r.smoothed_rtt(), initial_rtt_before_sample);

        // First rtt sample
        let rtt_sample = time::Duration::from_millis(400);
        let ack_delay = time::Duration::from_millis(100);
        r.update(ack_delay, rtt_sample);
        assert_eq!(r.latest_rtt(), rtt_sample);
        assert_eq!(r.min_rtt(), rtt_sample);
        assert_eq!(r.max_rtt(), rtt_sample);
        assert_eq!(r.rttvar(), rtt_sample / 2);
        assert_eq!(r.smoothed_rtt(), rtt_sample);
        assert_eq!(r.pto_base(), rtt_sample * 3);

        // Try set init_rtt after get RTT sample
        let initial_rtt_after_sample = time::Duration::from_millis(300);
        r.try_set_init_rtt(initial_rtt_after_sample);
        assert_eq!(r.latest_rtt(), rtt_sample);
        assert_eq!(r.min_rtt(), rtt_sample);
        assert_eq!(r.max_rtt(), rtt_sample);
        assert_eq!(r.rttvar(), rtt_sample / 2);
        assert_eq!(r.smoothed_rtt(), rtt_sample);

        // Second rtt sample
        let rtt_sample = time::Duration::from_millis(700);
        let ack_delay = time::Duration::from_millis(100);
        r.update(ack_delay, rtt_sample);
        assert_eq!(r.latest_rtt(), rtt_sample);
        assert_eq!(r.min_rtt(), time::Duration::from_millis(400));
        assert_eq!(r.max_rtt(), time::Duration::from_millis(700));
        assert_eq!(r.rttvar(), time::Duration::from_millis(200));
        assert_eq!(r.smoothed_rtt(), time::Duration::from_millis(425));
        assert_eq!(r.pto_base(), time::Duration::from_millis(1225));

        // Third rtt sample
        let rtt_sample = time::Duration::from_millis(225);
        let ack_delay = time::Duration::from_millis(100);
        r.update(ack_delay, rtt_sample);
        assert_eq!(r.latest_rtt(), rtt_sample);
        assert_eq!(r.min_rtt(), time::Duration::from_millis(225));
        assert_eq!(r.max_rtt(), time::Duration::from_millis(700));
        assert_eq!(r.rttvar(), time::Duration::from_millis(200));
        assert_eq!(r.smoothed_rtt(), time::Duration::from_millis(400));
        assert_eq!(r.pto_base(), time::Duration::from_millis(1200));
    }
}
