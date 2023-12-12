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

#![allow(unused_variables)]

use core::str::FromStr;
use std::any::Any;
use std::fmt;
use std::time::Instant;

use crate::connection::rtt::RttEstimator;
use crate::connection::space::SentPacket;
use crate::Error;
use crate::RecoveryConfig;
use crate::Result;
pub use bbr::Bbr;
pub use bbr::BbrConfig;
pub use bbr3::Bbr3;
pub use bbr3::Bbr3Config;
pub use copa::Copa;
pub use copa::CopaConfig;
pub use cubic::Cubic;
pub use cubic::CubicConfig;
pub use hystart_plus_plus::HystartPlusPlus;

/// Available congestion control algorithm
#[repr(C)]
#[derive(Eq, PartialEq, Debug, Clone, Copy, Default)]
pub enum CongestionControlAlgorithm {
    /// CUBIC uses a cubic function instead of a linear window increase function
    /// of the current TCP standards to improve scalability and stability under
    /// fast and long-distance networks..
    #[default]
    Cubic,

    /// BBR uses recent measurements of a transport connection's delivery rate,
    /// round-trip time, and packet loss rate to build an explicit model of the
    /// network path. The model is then used to control data transmission speed
    /// and the maximum volume of data allowed in flight in the network at any
    /// time.
    Bbr,

    /// BBRv3 is the latest version of BBR, including various fixes and
    /// algorithm updates that reduce packet re-transmit rate and slightly
    /// improve latency. (Experimental)
    Bbr3,

    /// COPA is a tunable delay-based congestion control algorithm. COPA is
    /// based on an objective function where the trade-off between throughput
    /// and delay can be configured via a user-specified parameter.
    /// (Experimental)
    Copa,
}

impl FromStr for CongestionControlAlgorithm {
    type Err = Error;

    fn from_str(algor: &str) -> Result<CongestionControlAlgorithm> {
        if algor.eq_ignore_ascii_case("cubic") {
            Ok(CongestionControlAlgorithm::Cubic)
        } else if algor.eq_ignore_ascii_case("bbr") {
            Ok(CongestionControlAlgorithm::Bbr)
        } else if algor.eq_ignore_ascii_case("bbr3") {
            Ok(CongestionControlAlgorithm::Bbr3)
        } else if algor.eq_ignore_ascii_case("copa") {
            Ok(CongestionControlAlgorithm::Copa)
        } else {
            Err(Error::InvalidConfig("unknown".into()))
        }
    }
}

/// Congestion control statistics.
#[derive(Debug, Default, Clone)]
pub struct CongestionStats {
    /// Bytes in flight.
    pub bytes_in_flight: u64,

    /// Total bytes sent in slow start.
    pub bytes_sent_in_slow_start: u64,

    /// Total bytes acked in slow start.
    pub bytes_acked_in_slow_start: u64,

    /// Total bytes lost in slow start.
    pub bytes_lost_in_slow_start: u64,

    /// Total bytes sent.
    pub bytes_sent_in_total: u64,

    /// Total bytes acked.
    pub bytes_acked_in_total: u64,

    /// Total bytes lost.
    pub bytes_lost_in_total: u64,
}

/// Congestion control interfaces shared by different algorithms.
pub trait CongestionController {
    /// Name of congestion control algorithm.
    fn name(&self) -> &str;

    /// Callback after packet was sent out.
    fn on_sent(&mut self, now: Instant, packet: &mut SentPacket, bytes_in_flight: u64);

    /// Callback for ack packets preprocessing.
    fn begin_ack(&mut self, now: Instant, bytes_in_flight: u64) {}

    /// Callback for processing each ack packet.
    fn on_ack(
        &mut self,
        packet: &mut SentPacket,
        now: Instant,
        app_limited: bool,
        rtt: &RttEstimator,
        bytes_in_flight: u64,
    ) {
    }

    /// Callback for Updating states after all ack packets are processed.
    fn end_ack(&mut self) {}

    /// Congestion event.
    fn on_congestion_event(
        &mut self,
        now: Instant,
        packet: &SentPacket,
        is_persistent_congestion: bool,
        lost_bytes: u64,
        bytes_in_flight: u64,
    ) {
    }

    /// Check if in slow start.
    fn in_slow_start(&self) -> bool {
        false
    }

    /// Check if in recovery mode.
    fn in_recovery(&self, sent_time: Instant) -> bool {
        false
    }

    /// Current congestion window.
    fn congestion_window(&self) -> u64;

    /// Current pacing rate estimated by Congestion Control Algorithm (CCA).
    /// If CCA does not estimate pacing rate, return None.
    fn pacing_rate(&self) -> Option<u64> {
        None
    }

    /// Initial congestion window.
    fn initial_window(&self) -> u64;

    /// Minimal congestion window.
    fn minimal_window(&self) -> u64;

    /// Congestion stats.
    fn stats(&self) -> &CongestionStats;
}

impl fmt::Debug for dyn CongestionController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "congestion controller.")
    }
}

/// Build a congestion controller.
pub fn build_congestion_controller(conf: &RecoveryConfig) -> Box<dyn CongestionController> {
    let max_datagram_size: u64 = conf.max_datagram_size as u64;
    let min_cwnd = conf.min_congestion_window.saturating_mul(max_datagram_size);
    let initial_cwnd = conf
        .initial_congestion_window
        .saturating_mul(max_datagram_size);

    match conf.congestion_control_algorithm {
        CongestionControlAlgorithm::Cubic => Box::new(Cubic::new(CubicConfig::new(
            min_cwnd,
            initial_cwnd,
            Some(conf.initial_rtt),
            max_datagram_size,
        ))),
        CongestionControlAlgorithm::Bbr => Box::new(Bbr::new(BbrConfig::new(
            min_cwnd,
            initial_cwnd,
            Some(conf.initial_rtt),
            max_datagram_size,
        ))),
        CongestionControlAlgorithm::Bbr3 => Box::new(Bbr3::new(Bbr3Config::new(
            min_cwnd,
            initial_cwnd,
            Some(conf.initial_rtt),
            max_datagram_size,
        ))),
        CongestionControlAlgorithm::Copa => Box::new(Copa::new(CopaConfig::new(
            min_cwnd,
            initial_cwnd,
            Some(conf.initial_rtt),
            max_datagram_size,
        ))),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn congestion_control_name() {
        use super::*;

        let cases = [
            ("cubic", Ok(CongestionControlAlgorithm::Cubic)),
            ("Cubic", Ok(CongestionControlAlgorithm::Cubic)),
            ("CUBIC", Ok(CongestionControlAlgorithm::Cubic)),
            ("bbr", Ok(CongestionControlAlgorithm::Bbr)),
            ("Bbr", Ok(CongestionControlAlgorithm::Bbr)),
            ("BBR", Ok(CongestionControlAlgorithm::Bbr)),
            ("bbr3", Ok(CongestionControlAlgorithm::Bbr3)),
            ("Bbr3", Ok(CongestionControlAlgorithm::Bbr3)),
            ("BBR3", Ok(CongestionControlAlgorithm::Bbr3)),
            ("copa", Ok(CongestionControlAlgorithm::Copa)),
            ("Copa", Ok(CongestionControlAlgorithm::Copa)),
            ("COPA", Ok(CongestionControlAlgorithm::Copa)),
            ("cubci", Err(Error::InvalidConfig("unknown".into()))),
        ];

        for (name, algor) in cases {
            assert_eq!(CongestionControlAlgorithm::from_str(name), algor);
        }
    }
}

#[path = "copa/copa.rs"]
mod copa;

#[path = "bbr/bbr.rs"]
mod bbr;

#[path = "bbr3/bbr3.rs"]
mod bbr3;

mod cubic;
mod delivery_rate;
mod hystart_plus_plus;
mod minmax;
mod pacing;
