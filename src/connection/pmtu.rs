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

use std::cmp;
use std::time;

/// The size of UDP payloads over IPv4 (1500-20-8)
const MAX_PACKET_SIZE_IPV4: usize = 1472;

/// The size of UDP payloads over IPv6 (1500-40-8)
const MAX_PACKET_SIZE_IPV6: usize = 1452;

/// MAX_PROBES represents the limit for the number of consecutive probe
/// attempts of any size.
const MAX_PROBE_COUNT: u8 = 3;

/// A simple implementation for Packetization Layer Path MTU Discovery for
/// Datagram Transports.
/// See RFC 9000 Section 14.3 and RFC 8899
#[derive(Default)]
pub(super) struct Dplpmtud {
    /// Whether a new probe packet should be sent.
    should_probe: bool,

    /// The current path MTU.
    current_size: usize,

    /// The size of the current probe packet, which is awaiting confirmation by
    /// an acknowledgment.
    probe_size: Option<usize>,

    /// The number of successive unsuccessful probe packets that have been sent.
    /// Each time a probe packet is acknowledged, the value is set to zero.
    probe_count: u8,

    /// The size of last probe packet which is declared as lost.
    failed_size: usize,

    /// It corresponds to the maximum datagram size.
    max_pmtu: usize,

    /// Whether it is an IPv6 path.
    is_ipv6: bool,
}

impl Dplpmtud {
    pub(super) fn new(enable: bool, mut max_pmtu: usize, is_ipv6: bool) -> Self {
        if max_pmtu == crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE {
            max_pmtu = if is_ipv6 {
                MAX_PACKET_SIZE_IPV6
            } else {
                MAX_PACKET_SIZE_IPV4
            };
        }

        Self {
            should_probe: enable,
            current_size: crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE,
            probe_size: None,
            max_pmtu,
            is_ipv6,
            ..Self::default()
        }
    }

    /// Return whether a PMTU probe should be scheduled
    pub(super) fn should_probe(&self) -> bool {
        self.should_probe
    }

    /// Return the current size of probe packet
    pub(super) fn get_probe_size(&mut self, peer_max_udp_payload: usize) -> usize {
        if let Some(probe_size) = self.probe_size {
            return probe_size;
        }

        let probe_size = self.cal_probe_size(peer_max_udp_payload);
        self.probe_size = Some(probe_size);
        probe_size
    }

    /// Return the current validated PMTU
    pub(super) fn get_current_size(&self) -> usize {
        self.current_size
    }

    /// Handle sent event of PMTU probe
    pub(super) fn on_pmtu_probe_sent(&mut self, pkt_size: usize) {
        self.should_probe = false;
    }

    /// Handle acknowledgement of PMTU probe
    pub(super) fn on_pmtu_probe_acked(&mut self, pkt_size: usize, peer_max_udp_payload: usize) {
        self.current_size = cmp::max(self.current_size, pkt_size);
        self.probe_count = 0;
        self.probe_size = Some(self.cal_probe_size(peer_max_udp_payload));
        self.should_probe = !self.check_finish(peer_max_udp_payload);
    }

    /// Handle loss of PMTU probe
    pub(super) fn on_pmtu_probe_lost(&mut self, pkt_size: usize, peer_max_udp_payload: usize) {
        if Some(pkt_size) != self.probe_size {
            return;
        }

        self.probe_count += 1;
        if self.probe_count < MAX_PROBE_COUNT {
            self.should_probe = true;
            return;
        }

        self.failed_size = pkt_size;
        self.probe_size = Some(self.cal_probe_size(peer_max_udp_payload));
        self.probe_count = 0;
        self.should_probe = !self.check_finish(peer_max_udp_payload);
    }

    /// Calculate the size of probe packet
    fn cal_probe_size(&self, peer_max_udp_payload: usize) -> usize {
        let mtu_ceiling = self.cal_mtu_ceiling(peer_max_udp_payload);

        // Try the largest ethernet MTU immediately
        if self.failed_size == 0 && mtu_ceiling < 1500 {
            return mtu_ceiling;
        }

        // Pick the half-way point
        (self.current_size + mtu_ceiling) / 2
    }

    /// Calculate the upper limit of probe size
    fn cal_mtu_ceiling(&self, peer_max_udp_payload: usize) -> usize {
        let mut mtu_ceiling = if self.failed_size > 0 {
            self.failed_size
        } else {
            self.max_pmtu
        };
        if mtu_ceiling > peer_max_udp_payload {
            mtu_ceiling = peer_max_udp_payload;
        }
        mtu_ceiling
    }

    /// Check whether PMTU discovery should be stopped
    fn check_finish(&self, peer_max_udp_payload: usize) -> bool {
        let mtu_ceiling = self.cal_mtu_ceiling(peer_max_udp_payload);
        self.current_size >= mtu_ceiling || self.current_size as f64 / mtu_ceiling as f64 >= 0.99
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dplpmtud_default() {
        let d = Dplpmtud::new(false, 1500, true);
        assert_eq!(d.should_probe(), false);
        assert_eq!(d.get_current_size(), crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE);

        let mut d = Dplpmtud::new(true, 1500, false);
        let peer_max_udp_payload = 1400;
        assert_eq!(d.should_probe(), true);
        assert_eq!(d.get_current_size(), crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE);
        assert_eq!(d.get_probe_size(peer_max_udp_payload), peer_max_udp_payload);
    }

    #[test]
    fn dplpmtud_max() {
        let mut d = Dplpmtud::new(true, 1200, false);
        let peer_max_udp_payload = 60000;
        assert_eq!(d.should_probe(), true);

        // Fake sending a PMTU probe
        let probe_size = d.get_probe_size(peer_max_udp_payload);
        d.on_pmtu_probe_sent(probe_size);
        assert_eq!(d.should_probe(), false);

        // Fake receiving its acknowledgement
        d.on_pmtu_probe_acked(probe_size, peer_max_udp_payload);
        assert_eq!(d.get_current_size(), 1472);
        assert_eq!(d.should_probe(), false);
    }

    #[test]
    fn dplpmtud_min() {
        let mut d = Dplpmtud::new(true, 1200, true);
        let peer_max_udp_payload = 60000;
        assert_eq!(d.should_probe(), true);

        for i in 0..10 {
            let probe_size = d.get_probe_size(peer_max_udp_payload);

            // Fake failing to probe with size `probe_size`
            for i in 0..MAX_PROBE_COUNT {
                // Fake sending a PMTU probe
                d.on_pmtu_probe_sent(probe_size);
                // Fake lost the PMTU porbe
                d.on_pmtu_probe_lost(probe_size, peer_max_udp_payload);
            }
            assert_eq!(d.failed_size, probe_size);

            if !d.should_probe() {
                break;
            }
        }

        assert_eq!(d.get_current_size(), 1200);
        assert_eq!(d.should_probe(), false);
    }

    #[test]
    fn dplpmtud_mid() {
        let mut d = Dplpmtud::new(true, 1200, true);
        let peer_max_udp_payload = 60000;
        assert_eq!(d.should_probe(), true);

        let pmtu = 1350;
        for i in 0..10 {
            let probe_size = d.get_probe_size(peer_max_udp_payload);

            if probe_size > pmtu {
                for i in 0..MAX_PROBE_COUNT {
                    d.on_pmtu_probe_sent(probe_size);
                    d.on_pmtu_probe_lost(probe_size, peer_max_udp_payload);
                }
                assert_eq!(d.failed_size, probe_size);
            } else {
                d.on_pmtu_probe_sent(probe_size);
                d.on_pmtu_probe_acked(probe_size, peer_max_udp_payload);
                assert_eq!(d.get_current_size(), probe_size);
            }

            if !d.should_probe() {
                break;
            }
        }

        assert_eq!(d.get_current_size(), 1349);
        assert_eq!(d.should_probe(), false);
    }
}
