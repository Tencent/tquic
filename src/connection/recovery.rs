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
use std::collections::VecDeque;
use std::ops::Range;
use std::time;
use std::time::Duration;
use std::time::Instant;

use log::*;

use super::rtt::RttEstimator;
use super::space::AckedPacket;
use super::space::PacketNumSpace;
use super::space::PacketNumSpaceMap;
use super::space::SentPacket;
use super::space::SpaceId;
use super::space::SpaceId::*;
use super::Connection;
use super::HandshakeStatus;
use crate::congestion_control;
use crate::congestion_control::CongestionController;
use crate::congestion_control::Pacer;
use crate::connection::Timer;
use crate::frame;
use crate::qlog;
use crate::qlog::events::EventData;
use crate::ranges::RangeSet;
use crate::Error;
use crate::PathStats;
use crate::RecoveryConfig;
use crate::Result;
use crate::TIMER_GRANULARITY;

const INITIAL_PACKET_THRESHOLD: u64 = 3;

const INITIAL_TIME_THRESHOLD: f64 = 9.0 / 8.0;

const MAX_PTO_PROBES_COUNT: usize = 2;

/// An implementation of the loss detection mechanisms described in
/// RFC 9002 Section 6 and Appendix A.
pub struct Recovery {
    /// The maximum amount of time by which the receiver intends to delay
    /// acknowledgments for packets in the Application Data packet number space.
    /// It is used for PTO calculation.
    pub max_ack_delay: Duration,

    /// The validated maximum size of outgoing UDP payloads in bytes.
    pub max_datagram_size: usize,

    /// The endpoint do not backoff the first `pto_linear_factor` consecutive probe timeouts.
    pto_linear_factor: u64,

    /// Upper limit of probe timeout.
    max_pto: Duration,

    /// The number of times a PTO has been sent without receiving an
    /// acknowledgment. It is used for PTO calculation.
    pto_count: usize,

    /// Multi-modal timer used for loss detection. The duration of the timer is
    /// based on the timer's mode, which is set in the packet and timer events.
    loss_detection_timer: Option<Instant>,

    /// Maximum reordering in packets before packet threshold loss detection
    /// considers a packet lost.
    pub pkt_thresh: u64,

    /// Maximum reordering in time before time threshold loss detection
    /// considers a packet lost. Specified as an RTT multiplier.
    pub time_thresh: f64,

    /// The sum of the size in bytes of all sent packets that contain at least
    /// one ack-eliciting or PADDING frame and have not been acknowledged or
    /// declared lost. The size does not include IP or UDP overhead.
    pub bytes_in_flight: usize,

    /// Number of ack-eliciting packets in flight.
    pub ack_eliciting_in_flight: u64,

    /// RTT estimation for the corresponding path.
    pub rtt: RttEstimator,

    /// Congestion controller for the corresponding path.
    pub congestion: Box<dyn CongestionController>,

    /// Pacing.
    pub pacer: Pacer,

    /// Next pacer tick
    pub pacer_timer: Option<Instant>,

    /// Cache pkt size
    pub cache_pkt_size: usize,

    /// The time for last congestion window event
    last_cwnd_limited_time: Option<Instant>,

    /// Path level Statistics.
    pub stats: PathStats,

    /// It tracks the last metrics used for emitting qlog RecoveryMetricsUpdated
    /// event.
    last_metrics: RecoveryMetrics,

    /// Trace id.
    trace_id: String,
}

impl Recovery {
    pub(super) fn new(conf: &RecoveryConfig) -> Self {
        Recovery {
            max_ack_delay: conf.max_ack_delay,
            max_datagram_size: crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE,
            pto_linear_factor: conf.pto_linear_factor,
            max_pto: conf.max_pto,
            pto_count: 0,
            loss_detection_timer: None,
            pkt_thresh: INITIAL_PACKET_THRESHOLD,
            time_thresh: INITIAL_TIME_THRESHOLD,
            bytes_in_flight: 0,
            ack_eliciting_in_flight: 0,
            rtt: RttEstimator::new(conf.initial_rtt),
            congestion: congestion_control::build_congestion_controller(conf),
            pacer: Pacer::build_pacer_controller(conf),
            pacer_timer: None,
            cache_pkt_size: conf.max_datagram_size,
            last_cwnd_limited_time: None,
            stats: PathStats::default(),
            last_metrics: RecoveryMetrics::default(),
            trace_id: String::from(""),
        }
    }

    /// Set trace id.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.trace_id = trace_id.to_string();
    }

    /// Handle packet sent event.
    ///
    /// See RFC 9002 Section A.5. On Sending a Packet
    pub(super) fn on_packet_sent(
        &mut self,
        mut pkt: SentPacket,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        let in_flight = pkt.in_flight;
        let ack_eliciting = pkt.ack_eliciting;
        let sent_size = pkt.sent_size;

        pkt.time_sent = now;
        let space = match spaces.get_mut(space_id) {
            Some(space) => space,
            None => return,
        };
        if in_flight {
            // notify congestion controller of the sent event
            if space_id != SpaceId::Initial && space_id != SpaceId::Handshake {
                self.congestion
                    .on_sent(now, &mut pkt, self.bytes_in_flight as u64);
                trace!(
                    "now={:?} {} {} ON_SENT {:?} inflight={} cwnd={}",
                    now,
                    self.trace_id,
                    self.congestion.name(),
                    pkt,
                    self.bytes_in_flight,
                    self.congestion.congestion_window()
                );
            }
        }
        space.sent.push_back(pkt);

        // An endpoint that sends only non-ack-eliciting packets might not
        // receive an acknowledgment for a long period of time.
        // It should count the number of such packets so as to elicit an ACK
        // from the peer.
        if ack_eliciting {
            space.consecutive_non_ack_eliciting_sent = 0;
        } else {
            space.consecutive_non_ack_eliciting_sent += 1;
        }

        if in_flight {
            if ack_eliciting {
                space.time_of_last_sent_ack_eliciting_pkt = Some(now);
                space.loss_probes = space.loss_probes.saturating_sub(1);
                space.ack_eliciting_in_flight += 1;
                self.ack_eliciting_in_flight += 1;
            }

            space.bytes_in_flight += sent_size;
            self.bytes_in_flight += sent_size;
            self.cache_pkt_size = sent_size;

            self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
        }

        // Update pacing tokens number.
        self.pacer.on_sent(sent_size as u64);
    }

    /// Handle packet acknowledgment event.
    ///
    /// See RFC 9002 Section A.7. On Receiving an Acknowledgment.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn on_ack_received(
        &mut self,
        ranges: &RangeSet,
        ack_delay: u64,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        qlog: Option<&mut qlog::QlogWriter>,
        now: Instant,
    ) -> Result<(u64, u64)> {
        let space = spaces.get_mut(space_id).ok_or(Error::InternalError)?;

        // Update the largest packet number acknowledged in the space
        let largest_acked_pkt = ranges.max().unwrap();
        if space.largest_acked_pkt == u64::MAX {
            space.largest_acked_pkt = largest_acked_pkt;
        } else {
            space.largest_acked_pkt = cmp::max(space.largest_acked_pkt, largest_acked_pkt);
        }

        if space_id != SpaceId::Initial && space_id != SpaceId::Handshake {
            self.congestion.begin_ack(now, self.bytes_in_flight as u64);
        }
        trace!(
            "now={:?} {} {} BEGIN_ACK inflight={} cwnd={}",
            now,
            self.trace_id,
            self.congestion.name(),
            self.bytes_in_flight,
            self.congestion.congestion_window()
        );

        // Detect acked packets
        let mut newly_acked_pkts = Vec::<AckedPacket>::new();
        let rtt_sample = self.detect_acked_packets(ranges, space, &mut newly_acked_pkts, now);
        if newly_acked_pkts.is_empty() {
            return Ok((0, 0));
        }

        // Update RTT estimation
        // TODO: check ack_delay against amx_ack_delay
        if let Some(rtt) = rtt_sample {
            // When adjusting an RTT sample using peer-reported acknowledgment
            // delays, an endpoint:
            // - MAY ignore the acknowledgment delay for Initial packets, since
            // these acknowledgments are not delayed by the peer.
            // - SHOULD ignore the peer's max_ack_delay until the handshake is
            // confirmed.
            // - MUST use the lesser of the acknowledgment delay and the peer's
            // max_ack_delay after the handshake is confirmed;
            // See RFC 9000 Section 5.3
            let ack_delay = Duration::from_micros(ack_delay);
            if !rtt.is_zero() {
                self.rtt.update(ack_delay, rtt);
            }
        }

        // Detect lost packets
        let (lost_packets, lost_bytes) = self.detect_lost_packets(space, qlog, now);

        // Remove acked or lost packets from sent queue in batch.
        self.drain_sent_packets(space, now, self.rtt.smoothed_rtt());

        // Notify the congestion controller of acked event
        if space_id != SpaceId::Initial && space_id != SpaceId::Handshake {
            self.congestion.end_ack();
        }

        self.pto_count = 0;
        self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
        Ok((lost_packets, lost_bytes))
    }

    /// Detect acknowledged packets.
    ///
    /// It return the latest RTT sample, if any.
    fn detect_acked_packets(
        &mut self,
        ranges: &RangeSet,
        space: &mut PacketNumSpace,
        newly_acked: &mut Vec<AckedPacket>,
        now: Instant,
    ) -> Option<Duration> {
        let mut largest_newly_acked_pkt_num = 0;
        let mut largest_newly_acked_sent_time = now;
        let mut newly_ack_eliciting_pkt_acked = false;

        let mut idx = 0;
        'ranges_loop: for r in ranges.iter() {
            'sent_pkt_loop: while idx < space.sent.len() {
                let sent_pkt = space.sent.get_mut(idx).unwrap();
                // Find an unacked sent packet which matches the current ACK range.
                // Note: The packet numbers in ranges and space.sent are in ascending order.
                if sent_pkt.pkt_num < r.start || sent_pkt.time_acked.is_some() {
                    idx += 1;
                    continue 'sent_pkt_loop;
                }
                if sent_pkt.pkt_num >= r.end {
                    continue 'ranges_loop;
                }

                sent_pkt.time_acked = Some(now);
                // TODO: detect spurious retransmissions and increase the
                // packet or time reordering threshold

                // TODO: update rtt.

                largest_newly_acked_pkt_num = sent_pkt.pkt_num;
                largest_newly_acked_sent_time = sent_pkt.time_sent;
                if sent_pkt.ack_eliciting {
                    newly_ack_eliciting_pkt_acked = true
                }

                if sent_pkt.in_flight {
                    space.bytes_in_flight =
                        space.bytes_in_flight.saturating_sub(sent_pkt.sent_size);
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(sent_pkt.sent_size);

                    if sent_pkt.ack_eliciting {
                        space.ack_eliciting_in_flight =
                            space.ack_eliciting_in_flight.saturating_sub(1);
                        self.ack_eliciting_in_flight =
                            self.ack_eliciting_in_flight.saturating_sub(1);
                    }
                }

                // Process each acked packet in congestion controller and update delivery
                // rate sample.
                if space.id != SpaceId::Initial && space.id != SpaceId::Handshake {
                    self.congestion.on_ack(
                        sent_pkt,
                        now,
                        false,
                        &self.rtt,
                        self.bytes_in_flight as u64,
                    );
                }

                trace!(
                    "now={:?} {} {} ON_ACK {:?} inflight={} cwnd={}",
                    now,
                    self.trace_id,
                    self.congestion.name(),
                    sent_pkt,
                    self.bytes_in_flight,
                    self.congestion.congestion_window()
                );
                self.stat_acked_event(1, sent_pkt.sent_size as u64);

                space.acked.append(&mut sent_pkt.frames);
                newly_acked.push(AckedPacket {
                    pkt_num: sent_pkt.pkt_num,
                    time_sent: sent_pkt.time_sent,
                    rtt: now.saturating_duration_since(sent_pkt.time_sent),
                });

                // Process next sent packet.
                idx += 1;
                if idx == space.sent.len() {
                    break 'ranges_loop;
                }
            }
        }

        // An endpoint generates an RTT sample on receiving an ACK frame that
        // meets the following two conditions:
        // * the largest acknowledged packet number is newly acknowledged
        // * at least one of the newly acknowledged packets was ack-eliciting
        if largest_newly_acked_pkt_num == space.largest_acked_pkt && newly_ack_eliciting_pkt_acked {
            let latest_rtt = now.saturating_duration_since(largest_newly_acked_sent_time);
            Some(latest_rtt)
        } else {
            None
        }
    }

    /// Check whether in persistent congestion.
    ///
    /// When a sender establishes loss of all packets sent over a long enough duration,
    /// the network is considered to be experiencing persistent congestion.
    /// See https://www.rfc-editor.org/rfc/rfc9002.html#name-persistent-congestion
    fn in_persistent_congestion(&self) -> bool {
        // todo: Check whether in persistent congestion.
        false
    }

    /// Detect lost packets from the sent packets.
    ///
    /// It is called every time an ACK is received or the time threshold loss
    /// detection timer expires.
    /// See RFC 9002 Section A.10. Detecting Lost Packets
    fn detect_lost_packets(
        &mut self,
        space: &mut PacketNumSpace,
        mut qlog: Option<&mut qlog::QlogWriter>,
        now: Instant,
    ) -> (u64, u64) {
        space.loss_time = None;

        let mut lost_packets = 0;
        let mut lost_bytes = 0;
        let mut latest_lost_packet = None;

        let loss_delay =
            cmp::max(self.rtt.latest_rtt(), self.rtt.smoothed_rtt()).mul_f64(self.time_thresh);
        let loss_delay = cmp::max(loss_delay, TIMER_GRANULARITY);
        let lost_send_time = now - loss_delay;

        let unacked_iter = space
            .sent
            .iter_mut()
            .take_while(|p| p.pkt_num <= space.largest_acked_pkt)
            .filter(|p| p.time_acked.is_none() && p.time_lost.is_none());
        for unacked in unacked_iter {
            // A packet is declared lost if it meets all of the following
            // conditions:
            // * The packet is unacknowledged, in flight, and was sent prior to
            //   an acknowledged packet.
            // * The packet was sent kPacketThreshold packets before an
            //   acknowledged packet, or it was sent long enough in the past.
            // See RFC 9002 Section 6.1
            if unacked.time_sent <= lost_send_time
                || unacked.pkt_num + self.pkt_thresh <= space.largest_acked_pkt
            {
                space.lost.append(&mut unacked.frames);
                unacked.time_lost = Some(now);

                lost_packets += 1;
                if unacked.in_flight {
                    lost_bytes += unacked.sent_size as u64;
                    space.bytes_in_flight = space.bytes_in_flight.saturating_sub(unacked.sent_size);
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(unacked.sent_size);

                    if unacked.ack_eliciting {
                        space.ack_eliciting_in_flight =
                            space.ack_eliciting_in_flight.saturating_sub(1);
                        self.ack_eliciting_in_flight =
                            self.ack_eliciting_in_flight.saturating_sub(1);
                    }
                }
                // Loss of a QUIC packet that is carried in a PMTU probe is not
                // a reliable indication of congestion and SHOULD NOT trigger a
                // congestion control reaction
                if !unacked.pmtu_probe {
                    latest_lost_packet = Some(unacked.clone());
                }
                if let Some(qlog) = qlog.as_mut() {
                    self.qlog_recovery_packet_lost(qlog, unacked);
                }
                trace!(
                    "now={:?} {} {} ON_LOST {:?} inflight={} cwnd={}",
                    now,
                    self.trace_id,
                    self.congestion.name(),
                    unacked,
                    self.bytes_in_flight,
                    self.congestion.congestion_window()
                );
            } else {
                let loss_time = match space.loss_time {
                    None => unacked.time_sent + loss_delay,
                    Some(loss_time) => cmp::min(loss_time, unacked.time_sent + loss_delay),
                };
                space.loss_time = Some(loss_time);
            }
        }

        // Notify congestion controller of the lost event
        if let Some(lost_packet) = latest_lost_packet {
            if space.id != SpaceId::Initial && space.id != SpaceId::Handshake {
                self.congestion.on_congestion_event(
                    now,
                    &lost_packet,
                    self.in_persistent_congestion(),
                    lost_bytes,
                    self.bytes_in_flight as u64,
                );
                trace!(
                    "now={:?} {} {} ON_CONGESTION_EVENT lost_size={} inflight={} cwnd={}",
                    now,
                    self.trace_id,
                    self.congestion.name(),
                    lost_bytes,
                    self.bytes_in_flight,
                    self.congestion.congestion_window()
                );
            }
        }

        self.stat_lost_event(lost_packets, lost_bytes);
        (lost_packets, lost_bytes)
    }

    // Remove acked or lost packet from the packet sent queue in batch.
    //
    // Removing packets from the middle would require copying to compact the vec.
    // So it only remove a contiguous range of packets from the start of the vec.
    fn drain_sent_packets(&mut self, space: &mut PacketNumSpace, now: Instant, rtt: Duration) {
        let mut lowest_non_expired_pkt_index = space.sent.len();
        for (i, pkt) in space.sent.iter().enumerate() {
            // find the first element that is neither acked nor lost.
            if pkt.time_acked.is_none() && pkt.time_lost.is_none() {
                lowest_non_expired_pkt_index = i;
                break;
            }
            if let Some(time_lost) = pkt.time_lost {
                if time_lost + rtt > now {
                    lowest_non_expired_pkt_index = i;
                    break;
                }
            }
        }
        space.sent.drain(..lowest_non_expired_pkt_index);
    }

    // Set timer for loss detection.
    //
    // See RFC 9002 A.8. Setting the Loss Detection Timer
    fn set_loss_detection_timer(
        &mut self,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        // Loss timer.
        let (earliest_loss_time, _) = self.get_loss_time_and_space(space_id, spaces);
        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            self.loss_detection_timer = earliest_loss_time;
            return;
        }

        // TODO: The server's timer is not set if nothing can be sent.

        if self.ack_eliciting_in_flight == 0 && handshake_status.peer_verified_address {
            // There is nothing to detect lost, so no timer is set.
            // However, the client needs to arm the timer if the
            // server might be blocked by the anti-amplification limit.
            self.loss_detection_timer = None;
            return;
        }

        // PTO timer.
        let (timeout, _) = self.get_pto_time_and_space(space_id, spaces, handshake_status, now);
        self.loss_detection_timer = timeout;
    }

    /// Return expiration time of loss timer
    pub(super) fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_detection_timer
    }

    /// Handles timeout event.
    ///
    /// When the loss detection timer expires, the timer's mode determines the
    /// action to be performed.
    /// See RFC 9002 Section A.10. On Timeout
    pub(super) fn on_loss_detection_timeout(
        &mut self,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        qlog: Option<&mut qlog::QlogWriter>,
        now: Instant,
    ) -> (u64, u64) {
        let (earliest_loss_time, sid) = self.get_loss_time_and_space(space_id, spaces);
        let space = match spaces.get_mut(sid) {
            Some(space) => space,
            None => return (0, 0),
        };

        // Loss timer mode
        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            let (lost_packets, lost_bytes) = self.detect_lost_packets(space, qlog, now);
            self.drain_sent_packets(space, now, self.rtt.smoothed_rtt());
            self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
            return (lost_packets, lost_bytes);
        }

        // PTO timer mode
        let sid = if self.ack_eliciting_in_flight > 0 {
            // Send new data if available, else retransmit old data. If neither
            // is available, send a single PING frame.
            let (_, e) = self.get_pto_time_and_space(space_id, spaces, handshake_status, now);
            e
        } else {
            // Client sends an anti-deadlock packet: Initial is padded to earn
            // more anti-amplification credit, a Handshake packet proves address
            // ownership.
            if handshake_status.derived_handshake_keys {
                Handshake
            } else {
                Initial
            }
        };
        let space = match spaces.get_mut(sid) {
            Some(space) => space,
            None => return (0, 0),
        };
        self.pto_count += 1;

        space.loss_probes = match sid {
            Initial | Handshake => 1,
            _ => cmp::min(self.pto_count, MAX_PTO_PROBES_COUNT),
        };

        // An endpoint SHOULD include new data in packets that are sent on PTO
        // expiration. Previously sent data MAY be sent if no new data can be
        // sent. However, we only try to retransmit the oldest unacked data.
        let unacked_iter = space
            .sent
            .iter_mut()
            .filter(|p| p.has_data && p.time_acked.is_none() && p.time_lost.is_none())
            .take(space.loss_probes);

        for unacked in unacked_iter {
            // A PTO timer expiration event does not indicate packet loss and
            // MUST NOT cause prior unacknowledged packets to be marked as lost.
            space.lost.extend_from_slice(&unacked.frames);
        }

        self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
        (0, 0)
    }

    /// Return the min loss time and the corresponding space
    fn get_loss_time_and_space(
        &mut self,
        space_id: SpaceId,
        spaces: &PacketNumSpaceMap,
    ) -> (Option<Instant>, SpaceId) {
        let candidates = if space_id != Initial && space_id != Handshake {
            [Initial, Handshake, space_id]
        } else {
            [Initial, Handshake, Data]
        };

        let mut sid = Initial;
        let mut time = None;
        for s in candidates {
            let space = match spaces.get(s) {
                Some(space) => space,
                None => continue,
            };
            let new_time = space.loss_time;
            if time.is_none() || (new_time.is_some() && new_time < time) {
                time = new_time;
                sid = s;
            }
        }

        (time, sid)
    }

    /// Calculate the probe timeout.
    fn calculate_pto(&self) -> Duration {
        let backoff_factor = self
            .pto_count
            .saturating_sub(self.pto_linear_factor as usize);

        cmp::min(
            self.rtt.pto_base() * 2_u32.saturating_pow(backoff_factor as u32),
            self.max_pto,
        )
    }

    /// Calculate the probe timeout include `max_ack_delay`.
    fn pto_with_ack_delay(&self, duration: Duration) -> Duration {
        let backoff_factor = self
            .pto_count
            .saturating_sub(self.pto_linear_factor as usize);

        cmp::min(
            duration + self.max_ack_delay * 2_u32.saturating_pow(backoff_factor as u32),
            self.max_pto,
        )
    }

    /// Return the min pto time and the corresponding space
    fn get_pto_time_and_space(
        &self,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        now: Instant,
    ) -> (Option<Instant>, SpaceId) {
        let mut duration = self.calculate_pto();

        // Arm PTO from now when there are no ack-eliciting packets inflight.
        if self.ack_eliciting_in_flight == 0 {
            if handshake_status.derived_handshake_keys {
                return (Some(now + duration), SpaceId::Handshake);
            } else {
                return (Some(now + duration), SpaceId::Initial);
            }
        }

        let candidates = if space_id != Initial && space_id != Handshake {
            [Initial, Handshake, space_id]
        } else {
            [Initial, Handshake, Data]
        };

        let mut pto_timeout = None;
        let mut pto_space = Initial;

        for sid in candidates {
            let space = match spaces.get_mut(sid) {
                Some(space) => space,
                None => continue,
            };
            if space.ack_eliciting_in_flight == 0 {
                continue;
            }

            if sid == Data {
                // An endpoint MUST NOT set its PTO timer for the Application
                // Data packet number space until the handshake is confirmed.
                if !handshake_status.completed {
                    return (pto_timeout, pto_space);
                }
                // Include max_ack_delay and backoff for Application Data.
                duration = self.pto_with_ack_delay(duration);
            }

            let new_time = space
                .time_of_last_sent_ack_eliciting_pkt
                .map(|t| t + duration);
            if pto_timeout.is_none() || new_time < pto_timeout {
                pto_timeout = new_time;
                pto_space = sid;
            }
        }
        (pto_timeout, pto_space)
    }

    /// Handles event of dropping Initial or Handshake keys
    ///
    /// When Initial or Handshake keys are discarded, packets from the space
    /// are discarded and loss detection state is updated.
    /// See RFC 9002 Section A.11. Upon Dropping Initial or Handshake keys
    pub(super) fn on_pkt_num_space_discarded(
        &mut self,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        let space = match spaces.get_mut(space_id) {
            Some(space) => space,
            None => return,
        };

        // Removing discarded packets from bytes in flight
        self.remove_from_bytes_in_flight(space);

        // Clear packet queue
        space.sent.clear();
        space.lost.clear();
        space.acked.clear();

        // Reset loss dection timer
        space.time_of_last_sent_ack_eliciting_pkt = None;
        space.loss_time = None;
        space.loss_probes = 0;
        space.bytes_in_flight = 0;
        space.ack_eliciting_in_flight = 0;
        self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
    }

    /// Removing Discarded Packets from Bytes in Flight
    ///
    /// When Initial or Handshake keys are discarded, packets sent in that
    /// space no longer count toward bytes in flight.
    fn remove_from_bytes_in_flight(&mut self, space: &PacketNumSpace) {
        for pkt in &space.sent {
            if !pkt.in_flight || pkt.time_acked.is_some() || pkt.time_lost.is_some() {
                continue;
            }

            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.sent_size);
            if pkt.ack_eliciting {
                self.ack_eliciting_in_flight = self.ack_eliciting_in_flight.saturating_sub(1);
            }
        }
    }

    /// Update maximum datagram size
    ///
    /// If `is_upper` is true, `max_datagram_size` is the upper limit of maximum datagram size.
    /// If `is_upper` is false, `max_datagram_size` is the new maximum datagram size.
    pub(super) fn update_max_datagram_size(
        &mut self,
        mut max_datagram_size: usize,
        is_upper: bool,
    ) {
        if is_upper {
            max_datagram_size = cmp::min(self.max_datagram_size, max_datagram_size);
        }

        // TODO: notify CC and pacer

        self.max_datagram_size = max_datagram_size;
    }

    /// Check whether this path can still send packets.
    pub(crate) fn can_send(&mut self) -> bool {
        self.bytes_in_flight < self.congestion.congestion_window() as usize
            && (!self.pacer.enabled() || self.can_pacing())
    }

    fn can_pacing(&mut self) -> bool {
        let now = time::Instant::now();
        let cwnd = self.congestion.congestion_window();
        let srtt = self.rtt.smoothed_rtt() as Duration;

        if let Some(pr) = self.congestion.pacing_rate() {
            self.pacer_timer = self.pacer.schedule(
                self.cache_pkt_size as u64,
                pr,
                srtt,
                cwnd,
                self.max_datagram_size as u64,
                now,
            );
        }

        if self.pacer_timer.is_none() {
            true
        } else {
            trace!("{} pacing timer is {:?}", self.trace_id, self.pacer_timer);
            false
        }
    }

    /// Update statistics for the packet sent event
    pub(crate) fn stat_sent_event(&mut self, sent_pkts: u64, sent_bytes: u64) {
        self.stats.sent_count = self.stats.sent_count.saturating_add(sent_pkts);
        self.stats.sent_bytes = self.stats.sent_bytes.saturating_add(sent_bytes);
        self.stat_cwnd_updated();
    }

    /// Update statistics for the packet recv event
    pub(crate) fn stat_recv_event(&mut self, recv_pkts: u64, recv_bytes: u64) {
        self.stats.recv_count = self.stats.recv_count.saturating_add(recv_pkts);
        self.stats.recv_bytes = self.stats.recv_bytes.saturating_add(recv_bytes);
    }

    /// Update statistics for the packet acked event
    pub(crate) fn stat_acked_event(&mut self, acked_pkts: u64, acked_bytes: u64) {
        self.stats.acked_count = self.stats.acked_count.saturating_add(acked_pkts);
        self.stats.acked_bytes = self.stats.acked_bytes.saturating_add(acked_bytes);
    }

    /// Update statistics for the packet loss event
    pub(crate) fn stat_lost_event(&mut self, lost_pkts: u64, lost_bytes: u64) {
        self.stats.lost_count = self.stats.lost_count.saturating_add(lost_pkts);
        self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(lost_bytes);
    }

    /// Update statistics for the congestion_window
    pub(crate) fn stat_cwnd_updated(&mut self) {
        let cwnd = self.congestion.congestion_window();
        if self.stats.init_cwnd == 0 {
            self.stats.init_cwnd = cwnd;
            self.stats.min_cwnd = cwnd;
            self.stats.max_cwnd = cwnd;
        }
        self.stats.final_cwnd = cwnd;
        if self.stats.max_cwnd < cwnd {
            self.stats.max_cwnd = cwnd;
        }
        if self.stats.min_cwnd > cwnd {
            self.stats.min_cwnd = cwnd;
        }
        let bytes_in_flight = self.bytes_in_flight as u64;
        if self.stats.max_inflight < bytes_in_flight {
            self.stats.max_inflight = bytes_in_flight;
        }
    }

    /// Update statistics for the congestion window limited event
    pub(crate) fn stat_cwnd_limited(&mut self) {
        let is_cwnd_limited = self.bytes_in_flight >= self.congestion.congestion_window() as usize;
        let now = Instant::now();
        if let Some(last_cwnd_limited_time) = self.last_cwnd_limited_time {
            // Update duration timely, in case it stays in cwnd limited all the time.
            let duration = now.saturating_duration_since(last_cwnd_limited_time);
            let duration = duration.as_millis() as u64;
            self.stats.cwnd_limited_duration =
                self.stats.cwnd_limited_duration.saturating_add(duration);
            if is_cwnd_limited {
                self.last_cwnd_limited_time = Some(now);
            } else {
                self.last_cwnd_limited_time = None;
            }
        } else if is_cwnd_limited {
            // A new cwnd limited event
            self.stats.cwnd_limited_count = self.stats.cwnd_limited_count.saturating_add(1);
            self.last_cwnd_limited_time = Some(now);
        }
    }

    /// Update with the latest values from recovery.
    pub(crate) fn stat_lazy_update(&mut self) {
        self.stats.min_rtt = self.rtt.min_rtt().as_micros() as u64;
        self.stats.max_rtt = self.rtt.max_rtt().as_micros() as u64;
        self.stats.srtt = self.rtt.smoothed_rtt().as_micros() as u64;
        self.stats.rttvar = self.rtt.rttvar().as_micros() as u64;
        self.stats.in_slow_start = self.congestion.in_slow_start();
        self.stats.pacing_rate = self.congestion.pacing_rate().unwrap_or_default();
    }

    /// Write a qlog RecoveryMetricsUpdated event if any recovery metric is updated.
    pub(crate) fn qlog_recovery_metrics_updated(&mut self, qlog: &mut qlog::QlogWriter) {
        let mut updated = false;

        let mut min_rtt = None;
        if self.last_metrics.min_rtt != self.rtt.min_rtt() {
            self.last_metrics.min_rtt = self.rtt.min_rtt();
            min_rtt = Some(self.last_metrics.min_rtt.as_secs_f32() * 1000.0);
            updated = true;
        }

        let mut smoothed_rtt = None;
        if self.last_metrics.smoothed_rtt != self.rtt.smoothed_rtt() {
            self.last_metrics.smoothed_rtt = self.rtt.smoothed_rtt();
            smoothed_rtt = Some(self.last_metrics.smoothed_rtt.as_secs_f32() * 1000.0);
            updated = true;
        }

        let mut latest_rtt = None;
        if self.last_metrics.latest_rtt != self.rtt.latest_rtt() {
            self.last_metrics.latest_rtt = self.rtt.latest_rtt();
            latest_rtt = Some(self.last_metrics.latest_rtt.as_secs_f32() * 1000.0);
            updated = true;
        }

        let mut rtt_variance = None;
        if self.last_metrics.rttvar != self.rtt.rttvar() {
            self.last_metrics.rttvar = self.rtt.rttvar();
            rtt_variance = Some(self.last_metrics.rttvar.as_secs_f32() * 1000.0);
            updated = true;
        }

        let mut congestion_window = None;
        if self.last_metrics.cwnd != self.congestion.congestion_window() {
            self.last_metrics.cwnd = self.congestion.congestion_window();
            congestion_window = Some(self.last_metrics.cwnd);
            updated = true;
        }

        let mut bytes_in_flight = None;
        if self.last_metrics.bytes_in_flight != self.bytes_in_flight as u64 {
            self.last_metrics.bytes_in_flight = self.bytes_in_flight as u64;
            bytes_in_flight = Some(self.last_metrics.bytes_in_flight);
            updated = true;
        }

        let mut pacing_rate = None;
        if self.last_metrics.pacing_rate != self.congestion.pacing_rate() {
            self.last_metrics.pacing_rate = self.congestion.pacing_rate();
            pacing_rate = self.last_metrics.pacing_rate.map(|v| v * 8); // bps
            updated = true;
        }

        if !updated {
            return;
        }

        let ev_data = EventData::RecoveryMetricsUpdated {
            min_rtt,
            smoothed_rtt,
            latest_rtt,
            rtt_variance,
            pto_count: None,
            congestion_window,
            bytes_in_flight,
            ssthresh: None,
            packets_in_flight: None,
            pacing_rate,
        };
        qlog.add_event_data(Instant::now(), ev_data).ok();
    }

    /// Write a qlog RecoveryPacketLost event.
    pub(crate) fn qlog_recovery_packet_lost(
        &mut self,
        qlog: &mut qlog::QlogWriter,
        pkt: &SentPacket,
    ) {
        let ev_data = EventData::RecoveryPacketLost {
            header: Some(qlog::events::PacketHeader {
                packet_type: pkt.pkt_type.to_qlog(),
                packet_number: pkt.pkt_num,
                ..qlog::events::PacketHeader::default()
            }),
            frames: None,
            is_mtu_probe_packet: None,
            trigger: None,
        };
        qlog.add_event_data(Instant::now(), ev_data).ok();
    }
}

/// Metrics used for emitting qlog RecoveryMetricsUpdated event.
#[derive(Default)]
struct RecoveryMetrics {
    /// The minimum RTT observed on the path, ignoring ack delay
    min_rtt: Duration,

    /// The smoothed RTT of the path is an exponentially weighted moving average
    /// of an endpoint's RTT samples
    smoothed_rtt: Duration,

    /// The most recent RTT sample.
    latest_rtt: Duration,

    /// The RTT variance estimates the variation in the RTT samples using a
    /// mean variation
    rttvar: Duration,

    /// Congestion window in bytes.
    cwnd: u64,

    /// Total number of bytes in fight.
    bytes_in_flight: u64,

    /// Pacing rate in Bps
    pacing_rate: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion_control::CongestionControlAlgorithm;
    use crate::connection::space::RateSamplePacketState;
    use crate::ranges::RangeSet;
    use std::time::Duration;
    use std::time::Instant;

    fn new_test_sent_packet(pkt_num: u64, sent_size: usize, now: Instant) -> SentPacket {
        SentPacket {
            pkt_num,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            sent_size,
            ack_eliciting: true,
            in_flight: true,
            has_data: true,
            rate_sample_state: Default::default(),
            ..SentPacket::default()
        }
    }

    fn new_test_recovery_config() -> RecoveryConfig {
        RecoveryConfig {
            max_datagram_size: 1200,
            max_ack_delay: Duration::from_millis(100),
            congestion_control_algorithm: CongestionControlAlgorithm::Bbr,
            min_congestion_window: 2_u64,
            initial_congestion_window: 10_u64,
            initial_rtt: crate::INITIAL_RTT,
            pto_linear_factor: crate::DEFAULT_PTO_LINEAR_FACTOR,
            max_pto: crate::MAX_PTO,
            ..RecoveryConfig::default()
        }
    }

    #[test]
    fn loss_on_timeout() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packet 0
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 1000);
        assert_eq!(recovery.bytes_in_flight, 1000);

        // Fake sending of packet 1
        let sent_pkt1 = new_test_sent_packet(1, 1001, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 2001);
        assert_eq!(recovery.bytes_in_flight, 2001);

        // Fake sending of packet 2
        let sent_pkt2 = new_test_sent_packet(2, 1002, now);
        recovery.on_packet_sent(sent_pkt2, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 3);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 3003);
        assert_eq!(spaces.get(space_id).unwrap().ack_eliciting_in_flight, 3);
        assert_eq!(recovery.bytes_in_flight, 3003);
        assert_eq!(recovery.ack_eliciting_in_flight, 3);

        // Advance ticks and fake receiving of ack
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        acked.insert(2..3);
        recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            None,
            now,
        )?;
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().ack_eliciting_in_flight, 1);
        assert_eq!(recovery.ack_eliciting_in_flight, 1);

        // Advance ticks until loss timeout
        now = recovery.loss_detection_timer().unwrap();
        let (lost_pkts, lost_bytes) =
            recovery.on_loss_detection_timeout(SpaceId::Handshake, &mut spaces, status, None, now);
        assert_eq!(lost_pkts, 1);
        assert_eq!(lost_bytes, 1001);
        assert_eq!(spaces.get(space_id).unwrap().ack_eliciting_in_flight, 0);
        assert_eq!(recovery.ack_eliciting_in_flight, 0);

        Ok(())
    }

    #[test]
    fn loss_on_reordering() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packet 0
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 1000);
        assert_eq!(recovery.bytes_in_flight, 1000);

        // Fake sending of packet 1
        let sent_pkt1 = new_test_sent_packet(1, 1001, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 2001);
        assert_eq!(recovery.bytes_in_flight, 2001);

        // Fake sending of packet 2
        let sent_pkt2 = new_test_sent_packet(2, 1002, now);
        recovery.on_packet_sent(sent_pkt2, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 3);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 3003);
        assert_eq!(recovery.bytes_in_flight, 3003);

        // Fake sending of packet 3
        let sent_pkt2 = new_test_sent_packet(3, 1003, now);
        recovery.on_packet_sent(sent_pkt2, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 4);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 4006);
        assert_eq!(recovery.bytes_in_flight, 4006);

        // Advance ticks and fake receiving of ack
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(1..4);

        // Detect packet loss base on reordering threshold
        let (lost_pkts, lost_bytes) = recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            None,
            now,
        )?;
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 4);
        assert_eq!(lost_pkts, 1);
        assert_eq!(lost_bytes, 1000);

        // Advance ticks and fake receiving of duplicated ack
        now += recovery.rtt.smoothed_rtt();
        let (lost_pkts, lost_bytes) = recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            None,
            now,
        )?;
        assert_eq!(lost_pkts, 0);
        assert_eq!(lost_bytes, 0);

        recovery.drain_sent_packets(
            spaces.get_mut(space_id).unwrap(),
            now,
            recovery.rtt.smoothed_rtt(),
        );
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 0);

        Ok(())
    }

    #[test]
    fn pto() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packet 0
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 1000);
        assert_eq!(recovery.bytes_in_flight, 1000);

        // Fake sending of packet 1
        let sent_pkt1 = new_test_sent_packet(1, 1001, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 2001);
        assert_eq!(recovery.bytes_in_flight, 2001);

        // Advance ticks and fake receiving of ack
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        let (lost_pkts, lost_bytes) = recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            None,
            now,
        )?;
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(lost_pkts, 0);
        assert_eq!(lost_bytes, 0);
        assert!(recovery.loss_detection_timer().is_some());

        // Advance ticks until pto timeout
        now = recovery.loss_detection_timer().unwrap();
        let (lost_pkts, lost_bytes) =
            recovery.on_loss_detection_timeout(SpaceId::Handshake, &mut spaces, status, None, now);
        assert_eq!(recovery.pto_count, 1);
        assert_eq!(lost_pkts, 0);
        assert_eq!(lost_bytes, 0);

        Ok(())
    }

    #[test]
    fn discard_pkt_num_space() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packet 0 on Handshake space
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 1000);
        assert_eq!(recovery.bytes_in_flight, 1000);

        // Fake sending of packet 1 on Handshake space
        let sent_pkt1 = new_test_sent_packet(1, 1001, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 2001);
        assert_eq!(recovery.bytes_in_flight, 2001);

        // Fake sending of packet 2 on Handshake space
        let sent_pkt2 = new_test_sent_packet(2, 1002, now);
        recovery.on_packet_sent(sent_pkt2, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 3);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 3003);
        assert_eq!(recovery.bytes_in_flight, 3003);

        // Fake sending of packet 0 on Data space
        let sent_pkt3 = new_test_sent_packet(0, 1003, now);
        recovery.on_packet_sent(sent_pkt3, SpaceId::Data, &mut spaces, status, now);
        assert_eq!(spaces.get(SpaceId::Data).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(SpaceId::Data).unwrap().bytes_in_flight, 1003);
        assert_eq!(recovery.bytes_in_flight, 4006);

        // Advance ticks and fake receiving of ack on Handshake space
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(0..2);
        recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            None,
            now,
        )?;
        assert_eq!(spaces.get(SpaceId::Handshake).unwrap().sent.len(), 1);
        assert_eq!(
            spaces.get(SpaceId::Handshake).unwrap().bytes_in_flight,
            1002
        );
        assert_eq!(recovery.bytes_in_flight, 2005);

        // Discard Handshake space
        recovery.on_pkt_num_space_discarded(space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 0);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 0);
        assert_eq!(spaces.get(space_id).unwrap().ack_eliciting_in_flight, 0);
        assert_eq!(recovery.bytes_in_flight, 1003);
        assert_eq!(recovery.ack_eliciting_in_flight, 1);

        Ok(())
    }

    fn check_acked_packets(sent: &VecDeque<SentPacket>, acked_ranges: Vec<Range<u64>>) -> bool {
        let ranges_contain = |pkt_num: u64, ranges: Vec<Range<u64>>| {
            for range in &ranges {
                if range.contains(&pkt_num) {
                    return true;
                }
            }
            return false;
        };

        for sent_pkt in sent {
            match sent_pkt.pkt_num {
                pkt_num if ranges_contain(pkt_num, acked_ranges.clone()) => {
                    if sent_pkt.time_acked.is_none() {
                        return false;
                    }
                }
                _ => {
                    if sent_pkt.time_acked.is_some() {
                        return false;
                    }
                }
            }
        }

        true
    }

    fn generate_ack(ranges: Vec<Range<u64>>) -> RangeSet {
        let mut acked = RangeSet::default();
        for range in ranges {
            acked.insert(range);
        }
        acked
    }

    #[test]
    fn detect_acked_packets() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packets on Data space.
        for pkt_num in 100..1000 as u64 {
            let sent_pkt = new_test_sent_packet(pkt_num, 1000, now);
            recovery.on_packet_sent(sent_pkt, SpaceId::Data, &mut spaces, status, now);
        }
        now += Duration::from_millis(100);

        // Packets with a higher number got acked in interleaved mode.
        // Fake receiving ACK.
        let ack = generate_ack(vec![500..550, 600..650, 700..750, 800..850, 900..950]);
        let mut newly_acked_pkts = Vec::<AckedPacket>::new();
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![500..550, 600..650, 700..750, 800..850, 900..950],
        ));
        // Fake receiving next ACK.
        let ack = generate_ack(vec![550..600, 650..700, 750..800, 850..900]);
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![500..950],
        ));
        // Fake receiving duplicated ACK.
        recovery.on_ack_received(&ack, 0, SpaceId::Data, &mut spaces, status, None, now)?;
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![500..950],
        ));

        // Got ACKs with no intersection.
        let ack = generate_ack(vec![0..100, 1000..1100]);
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![500..950],
        ));

        // Got ACKs with partial overlapping.
        let ack = generate_ack(vec![50..150, 950..1050]);
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![100..150, 500..1000],
        ));

        // Packets with a lower number got acked.
        let ack = generate_ack(vec![100..200, 300..400]);
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![100..200, 300..400, 500..1000],
        ));

        Ok(())
    }

    #[test]
    fn check_cwnd_for_non_app_data_ack() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();
        let cwnd_before_ack = recovery.congestion.congestion_window();

        // Fake sending of packet 0
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);

        // Fake sending of packet 1
        let sent_pkt1 = new_test_sent_packet(1, 2000, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);

        // Advance ticks and fake receiving of ack
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(0..2);

        // Detect packet loss base on reordering threshold
        let (lost_pkts, lost_bytes) = recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            None,
            now,
        )?;
        assert_eq!(cwnd_before_ack, recovery.congestion.congestion_window());

        Ok(())
    }

    const MAX_PTO_UT: Duration = Duration::from_secs(30);

    fn calculate_pto_with_count(count: usize) -> (Duration, Duration) {
        let mut conf = new_test_recovery_config();
        conf.pto_linear_factor = 2;
        conf.max_pto = MAX_PTO_UT;
        let mut recovery = Recovery::new(&conf);
        recovery.pto_count = count;

        let duration = recovery.calculate_pto();
        (duration, recovery.pto_with_ack_delay(duration))
    }

    #[test]
    fn calculate_pto() -> Result<()> {
        assert_eq!(
            calculate_pto_with_count(0),
            (
                Duration::from_millis(999),  // 999 * 2 ^ ( 2 - 2)
                Duration::from_millis(1099)  // (999 + 100) * 2 ^ 0, max_ack_delay is 100ms.
            )
        );

        assert_eq!(
            calculate_pto_with_count(2),
            (
                Duration::from_millis(999),  // 999 * 2 ^ 0
                Duration::from_millis(1099)  // (999 + 100) * 2 ^ 0
            )
        );

        assert_eq!(
            calculate_pto_with_count(3),
            (
                Duration::from_millis(1998), // 999 * 2 ^ ( 2 - 2)
                Duration::from_millis(2198)  // (999 + 100) * 2 ^ ( 3 - 2)
            )
        );

        // PTO reach the upper limit.
        assert_eq!(calculate_pto_with_count(100), (MAX_PTO_UT, MAX_PTO_UT));

        Ok(())
    }
}
