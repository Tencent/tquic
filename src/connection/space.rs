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

use std::collections::hash_map::IterMut;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use rustc_hash::FxHashMap;

use crate::frame;
use crate::ranges::RangeSet;
use crate::tls::Level;
use crate::window::SeqNumWindow;

pub const MAX_NON_ACK_ELICITING: usize = 24;

/// Packet numbers are divided into three spaces in QUIC
pub const SPACE_COUNT: usize = 3;

/// Packet number space identifiers.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u64)]
pub enum SpaceId {
    /// Initial space for all Initial packets.
    Initial = 0,

    /// Handshake space for all Handhshake packets.
    Handshake = 1,

    /// Application data space for all 0-RTT and 1-RTT packets.
    Data = 2,

    /// Extra application data space for Multipath QUIC.
    DataExt(u64),
}

impl SpaceId {
    /// Get encryption level for the given packet number space.
    pub fn to_level(self) -> Level {
        match self {
            SpaceId::Initial => Level::Initial,
            SpaceId::Handshake => Level::Handshake,
            SpaceId::Data => Level::OneRTT,
            SpaceId::DataExt(..) => Level::OneRTT,
        }
    }
}

/// A packet number space is the context in which a packet can be processed
/// and acknowledged.
pub struct PacketNumSpace {
    /// The unique id for the packet number space.
    pub id: SpaceId,

    /// The packet number of the next packet that will be sent, if any.
    pub next_pkt_num: u64,

    /// Number of consecutive non-ack-eliciting packet sent.
    pub consecutive_non_ack_eliciting_sent: usize,

    /// The lowest packet number sent with 1-RTT keys.
    pub lowest_1rtt_pkt_num: u64,

    /// Highest received packet number.
    pub largest_rx_pkt_num: u64,

    /// The time at which the packet of highest sequence number arrived.
    pub largest_rx_pkt_time: Instant,

    /// Highest received non-probing packet number.
    pub largest_rx_non_probing_pkt_num: u64,

    /// The packet numbers to acknowledge.
    pub recv_pkt_num_need_ack: RangeSet,

    /// The packet number window for deduplicate detection.
    pub recv_pkt_num_win: SeqNumWindow,

    /// Whether an ACK frame should be generated and sent to the peer.
    pub need_send_ack: bool,

    /// Sent packets metadata for loss recovery and congestion control.
    /// See RFC 9002 Section 9.1
    pub sent: VecDeque<SentPacket>,

    /// Lost frames.
    pub lost: Vec<frame::Frame>,

    /// Acknowledged frames.
    pub acked: Vec<frame::Frame>,

    /// The time the most recent ack-eliciting packet was sent.
    pub time_of_last_sent_ack_eliciting_pkt: Option<Instant>,

    /// The time at which the next packet in that packet number space can be
    /// considered lost based on exceeding the reordering window in time.
    pub loss_time: Option<Instant>,

    /// The largest packet number acknowledged in the packet number space so far.
    pub largest_acked_pkt: u64,

    /// The number of times a PTO has been sent without receiving an acknowledgment.
    pub loss_probes: usize,

    /// The sum of the size in bytes of all in-flight packets in the packet
    /// number space.
    pub bytes_in_flight: usize,

    /// Number of ack-eliciting packets in flight.
    pub ack_eliciting_in_flight: u64,

    /// Packet number space for application data
    pub is_data: bool,

    /// Reinjected frames to be sent.
    pub reinject: ReinjectQueue,
}

impl PacketNumSpace {
    pub fn new(id: SpaceId) -> Self {
        PacketNumSpace {
            id,
            next_pkt_num: 0,
            consecutive_non_ack_eliciting_sent: 0,
            lowest_1rtt_pkt_num: std::u64::MAX,
            largest_rx_pkt_num: 0,
            largest_rx_pkt_time: Instant::now(),
            largest_rx_non_probing_pkt_num: 0,
            recv_pkt_num_need_ack: RangeSet::new(crate::MAX_ACK_RANGES),
            recv_pkt_num_win: SeqNumWindow::default(),
            need_send_ack: false,
            sent: VecDeque::new(),
            lost: Vec::new(),
            acked: Vec::new(),
            time_of_last_sent_ack_eliciting_pkt: None,
            loss_time: None,
            largest_acked_pkt: std::u64::MAX,
            loss_probes: 0,
            bytes_in_flight: 0,
            ack_eliciting_in_flight: 0,
            is_data: id != SpaceId::Initial && id != SpaceId::Handshake,
            reinject: ReinjectQueue::default(),
        }
    }

    /// Return whether the `pkt_num` is duplicated.
    pub fn detect_duplicated_pkt_num(&mut self, pkt_num: u64) -> bool {
        self.recv_pkt_num_win.contains(pkt_num)
    }

    /// Return whether the connection should send an ack-eliciting packet.
    pub fn need_elicit_ack(&self) -> bool {
        // A receiver that sends only non-ack-eliciting packets, such as ACK
        // frames, might not receive an acknowledgment for a long period of
        // time. This could cause the receiver to maintain state for a large
        // number of ACK frames for a long period of time, and ACK frames it
        // sends could be unnecessarily large.
        //
        // In such a case, a receiver could send a PING or other small
        // ack-eliciting frame occasionally, such as once per round trip, to
        // elicit an ACK from the peer.
        // See RFC 9000 Section 13.2.4
        if self.consecutive_non_ack_eliciting_sent >= MAX_NON_ACK_ELICITING {
            return true;
        }

        // When a PTO timer expires, a sender MUST send at least one
        // ack-eliciting packet in the packet number space as a probe. It is
        // possible the sender has no new or previously sent data to send.
        //
        // When there is no data to send, the sender SHOULD send a PING or other
        // ack-eliciting frame in a single packet, rearming the PTO timer.
        // See RFC 9002 Section 6.2.4
        self.loss_probes > 0
    }

    /// Return whether the space should send a reinjection packet.
    pub fn need_send_reinjected_frames(&self) -> bool {
        !self.reinject.frames.is_empty()
    }
}

/// All packet number spaces on a QUIC connection
pub struct PacketNumSpaceMap {
    /// Pakket number spaces for Initial/Handshake/Data/DataExt
    spaces: FxHashMap<u64, PacketNumSpace>,

    /// Next space id for DataExt
    next_data_ext_id: u64,
}

impl PacketNumSpaceMap {
    pub fn new() -> Self {
        let mut m = PacketNumSpaceMap {
            spaces: FxHashMap::default(),
            next_data_ext_id: 3,
        };
        m.spaces.insert(0, PacketNumSpace::new(SpaceId::Initial));
        m.spaces.insert(1, PacketNumSpace::new(SpaceId::Handshake));
        m.spaces.insert(2, PacketNumSpace::new(SpaceId::Data));
        m
    }

    /// Get an immutable reference to the specified space.
    pub fn get(&self, space_id: SpaceId) -> Option<&PacketNumSpace> {
        match space_id {
            SpaceId::Initial => self.spaces.get(&0),
            SpaceId::Handshake => self.spaces.get(&1),
            SpaceId::Data => self.spaces.get(&2),
            SpaceId::DataExt(ref i) => self.spaces.get(i),
        }
    }

    /// Get an mutable reference to the specified space.
    pub fn get_mut(&mut self, space_id: SpaceId) -> Option<&mut PacketNumSpace> {
        match space_id {
            SpaceId::Initial => self.spaces.get_mut(&0),
            SpaceId::Handshake => self.spaces.get_mut(&1),
            SpaceId::Data => self.spaces.get_mut(&2),
            SpaceId::DataExt(ref i) => self.spaces.get_mut(i),
        }
    }

    /// Return a mutable iterator over all spaces.
    pub fn iter_mut(&mut self) -> IterMut<'_, u64, PacketNumSpace> {
        self.spaces.iter_mut()
    }

    /// Add extra packet number space for Multipath QUIC.
    pub fn add(&mut self) -> SpaceId {
        let space_id = SpaceId::DataExt(self.next_data_ext_id);
        self.spaces
            .insert(self.next_data_ext_id, PacketNumSpace::new(space_id));

        self.next_data_ext_id += 1;
        space_id
    }

    /// Delete extra packet number space for Multipath QUIC.
    pub fn drop(&mut self, space_id: SpaceId) {
        match space_id {
            SpaceId::Initial => self.spaces.remove(&0),
            SpaceId::Handshake => self.spaces.remove(&1),
            SpaceId::Data => self.spaces.remove(&2),
            SpaceId::DataExt(ref i) => self.spaces.remove(i),
        };
    }

    /// Return whether the connection should send a reinjection packet.
    pub fn need_send_reinjected_frames(&self) -> bool {
        for space in self.spaces.values() {
            if space.need_send_reinjected_frames() {
                return true;
            }
        }
        false
    }
}

impl Default for PacketNumSpaceMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-packet state for delivery rate estimation.
/// See https://datatracker.ietf.org/doc/html/draft-cheng-iccrg-delivery-rate-estimation-02#section-3.1.2
#[derive(Debug, Default, Clone)]
pub struct RateSamplePacketState {
    /// P.delivered: C.delivered when the packet was sent from transport connection C.
    pub delivered: u64,

    /// P.delivered_time: C.delivered_time when the packet was sent.
    pub delivered_time: Option<Instant>,

    /// P.first_sent_time: C.first_sent_time when the packet was sent.
    pub first_sent_time: Option<Instant>,

    /// P.is_app_limited: true if C.app_limited was non-zero when the packet was sent, else false.
    pub is_app_limited: bool,

    /// packet.tx_in_flight: The volume of data that was estimated to be in flight at the time of the transmission of the packet.
    pub tx_in_flight: u64,

    /// packet.lost: The volume of data that was declared lost on transmission.
    pub lost: u64,
    // P.sent_time: The time when the packet was sent. (Use time_sent in SentPacket)
    // sent_time: Instant,
}

/// Metadata of sent packet
#[derive(Clone)]
pub struct SentPacket {
    /// The packet number of the sent packet.
    pub pkt_num: u64,

    /// The Frames metadata of the sent packet.
    pub frames: Vec<frame::Frame>,

    /// The time the packet was sent.
    pub time_sent: Instant,

    /// The time the packet was acknowledged, if any.
    pub time_acked: Option<Instant>,

    /// The time the packet was declared lost, if any.
    pub time_lost: Option<Instant>,

    /// A Boolean that indicates whether a packet is ack-eliciting. If true, it
    /// is expected that an acknowledgment will be received, though the peer
    /// could delay sending the ACK frame containing it by up to the max_ack_delay.
    pub ack_eliciting: bool,

    /// A Boolean that indicates whether the packet counts toward bytes in
    /// flight.
    pub in_flight: bool,

    /// Whether the packet contains CRYPTO or STREAM frame
    pub has_data: bool,

    /// The number of bytes sent in the packet, not including UDP or IP overhead,
    /// but including QUIC framing overhead.
    pub sent_size: usize,

    /// Snapshot of the current delivery information.
    pub rate_sample_state: RateSamplePacketState,

    /// Whether it is a reinjected packet.
    pub reinjected: bool,
}

impl std::fmt::Debug for SentPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "pn={:?}", self.pkt_num)?;
        write!(f, " frames={:?}", self.frames)?;
        write!(f, " sent_size={}", self.sent_size)?;

        Ok(())
    }
}

/// Metadata of acknowledged packet
pub struct AckedPacket {
    /// The packet number of the sent packet.
    pub pkt_num: u64,

    /// The time the packet was sent.
    pub time_sent: Instant,

    /// The Duration between the time the packet is sent and acknowledged
    pub rtt: Duration,
}

/// Metadata of packets to be reinjected
#[derive(Default)]
pub struct ReinjectQueue {
    /// The reinjected frames to be sent.
    pub frames: VecDeque<frame::Frame>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_spaces() {
        let mut spaces = PacketNumSpaceMap::default();
        assert_eq!(spaces.iter_mut().count(), 3);
        assert_eq!(
            spaces.get_mut(SpaceId::Initial).unwrap().id,
            SpaceId::Initial
        );
        assert_eq!(
            spaces.get_mut(SpaceId::Handshake).unwrap().id,
            SpaceId::Handshake
        );
        assert_eq!(spaces.get_mut(SpaceId::Data).unwrap().id, SpaceId::Data);

        assert_eq!(
            spaces.get(SpaceId::Initial).unwrap().id.to_level(),
            Level::Initial
        );
        assert_eq!(
            spaces.get(SpaceId::Handshake).unwrap().id.to_level(),
            Level::Handshake
        );
        assert_eq!(
            spaces.get(SpaceId::Data).unwrap().id.to_level(),
            Level::OneRTT
        );

        let space = spaces.get_mut(SpaceId::Initial).unwrap();
        assert_eq!(space.detect_duplicated_pkt_num(0), false);
        assert_eq!(space.detect_duplicated_pkt_num(5), false);
    }

    #[test]
    fn extra_spaces() {
        let mut spaces = PacketNumSpaceMap::default();
        assert!(spaces.get(SpaceId::DataExt(3)).is_none());

        let space_id = spaces.add();
        assert_eq!(spaces.iter_mut().count(), 4);
        assert_eq!(space_id, SpaceId::DataExt(3));
        assert!(spaces.get(space_id).is_some());
        assert_eq!(
            spaces.get_mut(space_id).unwrap().id.to_level(),
            Level::OneRTT
        );

        spaces.drop(space_id);
        assert!(spaces.get(SpaceId::DataExt(3)).is_none());
        assert_eq!(spaces.iter_mut().count(), 3);

        spaces.add();
        spaces.drop(SpaceId::Initial);
        spaces.drop(SpaceId::Handshake);
        spaces.drop(SpaceId::Data);
        assert_eq!(spaces.iter_mut().count(), 1);
    }

    #[test]
    fn sent_packet() {
        let sent_pkt = SentPacket {
            pkt_num: 9,
            frames: vec![frame::Frame::Ping, frame::Frame::Paddings { len: 200 }],
            time_sent: Instant::now(),
            time_acked: None,
            time_lost: None,
            ack_eliciting: true,
            in_flight: true,
            has_data: false,
            sent_size: 240,
            rate_sample_state: Default::default(),
            reinjected: false,
        };
        assert_eq!(
            format!("{:?}", sent_pkt),
            "pn=9 frames=[PING, PADDINGS len=200] sent_size=240"
        );
    }
}
