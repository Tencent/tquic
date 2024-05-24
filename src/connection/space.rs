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
use crate::packet;
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

    /// Track the first received packet in current key phase.
    pub first_pkt_num_recv: Option<u64>,

    /// Track the first sent packet in current key phase.
    pub first_pkt_num_sent: Option<u64>,

    /// The time at which the packet of highest sequence number arrived.
    pub largest_rx_pkt_time: Instant,

    /// Highest received non-probing packet number.
    pub largest_rx_non_probing_pkt_num: u64,

    /// Highest received ack-eliciting packet number.
    pub largest_rx_ack_eliciting_pkt_num: u64,

    /// The packet numbers to acknowledge.
    pub recv_pkt_num_need_ack: RangeSet,

    /// The packet number window for deduplicate detection.
    pub recv_pkt_num_win: SeqNumWindow,

    /// Whether an ACK frame should be generated and sent to the peer.
    pub need_send_ack: bool,

    /// Number of ack-eliciting packets received since last ACK was sent
    pub ack_eliciting_pkts_since_last_sent_ack: u64,

    /// Timer used for sending a delayed ACK frame.
    pub ack_timer: Option<Instant>,

    /// Sent packets metadata for loss recovery and congestion control.
    /// See RFC 9002 Section 9.1
    pub sent: VecDeque<SentPacket>,

    /// Lost frames.
    pub lost: Vec<frame::Frame>,

    /// Acknowledged frames.
    pub acked: Vec<frame::Frame>,

    /// Buffered frames to be sent in multipath mode.
    pub buffered: BufferQueue,

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
}

impl PacketNumSpace {
    pub fn new(id: SpaceId) -> Self {
        PacketNumSpace {
            id,
            next_pkt_num: 0,
            consecutive_non_ack_eliciting_sent: 0,
            lowest_1rtt_pkt_num: u64::MAX,
            largest_rx_pkt_num: 0,
            first_pkt_num_recv: None,
            first_pkt_num_sent: None,
            largest_rx_pkt_time: Instant::now(),
            largest_rx_non_probing_pkt_num: 0,
            largest_rx_ack_eliciting_pkt_num: 0,
            recv_pkt_num_need_ack: RangeSet::new(crate::MAX_ACK_RANGES),
            recv_pkt_num_win: SeqNumWindow::default(),
            need_send_ack: false,
            ack_eliciting_pkts_since_last_sent_ack: 0,
            ack_timer: None,
            sent: VecDeque::new(),
            lost: Vec::new(),
            acked: Vec::new(),
            buffered: BufferQueue::default(),
            time_of_last_sent_ack_eliciting_pkt: None,
            loss_time: None,
            largest_acked_pkt: u64::MAX,
            loss_probes: 0,
            bytes_in_flight: 0,
            ack_eliciting_in_flight: 0,
            is_data: id != SpaceId::Initial && id != SpaceId::Handshake,
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

    /// Return whether the space should send a buffered packet.
    pub fn need_send_buffered_frames(&self) -> bool {
        !self.buffered.is_empty()
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

    /// Return whether the connection should send a buffered packet.
    pub fn need_send_buffered_frames(&self) -> bool {
        for space in self.spaces.values() {
            if space.need_send_buffered_frames() {
                return true;
            }
        }
        false
    }

    /// Return the lowest ack timer value among all spaces.
    pub fn min_ack_timer(&self) -> Option<Instant> {
        self.spaces.iter().filter_map(|(_, s)| s.ack_timer).min()
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
}

/// Metadata of sent packet
#[derive(Clone)]
pub struct SentPacket {
    /// The packet type of the sent packet.
    pub pkt_type: packet::PacketType,

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

    /// Whether it is a PMUT probe packet
    pub pmtu_probe: bool,

    /// The number of bytes sent in the packet, not including UDP or IP overhead,
    /// but including QUIC framing overhead.
    pub sent_size: usize,

    /// Snapshot of the current delivery information.
    pub rate_sample_state: RateSamplePacketState,

    /// Status about buffered frames written into the packet.
    pub buffer_flags: BufferFlags,
}

impl Default for SentPacket {
    fn default() -> Self {
        SentPacket {
            pkt_type: packet::PacketType::OneRTT,
            pkt_num: 0,
            frames: vec![],
            time_sent: Instant::now(),
            time_acked: None,
            time_lost: None,
            ack_eliciting: false,
            in_flight: false,
            has_data: false,
            pmtu_probe: false,
            sent_size: 0,
            rate_sample_state: RateSamplePacketState::default(),
            buffer_flags: BufferFlags::default(),
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BufferType {
    High = 0,
    Mid = 1,
    Low = 2,
}

impl From<usize> for BufferType {
    fn from(index: usize) -> BufferType {
        match index {
            0 => BufferType::High,
            1 => BufferType::Mid,
            _ => BufferType::Low,
        }
    }
}

/// Metadata of buffered packets to be sent
#[derive(Default)]
pub struct BufferQueue {
    queues: [VecDeque<frame::Frame>; 3],
    count: usize,
}

impl BufferQueue {
    /// Remove the first frame and returns it
    pub fn pop_front(&mut self) -> Option<(frame::Frame, BufferType)> {
        for (i, queue) in self.queues.iter_mut().enumerate() {
            if !queue.is_empty() {
                self.count -= 1;
                return Some((queue.pop_front().unwrap(), BufferType::from(i)));
            }
        }
        None
    }

    /// Prepend a frame to the specified queue.
    pub fn push_front(&mut self, frame: frame::Frame, queue_type: BufferType) {
        self.count += 1;
        self.queues[queue_type as usize].push_front(frame)
    }

    /// Append a frame to the back of the queue.
    pub fn push_back(&mut self, frame: frame::Frame, queue_type: BufferType) {
        self.count += 1;
        self.queues[queue_type as usize].push_back(frame)
    }

    /// Move all the frames into self.
    pub fn append(&mut self, frames: &mut VecDeque<frame::Frame>, queue_type: BufferType) {
        self.count += frames.len();
        self.queues[queue_type as usize].append(frames)
    }

    /// Return the number of frames in the queue.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[derive(Clone, Default, Debug)]
pub struct BufferFlags {
    pub from_high: bool,
    pub from_mid: bool,
    pub from_low: bool,
}

impl BufferFlags {
    pub fn has_buffered(&self) -> bool {
        self.from_high || self.from_mid || self.from_low
    }

    pub fn mark(&mut self, queue_type: BufferType) {
        match queue_type {
            BufferType::High => self.from_high = true,
            BufferType::Mid => self.from_mid = true,
            BufferType::Low => self.from_low = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;

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
            frames: vec![
                frame::Frame::Ping { pmtu_probe: None },
                frame::Frame::Paddings { len: 200 },
            ],
            time_sent: Instant::now(),
            time_acked: None,
            time_lost: None,
            ack_eliciting: true,
            in_flight: true,
            has_data: false,
            sent_size: 240,
            rate_sample_state: Default::default(),
            ..SentPacket::default()
        };
        assert_eq!(
            format!("{:?}", sent_pkt),
            "pn=9 frames=[PING, PADDINGS len=200] sent_size=240"
        );
    }

    #[test]
    fn buffer_queue() {
        // initial queue
        let mut queue = BufferQueue::default();
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.is_empty(), true);

        // push back/push front
        let f1 = Frame::MaxStreamData {
            stream_id: 4,
            max: 10240,
        };
        queue.push_back(f1.clone(), BufferType::High);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.is_empty(), false);

        let f2 = Frame::MaxStreamData {
            stream_id: 8,
            max: 24000,
        };
        queue.push_front(f2.clone(), BufferType::High);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.is_empty(), false);

        let f3 = Frame::Ping { pmtu_probe: None };
        queue.push_back(f3.clone(), BufferType::Low);

        assert_eq!(queue.pop_front(), Some((f2.clone(), BufferType::High)));
        assert_eq!(queue.pop_front(), Some((f1.clone(), BufferType::High)));
        assert_eq!(queue.pop_front(), Some((f3.clone(), BufferType::Low)));
        assert_eq!(queue.pop_front(), None);
        assert_eq!(queue.is_empty(), true);

        // append
        let mut fs = VecDeque::new();
        fs.push_back(f1.clone());
        fs.push_back(f2.clone());
        queue.append(&mut fs, BufferType::Mid);
        assert_eq!(queue.len(), 2);
        assert_eq!(fs.len(), 0);
        assert_eq!(queue.pop_front(), Some((f1.clone(), BufferType::Mid)));
        assert_eq!(queue.pop_front(), Some((f2.clone(), BufferType::Mid)));
    }

    #[test]
    fn buffer_flags() {
        use BufferType::*;
        let cases = [
            (vec![], false),
            (vec![High], true),
            (vec![Mid], true),
            (vec![Low], true),
            (vec![Low, High], true),
            (vec![Low, Mid], true),
            (vec![High, Mid], true),
            (vec![High, Mid, Low], true),
        ];
        for case in cases {
            let mut flags = BufferFlags::default();
            for flag in case.0 {
                flags.mark(flag);
            }
            assert_eq!(flags.has_buffered(), case.1);
        }
    }
}
