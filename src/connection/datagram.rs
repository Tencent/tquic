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

//! RFC 9221 DATAGRAM frame implementation for TQUIC.

use crate::Result;
use crate::{connection::datagram, error::Error};
use bytes::Bytes;
use core::error;
use log::*;
use std::collections::{HashMap, VecDeque};
/// Maximum size for a single DATAGRAM frame payload.
pub const MAX_DATAGRAM_SIZE: usize = 65535;

/// DATAGRAM frame manager for a QUIC connection.
///
/// This implementation follows RFC 9221 which defines an extension to QUIC
/// that adds support for sending and receiving unreliable datagrams over
/// a QUIC connection.
#[derive(Default)]
pub struct DatagramMap {
    /// Outgoing datagrams waiting to be sent.
    outgoing_queue: VecDeque<DatagramItem>,

    /// Incoming datagrams ready for application consumption.
    incoming_queue: VecDeque<DatagramItem>,

    /// Maximum outgoing datagram frame size supported by the peer.
    peer_max_datagram_frame_size: u64,

    /// Maximum incoming datagram frame size we support.
    local_max_datagram_frame_size: u64,

    /// Whether DATAGRAM extension is enabled for this connection.
    enabled: bool,

    /// Total number of datagrams sent.
    sent_count: u64,

    /// Total number of datagrams received.
    received_count: u64,

    /// Total bytes sent in datagram frames.
    sent_bytes: u64,

    /// Total bytes received in datagram frames.
    received_bytes: u64,

    /// Unique trace id for debug logging.
    trace_id: String,

    /// Used to identify a datagram frame.
    next_datagram_id: u64,
}

/// A single datagram item containing the payload and metadata.
#[derive(Debug, Clone)]
pub struct DatagramItem {
    /// The datagram payload.
    pub data: Bytes,

    /// Optional length field presence (for frame encoding).
    pub with_length: bool,

    /// Timestamp when the datagram was queued (for debugging/metrics).
    pub queued_at: std::time::Instant,

    /// Unique identifier for the datagram.
    pub id: Option<u64>,
}

impl DatagramMap {
    /// Create a new DatagramMap with default settings.
    pub fn new() -> Self {
        Self {
            outgoing_queue: VecDeque::new(),
            incoming_queue: VecDeque::new(),
            peer_max_datagram_frame_size: 0,
            local_max_datagram_frame_size: 0,
            enabled: false,
            sent_count: 0,
            received_count: 0,
            sent_bytes: 0,
            received_bytes: 0,
            trace_id: String::new(),
            next_datagram_id: 0,
        }
    }

    /// Set trace id for debug logging.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.trace_id = trace_id.to_string();
    }

    /// Enable or disable DATAGRAM extension based on transport parameters.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            // Clear queues if disabled
            self.outgoing_queue.clear();
            self.incoming_queue.clear();
        }
    }

    /// Check if DATAGRAM extension is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Update peer's maximum datagram frame size from transport parameters.
    pub fn set_peer_max_datagram_frame_size(&mut self, size: u64) {
        self.peer_max_datagram_frame_size = size;
        self.enabled = size > 0;
    }

    /// Get peer's maximum datagram frame size.
    pub fn peer_max_datagram_frame_size(&self) -> u64 {
        self.peer_max_datagram_frame_size
    }

    /// Set local maximum datagram frame size.
    pub fn set_local_max_datagram_frame_size(&mut self, size: u64) {
        self.local_max_datagram_frame_size = size;
    }

    /// Get local maximum datagram frame size.
    pub fn local_max_datagram_frame_size(&self) -> u64 {
        self.local_max_datagram_frame_size
    }

    /// Queue a datagram for sending.
    ///
    /// Returns `Error::DatagramTooLarge` if the datagram exceeds the peer's
    /// maximum datagram frame size.
    pub fn send_datagram(&mut self, data: Bytes) -> Result<u64> {
        debug!(
            "{} DatagramMap::send_datagram called, enabled: {}, data len: {}, peer_max: {}, queue size: {}",
            self.trace_id,
            self.enabled,
            data.len(),
            self.peer_max_datagram_frame_size,
            self.outgoing_queue.len()
        );

        let datagram_id = self.next_datagram_id;

        let item = DatagramItem {
            data,
            with_length: true,
            queued_at: std::time::Instant::now(),
            id: Some(datagram_id),
        };

        self.outgoing_queue.push_back(item);
        debug!(
            "{} Datagram queued successfully, new queue size: {}",
            self.trace_id,
            self.outgoing_queue.len()
        );
        self.next_datagram_id += 1;
        Ok(datagram_id)
    }

    /// Get the next datagram ready for transmission.
    ///
    /// Returns `None` if no datagrams are queued for sending.
    pub fn next_send_datagram(&mut self) -> Option<DatagramItem> {
        debug!(
            "{} DatagramMap::next_send_datagram called, queue size: {}",
            self.trace_id,
            self.outgoing_queue.len()
        );

        if let Some(item) = self.outgoing_queue.pop_front() {
            self.sent_count += 1;
            self.sent_bytes += item.data.len() as u64;
            debug!(
                "{} Popped datagram from queue, data len: {}, remaining queue size: {}",
                self.trace_id,
                item.data.len(),
                self.outgoing_queue.len()
            );
            Some(item)
        } else {
            debug!("{} No datagrams in queue to send", self.trace_id);
            None
        }
    }

    /// Check if there are datagrams ready for transmission.
    pub fn has_sendable_datagrams(&self) -> bool {
        let has_sendable = !self.outgoing_queue.is_empty();
        debug!(
            "{} DatagramMap::has_sendable_datagrams called, queue size: {}, result: {}",
            self.trace_id,
            self.outgoing_queue.len(),
            has_sendable
        );
        has_sendable
    }

    /// Put a datagram back to the front of the outgoing queue.
    /// This is used when a datagram couldn't be sent due to insufficient space.
    pub fn push_front_send_datagram(&mut self, item: DatagramItem) {
        // Revert the statistics since we're putting it back
        self.sent_count = self.sent_count.saturating_sub(1);
        self.sent_bytes = self.sent_bytes.saturating_sub(item.data.len() as u64);
        self.outgoing_queue.push_front(item);
    }

    /// Process a received DATAGRAM frame.
    ///
    pub fn on_datagram_frame_received(&mut self, len: Option<u64>, data: Bytes) -> Result<()> {
        // Validate the incoming datagram's size against the locally configured limit.
        //
        // According to RFC 9221 (Section 3), an endpoint that receives a DATAGRAM
        // frame with a payload larger than its advertised `max_datagram_frame_size`
        // transport parameter MUST treat this as a connection error of type
        // PROTOCOL_VIOLATION.
        if data.len() as u64 > self.local_max_datagram_frame_size {
            return Err(Error::ProtocolViolation);
        }

        let item = DatagramItem {
            data,
            with_length: len.is_some(),
            queued_at: std::time::Instant::now(),
            id: None,
        };

        self.received_count += 1;
        self.received_bytes += item.data.len() as u64;

        self.incoming_queue.push_back(item);

        Ok(())
    }

    /// Receive the next datagram from the incoming queue.
    ///
    /// Returns `None` if no datagrams are available for consumption.
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        self.incoming_queue.pop_front().map(|item| item.data)
    }

    /// Check if there are datagrams ready for consumption.
    pub fn has_readable_datagrams(&self) -> bool {
        !self.incoming_queue.is_empty()
    }

    /// Get the number of datagrams waiting to be sent.
    pub fn outgoing_count(&self) -> usize {
        self.outgoing_queue.len()
    }

    /// Get the number of datagrams waiting to be read.
    pub fn incoming_count(&self) -> usize {
        self.incoming_queue.len()
    }

    /// Get statistics about datagram usage.
    pub fn stats(&self) -> DatagramStats {
        DatagramStats {
            sent_count: self.sent_count,
            received_count: self.received_count,
            sent_bytes: self.sent_bytes,
            received_bytes: self.received_bytes,
            outgoing_queue_size: self.outgoing_queue.len(),
            incoming_queue_size: self.incoming_queue.len(),
        }
    }

    /// Clear all queued datagrams.
    pub fn clear(&mut self) {
        self.outgoing_queue.clear();
        self.incoming_queue.clear();
    }
}

/// Statistics about datagram usage.
#[derive(Debug, Clone, Copy)]
pub struct DatagramStats {
    /// Total number of datagrams sent.
    pub sent_count: u64,

    /// Total number of datagrams received.
    pub received_count: u64,

    /// Total bytes sent in datagram frames.
    pub sent_bytes: u64,

    /// Total bytes received in datagram frames.
    pub received_bytes: u64,

    /// Number of datagrams in outgoing queue.
    pub outgoing_queue_size: usize,

    /// Number of datagrams in incoming queue.
    pub incoming_queue_size: usize,
}

/// Legacy alias for backward compatibility.
/// This will be removed in future versions.
#[deprecated(note = "Use DatagramMap instead")]
pub type DataCenter = DatagramMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_map_new() {
        let map = DatagramMap::new();
        assert!(!map.is_enabled());
        assert_eq!(map.peer_max_datagram_frame_size(), 0);
        assert_eq!(
            map.local_max_datagram_frame_size(),
            MAX_DATAGRAM_SIZE as u64
        );
        assert!(!map.has_sendable_datagrams());
        assert!(!map.has_readable_datagrams());
    }

    #[test]
    fn datagram_enable_disable() {
        let mut map = DatagramMap::new();

        // Initially disabled
        assert!(!map.is_enabled());

        // Enable via peer max size
        map.set_peer_max_datagram_frame_size(1024);
        assert!(map.is_enabled());
        assert_eq!(map.peer_max_datagram_frame_size(), 1024);

        // Disable explicitly
        map.set_enabled(false);
        assert!(!map.is_enabled());
    }

    #[test]
    fn datagram_send_receive() {
        let mut map = DatagramMap::new();
        map.set_peer_max_datagram_frame_size(1024);

        // Send datagram
        let data = Bytes::from_static(b"Hello, DATAGRAM!");
        assert!(map.send_datagram(data.clone()).is_ok());
        assert!(map.has_sendable_datagrams());
        assert_eq!(map.outgoing_count(), 1);

        // Get next send datagram
        let item = map.next_send_datagram().unwrap();
        assert_eq!(item.data, data);
        assert!(item.with_length);
        assert!(!map.has_sendable_datagrams());

        // Receive datagram
        assert!(map
            .on_datagram_frame_received(Some(data.len() as u64), data.clone())
            .is_ok());
        assert!(map.has_readable_datagrams());
        assert_eq!(map.incoming_count(), 1);

        // Read datagram
        let received = map.recv_datagram().unwrap();
        assert_eq!(received, data);
        assert!(!map.has_readable_datagrams());
    }

    #[test]
    fn datagram_disabled() {
        let mut map = DatagramMap::new();
        // Don't enable datagrams

        let data = Bytes::from_static(b"test");
        assert_eq!(map.send_datagram(data.clone()), Err(Error::Done));
        assert_eq!(map.on_datagram_frame_received(None, data), Err(Error::Done));
    }

    #[test]
    fn datagram_stats() {
        let mut map = DatagramMap::new();
        map.set_peer_max_datagram_frame_size(1024);

        let data1 = Bytes::from_static(b"Hello");
        let data2 = Bytes::from_static(b"World");

        // Send and receive some datagrams
        map.send_datagram(data1.clone()).unwrap();
        map.send_datagram(data2.clone()).unwrap();
        map.next_send_datagram(); // Send first
        map.next_send_datagram(); // Send second

        map.on_datagram_frame_received(None, data1).unwrap();
        map.on_datagram_frame_received(None, data2).unwrap();

        let stats = map.stats();
        assert_eq!(stats.sent_count, 2);
        assert_eq!(stats.received_count, 2);
        assert_eq!(stats.sent_bytes, 10); // "Hello" + "World"
        assert_eq!(stats.received_bytes, 10);
        assert_eq!(stats.incoming_queue_size, 2);
        assert_eq!(stats.outgoing_queue_size, 0);
    }
}
