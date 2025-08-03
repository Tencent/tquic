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

//! QUIC Datagram Extension (RFC 9221) implementation.
//!
//! This module provides support for sending and receiving unreliable,
//! unordered datagrams over a QUIC connection.

use std::collections::VecDeque;

use bytes::Bytes;

use crate::error::Error;
use crate::frame::Frame;
use crate::Result;

/// Configuration for datagram support.
#[derive(Debug, Clone)]
pub struct DatagramConfig {
    /// Maximum size of a datagram frame that can be received.
    /// If None, datagram support is disabled.
    pub max_datagram_frame_size: Option<usize>,

    /// Maximum number of bytes to buffer for outgoing datagrams.
    pub send_buffer_size: usize,

    /// Maximum number of bytes to buffer for incoming datagrams.
    pub recv_buffer_size: usize,
}

impl Default for DatagramConfig {
    fn default() -> Self {
        Self {
            max_datagram_frame_size: None, // Disabled by default
            send_buffer_size: 1024 * 1024, // 1MB
            recv_buffer_size: 1024 * 1024, // 1MB
        }
    }
}

/// State for managing datagram sending and receiving.
#[derive(Debug)]
pub struct DatagramState {
    /// Configuration for datagram support.
    config: DatagramConfig,

    /// Queue of outgoing datagrams waiting to be sent.
    outgoing: VecDeque<Bytes>,

    /// Total size of data in the outgoing queue.
    outgoing_total_size: usize,

    /// Queue of incoming datagrams received from the peer.
    incoming: VecDeque<Bytes>,

    /// Total size of data in the incoming queue.
    incoming_total_size: usize,

    /// Whether the peer supports datagram frames.
    peer_supports_datagrams: bool,

    /// Maximum datagram frame size the peer can receive.
    peer_max_datagram_frame_size: Option<usize>,
}

impl DatagramState {
    /// Create a new datagram state with the given configuration.
    pub fn new(config: DatagramConfig) -> Self {
        Self {
            config,
            outgoing: VecDeque::new(),
            outgoing_total_size: 0,
            incoming: VecDeque::new(),
            incoming_total_size: 0,
            peer_supports_datagrams: false,
            peer_max_datagram_frame_size: None,
        }
    }

    /// Check if datagram support is enabled locally.
    pub fn is_enabled(&self) -> bool {
        self.config.max_datagram_frame_size.is_some()
    }

    /// Check if we can send datagrams to the peer.
    pub fn can_send_datagrams(&self) -> bool {
        self.is_enabled() && self.peer_supports_datagrams
    }

    /// Set the peer's datagram support capabilities.
    pub fn set_peer_capabilities(&mut self, max_datagram_frame_size: Option<u64>) {
        if let Some(size) = max_datagram_frame_size {
            self.peer_supports_datagrams = true;
            self.peer_max_datagram_frame_size = Some(size as usize);
        } else {
            self.peer_supports_datagrams = false;
            self.peer_max_datagram_frame_size = None;
        }
    }

    /// Get the maximum datagram payload size that can be sent.
    /// Returns None if datagrams are not supported.
    pub fn max_datagram_payload_size(&self, current_mtu: usize) -> Option<usize> {
        if !self.can_send_datagrams() {
            return None;
        }

        let peer_limit = self.peer_max_datagram_frame_size?;

        // Account for frame overhead:
        // - 1 byte for frame type (0x31)
        // - up to 8 bytes for length (varint encoding)
        let frame_overhead = 1 + 8;

        let mtu_limit = current_mtu.saturating_sub(frame_overhead);
        let peer_limit = peer_limit.saturating_sub(frame_overhead);

        Some(mtu_limit.min(peer_limit))
    }

    /// Queue a datagram for sending.
    /// Returns an error if the datagram is too large or if send buffer is full.
    pub fn send_datagram(&mut self, data: Bytes, drop_if_full: bool) -> Result<()> {
        if !self.is_enabled() {
            return Err(Error::DatagramError(
                "Datagram support is disabled locally".into(),
            ));
        }

        if !self.peer_supports_datagrams {
            return Err(Error::DatagramError(
                "Peer does not support datagrams".into(),
            ));
        }

        // Check if datagram fits in send buffer
        if self.outgoing_total_size + data.len() > self.config.send_buffer_size {
            if drop_if_full {
                // Drop old datagrams to make space
                while self.outgoing_total_size + data.len() > self.config.send_buffer_size {
                    if let Some(old_data) = self.outgoing.pop_front() {
                        self.outgoing_total_size -= old_data.len();
                    } else {
                        break;
                    }
                }
            } else {
                return Err(Error::DatagramError("Send buffer is full".into()));
            }
        }

        self.outgoing.push_back(data.clone());
        self.outgoing_total_size += data.len();
        Ok(())
    }

    /// Get the next datagram to send, if any.
    /// The caller should check max_datagram_payload_size before calling this.
    pub fn next_outgoing_datagram(&mut self, max_payload_size: usize) -> Option<Frame> {
        // Find a datagram that fits within the size limit
        while let Some(data) = self.outgoing.front() {
            if data.len() <= max_payload_size {
                let data = self.outgoing.pop_front().unwrap();
                self.outgoing_total_size -= data.len();
                return Some(Frame::Datagram { data });
            } else {
                // This datagram is too large, remove it
                let data = self.outgoing.pop_front().unwrap();
                self.outgoing_total_size -= data.len();
                // Continue to check the next datagram
            }
        }
        None
    }

    /// Handle a received datagram frame.
    pub fn handle_datagram_frame(&mut self, data: Bytes) -> Result<()> {
        if !self.is_enabled() {
            return Err(Error::ProtocolViolation);
        }

        // Check if the datagram fits in our configuration
        if let Some(max_size) = self.config.max_datagram_frame_size {
            if data.len() > max_size {
                return Err(Error::ProtocolViolation);
            }
        }

        // Drop old datagrams if receive buffer is full
        while self.incoming_total_size + data.len() > self.config.recv_buffer_size {
            if let Some(old_data) = self.incoming.pop_front() {
                self.incoming_total_size -= old_data.len();
            } else {
                break;
            }
        }

        self.incoming.push_back(data.clone());
        self.incoming_total_size += data.len();
        Ok(())
    }

    /// Receive a datagram, if any are available.
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        if let Some(data) = self.incoming.pop_front() {
            self.incoming_total_size -= data.len();
            Some(data)
        } else {
            None
        }
    }

    /// Get the number of bytes available in the send buffer.
    pub fn send_buffer_space(&self) -> usize {
        self.config
            .send_buffer_size
            .saturating_sub(self.outgoing_total_size)
    }

    /// Get the number of bytes available in the receive buffer.
    pub fn recv_buffer_space(&self) -> usize {
        self.config
            .recv_buffer_size
            .saturating_sub(self.incoming_total_size)
    }

    /// Check if there are outgoing datagrams to send.
    pub fn has_outgoing_datagrams(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Check if there are incoming datagrams to receive.
    pub fn has_incoming_datagrams(&self) -> bool {
        !self.incoming.is_empty()
    }

    /// Get the local max_datagram_frame_size transport parameter value.
    pub fn local_max_datagram_frame_size(&self) -> Option<u64> {
        self.config.max_datagram_frame_size.map(|size| size as u64)
    }

    /// Set the peer's max_datagram_frame_size capability.
    pub fn set_peer_max_datagram_frame_size(&mut self, peer_max_size: Option<u64>) {
        self.peer_max_datagram_frame_size = peer_max_size.map(|size| size as usize);
    }

    /// Get the next pending datagram to send.
    ///
    /// Returns None if no datagrams are pending or if sending is not enabled.
    pub fn get_pending_datagram(&mut self) -> Option<Bytes> {
        if !self.is_enabled() {
            return None;
        }

        if let Some(data) = self.outgoing.pop_front() {
            self.outgoing_total_size -= data.len();
            Some(data)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datagram_config_default() {
        let config = DatagramConfig::default();
        assert!(config.max_datagram_frame_size.is_none());
        assert_eq!(config.send_buffer_size, 1024 * 1024);
        assert_eq!(config.recv_buffer_size, 1024 * 1024);
    }

    #[test]
    fn test_datagram_state_disabled() {
        let config = DatagramConfig::default(); // disabled by default
        let mut state = DatagramState::new(config);

        assert!(!state.is_enabled());
        assert!(!state.can_send_datagrams());

        let data = Bytes::from("test");
        assert!(state.send_datagram(data, false).is_err());
    }

    #[test]
    fn test_datagram_state_enabled() {
        let config = DatagramConfig {
            max_datagram_frame_size: Some(1200),
            send_buffer_size: 4096,
            recv_buffer_size: 4096,
        };
        let mut state = DatagramState::new(config);

        assert!(state.is_enabled());
        assert!(!state.can_send_datagrams()); // peer not set yet

        // Set peer capabilities
        state.set_peer_capabilities(Some(1200));
        assert!(state.can_send_datagrams());

        // Test max payload size calculation
        let max_size = state.max_datagram_payload_size(1400);
        assert!(max_size.is_some());
        assert!(max_size.unwrap() <= 1200 - 9); // account for frame overhead
    }

    #[test]
    fn test_send_recv_datagram() {
        let config = DatagramConfig {
            max_datagram_frame_size: Some(1200),
            send_buffer_size: 4096,
            recv_buffer_size: 4096,
        };
        let mut state = DatagramState::new(config);
        state.set_peer_capabilities(Some(1200));

        // Send a datagram
        let data = Bytes::from("Hello, world!");
        assert!(state.send_datagram(data.clone(), false).is_ok());
        assert!(state.has_outgoing_datagrams());

        // Get the datagram for sending
        let frame = state.next_outgoing_datagram(1000);
        assert!(frame.is_some());

        if let Some(Frame::Datagram { data: frame_data }) = frame {
            assert_eq!(frame_data, data);
        } else {
            panic!("Expected datagram frame");
        }

        // Receive a datagram
        let recv_data = Bytes::from("Hello back!");
        assert!(state.handle_datagram_frame(recv_data.clone()).is_ok());
        assert!(state.has_incoming_datagrams());

        let received = state.recv_datagram();
        assert_eq!(received, Some(recv_data));
    }

    #[test]
    fn test_buffer_overflow() {
        let config = DatagramConfig {
            max_datagram_frame_size: Some(1200),
            send_buffer_size: 100, // small buffer
            recv_buffer_size: 100,
        };
        let mut state = DatagramState::new(config);
        state.set_peer_capabilities(Some(1200));

        // Fill the send buffer
        let data = Bytes::from(vec![0u8; 60]);
        assert!(state.send_datagram(data.clone(), false).is_ok());

        // This should fail because buffer is full
        assert!(state.send_datagram(data.clone(), false).is_err());

        // This should succeed with drop_if_full=true
        assert!(state.send_datagram(data, true).is_ok());
    }
}
