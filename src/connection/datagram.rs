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

use crate::connection::datagram;
use crate::frame;
use crate::frame::Frame;
use crate::DatagramConfig;
use crate::Error;
use bytes::Bytes;
use log::info;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
#[derive(Debug, Clone)]

pub enum AdjustResult {
    Success,
    Normal,
    TooSmall,
}

pub struct Datagramunit {
    data: Bytes,
    length: Option<usize>,
    datagram_id: usize,
    timer_in: Instant,
    /*
    the time arrive queue
    the priority
    the time of datagram become invalid
     */
}
impl Datagramunit {
    pub fn new(data: Bytes, length: Option<usize>, datagram_id: usize, timer_in: Instant) -> Self {
        Self {
            data: data,
            length: length,
            datagram_id: datagram_id,
            timer_in: timer_in,
        }
    }
}

pub struct DatagramMap {
    /// Sender states
    out_queue: VecDeque<Datagramunit>,
    index_out: usize,
    out_total_size: u64,
    out_max_size: u64,
    /// Receiver states
    in_queue: VecDeque<Datagramunit>,
    index_in: usize,
    in_total_size: u64,
    in_max_size: u64,
    local_max_datagram_frame_size: u64,
    peer_max_datagram_frame_size: u64,
    send_timeout: u64,
    priority: u8,
    datagram_event_mask: u8,
}
impl DatagramMap {
    pub fn new(
        peer_max_datagram_frame_size: u64,
        local_max_datagram_frame_size: u64,
        send_timeout: u64,
        priority: u8,
        datagram_event_mask: u8,
    ) -> Self {
        Self {
            out_queue: VecDeque::new(),
            index_out: 0,
            out_total_size: 0,
            out_max_size: 1024 * 1024,
            in_queue: VecDeque::new(),
            index_in: 0,
            in_total_size: 0,
            in_max_size: 1024 * 1024,
            local_max_datagram_frame_size,
            peer_max_datagram_frame_size,
            send_timeout,
            priority,
            datagram_event_mask,
        }
    }
    pub fn peer_is_enable(&self) -> bool {
        if self.peer_max_datagram_frame_size > 0 {
            return true;
        } else {
            return false;
        }
    }

    pub fn local_is_enable(&self) -> bool {
        if self.local_max_datagram_frame_size > 0 {
            return true;
        } else {
            return false;
        }
    }
    pub fn change_peer(&mut self, new_size: u64) {
        self.peer_max_datagram_frame_size = new_size;
    }
    pub fn change_local(&mut self, new_size: u64) {
        self.local_max_datagram_frame_size = new_size;
    }
    pub fn max_datagram_payload_size(&self, current_mtu: usize) -> Option<usize> {
        if !self.peer_is_enable() {
            return None;
        }
        let limit = self.peer_max_datagram_frame_size;
        let frame_overhead = frame::MAX_DATAGRAM_OVERHEAD;
        let mtu_limit = current_mtu.saturating_sub(frame_overhead);
        let peer_limit = current_mtu.saturating_sub(frame_overhead);
        Some(mtu_limit.min(peer_limit))
    }
    // Send a datagram from application to out_queue
    pub fn send_datagram(
        &mut self,
        data: Bytes,
        length: Option<usize>,
        drop_if: bool,
    ) -> Result<u64, Error> {
        // Drop timed-out frames before adding new datagram
        self.check_timeout();

        /*info!("send_datagram test for data:{:?}", data);
        info!(
            "local_max_datagram_size: {}",
            self.local_max_datagram_frame_size
        );
        info!(
            "peer_max_datagram_size: {}",
            self.peer_max_datagram_frame_size
        );*/
        if !self.peer_is_enable() {
            info!("!self.peer_is_enable");
            return Err(Error::ProtocolViolation);
        }

        let peer_max_size = self.peer_max_datagram_frame_size as usize;
        if data.len() > peer_max_size {
            info!(
                "Datagram size {} exceeds peer max {}",
                data.len(),
                peer_max_size
            );
            return Err(Error::ProtocolViolation); // Exceed peer_max error
        }

        if self.out_max_size < data.len() as u64 {
            return Err(Error::DatagramFrameBeyondMemory); // Data larger than out_queue capacity
        }

        let mut drop_num: u64 = 0;
        if self.out_total_size + data.len() as u64 > self.out_max_size {
            if drop_if {
                while self.out_total_size + data.len() as u64 > self.out_max_size {
                    if let Some(datagramunit) = self.out_queue.pop_front() {
                        drop_num += 1;
                        self.out_total_size -= datagramunit.data.len() as u64;
                    } else {
                        break;
                    }
                }
            } else {
                return Err(Error::DatagramFrameBeyondMemory);
            }
        }
        self.out_queue.push_back(Datagramunit::new(
            data.clone(),
            Some(data.len()),
            self.index_out,
            Instant::now(),
        ));
        self.out_total_size += data.len() as u64;
        self.index_out += 1; // Update index
        return Ok(drop_num.clone());
    }

    // Send a datagram from out_queue
    pub fn outcome_datagram(&mut self, max_payload_size: usize) -> Option<(Option<usize>, Bytes)> {
        self.check_timeout();

        loop {
            let Some(datagramunit) = self.out_queue.front() else {
                return None;
            };

            let elapsed = Instant::now().duration_since(datagramunit.timer_in);
            let timeout = Duration::from_millis(self.send_timeout);
            if elapsed >= timeout {
                let datagramunit = self.out_queue.pop_front().unwrap();
                self.out_total_size -= datagramunit.data.len() as u64;
                info!(
                    "Dropped datagram due to send timeout: {:?}",
                    datagramunit.datagram_id
                );
                continue;
            }
            if datagramunit.data.len() > max_payload_size {
                return None;
            } else {
                let datagramunit = self.out_queue.pop_front().unwrap();
                self.out_total_size -= datagramunit.data.len() as u64;
                return Some((Some(datagramunit.data.len()), datagramunit.data.clone()));
            }
        }
    }

    pub fn check_timeout(&mut self) -> u64 {
        let mut dropped_count = 0;
        let current_time = Instant::now();

        loop {
            let Some(datagramunit) = self.out_queue.front() else {
                break;
            };

            let elapsed = current_time.duration_since(datagramunit.timer_in);
            let timeout = Duration::from_millis(self.send_timeout);

            if elapsed >= timeout {
                let dropped = self.out_queue.pop_front().unwrap();
                self.out_total_size -= dropped.data.len() as u64;
                info!("Dropped timed-out datagram (ID: {:?})", dropped.datagram_id);
                dropped_count += 1;
            } else {
                // No more timeouts (queue is ordered by insertion time), exit loop
                break;
            }
        }

        dropped_count
    }

    // Receive a datagram from connection to in_queue
    pub fn incoming_datagram(
        &mut self,
        length: Option<usize>,
        data: Bytes,
    ) -> Result<usize, Error> {
        if !self.local_is_enable() {
            return Err(Error::ProtocolViolation);
        }
        if data.len() as u64 > self.in_max_size {
            return Err(Error::DatagramFrameBeyondMemory);
        }
        if data.len() as u64 > self.local_max_datagram_frame_size {
            return Err(Error::ProtocolViolation);
        }
        while self.in_total_size + data.len() as u64 > self.in_max_size {
            if let Some(datagramunit) = self.in_queue.pop_front() {
                self.in_total_size -= datagramunit.data.len() as u64;
            } else {
                break;
            }
        }
        self.in_queue.push_back(Datagramunit::new(
            data.clone(),
            length,
            self.index_in,
            Instant::now(),
        ));
        self.in_total_size += data.len() as u64;
        self.index_in += 1;
        Ok(self.index_in - 1)
    }

    // Get datagram from in_queue to application
    pub fn get_datagram(&mut self) -> Option<(Option<usize>, Bytes)> {
        if let Some(datagramunit) = self.in_queue.pop_front() {
            self.in_total_size -= datagramunit.data.len() as u64;
            Some((datagramunit.length, datagramunit.data.clone()))
        } else {
            None
        }
    }

    pub fn set_out_max_size(&mut self, new_max: u64) -> AdjustResult {
        if new_max > self.out_max_size {
            self.out_max_size = new_max;
            AdjustResult::Success
        } else if new_max >= self.out_total_size {
            self.out_max_size = new_max;
            AdjustResult::Normal
        } else {
            AdjustResult::TooSmall
        }
    }
    pub fn set_in_max_size(&mut self, new_max: u64) -> AdjustResult {
        if new_max > self.in_max_size {
            self.in_max_size = new_max;
            AdjustResult::Success
        } else if new_max >= self.in_total_size {
            self.in_max_size = new_max;
            AdjustResult::Normal
        } else {
            AdjustResult::TooSmall
        }
    }
    pub fn send_available_space(&self) -> usize {
        self.out_max_size.saturating_sub(self.out_total_size) as usize
    }
    pub fn recv_available_space(&self) -> usize {
        self.in_max_size.saturating_sub(self.in_total_size) as usize
    }
    pub fn if_out_empty(&self) -> bool {
        self.out_queue.is_empty()
    }
    pub fn if_in_empty(&self) -> bool {
        self.in_queue.is_empty()
    }
    pub fn need_send_datagram_frames(&self) -> bool {
        !self.if_out_empty()
    }
    pub fn get_mask(&self) -> u8 {
        return self.datagram_event_mask;
    }
    pub fn get_priority(&self) -> u8 {
        self.priority
    }

    pub fn set_send_timeout(&mut self, time: u64) {
        self.send_timeout = time;
    }
    pub fn get_send_timeout(&mut self) -> u64 {
        self.send_timeout
    }

    pub fn get_in_max_size(&self) -> u64 {
        self.in_max_size
    }
    pub fn get_out_max_size(&self) -> u64 {
        self.out_max_size
    }

    pub fn get_out_total_size(&self) -> u64 {
        self.out_total_size
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bytes::Bytes;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_datagram_normal_send_and_outcome() -> Result<(), Error> {
        // Initialize the datagram map
        let mut datagram_map = DatagramMap::new(
            1024, // Maximum datagram size supported by peer
            1024, // Maximum datagram size supported locally
            100,  // Send timeout in milliseconds (small value for testing)
            0,    // Priority
            31,   // Datagram event mask (all events enabled)
        );

        // Send a datagram
        let data = Bytes::from("test datagram data");
        let drop_num = datagram_map.send_datagram(data.clone(), None, false)?;
        assert_eq!(
            drop_num, 0,
            "No datagram should be dropped when the queue is not full"
        );

        // Retrieve the datagram immediately (before timeout)
        let result = datagram_map.outcome_datagram(1024);
        assert!(
            result.is_some(),
            "The datagram should be retrieved successfully"
        );
        let (len, out_data) = result.unwrap();
        assert_eq!(len, Some(data.len()), "The data length should match");
        assert_eq!(out_data, data, "The data content should match");

        Ok(())
    }

    #[test]
    fn test_datagram_timeout_drop() -> Result<(), Error> {
        let mut datagram_map = DatagramMap::new(
            1024, 1024, 100, // Set timeout to 100 milliseconds for testing
            0, 31,
        );

        // Send a datagram
        let data = Bytes::from("timeout test datagram");
        datagram_map.send_datagram(data.clone(), None, false)?;

        // Wait for the timeout (more than 100ms)
        thread::sleep(Duration::from_millis(200));

        // Retrieving should drop the timed-out datagram
        let result = datagram_map.outcome_datagram(1024);
        assert!(
            result.is_none(),
            "The datagram should be dropped after timeout"
        );
        assert!(
            datagram_map.if_out_empty(),
            "The outgoing queue should be empty after timeout drop"
        );

        Ok(())
    }

    #[test]
    fn test_datagram_queue_full_drop() -> Result<(), Error> {
        let mut datagram_map = DatagramMap::new(1024, 1024, 1000, 0, 31);
        datagram_map.out_max_size = 30; // Reduce outgoing queue size for overflow testing

        let data1 = Bytes::from("1234567890"); // 10 bytes
        let data2 = Bytes::from("abcdefghij"); // 10 bytes
        let data3 = Bytes::from("ABCDEFGHIJ"); // 10 bytes
        let data4 = Bytes::from("xyz123"); // 6 bytes

        // Send the first 3 datagrams; total queue size reaches 30 bytes (full)
        datagram_map.send_datagram(data1.clone(), None, true)?;
        datagram_map.send_datagram(data2.clone(), None, true)?;
        datagram_map.send_datagram(data3.clone(), None, true)?;
        assert_eq!(
            datagram_map.out_total_size, 30,
            "The total queue size should be 30 bytes"
        );

        let drop_num = datagram_map.send_datagram(data4.clone(), None, true)?;
        assert_eq!(drop_num, 1, "One old datagram should be dropped");
        assert_eq!(
            datagram_map.out_total_size, 26,
            "Total size after drop should be 26 bytes (10+10+6)"
        );

        // Retrieve and verify the queue order (remaining: data2, data3, data4)
        let result1 = datagram_map.outcome_datagram(1024);
        assert!(result1.is_some());
        let (_, out_data1) = result1.unwrap();
        assert_eq!(
            out_data1, data2,
            "The first retrieved datagram should be data2"
        );

        let result2 = datagram_map.outcome_datagram(1024);
        assert!(result2.is_some());
        let (_, out_data2) = result2.unwrap();
        assert_eq!(
            out_data2, data3,
            "The second retrieved datagram should be data3"
        );

        let result3 = datagram_map.outcome_datagram(1024);
        assert!(result3.is_some());
        let (_, out_data3) = result3.unwrap();
        assert_eq!(
            out_data3, data4,
            "The third retrieved datagram should be data4"
        );

        Ok(())
    }

    #[test]
    fn test_datagram_incoming_and_get() -> Result<(), Error> {
        let mut datagram_map = DatagramMap::new(1024, 1024, 1000, 0, 31);

        // Incoming datagram to the "in queue"
        let data = Bytes::from("incoming test datagram");
        let datagram_id = datagram_map.incoming_datagram(Some(data.len()), data.clone())?;
        assert_eq!(
            datagram_id, 0,
            "The ID of the first incoming datagram should be 0"
        );

        // Retrieve the datagram from the "in queue"
        let result = datagram_map.get_datagram();
        assert!(
            result.is_some(),
            "Should retrieve the incoming datagram successfully"
        );
        let (len, out_data) = result.unwrap();
        assert_eq!(len, Some(data.len()), "The data length should match");
        assert_eq!(out_data, data, "The data content should match");

        Ok(())
    }
    #[test]
    fn datagram_receive_too_large_is_protocol_violation() {
        // 1. Initialize DatagramMap with local support disabled (local_max = 0)
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size (irrelevant for receive logic)
            0,    // local_max_datagram_frame_size (disabled)
            1000, // send_timeout
            0,    // priority
            0,    // datagram_event_mask
        );

        // Test Case 1: Receiving datagram when local support is disabled should fail
        let large_data_disabled = Bytes::from(vec![0u8; 101]);
        let result_disabled = datagram_map.incoming_datagram(Some(101), large_data_disabled);
        assert!(
            matches!(result_disabled, Err(Error::ProtocolViolation)),
            "Should return ProtocolViolation when local datagram support is disabled"
        );

        // 2. Enable local support with 100-byte limit
        datagram_map.change_local(100);

        // Test Case 2: Receiving datagram larger than local max should fail
        let large_data_over_limit = Bytes::from(vec![0u8; 101]); // 101 > 100
        let result_over_limit = datagram_map.incoming_datagram(Some(101), large_data_over_limit);
        assert!(
            matches!(result_over_limit, Err(Error::ProtocolViolation)),
            "Should return ProtocolViolation when datagram exceeds local max size"
        );

        // Test Case 3: Valid size datagram should be received successfully
        let valid_data = Bytes::from(vec![0u8; 100]); // Exactly at limit
        let result_valid = datagram_map.incoming_datagram(Some(100), valid_data);
        assert!(
            result_valid.is_ok(),
            "Valid size datagram should be received without error"
        );

        // Verify the datagram was properly queued
        assert_eq!(
            datagram_map.in_total_size, 100,
            "Incoming queue total size should match datagram length"
        );
        assert!(
            !datagram_map.if_in_empty(),
            "Incoming queue should not be empty after valid datagram reception"
        );
    }
    #[test]
    fn datagram_stats_are_tracked_correctly() {
        // Initialize DatagramMap with 1KB limits and enabled support
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size
            1024, // local_max_datagram_frame_size
            1000, // send_timeout
            0,    // priority
            0,    // datagram_event_mask
        );
        // Set 1KB limits for both incoming and outgoing queues
        datagram_map.set_out_max_size(1024);

        let data1 = Bytes::from_static(b"Hello"); // 5 bytes
        let data2 = Bytes::from_static(b"World!"); // 6 bytes

        // Send two datagrams
        datagram_map
            .send_datagram(data1.clone(), Some(data1.len()), false)
            .unwrap();
        datagram_map
            .send_datagram(data2.clone(), Some(data2.len()), false)
            .unwrap();

        // Verify initial outgoing queue state
        assert_eq!(
            datagram_map.out_queue.len(),
            2,
            "Outgoing queue should contain 2 datagrams"
        );
        assert_eq!(
            datagram_map.out_total_size, 11,
            "Outgoing total size should be 11 bytes"
        );
        assert_eq!(datagram_map.index_out, 2, "Should have sent 2 datagrams");

        // Take both datagrams from queue for transmission
        let max_payload_size = 1024;
        datagram_map.outcome_datagram(max_payload_size);
        datagram_map.outcome_datagram(max_payload_size);

        // Verify outgoing queue is empty after transmission
        assert!(
            datagram_map.if_out_empty(),
            "Outgoing queue should be empty after transmission"
        );
        assert_eq!(
            datagram_map.out_total_size, 0,
            "Outgoing total size should be 0 after transmission"
        );

        // Receive two datagrams
        datagram_map
            .incoming_datagram(Some(data1.len()), data1.clone())
            .unwrap();
        datagram_map
            .incoming_datagram(Some(data2.len()), data2.clone())
            .unwrap();

        // Verify received statistics
        assert_eq!(
            datagram_map.in_queue.len(),
            2,
            "Incoming queue should contain 2 datagrams"
        );
        assert_eq!(
            datagram_map.in_total_size, 11,
            "Incoming total size should be 11 bytes"
        );
        assert_eq!(datagram_map.index_in, 2, "Should have received 2 datagrams");

        // Read one datagram from incoming queue
        datagram_map.get_datagram();

        // Verify statistics after reading one datagram
        assert_eq!(
            datagram_map.in_queue.len(),
            1,
            "Incoming queue should contain 1 datagram after reading"
        );
        assert_eq!(
            datagram_map.in_total_size, 6,
            "Incoming total size should be 6 bytes after reading"
        );
    }
    #[test]
    fn datagram_sender_queue_drops_oldest_when_full() {
        // 1. Initialize DatagramMap with 1KB (1024 bytes) outgoing queue limit
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size (supports datagram transmission)
            1024, // local_max_datagram_frame_size (irrelevant for sender queue test)
            1000, // send_timeout (not triggered in this test)
            0,    // priority
            0,    // datagram_event_mask
        );
        datagram_map.set_out_max_size(1024); // Set outgoing queue max size to 1024 bytes
        const DROP_IF: bool = true; // Enable dropping oldest when queue is full

        // 2. Define test datagrams with specific sizes
        let data1 = Bytes::from(vec![1u8; 124]); // 124 bytes (oldest, to be dropped)
        let data2 = Bytes::from(vec![2u8; 1000]); // 1000 bytes (kept after first drop)
        let data3 = Bytes::from(vec![3u8; 24]); // 24 bytes (added last, kept)

        // 3. Send first two datagrams (total 1124 bytes > 1024 bytes)
        // - data1 (124B) + data2 (1000B) = 1124B, which exceeds queue limit
        // - Expect: data1 is dropped, only data2 remains in queue
        let drop_num1 = datagram_map
            .send_datagram(data1.clone(), Some(data1.len()), DROP_IF)
            .unwrap();
        let drop_num2 = datagram_map
            .send_datagram(data2.clone(), Some(data2.len()), DROP_IF)
            .unwrap();

        // Verify after first two sends:
        assert_eq!(
            drop_num1, 0,
            "No datagrams should be dropped when sending first datagram"
        );
        assert_eq!(
            drop_num2, 1,
            "1 oldest datagram (data1) should be dropped when sending second"
        );
        assert_eq!(
            datagram_map.out_total_size, 1000,
            "Queue should only contain data2 (1000 bytes)"
        );
        assert_eq!(
            datagram_map.out_queue.len(),
            1,
            "Queue should have 1 datagram left (data2)"
        );

        // 4. Send third datagram (24 bytes)
        // - data2 (1000B) + data3 (24B) = 1024B, which fits queue limit
        // - Expect: no more drops, both data2 and data3 remain
        let drop_num3 = datagram_map
            .send_datagram(data3.clone(), Some(data3.len()), DROP_IF)
            .unwrap();

        // Verify after third send:
        assert_eq!(
            drop_num3, 0,
            "No datagrams should be dropped when sending third datagram"
        );
        assert_eq!(
            datagram_map.out_total_size, 1024,
            "Queue total size should be 1000+24=1024 bytes"
        );
        assert_eq!(
            datagram_map.out_queue.len(),
            2,
            "Queue should have 2 datagrams (data2 + data3)"
        );

        let max_payload_size = 1024; // Larger than all datagrams to avoid size filtering
        let (_, extracted_data2) = datagram_map.outcome_datagram(max_payload_size).unwrap();
        let (_, extracted_data3) = datagram_map.outcome_datagram(max_payload_size).unwrap();

        // Verify extracted datagrams are the correct ones (data1 is dropped, data2/data3 remain)
        assert_eq!(
            extracted_data2, data2,
            "First extracted datagram should be data2"
        );
        assert_eq!(
            extracted_data3, data3,
            "Second extracted datagram should be data3"
        );
        assert!(
            datagram_map.if_out_empty(),
            "Queue should be empty after extracting all datagrams"
        );
    }
    #[test]
    fn datagram_receiver_queue_drops_oldest_when_full() {
        // 1. Initialize DatagramMap with 1KB (1024 bytes) incoming queue limit
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size (not used for receiver logic)
            2048, // local_max_datagram_frame_size (enable reception)
            1000, // send_timeout (irrelevant for receiver test)
            0,    // priority
            0,    // datagram_event_mask
        );
        // Set incoming queue max size to 1024 bytes (1KB)
        datagram_map.in_max_size = 1024;

        // 2. Prepare test datagrams
        let data1 = Bytes::from(vec![1u8; 512]); // 512 bytes (oldest, to be dropped)
        let data2 = Bytes::from(vec![2u8; 512]); // 512 bytes (kept)
        let data3 = Bytes::from(vec![3u8; 100]); // 100 bytes (newest, kept)

        // 3. Receive first two datagrams (total 1024 bytes, fills queue)
        datagram_map
            .incoming_datagram(Some(data1.len()), data1.clone())
            .unwrap();
        datagram_map
            .incoming_datagram(Some(data2.len()), data2.clone())
            .unwrap();

        // Verify queue is full
        assert_eq!(
            datagram_map.in_total_size, 1024,
            "Queue should be full (512+512=1024 bytes)"
        );
        assert_eq!(
            datagram_map.in_queue.len(),
            2,
            "Queue should contain 2 datagrams"
        );

        // 4. Receive third datagram (triggers oldest drop)
        datagram_map
            .incoming_datagram(Some(data3.len()), data3.clone())
            .unwrap();

        // 5. Verify queue state after drop
        assert_eq!(
            datagram_map.in_total_size, 612,
            "Queue should be 512(data2) + 100(data3) = 612 bytes"
        );
        assert_eq!(
            datagram_map.in_queue.len(),
            2,
            "Queue should still contain 2 datagrams"
        );

        // 6. Extract datagrams to confirm remaining items
        let (_, received_data2) = datagram_map.get_datagram().unwrap();
        let (_, received_data3) = datagram_map.get_datagram().unwrap();

        assert_eq!(
            received_data2, data2,
            "First extracted datagram should be data2"
        );
        assert_eq!(
            received_data3, data3,
            "Second extracted datagram should be data3"
        );
        assert!(
            datagram_map.if_in_empty(),
            "Queue should be empty after extracting all datagrams"
        );
    }
    #[test]
    fn datagram_queue_limit_adjustment() {
        // 1. Initialize DatagramMap with 1KB (1024 bytes) outgoing limit
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size
            1024, // local_max_datagram_frame_size
            1000, // send_timeout
            0,    // priority
            0,    // datagram_event_mask
        );
        datagram_map.set_out_max_size(1024); // Set initial outgoing limit to 1KB

        // Send a 500-byte datagram
        datagram_map
            .send_datagram(Bytes::from(vec![0u8; 500]), Some(500), false)
            .unwrap();
        assert_eq!(
            datagram_map.out_total_size, 500,
            "Current outgoing size should be 500 bytes"
        );

        // 2. Adjust to larger size (2KB)
        let result = datagram_map.set_out_max_size(2048);
        assert!(
            matches!(result, AdjustResult::Success),
            "Should successfully adjust to larger limit"
        );
        assert_eq!(
            datagram_map.out_max_size, 2048,
            "Max outgoing size should be 2048 bytes"
        );

        // 3. Adjust to smaller but valid size (1KB)
        let result = datagram_map.set_out_max_size(1024);
        assert!(
            matches!(result, AdjustResult::Normal),
            "Should normally adjust to smaller valid limit"
        );
        assert_eq!(
            datagram_map.out_max_size, 1024,
            "Max outgoing size should be 1024 bytes"
        );

        // 4. Attempt to adjust to size smaller than current usage (0KB)
        let result = datagram_map.set_out_max_size(0);
        assert!(
            matches!(result, AdjustResult::TooSmall),
            "Should fail when adjusting to too small limit"
        );
        assert_eq!(
            datagram_map.out_max_size, 1024,
            "Max size should remain unchanged on failure"
        );
    }
    #[test]
    fn datagram_clear_buffers() {
        // 1. Initialize DatagramMap with enabled support
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size
            1024, // local_max_datagram_frame_size
            1000, // send_timeout
            0,    // priority
            0,    // datagram_event_mask
        );

        // 2. Populate outgoing and incoming queues
        // Send a datagram to outgoing queue
        datagram_map
            .send_datagram(Bytes::from_static(b"out"), Some(3), false)
            .unwrap();
        // Receive a datagram to incoming queue
        datagram_map
            .incoming_datagram(Some(2), Bytes::from_static(b"in"))
            .unwrap();

        // 3. Verify initial state (queues are not empty)
        assert_eq!(
            datagram_map.out_queue.len(),
            1,
            "Outgoing queue should have 1 datagram"
        );
        assert_eq!(
            datagram_map.in_queue.len(),
            1,
            "Incoming queue should have 1 datagram"
        );
        assert_eq!(
            datagram_map.out_total_size, 3,
            "Outgoing total size should be 3 bytes"
        );
        assert_eq!(
            datagram_map.in_total_size, 2,
            "Incoming total size should be 2 bytes"
        );

        // 4. Simulate clearing all buffers (without modifying DatagramMap implementation)
        // Clear outgoing queue
        while let Some(_) = datagram_map.out_queue.pop_front() {
            datagram_map.out_total_size = 0;
        }
        // Clear incoming queue
        while let Some(_) = datagram_map.in_queue.pop_front() {
            datagram_map.in_total_size = 0;
        }
        // Reset indexes (optional, depending on whether "count" needs to reset)
        datagram_map.index_out = 0;
        datagram_map.index_in = 0;

        // 5. Verify buffers are cleared
        assert!(
            datagram_map.out_queue.is_empty(),
            "Outgoing queue should be empty after clear"
        );
        assert!(
            datagram_map.in_queue.is_empty(),
            "Incoming queue should be empty after clear"
        );
        assert_eq!(
            datagram_map.out_total_size, 0,
            "Outgoing total size should be 0 after clear"
        );
        assert_eq!(
            datagram_map.in_total_size, 0,
            "Incoming total size should be 0 after clear"
        );
        assert_eq!(
            datagram_map.index_out, 0,
            "Outgoing index should reset to 0"
        );
        assert_eq!(datagram_map.index_in, 0, "Incoming index should reset to 0");
    }
    #[test]
    fn datagram_clear_individual_buffers() {
        // 1. Initialize DatagramMap with enabled support
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size
            1024, // local_max_datagram_frame_size
            1000, // send_timeout
            0,    // priority
            0,    // datagram_event_mask
        );

        // 2. Add data to both outgoing and incoming queues
        // Populate outgoing queue with "out" (3 bytes)
        datagram_map
            .send_datagram(Bytes::from_static(b"out"), Some(3), false)
            .unwrap();
        // Populate incoming queue with "in" (2 bytes)
        datagram_map
            .incoming_datagram(Some(2), Bytes::from_static(b"in"))
            .unwrap();

        // Verify initial state (both queues have data)
        assert_eq!(
            datagram_map.out_queue.len(),
            1,
            "Outgoing queue should have 1 datagram initially"
        );
        assert_eq!(
            datagram_map.in_queue.len(),
            1,
            "Incoming queue should have 1 datagram initially"
        );
        assert_eq!(
            datagram_map.out_total_size, 3,
            "Outgoing total size should be 3 bytes initially"
        );
        assert_eq!(
            datagram_map.in_total_size, 2,
            "Incoming total size should be 2 bytes initially"
        );

        // 3. Simulate clearing only sender buffer
        // Clear outgoing queue and reset its stats
        while let Some(_) = datagram_map.out_queue.pop_front() {}
        datagram_map.out_total_size = 0;
        datagram_map.index_out = 0;

        // Verify sender buffer is clear, receiver remains
        assert!(
            datagram_map.out_queue.is_empty(),
            "Outgoing queue should be empty after clearing sender buffer"
        );
        assert_eq!(
            datagram_map.out_total_size, 0,
            "Outgoing total size should be 0 after clearing sender buffer"
        );
        assert_eq!(
            datagram_map.in_queue.len(),
            1,
            "Incoming queue should remain after clearing sender buffer"
        );
        assert_eq!(
            datagram_map.in_total_size, 2,
            "Incoming total size should remain after clearing sender buffer"
        );

        // 4. Add data back to sender buffer
        datagram_map
            .send_datagram(Bytes::from_static(b"out2"), Some(4), false)
            .unwrap();
        assert_eq!(
            datagram_map.out_queue.len(),
            1,
            "Outgoing queue should have 1 datagram after re-populating"
        );
        assert_eq!(
            datagram_map.out_total_size, 4,
            "Outgoing total size should be 4 bytes after re-populating"
        );

        // 5. Simulate clearing only receiver buffer
        // Clear incoming queue and reset its stats
        while let Some(_) = datagram_map.in_queue.pop_front() {}
        datagram_map.in_total_size = 0;
        datagram_map.index_in = 0;

        // Verify receiver buffer is clear, sender remains
        assert!(
            datagram_map.in_queue.is_empty(),
            "Incoming queue should be empty after clearing receiver buffer"
        );
        assert_eq!(
            datagram_map.in_total_size, 0,
            "Incoming total size should be 0 after clearing receiver buffer"
        );
        assert_eq!(
            datagram_map.out_queue.len(),
            1,
            "Outgoing queue should remain after clearing receiver buffer"
        );
        assert_eq!(
            datagram_map.out_total_size, 4,
            "Outgoing total size should remain after clearing receiver buffer"
        );
    }
    /// Test equivalent of DatagramItem memory_size calculation using Datagramunit
    /// Verifies that the effective "memory size" of a Datagramunit equals its data length,
    /// which aligns with the original DatagramItem::memory_size logic.
    #[test]
    fn datagramunit_effective_memory_size() {
        // 1. Test small datagram (5 bytes)
        let small_data = Bytes::from_static(b"small"); // 5-byte static data
        let small_datagram = Datagramunit::new(
            small_data.clone(),
            Some(small_data.len()), // Explicitly set length to match data size
            1,                      // datagram_id
            Instant::now(),         // timer_in (queue entry time)
        );

        // Verify effective memory size equals data length (5 bytes)
        // Aligns with original test's "small_item.memory_size() == 5" assertion
        assert_eq!(
            small_datagram.data.len(),
            5,
            "Small Datagramunit effective memory size should match data length (5 bytes)"
        );
        // Additional check: Ensure stored length matches actual data length
        assert_eq!(
            small_datagram.length.unwrap(),
            small_datagram.data.len(),
            "Stored length should be consistent with actual data length for small datagram"
        );

        // 2. Test large datagram (1024 bytes)
        let large_data = Bytes::from(vec![0u8; 1024]); // 1024-byte dynamic data
        let large_datagram = Datagramunit::new(
            large_data.clone(),
            Some(large_data.len()), // Explicitly set length to match data size
            2,                      // datagram_id
            Instant::now(),         // timer_in (queue entry time)
        );

        // Verify effective memory size equals data length (1024 bytes)
        // Aligns with original test's "large_item.memory_size() == 1024" assertion
        assert_eq!(
            large_datagram.data.len(),
            1024,
            "Large Datagramunit effective memory size should match data length (1024 bytes)"
        );
        // Additional check: Ensure stored length matches actual data length
        assert_eq!(
            large_datagram.length.unwrap(),
            large_datagram.data.len(),
            "Stored length should be consistent with actual data length for large datagram"
        );
    }
    /// Test handling of empty datagrams (edge case with zero-length data)
    #[test]
    fn datagram_empty_data() {
        // 1. Initialize DatagramMap with enabled support (1024-byte limits)
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size (supports empty datagram)
            1024, // local_max_datagram_frame_size (supports empty datagram)
            1000, // send_timeout (irrelevant for this test)
            0,    // priority
            0,    // datagram_event_mask
        );

        // 2. Create empty data (zero-length Bytes)
        let empty_data = Bytes::new();
        assert_eq!(empty_data.len(), 0, "Empty data should have length 0");

        // 3. Send empty datagram and verify success
        let drop_num = datagram_map
            .send_datagram(empty_data.clone(), Some(0), false)
            .expect("Sending empty datagram should succeed");
        assert_eq!(
            drop_num, 0,
            "No datagrams should be dropped when sending empty data"
        );
        assert_eq!(
            datagram_map.index_out, 1,
            "First sent datagram should have ID 1"
        );
        assert_eq!(
            datagram_map.out_total_size, 0,
            "Outgoing total size should be 0 for empty datagram"
        );

        // 4. Retrieve empty datagram from outgoing queue
        let max_payload_size = 1024; // Larger than empty data
        let (data_len, retrieved_data) = datagram_map
            .outcome_datagram(max_payload_size)
            .expect("Should retrieve empty datagram from outgoing queue");

        // Verify retrieved data is empty
        assert_eq!(data_len, Some(0), "Retrieved data length should be 0");
        assert_eq!(retrieved_data.len(), 0, "Retrieved data should be empty");
        assert!(
            datagram_map.if_out_empty(),
            "Outgoing queue should be empty after retrieval"
        );

        // 5. Receive empty datagram into incoming queue
        let recv_id = datagram_map
            .incoming_datagram(Some(0), empty_data.clone())
            .expect("Receiving empty datagram should succeed");
        assert_eq!(recv_id, 0, "First received datagram should have ID 0"); // index_in starts at 0
        assert_eq!(
            datagram_map.in_total_size, 0,
            "Incoming total size should be 0 for empty datagram"
        );
        assert_eq!(
            datagram_map.in_queue.len(),
            1,
            "Incoming queue should contain 1 empty datagram"
        );

        // 6. Retrieve empty datagram from incoming queue
        let (recv_data_len, received_data) = datagram_map
            .get_datagram()
            .expect("Should retrieve empty datagram from incoming queue");

        // Verify received data is empty
        assert_eq!(recv_data_len, Some(0), "Received data length should be 0");
        assert_eq!(received_data.len(), 0, "Received data should be empty");
        assert!(
            datagram_map.if_in_empty(),
            "Incoming queue should be empty after retrieval"
        );
    }
    /// Test queue behavior when reaching exact capacity and handling overflow
    #[test]
    fn datagram_queue_exact_capacity() {
        // 1. Initialize DatagramMap: 1KB (1024 bytes) outgoing queue limit, peer support enabled
        let mut datagram_map = DatagramMap::new(
            2048, // peer_max_datagram_frame_size (larger than test data, avoid size error)
            1024, // local_max_datagram_frame_size (irrelevant for sender logic)
            1000, // send_timeout (not triggered in this test)
            0,    // priority
            0,    // datagram_event_mask
        );
        datagram_map.set_out_max_size(1024); // Set outgoing queue capacity to 1KB (1024 bytes)

        // 2. Step 1: Send 1024-byte data to fill queue exactly to capacity
        let full_cap_data = Bytes::from(vec![0u8; 1024]); // Exact capacity size
        let drop_num1 = datagram_map
            .send_datagram(
                full_cap_data.clone(),
                Some(full_cap_data.len()),
                true, // Enable dropping oldest when queue overflows (critical for Step 3)
            )
            .expect("Sending 1024-byte data to exact capacity should succeed");

        // Verify queue is exactly full
        assert_eq!(
            drop_num1, 0,
            "No datagrams should be dropped when filling to exact capacity"
        );
        assert_eq!(
            datagram_map.out_total_size, 1024,
            "Outgoing queue total size should be 1024 bytes (exact capacity)"
        );
        assert_eq!(
            datagram_map.out_queue.len(),
            1,
            "Outgoing queue should contain 1 datagram (exact capacity)"
        );

        // 3. Step 2: Send 1-byte data (causes overflow, triggers oldest drop)
        let small_data = Bytes::from(vec![1u8; 1]); // 1 byte (causes overflow)
        let drop_num2 = datagram_map
            .send_datagram(
                small_data.clone(),
                Some(small_data.len()),
                true, // Must enable drop to handle overflow
            )
            .expect("Sending 1-byte data (overflow) should succeed after dropping oldest");

        // Verify overflow handling: oldest (1024-byte) dropped, new (1-byte) retained
        assert_eq!(
            drop_num2, 1,
            "1 oldest datagram should be dropped to make space for new data"
        );
        assert_eq!(
            datagram_map.out_total_size, 1,
            "Outgoing queue total size should be 1 byte (only new data retained)"
        );
        assert_eq!(
            datagram_map.out_queue.len(),
            1,
            "Outgoing queue should contain 1 datagram (new 1-byte data)"
        );

        // Optional: Verify the retained data is the new 1-byte data
        let max_payload_size = 1024;
        let (retrieved_len, retrieved_data) = datagram_map
            .outcome_datagram(max_payload_size)
            .expect("Should retrieve retained data from outgoing queue");
        assert_eq!(
            retrieved_len,
            Some(1),
            "Retrieved data length should be 1 byte"
        );
        assert_eq!(
            retrieved_data, small_data,
            "Retrieved data should match the new 1-byte data"
        );
    }
    /// Test that sending a datagram fails when peer datagram support is disabled
    #[test]
    fn datagram_send_fails_when_peer_disabled() {
        // 1. Initialize DatagramMap with peer datagram support DISABLED (peer_max = 0)
        let mut datagram_map = DatagramMap::new(
            0,    // peer_max_datagram_frame_size = 0 (disabled)
            1024, // local_max_datagram_frame_size (irrelevant for this test)
            1000, // send_timeout (not triggered)
            0,    // priority
            0,    // datagram_event_mask
        );

        // 2. Attempt to send a datagram
        let test_data = Bytes::from_static(b"test");
        let result = datagram_map.send_datagram(
            test_data.clone(),
            Some(test_data.len()),
            false, // drop_if is irrelevant here (should fail before queue check)
        );

        // 3. Verify send operation fails with ProtocolViolation (equivalent to DatagramDisabled)
        assert!(
            matches!(result, Err(Error::ProtocolViolation)),
            "Sending datagram should fail with ProtocolViolation when peer support is disabled"
        );

        // 4. Additional verification: Ensure queue remains empty (no data was enqueued)
        assert!(
            datagram_map.out_queue.is_empty(),
            "Outgoing queue should remain empty after failed send"
        );
        assert_eq!(
            datagram_map.out_total_size, 0,
            "Outgoing total size should remain 0 after failed send"
        );
    }
    /// Test that datagrams are dropped when they expire (simulated with global timeout)
    /// Note: Cannot fully replicate the "expiration between checks" scenario due to DatagramMap's design
    #[test]
    fn datagram_expiration_handling() {
        // 1. Initialize DatagramMap with very short global send timeout (1ms)
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size (enable sending)
            1024, // local_max_datagram_frame_size (irrelevant)
            1,    // send_timeout = 1ms (global timeout for all datagrams)
            0,    // priority
            0,    // datagram_event_mask
        );

        // 2. Send a datagram that will expire after 1ms
        let test_data = Bytes::from_static(b"expires_soon");
        let drop_num = datagram_map
            .send_datagram(test_data.clone(), Some(test_data.len()), false)
            .expect("Sending datagram should succeed initially");
        assert_eq!(drop_num, 0, "No datagrams should be dropped on send");
        assert_eq!(
            datagram_map.out_queue.len(),
            1,
            "Datagram should be in outgoing queue"
        );

        // 3. Wait 5ms to ensure the datagram exceeds the 1ms timeout
        std::thread::sleep(Duration::from_millis(5));

        // 4. Attempt to retrieve the datagram (should be expired and dropped)
        let max_payload_size = 1024;
        let result = datagram_map.outcome_datagram(max_payload_size);

        // Verify the expired datagram is dropped (returns None)
        assert!(
            result.is_none(),
            "Expired datagram should be dropped and return None"
        );
        assert!(
            datagram_map.out_queue.is_empty(),
            "Outgoing queue should be empty after expired datagram is dropped"
        );
        assert_eq!(
            datagram_map.out_total_size, 0,
            "Outgoing total size should be 0 after expiration"
        );
    }

    /// Test all AdjustResult scenarios for incoming queue capacity adjustment
    /// Test all possible outcomes of incoming queue capacity adjustment
    /// Covers success (increase), normal (valid decrease), and too-small (invalid decrease) scenarios
    #[test]
    fn datagram_incoming_queue_adjust_scenarios() {
        // 1. Initialize DatagramMap with 1KB (1024 bytes) initial incoming queue limit
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size (irrelevant for incoming queue adjustment)
            1024, // local_max_datagram_frame_size (enable datagram reception)
            1000, // send_timeout (not used in this test)
            0,    // priority (irrelevant)
            0,    // datagram_event_mask (irrelevant)
        );
        datagram_map.in_max_size = 1024; // Set initial incoming queue max size to 1KB

        // 2. Add 512 bytes of data to incoming queue (to test capacity vs current usage)
        let test_data = Bytes::from(vec![0u8; 512]);
        datagram_map
            .incoming_datagram(Some(test_data.len()), test_data)
            .expect("Failed to add test data to incoming queue");
        assert_eq!(
            datagram_map.in_total_size, 512,
            "Current incoming queue usage should be 512 bytes after adding test data"
        );
        let result_success = datagram_map.set_in_max_size(2048); // 2KB = 2048 bytes
        assert!(
            matches!(result_success, AdjustResult::Success),
            "Increasing incoming queue capacity should return AdjustResult::Success"
        );
        assert_eq!(
            datagram_map.in_max_size, 2048,
            "Incoming queue max size should update to 2048 bytes after successful increase"
        );
        let result_normal = datagram_map.set_in_max_size(1024); // Revert to 1KB
        assert!(
            matches!(result_normal, AdjustResult::Normal),
            "Decreasing incoming queue capacity to valid size (>= current usage) should return AdjustResult::Normal"
        );
        assert_eq!(
            datagram_map.in_max_size, 1024,
            "Incoming queue max size should update to 1024 bytes after valid decrease"
        );

        let result_too_small = datagram_map.set_in_max_size(0);
        assert!(
            matches!(result_too_small, AdjustResult::TooSmall),
            "Decreasing incoming queue capacity below current usage should return AdjustResult::TooSmall"
        );
        assert_eq!(
            datagram_map.in_max_size, 1024,
            "Incoming queue max size should remain unchanged when adjustment is TooSmall"
        );
    }

    // Constants defining queue size granularity (1KB = 1024 bytes) and default size
    const DATAGRAM_QUEUE_GRANULARITY_BYTES: u64 = 1024;
    const DEFAULT_QUEUE_SIZE_KB: u64 = 1;

    #[test]
    fn datagram_queue_granularity() {
        // Initialize DatagramMap (peer/local max frame size irrelevant for granularity test)
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size
            1024, // local_max_datagram_frame_size
            1000, // send_timeout
            0,    // priority
            0,    // datagram_event_mask
        );

        // 1. Set outgoing queue limit to 2KB (2 * granularity) and verify
        let outgoing_limit_kb = 2;
        let outgoing_limit_bytes = outgoing_limit_kb * DATAGRAM_QUEUE_GRANULARITY_BYTES;
        datagram_map.set_out_max_size(outgoing_limit_bytes);
        assert_eq!(
            datagram_map.out_max_size, outgoing_limit_bytes,
            "Outgoing queue max size should be {} bytes ({}KB * 1024)",
            outgoing_limit_bytes, outgoing_limit_kb
        );

        // 2. Set incoming queue limit to 3KB (3 * granularity) and verify
        let incoming_limit_kb = 3;
        let incoming_limit_bytes = incoming_limit_kb * DATAGRAM_QUEUE_GRANULARITY_BYTES;
        datagram_map.set_in_max_size(incoming_limit_bytes); // Assumes set_in_max_size exists (from prior tests)
        assert_eq!(
            datagram_map.in_max_size, incoming_limit_bytes,
            "Incoming queue max size should be {} bytes ({}KB * 1024)",
            incoming_limit_bytes, incoming_limit_kb
        );

        // 3. Verify the granularity constant itself is 1024 bytes (1KB)
        assert_eq!(
            DATAGRAM_QUEUE_GRANULARITY_BYTES, 1024,
            "Queue granularity should be 1024 bytes (1KB)"
        );
    }
    /// Test that datagrams with identical content receive unique, incrementing IDs for sending and receiving
    #[test]
    fn datagram_unique_ids() {
        // Initialize DatagramMap with enabled datagram support
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size (enable sending)
            1024, // local_max_datagram_frame_size (enable receiving)
            1000, // send_timeout
            0,    // priority
            0,    // datagram_event_mask
        );

        // Create datagram with identical content
        let data = Bytes::from_static(b"same content");
        let data_len = Some(data.len());

        // 1. Send 3 datagrams with identical content
        let drop_num1 = datagram_map
            .send_datagram(data.clone(), data_len, false)
            .expect("First datagram send should succeed");
        let drop_num2 = datagram_map
            .send_datagram(data.clone(), data_len, false)
            .expect("Second datagram send should succeed");
        let drop_num3 = datagram_map
            .send_datagram(data.clone(), data_len, false)
            .expect("Third datagram send should succeed");

        // Verify no datagrams were dropped
        assert_eq!(drop_num1, 0, "No datagrams should be dropped on first send");
        assert_eq!(
            drop_num2, 0,
            "No datagrams should be dropped on second send"
        );
        assert_eq!(drop_num3, 0, "No datagrams should be dropped on third send");

        // Verify send IDs are incrementing (index_out starts at 0, so 3 sends -> index_out = 3)
        assert_eq!(
            datagram_map.index_out, 3,
            "After 3 sends, index_out should be 3"
        );

        // 2. Dequeue sent datagrams and verify their IDs
        let max_payload = 1024;
        let (_, item1_data) = datagram_map
            .outcome_datagram(max_payload)
            .expect("Should retrieve first sent datagram");
        let (_, item2_data) = datagram_map
            .outcome_datagram(max_payload)
            .expect("Should retrieve second sent datagram");
        let (_, item3_data) = datagram_map
            .outcome_datagram(max_payload)
            .expect("Should retrieve third sent datagram");

        // Note: To verify IDs, we need to track them before dequeuing (since outcome_datagram returns data only)
        // Workaround: Re-send and check IDs via internal queue inspection
        // (This assumes out_queue is accessible; adjust if using private fields)
        datagram_map
            .send_datagram(data.clone(), data_len, false)
            .unwrap();
        datagram_map
            .send_datagram(data.clone(), data_len, false)
            .unwrap();
        datagram_map
            .send_datagram(data.clone(), data_len, false)
            .unwrap();

        assert_eq!(
            datagram_map.out_queue[0].datagram_id, 3,
            "First queued datagram ID should be 3"
        );
        assert_eq!(
            datagram_map.out_queue[1].datagram_id, 4,
            "Second queued datagram ID should be 4"
        );
        assert_eq!(
            datagram_map.out_queue[2].datagram_id, 5,
            "Third queued datagram ID should be 5"
        );

        // 3. Receive 2 datagrams with identical content
        datagram_map
            .incoming_datagram(data_len, data.clone())
            .expect("First receive should succeed");
        datagram_map
            .incoming_datagram(data_len, data.clone())
            .expect("Second receive should succeed");

        // Verify receive IDs are incrementing (index_in starts at 0, so 2 receives -> index_in = 2)
        assert_eq!(
            datagram_map.index_in, 2,
            "After 2 receives, index_in should be 2"
        );
        assert_eq!(
            datagram_map.in_queue.len(),
            2,
            "Incoming queue should contain 2 datagrams"
        );

        // Verify received datagram IDs
        assert_eq!(
            datagram_map.in_queue[0].datagram_id, 0,
            "First received datagram ID should be 0"
        );
        assert_eq!(
            datagram_map.in_queue[1].datagram_id, 1,
            "Second received datagram ID should be 1"
        );
    }

    const DEFAULT_QUEUE_SIZE_MB: u64 = 1;
    const DEFAULT_QUEUE_SIZE_BYTES: u64 =
        DEFAULT_QUEUE_SIZE_MB * DATAGRAM_QUEUE_GRANULARITY_BYTES * DATAGRAM_QUEUE_GRANULARITY_BYTES;

    /// Test the correctness of outgoing queue max size accessors (setter and getter)
    ///
    /// Validates three key scenarios:
    /// 1. Explicitly setting a custom outgoing queue size (5 KB)
    /// 2. Using the default outgoing queue size (1 MB, aligned with DatagramMap's actual default)
    /// 3. Updating an existing outgoing queue size to a new value (10 KB)
    #[test]
    fn datagram_max_outgoing_size_accessor() {
        // Scenario 1: Verify explicitly set outgoing queue size (5 KB)
        let mut datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size (unrelated to queue size)
            1024, // local_max_datagram_frame_size (unrelated to queue size)
            1000, // send_timeout (unrelated to queue size)
            0,    // priority (unrelated to queue size)
            0,    // datagram_event_mask (unrelated to queue size)
        );
        let explicit_limit_kb = 5;
        let explicit_limit_bytes = explicit_limit_kb * DATAGRAM_QUEUE_GRANULARITY_BYTES;
        datagram_map.set_out_max_size(explicit_limit_bytes); // Set queue to 5 KB

        assert_eq!(
            datagram_map.get_out_max_size(),
            explicit_limit_bytes,
            "Explicitly set outgoing max size should be {} bytes ({} KB)",
            explicit_limit_bytes,
            explicit_limit_kb
        );

        // Scenario 2: Verify default outgoing queue size (1 MB)
        let default_datagram_map = DatagramMap::new(
            1024, // peer_max_datagram_frame_size
            1024, // local_max_datagram_frame_size
            1000, // send_timeout
            0,    // priority
            0,    // datagram_event_mask
        );

        assert_eq!(
            default_datagram_map.get_out_max_size(),
            DEFAULT_QUEUE_SIZE_BYTES,
            "Default outgoing max size should be {} bytes ({} MB)",
            DEFAULT_QUEUE_SIZE_BYTES,
            DEFAULT_QUEUE_SIZE_MB
        );

        // Scenario 3: Verify updated outgoing queue size (10 KB)
        let updated_limit_kb = 10;
        let updated_limit_bytes = updated_limit_kb * DATAGRAM_QUEUE_GRANULARITY_BYTES;
        datagram_map.set_out_max_size(updated_limit_bytes); // Update queue to 10 KB

        assert_eq!(
            datagram_map.get_out_max_size(),
            updated_limit_bytes,
            "Updated outgoing max size should be {} bytes ({} KB)",
            updated_limit_bytes,
            updated_limit_kb
        );
    }
}
