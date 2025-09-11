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

#![allow(dead_code)]

use std::any::Any;
use std::collections::btree_map;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::iter::Empty;

use brotli::enc::entropy_encode::SortHuffmanTree;
use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use log::*;

use std::time::Duration;
use std::time::Instant;

use crate::frame::Frame;
use crate::ranges;
use crate::Error;
use crate::Event;
use crate::EventQueue;
use crate::Result;
use crate::Shutdown;
use crate::TransportParams;

#[derive(Default)]
pub struct DatagramMap {
    /// Datagram priority queue for sending.
    send: BTreeMap<u8, VecDeque<DatagramSendBuf>>,

    /// Datagram queue for data receiving.
    recv: VecDeque<Bytes>,

    /// Event Queue for lost and ack events.
    pub(super) events: EventQueue,

    /// Max send queue size.
    max_send_queue_size: u64,

    /// Max recv queue size.
    max_recv_queue_size: u64,

    /// Whether recv queue has data to read or not.
    recv_queue_readable: bool,

    /// Peer transport parameters.
    peer_transport_params: Option<DatagramTransportParams>,

    /// Local transport parameters.
    local_transport_params: DatagramTransportParams,
}

impl DatagramMap {
    pub fn new(
        max_send_queue_size: u64,
        max_recv_queue_size: u64,
        local_params: DatagramTransportParams,
    ) -> DatagramMap {
        DatagramMap {
            send: BTreeMap::new(),
            recv: VecDeque::new(),
            max_send_queue_size: max_send_queue_size,
            max_recv_queue_size: max_recv_queue_size,
            recv_queue_readable: false,
            peer_transport_params: None,
            local_transport_params: local_params,
            ..DatagramMap::default()
        }
    }

    pub fn write(
        &mut self,
        priority: u8,
        data: Bytes,
        expiration_time: Option<Instant>,
    ) -> Result<usize> {
        // Try to get corresponding queue of the given priority.
        // If the queue has not been created, create one.
        let queue = match self.send.entry(priority) {
            btree_map::Entry::Vacant(v) => {
                let vec_deque: VecDeque<DatagramSendBuf> = VecDeque::new();
                v.insert(vec_deque)
            }
            btree_map::Entry::Occupied(v) => v.into_mut(),
        };

        // Check whether we can push more data into the queue.
        if queue.len() == self.max_send_queue_size as usize {
            debug!("Datagram send queue reach limit");
            return Err(Error::Done);
        }

        let data_len = data.len();
        queue.push_back(DatagramSendBuf::new(data, expiration_time));
        Ok(data_len)
    }

    pub fn peek_data(&mut self) -> Option<DatagramSendBuf> {
        // Try to get data of the highest queue.
        let queue = match self.send.iter_mut().next() {
            Some((_, queue)) => queue,
            None => return None,
        };

        // Try to pop expired element in front of the queue.
        while let Some(front) = queue.front() {
            if front
                .expire_time
                .map(|expire_time| Instant::now() >= expire_time)
                .unwrap_or(false)
            {
                queue.pop_front();
            } else {
                break;
            }
        }

        // Clean queue if it's empty.
        if queue.is_empty() {
            self.send.pop_first();
            return None;
        }

        Some(queue.front().unwrap().clone())
    }

    pub fn remove_data(&mut self) -> Result<()> {
        match self.send.first_entry() {
            Some(mut entry) => {
                let queue = entry.get_mut();
                queue.pop_front();
                if queue.is_empty() {
                    entry.remove();
                }
                Ok(())
            }

            // Should never happen.
            None => Err(Error::Done),
        }
    }

    pub fn on_recv_datagram(&mut self, length: u64, data: Bytes) -> Result<()> {
        // An endpoint that receives a DATAGRAM frame when it has not indicated support via the transport parameter
        // MUST terminate the connection with an error of type PROTOCOL_VIOLATION.
        // Similarly, an endpoint that receives a DATAGRAM frame that is larger than the value it sent in its
        // max_datagram_frame_size transport parameter MUST terminate the connection with an error of type PROTOCOL_VIOLATION.
        if self.local_transport_params.max_datagram_frame_size == 0
            || length > self.local_transport_params.max_datagram_frame_size
        {
            debug!("Datagram frame not supported or size too large");
            return Err(Error::ProtocolViolation);
        }

        if self.recv.len() == self.max_recv_queue_size as usize {
            debug!("Datagram recv queue reach limit, frame dropped");
            return Ok(());
        }

        self.recv.push_back(data);
        self.recv_queue_readable = true;
        Ok(())
    }

    pub fn is_readable(&mut self) -> bool {
        self.recv_queue_readable
    }

    pub fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        match self.recv.pop_front() {
            Some(data) => {
                let data_len = data.len();

                // Whether recv queue is empty or not.
                if self.recv.len() == 0 {
                    self.recv_queue_readable = false;
                }

                // Whether provide buffer can read data or not.
                if out.len() < data_len {
                    debug!("Provide buffer size too small. Data will drop");
                    return Err(Error::Done);
                }
                out[..data_len].copy_from_slice(&data[..]);
                Ok(data_len)
            }
            None => Err(Error::Done),
        }
    }

    pub fn get_highest_priority(&mut self) -> Option<u8> {
        match self.send.first_entry() {
            Some(entry) => return Some(*entry.key()),
            None => return None,
        }
    }

    /// Return true if there are any datagram data that can be written by the application.
    pub fn has_writable(&mut self) -> bool {
        if !self.send.is_empty() {
            return true;
        }
        false
    }

    pub fn need_send_datagram_frames(&mut self) -> bool {
        self.has_writable()
    }
}

#[derive(Default, Clone)]
pub struct DatagramSendBuf {
    pub data: Bytes,
    pub expire_time: Option<Instant>,
}

impl DatagramSendBuf {
    pub fn new(data: Bytes, expiration_time: Option<Instant>) -> Self {
        DatagramSendBuf {
            data: data,
            expire_time: expiration_time,
        }
    }
}

#[derive(Default)]
pub struct DatagramTransportParams {
    max_datagram_frame_size: u64,
}

impl DatagramTransportParams {
    pub fn from(tp: &TransportParams) -> Self {
        DatagramTransportParams {
            max_datagram_frame_size: tp.max_datagram_frame_size,
        }
    }
}
