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
use std::cmp;
use std::collections::btree_map;
use std::collections::hash_map;
use std::collections::BTreeMap;
use std::collections::BinaryHeap;
use std::collections::VecDeque;
use std::ops::Range;
use std::time;
use std::time::Instant;

use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use enumflags2::bitflags;
use enumflags2::BitFlags;
use log::*;
use rustc_hash::FxHashMap;
use rustc_hash::FxHashSet;
use smallvec::SmallVec;

use self::StreamFlags::*;
use crate::connection::flowcontrol;
use crate::ranges;
use crate::Error;
use crate::Event;
use crate::EventQueue;
use crate::Result;
use crate::Shutdown;
use crate::TransportParams;
use crate::MAX_STREAMS_PER_TYPE;

pub type StreamIdHashMap<V> = FxHashMap<u64, V>;
pub type StreamIdHashSet = FxHashSet<u64>;

#[cfg(test)]
const SEND_BUFFER_SIZE: usize = 5;

#[cfg(not(test))]
const SEND_BUFFER_SIZE: usize = 4096;

// Receiver stream flow control window default value, 32KB.
const DEFAULT_STREAM_WINDOW: u64 = 32 * 1024;

// Receiver stream flow control window max value, 6MB.
pub const MAX_STREAM_WINDOW: u64 = 6 * 1024 * 1024;

// Receiver connection flow control window default value, 48KB.
// Note that here we set the default value of the connection-level flow control window
// to be 1.5 times the size of the stream-level flow control window, i.e. 1.5 * 32KB.
pub const DEFAULT_CONNECTION_WINDOW: u64 = 48 * 1024;

// The maximum size of the receiver connection flow control window.
pub const MAX_CONNECTION_WINDOW: u64 = 15 * 1024 * 1024;

/// Stream manager for keeps track of streams on a QUIC Connection.
#[derive(Default)]
pub struct StreamMap {
    /// Whether it serves as a server.
    is_server: bool,

    /// Collection of streams that are organized and accessed by stream ID.
    streams: StreamIdHashMap<Stream>,

    /// Streams that have outstanding data ready to be sent to the peer,
    /// and categorized by their urgency, lower value means higher priority.
    sendable: BTreeMap<u8, StreamPriorityQueue>,

    /// Streams that have outstanding data can be read by the application.
    readable: StreamIdHashSet,

    /// Streams that have enough flow control capacity to be written to,
    /// and is not finished.
    writable: StreamIdHashSet,

    /// Streams that are shutdown on the send side by the application prematurely
    /// or received STOP_SENDING frame from the peer.
    ///
    /// Current endpoint should send a RESET_STREAM frame with the error code and
    /// final size values in the tuple of the map elements to the peer.
    reset: StreamIdHashMap<(u64, u64)>,

    /// Streams that are shutdown on the receive side, and need to send
    /// a STOP_SENDING frame.
    stopped: StreamIdHashMap<u64>,

    /// Keep track of IDs of previously closed streams. It can grow and use up a
    /// lot of memory, so it is used only in unit tests.
    #[cfg(test)]
    closed: StreamIdHashSet,

    /// Streams that peer are almost out of flow control capacity, and
    /// need local endpoint to send a MAX_STREAM_DATA frame to the peer.
    almost_full: StreamIdHashSet,

    /// Streams that are blocked on the send-side, and need to send a
    /// STREAM_DATA_BLOCKED frame to the peer. The value of the map elements is
    /// the stream offset at which the stream is blocked.
    data_blocked: StreamIdHashMap<u64>,

    /// Streams concurrency control.
    concurrency_control: ConcurrencyControl,

    /// Connection receive-side flow control.
    flow_control: flowcontrol::FlowControl,

    /// Connection send-side flow control.
    send_capacity: SendCapacity,

    /// The maximum stream receive-side flow control window, it is inherited
    /// from the connection configuration, and applies to all streams.
    max_stream_window: u64,

    /// Connection received-side flow control capacity almost full,
    /// local endpoint should issue more credit by sending a MAX_DATA
    /// frame to the peer.
    pub rx_almost_full: bool,

    /// Stream id for next bidirectional stream.
    next_stream_id_bidi: u64,

    /// Stream id for next unidirectional stream.
    next_stream_id_uni: u64,

    /// Peer transport parameters.
    peer_transport_params: StreamTransportParams,

    /// Local transport parameters.
    local_transport_params: StreamTransportParams,

    /// Events sent to the endpoint.
    pub(super) events: EventQueue,

    /// Unique trace id for debug logging.
    trace_id: String,
}

impl StreamMap {
    /// Create a new `StreamMap`.
    pub fn new(
        is_server: bool,
        max_connection_window: u64,
        max_stream_window: u64,
        local_params: StreamTransportParams,
    ) -> StreamMap {
        StreamMap {
            is_server,

            concurrency_control: ConcurrencyControl::new(
                local_params.initial_max_streams_bidi,
                local_params.initial_max_streams_uni,
            ),

            flow_control: flowcontrol::FlowControl::new(
                local_params.initial_max_data,
                max_connection_window,
            ),

            send_capacity: SendCapacity::default(),

            max_stream_window,
            rx_almost_full: false,

            next_stream_id_bidi: if is_server { 1 } else { 0 },
            next_stream_id_uni: if is_server { 3 } else { 2 },

            local_transport_params: local_params,
            peer_transport_params: StreamTransportParams::default(),

            ..StreamMap::default()
        }
    }

    /// Set trace id.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.trace_id = trace_id.to_string();
    }

    /// Return a reference to the stream with the given ID if it exists, or `None`.
    fn get(&self, id: u64) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// Return a mutable reference to the stream with the given ID if it exists,
    /// or `None`.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    /// Create a new bidirectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_bidi_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        let stream_id = self.next_stream_id_bidi;
        match self.stream_set_priority(stream_id, urgency, incremental) {
            Ok(_) => Ok(stream_id),
            Err(e) => Err(e),
        }
    }

    /// Create a new unidrectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_uni_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        let stream_id = self.next_stream_id_uni;
        match self.stream_set_priority(stream_id, urgency, incremental) {
            Ok(_) => Ok(stream_id),
            Err(e) => Err(e),
        }
    }

    /// Get the lowest offset of data to be read.
    pub fn stream_read_offset(&mut self, stream_id: u64) -> Option<u64> {
        match self.get_mut(stream_id) {
            Some(stream) => Some(stream.recv.read_off()),
            None => None,
        }
    }

    /// Read contiguous data from the stream's receive buffer into the given buffer.
    ///
    /// Return the number of bytes read and the `fin` flag if read successfully.
    /// Return `StreamStateError` if the stream closed or never opened.
    /// Return `Done` if the stream is not readable.
    pub fn stream_read(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        // Local initiated unidirectional streams are send-only, so we can't read from them.
        if !is_bidi(stream_id) && is_local(stream_id, self.is_server) {
            return Err(Error::StreamStateError);
        }

        // If the stream is not exist, it may not be opened yet, or it was closed,
        // return `StreamStateError`.
        let stream = self.get_mut(stream_id).ok_or(Error::StreamStateError)?;

        // If stream is not readable, return `Done`.
        if !stream.is_readable() {
            trace!("{} stream is not readable", stream.trace_id);
            return Err(Error::Done);
        }

        let local = stream.local;

        let (read, fin) = match stream.recv.read(out) {
            Ok(v) => v,

            Err(e) => {
                trace!("{} stream read error: {:?}", stream.trace_id, e);

                // Stream recv-side maybe reset by peer, if it is complete, we should
                // remove it from the stream map, and collect it to `closed` streams set.
                if stream.is_complete() {
                    self.mark_closed(stream_id, local);
                }

                self.mark_readable(stream_id, false);
                return Err(e);
            }
        };

        // We can't move these two lines of code after the connection-level
        // flow_control check, otherwise there will be a variable borrowing problem.
        let readable = stream.is_readable();
        let complete = stream.is_complete();

        // Check if we need to send a `MAX_STREAM_DATA` frame to update
        // stream-level flow control.
        if stream.recv.should_send_max_data() {
            self.mark_almost_full(stream_id, true);
        }

        // Update connection-level flow control consumption, and check if we should
        // send a `MAX_DATA` frame to update connection-level flow control limit.
        self.flow_control.increase_read_off(read as u64);
        if self.flow_control.should_send_max_data() {
            self.rx_almost_full = true;
        }

        // After reading, we should remove it from the readable queue if it is not
        // readable at the present.
        if !readable {
            self.mark_readable(stream_id, false);
        }

        // If the stream is complete, we should remove it from the streams map and
        // collect it to the `closed` streams set.
        if complete {
            self.mark_closed(stream_id, local);
        }

        Ok((read, fin))
    }

    /// Get the maximum offset of data written by application
    pub fn stream_write_offset(&mut self, stream_id: u64) -> Option<u64> {
        match self.get_mut(stream_id) {
            Some(stream) => Some(stream.send.write_off()),
            None => None,
        }
    }

    /// Write data to the stream's send buffer.
    pub fn stream_write(&mut self, stream_id: u64, mut buf: Bytes, fin: bool) -> Result<usize> {
        // Peer initiated unidirectional streams are receive-only, so we can't write to them.
        if !is_bidi(stream_id) && !is_local(stream_id, self.is_server) {
            return Err(Error::StreamStateError);
        }

        // If the connection-level flow control credit is not enough, mark the
        // the connection as blocked and schedule a `DATA_BLOCKED` frame to be sent.
        if self.max_tx_data_left() < buf.len() as u64 {
            self.update_data_blocked_at(Some(self.send_capacity.max_data));
        }

        let expect_written = buf.len();
        let capacity = self.send_capacity.capacity;

        // Get or create the stream if it was not created before.
        // If the stream was closed, return `Done`.
        let stream = self.get_or_create(stream_id, true)?;

        let was_writable = stream.is_writable();
        let was_sendable = stream.is_sendable();

        // When the connection's capacity is exhausted, if the input buffer is not empty,
        // return `Done`.
        if capacity == 0 && !buf.is_empty() {
            // Stream blocked by the connection's send capacity, must not affect
            // its writable state.
            if was_writable {
                self.mark_writable(stream_id, true);
            }

            // Stream blocked, but it still want to write, so we should mark it as want-write.
            let _ = self.want_write(stream_id, true);
            return Err(Error::Done);
        }

        // If the connection's send capacity is not enough, truncate the input
        // buffer with the capacity.
        let (fin, blocked_by_cap) = if capacity < buf.len() {
            buf.truncate(capacity);
            (false, true)
        } else {
            (fin, false)
        };

        // Save the buffer's length before its ownership moved.
        let buf_len = buf.len();

        let written = match stream.send.write(buf, fin) {
            Ok(v) => v,

            Err(e) => {
                self.mark_writable(stream_id, false);
                return Err(e);
            }
        };

        let urgency = stream.urgency;
        let incremental = stream.incremental;

        let sendable = stream.is_sendable();
        let writable = stream.is_writable();
        let empty_fin = buf_len == 0 && fin;

        if written < buf_len {
            let max_data = stream.send.max_data();

            if stream.send.blocked_at() != Some(max_data) {
                stream.send.update_blocked_at(Some(max_data));
                self.mark_blocked(stream_id, true, max_data);
            }
        } else {
            stream.send.update_blocked_at(None);
            self.mark_blocked(stream_id, false, 0);
        }

        // If the stream is sendable and it wasn't sendable before, push it to
        // the sendable queue.
        // Note: Buffer an empty block data with fin should be treated as sendable.
        if (sendable || empty_fin) && !was_sendable {
            self.push_sendable(stream_id, urgency, incremental);
        }

        if !writable {
            self.mark_writable(stream_id, false);
        } else if was_writable && blocked_by_cap {
            // Stream blocked by the connection's send capacity, must not affect
            // its writable state.
            self.mark_writable(stream_id, true);
        }

        self.send_capacity.capacity -= written;
        self.send_capacity.tx_data += written as u64;

        // Write partial data, mark the stream as want-write.
        if written < expect_written {
            let _ = self.want_write(stream_id, true);
        }

        // No data was written, it maybe limited by the stream-level flow control.
        if written == 0 && buf_len > 0 {
            return Err(Error::Done);
        }

        Ok(written)
    }

    /// Shutdown stream receive-side or send-side.
    pub fn stream_shutdown(&mut self, stream_id: u64, direction: Shutdown, err: u64) -> Result<()> {
        // We can't move this line to the match arm because of the borrow checker.
        let is_server = self.is_server;

        // If the stream was not created before or has been closed, return `Done`.
        let stream = self.get_mut(stream_id).ok_or(Error::Done)?;
        match direction {
            Shutdown::Read => {
                // Local initiated uni stream should not be shutdown in the receive-side.
                if is_local(stream_id, is_server) && !is_bidi(stream_id) {
                    return Err(Error::StreamStateError);
                }

                let unread_len = stream.recv.shutdown()?;

                // If the stream doesn't enter terminal state, sending a `STOP_SENDING`
                // frame to prompt closure of the stream in the opposite direction.
                if !stream.recv.is_fin() {
                    self.mark_stopped(stream_id, true, err);
                }

                // Stream should not be readable if it is shutdown in the receive-side.
                self.mark_readable(stream_id, false);

                // When a stream's receive-side shutdown, all unread data will be
                // discarded, we consider them as consumed, which might trigger a
                // connection-level flow control update.
                self.flow_control.increase_read_off(unread_len);
                if self.flow_control.should_send_max_data() {
                    self.rx_almost_full = true;
                }
            }

            Shutdown::Write => {
                // Peer initiated uni stream should not be shutdown in the send-side.
                if !is_local(stream_id, is_server) && !is_bidi(stream_id) {
                    return Err(Error::StreamStateError);
                }

                let (final_size, unsent) = stream.send.shutdown()?;

                // Give back some flow control credit by deducting the data that
                // was buffered but not actually sent before the stream send-side
                // was shutdown.
                self.send_capacity.tx_data = self.send_capacity.tx_data.saturating_sub(unsent);

                // Update connection-level send capacity.
                self.send_capacity.update_capacity();

                self.mark_reset(stream_id, true, err, final_size);

                // Stream should not be writable after it is shutdown in the send-side.
                self.mark_writable(stream_id, false);
            }
        }

        Ok(())
    }

    /// Set priority for a stream.
    pub fn stream_set_priority(
        &mut self,
        stream_id: u64,
        urgency: u8,
        incremental: bool,
    ) -> Result<()> {
        // Get or create the stream if it was not created before.
        let stream = match self.get_or_create(stream_id, true) {
            Ok(v) => v,
            // Stream has been closed, just ignore the prioritization.
            Err(Error::Done) => return Ok(()),
            Err(e) => return Err(e),
        };

        if stream.urgency == urgency && stream.incremental == incremental {
            return Ok(());
        }

        stream.urgency = urgency;
        stream.incremental = incremental;

        Ok(())
    }

    /// Get the stream's send-side capacity, in units of bytes.
    /// The capacity is the minimum of the connection-level flow control credit
    /// and the stream-level flow control credit.
    pub fn stream_capacity(&self, stream_id: u64) -> Result<usize> {
        match self.get(stream_id) {
            Some(s) => Ok(cmp::min(self.send_capacity.capacity, s.send.capacity()?)),
            None => Err(Error::StreamStateError),
        }
    }

    /// Return true if the stream has more than `len` bytes of send-side capacity.
    pub fn stream_writable(&mut self, stream_id: u64, len: usize) -> Result<bool> {
        if self.stream_capacity(stream_id)? >= len {
            return Ok(true);
        }

        // The connection-level flow control credit is not enough, mark the connection
        // blocked and schedule a DATA_BLOCKED frame to be sent to the peer.
        if self.max_tx_data_left() < len as u64 {
            self.update_data_blocked_at(Some(self.send_capacity.max_data));
        }

        // We have confirmed that the stream is existing when calling `stream_capacity`,
        // so it is safe to unwrap.
        let stream = self.get_mut(stream_id).unwrap();

        stream.write_thresh = cmp::max(1, len);

        let is_writable = stream.is_writable();

        // If the stream-level flow control credit is not enough, mark the stream
        // blocked and schedule a STREAM_DATA_BLOCKED frame to be sent to the peer.
        //
        // Note that we should mark the stream blocked at max_data, otherwise the
        // peer may ignore the STREAM_DATA_BLOCKED frame.
        if stream.send.capacity()? < len {
            let max_data = stream.send.max_data();
            if stream.send.blocked_at() != Some(max_data) {
                stream.send.update_blocked_at(Some(max_data));
                self.mark_blocked(stream_id, true, max_data);
            }
        } else if is_writable {
            self.mark_writable(stream_id, true);
        }

        Ok(false)
    }

    /// Return true if the stream has outstanding data to read.
    pub fn stream_readable(&self, stream_id: u64) -> bool {
        match self.get(stream_id) {
            Some(s) => s.is_readable(),
            None => false,
        }
    }

    /// Return true if the stream's receive-side final size is known, and the
    /// application has read all data from the stream.
    ///
    /// Note that this function also return true if the stream is reset by the peer.
    pub fn stream_finished(&self, stream_id: u64) -> bool {
        match self.get(stream_id) {
            Some(s) => s.recv.is_fin(),
            None => true,
        }
    }

    /// Set user context for a stream.
    pub fn stream_set_context<T: Any + Send + Sync>(
        &mut self,
        stream_id: u64,
        ctx: T,
    ) -> Result<()> {
        // Get or create the stream if it was not created before.
        let stream = match self.get_or_create(stream_id, true) {
            Ok(v) => v,
            Err(Error::Done) => return Ok(()), // stream closed
            Err(e) => return Err(e),
        };

        stream.context = Some(Box::new(ctx));
        Ok(())
    }

    /// Return the stream's user context.
    pub fn stream_context(&mut self, stream_id: u64) -> Option<&mut dyn Any> {
        if let Some(s) = self.get_mut(stream_id) {
            match s.context {
                Some(ref mut ctx) => Some(ctx.as_mut()),
                None => None,
            }
        } else {
            None
        }
    }

    /// Get the maximum amount of data that the stream can receive and sent.
    /// Return a tuple of (max_rx_data, max_tx_data).
    fn max_stream_data_limit(
        local: bool,
        bidi: bool,
        local_params: &StreamTransportParams,
        peer_params: &StreamTransportParams,
    ) -> (u64, u64) {
        // Based on the initiator(local/remote) and stream type(uni/bidi) to determine the
        // maximum amount of data that can be received and sent by the local endpoint.
        match (local, bidi) {
            // Local initiated bidirectional stream, can send and receive data.
            (true, true) => (
                local_params.initial_max_stream_data_bidi_local,
                peer_params.initial_max_stream_data_bidi_remote,
            ),

            // Local initiated unidirectional stream, can send data only.
            (true, false) => (0, peer_params.initial_max_stream_data_uni),

            // Peer initiated bidirectional stream, can receive and send data.
            (false, true) => (
                local_params.initial_max_stream_data_bidi_remote,
                peer_params.initial_max_stream_data_bidi_local,
            ),

            // Peer initiated unidirectional stream, can receive data only.
            (false, false) => (local_params.initial_max_stream_data_uni, 0),
        }
    }

    /// Return a mutable reference to the stream with the given ID if it exists,
    /// or create a new one with given paras otherwise if it is allowed.
    fn get_or_create(&mut self, id: u64, local: bool) -> Result<&mut Stream> {
        // A stream ID is a 62-bit integer (0 to 2^62-1) that is unique for all
        // streams on a connection.
        if id > crate::codec::VINT_MAX {
            return Err(Error::ProtocolViolation);
        }

        let closed = self.is_closed(id);
        match self.streams.entry(id) {
            // 1.Can not find any stream with the given stream ID.
            // It may not be created yet or it has been closed.
            hash_map::Entry::Vacant(v) => {
                // Stream has already been closed and collected into `closed`.
                if closed {
                    return Err(Error::Done);
                }

                // Requested stream ID is not valid with the current role.
                if local != is_local(id, self.is_server) {
                    return Err(Error::StreamStateError);
                }
                let bidi = is_bidi(id);

                // Get the maximum amount of data that the new stream can receive and sent.
                let (max_rx_data, max_tx_data) = Self::max_stream_data_limit(
                    local,
                    bidi,
                    &self.local_transport_params,
                    &self.peer_transport_params,
                );

                // Check if the stream ID complies with the stream limits of the current
                // role, and try to update the stream count if it is valid.
                self.concurrency_control
                    .check_concurrency_limits(id, self.is_server)?;

                // Create a new stream.
                let mut new_stream = Stream::new(
                    bidi,
                    local,
                    max_tx_data,
                    max_rx_data,
                    self.max_stream_window,
                );
                let trace_id = format!("{}-{}", &self.trace_id, id);
                new_stream.set_trace_id(&trace_id);

                // Stream might already be writable due to initial flow control credit.
                if new_stream.is_writable() {
                    self.writable.insert(id);
                }

                // Update stream id for next bidirectional/unidirectional stream.
                if bidi {
                    self.next_stream_id_bidi = cmp::max(self.next_stream_id_bidi, id);
                    self.next_stream_id_bidi = self.next_stream_id_bidi.saturating_add(4);
                } else {
                    self.next_stream_id_uni = cmp::max(self.next_stream_id_uni, id);
                    self.next_stream_id_uni = self.next_stream_id_uni.saturating_add(4);
                }

                self.concurrency_control.remove_avail_id(id, self.is_server);
                self.events.add(Event::StreamCreated(id));
                Ok(v.insert(new_stream))
            }

            // 2.Stream already exists.
            hash_map::Entry::Occupied(v) => Ok(v.into_mut()),
        }
    }

    /// Return true if we should send `MAX_DATA` frame to peer to update
    /// the connection level flow control limit.
    pub fn need_send_max_data(&self) -> bool {
        self.rx_almost_full && self.max_rx_data() < self.max_rx_data_next()
    }

    /// Return true if need to send stream frames.
    pub fn need_send_stream_frames(&self) -> bool {
        self.has_sendable_streams()
            || self.need_send_max_data()
            || self.data_blocked_at().is_some()
            || self.should_send_max_streams()
            || self.has_almost_full_streams()
            || self.has_blocked_streams()
            || self.has_reset_streams()
            || self.has_stopped_streams()
            || self.streams_blocked()
    }

    /// Push the stream ID to the sendable queue with the given urgency and
    /// incremental flag.
    ///
    /// If the given stream ID is already in the queue, this function must
    /// not be called to ensure the fairness of the scheduling and avoid the
    /// spurious cycles through the queue.
    fn push_sendable(&mut self, stream_id: u64, urgency: u8, incremental: bool) {
        // 1.Get priority queue with the given urgency, if it does not exist, create a new one.
        let queue = match self.sendable.entry(urgency) {
            btree_map::Entry::Vacant(v) => v.insert(StreamPriorityQueue::default()),
            btree_map::Entry::Occupied(v) => v.into_mut(),
        };

        // 2.Push the element to the queue corresponding to the given incremental flag.
        if !incremental {
            // Non-incremental streams are scheduled in order of their stream ID.
            queue.non_incremental.push(cmp::Reverse(stream_id))
        } else {
            // Incremental streams are scheduled in a round-robin fashion.
            queue.incremental.push_back(stream_id)
        };
    }

    /// Return the first stream ID from the sendable queue with the highest priority.
    ///
    /// Note that the caller should call `remove_sendable` to remove the stream from the
    /// queue if it is no longer sendable after sending some of its outstanding data.
    pub fn peek_sendable(&mut self) -> Option<u64> {
        let queue = match self.sendable.iter_mut().next() {
            Some((_, queue)) => queue,
            None => return None,
        };

        // 1.Try to get the non-incremental stream with the lowest stream ID.
        match queue.non_incremental.peek().map(|x| x.0) {
            Some(stream_id) => Some(stream_id),
            None => {
                // 2.Try to get the incremental stream from the front of the queue.
                // Incremental streams are scheduled in a round-robin fashion, So
                // we should move the current peeked incremental stream to the end
                // of the queue.
                match queue.incremental.pop_front() {
                    Some(stream_id) => {
                        queue.incremental.push_back(stream_id);
                        Some(stream_id)
                    }
                    // Should never happen.
                    None => None,
                }
            }
        }
    }

    /// Remove the last peeked stream from the sendable streams queue.
    pub fn remove_sendable(&mut self) {
        // Get the first entry which is the queue with the highest priority.
        let mut entry = match self.sendable.first_entry() {
            Some(entry) => entry,
            // Should never happen, as `peek_sendable()` must be called priorly.
            None => return,
        };

        let queue = entry.get_mut();
        queue
            .non_incremental
            .pop()
            .map(|x| x.0)
            .or_else(|| queue.incremental.pop_back());

        // Remove the queue from the queues list if it is empty at present time,
        // so that the next time `peek_sendable()` is invoked, the next non-empty
        // queue is selected.
        if queue.non_incremental.is_empty() && queue.incremental.is_empty() {
            entry.remove();
        }
    }

    /// Add or remove the stream ID to/from the `readable` streams set.
    ///
    /// Do nothing if `readable` is true but the stream was already in the list.
    fn mark_readable(&mut self, stream_id: u64, readable: bool) {
        match readable {
            true => self.readable.insert(stream_id),
            false => self.readable.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `writable` streams set.
    ///
    /// Do nothing if `writable` is true but the stream was already in the list.
    fn mark_writable(&mut self, stream_id: u64, writable: bool) {
        match writable {
            true => self.writable.insert(stream_id),
            false => self.writable.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `almost_full` streams set.
    ///
    /// Do nothing if `almost_full` is true but the stream was already in the list.
    pub fn mark_almost_full(&mut self, stream_id: u64, almost_full: bool) {
        match almost_full {
            true => self.almost_full.insert(stream_id),
            false => self.almost_full.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `data_blocked` streams set with the
    /// given offset value.
    ///
    /// If `blocked` is true but the stream was already in the list, the offset value
    /// will be updated.
    pub fn mark_blocked(&mut self, stream_id: u64, blocked: bool, off: u64) {
        match blocked {
            true => self.data_blocked.insert(stream_id, off),
            false => self.data_blocked.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `reset` streams set with the
    /// given error code and final size values.
    ///
    /// If `reset` is true but the stream was already in the list, the error code
    /// and final size values will be updated.
    pub fn mark_reset(&mut self, stream_id: u64, reset: bool, error_code: u64, final_size: u64) {
        match reset {
            true => self.reset.insert(stream_id, (error_code, final_size)),
            false => self.reset.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `stop` streams set with the
    /// given error code.
    ///
    /// If `stopped` is true but the stream was already in the list, the error code
    /// will be updated.
    pub fn mark_stopped(&mut self, stream_id: u64, stopped: bool, error_code: u64) {
        match stopped {
            true => self.stopped.insert(stream_id, error_code),
            false => self.stopped.remove(&stream_id),
        };
    }

    /// Remove the stream ID from the readable and writable streams sets, and
    /// adds it to the closed streams set.
    ///
    /// Note that this method does not check if the stream id is complied with
    /// the role of the endpoint.
    fn mark_closed(&mut self, stream_id: u64, local: bool) {
        if self.is_closed(stream_id) {
            return;
        }

        // Give back a max_streams credit if the stream was initiated by the peer.
        if !local {
            if is_bidi(stream_id) {
                self.concurrency_control
                    .increase_max_streams_credits(true, 1);
            } else {
                self.concurrency_control
                    .increase_max_streams_credits(false, 1);
            }
        }

        self.mark_readable(stream_id, false);
        self.mark_writable(stream_id, false);
        if let Some(stream) = self.get_mut(stream_id) {
            stream.mark_closed();
        }
        #[cfg(test)]
        self.closed.insert(stream_id);

        if self.events.add(Event::StreamClosed(stream_id)) {
            // When event queue is enabled, inform the Endpoint to process
            // StreamClosed event and destroy the stream object.
            return;
        }
        self.stream_destroy(stream_id);
    }

    /// Destroy the closed stream.
    pub(crate) fn stream_destroy(&mut self, stream_id: u64) {
        self.streams.remove(&stream_id);
    }

    /// Get the maximum streams that the peer allows the local endpoint to open.
    pub fn peer_max_streams(&self, bidi: bool) -> u64 {
        self.concurrency_control.peer_max_streams(bidi)
    }

    /// After sending a MAX_STREAMS(type: 0x12..0x13) frame, update local max_streams limit.
    pub fn update_local_max_streams(&mut self, bidi: bool) {
        self.concurrency_control.update_local_max_streams(bidi);
    }

    /// Get the maximum streams that the local endpoint allow the peer to open.
    pub fn max_streams(&self, bidi: bool) -> u64 {
        match bidi {
            true => self.concurrency_control.local_max_streams_bidi,
            false => self.concurrency_control.local_max_streams_uni,
        }
    }

    /// Get the next max streams limit that will be sent to the peer
    /// in a MAX_STREAMS(type:0x12..0x13) frame.
    pub fn max_streams_next(&self, bidi: bool) -> u64 {
        match bidi {
            true => self.concurrency_control.local_max_streams_bidi_next,
            false => self.concurrency_control.local_max_streams_uni_next,
        }
    }

    /// Return true if we should send a MAX_STREAMS(type: 0x12..0x13) frame to the peer.
    pub fn should_send_max_streams(&self) -> bool {
        self.concurrency_control
            .should_update_local_max_streams(true)
            || self
                .concurrency_control
                .should_update_local_max_streams(false)
    }

    /// Return true if the max streams limit should be updated
    /// by sending a MAX_STREAMS(type: 0x12..0x13) frame to the peer.
    pub fn should_update_local_max_streams(&self, bidi: bool) -> bool {
        self.concurrency_control
            .should_update_local_max_streams(bidi)
    }

    /// Get the last offset at which the connection send-side was blocked, if any.
    pub fn data_blocked_at(&self) -> Option<u64> {
        self.send_capacity.blocked_at
    }

    pub fn streams_blocked(&self) -> bool {
        self.concurrency_control.streams_blocked_at_bidi.is_some()
            || self.concurrency_control.streams_blocked_at_uni.is_some()
    }

    pub fn streams_blocked_at(&self, bidi: bool) -> Option<u64> {
        match bidi {
            true => self.concurrency_control.streams_blocked_at_bidi,
            false => self.concurrency_control.streams_blocked_at_uni,
        }
    }

    /// Return an iterator over all the existing streams.
    pub fn iter(&self) -> StreamIter {
        StreamIter {
            streams: self.streams.keys().copied().collect(),
        }
    }

    /// Return an iterator over streams that have outstanding data to be read
    /// by the application.
    pub fn readable_iter(&self) -> StreamIter {
        StreamIter::from(&self.readable)
    }

    /// Return true if there are any streams that have data to read.
    pub fn has_readable(&self) -> bool {
        let iter = StreamIter::from(&self.readable);
        for stream_id in iter {
            if self.check_readable(stream_id) {
                trace!("{} has readable stream {}", self.trace_id, stream_id);
                return true;
            }
        }

        trace!("{} no any readable stream", self.trace_id);
        false
    }

    /// Return an iterator over streams that have available send capacity of stream level.
    pub fn writable_iter(&self) -> StreamIter {
        StreamIter::from(&self.writable)
    }

    /// Return true if there are any streams that can be written by the application.
    pub fn has_writable(&self) -> bool {
        if self.send_capacity.capacity == 0 {
            return false;
        }

        let iter = StreamIter::from(&self.writable);
        for stream_id in iter {
            if self.check_writable(stream_id) {
                trace!("{} has writable stream {}", self.trace_id, stream_id);
                return true;
            }
        }

        trace!("{} no any writable stream", self.trace_id);
        false
    }

    /// Set want write flag for a stream.
    ///
    /// Return `Error::Done` if the stream is not found.
    pub fn want_write(&mut self, stream_id: u64, want: bool) -> Result<()> {
        match self.get_mut(stream_id) {
            Some(stream) => stream.mark_wantwrite(want),
            None => Err(Error::Done),
        }
    }

    /// Set want read flag for a stream.
    ///
    /// Return `Error::Done` if the stream is not found.
    pub fn want_read(&mut self, stream_id: u64, want: bool) -> Result<()> {
        match self.get_mut(stream_id) {
            Some(stream) => stream.mark_wantread(want),
            None => Err(Error::Done),
        }
    }

    /// Return true if application wants to write more data to the stream
    /// and it has enough flow control capacity to do so.
    ///
    /// Note that if application wants to write, and the stream was stopped
    /// by peer, return true.
    pub fn check_writable(&self, stream_id: u64) -> bool {
        if let Some(stream) = self.get(stream_id) {
            if !stream.is_wantwrite() {
                return false;
            }

            let capacity = match stream.send.capacity() {
                Ok(v) => v,

                // If stream.send.capacity() return err, it means the stream is stopped
                // by peer, then we return the stream to the application immediately.
                Err(_) => return true,
            };

            if cmp::min(self.send_capacity.capacity, capacity) >= stream.write_thresh {
                return true;
            }
        }

        false
    }

    /// Return true if application wants to read more data from the stream.
    pub fn check_readable(&self, stream_id: u64) -> bool {
        if let Some(stream) = self.get(stream_id) {
            return stream.is_wantread();
        }

        false
    }

    /// Return an iterator over streams that the available send capacity can be used
    /// by the peer are almost full, and need to send MAX_STREAM_DATA to the peer.
    pub fn almost_full(&self) -> StreamIter {
        StreamIter::from(&self.almost_full)
    }

    /// Return an iterator over streams that wish to send data but are unable to do so
    /// due to stream-level flow control and need to send STREAM_DATA_BLOCKED to the peer.
    pub fn blocked(&self) -> hash_map::Iter<u64, u64> {
        self.data_blocked.iter()
    }

    /// Create an iterator over streams that the send-side has been shutdown
    /// prematurely and need to send RESET_STREAM frame to the peer.
    pub fn reset(&self) -> hash_map::Iter<u64, (u64, u64)> {
        self.reset.iter()
    }

    /// Create an iterator over streams that the receive-side has been shutdown
    /// prematurely and need to send STOP_SENDING frame to the peer.
    pub fn stopped(&self) -> hash_map::Iter<u64, u64> {
        self.stopped.iter()
    }

    /// Return true if the stream has been closed.
    pub fn is_closed(&self, stream_id: u64) -> bool {
        // It is an existing stream
        if let Some(stream) = self.get(stream_id) {
            return stream.is_closed();
        }

        // It is a stream to be create
        let is_server = self.is_server;
        if self.concurrency_control.is_available(stream_id, is_server)
            || self.concurrency_control.is_limited(stream_id, is_server)
        {
            return false;
        }

        // It is a destroyed stream
        true
    }

    /// Return true if there are any streams that have buffered data to send.
    fn has_sendable_streams(&self) -> bool {
        !self.sendable.is_empty()
    }

    /// Return true if there are any streams that have data to be read by application.
    pub fn has_readable_streams(&self) -> bool {
        !self.readable.is_empty()
    }

    /// Return true if there are any streams that need to send MAX_STREAM_DATA
    /// to update the receive-side flow control limit.
    fn has_almost_full_streams(&self) -> bool {
        !self.almost_full.is_empty()
    }

    /// Return true if there are any streams that wish to send data but are unable
    /// to do so due to stream-level flow control and need to send STREAM_DATA_BLOCKED
    /// frame to the peer.
    fn has_blocked_streams(&self) -> bool {
        !self.data_blocked.is_empty()
    }

    /// Return true if there are any streams that are reset in the send-side
    /// and need to send RESET_STREAM frame to the peer.
    fn has_reset_streams(&self) -> bool {
        !self.reset.is_empty()
    }

    /// Return true if there are any streams that are shutdown on the receive-side
    /// and need to send STOP_SENDING frame to the peer.
    fn has_stopped_streams(&self) -> bool {
        !self.stopped.is_empty()
    }

    /// Update connection send-side flow control blocked state.
    pub fn update_data_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.send_capacity.update_blocked_at(blocked_at);
    }

    /// Update connection concurrency control blocked state.
    pub fn update_streams_blocked_at(&mut self, bidi: bool, blocked_at: Option<u64>) {
        self.concurrency_control
            .update_streams_blocked_at(bidi, blocked_at);
    }

    /// Receive a MAX_DATA frame from the peer, update the connection-level
    /// send-side flow control limit.
    pub fn on_max_data_frame_received(&mut self, max_data: u64) {
        self.send_capacity.update_max_data(max_data);
        self.send_capacity.update_capacity();

        // Cancel the connection-level flow control blocked state if the
        // connection-level flow control limit is increased, avoid sending
        // redundant DATA_BLOCKED frames.
        if Some(self.send_capacity.max_data) > self.send_capacity.blocked_at {
            self.send_capacity.blocked_at = None;
        }
    }

    /// Receive a MAX_STREAM_DATA frame from the peer, update the stream-level
    /// send-side flow control limit.
    pub fn on_max_stream_data_frame_received(
        &mut self,
        stream_id: u64,
        max_data: u64,
    ) -> Result<()> {
        // RFC9000 19.10. MAX_STREAM_DATA Frames
        // An endpoint that receives a MAX_STREAM_DATA frame for a receive-only stream
        // MUST terminate the connection with error STREAM_STATE_ERROR.
        if !is_local(stream_id, self.is_server) && !is_bidi(stream_id) {
            return Err(Error::StreamStateError);
        }

        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the frame.
        let stream = match self.get_or_create(stream_id, false) {
            Ok(v) => v,

            // Stream is already closed, just ignore the frame even though
            // it might be illegal.
            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        let was_sendable = stream.is_sendable();

        stream.send.update_max_data(max_data);

        // Note that we don't need to check and update the stream-level flow control
        // blocked state here, it will be checked and updated in stream_send.

        let writable = stream.is_writable();

        // If the stream is now sendable push it to the sendable queue,
        // but only if it wasn't already queued.
        if stream.is_sendable() && !was_sendable {
            // Note: rust borrow checker doesn't allow us to borrow `self` twice,
            // so here we cannot use stream.urgency and stream.incremental directly.
            let urgency = stream.urgency;
            let incremental = stream.incremental;
            self.push_sendable(stream_id, urgency, incremental);
        }

        if writable {
            self.mark_writable(stream_id, true);
        }

        Ok(())
    }

    /// Receive a MAX_STREAMS frame from the peer, update the max stream limits.
    pub fn on_max_streams_frame_received(&mut self, max_streams: u64, bidi: bool) -> Result<()> {
        // RFC9000 19.11. MAX_STREAMS Frames
        // A count of the cumulative number of streams of the corresponding
        // type that can be opened over the lifetime of the connection.
        // This value cannot exceed 2^60, as it is not possible to encode
        // stream IDs larger than 2^62-1. Receipt of a frame that permits
        // opening of a stream larger than this limit MUST be treated as
        // a connection error of type FRAME_ENCODING_ERROR.
        if max_streams > MAX_STREAMS_PER_TYPE {
            return Err(Error::FrameEncodingError);
        }

        self.concurrency_control
            .update_peer_max_streams(bidi, max_streams);

        Ok(())
    }

    /// Receive a DATA_BLOCKED frame from the peer.
    pub fn on_data_blocked_frame_received(&mut self, max_data: u64) {
        // We will judge whether to send MAX_DATA frame actively according to the received
        // data, and do not rely on the DATA_BLOCKED frame from the peer.
    }

    /// Receive a STREAM_DATA_BLOCKED frame from the peer.
    pub fn on_stream_data_blocked_frame_received(
        &mut self,
        stream_id: u64,
        max_stream_data: u64,
    ) -> Result<()> {
        // RFC9000 19.13. STREAM_DATA_BLOCKED Frames
        // An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only stream
        // MUST terminate the connection with error STREAM_STATE_ERROR.
        if is_local(stream_id, self.is_server) && !is_bidi(stream_id) {
            return Err(Error::StreamStateError);
        }

        Ok(())
    }

    /// Receive a STREAMS_BLOCKED frame from the peer.
    pub fn on_streams_blocked_frame_received(
        &mut self,
        max_streams: u64,
        bidi: bool,
    ) -> Result<()> {
        if max_streams > MAX_STREAMS_PER_TYPE {
            return Err(Error::FrameEncodingError);
        }

        Ok(())
    }

    /// Receive a RESET_STREAM frame from the peer.
    pub fn on_reset_stream_frame_received(
        &mut self,
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    ) -> Result<()> {
        // Peer can't send data on local initialized unidirectional streams.
        // RFC9000 19.4. RESET_STREAM Frame
        // An endpoint that receives a RESET_STREAM frame for a send-only stream
        // MUST terminate the connection with error STREAM_STATE_ERROR.
        if !is_bidi(stream_id) && is_local(stream_id, self.is_server) {
            return Err(Error::StreamStateError);
        }

        // Note: We cannot move this line to after calling get_or_create() because
        // borrow `*self` as immutable after it is borrowed as mutable was forbidden.
        let max_rx_data_left = self.max_rx_data_left();

        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the frame.
        let stream = match self.get_or_create(stream_id, false) {
            Ok(v) => v,

            // Stream is already closed, just ignore the frame even though
            // it might be illegal.
            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        if !stream.recv.is_complete() {
            warn!("{} received RESET_STREAM frame before recv completed with error code {} and final size {}, recv_off {} read_off {}",
                stream.trace_id, error_code, final_size, stream.recv.recv_off, stream.recv.read_off);
        } else {
            trace!(
                "{} received RESET_STREAM frame with error code {} and final size {}",
                stream.trace_id,
                error_code,
                final_size
            );
        }

        let was_readable = stream.is_readable();

        // When a stream is reset, all buffered data will be discarded, so consider
        // the received data as consumed, which might trigger a connection-level
        // flow control update.
        let max_fc_off_delta = final_size.saturating_sub(stream.recv.read_off());

        let max_rx_off_delta = stream.recv.reset(error_code, final_size)? as u64;

        if max_rx_off_delta > max_rx_data_left {
            return Err(Error::FlowControlError);
        }

        let is_readable = stream.is_readable();
        let is_complete = stream.is_complete();
        let local = stream.local;

        if !was_readable && is_readable {
            self.mark_readable(stream_id, true);
        }

        // Mark closed if the stream is complete and not readable.
        if is_complete && !is_readable {
            self.mark_closed(stream_id, local);
        }

        self.flow_control.increase_recv_off(max_rx_off_delta);
        self.flow_control.increase_read_off(max_fc_off_delta);
        if self.flow_control.should_send_max_data() {
            self.rx_almost_full = true;
        }

        Ok(())
    }

    /// Receive a STOP_SENDING frame from the peer.
    pub fn on_stop_sending_frame_received(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<()> {
        // RFC9000 19.5. STOP_SENDING Frames
        // An endpoint that receives a STOP_SENDING frame for a receive-only
        // stream MUST terminate the connection with error STREAM_STATE_ERROR.
        if !is_local(stream_id, self.is_server) && !is_bidi(stream_id) {
            return Err(Error::StreamStateError);
        }

        // Note that the following rule is implemented in get_or_create().
        // Receiving a STOP_SENDING frame for a locally initiated stream that
        // has not yet been created MUST be treated as a connection error of
        // type STREAM_STATE_ERROR.

        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the frame.
        let stream = match self.get_or_create(stream_id, false) {
            Ok(v) => v,

            // Stream is already closed, just ignore the frame even though
            // it might be illegal.
            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        if !stream.send.is_complete() {
            warn!("{} received STOP_SENDING frame before send completed with error code {}, write_off {} unsent_off {} unacked_len {}",
                stream.trace_id, error_code, stream.send.write_off, stream.send.unsent_off, stream.send.unacked_len);
        } else {
            trace!(
                "{} received STOP_SENDING frame with error code {}",
                stream.trace_id,
                error_code
            );
        }

        let was_writable = stream.is_writable();

        if let Ok((final_size, unsent)) = stream.send.stop(error_code) {
            // Claw back some flow control allowance from data that was
            // buffered but not actually sent before the stream was
            // reset.
            self.send_capacity.tx_data = self.send_capacity.tx_data.saturating_sub(unsent);
            self.send_capacity.update_capacity();

            // RFC9000 3.5
            //   A STOP_SENDING frame requests that the receiving endpoint send a RESET_STREAM frame.
            // An endpoint that receives a STOP_SENDING frame MUST send a RESET_STREAM frame if the
            // stream is in the "Ready" or "Send" state. If the stream is in the "Data Sent" state,
            // the endpoint MAY defer sending the RESET_STREAM frame until the packets containing
            // outstanding data are acknowledged or declared lost. If any outstanding data is declared
            // lost, the endpoint SHOULD send a RESET_STREAM frame instead of retransmitting the data.
            //   An endpoint SHOULD copy the error code from the STOP_SENDING frame to the RESET_STREAM
            // frame it sends, but it can use any application error code. An endpoint that sends a
            // STOP_SENDING frame MAY ignore the error code in any RESET_STREAM frames subsequently
            // received for that stream.
            self.mark_reset(stream_id, true, error_code, final_size);

            if !was_writable {
                self.mark_writable(stream_id, true);
            }
        }
        Ok(())
    }

    /// Autotune the connection's receive-side flow control window size.
    pub fn autotune_window(&mut self, now: time::Instant, srtt: time::Duration) {
        self.flow_control.autotune_window(now, srtt);
    }

    /// Get the connection's receive-side flow control limit.
    pub fn max_rx_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Get the connection's receive-side next flow control limit that will be
    /// sent to the peer in a MAX_DATA frame.
    pub fn max_rx_data_next(&self) -> u64 {
        self.flow_control.max_data_next()
    }

    /// Apply the connection's receive-side new flow control limit.
    pub fn update_max_rx_data(&mut self, now: Instant) {
        self.flow_control.update_max_data(now);
    }

    /// Ensure that the connection flow control window always has some room
    /// compared to the stream flow control window.
    pub fn ensure_window_lower_bound(&mut self, min_window: u64) {
        self.flow_control.ensure_window_lower_bound(min_window);
    }

    /// Get the connection's receive-side flow control capacity remaining.
    fn max_rx_data_left(&self) -> u64 {
        self.flow_control.max_data() - self.flow_control.recv_off()
    }

    /// Get the connection's send-side flow control capacity remaining.
    fn max_tx_data_left(&self) -> u64 {
        self.send_capacity.max_data - self.send_capacity.tx_data
    }

    /// Get the largest offset observed on current connection.
    #[cfg(test)]
    fn max_recv_off(&self) -> u64 {
        self.flow_control.recv_off()
    }

    /// Get the connection's send-side flow control limit.
    #[cfg(test)]
    fn max_tx_data(&self) -> u64 {
        self.send_capacity.max_data
    }

    /// Get the total amount of data sent on the entire connection.
    #[cfg(test)]
    fn tx_data(&self) -> u64 {
        self.send_capacity.tx_data
    }

    /// Get the connection's send-side flow control capacity remaining.
    #[cfg(test)]
    fn tx_capacity(&self) -> usize {
        self.send_capacity.capacity
    }

    /// Receive a STREAM frame from the peer.
    pub fn on_stream_frame_received(
        &mut self,
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
        data: Bytes,
    ) -> Result<()> {
        // RFC9000 19.8. STREAM Frames
        // An endpoint MUST terminate the connection with error STREAM_STATE_ERROR
        // if it receives a STREAM frame for a locally initiated stream that has not
        // yet been created, or for a send-only stream.
        if is_local(stream_id, self.is_server) {
            // Recv STREAM frame on a locally initiated uni stream.
            if !is_bidi(stream_id)
            // Recv STREAM frame on a stream that has not yet been created.
            || (self.get(stream_id).is_none() && !self.is_closed(stream_id))
            {
                return Err(Error::StreamStateError);
            }
        }

        // Note: We cannot move this line to after calling get_or_create() because
        // borrow `*self` as immutable after it is borrowed as mutable was forbidden.
        let max_rx_data_left = self.max_rx_data_left();

        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the frame.
        let stream = match self.get_or_create(stream_id, false) {
            Ok(v) => v,

            // Stream is already closed, just ignore the frame even though
            // it might be illegal.
            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        let data_max_off = offset + length as u64;

        // Check for the connection-level flow control limit.
        let max_rx_off_delta = data_max_off.saturating_sub(stream.recv.recv_off());
        if max_rx_off_delta > max_rx_data_left {
            return Err(Error::FlowControlError);
        }

        let was_readable = stream.is_readable();
        let was_draining = stream.is_draining();

        // Insert the new data into the stream's receive buffer.
        stream.recv.write(offset, data, fin)?;

        if !was_readable && stream.is_readable() {
            self.mark_readable(stream_id, true);
        }

        self.flow_control.increase_recv_off(max_rx_off_delta);

        if was_draining {
            // We won't buffer incoming data any more after the stream's receive-side
            // shutdown, but consider the received data as consumed, and try to update
            // the connection-level flow control limit.
            self.flow_control.increase_read_off(max_rx_off_delta);
            if self.flow_control.should_send_max_data() {
                self.rx_almost_full = true;
            }
        }

        Ok(())
    }

    /// STREAM frame was acked, release data block from send buffer, and
    /// delete stream from streams set if it's complete and not readable.
    pub fn on_stream_frame_acked(&mut self, stream_id: u64, offset: u64, length: usize) {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return,
        };

        stream.send.ack_and_drop(offset, length);

        // Mark closed if the stream is complete and not readable.
        if stream.is_complete() && !stream.is_readable() {
            let local = stream.local;
            self.mark_closed(stream_id, local);
        }
    }

    /// RESET_STREAM frame was acked, the sending part of the stream enters
    /// the "Reset Recvd" state, which is a terminal state. If the receiving
    /// part of the stream is already in a terminal state, delete the stream
    /// from streams set.
    pub fn on_reset_stream_frame_acked(&mut self, stream_id: u64) {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return,
        };

        // Mark closed if the stream is complete and not readable.
        if stream.is_complete() && !stream.is_readable() {
            let local = stream.local;
            self.mark_closed(stream_id, local);
        }
    }

    /// STREAM frame was lost, mark data block should be retransmitted and
    /// try add stream to priority queue.
    pub fn on_stream_frame_lost(&mut self, stream_id: u64, offset: u64, length: usize, fin: bool) {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return,
        };

        let was_sendable = stream.is_sendable();
        let empty_fin = length == 0 && fin;

        // Mark data block should be retransmitted.
        stream.send.retransmit(offset, length);

        // Add stream to priority queue if the stream is now sendable and
        // it wasn't already queued.
        // Note that the stream may only has a zero-length frame with fin flag.
        if (stream.is_sendable() || empty_fin) && !was_sendable {
            let urgency = stream.urgency;
            let incremental = stream.incremental;
            self.push_sendable(stream_id, urgency, incremental);
        }
    }

    /// RESET_STREAM frame was lost, if the stream is still open, add the stream
    /// to the reset set to ensure a RESET_STREAM frame will be retransmitted.
    pub fn on_reset_stream_frame_lost(&mut self, stream_id: u64, error_code: u64, final_size: u64) {
        if self.streams.contains_key(&stream_id) {
            self.mark_reset(stream_id, true, error_code, final_size);
        }
    }

    /// STOP_SENDING frame was lost, add the stream to the stopped set to ensure
    /// a STOP_SENDING frame will be sent unless the stream receive-side is finished.
    pub fn on_stop_sending_frame_lost(&mut self, stream_id: u64, error_code: u64) {
        let stream = match self.streams.get(&stream_id) {
            Some(v) => v,
            None => return,
        };

        // Receive-side final size is known, do not retransmit STOP_SENDING frame.
        if !stream.recv.is_fin() {
            self.mark_stopped(stream_id, true, error_code);
        }
    }

    /// MAX_STREAM_DATA frame was lost, add the stream to the almost full set
    /// to ensure a MAX_STREAM_DATA frame will be sent.
    pub fn on_max_stream_data_frame_lost(&mut self, stream_id: u64) {
        if self.streams.contains_key(&stream_id) {
            self.mark_almost_full(stream_id, true);
        }
    }

    /// MAX_DATA frame was lost, mark the receive-side flow control of the
    /// connection is almost full to ensure a MAX_DATA frame will be sent.
    pub fn on_max_data_frame_lost(&mut self) {
        self.rx_almost_full = true;
    }

    /// MAX_STREAMS frame was lost.
    pub fn on_max_streams_frame_lost(&mut self, bidi: bool, max: u64) {
        // We will send MAX_STREAMS frames to update the max_streams limit according to
        // the stream consumption situation actively, but we will not retransmit the lost
        // MAX_STREAMS frames. If multiple MAX_STREAMS frames are lost continuously, it
        // may cause the max_streams limit perceived by the peer to be smaller than the
        // max_streams limit we set. At this time, the peer should process according to
        // the max_streams limit specified in the protocol.
    }

    /// STREAM_DATA_BLOCKED frame was lost, if peer still not issue more
    /// max_stream_data credits, mark stream data blocked again to ensure
    /// a STREAM_DATA_BLOCKED frame will be sent.
    pub fn on_stream_data_blocked_frame_lost(&mut self, stream_id: u64, blocked_at: u64) {
        let stream = match self.streams.get(&stream_id) {
            Some(v) => v,
            None => return,
        };

        if blocked_at == stream.send.max_data {
            self.mark_blocked(stream_id, true, blocked_at);
        }
    }

    /// DATA_BLOCKED frame was lost, if peer still not issue more max_data credits,
    /// mark data blocked again to ensure a DATA_BLOCKED frame will be sent.
    pub fn on_data_blocked_frame_lost(&mut self, max: u64) {
        if max == self.send_capacity.max_data {
            self.update_data_blocked_at(Some(max));
        }
    }

    /// STREAMS_BLOCKED frame was lost, if peer still not issue more max_streams credits,
    /// mark streams blocked again to ensure a STREAMS_BLOCKED frame will be sent.
    pub fn on_streams_blocked_frame_lost(&mut self, bidi: bool, max_streams: u64) {
        if max_streams == self.concurrency_control.peer_max_streams(bidi) {
            self.concurrency_control
                .update_streams_blocked_at(bidi, Some(max_streams));
        }
    }

    /// Get the number of active streams in the map.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Update the peer transport parameters after receiving them from the peer.
    pub fn update_peer_stream_transport_params(&mut self, tp: StreamTransportParams) {
        self.peer_transport_params = tp;

        // Update the peer's max data and local's send capacity for
        // connection-level send-side flow control.
        self.send_capacity.update_max_data(tp.initial_max_data);
        self.send_capacity.update_capacity();

        // Update the peer's max streams limit for concurrency control.
        self.concurrency_control
            .update_peer_max_streams(true, tp.initial_max_streams_bidi);
        self.concurrency_control
            .update_peer_max_streams(false, tp.initial_max_streams_uni);
    }
}

/// Various flags of QUIC stream
#[bitflags]
#[repr(u32)]
#[derive(Clone, Copy)]
enum StreamFlags {
    /// Upper layer want to read data from stream.
    WantRead = 1 << 0,

    /// Upper layer want to write data to stream.
    WantWrite = 1 << 1,

    /// The stream has been closed and is waiting to release its resources.
    Closed = 1 << 2,
}

#[derive(Default)]
pub struct Stream {
    /// Whether the stream is bidirectional.
    pub bidi: bool,

    /// Whether the stream was created by the local endpoint.
    pub local: bool,

    /// The stream's urgency.
    //  1. RFC 9000 - 5.3.  Stream Prioritization
    //    Stream multiplexing can have a significant effect on application performance
    //  if resources allocated to streams are correctly prioritized.
    //    QUIC does not provide a mechanism for exchanging prioritization information.
    //  Instead, it relies on receiving priority information from the application.
    //    A QUIC implementation SHOULD provide ways in which an application can indicate
    //  the relative priority of streams. An implementation uses information provided
    //  by the application to determine how to allocate resources to active streams.
    //
    //  2. RFC 9218 - 4.1. Urgency
    //    Endpoints use this parameter to communicate their view of the precedence of
    //  HTTP responses. The chosen value of urgency can be based on the expectation
    //  that servers might use this information to transmit HTTP responses in the order
    //  of their urgency. The smaller the value, the higher the precedence.
    pub urgency: u8,

    /// Whether the stream data can be send incrementally.
    //  1. RFC 9000 QUIC transport prototocl doesn't define incremental parameter.
    //  2. RFC 9218 - 4.2. Incremental
    //    The incremental parameter value is Boolean. It indicates if an HTTP response
    //  can be processed incrementally, i.e., provide some meaningful output as chunks
    //  of the response arrive.
    pub incremental: bool,

    /// Receive-side stream buffer.
    pub recv: RecvBuf,

    /// Send-side stream buffer.
    pub send: SendBuf,

    /// Application can write data to send buffer only when flow control capacity
    /// larger than this value.
    //  Use case: Headers need to be sent atomically, so we should make sure there
    //  has enough capacity before sending headers.
    pub write_thresh: usize,

    /// Various stream states.
    flags: BitFlags<StreamFlags>,

    /// For holding Application context.
    pub context: Option<Box<dyn Any + Send + Sync>>,

    /// Unique trace id for debug logging.
    trace_id: String,
}

impl Stream {
    /// Create a new stream with the given flow control limits.
    pub fn new(
        bidi: bool,
        local: bool,
        max_tx_data: u64,
        max_rx_data: u64,
        max_window: u64,
    ) -> Stream {
        let flags = match bidi {
            // New bidi stream is always want to read and write.
            true => WantRead | WantWrite,
            false => {
                match local {
                    // New local initialize uni stream is always want to write, and not want to read.
                    true => WantWrite.into(),
                    // New remote initialize uni stream is always want to read, and not want to write.
                    false => WantRead.into(),
                }
            }
        };

        Stream {
            bidi,
            local,
            // 1.RFC9000 QUIC transport protocol doesn't specify the default value of
            // stream urgency.
            //
            // 2.RFC9218 define the HTTP stream urgency range from 0 to 7,
            // and 3 is the default, which is the middle of the range.
            //
            // 3.We use 127 as the default value, which is the middle of the u8 range.
            // not mandatory and can be changed, but we think 127 is a good choice.
            urgency: 127,
            // 1.RFC9000 QUIC transport protocol doesn't define incremental parameter.
            //
            // 2.RFC9218 define incremental parameter for HTTP, it indicates if HTTP
            // response can be processed incrementally, i.e, provide some meaningful
            // output as chunks of the response arrive.
            // The default value of incremental parameter is false(0).
            //
            // 3.Above all, we set the default value to true, which is more reasonable
            // and helps ensure fairness in scheduling.
            incremental: true,
            recv: RecvBuf::new(max_rx_data, max_window),
            send: SendBuf::new(max_tx_data),
            write_thresh: 1,
            flags,
            context: None,
            trace_id: String::new(),
        }
    }

    /// Set trace id.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.trace_id = trace_id.to_string();
        self.send.trace_id = trace_id.to_string();
        self.recv.trace_id = trace_id.to_string();
    }

    /// Return true if the stream has data to be read or an error to be collected.
    pub fn is_readable(&self) -> bool {
        self.recv.ready()
    }

    /// Return true if the stream's send-side has not been shutdown by application
    /// and is not finished and it has enough flow control capacity to be written to.
    pub fn is_writable(&self) -> bool {
        !self.send.is_fin()
            && !self.send.is_shutdown()
            && (self.send.write_off + self.write_thresh as u64) <= self.send.max_data
    }

    /// Return true if the stream buffering some data and flow control allows some of
    /// them to be sent.
    pub fn is_sendable(&self) -> bool {
        self.send.ready()
    }

    /// Return true if the stream is complete.
    pub fn is_complete(&self) -> bool {
        match (self.bidi, self.local) {
            // For bidi streams, the stream is closed when both send and receive are
            // complete.
            (true, _) => self.send.is_complete() && self.recv.is_complete(),
            // For uni streams initialized locally, the stream is closed when the send
            // side is complete.
            (false, true) => self.send.is_complete(),
            // For uni streams initialized by peer, the stream is closed when the recv
            // side is complete.
            (false, false) => self.recv.is_complete(),
        }
    }

    /// Return true if the stream receive-side has been shutdown.
    /// If true, all new incoming data will be discarded.
    pub fn is_draining(&self) -> bool {
        self.recv.is_shutdown()
    }

    /// Check whether the stream is WantWrite
    pub fn is_wantwrite(&self) -> bool {
        self.flags.contains(WantWrite)
    }

    /// Mark the stream as WantWrite or not.
    ///
    /// Return error if the stream is not bidi and not local uni stream.
    pub fn mark_wantwrite(&mut self, flag: bool) -> Result<()> {
        if !self.bidi && !self.local {
            return Err(Error::InternalError);
        }

        match flag {
            true => self.flags.insert(WantWrite),
            false => self.flags.remove(WantWrite),
        };

        Ok(())
    }

    /// Check whether the stream is WantRead
    pub fn is_wantread(&self) -> bool {
        self.flags.contains(WantRead)
    }

    /// Mark the stream as WantRead.
    ///
    /// Return error if the stream is not bidi and not remote uni stream.
    pub fn mark_wantread(&mut self, flag: bool) -> Result<()> {
        if !self.bidi && self.local {
            return Err(Error::InternalError);
        }

        match flag {
            true => self.flags.insert(WantRead),
            false => self.flags.remove(WantRead),
        };

        Ok(())
    }

    /// Check whether the stream is closed.
    pub fn is_closed(&self) -> bool {
        self.flags.contains(Closed)
    }

    /// Mark the stream as closed.
    pub fn mark_closed(&mut self) {
        self.flags.insert(Closed);
    }
}

/// Return true if the stream was created locally.
///
/// The least significant bit (0x01) of the stream ID identifies the initiator
/// of the stream.
/// Client-initiated streams have even-numbered stream IDs (with the bit set to 0),
/// and server-initiated streams have odd-numbered stream IDs (with the bit set to 1).
fn is_local(stream_id: u64, is_server: bool) -> bool {
    (stream_id & 0x1) == (is_server as u64)
}

/// Return true if the stream is bidirectional.
///
/// The second least significant bit (0x02) of the stream ID distinguishes
/// between bidirectional streams (with the bit set to 0) and unidirectional
/// streams (with the bit set to 1).
pub fn is_bidi(stream_id: u64) -> bool {
    (stream_id & 0x2) == 0
}

/// An iterator over QUIC streams.
#[derive(Default)]
pub struct StreamIter {
    streams: SmallVec<[u64; 8]>,
}

impl StreamIter {
    #[inline]
    fn from(streams: &StreamIdHashSet) -> Self {
        StreamIter {
            streams: streams.iter().copied().collect(),
        }
    }
}

impl Iterator for StreamIter {
    type Item = u64;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.streams.pop()
    }
}

impl ExactSizeIterator for StreamIter {
    #[inline]
    fn len(&self) -> usize {
        self.streams.len()
    }
}

/// Receive-side stream buffer.
///
/// The stream data received from peer is buffered in a BTreeMap ordered by
/// offset in ascending order. Contiguous data can then be read into a slice.
#[derive(Debug, Default)]
pub struct RecvBuf {
    /// Chunks of data received from the peer ordered by offset
    /// but have not yet been read by the application.
    /// Note: The key is the maximum offset of the chunk, not the lowest.
    data: BTreeMap<u64, RangeBuf>,

    /// The lowest data offset that has yet to be read by the application.
    read_off: u64,

    /// The largest data offset that has been received on this stream.
    recv_off: u64,

    /// The final stream offset received from the peer, if any.
    fin_off: Option<u64>,

    /// The error code received from the RESET_STREAM frame.
    error: Option<u64>,

    /// Whether the stream's Receive-side has been shut down.
    shutdown: bool,

    /// Receive-side stream flow controller.
    flow_control: flowcontrol::FlowControl,

    /// Unique trace id for debug logging.
    trace_id: String,
}

impl RecvBuf {
    /// Create a new receive-side stream buffer with given flow control limits.
    fn new(max_data: u64, max_window: u64) -> RecvBuf {
        RecvBuf {
            flow_control: flowcontrol::FlowControl::new(max_data, max_window),
            ..RecvBuf::default()
        }
    }

    /// Insert the given chunk of data into the buffer.
    pub fn write(&mut self, offset: u64, data: Bytes, fin: bool) -> Result<()> {
        let buf = RangeBuf::new(data, offset, fin);

        // 1. Validate the legality of stream flow control limits
        // An endpoint MUST terminate a connection with an error of type FLOW_CONTROL_ERROR
        // if it receives more data than the largest maximum stream data that it has sent
        // for the affected stream.
        if buf.max_off() > self.max_data() {
            return Err(Error::FlowControlError);
        }

        // 2. Validate the legality of final size constraints
        if let Some(fin_off) = self.fin_off {
            // A receiver SHOULD treat receipt of data at or beyond the final size as an
            // error of type FINAL_SIZE_ERROR.
            if buf.max_off() > fin_off {
                return Err(Error::FinalSizeError);
            }

            // Once a final size for a stream is known, it cannot change. If a STREAM
            // frame is received indicating a change in the final size for the stream,
            // an endpoint SHOULD respond with an error of type FINAL_SIZE_ERROR.
            if buf.fin() && fin_off != buf.max_off() {
                return Err(Error::FinalSizeError);
            }
        }

        // An endpoint received a STREAM frame containing a final size that was lower than
        // the size of stream data that was already received.
        if buf.fin() && buf.max_off() < self.recv_off {
            return Err(Error::FinalSizeError);
        }

        // 3. Check if the stream's receive-side is finished
        if self.is_fin() {
            return Ok(());
        }

        // If the buffer with a FIN flag, then set the final size of the stream
        // to the maximum offset of the buffer.
        if buf.fin() {
            self.fin_off = Some(buf.max_off());
        }

        // Do nothing if the buffer is empty and without fin flag.
        if !buf.fin() && buf.is_empty() {
            return Ok(());
        }

        // 4. Check if the buffer overlaps with existing data blocks
        // Check if data is fully duplicated, that is the buffer's max offset is
        // lower or equal to the lowest data offset that has yet to be read by
        // the application.
        if self.read_off >= buf.max_off() {
            // Exception case: Empty buffer with FIN flag.
            if !buf.is_empty() {
                return Ok(());
            }
        }

        // The newly received data may overlap with existing data blocks, and
        // it may be split into multiple segments before being stored.
        let mut tmp_bufs = VecDeque::with_capacity(2);
        tmp_bufs.push_back(buf);

        'outer_loop: while let Some(mut buf) = tmp_bufs.pop_front() {
            // Bytes up to self.read_off have already been consumed by application
            // so we should not buffer them again, just discard them.
            if self.read_off() > buf.off() {
                buf.advance((self.read_off() - buf.off()) as usize);
            }

            // Handle overlapping buffer or merge an empty final buffer.
            if buf.off() < self.recv_off() || buf.is_empty() {
                for (_, b) in self.data.range(buf.off()..) {
                    let off = buf.off();

                    // New buffer cannot overlap with any of the following buffers.
                    if b.off() > buf.max_off() {
                        break;
                    }
                    // New buffer completely overlaps with the existing one.
                    // i.e.[b.start  [buf.start, buf.end)  b.end)
                    else if off >= b.off() && buf.max_off() <= b.max_off() {
                        continue 'outer_loop;
                    }
                    // The first half of the buffer "buf" overlaps with the existing
                    // buffer "b". Advance the buffer "buf" to the end of the existing
                    // buffer "b".
                    // i.e. b.start < buf.start < b.end, discard [buf.start, b.end),
                    // and store buf = buf[b.end, buf.end)
                    else if off >= b.off() && off < b.max_off() {
                        buf.advance((b.max_off() - off) as usize);
                    }
                    // The second half of the buffer "buf" overlaps with the existing
                    // buffer "b". Use "split_off" to split the buffer, insert the first
                    // half of "buf" into "BTreeMap" after "for" loop, and the second
                    // half may still overlap with the existing part of "buf". Insert it
                    // into the temporary "VecDeque" for further processing.
                    // i.e. buf.start < b.start and buf.end > b.start
                    // [buf.start, b.start) will be insert to "BTreeMap"
                    // [b.start, buf.end) insert into the temp "VecDeque"
                    else if off < b.off() && buf.max_off() > b.off() {
                        tmp_bufs.push_back(buf.split_off((b.off() - off) as usize));
                    }
                }
            }

            // update stream received offset to max_off
            self.recv_off = cmp::max(self.recv_off, buf.max_off());

            if !self.shutdown {
                // Here we take buf.max_off as key but not buf.off,
                // because buf.off maybe changed while application consuming buf partially.
                self.data.insert(buf.max_off(), buf);
            }
        }

        Ok(())
    }

    /// Read data from the receive buffer, and write them into the given output buffer.
    ///
    /// Currently, only contiguous data can be consumed by application. If there is no
    /// data at the expected read offset, return `Done`.
    ///
    /// On success the amount of data read, and a flag indicating if there is
    /// no more data in the buffer, are returned as a tuple.
    pub fn read(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut len = 0;
        let mut cap = out.len();

        // Only contiguous data can be consumed by application.
        if !self.ready() {
            return Err(Error::Done);
        }

        // The stream has been reset by the peer.
        if let Some(e) = self.error {
            // An empty buffer with FIN flag may be left in the buffer when the stream
            // is reset, because the final offset of the stream is not known when the
            // stream is reset.
            self.data.clear();
            return Err(Error::StreamReset(e));
        }

        while cap > 0 && self.ready() {
            let mut entry = match self.data.first_entry() {
                Some(entry) => entry,
                None => break,
            };

            let buf = entry.get_mut();
            let buf_len = cmp::min(buf.len(), cap);
            out[len..len + buf_len].copy_from_slice(&buf[..buf_len]);

            // Update the lowest data offset that has yet to be read by the application.
            self.read_off += buf_len as u64;

            len += buf_len;
            cap -= buf_len;

            if buf_len < buf.len() {
                buf.consume(buf_len);

                // Reached the maximum capacity, stop reading.
                break;
            }

            // The data in current entry has all been consumed.
            entry.remove();
        }

        // Update consumed bytes for future stream-level flow control.
        self.flow_control.increase_read_off(len as u64);

        Ok((len, self.is_fin()))
    }

    /// Return true if the stream has buffered data to be read or an error to
    /// be collected.
    fn ready(&self) -> bool {
        match self.data.first_key_value() {
            Some((_, buf)) => buf.off() == self.read_off,
            None => false,
        }
    }

    /// Receive RESET_STREAM frame from peer, reset the stream at the given offset.
    ///
    /// If the recv side is not shutdown by the application, an empty buffer with
    /// FIN will be written to the recv buffer to notify the application that it
    /// has been reset by its peer.
    pub fn reset(&mut self, error_code: u64, final_size: u64) -> Result<usize> {
        // Once a final size for a stream is known, it cannot change. If a RESET_STREAM
        // frame is received indicating a change in the final size for the stream,
        // an endpoint SHOULD respond with an error of type FINAL_SIZE_ERROR.
        if let Some(fin_off) = self.fin_off {
            if fin_off != final_size {
                return Err(Error::FinalSizeError);
            }
        }

        // An endpoint received a RESET_STREAM frame containing a final size that was
        // lower than the size of stream data that was already received.
        if final_size < self.recv_off {
            return Err(Error::FinalSizeError);
        }

        // Align the consumption of connection flow control in bytes
        let max_rx_off_delta = final_size - self.recv_off;

        // Duplicate RESET_STREAM frame.
        if self.error.is_some() {
            return Ok(max_rx_off_delta as usize);
        }

        self.error = Some(error_code);

        // Discard all buffered data.
        self.data.clear();

        // Notify application that the stream has been reset by the peer.
        trace!(
            "Write an empty buffer with FIN to stream recv {:}",
            self.trace_id
        );
        self.write(final_size, Bytes::new(), true)?;

        self.read_off = final_size;

        Ok(max_rx_off_delta as usize)
    }

    /// Shutdown the stream's receive-side.
    ///
    /// After this operation, any subsequent data received on the stream will be discarded.
    fn shutdown(&mut self) -> Result<u64> {
        if self.shutdown {
            return Err(Error::Done);
        }

        // After shutdown flag is set, all subsequent data received on the stream
        // will be discarded.
        self.shutdown = true;

        let unread_len = self.recv_off() - self.read_off();

        // Discard all buffered data.
        self.data.clear();

        // Set application read offset as the largest received offset.
        self.read_off = self.recv_off();

        Ok(unread_len)
    }

    /// Apply the new local flow control limit.
    pub fn update_max_data(&mut self, now: time::Instant) {
        self.flow_control.update_max_data(now);
    }

    /// Get the next max_data limit, which will be sent to peer in MAX_STREAM_DATA frame.
    pub fn max_data_next(&mut self) -> u64 {
        self.flow_control.max_data_next()
    }

    /// Get the local current flow control limit.
    fn max_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Get the local current flow control window.
    pub fn window(&self) -> u64 {
        self.flow_control.window()
    }

    /// Autotune the local flow control window size.
    pub fn autotune_window(&mut self, now: time::Instant, srtt: time::Duration) {
        self.flow_control.autotune_window(now, srtt);
    }

    /// Get the lowest data offset that has yet to be read by the application.
    fn read_off(&self) -> u64 {
        self.read_off
    }

    /// Get the largest offset that has been received so far.
    fn recv_off(&self) -> u64 {
        self.recv_off
    }

    /// Return true if we should send `MAX_STREAM_DATA` frame to peer to update
    /// the local flow control limit.
    fn should_send_max_data(&self) -> bool {
        self.fin_off.is_none() && self.flow_control.should_send_max_data()
    }

    /// Return true if the stream's receive-side has been shutdown by application.
    fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Return true if the stream's receive-side final size is known, and the
    /// application has read all data from the stream.
    fn is_fin(&self) -> bool {
        self.fin_off == Some(self.read_off)
    }

    /// Return true if the stream's receive-side is complete.
    ///
    /// Actually, this is same as `is_fin()`.
    fn is_complete(&self) -> bool {
        self.fin_off == Some(self.read_off)
    }
}

/// Send-side stream buffer.
///
/// Buffer of outgoing retransmittable stream data.
///
/// New data is appended at the end of the stream, always.
#[derive(Debug, Default)]
pub struct SendBuf {
    /// Chunks of data to be sent, ordered by offset.
    /// Data written by application but not yet acknowledged.
    /// May or may not have been sent.
    data: VecDeque<RangeBuf>,

    /// The index of the data block that will be sent next. This design is to
    /// improve the performance of reading next sent data from `data` queue.
    /// Note that pos will be decreased when data is lost and needs to be retransmitted.
    pos: usize,

    /// The maximum offset of data written by application in the stream.
    write_off: u64,

    /// The first offset that has not been sent.
    unsent_off: u64,

    /// Total size of `unacked_segments`
    //  unacked_len = self.write_off - self.ack_off()
    unacked_len: usize,

    /// The maximum offset of data that can be sent in the stream.
    max_data: u64,

    /// The offset of data that is blocked by flow control, if any.
    blocked_at: Option<u64>,

    /// The final size of the stream, if known.
    fin_off: Option<u64>,

    /// Whether the stream's send-side has been shutdown.
    /// If true, no more data can be written to the stream.
    shutdown: bool,

    /// Ranges of data offsets that have been acknowledged.
    acked: ranges::RangeSet,

    /// Ranges of data offsets that have been deemed lost.
    retransmits: ranges::RangeSet,

    /// The error code received from the peer via STOP_SENDING.
    error: Option<u64>,

    /// Unique trace id for debug logging.
    trace_id: String,
}

impl SendBuf {
    /// Create a new send buffer with the given maximum stream data.
    fn new(max_data: u64) -> SendBuf {
        SendBuf {
            max_data,
            ..SendBuf::default()
        }
    }

    /// Insert data at the end of the buffer.
    /// Return the number of bytes that actually got written.
    pub fn write(&mut self, mut data: Bytes, mut fin: bool) -> Result<usize> {
        let max_off = self.write_off + data.len() as u64;

        // Get the number of bytes that can be written to the stream.
        // Note: Here may return an error if the stream was stopped.
        let capacity = self.capacity()?;

        if data.len() > capacity {
            // Truncate the data to fit the stream's capacity.
            let len = capacity;
            data.truncate(len);

            // Clear the fin flag because we are not writing the full data.
            fin = false;
        }

        if let Some(fin_off) = self.fin_off {
            // Can't write more data after the final offset.
            if max_off > fin_off {
                return Err(Error::FinalSizeError);
            }

            // Fin flag can't be cancelled after it was set.
            if max_off == fin_off && !fin {
                return Err(Error::FinalSizeError);
            }
        }

        if fin {
            self.fin_off = Some(max_off);
        }

        // We can't do this check earlier because we need to check the fin flag.
        if data.is_empty() {
            return Ok(data.len());
        }

        let data_len = data.len();
        let mut len = 0;

        // Split the remaining data into consistently sized chunks to avoid fragmentation.
        // Note: Chunks return from Bytes::chunks() are slices, not what we want.
        while data.len() > SEND_BUFFER_SIZE {
            let chunk = data.split_to(SEND_BUFFER_SIZE);
            len += chunk.len();

            let fin = len == data_len && fin;
            let buf = RangeBuf::new(chunk, self.write_off, fin);

            self.write_off += buf.len() as u64;
            self.data.push_back(buf);
        }

        // Write the remaining data.
        if !data.is_empty() {
            let buf = RangeBuf::new(data, self.write_off, fin);

            self.write_off += buf.len() as u64;
            self.data.push_back(buf);
        }

        self.unacked_len += data_len;

        Ok(data_len)
    }

    /// Compute the next range to transmit on the stream and update state to account
    /// for that transmission.
    ///
    /// Return the range of bytes to transmit.
    fn poll_transmit(&mut self, max_len: usize) -> Range<u64> {
        // 1. Check and Retransmit sent data
        if let Some(range) = self.retransmits.pop_min() {
            let end = cmp::min(range.end, range.start.saturating_add(max_len as u64));
            if end != range.end {
                self.retransmits.insert(end..range.end);
            }

            let rtx_range = range.start..end;
            trace!("{} poll_transmit, rtx range {:?}", self.trace_id, rtx_range);
            return rtx_range;
        }

        // 2. Transmit new data
        // Range: [self.unsent_off, min(write_off, self.unsent_off + max_len))
        let end = cmp::min(
            self.write_off,
            self.unsent_off.saturating_add(max_len as u64),
        );
        let new_range = self.unsent_off..end;
        trace!("{} poll_transmit, new range {:?}", self.trace_id, new_range);
        self.unsent_off = end;
        new_range
    }

    /// Read the range-associated interval data, which may actually be a subset of
    /// the range. For example, in scenarios where the data in the send buffer is not
    /// continuous, the caller should try again.
    fn read_range(&mut self, range: Range<u64>) -> &[u8] {
        while let Some(segment) = self.data.get(self.pos) {
            if range.start >= segment.off() && range.start < segment.max_off() {
                let start = (range.start - segment.off()) as usize;
                let end = ((range.end - segment.off()) as usize).min(segment.len());

                // The entire data block will be read, increase the position.
                if end == segment.len() {
                    self.pos += 1;
                }

                return &segment[start..end];
            }

            self.pos += 1;
        }

        &[]
    }

    /// Read data from the send buffer, and write them into the given output buffer.
    /// Return output buffer length and fin flag.
    pub fn read(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut len = 0;
        let mut cap = out.len();
        let out_off = self.send_off();
        // The caller of this function has already written the offset of the STREAM frame
        // into the header of the frame, so we must keep it consistent here.
        let mut next_off = out_off;

        while cap > 0
            && self.ready()
            && self.send_off() == next_off
            && self.send_off() < self.max_data
        {
            let range = self.poll_transmit(cap);
            // The data specified by the range may not be stored contiguously, so it
            // may not be retrieved by a single `read_range` call, so here we need to loop
            // until the range is completely copied into the given out buffer.
            let mut range = range.clone();

            let range_len: u64 = range.end - range.start;
            while range.start != range.end {
                let data = self.read_range(range.clone());
                let buf_len = data.len();

                out[len..len + buf_len].copy_from_slice(&data[..buf_len]);
                len += buf_len;
                range.start += buf_len as u64;
            }

            cap -= range_len as usize;
            next_off += range_len;
        }

        // Get the fin flag for the output buffer by matching the maximum offset of
        // the output buffer with the final offset of the stream(if any).
        //
        // Note: When send buffer only contains empty buffer with fin flag, send buffer
        // is not ready, but the fin flag will be read out.
        let fin = self.fin_off == Some(next_off);

        Ok((out.len() - cap, fin))
    }

    /// Return true if there is data to be sent.
    ///
    /// There may be some data inflight that has been sent but not yet acknowledged,
    /// even this is false.
    fn ready(&self) -> bool {
        !self.data.is_empty() && self.send_off() < self.write_off
    }

    /// Update the stream's send-side max_data limit.
    fn update_max_data(&mut self, max_data: u64) {
        self.max_data = cmp::max(self.max_data, max_data);
    }

    /// Update the last offset at which the stream was blocked, if any.
    fn update_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.blocked_at = blocked_at;
    }

    /// Get the last offset at which the stream was blocked, if any.
    fn blocked_at(&self) -> Option<u64> {
        self.blocked_at
    }

    /// Return the maximum offset of data written by application
    fn write_off(&self) -> u64 {
        self.write_off
    }

    /// Get the highest offset that has been consecutively acknowledged.
    //  Example: We get ack ranges [0, 50], [55, 60] then return 50.
    fn ack_off(&self) -> u64 {
        match self.acked.iter().next() {
            // Only take the initial range into account if it covers the start
            // of the stream continuously, i.e.[0..N).
            Some(std::ops::Range { start: 0, end }) => end,
            Some(_) | None => 0,
        }
    }

    /// Insert the new ACK packet number range into the range set.
    fn ack(&mut self, off: u64, len: usize) {
        self.acked.insert(off..off + len as u64);
    }

    /// Process the new ACK range, and try to delete the range data
    /// that has been acknowledged continuously(i.e.without holes).
    pub fn ack_and_drop(&mut self, off: u64, len: usize) {
        // Data queue is empty, we can clear the retransmit queue directly without any other processing.
        // There may be three cases:
        // 1. All data has been ACKed, i.e. the current ACK is a duplicate ACK;
        // 2. The stream received STOP_SENDING frame from the peer, and the data queue has been cleared;
        // 3. The stream has been actively RESET by the upper application, and the data queue has been cleared.
        if self.data.is_empty() {
            self.retransmits.clear();
            return;
        }

        trace!(
            "{} ack_and_drop range: {:?}, send_off {}, write_off {}, ack_off {}, pos {}",
            self.trace_id,
            Range {
                start: off,
                end: off + len as u64
            },
            self.send_off(),
            self.write_off(),
            self.ack_off(),
            self.pos
        );

        // Insert the new ACK range into the range set.
        // Note: The first acked range is always like [0, x).
        self.ack(off, len);

        // Spurious retransmission, remove them from retransmit queue.
        self.retransmits.remove(off..off + len as u64);

        // Get the highest contiguously acked offset.
        let ack_off = self.ack_off();

        // If there are gaps between [0, self.ack_off) and [off, off + len),
        // then we can't drop any data.
        if off > ack_off {
            return;
        }

        // Drop the data that has been contiguously acked.
        let base_off = self.write_off - self.unacked_len as u64;
        let mut to_advance: usize = (ack_off - base_off) as usize;
        self.unacked_len -= to_advance;
        let mut drop_blocks = 0;
        while to_advance > 0 {
            let front = self.data.front_mut().unwrap();

            // Drop the data block if it has been fully acknowledged.
            if front.len() <= to_advance {
                to_advance -= front.len();
                self.data.pop_front();
                drop_blocks += 1;
            // Advance the data block if it has been partially acknowledged.
            } else {
                front.advance(to_advance);
                to_advance = 0;
            }
        }

        // Note: We should take spuriously retransmitted scenario into account.
        // When a packet is deemed lost, causing the pos to be rolled back, but
        // the subsequent ack of the packet is received, the pos may be reduced
        // excessively, and we need to avoid this situation.
        self.pos = self.pos.saturating_sub(drop_blocks);

        if self.data.len() * 4 < self.data.capacity() {
            self.data.shrink_to_fit();
        }
    }

    /// Queue a range of sent but unacknowledged data(deemed lost) to the retranmission
    /// range set.
    pub fn retransmit(&mut self, off: u64, len: usize) {
        let mut start = off;
        let mut end = off + len as u64;
        let old_send_off = self.send_off();

        if self.data.is_empty() {
            return;
        }

        if end <= self.ack_off() {
            return;
        }

        // unsent data can't be lost.
        #[cfg(test)]
        if end > self.unsent_off {
            return;
        }

        for range in self.acked.iter() {
            // The retransmit range is before the current range, stop searching.
            if end <= range.start {
                break;
            }

            // The retransmit range is after the range, go to the next range.
            if start >= range.end {
                continue;
            }

            // The retransmit range is overlapped with the acked range, update the range.
            if start < range.start {
                if end <= range.end {
                    // The second half of the retransmit range is covered by the current acked range,
                    // only the first half of the retransmit range needs to be retransmitted.
                    end = range.start;
                    break;
                } else {
                    // start < range.start && end > range.end
                    // The retransmit range crosses the current acked range, split the retransmit
                    // range into two parts, and the first part needs to be retransmitted, and the
                    // second part will be checked against the next acked range.
                    self.retransmits.insert(start..range.start);
                    start = range.end;
                    continue;
                }
            } else {
                // start >= range.start && start < range.end
                if end <= range.end {
                    // Fully covered by the current acked range, clear the retransmit range.
                    end = start;
                    break;
                } else {
                    // start >= range.start && start < range.end && end > range.end
                    // The first half of the retransmit range is covered by the current acked range,
                    // only the second half of the retransmit range may needs to be retransmitted.
                    start = range.end;
                    continue;
                }
            }
        }

        self.retransmits.insert(start..end);

        // 1. If and only if we found new lost data, and the lost data is before the lowest
        // retransmits range, we should update the position of next data block to be sent.
        // 2. This design is to decrease the number of times we need to update the position
        // when we found large number of lost data during one processing cycle.
        if self.send_off() < old_send_off {
            // We don't update the position to the accurate value here. Instead, we update it
            // during the read_range phase, which can reduce the number of update operations.
            self.pos = 0;
        }
    }

    /// Return the first unacked subrange in `range`.
    pub fn filter_acked(&self, range: Range<u64>) -> Option<Range<u64>> {
        self.acked.filter(range)
    }

    /// Reset the stream at the current offset and clean up the cached data.
    ///
    /// Upon receiving a STOP_SENDING frame from peer, or actively shutting down
    /// by application, send a RESET_STREAM frame to peer to reset the stream.
    ///
    /// Return the final offset and the number of bytes that have not been sent.
    fn reset(&mut self) -> (u64, u64) {
        let unsent_len = self.write_off.saturating_sub(self.unsent_off);

        self.fin_off = Some(self.unsent_off);

        // Clean up all buffered data.
        self.data.clear();

        // Mark all sent data as acknowledged.
        self.ack(0, self.unsent_off as usize);

        self.pos = 0;
        self.write_off = self.unsent_off;

        (self.fin_off.unwrap(), unsent_len)
    }

    /// Reset the stream and record the received error code
    /// after receiving a STOP_SENDING frame from peer.
    fn stop(&mut self, error_code: u64) -> Result<(u64, u64)> {
        if self.error.is_some() {
            return Err(Error::Done);
        }

        let (fin_off, unsent) = self.reset();

        self.error = Some(error_code);

        Ok((fin_off, unsent))
    }

    /// Shutdown the stream's send-side.
    ///
    /// Return the stream final size and the number of bytes that have not been sent.
    fn shutdown(&mut self) -> Result<(u64, u64)> {
        if self.shutdown {
            return Err(Error::Done);
        }

        self.shutdown = true;

        Ok(self.reset())
    }

    /// Return true if the send-side of the stream has been shutdown by application.
    fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Return true if the stream's send-side final size is known, and the application
    /// has already written data up to that point.
    fn is_fin(&self) -> bool {
        self.fin_off == Some(self.write_off)
    }

    /// Return true if the stream's send-side enters a terminal state.
    ///
    /// When the stream's send-side final size is known, and all stream data
    /// has been successfully acknowledged, the stream enters a terminal state.
    fn is_complete(&self) -> bool {
        match self.fin_off {
            Some(fin_off) => fin_off == 0 || self.acked == (0..fin_off),
            None => false,
        }
    }

    /// Return true if `STOP_SENDING` frame was received.
    pub fn is_stopped(&self) -> bool {
        self.error.is_some()
    }

    /// Get the lowest offset of data to be sent.
    pub fn send_off(&self) -> u64 {
        // retransmits.min little than unsent_off, always.
        if !self.retransmits.is_empty() {
            self.retransmits.min().unwrap()
        } else {
            self.unsent_off
        }
    }

    /// Get the maximum offset of data that peer allows to send.
    fn max_data(&self) -> u64 {
        self.max_data
    }

    /// Get the stream send capacity. Return an error if the stream is stopped,
    /// else return the number of bytes that can be written to the stream.
    fn capacity(&self) -> Result<usize> {
        match self.error {
            // Stream was stopped by the peer.
            Some(e) => Err(Error::StreamStopped(e)),
            None => Ok((self.max_data - self.write_off) as usize),
        }
    }
}

/// Range buffer containing data at a specific offset.
///
/// The data is stored in a `Bytes` in a manner that allows for sharing
/// among multiple instances of `RangeBuf`.
#[derive(Clone, Debug)]
pub struct RangeBuf {
    /// The buffer that stores the data.
    data: Bytes,

    /// The starting offset of current buffer in a stream.
    off: u64,

    /// Whether current buffer holds the stream's final offset.
    fin: bool,

    // The moment when the data arrives.
    pub time: Instant,
}

impl RangeBuf {
    /// Create a new `RangeBuf` with the given Bytes.
    fn new(buf: Bytes, off: u64, fin: bool) -> RangeBuf {
        RangeBuf {
            data: buf,
            off,
            fin,
            time: Instant::now(),
        }
    }

    /// Return true if current buffer holds the stream's final offset.
    fn fin(&self) -> bool {
        self.fin
    }

    /// Get the starting offset of current buffer in a stream.
    fn off(&self) -> u64 {
        self.off
    }

    /// Get the largest offset of current buffer in a stream.
    fn max_off(&self) -> u64 {
        self.off() + self.len() as u64
    }

    /// Get the length of current buffer.
    fn len(&self) -> usize {
        self.data.len()
    }

    /// Return true if current buffer's length is zero.
    fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    /// Consume the starting `count` bytes of current buffer.
    /// This is equivalent to `self.advance(count)`.
    fn consume(&mut self, count: usize) {
        self.data.advance(count);
        self.off += count as u64;
    }

    /// Advance the internal cursor of current buffer.
    fn advance(&mut self, count: usize) {
        self.data.advance(count);
        self.off += count as u64;
    }

    /// Split the buffer into two at the given index.
    /// Afterwards self.data contains elements [0, at),
    /// and the returned RangeBuf.data contains elements [at, len).
    fn split_off(&mut self, at: usize) -> RangeBuf {
        let buf = RangeBuf {
            data: self.data.split_off(at),
            off: self.off + at as u64,
            fin: self.fin,
            time: self.time,
        };

        self.fin = false;

        buf
    }

    /// Split the buffer into two at the given index.
    /// Afterwards self.data contains elements [at, len),
    /// and the returned RangeBuf.data contains elements [0, at).
    fn split_to(&mut self, at: usize) -> RangeBuf {
        let buf = RangeBuf {
            data: self.data.split_to(at),
            off: self.off,
            fin: false,
            time: self.time,
        };

        self.off += at as u64;

        buf
    }
}

impl std::ops::Deref for RangeBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.data.deref()
    }
}

/// Initial transport parameters for streams.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct StreamTransportParams {
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
}

impl StreamTransportParams {
    pub fn from(tp: &TransportParams) -> Self {
        StreamTransportParams {
            initial_max_data: tp.initial_max_data,
            initial_max_stream_data_bidi_local: tp.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: tp.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: tp.initial_max_stream_data_uni,
            initial_max_streams_bidi: tp.initial_max_streams_bidi,
            initial_max_streams_uni: tp.initial_max_streams_uni,
        }
    }
}

/// Concurrency control for streams.
/// RFC9000 4.6 Controlling Concurrency
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-controlling-concurrency
#[derive(Clone, Debug, PartialEq, Default)]
struct ConcurrencyControl {
    /// Maximum bidirectional streams that the peer allow local endpoint to open.
    peer_max_streams_bidi: u64,

    /// Maximum unidirectional streams that the peer allow local endpoint to open.
    peer_max_streams_uni: u64,

    /// The total number of bidirectional streams opened by the peer.
    peer_opened_streams_bidi: u64,

    /// The total number of unidirectional streams opened by the peer.
    peer_opened_streams_uni: u64,

    /// Maximum bidirectional streams that the local endpoint allow the peer to open.
    local_max_streams_bidi: u64,
    /// The next MAX_STREAMS(type 0x12) limit for bidirectional streams
    local_max_streams_bidi_next: u64,

    /// Maximum unidirectional streams that the local endpoint allow the peer to open.
    local_max_streams_uni: u64,
    /// The next MAX_STREAMS(type 0x13) limit for unidirectional streams
    local_max_streams_uni_next: u64,

    /// The total number of bidirectional streams opened by the local endpoint.
    local_opened_streams_bidi: u64,

    /// The total number of unidirectional streams opened by the local endpoint.
    local_opened_streams_uni: u64,

    /// Local endpoint want to open more bidirectional streams, but blocked by
    /// peer's concurrency control limit, we need to send a STREAMS_BLOCKED(type 0x16)
    /// frame to notify peer.
    streams_blocked_at_bidi: Option<u64>,

    /// Local endpoint want to open more unidirectional streams, but blocked by
    /// peer's concurrency control limit, we need to send a STREAMS_BLOCKED(type 0x17)
    /// frame to notify peer.
    streams_blocked_at_uni: Option<u64>,

    /// Available stream ids for peer initiated bidirectional streams.
    peer_bidi_avail_ids: ranges::RangeSet,

    /// Available stream ids for peer initiated unidirectional streams.
    peer_uni_avail_ids: ranges::RangeSet,

    /// Available stream ids for local initiated bidirectional streams.
    local_bidi_avail_ids: ranges::RangeSet,

    /// Available stream ids for local initiated unidirectional streams.
    local_uni_avail_ids: ranges::RangeSet,
}

impl ConcurrencyControl {
    fn new(local_max_streams_bidi: u64, local_max_streams_uni: u64) -> ConcurrencyControl {
        let mut peer_bidi_avail_ids = ranges::RangeSet::default();
        peer_bidi_avail_ids.insert(0..local_max_streams_bidi);
        let mut peer_uni_avail_ids = ranges::RangeSet::default();
        peer_uni_avail_ids.insert(0..local_max_streams_uni);

        ConcurrencyControl {
            local_max_streams_bidi,
            local_max_streams_bidi_next: local_max_streams_bidi,
            local_max_streams_uni,
            local_max_streams_uni_next: local_max_streams_uni,
            peer_bidi_avail_ids,
            peer_uni_avail_ids,
            ..ConcurrencyControl::default()
        }
    }

    /// Update peer's max_streams limit after receiving a MAX_STREAMS(0x12..0x13) frame
    /// or processing peer's transport parameter.
    fn update_peer_max_streams(&mut self, bidi: bool, max_streams: u64) {
        match bidi {
            true => {
                if self.peer_max_streams_bidi < max_streams {
                    // insert available ids for local initiated bidi-streams
                    let ids = self.peer_max_streams_bidi..max_streams;
                    self.insert_avail_id(ids, true, true);
                    self.peer_max_streams_bidi = max_streams;
                }

                // Cancel the concurrency control blocked state if the max_streams_bidi limit
                // is increased, avoid sending redundant STREAMS_BLOCKED(0x16) frames.
                if Some(self.peer_max_streams_bidi) > self.streams_blocked_at_bidi {
                    self.streams_blocked_at_bidi = None;
                }
            }

            false => {
                if self.peer_max_streams_uni < max_streams {
                    // insert available ids for local initiated uni-streams
                    let ids = self.peer_max_streams_uni..max_streams;
                    self.insert_avail_id(ids, true, false);
                    self.peer_max_streams_uni = max_streams;
                }

                // Cancel the concurrency control blocked state if the max_streams_uni limit
                // is increased, avoid sending redundant STREAMS_BLOCKED(type: 0x17) frames.
                if Some(self.peer_max_streams_uni) > self.streams_blocked_at_uni {
                    self.streams_blocked_at_uni = None;
                }
            }
        }
    }

    /// After sending a MAX_STREAMS(type: 0x12..0x13) frame, update local max_streams limit.
    fn update_local_max_streams(&mut self, bidi: bool) {
        if bidi {
            // insert available ids for peer initiated bidi-streams
            let ids = self.local_max_streams_bidi..self.local_max_streams_bidi_next;
            self.insert_avail_id(ids, false, true);
            self.local_max_streams_bidi = self.local_max_streams_bidi_next;
        } else {
            // insert available ids for peer initiated uni-streams
            let ids = self.local_max_streams_uni..self.local_max_streams_uni_next;
            self.insert_avail_id(ids, false, false);
            self.local_max_streams_uni = self.local_max_streams_uni_next;
        }
    }

    /// Get the maximum number of streams that can be opened by the local endpoint.
    fn peer_max_streams(&self, bidi: bool) -> u64 {
        match bidi {
            true => self.peer_max_streams_bidi,
            false => self.peer_max_streams_uni,
        }
    }

    /// Get the remaining streams that local endpoint can open.
    fn peer_streams_left(&self, bidi: bool) -> u64 {
        match bidi {
            true => self.peer_max_streams_bidi - self.local_opened_streams_bidi,
            false => self.peer_max_streams_uni - self.local_opened_streams_uni,
        }
    }

    /// Return true if the local max_streams limit should be updated
    /// by sending a MAX_STREAMS(type: 0x12..0x13) frame to the peer.
    //  The left stream count < 1/2 * max concurrent stream limits.
    fn should_update_local_max_streams(&self, bidi: bool) -> bool {
        match bidi {
            true => {
                self.local_max_streams_bidi_next != self.local_max_streams_bidi
                    && self.local_max_streams_bidi_next - self.local_max_streams_bidi
                        > self.local_max_streams_bidi - self.peer_opened_streams_bidi
            }

            false => {
                self.local_max_streams_uni_next != self.local_max_streams_uni
                    && self.local_max_streams_uni_next - self.local_max_streams_uni
                        > self.local_max_streams_uni - self.peer_opened_streams_uni
            }
        }
    }

    /// Increase the next max_streams limit that will be sent to the peer
    /// in a MAX_STREAMS(type: 0x12..0x13) frame.
    fn increase_max_streams_credits(&mut self, bidi: bool, delta: u64) {
        match bidi {
            true => {
                self.local_max_streams_bidi_next =
                    self.local_max_streams_bidi_next.saturating_add(delta)
            }
            false => {
                self.local_max_streams_uni_next =
                    self.local_max_streams_uni_next.saturating_add(delta)
            }
        }
    }

    /// Update connection concurrency control blocked state.
    fn update_streams_blocked_at(&mut self, bidi: bool, blocket_at: Option<u64>) {
        match bidi {
            true => self.streams_blocked_at_bidi = blocket_at,
            false => self.streams_blocked_at_uni = blocket_at,
        }
    }

    /// Check if the stream ID complies with the stream limits of the current role,
    /// and try to update the stream count if the ID is valid.
    ///
    /// Note that the caller should ensure that the stream ID is valid with the
    /// initiator's role before calling this function.
    fn check_concurrency_limits(&mut self, id: u64, is_server: bool) -> Result<()> {
        // The two least significant bits from a stream ID identify the stream type,
        // and stream sequence starts from 0.
        let stream_sequence = (id >> 2) + 1;

        // RFC 9000 4.6 Controlling Concurrency
        // Endpoints MUST NOT exceed the limit set by their peer. An endpoint that
        // receives a frame with a stream ID exceeding the limit it has sent MUST
        // treat this as a connection error of type STREAM_LIMIT_ERROR.
        match (is_local(id, is_server), is_bidi(id)) {
            (true, true) => {
                let n = std::cmp::max(self.local_opened_streams_bidi, stream_sequence);

                if n > self.peer_max_streams_bidi {
                    // Can't open more bidirectional streams than the peer allows, send
                    // a STREAMS_BLOCKED(type: 0x16) frame to notify the peer update the
                    // max_streams_bidi limit.
                    self.update_streams_blocked_at(true, Some(self.peer_max_streams_bidi));
                    return Err(Error::StreamLimitError);
                }

                self.local_opened_streams_bidi = cmp::max(self.local_opened_streams_bidi, n);
            }

            (true, false) => {
                let n = std::cmp::max(self.local_opened_streams_uni, stream_sequence);

                if n > self.peer_max_streams_uni {
                    // Can't open more unidirectional streams than the peer allows, send
                    // a STREAMS_BLOCKED(type: 0x17) frame to notify the peer update the
                    // max_streams_uni limit.
                    self.update_streams_blocked_at(false, Some(self.peer_max_streams_uni));
                    return Err(Error::StreamLimitError);
                }

                self.local_opened_streams_uni = cmp::max(self.local_opened_streams_uni, n);
            }

            (false, true) => {
                let n = std::cmp::max(self.peer_opened_streams_bidi, stream_sequence);

                if n > self.local_max_streams_bidi {
                    return Err(Error::StreamLimitError);
                }

                self.peer_opened_streams_bidi = cmp::max(self.peer_opened_streams_bidi, n);
            }

            (false, false) => {
                let n = std::cmp::max(self.peer_opened_streams_uni, stream_sequence);

                if n > self.local_max_streams_uni {
                    return Err(Error::StreamLimitError);
                }

                self.peer_opened_streams_uni = cmp::max(self.peer_opened_streams_uni, n);
            }
        };

        Ok(())
    }

    /// Check whether the given stream ID exceeds stream limits.
    fn is_limited(&self, stream_id: u64, is_server: bool) -> bool {
        let seq = (stream_id >> 2) + 1;
        match (is_local(stream_id, is_server), is_bidi(stream_id)) {
            (true, true) => seq > self.peer_max_streams_bidi,
            (true, false) => seq > self.peer_max_streams_uni,
            (false, true) => seq > self.local_max_streams_bidi,
            (false, false) => seq > self.local_max_streams_uni,
        }
    }

    /// Check whether the given stream id is available for stream creation.
    fn is_available(&self, stream_id: u64, is_server: bool) -> bool {
        let id = stream_id >> 2;
        match (is_local(stream_id, is_server), is_bidi(stream_id)) {
            (true, true) => self.local_bidi_avail_ids.contains(id),
            (true, false) => self.local_uni_avail_ids.contains(id),
            (false, true) => self.peer_bidi_avail_ids.contains(id),
            (false, false) => self.peer_uni_avail_ids.contains(id),
        }
    }

    /// Inset the given stream ids into available set.
    fn insert_avail_id(&mut self, ids: Range<u64>, is_local: bool, is_bidi: bool) {
        match (is_local, is_bidi) {
            (true, true) => self.local_bidi_avail_ids.insert(ids),
            (true, false) => self.local_uni_avail_ids.insert(ids),
            (false, true) => self.peer_bidi_avail_ids.insert(ids),
            (false, false) => self.peer_uni_avail_ids.insert(ids),
        }
    }

    /// Remove the given stream id from available set.
    fn remove_avail_id(&mut self, stream_id: u64, is_server: bool) {
        let id = stream_id >> 2;
        match (is_local(stream_id, is_server), is_bidi(stream_id)) {
            (true, true) => self.local_bidi_avail_ids.remove_elem(id),
            (true, false) => self.local_uni_avail_ids.remove_elem(id),
            (false, true) => self.peer_bidi_avail_ids.remove_elem(id),
            (false, false) => self.peer_uni_avail_ids.remove_elem(id),
        }
    }
}

/// Connection-level send capacity for all streams
#[derive(Clone, Debug, Default)]
struct SendCapacity {
    /// The maximum amount of data that can be sent on the entire connection,
    /// in units of bytes.
    ///
    /// All data sent in STREAM frames counts toward this limit. The sum of the
    /// final sizes on all streams MUST NOT exceed this limit.
    ///
    /// Initially, this is set to the value of the initial_max_data transport
    /// parameter from peer. The value is also updated by MAX_DATA frames.
    max_data: u64,

    /// The total amount of data sent on the entire connection, in units of bytes.
    ///
    /// When sending a STREAM frame, or receiving a STOP_SENDING frame, or shutting
    /// down a stream send-side, update this value.
    tx_data: u64,

    /// Number of stream data that can be sent without exceeding the connection-level
    /// flow control limit, in units of bytes.
    capacity: usize,

    /// Connection send-side blocked at(if any), and need to send a
    /// DATA_BLOCKED frame to the peer.
    blocked_at: Option<u64>,
}

impl SendCapacity {
    /// Update the connection-level send-side max_data limit after
    /// processing peer's transport parameter initial_max_data(0x04)
    /// or receiving MAX_DATA frame.
    fn update_max_data(&mut self, max_data: u64) {
        // ignore if the value is smaller than the current value.
        self.max_data = cmp::max(self.max_data, max_data);
    }

    /// Update connection-level send capacity.
    fn update_capacity(&mut self) {
        self.capacity = (self.max_data - self.tx_data) as usize;
    }

    /// Update connection send-side flow control blocked state.
    fn update_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.blocked_at = blocked_at;
    }
}

/// Stream priority queue
///
/// Streams are categorized based on their urgency, where each urgency level
/// has two queues, including non-incremental and incremental streams.
///
/// Streams with lower urgency level are scheduled first, and within the
/// same urgency level non-incremental streams are scheduled before incremental
/// streams.
///
/// Non-incremental streams are scheduled in the order of their stream IDs.
/// Incremental streams are scheduled in a round-robin fashion.
#[derive(Debug, Default)]
struct StreamPriorityQueue {
    /// Non-incremental streams.
    non_incremental: BinaryHeap<std::cmp::Reverse<u64>>,
    /// Incremental streams.
    incremental: VecDeque<u64>,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    // StreamMap unit tests
    #[test]
    fn streams_new_client() {
        let peer_tp = StreamTransportParams {
            initial_max_streams_bidi: crate::codec::VINT_MAX,
            initial_max_streams_uni: crate::codec::VINT_MAX,
            ..StreamTransportParams::default()
        };
        let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);

        // client initiated bidirectional streams
        let id = map.stream_bidi_new(0, false);
        assert_eq!(id, Ok(0));
        let id = map.stream_bidi_new(0, false);
        assert_eq!(id, Ok(4));

        assert_eq!(map.stream_set_priority(20, 0, false), Ok(()));
        assert_eq!(map.stream_bidi_new(0, false), Ok(24));
        assert_eq!(
            map.stream_set_priority(crate::codec::VINT_MAX - 3, 0, false),
            Ok(())
        );
        assert_eq!(map.stream_bidi_new(0, false), Err(Error::ProtocolViolation));

        // client initiated unidirectional streams
        let id = map.stream_uni_new(0, false);
        assert_eq!(id, Ok(2));
        let id = map.stream_uni_new(0, false);
        assert_eq!(id, Ok(6));

        assert_eq!(map.stream_set_priority(22, 0, false), Ok(()));
        assert_eq!(map.stream_uni_new(0, false), Ok(26));
        assert_eq!(
            map.stream_set_priority(crate::codec::VINT_MAX - 1, 0, false),
            Ok(())
        );
        assert_eq!(map.stream_uni_new(0, false), Err(Error::ProtocolViolation));
    }

    #[test]
    fn streams_new_server() {
        let peer_tp = StreamTransportParams {
            initial_max_streams_bidi: crate::codec::VINT_MAX,
            initial_max_streams_uni: crate::codec::VINT_MAX,
            ..StreamTransportParams::default()
        };
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);

        // server initiated bidirectional streams
        let id = map.stream_bidi_new(1, false);
        assert_eq!(id, Ok(1));
        let id = map.stream_bidi_new(5, false);
        assert_eq!(id, Ok(5));

        assert_eq!(map.stream_set_priority(21, 0, false), Ok(()));
        assert_eq!(map.stream_bidi_new(0, false), Ok(25));
        assert_eq!(
            map.stream_set_priority(crate::codec::VINT_MAX - 2, 0, false),
            Ok(())
        );
        assert_eq!(map.stream_bidi_new(0, false), Err(Error::ProtocolViolation));

        // server initiated unidirectional streams
        let id = map.stream_uni_new(0, false);
        assert_eq!(id, Ok(3));
        let id = map.stream_uni_new(0, false);
        assert_eq!(id, Ok(7));

        assert_eq!(map.stream_set_priority(23, 0, false), Ok(()));
        assert_eq!(map.stream_uni_new(0, false), Ok(27));
        assert_eq!(
            map.stream_set_priority(crate::codec::VINT_MAX, 0, false),
            Ok(())
        );
        assert_eq!(map.stream_uni_new(0, false), Err(Error::ProtocolViolation));
    }

    // Test StreamMap::write
    #[test]
    fn stream_write_invalid_sid() {
        // MUST NOT write on the peer's unidirectional streams.
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert_eq!(
            map.stream_write(2, Bytes::new(), false),
            Err(Error::StreamStateError)
        );
    }

    #[test]
    fn stream_write_zero_capacity() {
        let peer_tp = StreamTransportParams {
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 21,
            initial_max_streams_bidi: 24,
            ..StreamTransportParams::default()
        };

        let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);

        // When the send capacity is zero, stream_write return Ok(0)
        // only when the send buffer is empty.
        assert_eq!(map.stream_write(0, Bytes::new(), false), Ok(0));
        // When the connection's capacity is exhausted, if the input
        // buffer is not empty, return `Done`.
        assert_eq!(
            map.stream_write(0, Bytes::from_static(b"hello"), false),
            Err(Error::Done)
        );
    }

    #[test]
    fn stream_write_blocked_by_connection_capacity() {
        let peer_tp = StreamTransportParams {
            initial_max_data: 10,
            initial_max_stream_data_bidi_remote: 20,
            initial_max_streams_bidi: 2,
            ..StreamTransportParams::default()
        };

        // 1. Create a client StreamMap
        let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);

        // 2. Try to write data, but blocked by connection capacity, only partial data is written.
        assert_eq!(
            map.stream_write(0, Bytes::from_static(b"EverythingOverQUIC"), true),
            Ok(10)
        );
        // Stream blocked by connection's send capacity, but the stream is still writable.
        assert_eq!(map.send_capacity.blocked_at, Some(10));
        assert!(map.writable.contains(&0));

        // 3. Update connection capacity, and write more data.
        map.on_max_data_frame_received(20);
        assert_eq!(
            map.stream_write(0, Bytes::from_static(b"OverQUIC"), true),
            Ok(8)
        );
    }

    #[test]
    fn stream_write_basic_logic() {
        let peer_tp = StreamTransportParams {
            initial_max_data: 10,
            initial_max_stream_data_bidi_local: 5,
            initial_max_stream_data_bidi_remote: 5,
            initial_max_stream_data_uni: 5,
            initial_max_streams_bidi: 5,
            initial_max_streams_uni: 5,
        };

        let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);

        // 1. Send more data than the stream-level flow control limit, the stream is blocked.
        assert_eq!(
            map.stream_write(0, Bytes::from_static(b"Everything"), false),
            Ok(5)
        );
        // init tx_cap is 10, sent 5, so tx_cap is 5 now.
        assert_eq!(map.tx_capacity(), 5);
        assert_eq!(map.tx_data(), 5);

        let stream = map.get(0).unwrap();
        assert!(stream.is_sendable());
        assert!(!stream.is_writable());
        assert_eq!(stream.send.blocked_at(), Some(5));

        // 2. After receiving max_stream_data frame, the stream is writable again.
        map.on_max_stream_data_frame_received(0, 20).unwrap();
        assert_eq!(
            map.stream_write(0, Bytes::from_static(b"thing"), false),
            Ok(5)
        );
        // init tx_cap is 10, sent 10, so tx_cap is 0 now.
        assert_eq!(map.tx_capacity(), 0);
        assert_eq!(map.tx_data(), 10);

        // 3. Send more data than the connection-level flow control limit, the stream is blocked.
        assert_eq!(
            map.stream_write(0, Bytes::from_static(b"OverQUIC"), true),
            Err(Error::Done)
        );

        // 4. After receiving max_data frame, the stream is writable again.
        map.on_max_data_frame_received(30);
        assert_eq!(
            map.stream_write(0, Bytes::from_static(b"OverQUIC"), true),
            Ok(8)
        );
        // after receiving max_data frame, tx_cap is 30, sent 18, so tx_cap is 12 now.
        assert_eq!(map.tx_capacity(), 12);
        assert_eq!(map.tx_data(), 18);

        let stream = map.get_mut(0).unwrap();
        assert!(stream.is_sendable());
        assert!(!stream.is_writable());

        let mut buf = vec![0; 18];
        assert_eq!(stream.send.read(&mut buf), Ok((18, true)));
        assert_eq!(&buf[..], b"EverythingOverQUIC");
    }

    #[test]
    fn stream_write_after_recv_stop_sending() {
        let local_tp = StreamTransportParams {
            initial_max_streams_bidi: 5,
            ..StreamTransportParams::default()
        };

        let peer_tp = StreamTransportParams {
            initial_max_data: 20,
            initial_max_stream_data_bidi_remote: 15,
            ..StreamTransportParams::default()
        };

        // 1. Creat a server StreamMap.
        let mut map = StreamMap::new(true, 50, 50, local_tp);
        map.update_peer_stream_transport_params(peer_tp);

        // 2. Receive a STOP_SENDING frame from client.
        assert!(map.on_stop_sending_frame_received(0, 7).is_ok());
        // Stream should be inserted into map.writable once STOP_SENDING frame is received.
        assert!(map.writable.contains(&0));

        // 3. Try to write data to stream(0), but it is stopped, so return StreamStopped error.
        assert_eq!(
            map.stream_write(0, Bytes::from_static(b"Q"), false),
            Err(Error::StreamStopped(7))
        );
    }

    // Test StreamMap::stream_writable
    #[test]
    fn stream_writable() {
        let local_tp = StreamTransportParams {
            initial_max_streams_bidi: 5,
            ..StreamTransportParams::default()
        };

        let peer_tp = StreamTransportParams {
            initial_max_data: 20,
            initial_max_stream_data_bidi_local: 15,
            ..StreamTransportParams::default()
        };

        // Creat a server StreamMap.
        let mut map = StreamMap::new(true, 50, 50, local_tp);
        map.update_peer_stream_transport_params(peer_tp);

        // Create a new client initiated bidi stream.
        assert!(map.get_or_create(0, false).is_ok());

        // 1. Stream has more than `len` bytes of send-side capacity.
        assert_eq!(map.stream_writable(0, 15), Ok(true));

        // 2. Stream blocked by stream-level flow control limit.
        assert_eq!(map.stream_writable(0, 16), Ok(false));
        assert_eq!(
            map.blocked().map(|(&k, &v)| (k, v)).collect::<Vec<_>>(),
            vec![(0, 15)]
        );

        // 3. Stream blocked by connection-level flow control limit.
        assert_eq!(map.stream_writable(0, 25), Ok(false));
        assert_eq!(map.send_capacity.blocked_at, Some(20));
    }

    // Test StreamMap::stream_set_priority
    #[test]
    fn stream_set_priority() {
        let peer_tp = StreamTransportParams {
            initial_max_streams_bidi: 1,
            ..StreamTransportParams::default()
        };

        // Create a client StreamMap.
        let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);

        // 1. Set priority on an invalid stream.
        assert_eq!(
            map.stream_set_priority(1, 1, true),
            Err(Error::StreamStateError)
        );

        // 2. Set priority on a not created stream.
        assert!(map.stream_set_priority(0, 1, true).is_ok());
        let stream = map.get(0).unwrap();
        assert_eq!((stream.urgency, stream.incremental), (1, true));

        // 3. Set priority on a stream with duplicate priority.
        assert!(map.stream_set_priority(0, 1, true).is_ok());
        let stream = map.get(0).unwrap();
        assert_eq!((stream.urgency, stream.incremental), (1, true));

        // 4. Set priority on a stream with different priority.
        assert!(map.stream_set_priority(0, 2, false).is_ok());
        let stream = map.get(0).unwrap();
        assert_eq!((stream.urgency, stream.incremental), (2, false));

        // 5. Set priority on a closed(0, simulation, not true) stream.
        map.mark_closed(0, true);
        assert!(map.stream_set_priority(0, 1, true).is_ok());
    }

    // Test StreamMap::stream_shutdown
    #[test]
    fn stream_shutdown_invalid_direction() {
        let local_tp = StreamTransportParams {
            initial_max_streams_uni: 5,
            ..StreamTransportParams::default()
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp);
        map.concurrency_control.update_peer_max_streams(false, 5);

        assert!(map.get_or_create(2, false).is_ok());
        assert!(map.get_or_create(3, true).is_ok());

        // Local initiated unidirectional stream should not be shutdown in the receive-side.
        assert_eq!(
            map.stream_shutdown(3, Shutdown::Read, 0),
            Err(Error::StreamStateError)
        );

        // Peer initiated unidirectional stream should not be shutdown in the send-side.
        assert_eq!(
            map.stream_shutdown(2, Shutdown::Write, 0),
            Err(Error::StreamStateError)
        );
    }

    #[test]
    fn stream_shutdown_not_exist() {
        let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());

        assert_eq!(map.stream_shutdown(0, Shutdown::Read, 0), Err(Error::Done));

        assert_eq!(map.stream_shutdown(0, Shutdown::Write, 0), Err(Error::Done));
    }

    #[test]
    fn stream_shutdown_read_should_update_flow_control() {
        let local_tp = StreamTransportParams {
            initial_max_data: 14,
            initial_max_stream_data_bidi_remote: 10,
            initial_max_streams_bidi: 2,
            ..StreamTransportParams::default()
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp);

        // Receive a stream frame from stream 0, range is [0, 10), fin = false.
        assert!(map
            .on_stream_frame_received(0, 0, 10, false, Bytes::from_static(b"Everything"))
            .is_ok());
        assert!(map.readable.contains(&0));
        assert!(map.stream_shutdown(0, Shutdown::Read, 10).is_ok());

        // init_max_data: 14, window: 14, read_off: 10
        // available_window: 4 < window / 2, should update max_data.
        assert_eq!(map.flow_control.max_data(), 14);
        assert_eq!(map.flow_control.max_data_next(), 24);
        assert!(map.flow_control.should_send_max_data());
        assert!(map.rx_almost_full);
    }

    // Test StreamMap::{stream_read, stream_readable, stream_finished}
    #[test]
    fn stream_read_invalid_sid() {
        // MUST NOT read from local initiated unidirectional stream.
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        let mut buf = vec![0; 1];
        assert_eq!(map.stream_read(3, &mut buf), Err(Error::StreamStateError));
    }

    #[test]
    fn stream_read_and_finished_basic_logic() {
        let local_tp = StreamTransportParams {
            initial_max_data: 20,
            initial_max_stream_data_bidi_remote: 20,
            initial_max_streams_bidi: 5,
            ..StreamTransportParams::default()
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp);

        // 1. Stream 0 is not exist, return StreamStateError.
        let mut buf = vec![0; 1];
        assert_eq!(map.stream_read(0, &mut buf), Err(Error::StreamStateError));

        // 2. Receive a stream frame, range is [0, 10), fin = false.
        assert_eq!(
            map.on_stream_frame_received(0, 0, 10, false, Bytes::from_static(b"Everything")),
            Ok(())
        );
        assert!(map.stream_readable(0));

        // 3. Read data from the stream.
        let mut buf = vec![0; 10];
        assert_eq!(map.stream_read(0, &mut buf), Ok((10, false)));
        assert_eq!(&buf[..10], b"Everything");
        assert!(!map.stream_finished(0));
        assert!(!map.stream_readable(0));

        // 4. There is no data to read, so return Done.
        let mut buf = vec![0; 1];
        assert_eq!(map.stream_read(0, &mut buf), Err(Error::Done));

        // 5. Receive a stream frame, range is [10, 18), fin = true.
        assert!(map
            .on_stream_frame_received(0, 10, 8, true, Bytes::from_static(b"OverQUIC"))
            .is_ok());
        assert!(!map.stream_finished(0));
        assert!(map.stream_readable(0));

        // 6. Read data from the stream.
        let mut buf = vec![0; 8];
        assert_eq!(map.stream_read(0, &mut buf), Ok((8, true)));
        assert_eq!(&buf[..8], b"OverQUIC");

        // 7. Stream receive-side is finished, and stream is not readable.
        assert!(map.stream_finished(0));
        assert!(!map.stream_readable(0));
    }

    // Test StreamMap::stream_capacity
    #[test]
    fn stream_capacity_not_exist() {
        let map = StreamMap::new(false, 50, 50, StreamTransportParams::default());

        assert_eq!(map.stream_capacity(0), Err(Error::StreamStateError));
    }

    #[test]
    fn stream_capacity_stopped() {
        let local_tp = StreamTransportParams {
            initial_max_data: 20,
            initial_max_stream_data_bidi_remote: 20,
            initial_max_streams_bidi: 5,
            ..StreamTransportParams::default()
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp);

        assert!(map.on_stop_sending_frame_received(4, 7).is_ok());
        assert_eq!(map.stream_capacity(4), Err(Error::StreamStopped(7)))
    }

    #[test]
    fn stream_capacity() {
        let peer_tp = StreamTransportParams {
            initial_max_data: 20,
            initial_max_stream_data_bidi_remote: 15,
            initial_max_streams_bidi: 5,
            ..StreamTransportParams::default()
        };

        // 1. Creat a client StreamMap.
        let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);

        // 2. Create a stream(0) and write data to it.
        assert_eq!(
            map.stream_write(0, Bytes::from_static(b"Everything"), false),
            Ok(10)
        );
        assert_eq!(map.tx_data(), 10);
        assert_eq!(map.tx_capacity(), 10);
        // self.tx_cap > stream.send.capacity
        assert_eq!(map.stream_capacity(0), Ok(5));

        // 3. Receive a MAX_STREAM_DATA frame, stream(0) capacity is increased.
        assert!(map.on_max_stream_data_frame_received(0, 50).is_ok());
        // self.tx_cap < stream.send.capacity
        assert_eq!(map.stream_capacity(0), Ok(10));
    }

    // Test StreamMap::new
    #[test]
    fn stream_map_new() {
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 5,
            initial_max_streams_uni: 5,
        };

        let peer_tp = StreamTransportParams::default();
        let map = StreamMap::new(true, 50, 50, local_tp.clone());

        assert!(map.is_server, "current role is server");
        assert_eq!(map.streams.len(), 0);
        assert!(map.sendable.is_empty(), "sendable is empty");
        assert!(map.readable.is_empty(), "readable is empty");
        assert!(map.writable.is_empty(), "writable is empty");
        assert!(map.reset.is_empty(), "reset is empty");
        assert!(map.stopped.is_empty(), "stopped is empty");
        assert!(map.closed.is_empty(), "closed is empty");
        assert!(map.almost_full.is_empty(), "almost_full is empty");
        assert!(map.data_blocked.is_empty(), "data_blocked is empty");

        // Check concurrency limits
        assert_eq!(map.concurrency_control, ConcurrencyControl::new(5, 5));

        // Check connection-level flow control
        assert_eq!(map.flow_control.window(), 100);
        assert_eq!(map.flow_control.max_data(), 100);
        assert!(
            !map.flow_control.should_send_max_data(),
            "should not update max_data"
        );

        assert_eq!(map.max_stream_window, 50);
        assert_eq!(map.max_recv_off(), 0);
        assert_eq!(map.tx_data(), 0);
        assert_eq!(map.max_tx_data(), 0);
        assert_eq!(map.rx_almost_full, false);
        assert_eq!(map.data_blocked_at(), None);
        assert_eq!(map.local_transport_params, local_tp);
        assert_eq!(map.peer_transport_params, peer_tp);
    }

    // Test StreamMap::max_stream_data_limit
    #[test]
    fn stream_map_max_stream_data_limit() {
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 11,
            initial_max_stream_data_bidi_remote: 12,
            initial_max_stream_data_uni: 13,
            initial_max_streams_bidi: 14,
            initial_max_streams_uni: 15,
        };

        let peer_tp = StreamTransportParams {
            initial_max_data: 200,
            initial_max_stream_data_bidi_local: 21,
            initial_max_stream_data_bidi_remote: 22,
            initial_max_stream_data_uni: 23,
            initial_max_streams_bidi: 24,
            initial_max_streams_uni: 25,
        };

        for (local, bidi, max_rx_data, max_tx_data) in vec![
            // local initiated bidi stream
            (true, true, 11, 22),
            // local initiated uni stream
            (true, false, 0, 23),
            // remote initiated bidi stream
            (false, true, 12, 21),
            // remote initiated uni stream
            (false, false, 13, 0),
        ] {
            assert_eq!(
                StreamMap::max_stream_data_limit(local, bidi, &local_tp, &peer_tp),
                (max_rx_data, max_tx_data)
            );
        }
    }

    // Test StreamMap::{get, get_mut, get_or_create}
    #[test]
    fn stream_map_get_or_create() {
        let local_tp = StreamTransportParams {
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
            ..StreamTransportParams::default()
        };

        let peer_tp = StreamTransportParams {
            initial_max_streams_bidi: 30,
            initial_max_streams_uni: 15,
            ..StreamTransportParams::default()
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp);
        map.update_peer_stream_transport_params(peer_tp);

        for stream_id in [4, 8, 12, 36, 6, 14, 10, 18, 5, 13, 9, 117, 7, 15, 11, 59] {
            assert!(map.get(stream_id).is_none(), "get unexpected stream");
            assert!(
                map.get_mut(stream_id).is_none(),
                "get_mut unexpected stream"
            );
        }

        // 1. Auto open streams
        // 1.1 Auto open client-initiated bidi stream
        //     36 is the highest stream-id that can be auto-opened
        for stream_id in [4, 12, 8, 36] {
            assert!(!is_local(stream_id, true), "stream id is client initiated");
            assert!(is_bidi(stream_id), "stream id is bidirectional");
            assert!(
                map.get_or_create(stream_id, false).is_ok(),
                "auto open client-initiated bidi stream"
            );
        }

        for stream_id in [4, 8, 12, 36] {
            assert!(map.get(stream_id).is_some(), "get stream {}", stream_id);
            assert!(
                map.get_mut(stream_id).is_some(),
                "get_mut stream {}",
                stream_id
            );
        }

        // 1.2 Auto open client-initiated uni stream
        //     18 is the highest stream-id that can be auto-opened
        for stream_id in [6, 14, 10, 18] {
            assert!(!is_local(stream_id, true), "stream id is client initiated");
            assert!(!is_bidi(stream_id), "stream id is unidirectional");
            assert!(
                map.get_or_create(stream_id, false).is_ok(),
                "auto open client-initiated uni stream"
            );
        }

        for stream_id in [6, 10, 14, 18] {
            assert!(map.get(stream_id).is_some(), "get stream {}", stream_id);
            assert!(
                map.get_mut(stream_id).is_some(),
                "get_mut stream {}",
                stream_id
            );
        }

        // 1.3 Auto open server-initiated bidi stream
        //     117 is the highest stream-id that can be auto-opened
        for stream_id in [5, 13, 9, 117] {
            assert!(is_local(stream_id, true), "stream id is server initiated");
            assert!(is_bidi(stream_id), "stream id is bidirectional");
            assert!(
                map.get_or_create(stream_id, true).is_ok(),
                "auto open server-initiated bidi stream"
            );
        }

        for stream_id in [5, 9, 13, 117] {
            assert!(map.get(stream_id).is_some(), "get stream {}", stream_id);
            assert!(
                map.get_mut(stream_id).is_some(),
                "get_mut stream {}",
                stream_id
            );
        }

        // 1.4 Auto open server-initiated uni stream
        //     59 is the highest stream-id that can be auto-opened
        for stream_id in [7, 15, 11, 59] {
            assert!(is_local(stream_id, true), "stream id is server initiated");
            assert!(!is_bidi(stream_id), "stream id is unidirectional");
            assert!(
                map.get_or_create(stream_id, true).is_ok(),
                "auto open server-initiated uni stream"
            );
        }

        for stream_id in [7, 11, 15, 59] {
            assert!(map.get(stream_id).is_some(), "get stream {}", stream_id);
            assert!(
                map.get_mut(stream_id).is_some(),
                "get_mut stream {}",
                stream_id
            );
        }

        // 2 Open too many streams
        // 2.1 Client opened too many bidi streams
        assert_eq!(
            map.get_or_create(40, false).err(),
            Some(Error::StreamLimitError),
            "stream limit should be exceeded"
        );

        // 2.2 Client opened too many uni streams
        assert_eq!(
            map.get_or_create(22, false).err(),
            Some(Error::StreamLimitError),
            "stream limit should be exceeded"
        );

        // 2.3 Server opened too many bidi streams
        assert_eq!(
            map.get_or_create(121, true).err(),
            Some(Error::StreamLimitError),
            "stream limit should be exceeded"
        );

        // 2.4 Server opened too many uni streams
        assert_eq!(
            map.get_or_create(63, true).err(),
            Some(Error::StreamLimitError),
            "stream limit should be exceeded"
        );

        for stream_id in [40, 22, 121, 63] {
            assert!(map.get(stream_id).is_none(), "get unexpected stream");
            assert!(
                map.get_mut(stream_id).is_none(),
                "get_mut unexpected stream"
            );
        }

        // 3. Open streams with wrong direction
        // 3.1 Client open server-initiated bidi stream
        assert_eq!(
            map.get_or_create(1, false).err(),
            Some(Error::StreamStateError),
            "stream direction is wrong"
        );

        // 3.2 Client open server-initiated uni stream
        assert_eq!(
            map.get_or_create(3, false).err(),
            Some(Error::StreamStateError),
            "stream direction is wrong"
        );

        // 3.3 Server open client-initiated bidi stream
        assert_eq!(
            map.get_or_create(0, true).err(),
            Some(Error::StreamStateError),
            "stream direction is wrong"
        );

        // 3.4 Server open client-initiated uni stream
        assert_eq!(
            map.get_or_create(2, true).err(),
            Some(Error::StreamStateError),
            "stream direction is wrong"
        );

        for stream_id in [0, 1, 2, 3] {
            assert!(map.get(stream_id).is_none(), "get unexpected stream");
            assert!(
                map.get_mut(stream_id).is_none(),
                "get_mut unexpected stream"
            );
        }
    }

    // Test StreamMap::{push_sendable, peek_sendable, remove_sendable}
    #[test]
    fn stream_map_sendable() {
        // Streams are categorized based on their urgency, where each urgency level
        // has two queues, including non-incremental and incremental streams.
        //
        // Streams with lower urgency level are scheduled first, and within the
        // same urgency level non-incremental streams are scheduled before incremental
        // streams.
        //
        // Non-incremental streams are scheduled in the order of their stream IDs.
        // Incremental streams are scheduled in a round-robin fashion.

        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert!(
            !map.has_sendable_streams(),
            "sendable stream should not exist"
        );

        // 1.Peek multiple times consecutively, the result should be the same.
        map.push_sendable(4, 7, false);
        assert!(map.has_sendable_streams());
        assert_eq!(map.peek_sendable(), Some(4));
        assert_eq!(map.peek_sendable(), Some(4));
        map.remove_sendable();

        // 2.Streams with lower urgency level are scheduled first.
        map.push_sendable(4, 2, false);
        map.push_sendable(8, 3, false);
        map.push_sendable(12, 1, false);
        assert_eq!(map.peek_sendable(), Some(12));
        map.remove_sendable();
        assert_eq!(map.peek_sendable(), Some(4));
        map.remove_sendable();
        assert_eq!(map.peek_sendable(), Some(8));
        map.remove_sendable();

        // 3.Within the same urgency level non-incremental streams are scheduled
        // before incremental streams.
        map.push_sendable(4, 7, true);
        map.push_sendable(8, 7, false);
        assert_eq!(map.peek_sendable(), Some(8));
        map.remove_sendable();
        assert_eq!(map.peek_sendable(), Some(4));
        map.remove_sendable();

        // 4.Non-incremental streams are scheduled in the order of their stream IDs.
        map.push_sendable(12, 7, false);
        map.push_sendable(4, 7, false);
        map.push_sendable(8, 7, false);
        assert_eq!(map.peek_sendable(), Some(4));
        map.remove_sendable();
        assert_eq!(map.peek_sendable(), Some(8));
        map.remove_sendable();
        assert_eq!(map.peek_sendable(), Some(12));
        map.remove_sendable();

        // 5.Incremental streams are scheduled in a round-robin fashion.
        map.push_sendable(12, 7, true);
        map.push_sendable(8, 7, true);
        map.push_sendable(4, 7, true);
        assert_eq!(map.peek_sendable(), Some(12));
        assert_eq!(map.peek_sendable(), Some(8));
        assert_eq!(map.peek_sendable(), Some(4));
        assert_eq!(map.peek_sendable(), Some(12));
        assert_eq!(map.peek_sendable(), Some(8));
        assert_eq!(map.peek_sendable(), Some(4));
        map.remove_sendable();
        map.remove_sendable();
        map.remove_sendable();

        assert!(
            !map.has_sendable_streams(),
            "sendable stream should not exist"
        );
    }

    // Test StreamMap::mark_readable
    #[test]
    fn stream_map_readable() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert!(map.readable.is_empty(), "readable stream should not exist");

        // Insert multiple streams unordered.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_readable(stream_id, true);
        }
        assert!(!map.readable.is_empty());

        let mut v = map.readable_iter().collect::<Vec<u64>>();
        assert_eq!(v.len(), 5);
        v.sort();
        assert_eq!(v, vec![0, 4, 8, 12, 16]);

        // Do nothing if `readable` is true but the stream was already in the list.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_readable(stream_id, true);
        }
        assert_eq!(map.readable_iter().collect::<Vec<u64>>().len(), 5);

        // Remove streams from the list if `readable` is false.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_readable(stream_id, false);
        }
        assert!(map.readable.is_empty());
    }

    // Test StreamMap::mark_writable
    #[test]
    fn stream_map_writable() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert!(map.writable.is_empty(), "writable stream should not exist");

        // Insert multiple streams unordered.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_writable(stream_id, true);
        }
        assert!(!map.writable.is_empty());

        let mut v = map.writable_iter().collect::<Vec<u64>>();
        assert_eq!(v.len(), 5);
        v.sort();
        assert_eq!(v, vec![0, 4, 8, 12, 16]);

        // Do nothing if `writable` is true but the stream was already in the list.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_writable(stream_id, true);
        }
        assert_eq!(map.writable_iter().collect::<Vec<u64>>().len(), 5);

        // Remove streams from the list if `writable` is false.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_writable(stream_id, false);
        }
        assert!(map.writable.is_empty());
    }

    // Test StreamMap::mark_almost_full
    #[test]
    fn stream_map_almost_full() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert!(
            map.almost_full.is_empty(),
            "almost_full stream should not exist"
        );

        // Insert multiple streams unordered.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_almost_full(stream_id, true);
        }
        assert!(!map.almost_full.is_empty());

        let mut v = map.almost_full().collect::<Vec<u64>>();
        assert_eq!(v.len(), 5);
        v.sort();
        assert_eq!(v, vec![0, 4, 8, 12, 16]);

        // Do nothing if `almost_full` is true but the stream was already in the list.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_almost_full(stream_id, true);
        }
        assert_eq!(map.almost_full().collect::<Vec<u64>>().len(), 5);

        // Remove streams from the list if `almost_full` is false.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_almost_full(stream_id, false);
        }
        assert!(map.almost_full.is_empty());
    }

    // Test StreamMap::mark_closed
    #[test]
    fn stream_map_closed() {
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp.clone());
        assert!(map.closed.is_empty(), "closed stream not empty");

        // Update the peer's max_streams limit for concurrency control.
        map.concurrency_control.update_peer_max_streams(true, 30);
        map.concurrency_control.update_peer_max_streams(false, 15);

        // Auto open 5 client-initiated bidi stream
        // [0, 4, 8, 12, 16]
        for seq in 0..=4 {
            let stream_id = seq * 4;
            assert!(
                !is_local(stream_id, true),
                "stream id is not client initiated"
            );
            assert!(is_bidi(stream_id), "stream id is unidirectional");
            assert!(
                map.get_or_create(stream_id, false).is_ok(),
                "auto open client-initiated bidi stream failed"
            );

            map.mark_writable(stream_id, true);
            map.mark_readable(stream_id, true);
        }
        assert_eq!(map.streams.len(), 5);
        assert_eq!(map.readable.len(), 5);
        assert_eq!(map.writable.len(), 5);

        // Auto open 3 client-initiated uni stream
        // [2, 6, 10]
        for seq in 0..=2 {
            let stream_id = seq * 4 + 2;
            assert!(
                !is_local(stream_id, true),
                "stream id is not client initiated"
            );
            assert!(!is_bidi(stream_id), "stream id is bidirectional");
            assert!(
                map.get_or_create(stream_id, false).is_ok(),
                "auto open client-initiated uni stream failed"
            );
            map.mark_writable(stream_id, true);
            map.mark_readable(stream_id, true);
        }
        assert_eq!(map.streams.len(), 8);
        assert_eq!(map.readable.len(), 8);
        assert_eq!(map.writable.len(), 8);

        // Auto open server-initiated bidi stream
        for stream_id in [5, 13, 9] {
            assert!(is_local(stream_id, true), "stream id is client initiated");
            assert!(is_bidi(stream_id), "stream id is unidirectional");
            assert!(
                map.get_or_create(stream_id, true).is_ok(),
                "auto open server-initiated bidi stream failed"
            );
            map.mark_writable(stream_id, true);
            map.mark_readable(stream_id, true);
        }
        assert_eq!(map.streams.len(), 11);
        assert_eq!(map.readable.len(), 11);
        assert_eq!(map.writable.len(), 11);

        // Auto open server-initiated uni stream
        for stream_id in [7, 15, 11] {
            assert!(is_local(stream_id, true), "stream id is client initiated");
            assert!(!is_bidi(stream_id), "stream id is bidirectional");
            assert!(
                map.get_or_create(stream_id, true).is_ok(),
                "auto open server-initiated uni stream failed"
            );
            map.mark_writable(stream_id, true);
            map.mark_readable(stream_id, true);
        }
        assert_eq!(map.streams.len(), 14);
        assert_eq!(map.readable.len(), 14);
        assert_eq!(map.writable.len(), 14);

        // Client opened too many bidi streams, blocked by local stream limit
        assert_eq!(
            map.get_or_create(40, false).err(),
            Some(Error::StreamLimitError),
            "stream limit should be exceeded"
        );
        // Client opened too many uni streams, blocked by local stream limit
        assert_eq!(
            map.get_or_create(22, false).err(),
            Some(Error::StreamLimitError),
            "stream limit should be exceeded"
        );

        assert_eq!(map.streams.len(), 14);
        assert_eq!(map.readable.len(), 14);
        assert_eq!(map.writable.len(), 14);

        // Mark 5 client-initiated bidi streams as closed, give back credit to the peer.
        // Close [0, 4, 8, 12, 16]
        for seq in 0..=4 {
            let stream_id = seq * 4;
            map.mark_closed(stream_id, false);
        }
        // Mark 2 client-initiated uni streams as closed, give back credit to the peer.
        // close [2, 6]
        for seq in 0..=1 {
            let stream_id = seq * 4 + 2;
            map.mark_closed(stream_id, false);
        }
        assert_eq!(map.streams.len(), 7);
        assert_eq!(map.readable.len(), 7);
        assert_eq!(map.writable.len(), 7);
        assert_eq!(map.closed.len(), 7);

        assert_eq!(map.max_streams_next(true), 15);
        assert_eq!(map.max_streams_next(false), 7);

        assert!(
            !map.should_update_local_max_streams(true),
            "bidi streams limit should not be updated"
        );
        assert!(
            !map.should_update_local_max_streams(false),
            "uni streams limit should not be updated"
        );

        map.mark_closed(5, true);
        map.mark_closed(7, true);
        assert!(
            !map.should_update_local_max_streams(true),
            "close local bidi stream should not affect local bidi streams limit"
        );
        assert!(
            !map.should_update_local_max_streams(false),
            "close local uni stream should not affect local uni streams limit"
        );
        assert_eq!(map.streams.len(), 5);
        assert_eq!(map.readable.len(), 5);
        assert_eq!(map.writable.len(), 5);
        assert_eq!(map.closed.len(), 9);

        // Auto open client-initiated bidi stream, id: 20
        assert!(
            map.get_or_create(20, false).is_ok(),
            "auto open client-initiated bidi stream failed"
        );
        // (15 - 10) > (10 - 6), should update
        assert_eq!(map.max_streams_next(true), 15);
        assert!(
            map.should_update_local_max_streams(true),
            "should update local bidi streams limit"
        );

        map.mark_closed(10, false);
        assert_eq!(map.max_streams_next(false), 8);
        // (8 - 5) > (5 - 3), should update
        assert!(
            map.should_update_local_max_streams(false),
            "should update local uni streams limit"
        );

        assert_eq!(map.streams.len(), 5);
        assert_eq!(map.readable.len(), 4);
        assert_eq!(map.writable.len(), 4);
        assert_eq!(map.closed.len(), 10);

        map.update_local_max_streams(true);
        assert_eq!(map.max_streams(true), 15);
        map.update_local_max_streams(false);
        assert_eq!(map.max_streams(false), 8);

        assert!(
            map.get_or_create(40, false).is_ok(),
            "auto open client-initiated bidi stream failed"
        );
        assert!(
            map.get_or_create(22, false).is_ok(),
            "auto open client-initiated uni stream failed"
        );
        assert_eq!(map.streams.len(), 7);

        let mut v = map.closed.iter().copied().collect::<Vec<u64>>();
        assert_eq!(v.len(), 10);
        v.sort();
        assert_eq!(v, vec![0, 2, 4, 5, 6, 7, 8, 10, 12, 16]);
    }

    // Test StreamMap::mark_reset
    #[test]
    fn stream_map_reset() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert!(map.reset.is_empty(), "reset stream should not exist");

        // Insert multiple streams unordered.
        for seq in [1, 2, 3, 0, 4] {
            let stream_id = seq * 4;
            map.mark_reset(stream_id, true, seq, seq);
        }
        assert!(!map.reset.is_empty());
        assert_eq!(map.reset.len(), 5);

        let mut v = map.reset().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v.len(), 5);
        v.sort();
        assert_eq!(
            v,
            vec![0, 1, 2, 3, 4]
                .into_iter()
                .map(|x| (x * 4, (x, x)))
                .collect::<Vec<_>>()
        );

        // If `reset` is true but the stream was already in the list, the error code
        // and the final size will be updated.
        for seq in [1, 2, 3, 0, 4] {
            let stream_id = seq * 4;
            map.mark_reset(stream_id, true, seq + 1, seq + 1);
        }
        let mut v = map.reset().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v.len(), 5);
        v.sort();
        assert_eq!(
            v,
            vec![0, 1, 2, 3, 4]
                .into_iter()
                .map(|x| (x * 4, (x + 1, x + 1)))
                .collect::<Vec<_>>()
        );

        // Remove streams from the list if `reset` is false.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_reset(stream_id, false, 0, 0);
        }
        assert!(map.reset.is_empty());
    }

    // Test StreamMap::mark_blocked
    #[test]
    fn stream_map_blocked() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert!(map.reset.is_empty(), "blocked stream should not exist");

        // Insert multiple streams unordered.
        for seq in [1, 2, 3, 0, 4] {
            let stream_id = seq * 4;
            map.mark_blocked(stream_id, true, seq * 100);
        }
        assert!(!map.data_blocked.is_empty());
        assert_eq!(map.data_blocked.len(), 5);

        let mut v = map.blocked().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v.len(), 5);
        v.sort();
        assert_eq!(
            v,
            vec![0, 1, 2, 3, 4]
                .into_iter()
                .map(|x| (x * 4, x * 100))
                .collect::<Vec<_>>()
        );

        // If `blocked` is true but the stream was already in the list, the offset
        // will be updated.
        for seq in [1, 2, 3, 0, 4] {
            let stream_id = seq * 4;
            map.mark_blocked(stream_id, true, seq * 200);
        }
        let mut v = map.blocked().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v.len(), 5);
        v.sort();
        assert_eq!(
            v,
            vec![0, 1, 2, 3, 4]
                .into_iter()
                .map(|x| (x * 4, x * 200))
                .collect::<Vec<_>>()
        );

        // Remove streams from the list if `blocked` is false.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_blocked(stream_id, false, 0);
        }
        assert!(map.data_blocked.is_empty());
    }

    // Test StreamMap::mark_stopped
    #[test]
    fn stream_map_stopped() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert!(map.reset.is_empty(), "stopped stream should not exist");

        // Insert multiple streams unordered.
        for seq in [1, 2, 3, 0, 4] {
            let stream_id = seq * 4;
            map.mark_stopped(stream_id, true, seq);
        }
        assert!(!map.stopped.is_empty());
        assert_eq!(map.stopped.len(), 5);

        let mut v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v.len(), 5);
        v.sort();
        assert_eq!(
            v,
            vec![0, 1, 2, 3, 4]
                .into_iter()
                .map(|x| (x * 4, x))
                .collect::<Vec<_>>()
        );

        // If `stopped` is true but the stream was already in the list, the offset
        // will be updated.
        for seq in [1, 2, 3, 0, 4] {
            let stream_id = seq * 4;
            map.mark_stopped(stream_id, true, seq * 2);
        }
        let mut v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v.len(), 5);
        v.sort();
        assert_eq!(
            v,
            vec![0, 1, 2, 3, 4]
                .into_iter()
                .map(|x| (x * 4, x * 2))
                .collect::<Vec<_>>()
        );

        // Remove streams from the list if `stopped` is false.
        for stream_id in [4, 8, 12, 0, 16] {
            map.mark_stopped(stream_id, false, 0);
        }
        assert!(map.stopped.is_empty());
    }

    // Test StreamMap::on_max_data_frame_received
    #[test]
    fn stream_map_on_max_data_frame_received() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert_eq!(map.max_tx_data(), 0);

        // Update max_data
        map.on_max_data_frame_received(100);
        assert_eq!(map.max_tx_data(), 100);

        // Assume that connection-level flow control is blocked at 150.
        map.update_data_blocked_at(Some(150));

        // Update max_data, but it doesn't change the blocked state.
        map.on_max_data_frame_received(130);
        assert_eq!(map.max_tx_data(), 130);
        assert_eq!(map.data_blocked_at(), Some(150));

        // Update max_data, and it changes the blocked state.
        map.on_max_data_frame_received(200);
        assert_eq!(map.max_tx_data(), 200);
        assert_eq!(map.data_blocked_at(), None);
    }

    // Test StreamMap::on_max_stream_data_frame_received
    #[test]
    fn stream_map_on_max_stream_data_frame_received() {
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp);

        // Update the peer's max_streams limit for concurrency control.
        map.concurrency_control.update_peer_max_streams(true, 30);
        map.concurrency_control.update_peer_max_streams(false, 15);

        // An endpoint that receives a MAX_STREAM_DATA frame for a receive-only stream
        // MUST terminate the connection with error STREAM_STATE_ERROR.
        assert_eq!(
            map.on_max_stream_data_frame_received(2, 100),
            Err(Error::StreamStateError)
        );

        // Client open too many bidi streams, get_or_create return StreamLimitError.
        assert_eq!(
            map.on_max_stream_data_frame_received(40, 100),
            Err(Error::StreamLimitError)
        );

        // Create a new bidi stream, it is not sendable, but it is writable.
        assert!(map.on_max_stream_data_frame_received(4, 10).is_ok());
        assert!(map.writable.contains(&4));
        let stream = map.get_mut(4).unwrap();
        assert_eq!(stream.send.max_data, 10);
        assert_eq!(
            stream.send.write(Bytes::from_static(b"Everything"), false),
            Ok(10)
        );
        assert_eq!(
            stream.send.write(Bytes::from_static(b"OverQUIC"), false),
            Ok(0)
        );

        // Update the peer's max stream data
        assert!(map.on_max_stream_data_frame_received(4, 18).is_ok());
        let stream = map.get_mut(4).unwrap();
        assert_eq!(stream.send.max_data, 18);
        assert_eq!(
            stream.send.write(Bytes::from_static(b"OverQUIC"), false),
            Ok(8)
        );

        // When stream's send-side flow control is exhausted,
        // write empty data with fin flag, it should be ok.
        assert_eq!(stream.send.write(Bytes::new(), true), Ok(0));

        // Shutdown the stream abrubtly, it should be ok.
        assert_eq!(stream.send.shutdown(), Ok((0, 18)));
        // Here we call `write` to make sure the stream's fin_off is set.
        assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
        assert!(stream.recv.shutdown().is_ok());
        assert_eq!(stream.is_complete(), true);
        map.mark_closed(4, false);
        assert!(
            map.on_max_stream_data_frame_received(4, 18).is_ok(),
            "Stream is already closed, just ignore the frame."
        );
    }

    // Test StreamMap::on_max_streams_frame_received
    #[test]
    fn stream_map_on_max_streams_frame_received() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert_eq!(map.concurrency_control.peer_max_streams_bidi, 0);
        assert_eq!(map.concurrency_control.peer_max_streams_uni, 0);

        // 1. Server initiated bidi(101) and uni(103) stream, exceeding the limit.
        for (stream_id, local) in vec![
            // bidi
            (101, true),
            // uni
            (103, true),
        ] {
            assert_eq!(
                map.get_or_create(stream_id, local).err(),
                Some(Error::StreamLimitError)
            );
        }

        // 2. max_streams > 2^60, return FrameEncodingError
        for (max_streams, bidi) in vec![(1 << 61, true), (1 << 61, false)] {
            assert_eq!(
                map.on_max_streams_frame_received(max_streams, bidi),
                Err(Error::FrameEncodingError)
            );
        }

        // 3. Receive a MAX_STREAMS frame for the bidi stream
        assert_eq!(map.on_max_streams_frame_received(100, true), Ok(()));
        assert_eq!(map.concurrency_control.peer_max_streams_bidi, 100);
        assert!(map.get_or_create(101, true).is_ok());

        // 4. Receive a MAX_STREAMS frame for the uni stream
        assert_eq!(map.on_max_streams_frame_received(50, false), Ok(()));
        assert_eq!(map.concurrency_control.peer_max_streams_uni, 50);
        assert!(map.get_or_create(103, true).is_ok());
    }

    // Test StreamMap::on_stream_data_blocked_frame_received
    #[test]
    fn stream_map_on_stream_data_blocked_frame_received() {
        // 1. Server endpoint
        // 1.1 Receive a STREAM_DATA_BLOCKED frame for a local initiated send-only stream
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        let stream_id = 3;
        assert!(is_local(stream_id, true));
        assert!(!is_bidi(stream_id));
        assert_eq!(
            map.on_stream_data_blocked_frame_received(stream_id, 100),
            Err(Error::StreamStateError)
        );

        // 1.2 Receive a STREAM_DATA_BLOCKED frame for a stream which allow receive data
        for stream_id in [0, 1, 2] {
            assert_eq!(
                map.on_stream_data_blocked_frame_received(stream_id, 100),
                Ok(())
            );
        }

        // 2. Client endpoint
        // 2.1 Receive a STREAM_DATA_BLOCKED frame for a local initiated send-only stream
        let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
        let stream_id = 2;
        assert!(is_local(stream_id, false));
        assert!(!is_bidi(stream_id));
        assert_eq!(
            map.on_stream_data_blocked_frame_received(stream_id, 100),
            Err(Error::StreamStateError)
        );

        // 2.2 Receive a STREAM_DATA_BLOCKED frame for a stream which allow receive data
        for stream_id in [0, 1, 3] {
            assert_eq!(
                map.on_stream_data_blocked_frame_received(stream_id, 100),
                Ok(())
            );
        }
    }

    // Test StreamMap::on_streams_blocked_frame_received
    #[test]
    fn stream_map_on_streams_blocked_frame_received() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());

        for (max_streams, bidi, result) in vec![
            (1 << 61, true, Err(Error::FrameEncodingError)),
            (1 << 61, false, Err(Error::FrameEncodingError)),
            (1 << 60, true, Ok(())),
            (1 << 60, false, Ok(())),
        ] {
            assert_eq!(
                map.on_streams_blocked_frame_received(max_streams, bidi),
                result
            );
        }
    }

    // Test StreamMap::on_reset_stream_frame_received
    #[test]
    fn stream_map_on_reset_stream_frame_received() {
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_remote: 110,
            initial_max_streams_bidi: 10,
            ..StreamTransportParams::default()
        };

        // Create a server StreamMap
        let mut map = StreamMap::new(true, 50, 50, local_tp);

        // 1. Receive a RESET_STREAM frame for a local initiated uni stream(3)
        assert_eq!(
            map.on_reset_stream_frame_received(3, 0, 10),
            Err(Error::StreamStateError)
        );

        // 2. Peer open too many streams
        assert_eq!(
            map.on_reset_stream_frame_received(40, 0, 10),
            Err(Error::StreamLimitError)
        );

        // 3. Peer send too much data, which exceeds the connection flow control limit.
        assert_eq!(
            map.on_reset_stream_frame_received(36, 0, 101),
            Err(Error::FlowControlError)
        );
        assert_eq!(map.max_rx_data_left(), 100);

        // 4. Peer send too much data, which exceeds the stream flow control limit.
        assert_eq!(
            map.on_reset_stream_frame_received(0, 0, 111),
            Err(Error::FlowControlError)
        );

        // 5. Duplicate RESET_STREAM frame with same final size
        // stream_id: 4, final_size: 10
        assert_eq!(map.on_reset_stream_frame_received(4, 0, 10), Ok(()));
        assert_eq!(map.max_recv_off(), 10);
        assert_eq!(map.on_reset_stream_frame_received(4, 0, 10), Ok(()));
        assert_eq!(map.max_recv_off(), 10);
        // After receiving a RESET_STREAM frame, the stream receive-side is finished,
        // but the stream is still readable.
        let stream = map.get(4).unwrap();
        assert!(stream.recv.is_fin());
        assert!(map.readable.contains(&4));

        // 6. Duplicate RESET_STREAM frame with different final size
        // stream_id: 8, final_size: 10
        assert_eq!(map.on_reset_stream_frame_received(8, 0, 10), Ok(()));
        assert_eq!(map.max_recv_off(), 20);
        assert_eq!(
            map.on_reset_stream_frame_received(8, 0, 20),
            Err(Error::FinalSizeError)
        );
        assert_eq!(map.max_recv_off(), 20);

        // 7. Receive a RESET_STREAM frame for a stream which has received some data
        //    and final size is same with the maximum received offset.
        // stream_id: 12, max received offset: 20, final size: 20.
        assert_eq!(
            map.on_stream_frame_received(12, 10, 10, false, Bytes::from_static(b"Everything")),
            Ok(())
        );
        assert_eq!(map.on_reset_stream_frame_received(12, 0, 20), Ok(()));
        assert_eq!(map.get(12).unwrap().recv.recv_off, 20);
        assert_eq!(map.get(12).unwrap().recv.fin_off, Some(20));

        // 8. Receive a RESET_STREAM frame for a stream which has received some data
        //    and final size is less than the maximum received offset.
        // stream_id: 16, max received offset: 20, final size: 10.
        assert_eq!(
            map.on_stream_frame_received(16, 10, 10, false, Bytes::from_static(b"Everything")),
            Ok(())
        );
        assert_eq!(
            map.on_reset_stream_frame_received(16, 0, 10),
            Err(Error::FinalSizeError)
        );

        // 9. Receive a RESET_STREAM frame for a stream which has received some data
        //    and final size is greater than the maximum received offset.
        // stream_id: 20, max received offset: 20, final size: 30.
        assert_eq!(
            map.on_stream_frame_received(20, 10, 10, false, Bytes::from_static(b"Everything")),
            Ok(())
        );
        assert_eq!(map.get(20).unwrap().recv.recv_off, 20);
        assert_eq!(map.on_reset_stream_frame_received(20, 0, 30), Ok(()));
        assert_eq!(map.get(20).unwrap().recv.recv_off, 30);
        assert_eq!(map.get(20).unwrap().recv.fin_off, Some(30));

        // 10. Receive a RESET_STREAM frame for a stream which has been closed.
        // Shutdown the stream abrubtly, it should be ok.
        let stream = map.get_or_create(24, false).unwrap();
        assert_eq!(stream.send.shutdown(), Ok((0, 0)));
        // Here we call `write` to make sure the stream's fin_off is set.
        assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
        assert!(stream.recv.shutdown().is_ok());
        assert_eq!(stream.is_complete(), true);
        map.mark_closed(24, false);
        assert!(
            map.on_reset_stream_frame_received(24, 0, 0).is_ok(),
            "Stream is already closed, just ignore the frame."
        );
    }

    #[test]
    fn stream_map_on_reset_stream_frame_received_flow_control_mechanism() {
        // Note: When a stream is reset, all buffered data will be discarded,
        // so consider the received data as consumed, which might trigger a
        // connection-level flow control update.

        let local_tp = StreamTransportParams {
            initial_max_data: 20,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp);
        assert_eq!(map.flow_control.window(), 20);
        assert_eq!(map.flow_control.max_data(), 20);

        // 1. Receive a RESET_STREAM frame for a stream which has received some data
        //    and final size is same with the maximum received offset.
        // stream_id: 4, max received offset: 4, read_off: 0, final size: 4.
        let stream = map.get_or_create(4, false).unwrap();
        assert_eq!(
            stream.recv.write(0, Bytes::from_static(b"QUIC"), false),
            Ok(())
        );
        assert_eq!(map.on_reset_stream_frame_received(4, 0, 4), Ok(()));
        // map.flow_control.consumed = 4
        assert_eq!(map.flow_control.max_data_next(), 24);
        assert!(
            !map.flow_control.should_send_max_data(),
            "available_window = 16 > 10 = window/2, not update max_data"
        );
        assert!(!map.rx_almost_full);

        // 2. Receive a RESET_STREAM frame for a stream which has received some data
        //    and final size is greater than the maximum received offset.
        // stream_id: 8, max received offset: 1, final size: 2.
        let stream = map.get_or_create(8, false).unwrap();
        assert_eq!(
            stream.recv.write(0, Bytes::from_static(b"QUICQUIC"), false),
            Ok(())
        );
        assert_eq!(map.on_reset_stream_frame_received(8, 0, 8), Ok(()));
        // map.flow_control.consumed = 12
        assert_eq!(map.flow_control.max_data_next(), 32);
        assert!(
            map.flow_control.should_send_max_data(),
            "available_window = 8 < 10 = window/2, update max_data"
        );
        assert!(map.rx_almost_full);
    }

    // Test StreamMap::on_stop_sending_frame_received
    #[test]
    fn stream_map_server_on_stop_sending_frame_received() {
        let is_server = true;
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };
        let mut map = StreamMap::new(is_server, 50, 50, local_tp);

        // 1. Receive a STOP_SENDING frame for a peer initiated receive-only stream
        let stream_id = 2;
        assert!(!is_local(stream_id, is_server));
        assert!(!is_bidi(stream_id));
        assert_eq!(
            map.on_stop_sending_frame_received(stream_id, 0),
            Err(Error::StreamStateError)
        );

        // 2. Receive a STOP_SENDING frame for a locally initiated stream that has not yet been created
        let stream_id = 1;
        assert!(is_local(stream_id, is_server));
        assert!(is_bidi(stream_id));
        assert_eq!(
            map.on_stop_sending_frame_received(stream_id, 0),
            Err(Error::StreamStateError)
        );

        // 3. Peer open too many bidi streams
        //    get_or_create will return Error::StreamLimitError
        assert_eq!(
            map.on_stop_sending_frame_received(40, 0),
            Err(Error::StreamLimitError)
        );

        // 4. Duplicate STOP_SENDING frame
        // stream_id: 4
        assert_eq!(map.on_stop_sending_frame_received(4, 7), Ok(()));
        assert_eq!(map.tx_data(), 0);
        // Send a RESET_STREAM frame to the peer after receiving a STOP_SENDING frame.
        assert!(map.reset.contains_key(&4));
        // After receiving a STOP_SENDING frame, the stream send-side is complete,
        // but the stream is still writable.
        let stream = map.get(4).unwrap();
        assert_eq!(stream.send.is_complete(), true);
        assert!(map.writable.contains(&4));
        assert_eq!(stream.send.error, Some(7));
        assert!(stream.send.is_stopped());
        assert_eq!(stream.send.capacity(), Err(Error::StreamStopped(7)));

        assert_eq!(map.on_stop_sending_frame_received(4, 0), Ok(()));

        // 5. Receive a STOP_SENDING frame for a stream which has been closed.
        // Shutdown the stream abrubtly, it should be ok.
        let stream = map.get_or_create(24, false).unwrap();
        assert_eq!(stream.send.shutdown(), Ok((0, 0)));
        // Here we call `write` to make sure the stream's fin_off is set.
        assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
        assert!(stream.recv.shutdown().is_ok());
        assert_eq!(stream.is_complete(), true);
        map.mark_closed(24, false);
        assert!(
            map.on_stop_sending_frame_received(24, 0).is_ok(),
            "Stream is already closed, just ignore the frame."
        );
    }

    #[test]
    fn stream_map_client_on_stop_sending_frame_received() {
        let is_server = false;
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };
        let mut map = StreamMap::new(is_server, 50, 50, local_tp);

        // 1. Receive a STOP_SENDING frame for a peer initiated receive-only stream
        let stream_id = 3;
        assert!(!is_local(stream_id, is_server));
        assert!(!is_bidi(stream_id));
        assert_eq!(
            map.on_stop_sending_frame_received(stream_id, 0),
            Err(Error::StreamStateError)
        );

        // 2. Receive a STOP_SENDING frame for a locally initiated stream that has not yet been created
        let stream_id = 0;
        assert!(is_local(stream_id, is_server));
        assert!(is_bidi(stream_id));
        assert_eq!(
            map.on_stop_sending_frame_received(stream_id, 0),
            Err(Error::StreamStateError)
        );

        // 3. Peer open too many bidi streams
        //    get_or_create will return Error::StreamLimitError
        assert_eq!(
            map.on_stop_sending_frame_received(41, 0),
            Err(Error::StreamLimitError)
        );

        // 4. Duplicate STOP_SENDING frame
        // stream_id: 5
        assert_eq!(map.on_stop_sending_frame_received(5, 7), Ok(()));
        assert_eq!(map.tx_data(), 0);
        // Send a RESET_STREAM frame to the peer after receiving a STOP_SENDING frame.
        assert!(map.reset.contains_key(&5));
        // After receiving a STOP_SENDING frame, the stream send-side is complete,
        // but the stream is still writable.
        let stream = map.get(5).unwrap();
        assert_eq!(stream.send.is_complete(), true);
        assert!(map.writable.contains(&5));
        assert_eq!(stream.send.error, Some(7));
        assert!(stream.send.is_stopped());
        assert_eq!(stream.send.capacity(), Err(Error::StreamStopped(7)));

        assert_eq!(map.on_stop_sending_frame_received(5, 0), Ok(()));

        // 5. Receive a STOP_SENDING frame for a stream which has been closed.
        // Shutdown the stream abrubtly, it should be ok.
        let stream = map.get_or_create(25, false).unwrap();
        assert_eq!(stream.send.shutdown(), Ok((0, 0)));
        // Here we call `write` to make sure the stream's fin_off is set.
        assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
        assert!(stream.recv.shutdown().is_ok());
        assert_eq!(stream.is_complete(), true);
        map.mark_closed(25, false);
        assert!(
            map.on_stop_sending_frame_received(25, 0).is_ok(),
            "Stream is already closed, just ignore the frame."
        );
    }

    // Test StreamMap::on_stream_frame_received
    #[test]
    fn stream_map_on_stream_frame_received() {
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };
        let mut map = StreamMap::new(true, 50, 50, local_tp);

        // 1. Receive a STREAM frame for a local initiated sent-only stream
        let stream_id = 3;
        assert!(is_local(stream_id, true));
        assert!(!is_bidi(stream_id));
        assert_eq!(
            map.on_stream_frame_received(stream_id, 0, 0, false, Bytes::from_static(b"Everything")),
            Err(Error::StreamStateError)
        );

        // 2. Receive a STREAM frame for a local initiated stream that has not yet been created
        let stream_id = 1;
        assert!(is_local(stream_id, true));
        assert!(is_bidi(stream_id));
        assert_eq!(
            map.on_stream_frame_received(stream_id, 0, 0, false, Bytes::from_static(b"Everything")),
            Err(Error::StreamStateError)
        );

        // 3. Peer open too many streams
        //    get_or_create will return Error::StreamLimitError
        assert_eq!(
            map.on_stream_frame_received(40, 0, 10, false, Bytes::from_static(b"Everything")),
            Err(Error::StreamLimitError)
        );

        // 4. Peer send too much data, exceed the connection-level flow control limit
        assert_eq!(
            map.on_stream_frame_received(0, 100, 10, false, Bytes::from_static(b"Everything")),
            Err(Error::FlowControlError)
        );

        // 5. Receive multi unorder STREAM frames for a stream
        // Receive the first block of data of stream 4
        assert_eq!(
            map.on_stream_frame_received(4, 0, 10, false, Bytes::from_static(b"Everything")),
            Ok(())
        );
        // Stream 4 should be created and readable.
        assert!(map.get(4).is_some());
        assert!(map.readable.contains(&4));
        assert_eq!(map.max_recv_off(), 10);
        // Receive the third block of data of stream 4
        assert_eq!(
            map.on_stream_frame_received(4, 14, 4, true, Bytes::from_static(b"QUIC")),
            Ok(())
        );
        assert_eq!(map.max_recv_off(), 18);
        // Receive the second block of data of stream 4
        assert_eq!(
            map.on_stream_frame_received(4, 10, 4, false, Bytes::from_static(b"Over")),
            Ok(())
        );
        assert_eq!(map.max_recv_off(), 18);

        let mut buf = vec![0; 18];
        assert_eq!(
            map.get_mut(4).unwrap().recv.read(&mut buf[0..10]),
            Ok((10, false))
        );
        assert_eq!(buf[0..10], b"Everything"[..]);
        assert_eq!(
            map.get_mut(4).unwrap().recv.read(&mut buf[10..18]),
            Ok((8, true))
        );
        assert_eq!(buf[10..18], b"OverQUIC"[..]);

        // 6. Receive multi overlap STREAM frames for a stream
        // Receive the first block of data of stream 8
        assert_eq!(
            map.on_stream_frame_received(8, 0, 10, false, Bytes::from_static(b"Everything")),
            Ok(())
        );
        assert_eq!(map.max_recv_off(), 28);
        // Duplicate receive the first block of data of stream 8
        assert_eq!(
            map.on_stream_frame_received(8, 0, 10, false, Bytes::from_static(b"Everything")),
            Ok(())
        );
        assert_eq!(map.max_recv_off(), 28);
        // Receive the fifth block of data of stream 8
        assert_eq!(
            map.on_stream_frame_received(8, 14, 4, true, Bytes::from_static(b"QUIC")),
            Ok(())
        );
        assert_eq!(map.max_recv_off(), 36);
        // Receive the second block of data of stream 8, overlap with the first block
        assert_eq!(
            map.on_stream_frame_received(8, 5, 6, false, Bytes::from_static(b"thingO")),
            Ok(())
        );
        assert_eq!(map.max_recv_off(), 36);
        // Receive the fourth block of data of stream 8, overlap with the fifth block
        assert_eq!(
            map.on_stream_frame_received(8, 13, 3, false, Bytes::from_static(b"rQU")),
            Ok(())
        );
        assert_eq!(map.max_recv_off(), 36);
        // Receive the third block of data of stream 8, overlap with the second and fourth block
        assert_eq!(
            map.on_stream_frame_received(8, 11, 4, false, Bytes::from_static(b"verQ")),
            Ok(())
        );
        assert_eq!(map.max_recv_off(), 36);

        let mut buf = vec![0; 18];
        assert_eq!(
            map.get_mut(8).unwrap().recv.read(&mut buf[0..10]),
            Ok((10, false))
        );
        assert_eq!(buf[0..10], b"Everything"[..]);
        assert_eq!(
            map.get_mut(8).unwrap().recv.read(&mut buf[10..18]),
            Ok((8, true))
        );
        assert_eq!(buf[10..18], b"OverQUIC"[..]);
    }

    fn stream_frame_received_on_closed_stream(map: &mut StreamMap, stream_id: u64) {
        // Create stream.
        let is_local = is_local(stream_id, map.is_server);
        let is_bidi = is_bidi(stream_id);
        let stream = map.get_or_create(stream_id, is_local).unwrap();

        // Fake close the stream.
        if is_bidi {
            assert!(stream.send.shutdown().is_ok());
        }
        assert!(stream.recv.write(0, Bytes::new(), true).is_ok());
        assert!(stream.recv.shutdown().is_ok());
        assert!(stream.is_complete());
        map.mark_closed(stream_id, is_local);

        // Receive stream frame on the closed stream.
        assert!(
            map.on_stream_frame_received(
                stream_id,
                0,
                10,
                false,
                Bytes::from_static(b"Everything")
            )
            .is_ok(),
            "Stream is already closed, just ignore the frame."
        );
    }

    // Test StreamMap::on_stream_frame_received, closed stream case.
    #[test]
    fn stream_map_on_stream_frame_received_with_closed_stream() {
        // Create stream map.
        let local_tp = StreamTransportParams {
            initial_max_streams_bidi: 5,
            initial_max_streams_uni: 5,
            ..StreamTransportParams::default()
        };
        let peer_tp = StreamTransportParams {
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
            ..StreamTransportParams::default()
        };
        let mut map = StreamMap::new(true, 50, 50, local_tp);
        map.update_peer_stream_transport_params(peer_tp);

        // Remote bidi stream.
        stream_frame_received_on_closed_stream(&mut map, 0);
        // Remote uni stream.
        stream_frame_received_on_closed_stream(&mut map, 2);
        // Local bidi stream.
        stream_frame_received_on_closed_stream(&mut map, 1);
    }

    #[test]
    fn receive_stream_frame_while_draining() {
        let local_tp = StreamTransportParams {
            initial_max_data: 20,
            initial_max_stream_data_bidi_local: 20,
            initial_max_stream_data_bidi_remote: 20,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };
        let mut map = StreamMap::new(true, 50, 50, local_tp);
        assert_eq!(map.flow_control.window(), 20);
        assert_eq!(map.flow_control.max_data(), 20);

        // Create stream 4
        let stream = map.get_or_create(4, false).unwrap();
        assert!(stream.recv.shutdown().is_ok());
        assert_eq!(stream.is_draining(), true);

        // Receive the first block of data of stream 4,  should not update max_data
        assert_eq!(
            map.on_stream_frame_received(4, 0, 4, false, Bytes::from_static(b"QUIC")),
            Ok(())
        );
        // map.flow_control.consumed = 4
        assert!(
            !map.flow_control.should_send_max_data(),
            "available_window = 16 > 10 = window/2, not update max_data"
        );
        assert!(!map.rx_almost_full);

        // Receive the second block of data of stream 4, should update max_data
        assert_eq!(
            map.on_stream_frame_received(4, 4, 8, false, Bytes::from_static(b"QUICQUIC")),
            Ok(())
        );
        // map.flow_control.consumed = 12
        assert!(
            map.flow_control.should_send_max_data(),
            "available_window = 8 < 10 = window/2, update max_data"
        );
        assert!(map.rx_almost_full);
    }

    // Test StreamMap::on_stream_frame_acked
    #[test]
    fn stream_map_on_stream_frame_acked() {
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };
        let peer_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp);
        map.update_peer_stream_transport_params(peer_tp);

        // Create a new client initiated bidirectional stream
        let stream = map.get_or_create(0, false).unwrap();
        assert_eq!(
            stream.send.write(Bytes::from_static(b"Everything"), false),
            Ok(10)
        );
        assert_eq!(stream.send.write(Bytes::from_static(b"Over"), false), Ok(4));
        assert_eq!(stream.send.write(Bytes::from_static(b"QUIC"), true), Ok(4));

        // Ack the first block of data of stream 0
        map.on_stream_frame_acked(0, 0, 10);
        let stream = map.get(0).unwrap();
        assert_eq!(stream.send.ack_off(), 10);
        assert_eq!(stream.send.unacked_len, 8);
        // Ack the third block of data of stream 0
        map.on_stream_frame_acked(0, 14, 4);
        let stream = map.get(0).unwrap();
        assert_eq!(stream.send.ack_off(), 10);
        assert_eq!(stream.send.unacked_len, 8);
        assert!(!stream.send.is_complete());
        // Ack the second block of data of stream 0
        map.on_stream_frame_acked(0, 10, 4);
        let stream = map.get_mut(0).unwrap();
        assert_eq!(stream.send.ack_off(), 18);
        assert_eq!(stream.send.unacked_len, 0);
        // All stream data has been acked, the stream's send-side should be complete.
        assert!(stream.send.is_complete());

        // Here we call `recv.write` to make sure the stream's fin_off is set.
        assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
        assert!(stream.recv.is_fin());

        // Stream is complete, but it still readable(read fin).
        assert_eq!(stream.is_complete(), true);
        assert!(stream.is_readable());

        // After shutdown the stream receive-side, it should be not readable.
        assert!(stream.recv.shutdown().is_ok());
        assert!(!stream.is_readable());

        // When the stream is complete, but not yet closed, if we receive a new
        // ACK for the stream, it should be closed.
        assert!(!map.is_closed(0));
        map.on_stream_frame_acked(0, 10, 4);
        assert!(map.is_closed(0));

        // Receive an ACK frame for a stream which has been closed, do nothing.
        map.on_stream_frame_acked(0, 10, 4);
    }

    // Test StreamMap::on_reset_stream_frame_acked
    #[test]
    fn stream_map_on_reset_stream_frame_acked() {
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };
        let mut map = StreamMap::new(true, 50, 50, local_tp);

        let stream = map.get_or_create(4, false).unwrap();
        assert_eq!(stream.send.shutdown(), Ok((0, 0)));
        assert!(stream.send.is_complete());
        map.on_reset_stream_frame_acked(4);

        // Receive an ACK for a RESET_STREAM frame, no effect on the stream receive-side.
        // The stream is still not complete because the stream receive-side is not complete.
        let stream = map.get_mut(4).unwrap();
        assert!(!stream.is_complete());

        // Here we call `recv.write` to make sure the stream's fin_off is set.
        assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
        assert!(stream.recv.is_fin());

        // Stream is complete, but it still readable(read fin).
        assert_eq!(stream.is_complete(), true);
        assert!(stream.is_readable());

        // After shutdown the stream receive-side, it should be not readable.
        assert!(stream.recv.shutdown().is_ok());
        assert!(!stream.is_readable());

        // When the stream is complete, but not yet closed, if we receive a new
        // ACK for a RESET_STREAM frame, it should be closed.
        assert!(!map.is_closed(4));
        map.on_reset_stream_frame_acked(4);
        assert!(map.is_closed(4));

        // Receive an ACK for a RESET_STREAM frame which has been closed, do nothing.
        map.on_reset_stream_frame_acked(4);
    }

    // Test StreamMap::on_stream_frame_lost
    #[test]
    fn stream_map_on_stream_frame_lost() {
        let local_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };
        let peer_tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 50,
            initial_max_stream_data_bidi_remote: 50,
            initial_max_stream_data_uni: 50,
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
        };

        let mut map = StreamMap::new(true, 50, 50, local_tp);
        map.update_peer_stream_transport_params(peer_tp);

        // Create a new client initiated bidirectional stream
        let stream = map.get_or_create(0, false).unwrap();
        assert_eq!(
            stream.send.write(Bytes::from_static(b"Everything"), false),
            Ok(10)
        );
        assert_eq!(stream.send.write(Bytes::from_static(b"Over"), false), Ok(4));
        assert_eq!(stream.send.write(Bytes::from_static(b"QUIC"), true), Ok(4));

        // Send all data of stream 0
        let mut out_buf = [0; 18];
        assert_eq!(stream.send.read(&mut out_buf), Ok((18, true)));
        assert!(!stream.is_sendable());

        // Lost the first and third block of data of stream 0
        assert!(map.peek_sendable().is_none());
        map.on_stream_frame_lost(0, 0, 10, false);
        let stream = map.get(0).unwrap();
        assert!(stream.is_sendable());
        assert_eq!(map.peek_sendable(), Some(0));
        map.on_stream_frame_lost(0, 14, 4, true);

        // Retransmit the first block of data of stream 0
        let stream = map.get_mut(0).unwrap();
        let mut out_buf = [0; 18];
        assert_eq!(stream.send.read(&mut out_buf), Ok((10, false)));
        assert!(stream.is_sendable());
        // Retransmit the third block of data of stream 0
        assert_eq!(stream.send.read(&mut out_buf[14..]), Ok((4, true)));
        assert!(!stream.is_sendable());
        map.remove_sendable();

        // Lost empty data with fin
        assert!(map.peek_sendable().is_none());
        map.on_stream_frame_lost(0, 18, 0, true);
        assert_eq!(map.peek_sendable(), Some(0));

        // Retransmit empty data with fin
        let stream = map.get_mut(0).unwrap();
        let mut out_buf = [0; 18];
        assert_eq!(stream.send.read(&mut out_buf), Ok((0, true)));

        // Ack all data of stream 0, the stream's send-side should be complete.
        map.on_stream_frame_acked(0, 0, 18);
        let stream = map.get_mut(0).unwrap();
        assert!(stream.send.is_complete());

        // Here we call `recv.write` to make sure the stream's fin_off is set.
        assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
        assert!(stream.recv.is_fin());
        assert!(stream.recv.shutdown().is_ok());
        assert_eq!(stream.is_complete(), true);
        map.mark_closed(0, false);
        assert!(map.is_closed(0));

        // After stream 0 is closed, ignore lost event.
        map.on_stream_frame_lost(0, 18, 0, true);
    }

    // Test StreamMap::on_reset_stream_frame_lost
    #[test]
    fn stream_map_on_reset_stream_frame_lost() {
        let local_tp = StreamTransportParams {
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
            ..StreamTransportParams::default()
        };
        let mut map = StreamMap::new(true, 50, 50, local_tp);

        // Found RESET_STREAM frame lost event on a client initiated bidirectional stream
        let stream = map.get_or_create(0, false).unwrap();
        map.on_reset_stream_frame_lost(0, 7, 10);
        let v = map.reset().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v, [(0, (7, 10))]);

        // Found RESET_STREAM frame lost event on a closed(4, simulation, not true) stream
        map.on_reset_stream_frame_lost(4, 7, 10);
        let v = map.reset().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v, [(0, (7, 10))]);
    }

    // Test StreamMap::on_stop_sending_frame_lost
    #[test]
    fn stream_map_on_stop_sending_frame_lost() {
        let local_tp = StreamTransportParams {
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
            ..StreamTransportParams::default()
        };
        let mut map = StreamMap::new(true, 50, 50, local_tp);

        // Found STOP_SENDING frame lost event on a client initiated bidirectional stream
        // and the fin flag of the stream receive-side is not set
        let stream = map.get_or_create(0, false).unwrap();
        map.on_stop_sending_frame_lost(0, 7);
        let v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v, [(0, 7)]);

        // Found STOP_SENDING frame lost event on a client initiated bidirectional stream
        // and the fin flag of the stream receive-side has been set
        let stream = map.get_or_create(4, false).unwrap();
        assert_eq!(stream.recv.write(0, Bytes::new(), true), Ok(()));
        map.on_stop_sending_frame_lost(4, 7);
        let v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v, [(0, 7)]);

        // Found STOP_SENDING frame lost event on a closed(8, simulation, not true) stream
        map.on_stop_sending_frame_lost(8, 7);
        let v = map.stopped().map(|(&k, &v)| (k, v)).collect::<Vec<_>>();
        assert_eq!(v, [(0, 7)]);
    }

    // Test StreamMap::on_max_stream_data_frame_lost
    #[test]
    fn stream_map_on_max_stream_data_frame_lost() {
        let local_tp = StreamTransportParams {
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
            ..StreamTransportParams::default()
        };
        let mut map = StreamMap::new(true, 50, 50, local_tp);

        // Found MAX_STREAM_DATA frame lost event on a client initiated bidirectional stream
        let stream = map.get_or_create(0, false).unwrap();
        map.on_max_stream_data_frame_lost(0);
        assert_eq!(map.almost_full().collect::<Vec<u64>>(), vec![0]);

        // Found RESET_STREAM frame lost event on a closed(4, simulation, not true) stream
        map.on_max_stream_data_frame_lost(4);
        assert_eq!(map.almost_full().collect::<Vec<u64>>(), vec![0]);
    }

    // Test StreamMap::on_max_data_frame_lost
    #[test]
    fn stream_map_on_max_data_frame_lost() {
        let mut map: StreamMap = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert!(!map.rx_almost_full);
        map.on_max_data_frame_lost();
        assert!(map.rx_almost_full);
    }

    // Test StreamMap::on_stream_data_blocked_frame_lost
    #[test]
    fn stream_map_on_stream_data_blocked_frame_lost() {
        let max_data = 100;
        let peer_tp = StreamTransportParams {
            initial_max_streams_bidi: 1,
            initial_max_stream_data_bidi_remote: max_data,
            ..StreamTransportParams::default()
        };

        // Create a client StreamMap and create a stream(0) on it
        let mut map = StreamMap::new(false, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);
        assert!(map.get_or_create(0, true).is_ok());
        assert_eq!(map.get(0).unwrap().send.max_data, max_data);

        // 1. Found STREAM_DATA_BLOCKED frame lost event, but the max_stream_data has been updated
        map.on_stream_data_blocked_frame_lost(0, max_data - 1);
        assert!(map.data_blocked.is_empty());

        // 2. Found STREAM_DATA_BLOCKED frame lost event, and the max_stream_data has not been updated
        map.on_stream_data_blocked_frame_lost(0, max_data);
        assert_eq!(map.data_blocked.contains_key(&0), true);
        assert_eq!(map.data_blocked.get(&0), Some(&max_data));

        // 3. Found Found STREAM_DATA_BLOCKED frame lost event on a closed stream
        map.mark_blocked(0, false, 0);
        map.mark_closed(0, true);
        map.on_stream_data_blocked_frame_lost(0, max_data);
        assert!(map.data_blocked.is_empty());
    }

    // Test StreamMap::on_data_blocked_frame_lost
    #[test]
    fn stream_map_on_data_blocked_frame_lost() {
        let max_data = 100;
        let peer_tp = StreamTransportParams {
            initial_max_data: max_data,
            ..StreamTransportParams::default()
        };
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);

        // 1. Found DATA_BLOCKED frame lost event, but the max_data has been updated
        map.on_data_blocked_frame_lost(max_data - 1);
        assert_eq!(map.data_blocked_at(), None);

        // 2. Found DATA_BLOCKED frame lost event, and the max_data has not been updated
        map.on_data_blocked_frame_lost(max_data);
        assert_eq!(map.data_blocked_at(), Some(max_data));

        // 3. Received MAX_DATA frame, and the max_data is larger than the data_blocked_at
        map.on_max_data_frame_received(max_data + 1);
        assert_eq!(map.data_blocked_at(), None);
    }

    // Test StreamMap::{streams_blocked, streams_blocked_at}
    #[test]
    fn stream_map_streams_blocked() {
        // Create a client StreamMap
        let is_server = false;
        let mut map = StreamMap::new(is_server, 50, 50, StreamTransportParams::default());

        for stream_id in [0, 2] {
            assert_eq!(
                map.get_or_create(stream_id, is_local(stream_id, is_server))
                    .err(),
                Some(Error::StreamLimitError)
            );
            assert_eq!(map.streams_blocked(), true);
            assert_eq!(
                map.streams_blocked_at(is_bidi(stream_id)),
                Some(map.concurrency_control.peer_max_streams(is_bidi(stream_id)))
            );

            assert!(map
                .on_max_streams_frame_received(1, is_bidi(stream_id))
                .is_ok());
            assert!(map.streams_blocked_at(is_bidi(stream_id)).is_none());
            assert!(map
                .get_or_create(stream_id, is_local(stream_id, is_server))
                .is_ok());
        }
    }

    // Test StreamMap::on_streams_blocked_frame_lost
    #[test]
    fn stream_map_on_streams_blocked_frame_lost() {
        let peer_tp = StreamTransportParams {
            initial_max_streams_bidi: 10,
            initial_max_streams_uni: 5,
            ..StreamTransportParams::default()
        };

        // Create a client StreamMap
        let is_server = false;
        let mut map = StreamMap::new(is_server, 50, 50, StreamTransportParams::default());
        map.update_peer_stream_transport_params(peer_tp);

        for bidi in &[true, false] {
            map.on_streams_blocked_frame_lost(*bidi, 1);
            assert_eq!(map.streams_blocked_at(*bidi), None);
            map.on_streams_blocked_frame_lost(
                *bidi,
                map.concurrency_control.peer_max_streams(*bidi),
            );
            assert_eq!(
                map.streams_blocked_at(*bidi),
                Some(map.concurrency_control.peer_max_streams(*bidi))
            );
        }
    }

    // Test StreamMap::update_peer_stream_transport_params
    #[test]
    fn stream_map_update_peer_stream_transport_params() {
        let mut map = StreamMap::new(true, 50, 50, StreamTransportParams::default());
        assert_eq!(map.peer_transport_params, StreamTransportParams::default());

        let tp = StreamTransportParams {
            initial_max_data: 100,
            initial_max_stream_data_bidi_local: 10,
            initial_max_stream_data_bidi_remote: 11,
            initial_max_stream_data_uni: 12,
            initial_max_streams_bidi: 13,
            initial_max_streams_uni: 14,
        };

        // Update peer transport params
        map.update_peer_stream_transport_params(tp.clone());
        assert_eq!(map.peer_transport_params, tp);
    }

    // Stream unit tests
    // Test Stream::new
    fn stream_new() {
        let stream = Stream::new(true, true, 20, 30, DEFAULT_STREAM_WINDOW);

        assert!(stream.local, "send-side is local");
        assert!(stream.bidi, "send-side is bidi");
        assert!(stream.incremental, "send-side is incremental");
        assert_eq!(stream.urgency, 127);
        assert_eq!(stream.write_thresh, 1);
        assert_eq!(stream.recv.max_data(), 30);
        assert_eq!(stream.send.max_data(), 20);
    }

    // Test Stream::is_complete
    #[test]
    fn stream_bidi_complete() {
        // Note that peer initiated stream unit tests are same as local initiated stream,
        // we would not write unit tests for them.

        // Create a local bidi stream
        let mut stream = Stream::new(true, true, 30, 30, DEFAULT_STREAM_WINDOW);

        // Check initial state
        assert!(!stream.send.is_fin(), "send-side is not fin");
        assert!(!stream.send.is_complete(), "send-side is not complete");
        assert!(!stream.recv.is_fin(), "recv-side is not fin");
        assert!(!stream.recv.is_complete(), "recv-side is not complete");
        assert!(!stream.is_complete(), "stream is not complete");

        // Check stream send-side state after sending data
        assert_eq!(
            stream.send.write(Bytes::from_static(b"Everything"), false),
            Ok(10)
        );
        assert_eq!(
            stream.send.write(Bytes::from_static(b"OverQUIC"), false),
            Ok(8)
        );

        assert!(!stream.send.is_fin());
        assert!(!stream.send.is_complete());

        // Send-side write fin
        assert_eq!(stream.send.write(Bytes::new(), true), Ok(0));

        assert!(stream.send.is_fin(), "send-side write fin");
        assert!(!stream.send.is_complete());

        // Check stream received-side state after receiving data
        assert!(stream
            .recv
            .write(0, Bytes::from_static(b"Everything"), true)
            .is_ok());
        assert!(!stream.recv.is_fin());
        assert!(!stream.recv.is_complete());

        // Check stream send-side state when some data is acked
        stream.send.ack(10, 8);
        assert!(!stream.send.is_complete());

        let mut buf = [0; 5];
        assert_eq!(stream.recv.read(&mut buf), Ok((5, false)));
        assert!(!stream.recv.is_fin());

        stream.send.ack(5, 5);
        assert!(!stream.send.is_complete());

        stream.send.ack(0, 5);
        assert!(
            stream.send.is_complete(),
            "all sent data is acked, send-side is complete"
        );

        assert!(!stream.is_complete());

        let mut buf = [0; 5];
        assert_eq!(stream.recv.read(&mut buf), Ok((5, true)));
        assert!(
            stream.recv.is_fin(),
            "all received data is read, recv-side is fin"
        );
        assert!(
            stream.recv.is_complete(),
            "all received data is read, recv-side is complete"
        );

        assert!(stream.is_complete());
    }

    #[test]
    fn stream_uni_complete() {
        // 1. Local initiated uni stream
        let mut stream = Stream::new(false, true, 30, 30, DEFAULT_STREAM_WINDOW);

        // Check initial state
        assert!(!stream.send.is_fin(), "send-side is not fin");
        assert!(!stream.send.is_complete(), "send-side is not complete");
        assert!(!stream.is_complete(), "stream is not complete");

        // Check stream send-side state after sending data
        assert_eq!(
            stream.send.write(Bytes::from_static(b"Everything"), false),
            Ok(10)
        );
        assert_eq!(
            stream.send.write(Bytes::from_static(b"OverQUIC"), false),
            Ok(8)
        );

        assert!(!stream.send.is_fin());
        assert!(!stream.send.is_complete());

        // Send-side write fin
        assert_eq!(stream.send.write(Bytes::new(), true), Ok(0));

        assert!(stream.send.is_fin(), "send-side write fin");
        assert!(!stream.send.is_complete());

        // Check stream send-side state when some data is acked
        stream.send.ack(10, 8);
        assert!(!stream.send.is_complete());
        assert!(!stream.is_complete());

        stream.send.ack(5, 5);
        assert!(!stream.send.is_complete());
        assert!(!stream.is_complete());

        stream.send.ack(0, 5);
        assert!(
            stream.send.is_complete(),
            "all sent data is acked, send-side is complete"
        );
        assert!(stream.is_complete());

        // 2. Peer initiated uni stream
        let mut stream = Stream::new(false, false, 30, 30, DEFAULT_STREAM_WINDOW);

        // Check initial state
        assert!(!stream.recv.is_fin(), "recv-side is not fin");
        assert!(!stream.recv.is_complete(), "recv-side is not complete");
        assert!(!stream.is_complete(), "stream is not complete");

        // Check stream received-side state after receiving data
        assert!(stream
            .recv
            .write(0, Bytes::from_static(b"Everything"), true)
            .is_ok());
        assert!(!stream.recv.is_fin());
        assert!(!stream.is_complete());

        let mut buf = [0; 5];
        assert_eq!(stream.recv.read(&mut buf), Ok((5, false)));
        assert!(!stream.recv.is_fin());
        assert!(!stream.is_complete());

        let mut buf = [0; 5];
        assert_eq!(stream.recv.read(&mut buf), Ok((5, true)));
        assert!(
            stream.recv.is_fin(),
            "all received data is read, recv-side is fin"
        );
        assert!(
            stream.recv.is_complete(),
            "all received data is read, recv-side is complete"
        );

        assert!(stream.is_complete());
    }

    #[test]
    fn stream_is_readable() {
        // Create a local initiated bidi stream
        let mut stream = Stream::new(true, true, 30, 30, DEFAULT_STREAM_WINDOW);
        assert!(!stream.is_readable(), "no data to read");

        // Receive the first block of data
        assert!(stream
            .recv
            .write(0, Bytes::from_static(b"Everything"), false)
            .is_ok());
        assert!(stream.is_readable());

        // Read first block of data
        let mut buf = [0; 10];
        assert_eq!(stream.recv.read(&mut buf), Ok((10, false)));
        assert!(!stream.is_readable(), "all received data is read");

        // Receive third block of data
        assert!(stream
            .recv
            .write(14, Bytes::from_static(b"QUIC"), true)
            .is_ok());
        assert!(!stream.is_readable(), "unordered data");

        // Receive second block of data
        assert!(stream
            .recv
            .write(10, Bytes::from_static(b"Over"), false)
            .is_ok());
        assert!(stream.is_readable());

        // Read part of the data
        let mut buf = [0; 5];
        assert_eq!(stream.recv.read(&mut buf), Ok((5, false)));
        assert_eq!(&buf, b"OverQ");
        assert!(stream.is_readable());

        // Read all the data
        let mut buf = [0; 3];
        assert_eq!(stream.recv.read(&mut buf), Ok((3, true)));
        assert_eq!(&buf, b"UIC");
        assert!(!stream.is_readable(), "all received data is read");
    }

    #[test]
    fn stream_is_writable() {
        // Create a local initiated bidi stream
        let mut stream = Stream::new(true, true, 10, 30, DEFAULT_STREAM_WINDOW);
        assert!(stream.is_writable(), "stream is writable");
        assert_eq!(stream.send.max_data(), 10);

        // Write the first block of data
        assert_eq!(
            stream.send.write(Bytes::from_static(b"Everything"), false),
            Ok(10)
        );
        assert!(!stream.is_writable(), "stream blocked by flow control");

        // Update flow control limit
        stream.send.update_max_data(20);
        assert_eq!(stream.send.max_data(), 20);
        assert!(stream.is_writable(), "stream is writable");

        // Write second block of data with fin
        assert_eq!(
            stream.send.write(Bytes::from_static(b"OverQUIC"), true),
            Ok(8)
        );
        assert!(stream.send.is_fin(), "send-side write fin");
        assert!(
            !stream.is_writable(),
            "stream is not writable because fin is write"
        );

        // Create a local initiated bidi stream
        let mut stream = Stream::new(true, true, 20, 30, DEFAULT_STREAM_WINDOW);
        assert!(stream.is_writable(), "stream is writable");
        assert_eq!(stream.send.max_data(), 20);

        // Write the first block of data
        assert_eq!(
            stream.send.write(Bytes::from_static(b"Everything"), false),
            Ok(10)
        );

        assert_eq!(stream.send.shutdown(), Ok((0, 10)));
        assert!(
            !stream.is_writable(),
            "stream is not writable because send-side is shutdown"
        );
    }

    // Test Stream::is_sendable, takes retranmission into account.
    #[test]
    fn stream_is_sendable() {
        // Create a local initiated bidi stream
        let mut stream = Stream::new(true, true, 20, 30, DEFAULT_STREAM_WINDOW);
        assert!(!stream.is_sendable(), "no data to send");
        assert_eq!(stream.send.max_data(), 20);

        // Write the first block of data
        assert_eq!(
            stream.send.write(Bytes::from_static(b"Everything"), false),
            Ok(10)
        );
        assert!(stream.is_sendable(), "has 10 bytes to send");

        // Send part of the first block data
        let mut buf = [0; 5];
        assert_eq!(stream.send.read(&mut buf), Ok((5, false)));
        assert!(
            stream.is_sendable(),
            "send_off < write_off, has 5 bytes to send"
        );

        // Send all the first block data
        let mut buf = [0; 5];
        assert_eq!(stream.send.read(&mut buf), Ok((5, false)));
        assert!(!stream.is_sendable(), "all buffered data is sent");

        // Write the second block of data
        assert_eq!(
            stream.send.write(Bytes::from_static(b"OverQUIC"), true),
            Ok(8)
        );
        assert!(stream.is_sendable(), "has 8 bytes to send");

        // Send all the second block data
        let mut buf = [0; 8];
        assert_eq!(stream.send.read(&mut buf), Ok((8, true)));
        assert!(!stream.is_sendable(), "all buffered data is sent");

        // Ack part of the second block data: [15, 18)
        stream.send.ack_and_drop(15, 3);

        // Lost part of the first block of data and need to retransmit
        stream.send.retransmit(5, 10);
        assert!(stream.is_sendable(), "has 10 bytes to retransmit");
        let mut buf = [0; 10];
        assert_eq!(stream.send.read(&mut buf), Ok((10, false)));
        assert_eq!(buf, b"thingOverQ"[..]);
        assert!(!stream.is_sendable(), "all buffered data is sent");

        // Lost part of the first block of data and need to retransmit
        stream.send.retransmit(0, 5);
        assert!(stream.is_sendable(), "has 5 bytes to retransmit");
        let mut buf = [0; 5];
        assert_eq!(stream.send.read(&mut buf), Ok((5, false)));
        assert_eq!(buf, b"Every"[..]);
        assert!(!stream.is_sendable(), "all buffered data is sent");

        // All data is sent and acked
        stream.send.ack_and_drop(0, 15);
        assert!(!stream.is_sendable(), "all data is sent and acked");
        assert!(stream.send.is_complete(), "all data is sent and acked");
    }

    // Test Stream::is_draining, takes unacked data into account.
    #[test]
    fn stream_is_draining() {
        // Create a local initiated bidi stream
        let mut stream = Stream::new(true, true, 20, 30, DEFAULT_STREAM_WINDOW);
        assert!(!stream.is_draining(), "the stream's recv-side is open");

        // Receive the first block of data
        assert!(stream
            .recv
            .write(0, Bytes::from_static(b"Everything"), false)
            .is_ok());
        assert!(stream.is_readable());

        // Receive the third block of data, unorderly
        assert!(stream
            .recv
            .write(14, Bytes::from_static(b"QUIC"), true)
            .is_ok());
        assert_eq!(stream.recv.recv_off(), 18);

        // Read part of the first block data
        let mut buf = [0; 5];
        assert_eq!(stream.recv.read(&mut buf), Ok((5, false)));
        assert_eq!(buf, b"Every"[..]);
        assert_eq!(stream.recv.read_off(), 5);

        // Shutdown the stream's recv-side
        assert!(stream.recv.shutdown().is_ok());
        assert_eq!(stream.recv.read_off(), stream.recv.recv_off());
        assert!(stream.is_draining(), "the stream's recv-side is shutdown");
        assert!(!stream.is_readable(), "the stream's recv-side is shutdown");

        // Receive second block of data, which will be discarded
        assert!(stream
            .recv
            .write(10, Bytes::from_static(b"Over"), false)
            .is_ok());
        assert!(stream.is_draining(), "the stream's recv-side is shutdown");
        assert!(!stream.is_readable(), "the stream's recv-side is shutdown");
    }

    // ConcurrencyControl unit tests
    // Test ConcurrencyControl::new
    #[test]
    fn concurrency_control_new() {
        let cc = ConcurrencyControl::new(10, 3);

        let mut peer_bidi_avail_ids = ranges::RangeSet::default();
        peer_bidi_avail_ids.insert(0..10);
        let mut peer_uni_avail_ids = ranges::RangeSet::default();
        peer_uni_avail_ids.insert(0..3);
        assert_eq!(
            cc,
            ConcurrencyControl {
                local_max_streams_bidi: 10,
                local_max_streams_bidi_next: 10,
                local_max_streams_uni: 3,
                local_max_streams_uni_next: 3,
                local_opened_streams_bidi: 0,
                local_opened_streams_uni: 0,
                peer_max_streams_bidi: 0,
                peer_max_streams_uni: 0,
                peer_opened_streams_bidi: 0,
                peer_opened_streams_uni: 0,
                streams_blocked_at_bidi: None,
                streams_blocked_at_uni: None,
                peer_bidi_avail_ids,
                peer_uni_avail_ids,
                ..ConcurrencyControl::default()
            }
        );
    }

    // Test ConcurrencyControl::check_concurrency_limits
    #[test]
    fn concurrency_control_check_concurrency_limits() {
        let mut cc = ConcurrencyControl::new(20, 12);
        cc.update_peer_max_streams(true, 10);
        cc.update_peer_max_streams(false, 6);

        assert_eq!(cc.local_max_streams_bidi, 20);
        assert_eq!(cc.local_max_streams_uni, 12);
        assert_eq!(cc.peer_max_streams_bidi, 10);
        assert_eq!(cc.peer_max_streams_uni, 6);

        // 1. Test is_server = true, i.e. current endpoint is server

        // 1.1 Server initiated bidirectional stream
        // (stream_id & 0x01 == 1 && stream_id & 0x02 == 0), 1, 5, 9...
        // is_server = true, is_local = true, is_bidi = true
        for (stream_id, is_server, result, local_opened_streams_bidi) in vec![
            (5, true, Ok(()), 2),
            // Open stream in order
            (9, true, Ok(()), 3),
            // Open stream unordered
            (1, true, Ok(()), 3),
            // Local opened bidi stream over peer_max_streams_bidi limit
            (41, true, Err(Error::StreamLimitError), 3),
        ] {
            assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
            assert_eq!(cc.local_opened_streams_bidi, local_opened_streams_bidi);
        }

        // 1.2 Server initiated unidirectional stream
        // (stream_id & 0x01 == 1 && stream_id & 0x02 == 1), 3, 7, 11...
        // is_server = true, is_local = true, is_bidi = false
        for (stream_id, is_server, result, local_opened_streams_uni) in vec![
            (7, true, Ok(()), 2),
            // Open stream in order
            (11, true, Ok(()), 3),
            // Open stream unordered
            (3, true, Ok(()), 3),
            // Local opened uni stream over peer_max_streams_uni limit
            (27, true, Err(Error::StreamLimitError), 3),
        ] {
            assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
            assert_eq!(cc.local_opened_streams_uni, local_opened_streams_uni);
        }

        // 1.3 Client initiated bidirectional stream
        // (stream_id & 0x01 == 0 && stream_id & 0x02 == 0), 0, 4, 8...
        // is_server = true, is_local = false, is_bidi = true
        for (stream_id, is_server, result, peer_opened_streams_bidi) in vec![
            (4, true, Ok(()), 2),
            // Open stream in order
            (8, true, Ok(()), 3),
            // Open stream unordered
            (0, true, Ok(()), 3),
            // Peer opened bidi stream over local_max_streams_bidi limit
            (80, true, Err(Error::StreamLimitError), 3),
        ] {
            assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
            assert_eq!(cc.peer_opened_streams_bidi, peer_opened_streams_bidi);
        }

        // 1.4 Client initiated unidirectional stream
        // (stream_id & 0x01 == 0 && stream_id & 0x02 == 1), 2, 6, 10...
        // is_server = true, is_local = false, is_bidi = false
        for (stream_id, is_server, result, peer_opened_streams_uni) in vec![
            (6, true, Ok(()), 2),
            // Open stream in order
            (10, true, Ok(()), 3),
            // Open stream unordered
            (2, true, Ok(()), 3),
            // Peer opened uni stream over local_max_streams_uni limit
            (50, true, Err(Error::StreamLimitError), 3),
        ] {
            assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
            assert_eq!(cc.peer_opened_streams_uni, peer_opened_streams_uni);
        }

        // 2. Test is_server = false, i.e. current endpoint is client
        let mut cc = ConcurrencyControl::new(20, 12);
        cc.update_peer_max_streams(true, 10);
        cc.update_peer_max_streams(false, 6);

        assert_eq!(cc.local_max_streams_bidi, 20);
        assert_eq!(cc.local_max_streams_uni, 12);
        assert_eq!(cc.peer_max_streams_bidi, 10);
        assert_eq!(cc.peer_max_streams_uni, 6);

        // 2.1 Server initiated bidirectional stream
        // (stream_id & 0x01 == 1 && stream_id & 0x02 == 0), 1, 5, 9...
        // is_server = false, is_local = false, is_bidi = true
        assert_eq!(cc.check_concurrency_limits(5, false), Ok(()));
        assert_eq!(cc.peer_opened_streams_bidi, 2);
        // Open stream in order
        assert_eq!(cc.check_concurrency_limits(9, false), Ok(()));
        assert_eq!(cc.peer_opened_streams_bidi, 3);
        // Open stream unordered
        assert_eq!(cc.check_concurrency_limits(1, false), Ok(()));
        assert_eq!(cc.peer_opened_streams_bidi, 3);
        // Peer opened bidi stream over local_max_streams_bidi limit
        assert_eq!(
            cc.check_concurrency_limits(81, false),
            Err(Error::StreamLimitError)
        );

        // 2.2 Server initiated unidirectional stream
        // (stream_id & 0x01 == 1 && stream_id & 0x02 == 1), 3, 7, 11...
        // is_server = false, is_local = false, is_bidi = false
        for (stream_id, is_server, result, peer_opened_streams_uni) in vec![
            (7, false, Ok(()), 2),
            // Open stream in order
            (11, false, Ok(()), 3),
            // Open stream unordered
            (3, false, Ok(()), 3),
            // Peer opened uni stream over local_max_streams_uni limit
            (51, false, Err(Error::StreamLimitError), 3),
        ] {
            assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
            assert_eq!(cc.peer_opened_streams_uni, peer_opened_streams_uni);
        }

        // 2.3 Client initiated bidirectional stream
        // (stream_id & 0x01 == 0 && stream_id & 0x02 == 0), 0, 4, 8...
        // is_server = false, is_local = true, is_bidi = true
        for (stream_id, is_server, result, local_opened_streams_bidi) in vec![
            (4, false, Ok(()), 2),
            // Open stream in order
            (8, false, Ok(()), 3),
            // Open stream unordered
            (0, false, Ok(()), 3),
            // Local opened bidi stream over peer_max_streams_bidi limit
            (40, false, Err(Error::StreamLimitError), 3),
        ] {
            assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
            assert_eq!(cc.local_opened_streams_bidi, local_opened_streams_bidi);
        }

        // 2.4 Client initiated unidirectional stream
        // (stream_id & 0x01 == 0 && stream_id & 0x02 == 1), 2, 6, 10...
        // is_server = false, is_local = true, is_bidi = false
        for (stream_id, is_server, result, local_opened_streams_uni) in vec![
            (6, false, Ok(()), 2),
            // Open stream in order
            (10, false, Ok(()), 3),
            // Open stream unordered
            (2, false, Ok(()), 3),
            // Local opened uni stream over peer_max_streams_uni limit
            (26, false, Err(Error::StreamLimitError), 3),
        ] {
            assert_eq!(cc.check_concurrency_limits(stream_id, is_server), result);
            assert_eq!(cc.local_opened_streams_uni, local_opened_streams_uni);
        }
    }

    // Test ConcurrencyControl::{
    //         should_update_max_streams_bidi,
    //         should_update_max_streams_uni,
    //         add_max_streams_bidi_credits,
    //         add_max_streams_uni_credits,
    //         update_peer_max_streams_bidi,
    //         update_peer_max_streams_uni,
    //         max_streams_bidi_next,
    //         max_streams_uni_next,
    //         peer_streams_left_bidi,
    //         peer_streams_left_uni,
    // }
    #[test]
    fn concurrency_control_update_methods() {
        let mut cc = ConcurrencyControl::new(20, 12);
        cc.update_peer_max_streams(true, 10);
        cc.update_peer_max_streams(false, 6);

        assert_eq!(cc.should_update_local_max_streams(true), false);
        assert_eq!(cc.should_update_local_max_streams(false), false);
        assert_eq!(cc.local_max_streams_bidi_next, 20);
        assert_eq!(cc.local_max_streams_uni_next, 12);
        assert_eq!(cc.peer_streams_left(true), 10);
        assert_eq!(cc.peer_streams_left(false), 6);

        // Peer opened 20 bidi streams
        assert_eq!(cc.check_concurrency_limits(76, true), Ok(()));
        assert_eq!(cc.peer_opened_streams_bidi, 20);
        // Peer opened 12 uni streams
        assert_eq!(cc.check_concurrency_limits(46, true), Ok(()));
        assert_eq!(cc.peer_opened_streams_uni, 12);
        assert_eq!(cc.should_update_local_max_streams(true), false);
        assert_eq!(cc.should_update_local_max_streams(false), false);
        cc.increase_max_streams_credits(true, 11);
        cc.increase_max_streams_credits(false, 7);
        assert_eq!(cc.local_max_streams_bidi_next, 31);
        assert_eq!(cc.local_max_streams_uni_next, 19);
        // Peer opened 20 bidi streams, closed 11(> 20/2), should update
        assert_eq!(cc.should_update_local_max_streams(true), true);
        // Peer opened 12 uni streams, closed 7(>12/2), should update
        assert_eq!(cc.should_update_local_max_streams(false), true);
        cc.update_local_max_streams(true);
        cc.update_local_max_streams(false);
        // After update, should_update_max_streams_bidi should be false
        assert_eq!(cc.should_update_local_max_streams(true), false);
        assert_eq!(cc.should_update_local_max_streams(false), false);
        assert_eq!(cc.local_max_streams_bidi_next, 31);
        assert_eq!(cc.local_max_streams_uni_next, 19);

        // Local opened 2 bidi streams, left 8
        assert_eq!(cc.check_concurrency_limits(5, true), Ok(()));
        assert_eq!(cc.local_opened_streams_bidi, 2);
        // Local opened 2 uni streams, left 4
        assert_eq!(cc.check_concurrency_limits(7, true), Ok(()));
        assert_eq!(cc.local_opened_streams_uni, 2);
        assert_eq!(cc.peer_streams_left(true), 8);
        assert_eq!(cc.peer_streams_left(false), 4);
    }

    // RecvBuf unit tests
    // Test RecvBuf::new
    #[test]
    fn recv_buf_new() {
        let max_data: u64 = 100;
        let max_window: u64 = 600;
        let recv = RecvBuf::new(100, 600);
        assert_eq!(recv.data.len(), 0);
        assert_eq!(recv.read_off, 0);
        assert_eq!(recv.recv_off, 0);
        assert_eq!(recv.fin_off, None);
        assert_eq!(recv.error, None);
        assert_eq!(recv.shutdown, false);
    }

    // Write multiple empty FIN buffers to RecvBuf.
    #[test]
    fn recv_buf_write_multiple_empty_fin_buffer() {
        let mut recv = RecvBuf::new(100, 600);
        assert_eq!(recv.data.len(), 0);

        // recv [0, 10) with FIN
        assert_eq!(
            recv.write(0, Bytes::from_static(b"Everything"), true),
            Ok(())
        );

        for i in 1..5 {
            // Write empty FIN buffer
            assert_eq!(recv.write(10, Bytes::new(), true), Ok(()));
            assert_eq!(recv.data.len(), 1);
            assert_eq!(recv.fin_off, Some(10));
            assert!(recv.ready());
        }
    }

    // Test RecvBuf::{write, read}
    #[test]
    fn recv_buf_multi_write_in_order() {
        let mut recv = RecvBuf::new(100, 600);
        assert_eq!(recv.data.len(), 0);

        let data = Bytes::from("Hello, TQUIC!");
        let data_len = data.len();

        let first = Bytes::from("Hell");
        let second = Bytes::from("o, T");
        let third = Bytes::from("QUIC!");

        assert_eq!(recv.write(0, first, false), Ok(()));
        assert_eq!(recv.recv_off, 4);

        assert_eq!(recv.write(4, second, false), Ok(()));
        assert_eq!(recv.recv_off, 8);

        assert_eq!(recv.write(8, third, true), Ok(()));
        assert_eq!(recv.recv_off, 13);

        let mut out_buf = [0; 128];
        let (len, fin) = recv.read(&mut out_buf[..128]).unwrap();
        assert_eq!(len, 13);
        assert_eq!(fin, true);
        assert_eq!(recv.fin_off, Some(13));
        assert_eq!(recv.recv_off, 13);
        assert_eq!(recv.read_off, 13);
        assert_eq!(out_buf[..data_len], data[..data_len]);
    }

    // Test RecvBuf::{write, read} with out of order data
    #[test]
    fn recv_buf_multi_write_out_of_order() {
        let mut recv = RecvBuf::new(100, 600);
        assert_eq!(recv.data.len(), 0);

        let data = Bytes::from("Hello, TQUIC!");
        let data_len = data.len();

        let first = Bytes::from("Hell");
        let second = Bytes::from("o, T");
        let third = Bytes::from("QUIC!");

        // recv [4, 8)
        assert_eq!(recv.write(4, second, false), Ok(()));
        assert_eq!(recv.recv_off, 8);
        assert_eq!(recv.read_off, 0);

        // Out of order, read 0 bytes
        let mut out_buf = [0; 128];
        assert_eq!(recv.read(&mut out_buf[..128]), Err(Error::Done));

        // recv [8, 13)
        assert_eq!(recv.write(8, third, true), Ok(()));
        assert_eq!(recv.recv_off, 13);
        assert_eq!(recv.read_off, 0);
        assert_eq!(recv.fin_off, Some(13));

        // Out of order, read 0 bytes
        let mut out_buf = [0; 128];
        assert_eq!(recv.read(&mut out_buf[..128]), Err(Error::Done));

        // recv [0, 4)
        assert_eq!(recv.write(0, first, false), Ok(()));
        assert_eq!(recv.recv_off, 13);
        assert_eq!(recv.fin_off, Some(13));

        // read 13 bytes
        let mut out_buf = [0; 128];
        let (len, fin) = recv.read(&mut out_buf[..128]).unwrap();
        assert_eq!(len, 13);
        assert_eq!(fin, true);
        assert_eq!(recv.fin_off, Some(13));
        assert_eq!(recv.recv_off, 13);
        assert_eq!(recv.read_off, 13);
        assert_eq!(out_buf[..data_len], data[..data_len]);
    }

    #[test]
    fn recv_buf_write_overlapping_data() {
        let mut recv = RecvBuf::new(20, 10);
        assert_eq!(recv.data.len(), 0);

        let data = Bytes::from("EverythingOverQUIC");
        let data_len = data.len();

        // recv [0, 5)
        assert_eq!(recv.write(0, Bytes::from_static(b"Every"), false), Ok(()));

        // consume [0, 5)
        let mut buf = [0; 5];
        assert_eq!(recv.read(&mut buf), Ok((5, false)));
        assert_eq!(buf, data[..5]);

        // recv [0, 10)
        // Bytes up to read_off have already been consumed by application, will be
        // discard directly.
        assert_eq!(
            recv.write(0, Bytes::from_static(b"Everything"), false),
            Ok(())
        );

        // recv [14, 18)
        assert_eq!(recv.write(14, Bytes::from_static(b"QUIC"), true), Ok(()));

        // duplicate recv [5, 10)
        assert_eq!(recv.write(5, Bytes::from_static(b"thing"), false), Ok(()));

        // recv [5, 11), overlap with [0, 10)
        assert_eq!(recv.write(5, Bytes::from_static(b"thingO"), false), Ok(()));

        // recv [13, 16), overlap with [14, 18)
        assert_eq!(recv.write(13, Bytes::from_static(b"rQU"), false), Ok(()));

        // recv [10, 14), overlap with [5, 11) and [13, 16)
        assert_eq!(recv.write(10, Bytes::from_static(b"Over"), false), Ok(()));
        assert_eq!(recv.recv_off, 18);

        let mut buf = [0; 18];
        assert_eq!(recv.read(&mut buf), Ok((13, true)));
        assert_eq!(buf[0..13], data[5..]);
    }

    #[test]
    fn recv_buf_write_exceed_flow_control() {
        let mut recv = RecvBuf::new(10, 5);
        assert_eq!(
            recv.write(0, Bytes::from_static(b"EverythingOverQUIC"), false),
            Err(Error::FlowControlError)
        );
    }

    #[test]
    fn recv_buf_final_size_legality() {
        let mut recv = RecvBuf::new(20, 10);
        // recv [0, 14)
        assert_eq!(
            recv.write(0, Bytes::from_static(b"EverythingOver"), false),
            Ok(())
        );

        // Do nothing if the buffer is empty and without fin flag.
        assert_eq!(recv.write(10, Bytes::new(), false), Ok(()));

        // An endpoint received a STREAM frame containing a final size that was lower than
        // the size of data that was already received.
        assert_eq!(
            recv.write(0, Bytes::from_static(b"Everything"), true),
            Err(Error::FinalSizeError)
        );

        // recv [14, 18)
        assert_eq!(recv.write(14, Bytes::from_static(b"QUIC"), true), Ok(()));

        // A receiver SHOULD treat receipt of data at or beyond the final size as an error
        // of type FINAL_SIZE_ERROR.
        assert_eq!(
            recv.write(18, Bytes::from_static(b"!"), false),
            Err(Error::FinalSizeError)
        );

        // Once a final size for a stream is known, it cannot be change. If a STREAM frame
        // is received indicating a change in the final size for the stream, an endpoint
        // SHOULD respond with an error of type FINAL_SIZE_ERROR.
        assert_eq!(
            recv.write(10, Bytes::from_static(b"Over"), true),
            Err(Error::FinalSizeError)
        );

        // Do nothing if the final offset is already known, an the buffer is empty.
        assert_eq!(recv.write(10, Bytes::new(), false), Ok(()));
    }

    #[test]
    fn recv_buf_read_after_reset() {
        let mut buf = [0; 20];

        // Subcase 1: reset before receiving any data
        let mut recv = RecvBuf::new(20, 10);
        assert_eq!(recv.reset(7, 18), Ok(18));

        assert!(recv.ready());
        assert_eq!(recv.read(&mut buf), Err(Error::StreamReset(7)));
        assert_eq!(recv.read(&mut buf), Err(Error::Done));

        // Subcase 2: reset after receiving some data without fin flag
        let mut recv = RecvBuf::new(20, 10);

        // recv [0, 10), and then reset it at offset 18 with error code 7.
        assert_eq!(
            recv.write(0, Bytes::from_static(b"Everything"), false),
            Ok(())
        );
        assert_eq!(recv.reset(7, 18), Ok(8));

        // The stream has been reset by the peer.
        assert_eq!(recv.read(&mut buf), Err(Error::StreamReset(7)));
        assert_eq!(recv.read(&mut buf), Err(Error::Done));

        // Subcase 3: reset after receiving some data with fin flag
        let mut recv = RecvBuf::new(20, 10);

        // recv [0, 18), and then reset it at offset 18 with error code 7.
        assert_eq!(
            recv.write(0, Bytes::from_static(b"EverythingOverQuic"), true),
            Ok(())
        );
        assert_eq!(recv.reset(7, 18), Ok(0));

        // The stream has been reset by the peer.
        assert_eq!(recv.read(&mut buf), Err(Error::StreamReset(7)));
        assert_eq!(recv.read(&mut buf), Err(Error::Done));
    }

    #[test]
    fn stream_shutdown_read() {
        let mut recv = RecvBuf::new(20, 10);

        // recv [0, 10)
        assert_eq!(
            recv.write(0, Bytes::from_static(b"Everything"), false),
            Ok(())
        );
        // recv [14, 18)
        assert_eq!(recv.write(14, Bytes::from_static(b"QUIC"), false), Ok(()));

        assert_eq!(recv.data.len(), 2);
        assert_eq!(recv.recv_off(), 18);
        assert_eq!(recv.read_off(), 0);
        assert!(!recv.is_shutdown());

        // Aftet shutdown read:
        //   1) read_off will be updated to recv_off;
        //   2) data will be cleared;
        //   3) is_shutdown will be set to true.
        assert!(recv.shutdown().is_ok());
        assert!(recv.is_shutdown());
        assert!(recv.data.is_empty());
        assert_eq!(recv.recv_off(), 18);
        assert_eq!(recv.read_off(), 18);

        // shutdown read, would not affect the finished state of the stream's receive-side.
        assert!(!recv.is_fin());

        // duplicate shutdown
        assert_eq!(recv.shutdown(), Err(Error::Done));
    }

    // SendBuf unit tests
    // Test SendBuf::new
    #[test]
    fn send_buf_new() {
        let mut send = SendBuf::new(100);
        assert_eq!(send.capacity().unwrap(), 100);
        assert_eq!(send.data.len(), 0);
        assert_eq!(send.write_off, 0);
        assert_eq!(send.unsent_off, 0);
        assert_eq!(send.unacked_len, 0);
        assert_eq!(send.max_data, 100);
        assert_eq!(send.blocked_at, None);
        assert_eq!(send.fin_off, None);
        assert_eq!(send.shutdown, false);
        assert_eq!(send.acked.len(), 0);
        assert_eq!(send.retransmits.len(), 0);
        assert_eq!(send.error, None);
        assert_eq!(send.read_range(0..10).is_empty(), true);
    }

    // Test the properties of SendBuf, include data blocks, cap,
    // write, write_off, unsent_off, unacked_len, fin_off, error
    #[test]
    fn send_buf_write_basic_logic() {
        let max_tx_data: usize = 100;
        let mut send = SendBuf::new(max_tx_data as u64);
        assert_eq!(send.data.len(), 0);
        assert_eq!(send.capacity().unwrap(), max_tx_data);

        // Data will be split into consistently sized chunks to avoid fragmentation.
        // Each chunk size is limited by SEND_BUFFER_SIZE(5).

        // Write SEND_BUFFER_SIZE(5) bytes
        let data = Bytes::from("Hello");
        assert_eq!(send.write(data, false), Ok(5));
        assert_eq!(send.unacked_len, 5);
        assert_eq!(send.capacity().unwrap(), max_tx_data.saturating_sub(5));
        // ceil(5 / 5) == 1
        assert_eq!(send.data.len(), 1);

        let data = Bytes::from("Everything over QUIC!");
        assert_eq!(send.write(data, false), Ok(21));
        assert_eq!(send.unacked_len, 26);
        assert_eq!(send.capacity().unwrap(), max_tx_data.saturating_sub(26));
        // ceil(21 / 5) == 5, plus 1 from previous write, equals 6
        assert_eq!(send.data.len(), 6);

        let data = Bytes::from(Bytes::copy_from_slice(&b"a".repeat(100)));
        assert_eq!(send.write(data, true), Ok(74));
        assert_eq!(send.unacked_len, 100);
        assert_eq!(send.capacity().unwrap(), 0);
        // ceil(74 / 5) == 15, plus 6 from previous write, equals 21
        assert_eq!(send.data.len(), 21);
        assert_eq!(send.fin_off, None);

        // Write an empty buffer with fin flag set.
        assert_eq!(send.write(Bytes::new(), true), Ok(0));
        assert_eq!(send.unacked_len, 100);
        assert_eq!(send.capacity().unwrap(), 0);
        assert_eq!(send.data.len(), 21);
        assert_eq!(send.fin_off, Some(100));

        // Can't write more data after fin flag is set.
        assert_eq!(
            send.write(Bytes::from_static(b"b"), true),
            Err(Error::FinalSizeError)
        );
        // Fin flag can't be cancelled after it was set.
        assert_eq!(send.write(Bytes::new(), false), Err(Error::FinalSizeError));
    }

    // Test for SendBuf::{write, read}
    #[test]
    fn send_buf_multi_write() {
        let mut send = SendBuf::new(100);
        assert_eq!(send.data.len(), 0);

        let data = Bytes::from("Hello, TQUIC!");
        let first = Bytes::from("Hell");
        let second = Bytes::from("o, T");
        let third = Bytes::from("QUIC!");

        // write [0, 4)
        assert_eq!(send.write(first, false), Ok(4));
        assert_eq!(send.unacked_len, 4);
        assert_eq!(send.data.len(), 1);

        // write [4, 8)
        assert_eq!(send.write(second, false), Ok(4));
        assert_eq!(send.unacked_len, 8);
        assert_eq!(send.data.len(), 2);

        // write [8, 13)
        assert_eq!(send.write(third, true), Ok(5));
        assert_eq!(send.unacked_len, 13);
        assert_eq!(send.data.len(), 3);

        let mut out_buf = [0; 128];
        let (len, fin) = send.read(&mut out_buf[..128]).unwrap();
        assert_eq!(len, 13);
        assert_eq!(fin, true);
        assert_eq!(send.fin_off, Some(13));
        assert_eq!(send.unacked_len, 13);
        assert_eq!(send.unsent_off, 13);
        assert_eq!(out_buf[..13], data[..13]);
    }

    #[test]
    fn send_buf_ack_in_order() {
        let mut send = SendBuf::new(100);
        assert_eq!(send.data.len(), 0);

        let write_data = Bytes::from("Hello, TQUIC!");
        let data = write_data.clone();
        let first = Bytes::from("Hell");
        let second = Bytes::from("o, T");
        let third = Bytes::from("QUIC!");

        assert_eq!(send.write(write_data, true), Ok(13));
        assert_eq!(send.unacked_len, 13);

        let mut out_buf = [0; 128];
        let (len, fin) = send.read(&mut out_buf[..128]).unwrap();
        assert_eq!(len, 13);
        assert_eq!(fin, true);
        assert_eq!(send.fin_off, Some(13));
        assert_eq!(send.unacked_len, 13);
        assert_eq!(send.unsent_off, 13);
        assert_eq!(out_buf[..13], data[..13]);

        // all data is unacked
        assert_eq!(aggregate_unacked(&send), data[..13].to_vec());

        // ack [0, 4]
        send.ack_and_drop(0, 4);
        assert_eq!(send.ack_off(), 4);
        assert_eq!(aggregate_unacked(&send), data[4..13].to_vec());

        // ack [4, 8]
        send.ack_and_drop(4, 4);
        assert_eq!(send.ack_off(), 8);
        assert_eq!(aggregate_unacked(&send), data[8..13].to_vec());

        // ack [8, 13]
        send.ack_and_drop(8, 5);
        assert_eq!(send.ack_off(), 13);
        assert_eq!(aggregate_unacked(&send).is_empty(), true);
    }

    #[test]
    fn send_buf_ack_out_of_order() {
        let mut send = SendBuf::new(100);
        assert_eq!(send.data.len(), 0);

        let write_data = Bytes::from("Hello, TQUIC!");
        let data = write_data.clone();
        let first = Bytes::from("Hell");
        let second = Bytes::from("o, T");
        let third = Bytes::from("QUIC!");

        assert_eq!(send.write(write_data, true), Ok(13));
        assert_eq!(send.unacked_len, 13);

        let mut out_buf = [0; 128];
        assert_eq!(send.read(&mut out_buf[..128]), Ok((13, true)));
        assert_eq!(send.fin_off, Some(13));
        assert_eq!(send.unacked_len, 13);
        assert_eq!(send.unsent_off, 13);
        assert_eq!(out_buf[..13], data[..13]);

        // read nothing because all data is sent and no data need to be retransmitted
        assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

        // all data is unacked
        assert_eq!(aggregate_unacked(&send), data[..13].to_vec());

        // ack [8, 13]
        send.ack_and_drop(8, 5);
        assert_eq!(send.ack_off(), 0);
        assert_eq!(aggregate_unacked(&send), data[..13].to_vec());

        // ack [0, 4]
        send.ack_and_drop(0, 4);
        assert_eq!(send.ack_off(), 4);
        assert_eq!(aggregate_unacked(&send), data[4..13].to_vec());

        // ack [4, 8]
        send.ack_and_drop(4, 4);
        assert_eq!(send.ack_off(), 13);
        assert_eq!(aggregate_unacked(&send).is_empty(), true);
    }

    #[test]
    fn send_buf_spurious_retransmit() {
        let mut send = SendBuf::new(100);
        assert_eq!(send.data.len(), 0);

        let write_data = Bytes::from("Hello, TQUIC!");
        let data = write_data.clone();
        let first = Bytes::from("Hell");
        let second = Bytes::from("o, T");
        let third = Bytes::from("QUIC!");

        assert_eq!(send.write(write_data, true), Ok(13));
        assert_eq!(send.unacked_len, 13);

        let mut out_buf = [0; 128];
        assert_eq!(send.read(&mut out_buf[..128]), Ok((13, true)));
        assert_eq!(send.fin_off, Some(13));
        assert_eq!(send.unacked_len, 13);
        assert_eq!(send.unsent_off, 13);
        assert_eq!(out_buf[..13], data[..13]);

        // read nothing because all data is sent and no data need to be retransmitted
        assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

        // lost [4, 8), retransmit [4, 8)
        send.retransmit(4, 4);
        assert_eq!(send.read(&mut out_buf[..128]), Ok((4, false)));
        assert_eq!(out_buf[..4], data[4..8]);
        // read nothing because all data is sent and no data need to be retransmitted
        assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

        // lost [4, 8) and invalid range [8, 21), retransmit [4, 8)
        send.retransmit(4, 4);
        // invalid retransmit range [8, 21), nothing changed
        send.retransmit(8, 13);
        assert_eq!(send.read(&mut out_buf[..128]), Ok((4, false)));
        assert_eq!(out_buf[..4], data[4..8]);
        // read nothing because all data is sent and no data need to be retransmitted
        assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

        // lost [0, 4) and [8, 13), retransmit [0, 4) and [8, 13)
        send.retransmit(0, 4);
        send.retransmit(8, 5);
        assert_eq!(send.read(&mut out_buf[..128]), Ok((4, false)));
        assert_eq!(out_buf[..4], data[0..4]);
        assert_eq!(send.read(&mut out_buf[..128]), Ok((5, true)));
        assert_eq!(out_buf[..5], data[8..13]);
        // read nothing because all data is sent and no data need to be retransmitted
        assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));

        // spurious retransmit [4, 8)
        send.retransmit(4, 4);
        send.ack_and_drop(4, 4);
        assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));
        // no data be acked continuously == all data is unacked
        assert_eq!(aggregate_unacked(&send), data[..13].to_vec());

        // spurious retransmit [0, 13)
        send.retransmit(0, 13);
        // ack [4, 8)
        send.ack_and_drop(4, 4);
        // no data be acked continuously == all data is unacked
        assert_eq!(aggregate_unacked(&send), data[..13].to_vec());
        assert_eq!(send.read(&mut out_buf[..128]), Ok((4, false)));
        assert_eq!(out_buf[..4], data[0..4]);
        assert_eq!(send.read(&mut out_buf[..128]), Ok((5, true)));
        assert_eq!(out_buf[..5], data[8..13]);
        // ack [0, 4)
        send.ack_and_drop(0, 4);
        assert_eq!(aggregate_unacked(&send), data[8..13].to_vec());
        assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));
        // spurious retransmit [0, 10), effective retransmit [8, 10)
        send.retransmit(0, 10);
        assert_eq!(aggregate_unacked(&send), data[8..13].to_vec());
        assert_eq!(send.read(&mut out_buf[..128]), Ok((2, false)));
        assert_eq!(out_buf[..2], data[8..10]);
        // ack [8, 13)
        send.ack_and_drop(8, 5);
        assert_eq!(aggregate_unacked(&send).is_empty(), true);
        assert_eq!(send.read(&mut out_buf[..128]), Ok((0, true)));
    }

    #[test]
    fn send_buf_retransmit_over_acked_ranges() {
        let mut send = SendBuf::new(100);
        assert_eq!(send.data.len(), 0);

        let write_data = Bytes::from("Everything over QUIC!");
        let data = write_data.clone();

        // Write [0, 21)
        assert_eq!(send.write(write_data, true), Ok(21));
        let mut out_buf = [0; 128];

        // Sent [0, 20)
        assert_eq!(send.read(&mut out_buf[..20]), Ok((20, false)));
        assert_eq!(out_buf[..20], data[..20]);

        // Ack [0, 5) + [10, 20), ack_off: 5
        send.ack_and_drop(0, 5);
        send.ack_and_drop(10, 10);
        assert_eq!(send.ack_off(), 5);

        // Lost [5, 15)
        send.retransmit(5, 10);
        // Ack [5, 11), ack_off: 20
        send.ack_and_drop(5, 6);
        assert_eq!(send.ack_off(), 20);

        assert_eq!(send.read(&mut out_buf[..20]), Ok((1, true)));
        assert_eq!(out_buf[..1], data[20..21]);
    }

    #[test]
    fn send_buf_retransmit_cross_acked_ranges() {
        let mut send = SendBuf::new(100);
        assert_eq!(send.data.len(), 0);

        let write_data = Bytes::from("Everything over QUIC!");
        let data = write_data.clone();

        // Write [0, 21)
        assert_eq!(send.write(write_data, true), Ok(21));
        let mut out_buf = [0; 128];

        // Sent [0, 20)
        assert_eq!(send.read(&mut out_buf[..20]), Ok((20, false)));
        assert_eq!(out_buf[..20], data[..20]);

        // Ack [5, 10) + [15, 18), ack_off: 0
        send.ack_and_drop(5, 5);
        send.ack_and_drop(15, 3);
        assert_eq!(send.acked.peek_min(), Some(5..10));
        assert_eq!(send.ack_off(), 0);

        // 1. The retransmit range is before the first acked range.
        // Lost [0, 1)
        send.retransmit(0, 1);
        assert_eq!(send.retransmits.peek_min(), Some(0..1));
        // Lost [1, 5)
        send.retransmit(1, 4);
        assert_eq!(send.retransmits.pop_min(), Some(0..5));

        // 2. The second half of the retransmit range is covered by the acked range.
        // Lost [1, 6)
        send.retransmit(1, 5);
        assert_eq!(send.retransmits.peek_min(), Some(1..5));
        // Lost [1, 10)
        send.retransmit(1, 9);
        assert_eq!(send.retransmits.pop_min(), Some(1..5));

        // 3. The retransmit range crosses the first acked range.
        // Lost [1, 11)
        send.retransmit(1, 10);
        assert_eq!(send.retransmits.pop_min(), Some(1..5));
        assert_eq!(send.retransmits.pop_min(), Some(10..11));
        // Lost [1, 15)
        send.retransmit(1, 14);
        assert_eq!(send.retransmits.pop_min(), Some(1..5));
        assert_eq!(send.retransmits.pop_min(), Some(10..15));

        // 4. The retransmit range crosses the first acked range and intersects with the second acked range.
        // Lost [1, 16)
        send.retransmit(1, 15);
        assert_eq!(send.retransmits.pop_min(), Some(1..5));
        assert_eq!(send.retransmits.pop_min(), Some(10..15));
        assert!(send.retransmits.is_empty());
        // Lost [1, 18)
        send.retransmit(1, 17);
        assert_eq!(send.retransmits.pop_min(), Some(1..5));
        assert_eq!(send.retransmits.pop_min(), Some(10..15));
        assert!(send.retransmits.is_empty());

        // 5. The retransmit range crosses multiple acked ranges.
        // Lost [1, 19)
        send.retransmit(1, 18);
        assert_eq!(send.retransmits.pop_min(), Some(1..5));
        assert_eq!(send.retransmits.pop_min(), Some(10..15));
        assert_eq!(send.retransmits.pop_min(), Some(18..19));
        assert!(send.retransmits.is_empty());

        // 6. The retransmit range is covered by the acked range fully.
        // Lost [5, 10)
        send.retransmit(5, 5);
        assert!(send.retransmits.is_empty());

        // 7. The first half of the retransmit range is covered by the acked range.
        // Lost [6, 12)
        send.retransmit(6, 6);
        assert_eq!(send.retransmits.pop_min(), Some(10..12));
        // Lost [9, 12)
        send.retransmit(9, 3);
        assert_eq!(send.retransmits.pop_min(), Some(10..12));

        // 8. The retransmit range interacts with multiple acked ranges.
        // Lost [6, 17)
        send.retransmit(6, 11);
        assert_eq!(send.retransmits.pop_min(), Some(10..15));
        assert!(send.retransmits.is_empty());

        // 9. The first half of the retransmit range is covered by the first acked range,
        // and crosses the second acked range.
        // Lost [6, 20)
        send.retransmit(6, 14);
        assert_eq!(send.retransmits.pop_min(), Some(10..15));
        assert_eq!(send.retransmits.pop_min(), Some(18..20));
        assert!(send.retransmits.is_empty());

        // 10. The retransmit range is after the second acked range.
        send.retransmit(18, 1);
        assert_eq!(send.retransmits.pop_min(), Some(18..19));
        send.retransmit(18, 2);
        assert_eq!(send.retransmits.pop_min(), Some(18..20));

        assert_eq!(send.read(&mut out_buf[..20]), Ok((1, true)));
        assert_eq!(out_buf[..1], data[20..21]);
    }

    #[test]
    fn send_buf_poll_transmit() {
        let mut send = SendBuf::new(100);

        assert_eq!(
            send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
            Ok(18)
        );

        let mut buf = [0; 18];
        assert_eq!(send.read(&mut buf[0..14]), Ok((14, false)));

        // Lost [0, 5) and [10, 14)
        send.retransmit(0, 5);
        send.retransmit(10, 4);

        // retransmit [0, 5)
        assert_eq!(send.poll_transmit(5), Range { start: 0, end: 5 });
        // retransmit [10, 12)
        assert_eq!(send.poll_transmit(2), Range { start: 10, end: 12 });
        // retransmit [12, 14)
        assert_eq!(send.poll_transmit(2), Range { start: 12, end: 14 });
        // send [14, 18)
        assert_eq!(send.poll_transmit(2), Range { start: 14, end: 16 });
        // send [16, 18)
        assert_eq!(send.poll_transmit(10), Range { start: 16, end: 18 });
    }

    // Test SendBuf::shutdown
    #[test]
    fn stream_shutdown_write() {
        // After shutdown, stream send-side is complete and no data can be written.
        // 1. Shutdown directly after creation
        let mut send = SendBuf::new(100);
        assert_eq!(send.shutdown(), Ok((0, 0)));
        assert_eq!(send.is_complete(), true);

        // 2. After writing data, shutdown the stream prematurely before any data is sent.
        let mut send = SendBuf::new(100);
        assert_eq!(
            send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
            Ok(18)
        );
        assert_eq!(send.shutdown(), Ok((0, 18)));
        assert_eq!(send.is_complete(), true);

        // 3. After writing data, shutdown the stream after part of data is sent.
        let mut send = SendBuf::new(100);
        assert_eq!(
            send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
            Ok(18)
        );
        assert_eq!(send.read(&mut [0; 10]), Ok((10, false)));
        assert_eq!(send.shutdown(), Ok((10, 8)));
        assert_eq!(send.is_complete(), true);

        // 4. After writing data, shutdown the stream after all data is sent.
        let mut send = SendBuf::new(100);
        assert_eq!(
            send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
            Ok(18)
        );
        assert_eq!(send.read(&mut [0; 18]), Ok((18, true)));
        assert_eq!(send.shutdown(), Ok((18, 0)));
        assert_eq!(send.is_complete(), true);

        // 5. After writing data, shutdown the stream after all data is sent and acked.
        let mut send = SendBuf::new(100);
        assert_eq!(
            send.write(Bytes::from_static(b"EverythingOverQUIC"), true),
            Ok(18)
        );
        assert_eq!(send.read(&mut [0; 18]), Ok((18, true)));
        send.ack_and_drop(0, 18);
        assert_eq!(send.shutdown(), Ok((18, 0)));
        assert_eq!(send.is_complete(), true);

        // 6. Shutdown duplicate.
        assert_eq!(send.shutdown(), Err(Error::Done));
    }

    // Aggregates all unacked data in the send buffer.
    fn aggregate_unacked(buf: &SendBuf) -> Vec<u8> {
        let mut data = Vec::new();
        for b in buf.data.iter() {
            data.extend_from_slice(&b[..]);
        }
        data
    }

    #[test]
    fn rangebuf_split_off() {
        // Create a RangeBuf with 21 Bytes data.
        let x = b"Everything over QUIC!";
        let mut buf = RangeBuf::new(Bytes::copy_from_slice(x), 10, true);

        // Check the RangeBuf metadata.
        assert_eq!(buf.off, 10);
        assert_eq!(buf.fin, true);
        assert_eq!(buf.data.len(), 21);

        // Check the RangeBuf methods.
        assert_eq!(buf.off(), 10);
        assert_eq!(buf.fin(), true);
        assert_eq!(buf.len(), 21);
        assert_eq!(buf.max_off(), 31);
        assert_eq!(buf.is_empty(), false);

        // Check the RangeBuf slice.
        assert_eq!(buf[..], x[..]);

        // Consuming 5 Bytes from buf.
        // After Consuming, buf == "thing over QUIC!"
        buf.consume(5);

        assert_eq!(buf.off, 15);
        assert_eq!(buf.fin, true);
        assert_eq!(buf.data.len(), 16);

        assert_eq!(buf.off(), 15);
        assert_eq!(buf.fin(), true);
        assert_eq!(buf.len(), 16);
        assert_eq!(buf.max_off(), 31);
        assert_eq!(buf.is_empty(), false);

        assert_eq!(buf[..], x[5..]);

        // Split buffer, new buf contains [at, len), old buf contains [0, at).
        // After splitting, buf == "thing", new_buf == " over QUIC!".
        let mut new_buf = buf.split_off(5);

        assert_eq!(buf.off, 15);
        assert_eq!(buf.fin, false);
        assert_eq!(buf.data.len(), 5);

        assert_eq!(buf.off(), 15);
        assert_eq!(buf.fin(), false);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.max_off(), 20);
        assert_eq!(buf.is_empty(), false);

        assert_eq!(buf[..], x[5..10]);

        assert_eq!(new_buf.off, 20);
        assert_eq!(new_buf.fin, true);
        assert_eq!(new_buf.data.len(), 11);

        assert_eq!(new_buf.off(), 20);
        assert_eq!(new_buf.fin(), true);
        assert_eq!(new_buf.len(), 11);
        assert_eq!(new_buf.max_off(), 31);
        assert_eq!(new_buf.is_empty(), false);

        assert_eq!(new_buf[..], x[10..]);

        // Consuming 5 Bytes data from new_buf.
        // After Consuming, new_buf == " QUIC!".
        new_buf.consume(5);

        assert_eq!(new_buf.off, 25);
        assert_eq!(new_buf.fin, true);
        assert_eq!(new_buf.data.len(), 6);

        assert_eq!(new_buf.off(), 25);
        assert_eq!(new_buf.fin(), true);
        assert_eq!(new_buf.len(), 6);
        assert_eq!(new_buf.max_off(), 31);
        assert_eq!(new_buf.is_empty(), false);

        assert_eq!(new_buf[..], x[15..]);

        // Split buffer again, new buf contains [at, len), old buf contains [0, at).
        // After splitting, new_buf == " ", new_new_buf == "QUIC!".
        let mut new_new_buf = new_buf.split_off(1);

        assert_eq!(new_buf.off, 25);
        assert_eq!(new_buf.fin, false);
        assert_eq!(new_buf.data.len(), 1);

        assert_eq!(new_buf.off(), 25);
        assert_eq!(new_buf.fin(), false);
        assert_eq!(new_buf.len(), 1);
        assert_eq!(new_buf.max_off(), 26);
        assert_eq!(new_buf.is_empty(), false);

        assert_eq!(new_buf[..], x[15..16]);

        assert_eq!(new_new_buf.off, 26);
        assert_eq!(new_new_buf.fin, true);
        assert_eq!(new_new_buf.data.len(), 5);

        assert_eq!(new_new_buf.off(), 26);
        assert_eq!(new_new_buf.fin(), true);
        assert_eq!(new_new_buf.len(), 5);
        assert_eq!(new_new_buf.max_off(), 31);
        assert_eq!(new_new_buf.is_empty(), false);

        assert_eq!(new_new_buf[..], x[16..]);

        // Consuming 5 Bytes data from new_new_buf.
        // After Consuming, new_new_buf == "".
        new_new_buf.consume(5);

        assert_eq!(new_new_buf.off, 31);
        assert_eq!(new_new_buf.fin, true);
        assert_eq!(new_new_buf.data.len(), 0);

        assert_eq!(new_new_buf.off(), 31);
        assert_eq!(new_new_buf.fin(), true);
        assert_eq!(new_new_buf.len(), 0);
        assert_eq!(new_new_buf.max_off(), 31);
        assert_eq!(new_new_buf.is_empty(), true);

        assert_eq!(&new_new_buf[..], b"");
    }

    #[test]
    fn rangebuf_split_to() {
        // Create a RangeBuf with 21 Bytes data.
        let x = b"Everything over QUIC!";
        let mut buf = RangeBuf::new(Bytes::copy_from_slice(x), 10, true);

        // Check the RangeBuf metadata.
        assert_eq!(buf.off, 10);
        assert_eq!(buf.fin, true);
        assert_eq!(buf.data.len(), 21);

        // Check the RangeBuf methods.
        assert_eq!(buf.off(), 10);
        assert_eq!(buf.fin(), true);
        assert_eq!(buf.len(), 21);
        assert_eq!(buf.max_off(), 31);
        assert_eq!(buf.is_empty(), false);

        // Check the RangeBuf slice.
        assert_eq!(buf[..], x[..]);

        // Advance 5 Bytes from buf.
        // After advancing, buf == "thing over QUIC!"
        buf.advance(5);

        assert_eq!(buf.off, 15);
        assert_eq!(buf.fin, true);
        assert_eq!(buf.data.len(), 16);

        assert_eq!(buf.off(), 15);
        assert_eq!(buf.fin(), true);
        assert_eq!(buf.len(), 16);
        assert_eq!(buf.max_off(), 31);
        assert_eq!(buf.is_empty(), false);

        assert_eq!(buf[..], x[5..]);

        // Split buffer, old buf contains [at, len), new buf contains [0, at).
        // After splitting, new_buf == "thing", buf == " over QUIC!".
        let new_buf = buf.split_to(5);

        assert_eq!(new_buf.off, 15);
        assert_eq!(new_buf.fin, false);
        assert_eq!(new_buf.data.len(), 5);

        assert_eq!(new_buf.off(), 15);
        assert_eq!(new_buf.fin(), false);
        assert_eq!(new_buf.len(), 5);
        assert_eq!(new_buf.max_off(), 20);
        assert_eq!(new_buf.is_empty(), false);

        assert_eq!(new_buf[..], x[5..10]);

        assert_eq!(buf.off, 20);
        assert_eq!(buf.fin, true);
        assert_eq!(buf.data.len(), 11);

        assert_eq!(buf.off(), 20);
        assert_eq!(buf.fin(), true);
        assert_eq!(buf.len(), 11);
        assert_eq!(buf.max_off(), 31);
        assert_eq!(buf.is_empty(), false);

        assert_eq!(buf[..], x[10..]);

        // Advance 5 Bytes data from buf.
        // After advancing, buf == " QUIC!".
        buf.advance(5);

        assert_eq!(buf.off, 25);
        assert_eq!(buf.fin, true);
        assert_eq!(buf.data.len(), 6);

        assert_eq!(buf.off(), 25);
        assert_eq!(buf.fin(), true);
        assert_eq!(buf.len(), 6);
        assert_eq!(buf.max_off(), 31);
        assert_eq!(buf.is_empty(), false);

        assert_eq!(buf[..], x[15..]);

        // Split buffer again, old buf contains [at, len), new buf contains [0, at).
        // After splitting, new_buf == " ", buf == "QUIC!".
        let new_buf = buf.split_to(1);

        assert_eq!(new_buf.off, 25);
        assert_eq!(new_buf.fin, false);
        assert_eq!(new_buf.data.len(), 1);

        assert_eq!(new_buf.off(), 25);
        assert_eq!(new_buf.fin(), false);
        assert_eq!(new_buf.len(), 1);
        assert_eq!(new_buf.max_off(), 26);
        assert_eq!(new_buf.is_empty(), false);

        assert_eq!(new_buf[..], x[15..16]);

        assert_eq!(buf.off, 26);
        assert_eq!(buf.fin, true);
        assert_eq!(buf.data.len(), 5);

        assert_eq!(buf.off(), 26);
        assert_eq!(buf.fin(), true);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.max_off(), 31);
        assert_eq!(buf.is_empty(), false);

        assert_eq!(buf[..], x[16..]);

        // Advance 5 Bytes data from buf.
        // After advancing, buf == "".
        buf.advance(5);

        assert_eq!(buf.off, 31);
        assert_eq!(buf.fin, true);
        assert_eq!(buf.data.len(), 0);

        assert_eq!(buf.off(), 31);
        assert_eq!(buf.fin(), true);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.max_off(), 31);
        assert_eq!(buf.is_empty(), true);

        assert_eq!(&buf[..], b"");
    }
}
