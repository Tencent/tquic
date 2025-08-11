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
//!
//! This module provides support for unreliable datagram transmission over QUIC connections
//! as defined in RFC 9221. Datagrams are application messages that can be lost or reordered
//! but are delivered without the overhead of stream flow control and ordering guarantees.
//!
//! ## Features
//!
//! * Priority-based queue management with BTreeMap organization
//! * Automatic expiration of outdated datagrams
//! * Memory-bounded queues with configurable limits  
//! * Statistics tracking for sent/received datagrams
//! * Event generation for dropped datagrams
//!
//! ## Usage
//!
//! ```rust,ignore
//! let mut manager = DatagramManager::new();
//! manager.set_peer_max_datagram_frame_size(1200);
//! manager.set_local_max_datagram_frame_size(1200);
//!
//! // Send a datagram with priority and expiration
//! let params = SendDatagramParams::with_priority_and_expiration(0, 5000);
//! let datagram_id = manager.send_datagram(data, params)?;
//!
//! // Get next datagram for transmission (handles priority and expiration)
//! if let Some(item) = manager.next_send_datagram() {
//!     // Send the datagram...
//! }
//! ```
use crate::qlog::events;
use crate::Event;
use crate::EventQueue;
use crate::Result;
use crate::{connection::datagram, error::Error};
use bytes::Bytes;
use core::error;
use log::*;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::rc::Rc;
use std::time::Instant;

/// Default queue size limit in kilobytes for both incoming and outgoing queues.
///
/// This provides a reasonable balance between memory usage and buffering capacity.
pub const DEFAULT_QUEUE_SIZE_KB: usize = 16 * 1024;

/// Memory allocation granularity for datagram queues in bytes.
///
/// Queue size limits are specified in KB but internally managed with this byte granularity.
/// This allows for more precise memory management while keeping the API simple.
pub const DATAGRAM_QUEUE_GRANULARITY_BYTES: usize = 1024;

/// Parameters for sending a datagram with priority and expiration control.
///
/// This structure encapsulates all parameters needed for datagram transmission,
/// making it easy to extend with additional parameters in the future without
/// breaking API compatibility.
///
/// ## Priority System
///
/// The priority system uses a numeric scale where lower numbers indicate higher priority:
/// - 0: Highest priority (critical data)
/// - 127: Default priority (normal data)  
/// - 255: Lowest priority (background data)
///
/// ## Expiration
///
/// Datagrams can optionally be given an expiration time. Expired datagrams are
/// automatically dropped when encountered during transmission, helping prevent
/// the transmission of stale data.
#[derive(Debug, Clone)]
pub struct SendDatagramParams {
    /// Priority of the datagram (lower number = higher priority).
    ///
    /// Range: 0-255, where 0 is highest priority and 255 is lowest.
    /// Default is 127 to provide a middle ground for most applications.
    pub priority: u8,

    /// Relative expiration time in milliseconds from now.
    ///
    /// When set to `Some(ms)`, the datagram will be dropped if not transmitted
    /// within the specified number of milliseconds. `None` means no expiration.
    pub expiration_ms: Option<u64>,
}

impl Default for SendDatagramParams {
    fn default() -> Self {
        Self {
            priority: 127,
            expiration_ms: None,
        }
    }
}

impl SendDatagramParams {
    /// Create new send parameters with priority only (no expiration).
    ///
    /// # Arguments
    /// * `priority` - Priority level (0 = highest, 255 = lowest)
    ///
    /// # Examples
    /// ```rust,ignore
    /// let params = SendDatagramParams::with_priority(0); // Highest priority
    /// let params = SendDatagramParams::with_priority(255); // Lowest priority
    /// ```
    pub fn with_priority(priority: u8) -> Self {
        Self {
            priority,
            expiration_ms: None,
        }
    }

    /// Create new send parameters with both priority and expiration.
    ///
    /// # Arguments
    /// * `priority` - Priority level (0 = highest, 255 = lowest)
    /// * `expiration_ms` - Expiration time in milliseconds from now,0 is no expiration
    ///
    /// # Examples
    /// ```rust,ignore
    /// // High priority datagram that expires in 5 seconds
    /// let params = SendDatagramParams::with_priority_and_expiration(0, 5000);
    ///
    /// // Low priority datagram that expires in 30 seconds
    /// let params = SendDatagramParams::with_priority_and_expiration(200, 30000);
    /// ```
    pub fn with_priority_and_expiration(priority: u8, expiration_ms: u64) -> Self {
        Self {
            priority,
            expiration_ms: if expiration_ms > 0 {
                Some(expiration_ms)
            } else {
                None
            },
        }
    }
}

/// DATAGRAM frame manager for a QUIC connection.
///
/// This implementation follows RFC 9221 which defines an extension to QUIC
/// that adds support for sending and receiving unreliable datagrams over
/// a QUIC connection.
///
/// ## Key Features
///
/// * **Priority-based sending**: Uses BTreeMap to organize outgoing datagrams by priority
/// * **Automatic expiration**: Expired datagrams are automatically dropped during transmission
/// * **Memory management**: Configurable memory limits with automatic cleanup of old data
/// * **Statistics tracking**: Comprehensive metrics for monitoring datagram usage
/// * **Event generation**: Emits events when datagrams are dropped for observability
///
/// ## Memory Management
///
/// The manager maintains separate memory-bounded queues for incoming and outgoing datagrams.
/// When limits are exceeded, the oldest datagrams are dropped first (for incoming) or
/// lowest priority datagrams are dropped first (for outgoing).
///
/// ## Priority System
///
/// Outgoing datagrams are organized by priority using a BTreeMap where:
/// - Lower numeric values = higher priority (0 is highest)
/// - Higher priority datagrams are sent first
/// - Within the same priority, FIFO order is maintained
/// - When memory is constrained, lower priority datagrams are dropped first
pub struct DatagramManager {
    /// Outgoing datagrams waiting to be sent, organized by priority.
    /// Lower priority values have higher precedence (0 is highest priority).
    outgoing_queue: BTreeMap<u8, VecDeque<DatagramItem>>,

    /// Total size of all outgoing datagrams in bytes.
    total_outgoing_size: usize,

    /// Maximum allowed size for outgoing datagrams in bytes.
    max_outgoing_size: usize,

    /// Incoming datagrams ready for application consumption.
    incoming_queue: DatagramQueue,

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

    /// Used to identify a send datagram frame.
    next_send_datagram_id: u64,

    /// Used to identify a recv datagram frame.
    next_recv_datagram_id: u64,

    /// Events sent to the endpoint.
    pub(super) events: Rc<RefCell<EventQueue>>,
}

pub enum AdjustResult {
    /// Successfully adjusted the queue size,the new max size is bigger than old.
    Success,
    /// The new size is smaller than the maximum allowed size but bigger than the current size.
    Normal,
    /// The new size is smaller than the current size.
    TooSmall,
}

/// A memory-limited queue for datagrams.
pub struct DatagramQueue {
    /// The core data structure: a queue of items.
    data: VecDeque<DatagramItem>,

    /// Current total size of all datagram payloads in the queue, in bytes.
    current_size: usize,

    /// The maximum memory size this queue is allowed to occupy, in bytes.
    max_size: usize,

    events: Rc<RefCell<EventQueue>>,
}

impl DatagramQueue {
    /// Creates a new datagram queue with a specific memory limit.
    /// Use Kb as basic unit.
    pub fn new(max_size_kb: usize, events: Rc<RefCell<EventQueue>>) -> Self {
        Self {
            data: VecDeque::new(),
            current_size: 0,
            max_size: max_size_kb * DATAGRAM_QUEUE_GRANULARITY_BYTES,
            events,
        }
    }

    /// Attempts to add an item to the queue.
    ///
    /// If the queue is full, it will try to make space by dropping.
    /// If a datagram is larger than the memsize, do not enqueue it.
    pub fn enqueue(&mut self, item: DatagramItem) -> Result<()> {
        let item_size = item.memory_size();

        // If the item is larger than the maximum size, drop it directly.
        if item_size > self.max_size {
            self.events
                .borrow_mut()
                .add(Event::DatagramReceiverDrop(item.id));
            return Err(Error::DatagramTooLarge);
        }
        // If adding this item would exceed the memory limit, try to make space
        if self.current_size + item_size > self.max_size {
            self.make_space_for(item_size);
        }

        // Add the item to the queue
        self.current_size += item_size;
        self.data.push_back(item);

        Ok(())
    }

    /// Returns `Some(DatagramItem)` or `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<DatagramItem> {
        if let Some(item) = self.data.pop_front() {
            self.current_size = self.current_size.saturating_sub(item.memory_size());
            Some(item)
        } else {
            None
        }
    }

    /// Returns the number of items currently in the queue.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the queue contains no items.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the current memory usage of the queue in bytes.
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Returns the configured maximum memory size of the queue in bytes.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Updates the maximum memory size of the queue at runtime.
    /// if now current == max,just success.
    pub fn set_max_size(&mut self, new_max_size_kb: usize) -> AdjustResult {
        let new_size = new_max_size_kb * DATAGRAM_QUEUE_GRANULARITY_BYTES;
        if new_size < self.current_size {
            return AdjustResult::TooSmall;
        } else if new_size < self.max_size {
            self.max_size = new_size;
            return AdjustResult::Normal;
        }
        self.max_size = new_size;
        return AdjustResult::Success;
    }

    /// Removes all items from the queue.
    pub fn clear(&mut self) {
        self.data.clear();
        self.current_size = 0;
    }

    /// Try to make space for a new item of given size.
    fn make_space_for(&mut self, needed_size: usize) {
        // If not enough space, remove items from the front (oldest first)
        while self.current_size + needed_size > self.max_size && !self.data.is_empty() {
            if let Some(item) = self.data.pop_front() {
                self.current_size = self.current_size.saturating_sub(item.memory_size());

                // Notify the receiver that a datagram was dropped
                self.events
                    .borrow_mut()
                    .add(Event::DatagramReceiverDrop(item.id));
            }
        }
    }
}

/// A single datagram item containing the payload and metadata.
///
/// This structure represents a single datagram in the queue system, containing
/// both the actual data payload and associated metadata needed for processing,
/// prioritization, and expiration handling.
///
/// ## Lifecycle
///
/// 1. Created when `send_datagram()` is called with user data and parameters
/// 2. Stored in priority-ordered queues within `DatagramManager`  
/// 3. Retrieved by `next_send_datagram()` for transmission (if not expired)
/// 4. Automatically dropped if expired or when memory limits are exceeded
#[derive(Debug, Clone)]
pub struct DatagramItem {
    /// The datagram payload data to be transmitted.
    pub data: Bytes,

    /// Whether to include length field in frame encoding.
    ///
    /// When `true`, the DATAGRAM frame will include a length field.
    /// When `false`, the frame data extends to the end of the packet.
    pub with_length: bool,

    /// Timestamp when the datagram was queued for transmission.
    ///
    /// Used for debugging, metrics, and calculating how long items
    /// have been waiting in the queue.
    pub queued_at: std::time::Instant,

    /// Unique identifier for this datagram.
    ///
    /// Used for tracking purposes and in drop events. IDs are
    /// monotonically increasing within a connection.
    pub id: u64,

    /// Priority of this datagram (lower number = higher priority).
    ///
    /// Determines the order in which datagrams are transmitted.
    /// Range: 0-255, where 0 is highest priority.
    pub priority: u8,

    /// Absolute expiration time when this datagram becomes invalid.
    ///
    /// When `Some(instant)`, the datagram will be automatically dropped
    /// if transmission is attempted after this time. `None` means no expiration.
    pub expires_at: Option<std::time::Instant>,
}

impl DatagramItem {
    /// Get the memory size of this datagram item in bytes.
    ///
    /// Returns only the size of the actual payload data, not including
    /// the metadata overhead. This is used for memory quota calculations.
    pub fn memory_size(&self) -> usize {
        self.data.len()
    }

    /// Check if this datagram has expired and should be dropped.
    ///
    /// Returns `true` if the datagram has an expiration time that has passed,
    /// `false` if the datagram is still valid or has no expiration.
    ///
    /// # Examples
    /// ```rust,ignore
    /// if item.is_expired() {
    ///     // Drop this datagram and generate a drop event
    /// }
    /// ```
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            std::time::Instant::now() > expires_at
        } else {
            false
        }
    }
}

impl DatagramManager {
    /// Create a new DatagramManager with default settings.
    pub fn new() -> Self {
        let events = Rc::new(RefCell::new(EventQueue::default()));
        Self {
            outgoing_queue: BTreeMap::new(),
            total_outgoing_size: 0,
            max_outgoing_size: DEFAULT_QUEUE_SIZE_KB * DATAGRAM_QUEUE_GRANULARITY_BYTES,
            incoming_queue: DatagramQueue::new(DEFAULT_QUEUE_SIZE_KB, events.clone()),
            peer_max_datagram_frame_size: 0,
            local_max_datagram_frame_size: 0,
            enabled: false,
            sent_count: 0,
            received_count: 0,
            sent_bytes: 0,
            received_bytes: 0,
            trace_id: String::new(),
            next_send_datagram_id: 1,
            next_recv_datagram_id: 1,
            events,
        }
    }

    /// Set trace id for debug logging.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.trace_id = trace_id.to_string();
    }

    /// Check if DATAGRAM extension is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Update peer's maximum datagram frame size from transport parameters.
    pub fn set_peer_max_datagram_frame_size(&mut self, size: u64) {
        self.peer_max_datagram_frame_size = size;
        self.enabled = size > 0;

        // Drain the queue and generate drop events.
        if !self.enabled {
            for (_, mut queue) in std::mem::take(&mut self.outgoing_queue) {
                while let Some(item) = queue.pop_front() {
                    self.events
                        .borrow_mut()
                        .add(Event::DatagramSenderDrop(item.id));
                }
            }
            self.total_outgoing_size = 0;
        }
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

    /// Queue a datagram for sending with the specified parameters.
    ///
    /// This method adds a datagram to the outgoing priority queue. The datagram will
    /// be transmitted according to its priority level, with automatic handling of
    /// expiration and memory management.
    ///
    /// # Arguments
    /// * `data` - The datagram payload to send
    /// * `params` - Sending parameters including priority and optional expiration
    ///
    /// # Returns
    /// * `Ok(datagram_id)` - Unique ID for the queued datagram
    /// * `Err(DatagramDisabled)` - DATAGRAM extension is not enabled
    /// * `Err(DatagramTooLarge)` - Datagram exceeds peer's or local limits
    ///
    /// # Priority Handling
    /// Lower priority values have higher precedence (0 is highest priority).
    /// Datagrams are organized in a BTreeMap by priority, ensuring higher
    /// priority items are transmitted first.
    ///
    /// # Memory Management  
    /// If adding this datagram would exceed memory limits, lower priority
    /// datagrams will be automatically dropped to make space.
    ///
    /// # Examples
    /// ```rust,ignore
    /// // Send high priority datagram with 5 second expiration
    /// let params = SendDatagramParams::with_priority_and_expiration(0, 5000);
    /// let id = manager.send_datagram(data, params)?;
    ///
    /// // Send normal priority datagram (no expiration)
    /// let params = SendDatagramParams::with_priority(127);
    /// let id = manager.send_datagram(data, params)?;
    /// ```
    pub fn send_datagram(&mut self, data: Bytes, params: SendDatagramParams) -> Result<u64> {
        debug!(
            "{} DatagramManager::send_datagram called, enabled: {}, data len: {}, peer_max: {}, total size: {}, priority: {}, expiration: {:?}",
            self.trace_id,
            self.enabled,
            data.len(),
            self.peer_max_datagram_frame_size,
            self.total_outgoing_size,
            params.priority,
            params.expiration_ms
        );
        if !self.is_enabled() {
            return Err(Error::DatagramDisabled);
        }

        if data.len() as u64 > self.peer_max_datagram_frame_size {
            return Err(Error::DatagramTooLarge);
        }

        let item_size = data.len();

        // Check if this single item exceeds the total queue capacity
        if item_size > self.max_outgoing_size {
            let datagram_id = self.next_send_datagram_id;
            self.next_send_datagram_id += 1;
            self.events
                .borrow_mut()
                .add(Event::DatagramSenderDrop(datagram_id));
            return Err(Error::DatagramTooLarge);
        }

        // Make space if needed by dropping oldest items
        self.make_space_for(item_size);

        let datagram_id = self.next_send_datagram_id;

        // Calculate absolute expiration time
        let expires_at = params
            .expiration_ms
            .map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms));

        let item = DatagramItem {
            data,
            with_length: true,
            queued_at: std::time::Instant::now(),
            id: datagram_id,
            priority: params.priority,
            expires_at,
        };

        // Add to the appropriate priority queue
        self.outgoing_queue
            .entry(params.priority)
            .or_insert_with(VecDeque::new)
            .push_back(item);

        self.total_outgoing_size += item_size;
        self.next_send_datagram_id += 1;

        debug!(
            "{} Datagram queued successfully with priority {}, new total size: {} ",
            self.trace_id, params.priority, self.total_outgoing_size
        );

        Ok(datagram_id)
    }

    /// Convenience method for sending datagram with priority only (for backward compatibility).
    pub fn send_datagram_with_priority(&mut self, data: Bytes, priority: u8) -> Result<u64> {
        self.send_datagram(data, SendDatagramParams::with_priority(priority))
    }

    /// Make space for a new item by dropping oldest items from lowest priority queues first.
    fn make_space_for(&mut self, needed_size: usize) {
        while self.total_outgoing_size + needed_size > self.max_outgoing_size {
            let mut removed_item = None;

            // Find the lowest priority (highest number) queue that has items
            // Iterate in reverse order to start with highest priority numbers
            let priorities: Vec<u8> = self.outgoing_queue.keys().cloned().collect();
            for priority in priorities.iter().rev() {
                if let Some(queue) = self.outgoing_queue.get_mut(priority) {
                    if let Some(item) = queue.pop_front() {
                        self.total_outgoing_size =
                            self.total_outgoing_size.saturating_sub(item.memory_size());
                        self.events
                            .borrow_mut()
                            .add(Event::DatagramSenderDrop(item.id));
                        removed_item = Some(());
                        break;
                    }
                }
            }

            // Remove empty queues
            self.outgoing_queue.retain(|_, queue| !queue.is_empty());

            // If no item was removed, we can't make more space
            if removed_item.is_none() {
                break;
            }
        }
    }

    /// Used to check the left space if can write the datagram frame
    pub fn get_next_send_datagram_info(&self) -> (u8, usize) {
        // Find the item from the highest priority (lowest number) queue
        for (priority, queue) in &self.outgoing_queue {
            if let Some(item) = queue.front() {
                return (*priority, item.data.len());
            }
        }
        (255, usize::MAX)
    }

    /// Get the next datagram ready for transmission.
    ///
    /// This method retrieves the highest priority datagram that is ready for transmission,
    /// automatically handling expiration cleanup and priority ordering.
    ///
    /// # Returns
    /// * `Some(DatagramItem)` - The next datagram to transmit
    /// * `None` - No datagrams available (queue empty or all expired)
    ///
    /// # Behavior
    /// * Datagrams are returned in priority order (lowest priority number first)
    /// * Expired datagrams are automatically dropped and events are generated
    /// * Within the same priority level, FIFO order is maintained
    /// * Empty priority queues are automatically cleaned up
    /// * Statistics (sent_count, sent_bytes) are updated when a datagram is returned
    ///
    /// # Expiration Handling
    /// The method performs comprehensive expiration cleanup:
    /// 1. Removes expired items from the front of each queue
    /// 2. Continues checking until a valid (non-expired) item is found
    /// 3. Generates drop events for all expired items
    /// 4. Returns `None` if all remaining items are expired
    ///
    /// # Examples
    /// ```rust,ignore
    /// while let Some(datagram) = manager.next_send_datagram() {
    ///     // Send the datagram over the network
    ///     send_datagram_frame(&datagram.data);
    /// }
    /// ```
    pub fn next_send_datagram(&mut self) -> Option<DatagramItem> {
        debug!(
            "{} DatagramManager::next_send_datagram called, total size: {}",
            self.trace_id, self.total_outgoing_size
        );

        loop {
            // Find the highest priority (lowest number) queue that has items
            let mut item_to_return = None;
            let mut expired_items = Vec::new();
            let mut priorities_to_cleanup = Vec::new();

            for (priority, queue) in &mut self.outgoing_queue {
                // Remove expired items from the front of the queue
                while let Some(front_item) = queue.front() {
                    if front_item.is_expired() {
                        let expired_item = queue.pop_front().unwrap();
                        self.total_outgoing_size = self
                            .total_outgoing_size
                            .saturating_sub(expired_item.memory_size());
                        expired_items.push(expired_item.id);
                    } else {
                        break;
                    }
                }

                // Check if queue is empty after cleanup and mark for removal
                if queue.is_empty() {
                    priorities_to_cleanup.push(*priority);
                    continue;
                }

                // Try to get a non-expired item
                if let Some(item) = queue.pop_front() {
                    if item.is_expired() {
                        // This item expired between checks, drop it
                        self.total_outgoing_size =
                            self.total_outgoing_size.saturating_sub(item.memory_size());
                        expired_items.push(item.id);

                        // Check if queue is empty after removing this item
                        if queue.is_empty() {
                            priorities_to_cleanup.push(*priority);
                        }
                    } else {
                        // Found a valid item
                        self.sent_count += 1;
                        self.sent_bytes += item.data.len() as u64;
                        self.total_outgoing_size =
                            self.total_outgoing_size.saturating_sub(item.memory_size());

                        debug!(
                            "{} Popped datagram from priority {} queue, data len: {}, remaining total size: {}",
                            self.trace_id,
                            priority,
                            item.data.len(),
                            self.total_outgoing_size
                        );

                        item_to_return = Some(item);
                        if queue.is_empty() {
                            priorities_to_cleanup.push(*priority);
                        }
                        break;
                    }
                }
            }

            // Generate drop events for expired items
            for expired_id in expired_items {
                debug!(
                    "{} Dropping expired datagram with ID: {}",
                    self.trace_id, expired_id
                );
                self.events
                    .borrow_mut()
                    .add(Event::DatagramTimeExpiredDrop(expired_id));
            }

            // Remove empty queues
            for priority in priorities_to_cleanup {
                self.outgoing_queue.remove(&priority);
            }

            // If we found a valid item, return it
            if item_to_return.is_some() {
                return item_to_return;
            }

            // If no valid item found and no queues left, break
            if self.outgoing_queue.is_empty() {
                debug!("{} No datagrams in queue to send", self.trace_id);
                return None;
            }

            // If there are still queues but all items were expired, continue the loop
            // This should eventually terminate when all expired items are cleaned up
        }
    }

    /// Check if there are datagrams ready for transmission.
    pub fn has_sendable_datagrams(&self) -> bool {
        let has_sendable = !self.outgoing_queue.is_empty();
        debug!(
            "{} DatagramManager::has_sendable_datagrams called, total size: {}, result: {}",
            self.trace_id, self.total_outgoing_size, has_sendable
        );
        has_sendable
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
        let datagram_id = self.next_recv_datagram_id;
        let item = DatagramItem {
            data,
            with_length: len.is_some(),
            queued_at: std::time::Instant::now(),
            id: self.next_recv_datagram_id,
            priority: 0,      // Received datagrams don't have priority
            expires_at: None, // Received datagrams don't expire
        };
        self.next_recv_datagram_id += 1;
        self.received_count += 1;
        self.received_bytes += item.data.len() as u64;

        self.incoming_queue.enqueue(item)?;
        Ok(())
    }

    /// Receive the next datagram from the incoming queue.
    ///
    /// Returns `None` if no datagrams are available for consumption.
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        self.incoming_queue.dequeue().map(|item| item.data)
    }

    /// Check if there are datagrams ready for consumption.
    pub fn has_readable_datagrams(&self) -> bool {
        !self.incoming_queue.is_empty()
    }

    /// Get the number of datagrams waiting to be sent.
    pub fn outgoing_count(&self) -> usize {
        self.outgoing_queue.values().map(|queue| queue.len()).sum()
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
            outgoing_queue_size: self.outgoing_count(),
            incoming_queue_size: self.incoming_queue.len(),
        }
    }

    /// Creates a new DatagramManager with specified memory limits for its queues.
    pub fn with_limits(outgoing_max_bytes: usize, incoming_max_bytes: usize) -> Self {
        let events = Rc::new(RefCell::new(EventQueue::default()));

        Self {
            outgoing_queue: BTreeMap::new(),
            total_outgoing_size: 0,
            max_outgoing_size: outgoing_max_bytes * DATAGRAM_QUEUE_GRANULARITY_BYTES,
            incoming_queue: DatagramQueue::new(incoming_max_bytes, events.clone()),
            peer_max_datagram_frame_size: 0,
            local_max_datagram_frame_size: 0,
            enabled: false,
            sent_count: 0,
            received_count: 0,
            sent_bytes: 0,
            received_bytes: 0,
            trace_id: String::new(),
            next_send_datagram_id: 1,
            next_recv_datagram_id: 1,
            events,
        }
    }

    /// Sets a new memory limit for the outgoing datagram queue.
    pub fn set_outgoing_queue_limit(&mut self, new_max_bytes: usize) -> AdjustResult {
        let new_size = new_max_bytes * DATAGRAM_QUEUE_GRANULARITY_BYTES;
        if new_size < self.total_outgoing_size {
            return AdjustResult::TooSmall;
        } else if new_size < self.max_outgoing_size {
            self.max_outgoing_size = new_size;
            return AdjustResult::Normal;
        }
        self.max_outgoing_size = new_size;
        AdjustResult::Success
    }

    /// Sets a new memory limit for the incoming datagram queue.
    pub fn set_incoming_queue_limit(&mut self, new_max_bytes: usize) -> AdjustResult {
        self.incoming_queue.set_max_size(new_max_bytes)
    }

    /// Clear all queued datagrams.
    pub fn clear_all_buffer(&mut self) {
        self.clear_sender_buffer();
        self.incoming_queue.clear();
    }

    pub fn clear_sender_buffer(&mut self) {
        self.outgoing_queue.clear();
        self.total_outgoing_size = 0;
    }

    pub fn clear_receiver_buffer(&mut self) {
        self.incoming_queue.clear();
    }

    /// Clear all datagrams in the specified priority queue.
    ///
    /// This method removes all datagrams from a specific priority level,
    /// updates memory accounting, and generates appropriate drop events.
    /// Useful for clearing specific priority levels during congestion control
    /// or when certain types of data become obsolete.
    ///
    /// # Arguments
    /// * `priority` - The priority level to clear (0-255)
    ///
    /// # Returns
    /// The number of datagrams that were cleared from the specified priority level.
    /// Returns 0 if the priority level had no queued datagrams.
    ///
    /// # Side Effects
    /// * Updates `total_outgoing_size` to reflect removed data
    /// * Generates `DatagramSenderDrop` events for each removed datagram
    /// * Removes the entire priority queue if it becomes empty
    ///
    /// # Examples
    /// ```rust,ignore
    /// // Clear all low priority datagrams during congestion
    /// let dropped_count = manager.clear_priority_queue(200);
    /// println!("Dropped {} low priority datagrams", dropped_count);
    /// ```
    pub fn clear_priority_queue(&mut self, priority: u8) -> usize {
        if let Some(queue) = self.outgoing_queue.remove(&priority) {
            let count = queue.len();
            // Calculate the total size of removed items
            let removed_size: usize = queue.iter().map(|item| item.memory_size()).sum();
            self.total_outgoing_size = self.total_outgoing_size.saturating_sub(removed_size);

            // Generate drop events for all removed items
            for item in queue {
                self.events
                    .borrow_mut()
                    .add(Event::DatagramSenderDrop(item.id));
            }

            count
        } else {
            0
        }
    }

    pub fn max_outgoing_size(&self) -> usize {
        self.max_outgoing_size
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
#[deprecated(note = "Use DatagramManager instead")]
pub type DataCenter = DatagramManager;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Event; // Make sure to import Event for testing queue drops

    /// Test basic creation and initial state of the DatagramManager.
    ///
    /// Verifies that a new DatagramManager starts in the correct disabled state
    /// with appropriate default values for all configuration parameters.
    #[test]
    fn datagram_manager_new() {
        let manager = DatagramManager::new();
        assert!(!manager.is_enabled(), "Should be disabled by default");
        assert_eq!(
            manager.peer_max_datagram_frame_size(),
            0,
            "Peer max size should be 0"
        );
        assert_eq!(
            manager.local_max_datagram_frame_size(),
            0,
            "Local max size should be 0"
        );
        assert!(
            !manager.has_sendable_datagrams(),
            "Outgoing queue should be empty"
        );
        assert!(
            !manager.has_readable_datagrams(),
            "Incoming queue should be empty"
        );
    }

    /// Test enabling and disabling the DATAGRAM extension.
    ///
    /// Verifies that the manager correctly enables when peer capabilities are set
    /// and properly cleans up queued datagrams when disabled.
    #[test]
    fn datagram_enable_disable() {
        let mut manager = DatagramManager::new();

        // Initially disabled
        assert!(!manager.is_enabled());

        // Enable by setting peer's max datagram frame size
        manager.set_peer_max_datagram_frame_size(1200);
        assert!(
            manager.is_enabled(),
            "Should be enabled after setting peer max size"
        );
        assert_eq!(manager.peer_max_datagram_frame_size(), 1200);

        // Queues should be cleared when disabled
        manager.set_peer_max_datagram_frame_size(1200);
        manager
            .send_datagram(
                Bytes::from_static(b"data"),
                SendDatagramParams::with_priority(0),
            )
            .unwrap();
        assert_eq!(manager.outgoing_count(), 1);
    }

    /// Test the basic send and receive workflow.
    ///
    /// Validates the complete lifecycle of datagram transmission including
    /// queueing, retrieval for transmission, receiving, and application consumption.
    #[test]
    fn datagram_send_and_receive_workflow() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(1024);
        manager.set_local_max_datagram_frame_size(1024);

        // 1. Send a datagram
        let data_to_send = Bytes::from_static(b"Hello, DATAGRAM!");
        let send_id = manager
            .send_datagram(data_to_send.clone(), SendDatagramParams::with_priority(0))
            .unwrap();
        assert_eq!(send_id, 1, "First sent datagram should have ID 1");
        assert!(
            manager.has_sendable_datagrams(),
            "Should have a sendable datagram"
        );
        assert_eq!(manager.outgoing_count(), 1);

        // 2. Get the datagram for transmission
        let item_to_send = manager.next_send_datagram().unwrap();
        assert_eq!(item_to_send.data, data_to_send);
        assert!(
            item_to_send.with_length,
            "with_length should be true by default"
        );
        assert_eq!(item_to_send.id, 1);
        assert!(
            !manager.has_sendable_datagrams(),
            "Queue should be empty after taking item"
        );

        // 3. Simulate receiving a datagram frame from the peer
        let data_to_receive = Bytes::from_static(b"Reply from peer");
        manager
            .on_datagram_frame_received(Some(data_to_receive.len() as u64), data_to_receive.clone())
            .unwrap();
        assert!(
            manager.has_readable_datagrams(),
            "Should have a readable datagram"
        );
        assert_eq!(manager.incoming_count(), 1);

        // 4. Application reads the received datagram
        let received_data = manager.recv_datagram().unwrap();
        assert_eq!(received_data, data_to_receive);
        assert!(
            !manager.has_readable_datagrams(),
            "Incoming queue should be empty after reading"
        );
    }

    // Test that receiving a frame larger than the local limit results in a protocol violation.
    #[test]
    fn datagram_receive_too_large_is_protocol_violation() {
        let mut manager = DatagramManager::new();

        let large_data = Bytes::from(vec![0; 101]);
        let result = manager.on_datagram_frame_received(Some(101), large_data);
        assert!(
            matches!(result, Err(Error::ProtocolViolation)),
            "Should be a protocol violation for datagram disabled"
        );

        manager.set_local_max_datagram_frame_size(100); // Set a small limit

        let large_data = Bytes::from(vec![0; 101]);
        let result = manager.on_datagram_frame_received(Some(101), large_data);
        assert!(
            matches!(result, Err(Error::ProtocolViolation)),
            "Should be a protocol violation for oversized frame"
        );
    }

    // Test statistics tracking.
    #[test]
    fn datagram_stats_are_tracked_correctly() {
        let mut manager = DatagramManager::with_limits(1, 1); // 1KB limits
        manager.set_peer_max_datagram_frame_size(1024);
        manager.set_local_max_datagram_frame_size(1024);

        let data1 = Bytes::from_static(b"Hello");
        let data2 = Bytes::from_static(b"World!");

        // Send two datagrams
        manager
            .send_datagram(data1.clone(), SendDatagramParams::with_priority(0))
            .unwrap();
        manager
            .send_datagram(data2.clone(), SendDatagramParams::with_priority(0))
            .unwrap();

        // Take them from the queue for sending
        manager.next_send_datagram();
        manager.next_send_datagram();

        // Receive two datagrams
        manager
            .on_datagram_frame_received(None, data1.clone())
            .unwrap();
        manager
            .on_datagram_frame_received(None, data2.clone())
            .unwrap();

        let stats = manager.stats();
        assert_eq!(stats.sent_count, 2);
        assert_eq!(stats.received_count, 2);
        assert_eq!(stats.sent_bytes, 11); // 5 + 6
        assert_eq!(stats.received_bytes, 11); // 5 + 6
        assert_eq!(stats.outgoing_queue_size, 0);
        assert_eq!(stats.incoming_queue_size, 2);

        // Read one datagram
        manager.recv_datagram();
        let stats = manager.stats();
        assert_eq!(stats.incoming_queue_size, 1);
    }

    // Test queue memory limit enforcement and dropping behavior for the sender.
    #[test]
    fn datagram_sender_queue_drops_oldest_when_full() {
        // Create a manager with a very small queue limit (e.g., 20 bytes).
        let mut manager = DatagramManager::with_limits(1, 1); // Use KB, so this is 1024 bytes
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();
        let data1 = Bytes::from(vec![1; 124]);
        let data2 = Bytes::from(vec![2; 1000]);
        let data3 = Bytes::from(vec![3; 24]);

        // Enqueue first two items, filling the queue (124 + 1000 = 1124 bytes).
        let id1 = manager
            .send_datagram(data1, SendDatagramParams::with_priority(0))
            .unwrap();
        let id2 = manager
            .send_datagram(data2, SendDatagramParams::with_priority(0))
            .unwrap();
        assert_eq!(manager.total_outgoing_size, 1000);
        assert_eq!(manager.outgoing_count(), 1);

        // Enqueue a third item. This should cause the first item to be dropped.
        let id3 = manager
            .send_datagram(data3, SendDatagramParams::with_priority(0))
            .unwrap();
        assert_eq!(manager.total_outgoing_size, 1024, "1000(data2) + 24(data3)");
        assert_eq!(manager.outgoing_count(), 2);

        // Check that the correct drop event was generated.
        let event = manager.events.borrow_mut().poll();
        assert!(
            matches!(event, Some(Event::DatagramSenderDrop(id)) if id == id1),
            "Event for dropped datagram ID 1 should be generated"
        );

        // Verify the remaining items in the queue are the second and third.
        let item2 = manager.next_send_datagram().unwrap();
        assert_eq!(item2.id, id2);
        let item3 = manager.next_send_datagram().unwrap();
        assert_eq!(item3.id, id3);
    }

    // Test that the receiver queue correctly drops the oldest datagrams when it reaches its memory limit.
    #[test]
    fn datagram_receiver_queue_drops_oldest_when_full() {
        // Create a manager with a 1 KB limit for the incoming queue.
        // The `with_limits` constructor takes the size in KB.
        let mut manager = DatagramManager::with_limits(1, 1);
        manager.events.borrow_mut().enable();
        // We must set a local max frame size to allow receiving frames.
        manager.set_local_max_datagram_frame_size(2048);

        // Prepare three datagrams. The first two will fill the queue.
        let data1 = Bytes::from(vec![1; 512]); // 512 bytes
        let data2 = Bytes::from(vec![2; 512]); // 512 bytes
        let data3 = Bytes::from(vec![3; 100]); // 100 bytes

        // Simulate receiving the first two datagrams.
        // The queue is now full (512 + 512 = 1024 bytes).
        manager
            .on_datagram_frame_received(None, data1.clone())
            .unwrap();
        manager
            .on_datagram_frame_received(None, data2.clone())
            .unwrap();

        // Verify the state of the incoming queue.
        assert_eq!(
            manager.incoming_queue.current_size(),
            1024,
            "Queue should be full at 1024 bytes"
        );
        assert_eq!(manager.incoming_count(), 2, "Queue should contain 2 items");

        // Simulate receiving a third datagram. This should trigger a drop.
        // The queue will drop `data1` (512 bytes) to make space for `data3` (100 bytes).
        manager
            .on_datagram_frame_received(None, data3.clone())
            .unwrap();

        // Verify the new state of the incoming queue.
        // Expected size = (1024 - 512) + 100 = 612 bytes.
        assert_eq!(
            manager.incoming_queue.current_size(),
            612,
            "Queue size should be 512 (data2) + 100 (data3)"
        );
        assert_eq!(
            manager.incoming_count(),
            2,
            "Queue should still contain 2 items"
        );
        assert_eq!(
            !manager.events.borrow().is_empty(),
            true,
            "There should be events in the queue"
        );
        // Check that the correct drop event was generated for the first datagram.
        // The first received datagram has an ID of 1.
        let event = manager.events.borrow_mut().poll();
        assert!(
            matches!(event, Some(Event::DatagramReceiverDrop(id)) if id == 1),
            "Event for dropped receiver datagram ID 1 should be generated"
        );

        // Verify that the remaining items in the queue are the second and third datagrams.
        let received_item2 = manager.recv_datagram().unwrap();
        assert_eq!(
            received_item2, data2,
            "The second datagram should be in the queue"
        );

        let received_item3 = manager.recv_datagram().unwrap();
        assert_eq!(
            received_item3, data3,
            "The third datagram should be in the queue"
        );

        // The queue should now be empty.
        assert!(
            manager.recv_datagram().is_none(),
            "Queue should be empty after reading all items"
        );
    }

    // Test adjusting queue limits dynamically.
    #[test]
    fn datagram_queue_limit_adjustment() {
        let mut manager = DatagramManager::with_limits(1, 1); // 1KB limit
        manager.set_peer_max_datagram_frame_size(1024);
        manager
            .send_datagram(
                Bytes::from(vec![0; 500]),
                SendDatagramParams::with_priority(0),
            )
            .unwrap();
        assert_eq!(manager.total_outgoing_size, 500);

        // Adjust to a larger size
        assert!(matches!(
            manager.set_outgoing_queue_limit(2),
            AdjustResult::Success
        ));
        assert_eq!(manager.max_outgoing_size, 2048);

        // Adjust to a smaller, but still valid, size
        assert!(matches!(
            manager.set_outgoing_queue_limit(1),
            AdjustResult::Normal
        ));
        assert_eq!(manager.max_outgoing_size, 1024);

        // Attempt to adjust to a size smaller than current usage
        assert!(matches!(
            manager.set_outgoing_queue_limit(0),
            AdjustResult::TooSmall
        ));
        assert_eq!(
            manager.max_outgoing_size, 1024,
            "Max size should not change on failure"
        );
    }

    // Test clearing the buffers.
    #[test]
    fn datagram_clear_buffers() {
        let mut manager = DatagramManager::with_limits(1, 1);
        manager.set_peer_max_datagram_frame_size(1024);
        manager.set_local_max_datagram_frame_size(1024);

        manager
            .send_datagram(Bytes::from_static(b"out"), SendDatagramParams::default())
            .unwrap();
        manager
            .on_datagram_frame_received(None, Bytes::from_static(b"in"))
            .unwrap();

        assert_eq!(manager.outgoing_count(), 1);
        assert_eq!(manager.incoming_count(), 1);

        manager.clear_all_buffer();

        assert_eq!(manager.outgoing_count(), 0);
        assert_eq!(manager.incoming_count(), 0);
        assert_eq!(manager.total_outgoing_size, 0);
        assert_eq!(manager.incoming_queue.current_size(), 0);
    }

    // Test individual buffer clearing methods
    #[test]
    fn datagram_clear_individual_buffers() {
        let mut manager = DatagramManager::with_limits(1, 1);
        manager.set_peer_max_datagram_frame_size(1024);
        manager.set_local_max_datagram_frame_size(1024);

        // Add data to both queues
        manager
            .send_datagram(Bytes::from_static(b"out"), SendDatagramParams::default())
            .unwrap();
        manager
            .on_datagram_frame_received(None, Bytes::from_static(b"in"))
            .unwrap();

        assert_eq!(manager.outgoing_count(), 1);
        assert_eq!(manager.incoming_count(), 1);

        // Test clearing only sender buffer
        manager.clear_sender_buffer();
        assert_eq!(manager.outgoing_count(), 0);
        assert_eq!(manager.incoming_count(), 1);
        assert_eq!(manager.total_outgoing_size, 0);

        // Add data back to sender
        manager
            .send_datagram(Bytes::from_static(b"out2"), SendDatagramParams::default())
            .unwrap();
        assert_eq!(manager.outgoing_count(), 1);

        // Test clearing only receiver buffer
        manager.clear_receiver_buffer();
        assert_eq!(manager.outgoing_count(), 1);
        assert_eq!(manager.incoming_count(), 0);
        assert_eq!(manager.incoming_queue.current_size(), 0);
    }

    /// Test clearing specific priority queues.
    ///
    /// Validates that the `clear_priority_queue` method correctly removes only
    /// datagrams from the specified priority level while leaving other priorities
    /// intact, and properly generates drop events for monitoring.
    #[test]
    fn datagram_clear_priority_queue() {
        let mut manager = DatagramManager::with_limits(2, 1);
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Add datagrams with different priorities
        let id1 = manager
            .send_datagram(
                Bytes::from_static(b"high_priority"),
                SendDatagramParams::with_priority(0),
            )
            .unwrap();
        let id2 = manager
            .send_datagram(
                Bytes::from_static(b"medium_priority"),
                SendDatagramParams::with_priority(1),
            )
            .unwrap();
        let id3 = manager
            .send_datagram(
                Bytes::from_static(b"low_priority1"),
                SendDatagramParams::with_priority(2),
            )
            .unwrap();
        let id4 = manager
            .send_datagram(
                Bytes::from_static(b"low_priority2"),
                SendDatagramParams::with_priority(2),
            )
            .unwrap();

        assert_eq!(manager.outgoing_count(), 4);
        let initial_size = manager.total_outgoing_size;

        // Clear priority 2 queue (should remove 2 items)
        let cleared_count = manager.clear_priority_queue(2);
        assert_eq!(cleared_count, 2);
        assert_eq!(manager.outgoing_count(), 2);

        // Verify the total size was updated correctly
        let expected_removed_size = "low_priority1".len() + "low_priority2".len();
        assert_eq!(
            manager.total_outgoing_size,
            initial_size - expected_removed_size
        );

        // Verify drop events were generated
        let mut dropped_ids = std::collections::HashSet::new();
        while let Some(event) = manager.events.borrow_mut().poll() {
            if let Event::DatagramSenderDrop(id) = event {
                dropped_ids.insert(id);
            }
        }
        assert_eq!(dropped_ids.len(), 2);
        assert!(dropped_ids.contains(&id3));
        assert!(dropped_ids.contains(&id4));

        // Verify remaining items are correct
        let item1 = manager.next_send_datagram().unwrap();
        assert_eq!(item1.id, id1);
        assert_eq!(item1.priority, 0);

        let item2 = manager.next_send_datagram().unwrap();
        assert_eq!(item2.id, id2);
        assert_eq!(item2.priority, 1);

        assert!(manager.next_send_datagram().is_none());

        // Test clearing non-existent priority
        let cleared_count = manager.clear_priority_queue(99);
        assert_eq!(cleared_count, 0);
    }

    // Test set_trace_id functionality
    #[test]
    fn datagram_set_trace_id() {
        let mut manager = DatagramManager::new();
        manager.set_trace_id("test-connection-123");
        // Note: trace_id is used in debug logs, so we can't directly test it
        // but we can ensure the method doesn't panic
        assert!(!manager.trace_id.is_empty());
    }

    // Test DatagramItem memory_size calculation
    #[test]
    fn datagram_item_memory_size() {
        let small_item = DatagramItem {
            data: Bytes::from_static(b"small"),
            with_length: true,
            queued_at: Instant::now(),
            id: 1,
            priority: 0,
            expires_at: None,
        };
        assert_eq!(small_item.memory_size(), 5); // "small".len()

        let large_item = DatagramItem {
            data: Bytes::from(vec![0; 1024]),
            with_length: false,
            queued_at: Instant::now(),
            id: 2,
            priority: 0,
            expires_at: None,
        };
        assert_eq!(large_item.memory_size(), 1024);
    }

    // Test edge case: empty datagram
    #[test]
    fn datagram_empty_data() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(1024);
        manager.set_local_max_datagram_frame_size(1024);

        // Send empty datagram
        let empty_data = Bytes::new();
        let send_id = manager
            .send_datagram(empty_data.clone(), SendDatagramParams::default())
            .unwrap();
        assert_eq!(send_id, 1);

        let item = manager.next_send_datagram().unwrap();
        assert_eq!(item.data.len(), 0);
        assert_eq!(item.memory_size(), 0);

        // Receive empty datagram
        manager
            .on_datagram_frame_received(Some(0), empty_data.clone())
            .unwrap();
        assert_eq!(manager.incoming_count(), 1);
        let received = manager.recv_datagram().unwrap();
        assert_eq!(received.len(), 0);
    }

    // Test queue behavior when at exact capacity
    #[test]
    fn datagram_queue_exact_capacity() {
        let mut manager = DatagramManager::with_limits(1, 1); // 1KB = 1024 bytes
        manager.set_peer_max_datagram_frame_size(1024);

        // Fill exactly to capacity
        let data = Bytes::from(vec![0; 1024]);
        manager
            .send_datagram(data, SendDatagramParams::default())
            .unwrap();
        assert_eq!(manager.total_outgoing_size, 1024);
        assert_eq!(manager.outgoing_count(), 1);

        // Try to add one more byte - should cause the first item to be dropped
        let small_data = Bytes::from(vec![1; 1]);
        manager
            .send_datagram(small_data, SendDatagramParams::default())
            .unwrap();
        assert_eq!(manager.total_outgoing_size, 1);
        assert_eq!(manager.outgoing_count(), 1);
    }

    /// Test that sending a datagram fails immediately if the DATAGRAM extension is disabled.
    #[test]
    fn datagram_send_fails_when_disabled() {
        let mut manager = DatagramManager::new();
        // Don't enable the datagram extension (peer_max_datagram_frame_size = 0)

        let data = Bytes::from_static(b"test");
        let result = manager.send_datagram(data, SendDatagramParams::default());

        assert!(
            matches!(result, Err(Error::DatagramDisabled)),
            "Should fail with DatagramDisabled when extension is not enabled"
        );
    }

    /// Test that sending a datagram larger than the entire local queue capacity fails.
    #[test]
    fn datagram_send_fails_if_larger_than_queue_capacity() {
        let mut manager = DatagramManager::with_limits(1, 1); // 1KB limit
        manager.set_peer_max_datagram_frame_size(2048); // Peer allows larger frames
        manager.events.borrow_mut().enable();

        let oversized_data = Bytes::from(vec![0; 1025]); // Exceeds local queue capacity
        let result = manager.send_datagram(oversized_data, SendDatagramParams::default());

        assert!(
            matches!(result, Err(Error::DatagramTooLarge)),
            "Should fail with DatagramTooLarge when data exceeds queue capacity"
        );

        // Check that a drop event was generated
        let event = manager.events.borrow_mut().poll();
        assert!(
            matches!(event, Some(Event::DatagramSenderDrop(1))),
            "Should generate sender drop event for oversized datagram"
        );
    }

    /// Test expiration handling with items expiring between different checks.
    ///
    /// This test covers the case where an item expires between the front() check
    /// and the pop_front() operation, testing the double expiration check logic.
    #[test]
    fn datagram_expiration_between_checks() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Send a datagram with very short expiration (1ms)
        let short_expiry_data = Bytes::from_static(b"expires_soon");
        let id = manager
            .send_datagram(
                short_expiry_data,
                SendDatagramParams::with_priority_and_expiration(0, 1),
            )
            .unwrap();

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_millis(5));

        // Try to get the datagram - it should be expired and dropped
        let result = manager.next_send_datagram();
        assert!(result.is_none(), "Should return None for expired datagram");

        // Check that a drop event was generated
        let event = manager.events.borrow_mut().poll();
        assert!(
            matches!(event, Some(Event::DatagramTimeExpiredDrop(expired_id)) if expired_id == id),
            "Should generate time expired drop event"
        );
    }

    /// Test DatagramQueue's AdjustResult scenarios for incoming queue.
    ///
    /// Validates all possible outcomes when adjusting the incoming queue size,
    /// including edge cases where current size equals the new maximum.
    #[test]
    fn datagram_incoming_queue_adjust_scenarios() {
        let mut manager = DatagramManager::with_limits(1, 1); // 1KB incoming limit
        manager.set_local_max_datagram_frame_size(1024);

        // Add some data to test TooSmall scenario
        manager
            .on_datagram_frame_received(None, Bytes::from(vec![0; 512]))
            .unwrap();
        assert_eq!(manager.incoming_queue.current_size(), 512);

        // Test Success (increase size)
        let result = manager.set_incoming_queue_limit(2);
        assert!(matches!(result, AdjustResult::Success));

        // Test Normal (decrease but still larger than current)
        let result = manager.set_incoming_queue_limit(1);
        assert!(matches!(result, AdjustResult::Normal));

        // Test TooSmall (smaller than current usage)
        let result = manager.set_incoming_queue_limit(0);
        assert!(matches!(result, AdjustResult::TooSmall));
    }

    /// Test the max_outgoing_size() getter method.
    ///
    /// Ensures the getter returns the correct maximum outgoing queue size
    /// and that it updates when the limit is changed.
    #[test]
    fn datagram_max_outgoing_size_getter() {
        let manager = DatagramManager::with_limits(5, 3); // 5KB outgoing, 3KB incoming
        assert_eq!(
            manager.max_outgoing_size(),
            5 * DATAGRAM_QUEUE_GRANULARITY_BYTES
        );

        let mut manager = DatagramManager::new();
        assert_eq!(
            manager.max_outgoing_size(),
            DEFAULT_QUEUE_SIZE_KB * DATAGRAM_QUEUE_GRANULARITY_BYTES
        );

        // Change the limit and verify getter returns new value
        manager.set_outgoing_queue_limit(10);
        assert_eq!(
            manager.max_outgoing_size(),
            10 * DATAGRAM_QUEUE_GRANULARITY_BYTES
        );
    }

    /// Test that set_enabled() method works correctly.
    ///
    /// Verifies that the enabled state can be manually controlled independently
    /// of peer frame size settings.
    #[test]
    fn datagram_manual_enable_disable() {
        let mut manager = DatagramManager::new();
        assert!(!manager.is_enabled());

        // Manually enable
        manager.set_enabled(true);
        assert!(manager.is_enabled());

        // Manually disable
        manager.set_enabled(false);
        assert!(!manager.is_enabled());

        // Set peer max frame size should still enable
        manager.set_peer_max_datagram_frame_size(1024);
        assert!(manager.is_enabled());

        // Manual disable should override
        manager.set_peer_max_datagram_frame_size(0);
        assert!(!manager.is_enabled());
    }

    /// Test queue granularity constant validation.
    ///
    /// Ensures that queue size calculations use the correct granularity
    /// and that limits are properly converted from KB to bytes.
    #[test]
    fn datagram_queue_granularity() {
        let manager = DatagramManager::with_limits(2, 3); // 2KB out, 3KB in
        assert_eq!(
            manager.max_outgoing_size,
            2 * DATAGRAM_QUEUE_GRANULARITY_BYTES
        );
        assert_eq!(
            manager.incoming_queue.max_size(),
            3 * DATAGRAM_QUEUE_GRANULARITY_BYTES
        );
        assert_eq!(DATAGRAM_QUEUE_GRANULARITY_BYTES, 1024);
    }

    /// Test multiple datagrams with same content but different IDs.
    ///
    /// Verifies that identical datagram content gets unique IDs for both
    /// sending and receiving, ensuring proper tracking and identification.
    #[test]
    fn datagram_unique_ids() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(1024);
        manager.set_local_max_datagram_frame_size(1024);

        let data = Bytes::from_static(b"same content");

        // Send multiple datagrams with same content
        let id1 = manager
            .send_datagram(data.clone(), SendDatagramParams::default())
            .unwrap();
        let id2 = manager
            .send_datagram(data.clone(), SendDatagramParams::default())
            .unwrap();
        let id3 = manager
            .send_datagram(data.clone(), SendDatagramParams::default())
            .unwrap();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);

        // Verify IDs in dequeued items
        let item1 = manager.next_send_datagram().unwrap();
        let item2 = manager.next_send_datagram().unwrap();
        let item3 = manager.next_send_datagram().unwrap();

        assert_eq!(item1.id, 1);
        assert_eq!(item2.id, 2);
        assert_eq!(item3.id, 3);

        // Receive multiple datagrams
        manager
            .on_datagram_frame_received(None, data.clone())
            .unwrap();
        manager
            .on_datagram_frame_received(None, data.clone())
            .unwrap();

        // Received datagrams should have separate IDs starting from 1
        // (We can't directly access the IDs of received items, but we can check the count)
        assert_eq!(manager.incoming_count(), 2);
    }

    /// Test that sending a datagram larger than the peer's advertised limit fails.
    #[test]
    fn datagram_send_fails_if_larger_than_peer_limit() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(100); // Peer can only accept 100 bytes

        // This datagram is larger than the peer's limit
        let large_data = Bytes::from(vec![0; 101]);
        let result = manager.send_datagram(large_data, SendDatagramParams::default());

        assert!(
            matches!(result, Err(Error::DatagramTooLarge)),
            "Sending should fail with DatagramTooLarge error for oversized datagram"
        );
        assert_eq!(
            manager.outgoing_count(),
            0,
            "Oversized datagram should not be enqueued"
        );
    }

    /// Test that disabling the datagram manager correctly drains the outgoing queue
    /// and generates drop events for each item.
    #[test]
    fn datagram_drains_and_drops_on_disable() {
        let mut manager = DatagramManager::with_limits(1, 1);
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Queue three datagrams
        let id1 = manager
            .send_datagram(Bytes::from_static(b"one"), SendDatagramParams::default())
            .unwrap();
        let id2 = manager
            .send_datagram(Bytes::from_static(b"two"), SendDatagramParams::default())
            .unwrap();
        let id3 = manager
            .send_datagram(Bytes::from_static(b"three"), SendDatagramParams::default())
            .unwrap();
        assert_eq!(manager.outgoing_count(), 3);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);

        // Now, disable datagrams by setting peer's max size to 0
        manager.set_peer_max_datagram_frame_size(0);

        assert!(!manager.is_enabled(), "Manager should be disabled");
        assert_eq!(
            manager.outgoing_count(),
            0,
            "Outgoing queue should be empty after disabling"
        );
        assert_eq!(
            manager.total_outgoing_size, 0,
            "Outgoing queue size should be 0"
        );

        // Verify that drop events were generated for all three items
        let mut dropped_ids = std::collections::HashSet::new();
        while let Some(event) = manager.events.borrow_mut().poll() {
            if let Event::DatagramSenderDrop(id) = event {
                dropped_ids.insert(id);
            }
        }
        assert_eq!(dropped_ids.len(), 3, "There should be 3 drop events");
        assert!(dropped_ids.contains(&id1));
        assert!(dropped_ids.contains(&id2));
        assert!(dropped_ids.contains(&id3));
    }

    /// Test that enqueuing a new item can cause multiple old items to be dropped
    /// if the new item is large.
    #[test]
    fn datagram_queue_drops_multiple_old_items() {
        let mut manager = DatagramManager::with_limits(1, 1); // 1024 bytes limit
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Enqueue three small items
        let id1 = manager
            .send_datagram(Bytes::from(vec![1; 400]), SendDatagramParams::default())
            .unwrap();
        let id2 = manager
            .send_datagram(Bytes::from(vec![2; 400]), SendDatagramParams::default())
            .unwrap();
        let id3 = manager
            .send_datagram(Bytes::from(vec![3; 200]), SendDatagramParams::default())
            .unwrap();
        // Current usage: 400 + 400 + 200 = 1000 bytes. Count: 3
        assert_eq!(manager.total_outgoing_size, 1000);
        assert_eq!(manager.outgoing_count(), 3);

        // Enqueue a large item that requires dropping the first two items
        // Needed space = 800. Current free space = 24.
        // To make space, we need to free 800 - 24 = 776 bytes.
        // Dropping item 1 (400 bytes) is not enough.
        // Dropping item 1 and 2 (400 + 400 = 800 bytes) is enough.
        let data4 = Bytes::from(vec![4; 800]);
        let id4 = manager
            .send_datagram(data4.clone(), SendDatagramParams::default())
            .unwrap();

        // Queue should now contain item 3 (200) and item 4 (800). Total: 1000 bytes.
        assert_eq!(manager.total_outgoing_size, 1000);
        assert_eq!(manager.outgoing_count(), 2);

        // Verify that drop events were generated for item 1 and 2
        let mut dropped_ids = std::collections::HashSet::new();
        while let Some(event) = manager.events.borrow_mut().poll() {
            if let Event::DatagramSenderDrop(id) = event {
                dropped_ids.insert(id);
            }
        }
        assert_eq!(dropped_ids.len(), 2);
        assert!(dropped_ids.contains(&id1));
        assert!(dropped_ids.contains(&id2));

        // Verify the remaining items are correct
        let item3 = manager.next_send_datagram().unwrap();
        assert_eq!(item3.id, id3);
        let item4 = manager.next_send_datagram().unwrap();
        assert_eq!(item4.id, id4);
        assert!(manager.next_send_datagram().is_none());
    }

    /// Test behavior with a zero-sized queue limit.
    #[test]
    fn datagram_zero_sized_queue() {
        // Set a 0 KB limit for the outgoing queue
        let mut manager = DatagramManager::with_limits(0, 1);
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        assert_eq!(manager.max_outgoing_size, 0);

        // Any attempt to send a non-empty datagram should fail
        let result = manager.send_datagram(
            Bytes::from_static(b"non-empty"),
            SendDatagramParams::default(),
        );
        assert!(
            matches!(result, Err(Error::DatagramTooLarge)),
            "Sending to a zero-sized queue should fail"
        );

        // Check for the corresponding drop event
        assert!(
            matches!(
                manager.events.borrow_mut().poll(),
                Some(Event::DatagramSenderDrop(1))
            ),
            "A drop event should be generated"
        );

        // Sending an empty datagram should succeed as it takes no space
        let empty_id = manager
            .send_datagram(Bytes::new(), SendDatagramParams::default())
            .unwrap();
        assert_eq!(manager.outgoing_count(), 1);
        let item = manager.next_send_datagram().unwrap();
        assert_eq!(item.id, empty_id);
        assert_eq!(item.data.len(), 0);
    }

    /// Test the datagram expiration logic.
    ///
    /// Verifies that:
    /// 1. Expired datagrams are dropped by `next_send_datagram`.
    /// 2. A `DatagramTimeExpiredDrop` event is generated for each expired item.
    /// 3. `next_send_datagram` correctly skips expired items to find the next valid one,
    ///    even if it's in a lower-priority queue.
    #[test]
    fn datagram_expiration_logic() {
        let mut manager = DatagramManager::with_limits(1, 1);
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Arrange: Queue several datagrams with different expiration times and priorities.
        // ID 1: Already expired. Should be dropped immediately.
        let id1 = manager
            .send_datagram(
                Bytes::from_static(b"expired"),
                SendDatagramParams::with_priority_and_expiration(0, 1), // Expires immediately
            )
            .unwrap();
        // ID 2: Will expire after a short delay.
        let id2 = manager
            .send_datagram(
                Bytes::from_static(b"expires soon"),
                SendDatagramParams::with_priority_and_expiration(0, 10), // Expires in 10ms
            )
            .unwrap();
        // ID 3: Valid, no expiration.
        let id3 = manager
            .send_datagram(
                Bytes::from_static(b"valid"),
                SendDatagramParams::with_priority(0),
            )
            .unwrap();
        // ID 4: Valid, lower priority.
        let id4 = manager
            .send_datagram(
                Bytes::from_static(b"valid low priority"),
                SendDatagramParams::with_priority(1),
            )
            .unwrap();

        // Act & Assert 1: The first call should drop the expired item (id1) and return the next valid one (id3).
        // Note: We access id2 before id3 in the queue, but it will expire.
        std::thread::sleep(std::time::Duration::from_millis(20)); // Wait for id2 to expire

        // The first call to next_send_datagram will clean up expired items at the front.
        let item3 = manager.next_send_datagram().unwrap();
        assert_eq!(item3.id, id3, "Should return the first valid datagram");

        // Check for drop events. Both id1 and id2 should have expired and been dropped.
        let mut expired_ids = std::collections::HashSet::new();
        while let Some(Event::DatagramTimeExpiredDrop(id)) = manager.events.borrow_mut().poll() {
            expired_ids.insert(id);
        }
        assert_eq!(
            expired_ids.len(),
            2,
            "Two datagrams should be dropped due to expiration"
        );
        assert!(expired_ids.contains(&id1));
        assert!(expired_ids.contains(&id2));
        assert_eq!(
            manager.outgoing_count(),
            1,
            "Only one datagram should remain"
        );

        // Act & Assert 2: The next call should return the lower-priority item.
        let item4 = manager.next_send_datagram().unwrap();
        assert_eq!(item4.id, id4, "Should return the lower-priority datagram");

        assert!(
            manager.next_send_datagram().is_none(),
            "Queue should be empty"
        );
    }

    /// Test that when making space, the sender drops items from the lowest-priority queue first.
    #[test]
    fn datagram_sender_drops_from_lowest_priority() {
        let mut manager = DatagramManager::with_limits(1, 1); // 1024 bytes limit
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Arrange: Fill the queue with items of different priorities.
        // The low-priority item is added first.
        let id_low_prio = manager
            .send_datagram(
                Bytes::from(vec![1; 500]),
                SendDatagramParams::with_priority(128),
            )
            .unwrap();
        let id_high_prio = manager
            .send_datagram(
                Bytes::from(vec![2; 500]),
                SendDatagramParams::with_priority(10),
            )
            .unwrap();

        assert_eq!(manager.total_outgoing_size, 1000);
        assert_eq!(manager.outgoing_count(), 2);

        // Act: Add a new item that requires dropping one of the existing items.
        // It needs 500 bytes, but only 24 are free. Must drop one 500-byte item.
        let id_new = manager
            .send_datagram(
                Bytes::from(vec![3; 500]),
                SendDatagramParams::with_priority(20),
            )
            .unwrap();

        // Assert: The lowest-priority item (id_low_prio) should have been dropped.
        assert_eq!(manager.total_outgoing_size, 1000); // 500 (high_prio) + 500 (new)
        assert_eq!(manager.outgoing_count(), 2);

        let event = manager.events.borrow_mut().poll().unwrap();
        assert!(
            matches!(event, Event::DatagramSenderDrop(id) if id == id_low_prio),
            "The lowest priority datagram should be dropped"
        );

        // Verify the remaining items are the high-priority one and the new one.
        let item_high = manager.next_send_datagram().unwrap();
        assert_eq!(
            item_high.id, id_high_prio,
            "High priority item should remain"
        );

        let item_new = manager.next_send_datagram().unwrap();
        assert_eq!(item_new.id, id_new, "The new item should be in the queue");
    }

    /// Test the behavior of `get_next_send_datagram_info` when the highest-priority item is expired.
    ///
    /// This test highlights that `get_next_send_datagram_info` is a "dumb" peek and does not
    /// account for expiration. `next_send_datagram` is the one that performs the actual logic.
    #[test]
    fn get_next_send_datagram_info_with_expired_item() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(1024);

        // Arrange: Queue an expired item at high priority and a valid item at low priority.
        manager
            .send_datagram(
                Bytes::from_static(b"expired_data"),
                SendDatagramParams::with_priority_and_expiration(0, 1),
            )
            .unwrap();
        manager
            .send_datagram(
                Bytes::from_static(b"valid_data"),
                SendDatagramParams::with_priority(1),
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5)); // Ensure expiration

        // Act 1: Call get_next_send_datagram_info
        let (prio, len) = manager.get_next_send_datagram_info();

        // Assert 1: It should report the info of the expired, high-priority item.
        assert_eq!(prio, 0, "Should report priority of the expired item");
        assert_eq!(
            len,
            "expired_data".len(),
            "Should report length of the expired item"
        );

        // Act 2: Call next_send_datagram
        let item = manager.next_send_datagram().unwrap();

        // Assert 2: It should have skipped the expired item and returned the valid, low-priority one.
        assert_eq!(item.id, 2, "Should return the valid datagram");
        assert_eq!(item.priority, 1, "Returned item should have priority 1");
        assert_eq!(item.data.as_ref(), b"valid_data");
    }

    /// Test that the receiver queue drops an incoming datagram if it's larger than the
    /// queue's max_size, even if it's smaller than `local_max_datagram_frame_size`.
    #[test]
    fn datagram_receiver_drops_item_larger_than_queue_limit() {
        // Arrange: Configure a large frame size but a small queue size.
        // Frame size limit allows the datagram, but queue memory limit does not.
        let mut manager = DatagramManager::with_limits(1, 1); // 1KB incoming queue
        manager.set_local_max_datagram_frame_size(2048); // Can receive up to 2KB frames
        manager.events.borrow_mut().enable();

        // This datagram is valid according to frame size (1500 < 2048) but
        // too large for the incoming queue (1500 > 1024).
        let oversized_for_queue = Bytes::from(vec![0; 1500]);

        // Act: Try to process the frame.
        let result = manager.on_datagram_frame_received(None, oversized_for_queue);

        // Assert: The operation should fail, the datagram should be dropped, and an event generated.
        assert!(
            matches!(result, Err(Error::DatagramTooLarge)),
            "Should return DatagramTooLarge because it exceeds queue memory limit"
        );
        assert_eq!(
            manager.incoming_count(),
            0,
            "Datagram should not be enqueued"
        );
        assert_eq!(
            manager.stats().received_count,
            1,
            "Stats should count dropped datagrams"
        );

        let event = manager.events.borrow_mut().poll().unwrap();
        assert!(
            matches!(event, Event::DatagramReceiverDrop(id) if id == 1),
            "A receiver drop event should be generated"
        );
    }

    /// Test DatagramQueue's clear method functionality.
    ///
    /// Verifies that clearing a queue properly resets both data and size counters.
    #[test]
    fn datagram_queue_clear_functionality() {
        let events = Rc::new(RefCell::new(EventQueue::default()));
        let mut queue = DatagramQueue::new(1, events); // 1KB limit

        // Add some items
        let item1 = DatagramItem {
            data: Bytes::from(vec![0; 100]),
            with_length: true,
            queued_at: Instant::now(),
            id: 1,
            priority: 0,
            expires_at: None,
        };
        let item2 = DatagramItem {
            data: Bytes::from(vec![1; 200]),
            with_length: true,
            queued_at: Instant::now(),
            id: 2,
            priority: 0,
            expires_at: None,
        };

        queue.enqueue(item1).unwrap();
        queue.enqueue(item2).unwrap();

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.current_size(), 300);
        assert!(!queue.is_empty());

        // Clear the queue
        queue.clear();

        assert_eq!(queue.len(), 0);
        assert_eq!(queue.current_size(), 0);
        assert!(queue.is_empty());
    }

    /// Test that DatagramQueue make_space_for generates proper drop events.
    ///
    /// Ensures that when space is made by dropping items, appropriate events are generated.
    #[test]
    fn datagram_queue_make_space_generates_events() {
        let events = Rc::new(RefCell::new(EventQueue::default()));
        events.borrow_mut().enable();
        let mut queue = DatagramQueue::new(1, events.clone()); // 1KB limit

        // Fill the queue to capacity
        let big_item = DatagramItem {
            data: Bytes::from(vec![0; 1024]),
            with_length: true,
            queued_at: Instant::now(),
            id: 1,
            priority: 0,
            expires_at: None,
        };
        queue.enqueue(big_item).unwrap();

        // Try to add another item that will force cleanup
        let small_item = DatagramItem {
            data: Bytes::from(vec![1; 100]),
            with_length: true,
            queued_at: Instant::now(),
            id: 2,
            priority: 0,
            expires_at: None,
        };
        queue.enqueue(small_item).unwrap();

        // Check that a drop event was generated for the first item
        let event = events.borrow_mut().poll();
        assert!(
            matches!(event, Some(Event::DatagramReceiverDrop(1))),
            "Should generate receiver drop event for displaced item"
        );

        // Verify queue state
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.current_size(), 100);
    }

    /// Test the case where an item expires between the front() check and pop_front().
    ///
    /// This tests the race condition protection where an item might expire in the
    /// small window between checking if it's expired and actually removing it.
    #[test]
    fn datagram_item_expires_between_checks() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Create a datagram that will expire very soon
        let short_expire_params = SendDatagramParams::with_priority_and_expiration(0, 1);
        let expire_id = manager
            .send_datagram(Bytes::from_static(b"about_to_expire"), short_expire_params)
            .unwrap();

        // Add a valid datagram after it
        let valid_params = SendDatagramParams::with_priority(0);
        let valid_id = manager
            .send_datagram(Bytes::from_static(b"valid"), valid_params)
            .unwrap();

        // Wait for the first item to expire
        std::thread::sleep(std::time::Duration::from_millis(2));

        // This should handle the case where the item expires between checks
        let item = manager.next_send_datagram().unwrap();
        assert_eq!(
            item.id, valid_id,
            "Should get the valid item, not the expired one"
        );

        // Check that expiration drop event was generated
        let event = manager.events.borrow_mut().poll();
        assert!(
            matches!(event, Some(Event::DatagramTimeExpiredDrop(id)) if id == expire_id),
            "Should generate drop event for item that expired between checks"
        );
    }

    /// Test multiple priority queues with mixed expired and valid items.
    ///
    /// This comprehensive test verifies the complete priority and expiration
    /// handling logic, including proper queue cleanup and event generation.
    #[test]
    fn datagram_mixed_priority_expiration_handling() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Priority 0: one expired, one valid
        manager
            .send_datagram(
                Bytes::from_static(b"p0_expired"),
                SendDatagramParams::with_priority_and_expiration(0, 1),
            )
            .unwrap();
        let p0_valid_id = manager
            .send_datagram(
                Bytes::from_static(b"p0_valid"),
                SendDatagramParams::with_priority(0),
            )
            .unwrap();

        // Priority 1: all expired
        manager
            .send_datagram(
                Bytes::from_static(b"p1_expired1"),
                SendDatagramParams::with_priority_and_expiration(1, 1),
            )
            .unwrap();
        manager
            .send_datagram(
                Bytes::from_static(b"p1_expired2"),
                SendDatagramParams::with_priority_and_expiration(1, 1),
            )
            .unwrap();

        // Priority 2: valid item
        let p2_valid_id = manager
            .send_datagram(
                Bytes::from_static(b"p2_valid"),
                SendDatagramParams::with_priority(2),
            )
            .unwrap();

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_millis(1));

        // Should get priority 0 valid item first
        let item1 = manager.next_send_datagram().unwrap();
        assert_eq!(item1.id, p0_valid_id);
        assert_eq!(item1.priority, 0);

        // Should get priority 2 valid item next (priority 1 queue should be cleaned up)
        let item2 = manager.next_send_datagram().unwrap();
        assert_eq!(item2.id, p2_valid_id);
        assert_eq!(item2.priority, 2);

        // No more items
        assert!(manager.next_send_datagram().is_none());

        // Verify all expired items generated drop events
        let mut drop_count = 0;
        while let Some(event) = manager.events.borrow_mut().poll() {
            if matches!(event, Event::DatagramTimeExpiredDrop(_)) {
                drop_count += 1;
            }
        }
        assert_eq!(drop_count, 3, "Should have 3 expiration drop events");

        // Verify all empty queues were cleaned up
        assert!(
            manager.outgoing_queue.is_empty(),
            "All queues should be cleaned up"
        );
    }

    /// Test that a fully expired priority queue is cleaned up correctly,
    /// and the manager proceeds to the next valid item in a lower-priority queue.
    /// This test covers the case where a queue becomes empty after cleanup inside the loop.
    #[test]
    fn test_next_send_datagram_cleans_fully_expired_queue() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Arrange:
        // Priority 10: Two expired items. This queue should be completely cleared.
        manager
            .send_datagram(
                Bytes::from_static(b"p10_expired1"),
                SendDatagramParams::with_priority_and_expiration(10, 1),
            )
            .unwrap();
        manager
            .send_datagram(
                Bytes::from_static(b"p10_expired2"),
                SendDatagramParams::with_priority_and_expiration(10, 1),
            )
            .unwrap();

        // Priority 20: One valid item. This is what we expect to get.
        let valid_item_id = manager
            .send_datagram_with_priority(Bytes::from_static(b"p20_valid"), 20)
            .unwrap();

        // Ensure items are expired
        std::thread::sleep(std::time::Duration::from_millis(5));

        // Act:
        let result = manager.next_send_datagram();

        // Assert:
        // 1. We got the valid item from the lower-priority queue.
        assert!(result.is_some(), "Should have returned a valid item");
        let item = result.unwrap();
        assert_eq!(item.id, valid_item_id);
        assert_eq!(item.priority, 20);

        // 2. The high-priority queue (prio 10) should have been removed.
        // The low-priority queue (prio 20) is now also empty because we took its only item.
        assert!(
            manager.outgoing_queue.is_empty(),
            "All queues should be empty after processing"
        );
        assert_eq!(manager.outgoing_count(), 0);

        // 3. Two drop events for the expired items should exist.
        let mut expired_events = 0;
        while let Some(event) = manager.events.borrow_mut().poll() {
            if matches!(event, Event::DatagramTimeExpiredDrop(_)) {
                expired_events += 1;
            }
        }
        assert_eq!(
            expired_events, 2,
            "Should have generated two expiration drop events"
        );
    }

    /// Test that `next_send_datagram` returns `None` when all items in all queues
    /// have expired, and correctly cleans up the entire outgoing queue.
    /// This test covers the path where the outgoing queue becomes completely empty after cleanup.
    #[test]
    fn test_next_send_datagram_returns_none_when_all_items_expire() {
        let mut manager = DatagramManager::new();
        manager.set_peer_max_datagram_frame_size(1024);
        manager.events.borrow_mut().enable();

        // Arrange:
        // Add only expired items across multiple priority queues.
        manager
            .send_datagram(
                Bytes::from_static(b"p10_expired"),
                SendDatagramParams::with_priority_and_expiration(10, 1),
            )
            .unwrap();
        manager
            .send_datagram(
                Bytes::from_static(b"p20_expired"),
                SendDatagramParams::with_priority_and_expiration(20, 1),
            )
            .unwrap();

        assert_eq!(manager.outgoing_count(), 2);
        let initial_size = manager.total_outgoing_size;
        assert!(initial_size > 0);

        // Ensure items are expired
        std::thread::sleep(std::time::Duration::from_millis(5));

        // Act:
        let result = manager.next_send_datagram();

        // Assert:
        // 1. The result should be None as there are no valid datagrams.
        assert!(
            result.is_none(),
            "Should return None when all items are expired"
        );

        // 2. The entire outgoing queue should be empty.
        assert!(
            manager.outgoing_queue.is_empty(),
            "Outgoing queue should be empty"
        );
        assert_eq!(manager.outgoing_count(), 0);
        assert_eq!(manager.total_outgoing_size, 0, "Total size should be zero");

        // 3. Drop events should have been generated for all items.
        let mut expired_events = 0;
        while let Some(event) = manager.events.borrow_mut().poll() {
            if matches!(event, Event::DatagramTimeExpiredDrop(_)) {
                expired_events += 1;
            }
        }
        assert_eq!(expired_events, 2, "Should have dropped all expired items");
    }
}
