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

use std::time::Duration;
use std::time::Instant;

use priority_queue::double_priority_queue::DoublePriorityQueue;

type Index = u64;

/// Store timers in a binary queue. Keep them sorted by which timer is going to expire first.
pub struct TimerQueue {
    timers: DoublePriorityQueue<Index, Instant>,
}

impl TimerQueue {
    /// Create a new TimerQueue.
    pub fn new() -> Self {
        Self {
            timers: DoublePriorityQueue::new(),
        }
    }

    /// Creates an empty timer queue with a specific capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            timers: DoublePriorityQueue::with_capacity(capacity),
        }
    }

    /// Return the number of timers in the queue.
    pub fn len(&self) -> usize {
        self.timers.len()
    }

    /// Return if the timer queue is empty.
    pub fn is_empty(&self) -> bool {
        self.timers.is_empty()
    }

    /// Add a timer into the queue, replacing any existing timer if one exists.
    pub fn add(&mut self, idx: u64, duration: Duration, now: Instant) {
        _ = self.timers.push(idx, now + duration);
    }

    /// Delete a timer by id.
    pub fn del(&mut self, idx: &u64) {
        _ = self.timers.remove(idx);
    }

    /// Return the amount of time remaining for the earliest expiring timer.
    pub fn time_remaining(&self, now: Instant) -> Option<Duration> {
        self.timers.peek_min().map(|(_, expires_at)| {
            if now > *expires_at {
                return Duration::new(0, 0);
            }
            *expires_at - now
        })
    }

    /// Return the next expired timer if any.
    pub fn next_expire(&mut self, now: Instant) -> Option<Index> {
        if let Some((_, expires_at)) = self.timers.peek_min() {
            if *expires_at <= now {
                let idx = self.timers.pop_min().map(|(idx, _)| idx).unwrap();
                return Some(idx);
            }
        }
        None
    }

    /// Clear all the timers
    pub fn clear(&mut self) {
        self.timers.clear();
    }
}

impl Default for TimerQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add() {
        let mut tq = TimerQueue::with_capacity(10);
        assert!(tq.is_empty());

        let now = Instant::now();
        // Add a new timer.
        tq.add(0, Duration::from_millis(100), now);
        assert_eq!(tq.len(), 1);

        // Add another new timer.
        tq.add(1, Duration::from_millis(200), now);
        assert_eq!(tq.len(), 2);

        // Add an existing new timer.
        tq.add(1, Duration::from_millis(300), now);
        assert_eq!(tq.len(), 2);
    }

    #[test]
    fn del() {
        let mut tq = TimerQueue::default();

        let now = Instant::now();
        // Add a new timer.
        tq.add(0, Duration::from_millis(100), now);
        assert_eq!(tq.len(), 1);

        // Delete a non-existing timer.
        tq.del(&1);
        assert_eq!(tq.len(), 1);

        // Delete an existing new timer.
        tq.del(&0);
        assert!(tq.is_empty());
    }

    #[test]
    fn expired() {
        let mut tq = TimerQueue::default();

        let now = Instant::now();
        tq.add(0, Duration::from_millis(100), now);
        tq.add(1, Duration::from_millis(200), now);
        tq.add(2, Duration::from_millis(300), now);
        assert!(tq.next_expire(now).is_none());
        assert_eq!(tq.len(), 3);

        let t = now + Duration::from_millis(100);
        let idx = tq.next_expire(t);
        assert!(idx.is_some());
        assert_eq!(idx.unwrap(), 0);
        assert_eq!(tq.len(), 2);

        tq.del(&2);
        tq.add(3, Duration::from_millis(1000), now);
        tq.add(4, Duration::from_millis(1000), now);
        tq.add(5, Duration::from_millis(1500), now);
        let t = now + Duration::from_millis(1000);
        assert_eq!(tq.next_expire(t), Some(1));
        assert_eq!(tq.next_expire(t), Some(3));
        assert_eq!(tq.next_expire(t), Some(4));
        assert_eq!(tq.len(), 1);
    }

    #[test]
    fn time_remaining() {
        let mut tq = TimerQueue::default();

        let now = Instant::now();
        assert_eq!(tq.time_remaining(now), None);

        tq.add(0, Duration::from_millis(100), now);
        tq.add(1, Duration::from_millis(200), now);
        tq.add(2, Duration::from_millis(300), now);
        assert_eq!(tq.len(), 3);
        assert_eq!(tq.time_remaining(now), Some(Duration::from_millis(100)));
    }
}
