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

use std::time::Instant;

use strum::EnumCount;
use strum_macros::EnumCount;
use strum_macros::EnumIter;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, EnumIter, EnumCount)]
pub(crate) enum Timer {
    /// When to declare unacked packets lost or send ack-eliciting probe packets
    LossDetection,

    /// When to close the connection after no activity
    Idle,

    /// When to determine the handshake is failed if it is not completed in time.
    Handshake,

    /// When the timer expires, the connection has been gracefully terminated.
    Draining,

    /// When keys are discarded because they should not be needed anymore
    KeyDiscard,

    /// When to send a `PING` frame to keep the connection alive
    KeepAlive,

    /// When to declare PATH_CHALLENGE probing packet lost
    PathChallenge,
}

/// Associated timeout values with each `Timer`
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct TimerTable {
    expires: [Option<Instant>; Timer::COUNT],
}

impl TimerTable {
    /// Set expiration time for the giver timer
    pub fn set(&mut self, timer: Timer, time: Instant) {
        self.expires[timer as usize] = Some(time);
    }

    /// Get expiration time for the giver timer
    pub fn get(&self, timer: Timer) -> Option<Instant> {
        self.expires[timer as usize]
    }

    /// Cancel the giver timer
    pub fn stop(&mut self, timer: Timer) {
        self.expires[timer as usize] = None;
    }

    /// Get the minmium expiration time of all timers
    pub fn next_timeout(&self) -> Option<Instant> {
        self.expires.iter().filter_map(|&x| x).min()
    }

    /// Check whether the given timer is expired
    pub fn is_expired(&self, timer: Timer, after: Instant) -> bool {
        self.expires[timer as usize].map_or(false, |x| x <= after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Add;
    use std::time::Duration;
    use std::time::Instant;

    #[test]
    fn timer_operation() {
        let mut timers = TimerTable::default();
        assert_eq!(timers.next_timeout(), None);

        // Set timers
        let now = Instant::now();
        let loss_time = now.add(Duration::from_millis(200));
        let idle_time = now.add(Duration::from_millis(3000));
        timers.set(Timer::LossDetection, loss_time);
        timers.set(Timer::Idle, idle_time);

        assert_eq!(timers.get(Timer::LossDetection), Some(loss_time));
        assert_eq!(timers.get(Timer::Idle), Some(idle_time));
        assert_eq!(timers.get(Timer::Draining), None);
        assert_eq!(timers.get(Timer::KeyDiscard), None);
        assert_eq!(timers.next_timeout(), Some(loss_time));

        // Stop timer
        timers.stop(Timer::LossDetection);
        assert_eq!(timers.get(Timer::LossDetection), None);
        assert_eq!(timers.get(Timer::Idle), Some(idle_time));
        assert_eq!(timers.next_timeout(), Some(idle_time));
    }

    #[test]
    fn timer_expiration() {
        let mut timers = TimerTable::default();
        let now = Instant::now();
        let loss_time = now.add(Duration::from_millis(200));
        let idle_time = now.add(Duration::from_millis(3000));
        timers.set(Timer::LossDetection, loss_time);
        timers.set(Timer::Idle, idle_time);

        assert_eq!(timers.is_expired(Timer::LossDetection, now), false);
        assert_eq!(timers.is_expired(Timer::Idle, now), false);

        // Advance ticks
        let now = loss_time;
        assert_eq!(timers.is_expired(Timer::LossDetection, now), true);
        assert_eq!(timers.is_expired(Timer::Idle, now), false);

        // Advance ticks
        let now = idle_time;
        assert_eq!(timers.is_expired(Timer::LossDetection, now), true);
        assert_eq!(timers.is_expired(Timer::Idle, now), true);
    }
}
