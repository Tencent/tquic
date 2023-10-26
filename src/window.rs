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

/// A sliding window packet number for deduplication detection.
/// See RFC 4303 Section 3.4.3 for a similar algorithm.
#[derive(Clone, Copy, Default)]
pub struct SeqNumWindow {
    /// The lowest sequence number
    lower: u64,

    /// A contiguous bitfield, where each bit corresponds to a sequence number
    window: u128,
}

impl SeqNumWindow {
    /// Insert an sequence number
    pub fn insert(&mut self, seq: u64) {
        // Sequence number is on the left end of the window.
        if seq < self.lower {
            return;
        }

        // Sequence number is on the right end of the window.
        if seq > self.upper() {
            let diff = seq - self.upper();
            self.lower += diff;
            self.window = self.window.checked_shl(diff as u32).unwrap_or(0);
        }

        let mask = 1_u128 << (self.upper() - seq);
        self.window |= mask;
    }

    /// Check whether the packet number exist or not
    pub fn contains(&mut self, seq: u64) -> bool {
        // Sequence number is on the right end of the window.
        if seq > self.upper() {
            return false;
        }

        // Sequence number is on the left end of the window.
        if seq < self.lower {
            return true;
        }

        let mask = 1_u128 << (self.upper() - seq);
        self.window & mask != 0
    }

    /// Return the largest sequence number
    fn upper(&self) -> u64 {
        self.lower
            .saturating_add(std::mem::size_of::<u128>() as u64 * 8)
            - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_num_window_default() {
        let mut win = SeqNumWindow::default();
        assert!(!win.contains(0));
        assert!(!win.contains(1));
    }

    #[test]
    fn seq_num_window_insert() {
        let mut win = SeqNumWindow::default();
        win.insert(0);
        assert!(win.contains(0));
        assert!(!win.contains(1));

        win.insert(1);
        assert!(win.contains(0));
        assert!(win.contains(1));

        win.insert(3);
        assert!(win.contains(0));
        assert!(win.contains(1));
        assert!(!win.contains(2));
        assert!(win.contains(3));
        assert!(!win.contains(200));
    }

    #[test]
    fn seq_num_window_insert_slide() {
        let mut win = SeqNumWindow::default();

        win.insert(10);
        assert!(!win.contains(0));
        assert!(win.contains(10));

        win.insert(138);
        assert!(win.contains(138));
        assert!(!win.contains(137));
        assert!(win.contains(10));
        assert!(win.contains(0));
    }

    #[test]
    fn seq_num_window_insert_max() {
        let mut win = SeqNumWindow::default();
        let max_seq = std::u64::MAX - 1;
        win.insert(max_seq);
        assert!(win.contains(0));
        assert!(win.contains(max_seq));
        assert!(!win.contains(max_seq - 1));
        assert!(win.contains(max_seq - 128));
    }
}
