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

use std::ops::Range;

use std::collections::btree_map;
use std::collections::BTreeMap;
use std::collections::Bound::Excluded;
use std::collections::Bound::Included;
use std::collections::Bound::Unbounded;

/// A set of u64 values, support range operations, like insert, remove, etc.
#[derive(Clone, PartialEq, Eq, PartialOrd)]
pub struct RangeSet {
    /// The inner `RangeSet`.
    set: BTreeMap<u64, u64>,

    /// The maximum items in the set.
    capacity: usize,
}

impl RangeSet {
    /// Create a new `RangeSet` with the given capacity.
    pub fn new(capacity: usize) -> Self {
        RangeSet {
            set: BTreeMap::default(),
            capacity,
        }
    }

    /// Insert `range` into the set.
    /// Note that the range is [start, end), i.e. contains `start` but not `end`.
    pub fn insert(&mut self, mut range: Range<u64>) {
        // If the given range is empty, do nothing.
        if range.is_empty() {
            return;
        }

        if let Some(r) = self.prev_to(range.start) {
            if r.end >= range.end {
                // Fully covered by preceding existing range, do nothing.
                return;
            } else if r.end >= range.start {
                // The new range overlaps with the preceding existing range, merge them into a single range.
                self.set.remove(&r.start);
                range.start = r.start;
            }
        }

        while let Some(r) = self.next_to(range.start) {
            // There is no overlap between the new range and the following existing range, break.
            if r.start > range.end {
                break;
            }

            // The new range overlaps with the following existing range, merge them into a single range.
            self.set.remove(&r.start);
            range.end = std::cmp::max(r.end, range.end);
        }

        // If the set is full, remove the first range.
        if self.len() >= self.capacity {
            self.set.pop_first();
        }

        // Insert the new range.
        self.set.insert(range.start, range.end);
    }

    /// Add `elem` to the set, i.e. insert range [elem, elem + 1) into the set.
    pub fn add_elem(&mut self, elem: u64) {
        self.insert(elem..elem + 1);
    }

    /// Remove all sub-ranges that are fully covered by `range` from the set.
    pub fn remove(&mut self, range: Range<u64>) {
        // If the set or the given range is empty, do nothing.
        if self.is_empty() || range.is_empty() {
            return;
        }

        // Check for any overlap between the given range and the preceding existing range.
        if let Some(r) = self.prev_to(range.start) {
            if r.end > range.start {
                self.set.remove(&r.start);

                if r.start < range.start {
                    self.set.insert(r.start, range.start);
                }

                if r.end > range.end {
                    self.set.insert(range.end, r.end);
                }

                // The following ranges would not overlap with the given range, return prematurely.
                if r.end >= range.end {
                    return;
                }
            }
        }

        // Check for any overlap between the given range and the following existing range.
        while let Some(r) = self.next_to(range.start) {
            // Following ranges would not overlap with the given range, break.
            if r.start > range.end {
                break;
            }

            self.set.remove(&r.start);
            if r.end > range.end {
                self.set.insert(range.end, r.end);
                break;
            }
        }
    }

    /// Remove `elem` from the set, i.e. remove range [elem, elem + 1) from the set.
    pub fn remove_elem(&mut self, elem: u64) {
        self.remove(elem..elem + 1);
    }

    /// Remove all ranges that are smaller or equal to `elem` from the set.
    pub fn remove_until(&mut self, elem: u64) {
        let ranges: Vec<Range<u64>> = self
            .set
            .range((Unbounded, Included(&elem)))
            .map(|(&s, &e)| (s..e))
            .collect();

        for r in ranges {
            self.set.remove(&r.start);

            if r.end > elem + 1 {
                let start = elem + 1;
                self.insert(start..r.end);
            }
        }
    }

    /// Clear the range set.
    pub fn clear(&mut self) {
        self.set.clear();
    }

    /// Return the first non-overlapped subrange in `range`.
    pub fn filter(&self, range: Range<u64>) -> Option<Range<u64>> {
        // If the range set is empty
        if self.is_empty() {
            return Some(range);
        }

        let mut new_start = range.start;
        let mut new_end = range.end;

        if let Some(r) = self.prev_to(range.start) {
            if r.end >= range.end {
                return None;
            } else if r.end > range.start {
                new_start = r.end;
            }
        }

        if let Some(r) = self.next_after(range.start) {
            if r.start < range.end {
                new_end = r.start
            }
        }

        Some(new_start..new_end)
    }

    /// Return true if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Return the minimum value in the set.
    pub fn min(&self) -> Option<u64> {
        self.iter().next().map(|x| x.start)
    }

    /// Return the maximum value in the set.
    #[allow(clippy::manual_next_back)]
    pub fn max(&self) -> Option<u64> {
        self.iter().rev().next().map(|x| x.end - 1)
    }

    /// Return the number of ranges in the set.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Return an iterator over the ranges in the set.
    pub fn iter(&self) -> Iter {
        Iter {
            set: self.set.iter(),
        }
    }

    /// Flatten the ranges in the set into a single iterator.
    pub fn flatten(&self) -> Flatten {
        Flatten {
            set: self.set.iter(),
            next: 0,
            end: 0,
        }
    }

    /// Find the closest range to `elem` that begins *at* or before it.
    fn prev_to(&self, elem: u64) -> Option<Range<u64>> {
        self.set
            .range((Unbounded, Included(elem)))
            .map(|(&s, &e)| (s..e))
            .next_back()
    }

    /// Find the closest range to `elem` that begins *at* or after it.
    fn next_to(&self, elem: u64) -> Option<Range<u64>> {
        self.set
            .range((Included(elem), Unbounded))
            .map(|(&s, &e)| (s..e))
            .next()
    }

    /// Find the closest range to `elem` that begins after it.
    fn next_after(&self, elem: u64) -> Option<Range<u64>> {
        self.set
            .range((Excluded(elem), Unbounded))
            .map(|(&s, &e)| (s..e))
            .next()
    }

    /// Check if the element exists or not
    pub fn contains(&self, elem: u64) -> bool {
        if let Some(prev) = self.prev_to(elem) {
            if prev.contains(&elem) {
                return true;
            }
        }
        if let Some(next) = self.next_to(elem) {
            if next.contains(&elem) {
                return true;
            }
        }
        false
    }

    /// Peek at the smallest range in the set.
    pub fn peek_min(&self) -> Option<Range<u64>> {
        let (&start, &end) = self.set.iter().next()?;
        Some(start..end)
    }

    /// Pop the smallest range in the set.
    pub fn pop_min(&mut self) -> Option<Range<u64>> {
        let result = self.peek_min()?;
        self.set.remove(&result.start);
        Some(result)
    }
}

impl Default for RangeSet {
    fn default() -> Self {
        Self::new(usize::MAX)
    }
}

impl PartialEq<Range<u64>> for RangeSet {
    // If and only if the `RangeSet` contains a single range and that range is
    // equal to the given range, return true.
    fn eq(&self, other: &Range<u64>) -> bool {
        if self.len() == 1 && self.peek_min().unwrap() == *other {
            return true;
        }

        false
    }
}

impl std::fmt::Debug for RangeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ranges: Vec<Range<u64>> = self
            .iter()
            .map(|mut r| {
                // Convert [start, end) to [start, end].
                r.end -= 1;
                r
            })
            .collect();

        write!(f, "{ranges:?}")
    }
}

pub struct Iter<'a> {
    set: btree_map::Iter<'a, u64, u64>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = Range<u64>;

    fn next(&mut self) -> Option<Range<u64>> {
        let (&start, &end) = self.set.next()?;
        Some(start..end)
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    fn next_back(&mut self) -> Option<Range<u64>> {
        let (&start, &end) = self.set.next_back()?;
        Some(start..end)
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {
    fn len(&self) -> usize {
        self.set.len()
    }
}

pub struct Flatten<'a> {
    set: btree_map::Iter<'a, u64, u64>,
    next: u64,
    end: u64,
}

impl<'a> Iterator for Flatten<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.next == self.end {
            let (&start, &end) = self.set.next()?;

            self.next = start;
            self.end = end;
        }

        let next = self.next;
        self.next += 1;

        Some(next)
    }
}

impl<'a> DoubleEndedIterator for Flatten<'a> {
    fn next_back(&mut self) -> Option<u64> {
        if self.next == self.end {
            let (&start, &end) = self.set.next_back()?;

            self.next = start;
            self.end = end;
        }

        self.end -= 1;

        Some(self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity() {
        let mut r = RangeSet::new(5);
        assert_eq!(r.len(), 0);
        assert_eq!(r.min(), None);
        assert_eq!(r.max(), None);

        // Insert [200, 300).
        r.insert(200..300);
        assert_eq!(r.len(), 1);
        assert_eq!(r.min(), Some(200));
        assert_eq!(r.max(), Some(299));

        // Insert [400, 500).
        r.insert(400..500);
        assert_eq!(r.len(), 2);
        assert_eq!(r.min(), Some(200));
        assert_eq!(r.max(), Some(499));

        // Insert [20, 30).
        r.insert(20..30);
        assert_eq!(r.len(), 3);
        assert_eq!(r.min(), Some(20));
        assert_eq!(r.max(), Some(499));

        // Insert [40, 50).
        r.insert(40..50);
        assert_eq!(r.len(), 4);
        assert_eq!(r.min(), Some(20));
        assert_eq!(r.max(), Some(499));

        // Insert [60, 70).
        r.insert(60..70);
        assert_eq!(r.len(), 5);
        assert_eq!(r.min(), Some(20));
        assert_eq!(r.max(), Some(499));

        // Insert a range that is too large should cause the smallest range to be removed.
        r.insert(90..100);
        assert_eq!(r.len(), 5);
        assert_eq!(r.min(), Some(40));
        assert_eq!(r.max(), Some(499));

        // Insert a range that is too large should cause the smallest range to be removed.
        r.insert(110..120);
        assert_eq!(r.len(), 5);
        assert_eq!(r.min(), Some(60));
        assert_eq!(r.max(), Some(499));
    }

    #[test]
    fn insert_empty_range() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Insert an empty range should do nothing.
        r.insert(0..0);
        assert_eq!(r.len(), 0);
        assert_eq!(r.iter().next(), None);
        assert_eq!(r.iter().next_back(), None);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Insert an non-empty range.
        r.insert(7..11);
        assert_eq!(r.len(), 1);
        assert_eq!(r.iter().next(), Some(7..11));
        assert_eq!(r.iter().next_back(), Some(7..11));
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[7, 8, 9, 10]);

        // Insert an invalid range [13..10), which should be ignored.
        r.insert(13..10);
        assert_eq!(r.len(), 1);
        assert_eq!(r.iter().next(), Some(7..11));
        assert_eq!(r.iter().next_back(), Some(7..11));
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[7, 8, 9, 10]);
    }

    #[test]
    fn insert_without_overlap() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Insert [7..11)
        r.insert(7..11);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[7, 8, 9, 10]);

        // Insert [13..16)
        r.insert(13..16);
        assert_eq!(r.len(), 2);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[7, 8, 9, 10, 13, 14, 15]
        );

        // Insert [3..5)
        r.insert(3..5);
        assert_eq!(r.len(), 3);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[3, 4, 7, 8, 9, 10, 13, 14, 15]
        );
    }

    #[test]
    fn insert_overlap() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);
        assert_eq!(r.min(), None);
        assert_eq!(r.max(), None);

        // Insert [10..20)
        r.insert(10..20);
        assert_eq!(r.len(), 1);
        assert_eq!(r.min(), Some(10));
        assert_eq!(r.max(), Some(19));

        // Insert an overlapping range [15..25), right overlap, which should be merged into [10..25).
        r.insert(15..25);
        assert_eq!(r.len(), 1);
        assert_eq!(r.min(), Some(10));
        assert_eq!(r.max(), Some(24));

        // Insert an overlapping range [25, 30), touching the right edge, which should be merged into [10..30).
        r.insert(25..30);
        assert_eq!(r.len(), 1);
        assert_eq!(r.min(), Some(10));
        assert_eq!(r.max(), Some(29));

        // Insert an overlapping range [5, 10), touching the left edge, which should be merged into [5..30).
        r.insert(5..10);
        assert_eq!(r.len(), 1);
        assert_eq!(r.min(), Some(5));
        assert_eq!(r.max(), Some(29));

        // Insert an overlapping range [1, 8), left overlap, which should be merged into [1..30).
        r.insert(1..8);
        assert_eq!(r.len(), 1);
        assert_eq!(r.min(), Some(1));
        assert_eq!(r.max(), Some(29));

        // Insert a new range [40, 60), get [1..30) and [40..60).
        r.insert(40..60);
        assert_eq!(r.len(), 2);
        assert_eq!(r.min(), Some(1));
        assert_eq!(r.max(), Some(59));

        // Insert a new range [70, 80), get [1..30), [40..60) and [70..80).
        r.insert(70..80);
        assert_eq!(r.len(), 3);
        assert_eq!(r.min(), Some(1));
        assert_eq!(r.max(), Some(79));

        // Insert a fully contained range [5, 25), nothing should change.
        r.insert(5..25);
        assert_eq!(r.len(), 3);
        assert_eq!(r.min(), Some(1));
        assert_eq!(r.max(), Some(79));

        // Insert a duplicate range [40, 60), nothing should change.
        r.insert(40..60);
        assert_eq!(r.len(), 3);
        assert_eq!(r.min(), Some(1));
        assert_eq!(r.max(), Some(79));

        // Insert [25, 30), fully contained in [1..30), and right edge same as [1..30), nothing should change.
        r.insert(25..30);
        assert_eq!(r.len(), 3);
        assert_eq!(r.min(), Some(1));
        assert_eq!(r.max(), Some(79));

        // Insert [70, 75), fully contained in [70..80), and left edge same as [70..80), nothing should change.
        r.insert(70..75);
        assert_eq!(r.len(), 3);
        assert_eq!(r.min(), Some(1));
        assert_eq!(r.max(), Some(79));

        // Insert an overlapping range [25, 75), overlap with all ranges, merge into [1..80).
        r.insert(25..75);
        assert_eq!(r.len(), 1);
        assert_eq!(r.min(), Some(1));
        assert_eq!(r.max(), Some(79));
    }

    #[test]
    fn remove() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Try to remove [1, 5), but the range set is empty, nothing should change.
        r.remove(1..5);
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Insert ranges: [1..6), [8, 13), [15, 20), [22, 27)
        for i in [1, 8, 15, 22] {
            r.insert(i..i + 5);
        }
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26]
        );

        // Try to remove an empty range [1, 1), nothing should change.
        r.remove(1..1);
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26]
        );

        // Try to remove range [1, 2), the left part of first range.
        // Get [2..6), [8, 13), [15, 20), [22, 27)
        r.remove(1..2);
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26]
        );

        // Try to remove range [3, 6), the right part of first range.
        // Get [2..3), [8, 13), [15, 20), [22, 27)
        r.remove(3..6);
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[2, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26]
        );

        // Try to remove range [8, 10), the left part of second range.
        // Get [2..3), [10, 13), [15, 20), [22, 27)
        r.remove(8..10);
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[2, 10, 11, 12, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26]
        );

        // Try to remove range [12, 13), the right part of second range.
        // Get [2..3), [10, 12), [15, 20), [22, 27)
        r.remove(12..13);
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[2, 10, 11, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26]
        );

        // Try to remove range [22, 24), the left part of last range.
        // Get [2..3), [10, 12), [15, 20), [24, 27)
        r.remove(22..24);
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[2, 10, 11, 15, 16, 17, 18, 19, 24, 25, 26]
        );

        // Try to remove range [26, 27), the right part of last range.
        // Get [2..3), [10, 12), [15, 20), [24, 26)
        r.remove(26..27);
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[2, 10, 11, 15, 16, 17, 18, 19, 24, 25]
        );

        // Try to remove range [10, 12), the whole second range.
        // Get [2..3), [15, 20), [24, 26)
        r.remove(10..12);
        assert_eq!(r.len(), 3);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[2, 15, 16, 17, 18, 19, 24, 25]
        );

        // Try to remove [2, 20), the first and third range.
        // Get [24, 26)
        r.remove(2..20);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[24, 25]);

        // Try to remove [24, 26), the last range.
        // Get empty
        r.remove(24..26);
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());
    }

    #[test]
    fn remove_cross_multi_ranges() {
        let mut r = RangeSet::default();

        // Insert [1, 3), [4, 6), [7, 9), [10, 12), [13, 15)
        for i in [1, 4, 7, 10, 13] {
            r.insert(i..i + 2);
        }
        assert_eq!(r.len(), 5);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[1, 2, 4, 5, 7, 8, 10, 11, 13, 14]
        );

        // Try to remove ranges [2, 8), cross multiple ranges.
        // Get [1, 2), [8, 9), [10, 12), [13, 15)
        r.remove(2..8);
        assert_eq!(r.len(), 4);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[1, 8, 10, 11, 13, 14]);

        // Try to remove ranges [8, 14), cross multiple ranges.
        // Get [1, 2), [14, 15)
        r.remove(8..14);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[1, 14]);

        // Try to remove ranges [1, 15), cross all ranges.
        // Get empty
        r.remove(1..15);
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());
    }

    #[test]
    fn remove_until() {
        let mut r = RangeSet::default();

        // Insert [1, 4), [6, 9), [11, 14), [16, 19), [21, 24)
        for i in [1, 6, 11, 16, 21] {
            r.insert(i..i + 3);
        }
        assert_eq!(r.len(), 5);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[1, 2, 3, 6, 7, 8, 11, 12, 13, 16, 17, 18, 21, 22, 23]
        );

        // Try to remove until 0, nothing changed.
        // Get [1, 4), [6, 9), [11, 14), [16, 19), [21, 24)
        r.remove_until(0);
        assert_eq!(r.len(), 5);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[1, 2, 3, 6, 7, 8, 11, 12, 13, 16, 17, 18, 21, 22, 23]
        );

        // Try to remove until 1
        // Get [2, 4), [6, 9), [11, 14), [16, 19), [21, 24)
        r.remove_until(1);
        assert_eq!(r.len(), 5);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[2, 3, 6, 7, 8, 11, 12, 13, 16, 17, 18, 21, 22, 23]
        );

        // Try to remove until 2
        // Get [3, 4), [6, 9), [11, 14), [16, 19), [21, 24)
        r.remove_until(2);
        assert_eq!(r.len(), 5);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[3, 6, 7, 8, 11, 12, 13, 16, 17, 18, 21, 22, 23]
        );

        // Try to remove until 7
        // Get [8, 9), [11, 14), [16, 19), [21, 24)
        r.remove_until(7);
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[8, 11, 12, 13, 16, 17, 18, 21, 22, 23]
        );

        // Try to remove until 14
        // Get [16, 19), [21, 24)
        r.remove_until(14);
        assert_eq!(r.len(), 2);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[16, 17, 18, 21, 22, 23]
        );

        // Try to remove until 20
        // Get [21, 24)
        r.remove_until(20);
        assert_eq!(r.len(), 1);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[21, 22, 23]);

        // Try to remove until 24
        // Get empty
        r.remove_until(24);
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Insert [1, 4), [6, 9), [11, 14), [16, 19), [21, 24)
        for i in [1, 6, 11, 16, 21] {
            r.insert(i..i + 3);
        }
        assert_eq!(r.len(), 5);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[1, 2, 3, 6, 7, 8, 11, 12, 13, 16, 17, 18, 21, 22, 23]
        );

        // Try to remove until 25
        // Get empty
        r.remove_until(25);
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Try to remove until 30
        // Get empty
        r.remove_until(30);
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());
    }

    #[test]
    fn clear() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Clear empty set, nothing should change.
        r.clear();
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Insert ranges: [1..6), [8, 13), [15, 20), [22, 27)
        for i in [1, 8, 15, 22] {
            r.insert(i..i + 5);
        }
        assert_eq!(r.len(), 4);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26]
        );

        // Clear the set, nothing should remain.
        r.clear();
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());
    }

    #[test]
    fn filter() {
        // simple cases
        let cases = [
            (vec![2..4, 6..8], 0..2, Some(0..2)),
            (vec![2..4, 6..8], 4..6, Some(4..6)),
            (vec![2..4, 6..8], 8..9, Some(8..9)),
            (vec![], 8..9, Some(8..9)),
            (vec![2..4, 6..8], 2..4, None),
            (vec![2..4, 6..8], 6..8, None),
            (vec![2..4, 6..8], 2..3, None),
            (vec![2..4, 6..8], 3..4, None),
            (vec![2..4, 6..8], 6..7, None),
            (vec![2..4, 6..8], 7..8, None),
            (vec![2..4, 6..8], 0..4, Some(0..2)),
            (vec![2..4, 6..8], 2..5, Some(4..5)),
            (vec![2..4, 6..8], 5..8, Some(5..6)),
            (vec![2..4, 6..8], 6..9, Some(8..9)),
            (vec![2..4, 6..8], 3..5, Some(4..5)),
            (vec![2..4, 6..8], 7..9, Some(8..9)),
            (vec![2..4, 6..8], 0..3, Some(0..2)),
            (vec![2..4, 6..8], 5..7, Some(5..6)),
            (vec![2..4, 6..8], 0..5, Some(0..2)),
            (vec![2..4, 6..8], 5..9, Some(5..6)),
            (vec![2..4, 6..8], 3..7, Some(4..6)),
            (vec![2..4, 6..8], 3..9, Some(4..6)),
            (vec![2..4, 6..8], 0..7, Some(0..2)),
            (vec![2..4, 6..8], 0..9, Some(0..2)),
        ];
        for case in cases {
            let mut rs = RangeSet::default();
            for r in case.0 {
                rs.insert(r);
            }
            assert_eq!(rs.filter(case.1), case.2);
        }

        // all cases
        let mut rs = RangeSet::default();
        for r in vec![2..4, 6..8] {
            rs.insert(r);
        }
        for i in 0..10 {
            for j in i + 1..11 {
                let res = rs.filter(i..j);
                if (i < 2 && j <= 2) || (i >= 4 && j <= 6) || i >= 8 {
                    assert_eq!(res, Some(i..j), "{:?} want {:?}, got {:?}", i..j, i..j, res)
                } else if i < 2 && j > 2 {
                    assert_eq!(res, Some(i..2), "{:?} want {:?}, got {:?}", i..j, i..2, res)
                } else if i >= 2 && i <= 4 && j > 4 && j <= 6 {
                    assert_eq!(res, Some(4..j), "{:?} want {:?}, got {:?}", i..j, 4..j, res)
                } else if i >= 2 && i <= 4 && j > 4 && j > 6 {
                    assert_eq!(res, Some(4..6), "{:?} want {:?}, got {:?}", i..j, 4..6, res)
                } else if i >= 4 && i < 6 && j >= 6 {
                    assert_eq!(res, Some(i..6), "{:?} want {:?}, got {:?}", i..j, i..6, res)
                } else if i >= 6 && i < 8 && j > 8 {
                    assert_eq!(res, Some(8..j), "{:?} want {:?}, got {:?}", i..j, 8..j, res)
                } else {
                    assert_eq!(res, None, "{:?} want None, got {:?}", i..j, res)
                }
            }
        }
    }

    #[test]
    fn add_elem() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &Vec::<u64>::new());

        // Insert ranges: [1..6), [8, 13), [15, 20)
        for i in [1, 8, 15] {
            r.insert(i..i + 5);
        }
        assert_eq!(r.len(), 3);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19]
        );

        // Add new elems at the beginning and the end: 0, 20
        r.add_elem(0);
        r.add_elem(20);
        assert_eq!(r.len(), 3);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 20]
        );

        // Add existing range's edge elems: 0, 1, 5, 8, 12, 15, 20, nothing should change.
        for i in [0, 1, 5, 8, 12, 15, 20] {
            r.add_elem(i);
        }
        assert_eq!(r.len(), 3);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 20]
        );

        // Add existing range's inner elems: 2, 3, 4, 9, 10, 11, 16, 17, 18, nothing should change.
        for i in [2, 3, 4, 9, 10, 11, 16, 17, 18] {
            r.add_elem(i);
        }
        assert_eq!(r.len(), 3);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 15, 16, 17, 18, 19, 20]
        );

        // Add new elems, make all ranges merge into one.
        for i in [6, 7, 13, 14] {
            r.add_elem(i);
        }
        assert_eq!(r.len(), 1);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        );

        // Add new elems, which has a gap with existing ranges.
        for i in [40, 36, 35, 30, 25] {
            r.add_elem(i);
        }
        assert_eq!(r.len(), 5);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 25, 30,
                35, 36, 40
            ]
        );
    }

    #[test]
    fn prev_to() {
        let mut r = RangeSet::default();

        // Insert ranges: [1..6), [8, 13), [15, 20), [22, 27)
        for i in [1, 8, 15, 22] {
            r.insert(i..i + 5);
        }

        assert_eq!(r.prev_to(0), None);

        for i in [1, 2, 5, 6, 7] {
            assert_eq!(r.prev_to(i), Some(1..6));
        }

        for i in [8, 9, 12, 13, 14] {
            assert_eq!(r.prev_to(i), Some(8..13));
        }

        for i in [22, 23, 26, 27, 28] {
            assert_eq!(r.prev_to(i), Some(22..27));
        }
    }

    #[test]
    fn next_to() {
        let mut r = RangeSet::default();

        // Insert ranges: [1..6), [8, 13), [15, 20), [22, 27)
        for i in [1, 8, 15, 22] {
            r.insert(i..i + 5);
        }

        for i in [0, 1] {
            assert_eq!(r.next_to(i), Some(1..6));
        }

        for i in [6, 7, 8] {
            assert_eq!(r.next_to(i), Some(8..13));
        }

        for i in [13, 14, 15] {
            assert_eq!(r.next_to(i), Some(15..20));
        }

        for i in [20, 21, 22] {
            assert_eq!(r.next_to(i), Some(22..27));
        }

        for i in [23, 27, 28] {
            assert_eq!(r.next_to(i), None);
        }
    }

    #[test]
    fn contains() {
        let mut r = RangeSet::default();
        // Insert ranges: [2..6), [8, 13)
        r.insert(2..6);
        r.insert(8..13);

        for i in [0, 1] {
            assert_eq!(r.contains(i), false);
        }
        for i in 2..6 {
            assert_eq!(r.contains(i), true);
        }
        for i in [6, 7] {
            assert_eq!(r.contains(i), false);
        }
        for i in 8..13 {
            assert_eq!(r.contains(i), true);
        }
        for i in 13..20 {
            assert_eq!(r.contains(i), false);
        }
    }

    #[test]
    fn flatten() {
        let mut r = RangeSet::default();
        assert_eq!(r.len(), 0);

        let empty: &[u64] = &[];
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &empty);

        // Insert range [0, 1), only one elem.
        r.insert(0..1);
        assert_eq!(r.len(), 1);
        // Traverse the range from both directions.
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[0]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(), &[0]);

        // Insert range [10, 13)
        r.insert(10..13);
        assert_eq!(r.len(), 2);
        assert_eq!(&r.flatten().collect::<Vec<u64>>(), &[0, 10, 11, 12]);
        assert_eq!(&r.flatten().rev().collect::<Vec<u64>>(), &[12, 11, 10, 0]);

        // Insert range [5, 8)
        r.insert(5..8);
        assert_eq!(r.len(), 3);
        assert_eq!(
            &r.flatten().collect::<Vec<u64>>(),
            &[0, 5, 6, 7, 10, 11, 12]
        );
        assert_eq!(
            &r.flatten().rev().collect::<Vec<u64>>(),
            &[12, 11, 10, 7, 6, 5, 0]
        );
    }

    #[test]
    fn partial_eq() {
        let mut r = RangeSet::default();
        assert_ne!(r, 0..0);

        let final_range = Range { start: 1, end: 100 };

        r.insert(1..10);
        assert_ne!(r, final_range);

        r.insert(30..40);
        assert_ne!(r, final_range);

        r.insert(20..30);
        assert_ne!(r, final_range);

        r.insert(25..100);
        assert_ne!(r, final_range);

        r.insert(5..20);
        assert_eq!(r, final_range);
    }

    #[test]
    fn smallest_largest() {
        let mut r = RangeSet::default();
        assert_eq!(r.min(), None);
        assert_eq!(r.max(), None);

        // Insert [200, 300)
        r.insert(200..300);
        assert_eq!(r.min(), Some(200));
        assert_eq!(r.max(), Some(299));

        // Insert [400, 500)
        r.insert(400..500);
        assert_eq!(r.min(), Some(200));
        assert_eq!(r.max(), Some(499));

        // Insert [10, 20)
        r.insert(10..20);
        assert_eq!(r.min(), Some(10));
        assert_eq!(r.max(), Some(499));

        // Insert [600, 700)
        r.insert(600..700);
        assert_eq!(r.min(), Some(10));
        assert_eq!(r.max(), Some(699));

        // Insert [1, 600)
        r.insert(1..600);
        assert_eq!(r.min(), Some(1));
        assert_eq!(r.max(), Some(699));
    }

    #[test]
    fn peek_min() {
        let mut r = RangeSet::default();
        assert_eq!(r.peek_min(), None);

        for range in [(50..60), (30..40), (10..20)].iter() {
            r.insert(range.clone());
            assert_eq!(r.peek_min(), Some(range.clone()));
        }
    }

    #[test]
    fn pop_min() {
        let mut r = RangeSet::default();
        assert_eq!(r.pop_min(), None);

        for range in [(50..60), (30..40), (10..20)].iter() {
            r.insert(range.clone());
        }

        for range in [(10..20), (30..40), (50..60)].iter() {
            assert_eq!(r.pop_min(), Some(range.clone()));
        }

        assert_eq!(r.pop_min(), None);
    }
}
