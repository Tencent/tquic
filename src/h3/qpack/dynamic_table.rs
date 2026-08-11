// Copyright (c) 2026 The TQUIC Authors.
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

use std::collections::VecDeque;

/// The per-entry overhead defined by RFC 9204 Section 3.2.1.
const ENTRY_OVERHEAD: u64 = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynamicEntry {
    pub absolute_index: u64,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    references: usize,
}

impl DynamicEntry {
    fn new(absolute_index: u64, name: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            absolute_index,
            name,
            value,
            references: 0,
        }
    }

    pub fn size(&self) -> u64 {
        entry_size(&self.name, &self.value)
    }

    fn evictable(&self, known_received_count: u64) -> bool {
        self.absolute_index < known_received_count && self.references == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicTableError {
    CapacityTooLarge,
    EntryTooLarge,
    InvalidIndex,
}

/// A FIFO QPACK dynamic table.
///
/// Absolute indices remain stable for an entry's lifetime. Eviction only
/// removes entries from the front, so the entries retained by this structure
/// always form one contiguous range of absolute indices.
#[derive(Clone, Debug)]
pub struct DynamicTable {
    entries: VecDeque<DynamicEntry>,
    size: u64,
    capacity: u64,
    max_capacity: u64,
    insert_count: u64,
}

impl DynamicTable {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            capacity: 0,
            max_capacity,
            insert_count: 0,
        }
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    pub fn max_capacity(&self) -> u64 {
        self.max_capacity
    }

    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    pub fn set_max_capacity(&mut self, max_capacity: u64) {
        self.max_capacity = max_capacity;
    }

    /// Apply a capacity update on a decoder table.
    pub fn set_capacity(&mut self, capacity: u64) -> Result<(), DynamicTableError> {
        if capacity > self.max_capacity {
            return Err(DynamicTableError::CapacityTooLarge);
        }

        self.capacity = capacity;
        while self.size > self.capacity {
            self.evict_one()?;
        }

        Ok(())
    }

    /// Apply a capacity update on an encoder table without evicting entries
    /// that the decoder has not acknowledged or that are still referenced by
    /// an outstanding field section.
    pub fn set_encoder_capacity(
        &mut self,
        capacity: u64,
        known_received_count: u64,
    ) -> Result<bool, DynamicTableError> {
        if capacity > self.max_capacity {
            return Err(DynamicTableError::CapacityTooLarge);
        }

        let mut projected_size = self.size;
        let mut evict_count = 0;
        for entry in &self.entries {
            if projected_size <= capacity {
                break;
            }
            if !entry.evictable(known_received_count) {
                return Ok(false);
            }
            projected_size -= entry.size();
            evict_count += 1;
        }

        for _ in 0..evict_count {
            self.evict_one()?;
        }
        self.capacity = capacity;
        Ok(true)
    }

    /// Insert an entry on a decoder table. The encoder is responsible for
    /// ensuring that any evicted entries are evictable.
    pub fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) -> Result<u64, DynamicTableError> {
        let size = entry_size(&name, &value);
        if size > self.capacity {
            return Err(DynamicTableError::EntryTooLarge);
        }

        while self.size > self.capacity - size {
            self.evict_one()?;
        }

        Ok(self.push(name, value))
    }

    /// Try to insert an entry on an encoder table. `None` means insertion is
    /// currently prohibited because it would evict an unacknowledged or
    /// referenced entry, or because the entry is larger than the capacity.
    pub fn try_insert_encoder(
        &mut self,
        name: Vec<u8>,
        value: Vec<u8>,
        known_received_count: u64,
    ) -> Result<Option<u64>, DynamicTableError> {
        let size = entry_size(&name, &value);
        if size > self.capacity {
            return Ok(None);
        }

        let target_size = self.capacity - size;
        let mut projected_size = self.size;
        let mut evict_count = 0;
        for entry in &self.entries {
            if projected_size <= target_size {
                break;
            }
            if !entry.evictable(known_received_count) {
                return Ok(None);
            }
            projected_size -= entry.size();
            evict_count += 1;
        }

        if projected_size > target_size {
            return Ok(None);
        }

        for _ in 0..evict_count {
            self.evict_one()?;
        }

        Ok(Some(self.push(name, value)))
    }

    pub fn get_absolute(&self, absolute_index: u64) -> Option<&DynamicEntry> {
        let first = self.first_index();
        let offset = usize::try_from(absolute_index.checked_sub(first)?).ok()?;
        self.entries.get(offset)
    }

    pub fn get_relative(&self, relative_index: u64) -> Option<&DynamicEntry> {
        let relative = relative_index.checked_add(1)?;
        let absolute_index = self.insert_count.checked_sub(relative)?;
        self.get_absolute(absolute_index)
    }

    pub fn find_exact(&self, name: &[u8], value: &[u8]) -> Option<u64> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.name.eq_ignore_ascii_case(name) && entry.value == value)
            .map(|entry| entry.absolute_index)
    }

    pub fn find_name(&self, name: &[u8]) -> Option<u64> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.name.eq_ignore_ascii_case(name))
            .map(|entry| entry.absolute_index)
    }

    pub fn add_reference(&mut self, absolute_index: u64) -> Result<(), DynamicTableError> {
        let entry = self
            .get_absolute_mut(absolute_index)
            .ok_or(DynamicTableError::InvalidIndex)?;
        entry.references = entry
            .references
            .checked_add(1)
            .ok_or(DynamicTableError::InvalidIndex)?;
        Ok(())
    }

    pub fn release_reference(&mut self, absolute_index: u64) -> Result<(), DynamicTableError> {
        let entry = self
            .get_absolute_mut(absolute_index)
            .ok_or(DynamicTableError::InvalidIndex)?;
        entry.references = entry
            .references
            .checked_sub(1)
            .ok_or(DynamicTableError::InvalidIndex)?;
        Ok(())
    }

    fn first_index(&self) -> u64 {
        self.insert_count - self.entries.len() as u64
    }

    fn get_absolute_mut(&mut self, absolute_index: u64) -> Option<&mut DynamicEntry> {
        let first = self.first_index();
        let offset = usize::try_from(absolute_index.checked_sub(first)?).ok()?;
        self.entries.get_mut(offset)
    }

    fn push(&mut self, name: Vec<u8>, value: Vec<u8>) -> u64 {
        let absolute_index = self.insert_count;
        let entry = DynamicEntry::new(absolute_index, name, value);
        self.size += entry.size();
        self.entries.push_back(entry);
        self.insert_count += 1;
        absolute_index
    }

    fn evict_one(&mut self) -> Result<(), DynamicTableError> {
        let entry = self
            .entries
            .pop_front()
            .ok_or(DynamicTableError::InvalidIndex)?;
        self.size -= entry.size();
        Ok(())
    }
}

pub fn entry_size(name: &[u8], value: &[u8]) -> u64 {
    name.len() as u64 + value.len() as u64 + ENTRY_OVERHEAD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insertion_and_fifo_eviction() {
        let mut table = DynamicTable::new(84);
        table.set_capacity(84).unwrap();
        assert_eq!(table.insert(b"a".to_vec(), b"1".to_vec()), Ok(0));
        assert_eq!(table.insert(b"b".to_vec(), b"2".to_vec()), Ok(1));
        assert_eq!(table.insert(b"c".to_vec(), b"3".to_vec()), Ok(2));
        assert!(table.get_absolute(0).is_none());
        assert_eq!(table.get_relative(0).unwrap().name, b"c");
        assert_eq!(table.get_relative(1).unwrap().name, b"b");
    }

    #[test]
    fn encoder_preserves_referenced_entries() {
        let mut table = DynamicTable::new(68);
        assert!(table.set_encoder_capacity(68, 0).unwrap());
        let first = table
            .try_insert_encoder(b"a".to_vec(), b"1".to_vec(), 0)
            .unwrap()
            .unwrap();
        table.add_reference(first).unwrap();
        assert_eq!(
            table
                .try_insert_encoder(b"b".to_vec(), b"2".to_vec(), 1)
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            table
                .try_insert_encoder(b"c".to_vec(), b"3".to_vec(), 2)
                .unwrap(),
            None
        );
        table.release_reference(first).unwrap();
        assert_eq!(
            table
                .try_insert_encoder(b"c".to_vec(), b"3".to_vec(), 2)
                .unwrap(),
            Some(2)
        );
    }

    #[test]
    fn rejects_oversized_decoder_entry() {
        let mut table = DynamicTable::new(32);
        table.set_capacity(32).unwrap();
        assert_eq!(
            table.insert(b"a".to_vec(), Vec::new()),
            Err(DynamicTableError::EntryTooLarge)
        );
    }
}
