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

//! HTTP/3 header compression (QPACK).

use std::collections::HashMap;
use std::collections::VecDeque;

use log::trace;

use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::h3::qpack::prefix_int::*;
use crate::h3::qpack::static_table::*;
use crate::h3::Header;
use crate::h3::Http3Error;
use crate::h3::NameValue;
use crate::h3::Result;

use self::dynamic_table::DynamicTable;

// Encoder stream instructions (RFC 9204 Section 4.3).
const INSERT_WITH_NAME_REF: u8 = 0b1000_0000;
const INSERT_WITH_LITERAL_NAME: u8 = 0b0100_0000;
const SET_DYNAMIC_TABLE_CAPACITY: u8 = 0b0010_0000;

// Decoder stream instructions (RFC 9204 Section 4.4).
const SECTION_ACKNOWLEDGMENT: u8 = 0b1000_0000;
const STREAM_CANCELLATION: u8 = 0b0100_0000;

/// An indexed field line representation starts with the '1' 1-bit pattern,
/// followed by the 'T' bit, indicating whether the reference is into the
/// static or dynamic table.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 1 | T |      Index (6+)       |
/// +---+---+-----------------------+
const INDEXED: u8 = 0b1000_0000;

/// An indexed field line with post-Base index representation starts with
/// the '0001' 4-bit pattern.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 0 | 0 | 1 |  Index (4+)   |
/// +---+---+---+---+---------------+
const INDEXED_WITH_POST_BASE: u8 = 0b0001_0000;

/// A literal field line with name reference representation starts with
/// the '01' 2-bit pattern.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 1 | N | T |Name Index (4+)|
/// +---+---+---+---+---------------+
/// | H |     Value Length (7+)     |
/// +---+---------------------------+
/// |  Value String (Length bytes)  |
/// +-------------------------------+
const LITERAL_WITH_NAME_REF: u8 = 0b0100_0000;

/// A literal field line with post-Base name reference representation
/// starts with the '0000' 4-bit pattern.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
/// +---+---+---+---+---+-----------+
/// | H |     Value Length (7+)     |
/// +---+---------------------------+
/// |  Value String (Length bytes)  |
/// +-------------------------------+
const LITERAL_WITH_POST_BASE: u8 = 0b0000_0000;

/// The literal field line with literal name representation starts with
/// the '001' 3-bit pattern.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 0 | 1 | N | H |NameLen(3+)|
/// +---+---+---+---+---+-----------+
/// |  Name String (Length bytes)   |
/// +---+---------------------------+
/// | H |     Value Length (7+)     |
/// +---+---------------------------+
/// |  Value String (Length bytes)  |
/// +-------------------------------+
const LITERAL: u8 = 0b0010_0000;

/// Each representation corresponds to a single field line. It reference the
/// static table or the dynamic table in a particular state, but do not modify
/// that state.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Representation {
    /// An indexed field line representation identifies an entry in the static
    /// table or an entry in the dynamic table with an absolute index less than
    /// the value of the Base
    Indexed,

    /// An indexed field line with post-Base index representation identifies an
    /// entry in the dynamic table with an absolute index greater than or equal
    /// to the value of the Base.
    IndexedWithPostBase,

    /// A literal field line with name reference representation encodes a field
    /// line where the field name matches the field name of an entry in the
    /// static table or the field name of an entry in the dynamic table with an
    /// absolute index less than the value of the Base.
    LiteralWithNameRef,

    /// A literal field line with post-Base name reference representation encodes
    /// a field line where the field name matches the field name of a dynamic
    /// table entry with an absolute index greater than or equal to the value of
    /// the Base.
    LiteralWithPostBase,

    /// The literal field line with literal name representation encodes a field
    /// name and a field value as string literals.
    Literal,
}

impl Representation {
    pub fn from(b: u8) -> Representation {
        if b & INDEXED == INDEXED {
            return Representation::Indexed;
        }
        if b & LITERAL_WITH_NAME_REF == LITERAL_WITH_NAME_REF {
            return Representation::LiteralWithNameRef;
        }
        if b & LITERAL == LITERAL {
            return Representation::Literal;
        }
        if b & INDEXED_WITH_POST_BASE == INDEXED_WITH_POST_BASE {
            return Representation::IndexedWithPostBase;
        }
        Representation::LiteralWithPostBase
    }
}

#[derive(Clone, Debug)]
struct OutstandingSection {
    required_insert_count: u64,
    references: Vec<u64>,
}

#[derive(Clone, Debug)]
enum PlannedField {
    StaticIndexed(u64),
    DynamicIndexed(u64),
    StaticName {
        index: u64,
        value: Vec<u8>,
        never_index: bool,
    },
    DynamicName {
        absolute_index: u64,
        value: Vec<u8>,
        never_index: bool,
    },
    Literal {
        name: Vec<u8>,
        value: Vec<u8>,
        never_index: bool,
    },
}

/// A QPACK encoder.
///
/// The encoder deliberately references only entries covered by the Known
/// Received Count. This conservative policy avoids creating blocked streams
/// while still compressing repeated field lines after the decoder confirms an
/// insertion.
#[derive(Clone, Debug)]
pub struct QpackEncoder {
    table: DynamicTable,
    known_received_count: u64,
    pending_capacity: Option<u64>,
    decoder_stream_buf: Vec<u8>,
    outstanding: HashMap<u64, VecDeque<OutstandingSection>>,
}

impl Default for QpackEncoder {
    fn default() -> Self {
        Self {
            table: DynamicTable::new(0),
            known_received_count: 0,
            pending_capacity: None,
            decoder_stream_buf: Vec::new(),
            outstanding: HashMap::new(),
        }
    }
}

impl QpackEncoder {
    pub fn new() -> QpackEncoder {
        QpackEncoder::default()
    }

    /// Update the maximum capacity advertised by the peer. The matching Set
    /// Dynamic Table Capacity instruction is emitted with the first insertion.
    pub fn set_max_capacity(&mut self, capacity: u64) -> Result<()> {
        self.table.set_max_capacity(capacity);
        if !self
            .table
            .set_encoder_capacity(capacity, self.known_received_count)
            .map_err(|_| Http3Error::QpackDecoderStreamError)?
        {
            return Err(Http3Error::QpackDecoderStreamError);
        }
        self.pending_capacity = (capacity > 0).then_some(capacity);
        Ok(())
    }

    /// Encode a list of headers into a QPACK field section without associating
    /// the section with an HTTP stream. This preserves the original unit-level
    /// API and uses the static table when no peer capacity has been configured.
    pub fn encode<T: NameValue>(&mut self, headers: &[T], out: &mut [u8]) -> Result<usize> {
        self.encode_transactional(None, headers, out)
            .map(|(field_len, _)| field_len)
    }

    /// Encode a field section for an HTTP stream and return encoder-stream
    /// instructions that must be written before the field section.
    pub fn encode_for_stream<T: NameValue>(
        &mut self,
        stream_id: u64,
        headers: &[T],
        out: &mut [u8],
    ) -> Result<(usize, Vec<u8>)> {
        self.encode_transactional(Some(stream_id), headers, out)
    }

    fn encode_transactional<T: NameValue>(
        &mut self,
        stream_id: Option<u64>,
        headers: &[T],
        out: &mut [u8],
    ) -> Result<(usize, Vec<u8>)> {
        let mut next = self.clone();
        let result = next.encode_inner(stream_id, headers, out)?;
        *self = next;
        Ok(result)
    }

    fn encode_inner<T: NameValue>(
        &mut self,
        stream_id: Option<u64>,
        headers: &[T],
        out: &mut [u8],
    ) -> Result<(usize, Vec<u8>)> {
        let allow_dynamic = stream_id.is_some();
        let mut fields = Vec::with_capacity(headers.len());
        let mut references = Vec::new();
        let mut instructions = Vec::new();

        for hdr in headers {
            let never_index = is_sensitive(hdr.name());
            let static_match = encode_static(hdr);

            let field = if !never_index && matches!(static_match, Some((_, true))) {
                PlannedField::StaticIndexed(static_match.unwrap().0)
            } else if !never_index && allow_dynamic {
                match self.table.find_exact(hdr.name(), hdr.value()) {
                    Some(absolute_index) if absolute_index < self.known_received_count => {
                        self.add_reference(absolute_index, &mut references)?;
                        PlannedField::DynamicIndexed(absolute_index)
                    }
                    _ => self.plan_literal(
                        hdr,
                        static_match,
                        never_index,
                        allow_dynamic,
                        &mut references,
                    )?,
                }
            } else {
                self.plan_literal(
                    hdr,
                    static_match,
                    never_index,
                    allow_dynamic,
                    &mut references,
                )?
            };

            if !never_index && allow_dynamic {
                self.maybe_insert(hdr, &mut instructions)?;
            }
            fields.push(field);
        }

        let required_insert_count = match references.iter().copied().max() {
            Some(index) => index.checked_add(1).ok_or(Http3Error::InternalError)?,
            None => 0,
        };
        let base = required_insert_count;
        let encoded_insert_count =
            encode_required_insert_count(required_insert_count, self.table.max_capacity())?;

        let mut off = encode_int(encoded_insert_count, 0, 8, out)?;
        off += encode_int(0, 0, 7, &mut out[off..])?;

        for field in fields {
            match field {
                PlannedField::StaticIndexed(index) => {
                    const STATIC: u8 = 0x40;
                    off += encode_int(index, INDEXED | STATIC, 6, &mut out[off..])?;
                    trace!("QpackEncoder Indexed index={} static=true", index);
                }
                PlannedField::DynamicIndexed(absolute_index) => {
                    let relative = absolute_index
                        .checked_add(1)
                        .ok_or(Http3Error::InternalError)?;
                    let index = base
                        .checked_sub(relative)
                        .ok_or(Http3Error::InternalError)?;
                    off += encode_int(index, INDEXED, 6, &mut out[off..])?;
                    trace!("QpackEncoder Indexed index={} static=false", index);
                }
                PlannedField::StaticName {
                    index,
                    value,
                    never_index,
                } => {
                    const STATIC: u8 = 0x10;
                    let first = LITERAL_WITH_NAME_REF | STATIC | if never_index { 0x20 } else { 0 };
                    off += encode_int(index, first, 4, &mut out[off..])?;
                    off += encode_string(&value, 0, 7, false, &mut out[off..])?;
                }
                PlannedField::DynamicName {
                    absolute_index,
                    value,
                    never_index,
                } => {
                    let relative = absolute_index
                        .checked_add(1)
                        .ok_or(Http3Error::InternalError)?;
                    let index = base
                        .checked_sub(relative)
                        .ok_or(Http3Error::InternalError)?;
                    let first = LITERAL_WITH_NAME_REF | if never_index { 0x20 } else { 0 };
                    off += encode_int(index, first, 4, &mut out[off..])?;
                    off += encode_string(&value, 0, 7, false, &mut out[off..])?;
                }
                PlannedField::Literal {
                    name,
                    value,
                    never_index,
                } => {
                    let first = LITERAL | if never_index { 0x10 } else { 0 };
                    off += encode_string(&name, first, 3, true, &mut out[off..])?;
                    off += encode_string(&value, 0, 7, false, &mut out[off..])?;
                }
            }
        }

        if let (Some(stream_id), false) = (stream_id, references.is_empty()) {
            self.outstanding
                .entry(stream_id)
                .or_default()
                .push_back(OutstandingSection {
                    required_insert_count,
                    references,
                });
        }

        Ok((off, instructions))
    }

    fn plan_literal<T: NameValue>(
        &mut self,
        hdr: &T,
        static_match: Option<(u64, bool)>,
        never_index: bool,
        allow_dynamic: bool,
        references: &mut Vec<u64>,
    ) -> Result<PlannedField> {
        if let Some((index, _)) = static_match {
            return Ok(PlannedField::StaticName {
                index,
                value: hdr.value().to_vec(),
                never_index,
            });
        }

        if !never_index && allow_dynamic {
            if let Some(absolute_index) = self.table.find_name(hdr.name()) {
                if absolute_index < self.known_received_count {
                    self.add_reference(absolute_index, references)?;
                    return Ok(PlannedField::DynamicName {
                        absolute_index,
                        value: hdr.value().to_vec(),
                        never_index,
                    });
                }
            }
        }

        Ok(PlannedField::Literal {
            name: hdr.name().to_ascii_lowercase(),
            value: hdr.value().to_vec(),
            never_index,
        })
    }

    fn add_reference(&mut self, absolute_index: u64, references: &mut Vec<u64>) -> Result<()> {
        self.table
            .add_reference(absolute_index)
            .map_err(|_| Http3Error::InternalError)?;
        references.push(absolute_index);
        Ok(())
    }

    fn maybe_insert<T: NameValue>(&mut self, hdr: &T, instructions: &mut Vec<u8>) -> Result<()> {
        if self.table.capacity() == 0
            || matches!(encode_static(hdr), Some((_, true)))
            || self.table.find_exact(hdr.name(), hdr.value()).is_some()
        {
            return Ok(());
        }

        let static_name = encode_static(hdr).map(|(index, _)| index);
        let dynamic_name = self.table.find_name(hdr.name()).map(|absolute_index| {
            (
                absolute_index,
                self.table.insert_count() - absolute_index - 1,
            )
        });
        let name = hdr.name().to_ascii_lowercase();
        let value = hdr.value().to_vec();

        let inserted = self
            .table
            .try_insert_encoder(name.clone(), value.clone(), self.known_received_count)
            .map_err(|_| Http3Error::InternalError)?;
        if inserted.is_none() {
            return Ok(());
        }

        if let Some(capacity) = self.pending_capacity.take() {
            append_int(instructions, capacity, SET_DYNAMIC_TABLE_CAPACITY, 5)?;
        }

        if let Some(index) = static_name {
            append_int(instructions, index, INSERT_WITH_NAME_REF | 0x40, 6)?;
            append_string(instructions, &value, 0, 7, false)?;
        } else if let Some((_, relative_index)) = dynamic_name {
            append_int(instructions, relative_index, INSERT_WITH_NAME_REF, 6)?;
            append_string(instructions, &value, 0, 7, false)?;
        } else {
            append_string(instructions, &name, INSERT_WITH_LITERAL_NAME, 5, true)?;
            append_string(instructions, &value, 0, 7, false)?;
        }

        Ok(())
    }

    /// Process decoder-stream acknowledgments and insert-count updates.
    pub fn process_decoder_instructions(&mut self, data: &[u8]) -> Result<()> {
        self.decoder_stream_buf.extend_from_slice(data);

        let mut consumed = 0;
        while consumed < self.decoder_stream_buf.len() {
            let buf = &self.decoder_stream_buf[consumed..];
            let first = buf[0];
            let (value, len) = if first & SECTION_ACKNOWLEDGMENT != 0 {
                match decode_int_partial(buf, 7).map_err(|_| Http3Error::QpackDecoderStreamError)? {
                    Some(v) => v,
                    None => break,
                }
            } else {
                match decode_int_partial(buf, 6).map_err(|_| Http3Error::QpackDecoderStreamError)? {
                    Some(v) => v,
                    None => break,
                }
            };

            if first & SECTION_ACKNOWLEDGMENT != 0 {
                self.acknowledge_section(value)?;
            } else if first & 0xc0 == STREAM_CANCELLATION {
                self.cancel_stream(value)?;
            } else {
                self.increment_known_received(value)?;
            }
            consumed += len;
        }

        self.decoder_stream_buf.drain(..consumed);
        Ok(())
    }

    fn acknowledge_section(&mut self, stream_id: u64) -> Result<()> {
        let section = {
            let sections = self
                .outstanding
                .get_mut(&stream_id)
                .ok_or(Http3Error::QpackDecoderStreamError)?;
            sections
                .pop_front()
                .ok_or(Http3Error::QpackDecoderStreamError)?
        };
        if self
            .outstanding
            .get(&stream_id)
            .is_some_and(VecDeque::is_empty)
        {
            self.outstanding.remove(&stream_id);
        }

        self.known_received_count = self.known_received_count.max(section.required_insert_count);
        self.release_references(section.references)
    }

    fn cancel_stream(&mut self, stream_id: u64) -> Result<()> {
        let Some(sections) = self.outstanding.remove(&stream_id) else {
            return Ok(());
        };
        for section in sections {
            self.release_references(section.references)?;
        }
        Ok(())
    }

    fn increment_known_received(&mut self, increment: u64) -> Result<()> {
        let known_received_count = self
            .known_received_count
            .checked_add(increment)
            .ok_or(Http3Error::QpackDecoderStreamError)?;
        if increment == 0 || known_received_count > self.table.insert_count() {
            return Err(Http3Error::QpackDecoderStreamError);
        }
        self.known_received_count = known_received_count;
        Ok(())
    }

    fn release_references(&mut self, references: Vec<u64>) -> Result<()> {
        for absolute_index in references {
            self.table
                .release_reference(absolute_index)
                .map_err(|_| Http3Error::QpackDecoderStreamError)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeStatus {
    Decoded {
        headers: Vec<Header>,
        consumed: usize,
        decoder_instructions: Vec<u8>,
    },
    Blocked {
        required_insert_count: u64,
    },
}

#[derive(Debug)]
enum EncoderInstruction {
    SetCapacity(u64),
    InsertWithNameReference {
        static_table: bool,
        index: u64,
        value: Vec<u8>,
    },
    InsertWithLiteralName {
        name: Vec<u8>,
        value: Vec<u8>,
    },
    Duplicate(u64),
}

/// A QPACK decoder.
#[derive(Debug)]
pub struct QpackDecoder {
    table: DynamicTable,
    encoder_stream_buf: Vec<u8>,
    reported_insert_count: u64,
}

impl Default for QpackDecoder {
    fn default() -> Self {
        Self::with_max_capacity(0)
    }
}

impl QpackDecoder {
    pub fn new() -> QpackDecoder {
        QpackDecoder::default()
    }

    pub fn with_max_capacity(max_capacity: u64) -> QpackDecoder {
        QpackDecoder {
            table: DynamicTable::new(max_capacity),
            encoder_stream_buf: Vec::new(),
            reported_insert_count: 0,
        }
    }

    pub fn insert_count(&self) -> u64 {
        self.table.insert_count()
    }

    pub fn stream_cancellation(&self, stream_id: u64) -> Result<Vec<u8>> {
        if self.table.max_capacity() == 0 {
            return Ok(Vec::new());
        }
        let mut instruction = Vec::new();
        append_int(&mut instruction, stream_id, STREAM_CANCELLATION, 6)?;
        Ok(instruction)
    }

    /// Decode a QPACK header block into a list of headers.
    pub fn decode(&mut self, buf: &[u8], max_size: u64) -> Result<(Vec<Header>, usize)> {
        match self.decode_field_section(0, buf, max_size)? {
            DecodeStatus::Decoded {
                headers, consumed, ..
            } => Ok((headers, consumed)),
            DecodeStatus::Blocked { .. } => Err(Http3Error::Done),
        }
    }

    pub fn decode_field_section(
        &mut self,
        stream_id: u64,
        mut buf: &[u8],
        max_size: u64,
    ) -> Result<DecodeStatus> {
        let buf_len = buf.len();
        let mut out = Vec::new();
        let mut left = max_size;
        let mut largest_reference = None;

        let (encoded_insert_count, off) = decode_int(buf, 8)?;
        buf = &buf[off..];

        if buf.is_empty() {
            return Err(Http3Error::QpackDecompressionFailed);
        }
        let sign = buf[0] & 0x80 != 0;
        let (delta_base, off) = decode_int(buf, 7)?;
        buf = &buf[off..];

        let required_insert_count = decode_required_insert_count(
            encoded_insert_count,
            self.table.insert_count(),
            self.table.max_capacity(),
        )?;
        let base = if sign {
            let delta_base = delta_base
                .checked_add(1)
                .ok_or(Http3Error::QpackDecompressionFailed)?;
            required_insert_count
                .checked_sub(delta_base)
                .ok_or(Http3Error::QpackDecompressionFailed)?
        } else {
            required_insert_count
                .checked_add(delta_base)
                .ok_or(Http3Error::QpackDecompressionFailed)?
        };

        trace!(
            "QpackDecoder Header count={} base={}",
            required_insert_count,
            base
        );

        if required_insert_count > self.table.insert_count() {
            return Ok(DecodeStatus::Blocked {
                required_insert_count,
            });
        }

        while !buf.is_empty() {
            let first = buf[0];
            match Representation::from(first) {
                Representation::Indexed => {
                    const STATIC: u8 = 0x40;
                    let static_idx = first & STATIC == STATIC;
                    let (index, off) = decode_int(buf, 6)?;
                    buf = &buf[off..];

                    let (name, value) = if static_idx {
                        let (name, value) = decode_static(index)?;
                        (name.to_vec(), value.to_vec())
                    } else {
                        let absolute_index = relative_absolute(base, index, required_insert_count)?;
                        update_largest_reference(&mut largest_reference, absolute_index);
                        let entry = self
                            .table
                            .get_absolute(absolute_index)
                            .ok_or(Http3Error::QpackDecompressionFailed)?;
                        (entry.name.clone(), entry.value.clone())
                    };

                    charge_field(&mut left, &name, &value)?;
                    out.push(Header(name, value));
                }

                Representation::IndexedWithPostBase => {
                    let (index, off) = decode_int(buf, 4)?;
                    buf = &buf[off..];
                    let absolute_index = post_base_absolute(base, index, required_insert_count)?;
                    update_largest_reference(&mut largest_reference, absolute_index);
                    let entry = self
                        .table
                        .get_absolute(absolute_index)
                        .ok_or(Http3Error::QpackDecompressionFailed)?;
                    let name = entry.name.clone();
                    let value = entry.value.clone();
                    charge_field(&mut left, &name, &value)?;
                    out.push(Header(name, value));
                }

                Representation::LiteralWithNameRef => {
                    const STATIC: u8 = 0x10;
                    let static_idx = first & STATIC == STATIC;
                    let (name_idx, off) = decode_int(buf, 4)?;
                    buf = &buf[off..];
                    let (value, off) = self.decode_str(buf)?;
                    buf = &buf[off..];

                    let name = if static_idx {
                        decode_static(name_idx)?.0.to_vec()
                    } else {
                        let absolute_index =
                            relative_absolute(base, name_idx, required_insert_count)?;
                        update_largest_reference(&mut largest_reference, absolute_index);
                        self.table
                            .get_absolute(absolute_index)
                            .ok_or(Http3Error::QpackDecompressionFailed)?
                            .name
                            .clone()
                    };

                    charge_field(&mut left, &name, &value)?;
                    out.push(Header(name, value));
                }

                Representation::LiteralWithPostBase => {
                    let (name_idx, off) = decode_int(buf, 3)?;
                    buf = &buf[off..];
                    let (value, off) = self.decode_str(buf)?;
                    buf = &buf[off..];
                    let absolute_index = post_base_absolute(base, name_idx, required_insert_count)?;
                    update_largest_reference(&mut largest_reference, absolute_index);
                    let name = self
                        .table
                        .get_absolute(absolute_index)
                        .ok_or(Http3Error::QpackDecompressionFailed)?
                        .name
                        .clone();
                    charge_field(&mut left, &name, &value)?;
                    out.push(Header(name, value));
                }

                Representation::Literal => {
                    let name_huff = buf[0] & 0x08 == 0x08;
                    let (name_len, off) = decode_int(buf, 3)?;
                    buf = &buf[off..];

                    let name = buf.read(name_len as usize)?;
                    let name = if name_huff {
                        huffman::decode(&name)?
                    } else {
                        name.to_vec()
                    };
                    let (value, off) = self.decode_str(buf)?;
                    buf = &buf[off..];

                    charge_field(&mut left, &name, &value)?;
                    out.push(Header(name, value));
                }
            }
        }

        let expected_required_insert_count = match largest_reference {
            Some(index) => index
                .checked_add(1)
                .ok_or(Http3Error::QpackDecompressionFailed)?,
            None => 0,
        };
        if expected_required_insert_count != required_insert_count {
            return Err(Http3Error::QpackDecompressionFailed);
        }

        let mut decoder_instructions = Vec::new();
        if required_insert_count != 0 {
            append_int(
                &mut decoder_instructions,
                stream_id,
                SECTION_ACKNOWLEDGMENT,
                7,
            )?;
        }

        Ok(DecodeStatus::Decoded {
            headers: out,
            consumed: buf_len - buf.len(),
            decoder_instructions,
        })
    }

    /// Decode a string in Huffman encoding or literal form.
    fn decode_str(&self, buf: &[u8]) -> Result<(Vec<u8>, usize)> {
        decode_string_partial(buf, 7)?.ok_or(Http3Error::QpackDecompressionFailed)
    }

    /// Process control instructions from the encoder and return decoder-stream
    /// Insert Count Increment feedback.
    pub fn process_encoder_instructions(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.encoder_stream_buf.extend_from_slice(data);

        let mut consumed = 0;
        while consumed < self.encoder_stream_buf.len() {
            let Some((instruction, len)) =
                parse_encoder_instruction(&self.encoder_stream_buf[consumed..])
                    .map_err(|_| Http3Error::QpackEncoderStreamError)?
            else {
                break;
            };
            self.apply_encoder_instruction(instruction)?;
            consumed += len;
        }
        self.encoder_stream_buf.drain(..consumed);

        let mut feedback = Vec::new();
        let increment = self.table.insert_count() - self.reported_insert_count;
        if increment != 0 {
            append_int(&mut feedback, increment, 0, 6)
                .map_err(|_| Http3Error::QpackEncoderStreamError)?;
            self.reported_insert_count = self.table.insert_count();
        }
        Ok(feedback)
    }

    fn apply_encoder_instruction(&mut self, instruction: EncoderInstruction) -> Result<()> {
        match instruction {
            EncoderInstruction::SetCapacity(capacity) => self
                .table
                .set_capacity(capacity)
                .map_err(|_| Http3Error::QpackEncoderStreamError),
            EncoderInstruction::InsertWithNameReference {
                static_table,
                index,
                value,
            } => {
                let name = if static_table {
                    decode_static(index)
                        .map_err(|_| Http3Error::QpackEncoderStreamError)?
                        .0
                        .to_vec()
                } else {
                    self.table
                        .get_relative(index)
                        .ok_or(Http3Error::QpackEncoderStreamError)?
                        .name
                        .clone()
                };
                self.table
                    .insert(name, value)
                    .map(|_| ())
                    .map_err(|_| Http3Error::QpackEncoderStreamError)
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => self
                .table
                .insert(name, value)
                .map(|_| ())
                .map_err(|_| Http3Error::QpackEncoderStreamError),
            EncoderInstruction::Duplicate(index) => {
                let entry = self
                    .table
                    .get_relative(index)
                    .ok_or(Http3Error::QpackEncoderStreamError)?;
                let name = entry.name.clone();
                let value = entry.value.clone();
                self.table
                    .insert(name, value)
                    .map(|_| ())
                    .map_err(|_| Http3Error::QpackEncoderStreamError)
            }
        }
    }

    /// Backwards-compatible control-stream entry point.
    pub fn process(&mut self, buf: &mut [u8]) -> Result<()> {
        self.process_encoder_instructions(buf).map(|_| ())
    }
}

fn is_sensitive(name: &[u8]) -> bool {
    [
        b"authorization".as_slice(),
        b"proxy-authorization".as_slice(),
        b"cookie".as_slice(),
        b"set-cookie".as_slice(),
    ]
    .iter()
    .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
}

fn encode_string(
    value: &[u8],
    first: u8,
    prefix: usize,
    lower_case: bool,
    out: &mut [u8],
) -> Result<usize> {
    let huffman_len = huffman::encode_output_length(value, lower_case);
    if huffman_len < value.len() {
        let huffman_bit = 1u8
            .checked_shl(prefix as u32)
            .ok_or(Http3Error::InternalError)?;
        let mut off = encode_int(huffman_len as u64, first | huffman_bit, prefix, out)?;
        off += huffman::encode(value, &mut out[off..], lower_case)?;
        Ok(off)
    } else {
        let encoded = if lower_case {
            value.to_ascii_lowercase()
        } else {
            value.to_vec()
        };
        let mut off = encode_int(encoded.len() as u64, first, prefix, out)?;
        let mut buf = &mut out[off..];
        off += buf.write(&encoded)?;
        Ok(off)
    }
}

fn append_int(out: &mut Vec<u8>, value: u64, first: u8, prefix: usize) -> Result<()> {
    let mut buf = [0; 16];
    let len = encode_int(value, first, prefix, &mut buf)?;
    out.extend_from_slice(&buf[..len]);
    Ok(())
}

fn append_string(
    out: &mut Vec<u8>,
    value: &[u8],
    first: u8,
    prefix: usize,
    lower_case: bool,
) -> Result<()> {
    let mut buf = vec![0; value.len() + 32];
    let len = encode_string(value, first, prefix, lower_case, &mut buf)?;
    out.extend_from_slice(&buf[..len]);
    Ok(())
}

fn decode_int_partial(buf: &[u8], prefix: usize) -> Result<Option<(u64, usize)>> {
    if buf.is_empty() {
        return Ok(None);
    }

    let mask = 2u64
        .checked_pow(prefix as u32)
        .and_then(|value| value.checked_sub(1))
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    let mut value = u64::from(buf[0]) & mask;
    if value < mask {
        return Ok(Some((value, 1)));
    }

    let mut shift = 0;
    for (offset, byte) in buf[1..].iter().copied().enumerate() {
        if shift >= 62 {
            return Err(Http3Error::QpackDecompressionFailed);
        }
        let increment = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(Http3Error::QpackDecompressionFailed)?;
        value = value
            .checked_add(increment)
            .filter(|value| *value <= MAX_QPACK_INT)
            .ok_or(Http3Error::QpackDecompressionFailed)?;
        if byte & 0x80 == 0 {
            return Ok(Some((value, offset + 2)));
        }
        shift += 7;
    }

    Ok(None)
}

fn decode_string_partial(buf: &[u8], prefix: usize) -> Result<Option<(Vec<u8>, usize)>> {
    if buf.is_empty() {
        return Ok(None);
    }

    let huffman_bit = 1u8
        .checked_shl(prefix as u32)
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    let huffman_encoded = buf[0] & huffman_bit != 0;
    let Some((length, prefix_len)) = decode_int_partial(buf, prefix)? else {
        return Ok(None);
    };
    let length = usize::try_from(length).map_err(|_| Http3Error::QpackDecompressionFailed)?;
    let end = prefix_len
        .checked_add(length)
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    if buf.len() < end {
        return Ok(None);
    }

    let encoded = &buf[prefix_len..end];
    let value = if huffman_encoded {
        huffman::decode(encoded)?
    } else {
        encoded.to_vec()
    };
    Ok(Some((value, end)))
}

fn encode_required_insert_count(required_insert_count: u64, max_capacity: u64) -> Result<u64> {
    if required_insert_count == 0 {
        return Ok(0);
    }

    let max_entries = max_capacity / 32;
    let full_range = max_entries
        .checked_mul(2)
        .filter(|value| *value != 0)
        .ok_or(Http3Error::InternalError)?;
    Ok(required_insert_count % full_range + 1)
}

fn decode_required_insert_count(
    encoded_insert_count: u64,
    total_insert_count: u64,
    max_capacity: u64,
) -> Result<u64> {
    if encoded_insert_count == 0 {
        return Ok(0);
    }

    let max_entries = max_capacity / 32;
    let full_range = max_entries
        .checked_mul(2)
        .filter(|value| *value != 0)
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    if encoded_insert_count > full_range {
        return Err(Http3Error::QpackDecompressionFailed);
    }

    let max_value = total_insert_count
        .checked_add(max_entries)
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    let max_wrapped = max_value / full_range * full_range;
    let mut required_insert_count = max_wrapped
        .checked_add(encoded_insert_count - 1)
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    if required_insert_count > max_value {
        if required_insert_count <= full_range {
            return Err(Http3Error::QpackDecompressionFailed);
        }
        required_insert_count -= full_range;
    }
    if required_insert_count == 0 {
        return Err(Http3Error::QpackDecompressionFailed);
    }
    Ok(required_insert_count)
}

fn parse_encoder_instruction(buf: &[u8]) -> Result<Option<(EncoderInstruction, usize)>> {
    if buf.is_empty() {
        return Ok(None);
    }

    let first = buf[0];
    if first & INSERT_WITH_NAME_REF != 0 {
        let Some((index, prefix_len)) = decode_int_partial(buf, 6)? else {
            return Ok(None);
        };
        let Some((value, value_len)) = decode_string_partial(&buf[prefix_len..], 7)? else {
            return Ok(None);
        };
        return Ok(Some((
            EncoderInstruction::InsertWithNameReference {
                static_table: first & 0x40 != 0,
                index,
                value,
            },
            prefix_len + value_len,
        )));
    }

    if first & 0xc0 == INSERT_WITH_LITERAL_NAME {
        let Some((name, name_len)) = decode_string_partial(buf, 5)? else {
            return Ok(None);
        };
        let Some((value, value_len)) = decode_string_partial(&buf[name_len..], 7)? else {
            return Ok(None);
        };
        return Ok(Some((
            EncoderInstruction::InsertWithLiteralName { name, value },
            name_len + value_len,
        )));
    }

    if first & 0xe0 == SET_DYNAMIC_TABLE_CAPACITY {
        let Some((capacity, len)) = decode_int_partial(buf, 5)? else {
            return Ok(None);
        };
        return Ok(Some((EncoderInstruction::SetCapacity(capacity), len)));
    }

    let Some((index, len)) = decode_int_partial(buf, 5)? else {
        return Ok(None);
    };
    Ok(Some((EncoderInstruction::Duplicate(index), len)))
}

fn relative_absolute(base: u64, index: u64, required_insert_count: u64) -> Result<u64> {
    let relative = index
        .checked_add(1)
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    let absolute_index = base
        .checked_sub(relative)
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    if absolute_index >= required_insert_count {
        return Err(Http3Error::QpackDecompressionFailed);
    }
    Ok(absolute_index)
}

fn post_base_absolute(base: u64, index: u64, required_insert_count: u64) -> Result<u64> {
    let absolute_index = base
        .checked_add(index)
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    if absolute_index >= required_insert_count {
        return Err(Http3Error::QpackDecompressionFailed);
    }
    Ok(absolute_index)
}

fn update_largest_reference(largest_reference: &mut Option<u64>, absolute_index: u64) {
    *largest_reference =
        Some(largest_reference.map_or(absolute_index, |current| current.max(absolute_index)));
}

fn charge_field(left: &mut u64, name: &[u8], value: &[u8]) -> Result<()> {
    let field_size = (name.len() as u64)
        .checked_add(value.len() as u64)
        .and_then(|size| size.checked_add(32))
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    *left = left
        .checked_sub(field_size)
        .ok_or(Http3Error::QpackDecompressionFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3;

    #[test]
    fn static_table() {
        let mut encoded = [0u8; 158];

        let headers = vec![
            h3::Header::new(b":authority", b""),
            h3::Header::new(b":path", b"/"),
            h3::Header::new(b"age", b"0"),
            h3::Header::new(b"content-disposition", b""),
            h3::Header::new(b"content-length", b"0"),
            h3::Header::new(b"cookie", b""),
            h3::Header::new(b"date", b""),
            h3::Header::new(b"etag", b""),
            h3::Header::new(b"if-modified-since", b""),
            h3::Header::new(b"if-none-match", b""),
            h3::Header::new(b"last-modified", b""),
            h3::Header::new(b"link", b""),
            h3::Header::new(b"location", b""),
            h3::Header::new(b"referer", b""),
            h3::Header::new(b"set-cookie", b""),
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":method", b"DELETE"),
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b":method", b"HEAD"),
            h3::Header::new(b":method", b"OPTIONS"),
            h3::Header::new(b":method", b"POST"),
            h3::Header::new(b":method", b"PUT"),
            h3::Header::new(b":scheme", b"http"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":status", b"103"),
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b":status", b"304"),
            h3::Header::new(b":status", b"404"),
            h3::Header::new(b":status", b"503"),
            h3::Header::new(b"accept", b"*/*"),
            h3::Header::new(b"accept", b"application/dns-message"),
            h3::Header::new(b"accept-encoding", b"gzip, deflate, br"),
            h3::Header::new(b"accept-ranges", b"bytes"),
            h3::Header::new(b"access-control-allow-headers", b"cache-control"),
            h3::Header::new(b"access-control-allow-headers", b"content-type"),
            h3::Header::new(b"access-control-allow-origin", b"*"),
            h3::Header::new(b"cache-control", b"max-age=0"),
            h3::Header::new(b"cache-control", b"max-age=2592000"),
            h3::Header::new(b"cache-control", b"max-age=604800"),
            h3::Header::new(b"cache-control", b"no-cache"),
            h3::Header::new(b"cache-control", b"no-store"),
            h3::Header::new(b"cache-control", b"public, max-age=31536000"),
            h3::Header::new(b"content-encoding", b"br"),
            h3::Header::new(b"content-encoding", b"gzip"),
            h3::Header::new(b"content-type", b"application/dns-message"),
            h3::Header::new(b"content-type", b"application/javascript"),
            h3::Header::new(b"content-type", b"application/json"),
            h3::Header::new(b"content-type", b"application/x-www-form-urlencoded"),
            h3::Header::new(b"content-type", b"image/gif"),
            h3::Header::new(b"content-type", b"image/jpeg"),
            h3::Header::new(b"content-type", b"image/png"),
            h3::Header::new(b"content-type", b"text/css"),
            h3::Header::new(b"content-type", b"text/html; charset=utf-8"),
            h3::Header::new(b"content-type", b"text/plain"),
            h3::Header::new(b"content-type", b"text/plain;charset=utf-8"),
            h3::Header::new(b"range", b"bytes=0-"),
            h3::Header::new(b"strict-transport-security", b"max-age=31536000"),
            h3::Header::new(
                b"strict-transport-security",
                b"max-age=31536000; includesubdomains",
            ),
            h3::Header::new(
                b"strict-transport-security",
                b"max-age=31536000; includesubdomains; preload",
            ),
            h3::Header::new(b"vary", b"accept-encoding"),
            h3::Header::new(b"vary", b"origin"),
            h3::Header::new(b"x-content-type-options", b"nosniff"),
            h3::Header::new(b"x-xss-protection", b"1; mode=block"),
            h3::Header::new(b":status", b"100"),
            h3::Header::new(b":status", b"204"),
            h3::Header::new(b":status", b"206"),
            h3::Header::new(b":status", b"302"),
            h3::Header::new(b":status", b"400"),
            h3::Header::new(b":status", b"403"),
            h3::Header::new(b":status", b"421"),
            h3::Header::new(b":status", b"425"),
            h3::Header::new(b":status", b"500"),
            h3::Header::new(b"accept-language", b""),
            h3::Header::new(b"access-control-allow-credentials", b"FALSE"),
            h3::Header::new(b"access-control-allow-credentials", b"TRUE"),
            h3::Header::new(b"access-control-allow-headers", b"*"),
            h3::Header::new(b"access-control-allow-methods", b"get"),
            h3::Header::new(b"access-control-allow-methods", b"get, post, options"),
            h3::Header::new(b"access-control-allow-methods", b"options"),
            h3::Header::new(b"access-control-expose-headers", b"content-length"),
            h3::Header::new(b"access-control-request-headers", b"content-type"),
            h3::Header::new(b"access-control-request-method", b"get"),
            h3::Header::new(b"access-control-request-method", b"post"),
            h3::Header::new(b"alt-svc", b"clear"),
            h3::Header::new(b"authorization", b""),
            h3::Header::new(
                b"content-security-policy",
                b"script-src 'none'; object-src 'none'; base-uri 'none'",
            ),
            h3::Header::new(b"early-data", b"1"),
            h3::Header::new(b"expect-ct", b""),
            h3::Header::new(b"forwarded", b""),
            h3::Header::new(b"if-range", b""),
            h3::Header::new(b"origin", b""),
            h3::Header::new(b"purpose", b"prefetch"),
            h3::Header::new(b"server", b""),
            h3::Header::new(b"timing-allow-origin", b"*"),
            h3::Header::new(b"upgrade-insecure-requests", b"1"),
            h3::Header::new(b"user-agent", b""),
            h3::Header::new(b"x-forwarded-for", b""),
            h3::Header::new(b"x-frame-options", b"deny"),
            h3::Header::new(b"x-frame-options", b"sameorigin"),
        ];

        let mut enc = QpackEncoder::new();
        assert_eq!(enc.encode(&headers, &mut encoded), Ok(encoded.len()));

        let mut dec = QpackDecoder::new();
        assert_eq!(
            dec.decode(&mut encoded, u64::MAX),
            Ok((headers, encoded.len()))
        );
    }

    #[test]
    fn qpack_encode_and_decode() {
        let cases = [
            // Indexed
            (
                vec![h3::Header::new(b":status", b"200")],
                vec![0x00, 0x00, 0xd9],
            ),
            // Indexed name with literal value
            (
                vec![h3::Header::new(b":path", b"/index.html")],
                vec![
                    0x00, 0x00, 0x51, 0x88, 0x60, 0xd5, 0x48, 0x5f, 0x2b, 0xce, 0x9a, 0x68,
                ],
            ),
            // Literal name and value
            (
                vec![h3::Header::new(b"x-proto", b"QUIC")],
                vec![
                    0x00, 0x00, 0x2d, 0xf2, 0xb5, 0x76, 0x1d, 0x27, 0x04, 0x51, 0x55, 0x49, 0x43,
                ],
            ),
        ];

        let mut buf = [0u8; 64];
        let mut encoder = QpackEncoder::new();
        let mut decoder = QpackDecoder::new();

        for (headers, encoded) in cases {
            assert_eq!(encoder.encode(&headers, &mut buf), Ok(encoded.len()));
            assert_eq!(&encoded[..], &buf[..encoded.len()]);

            assert_eq!(
                decoder.decode(&encoded, 1024 * 16),
                Ok((headers, encoded.len()))
            );
        }
    }

    #[test]
    fn qpack_encode_lower_case() {
        let headers_original = vec![
            crate::h3::Header::new(b":StatuS", b"200"),
            crate::h3::Header::new(b":PatH", b"/Index.html"),
            crate::h3::Header::new(b"X-Proto", b"QUIC"),
        ];
        let headers_expected = vec![
            crate::h3::Header::new(b":status", b"200"),
            crate::h3::Header::new(b":path", b"/Index.html"),
            crate::h3::Header::new(b"x-proto", b"QUIC"),
        ];

        let mut buf = [0u8; 64];
        let mut enc = QpackEncoder::new();
        let mut dec = QpackDecoder::new();

        let len = enc.encode(&headers_original, &mut buf).unwrap();
        let headers_out = dec.decode(&buf[..len], 1024 * 16).unwrap().0;
        assert_eq!(headers_expected, headers_out);
    }

    #[test]
    fn qpack_ascii_range() {
        let headers = vec![
            crate::h3::Header::new(b"location", b"^	$"),
            crate::h3::Header::new(b"~!@#$%^&*()_+", b"quic"),
            crate::h3::Header::new(b" ", b"hello"),
        ];

        let mut buf = [0u8; 64];
        let mut enc = QpackEncoder::new();
        let mut dec = QpackDecoder::new();

        let len = enc.encode(&headers, &mut buf).unwrap();
        let headers2 = dec.decode(&buf[..len], 1024 * 16).unwrap().0;
        assert_eq!(headers, headers2);
    }

    #[test]
    fn qpack_decode_empty_buffer() {
        let buf = vec![];
        let mut dec = QpackDecoder::new();
        assert!(dec.decode(&buf, 1024 * 16).is_err());
    }

    #[test]
    fn rfc9204_appendix_b_dynamic_table() {
        let encoder_instructions =
            hex::decode("3fbd01c00f7777772e6578616d706c652e636f6dc10c2f73616d706c652f70617468")
                .unwrap();
        let field_section = hex::decode("03811011").unwrap();

        let mut decoder = QpackDecoder::with_max_capacity(220);
        assert_eq!(
            decoder
                .process_encoder_instructions(&encoder_instructions)
                .unwrap(),
            vec![0x02]
        );

        let status = decoder
            .decode_field_section(4, &field_section, u64::MAX)
            .unwrap();
        assert_eq!(
            status,
            DecodeStatus::Decoded {
                headers: vec![
                    Header::new(b":authority", b"www.example.com"),
                    Header::new(b":path", b"/sample/path"),
                ],
                consumed: field_section.len(),
                decoder_instructions: vec![0x84],
            }
        );

        // Appendix B.3: speculative insertion with a literal name.
        let speculative_insert =
            hex::decode("4a637573746f6d2d6b65790c637573746f6d2d76616c7565").unwrap();
        assert_eq!(
            decoder
                .process_encoder_instructions(&speculative_insert)
                .unwrap(),
            vec![0x01]
        );

        // Appendix B.4: the field section blocks until the delayed Duplicate
        // arrives, and can be canceled while it is blocked.
        let blocked_field_section = hex::decode("050080c181").unwrap();
        assert_eq!(
            decoder
                .decode_field_section(8, &blocked_field_section, u64::MAX)
                .unwrap(),
            DecodeStatus::Blocked {
                required_insert_count: 4,
            }
        );
        assert_eq!(decoder.stream_cancellation(8).unwrap(), vec![0x48]);
        assert_eq!(
            decoder.process_encoder_instructions(&[0x02]).unwrap(),
            vec![0x01]
        );
        assert_eq!(
            decoder
                .decode_field_section(8, &blocked_field_section, u64::MAX)
                .unwrap(),
            DecodeStatus::Decoded {
                headers: vec![
                    Header::new(b":authority", b"www.example.com"),
                    Header::new(b":path", b"/"),
                    Header::new(b"custom-key", b"custom-value"),
                ],
                consumed: blocked_field_section.len(),
                decoder_instructions: vec![0x88],
            }
        );

        // Appendix B.5: an insertion using a dynamic name reference evicts
        // the oldest entry while absolute indices remain stable.
        let insert_with_dynamic_name = hex::decode("810d637573746f6d2d76616c756532").unwrap();
        assert_eq!(
            decoder
                .process_encoder_instructions(&insert_with_dynamic_name)
                .unwrap(),
            vec![0x01]
        );
        assert_eq!(decoder.insert_count(), 5);
        assert!(decoder.table.get_absolute(0).is_none());
        assert_eq!(decoder.table.get_absolute(4).unwrap().name, b"custom-key");
        assert_eq!(
            decoder.table.get_absolute(4).unwrap().value,
            b"custom-value2"
        );
    }

    #[test]
    fn dynamic_table_encoder_round_trip() {
        let headers = vec![Header::new(b"x-foo", b"bar")];
        let mut encoder = QpackEncoder::new();
        encoder.set_max_capacity(256).unwrap();
        let mut decoder = QpackDecoder::with_max_capacity(256);
        let mut field_section = [0; 128];

        let (first_len, encoder_instructions) = encoder
            .encode_for_stream(0, &headers, &mut field_section)
            .unwrap();
        assert!(!encoder_instructions.is_empty());
        let feedback = decoder
            .process_encoder_instructions(&encoder_instructions)
            .unwrap();
        assert_eq!(feedback, vec![0x01]);
        assert_eq!(
            decoder
                .decode(&field_section[..first_len], u64::MAX)
                .unwrap()
                .0,
            headers
        );

        encoder.process_decoder_instructions(&feedback).unwrap();
        let (second_len, encoder_instructions) = encoder
            .encode_for_stream(0, &headers, &mut field_section)
            .unwrap();
        assert!(encoder_instructions.is_empty());
        assert!(second_len < first_len);

        let status = decoder
            .decode_field_section(0, &field_section[..second_len], u64::MAX)
            .unwrap();
        assert_eq!(
            status,
            DecodeStatus::Decoded {
                headers,
                consumed: second_len,
                decoder_instructions: vec![0x80],
            }
        );
        encoder.process_decoder_instructions(&[0x80]).unwrap();

        let renamed_value = vec![Header::new(b"x-foo", b"baz")];
        let (third_len, encoder_instructions) = encoder
            .encode_for_stream(4, &renamed_value, &mut field_section)
            .unwrap();
        assert!(!encoder_instructions.is_empty());
        assert_eq!(
            decoder
                .process_encoder_instructions(&encoder_instructions)
                .unwrap(),
            vec![0x01]
        );
        assert_eq!(
            decoder
                .decode_field_section(4, &field_section[..third_len], u64::MAX)
                .unwrap(),
            DecodeStatus::Decoded {
                headers: renamed_value,
                consumed: third_len,
                decoder_instructions: vec![0x84],
            }
        );
    }

    #[test]
    fn literal_with_post_base_name_reference() {
        let mut decoder = QpackDecoder::with_max_capacity(64);
        let mut encoder_instructions = Vec::new();
        append_int(&mut encoder_instructions, 64, SET_DYNAMIC_TABLE_CAPACITY, 5).unwrap();
        append_string(
            &mut encoder_instructions,
            b"x-name",
            INSERT_WITH_LITERAL_NAME,
            5,
            false,
        )
        .unwrap();
        append_string(&mut encoder_instructions, b"old", 0, 7, false).unwrap();
        decoder
            .process_encoder_instructions(&encoder_instructions)
            .unwrap();

        // Required Insert Count=1, Base=0, followed by a literal whose name
        // uses post-Base index 0 (absolute index 0).
        let field_section = [0x02, 0x80, 0x00, 0x03, b'n', b'e', b'w'];
        assert_eq!(
            decoder
                .decode_field_section(4, &field_section, u64::MAX)
                .unwrap(),
            DecodeStatus::Decoded {
                headers: vec![Header::new(b"x-name", b"new")],
                consumed: field_section.len(),
                decoder_instructions: vec![0x84],
            }
        );
    }

    #[test]
    fn rejects_overflowing_delta_base() {
        let mut field_section = vec![0];
        append_int(&mut field_section, u64::MAX, 0x80, 7).unwrap();

        let mut decoder = QpackDecoder::new();
        assert_eq!(
            decoder.decode_field_section(0, &field_section, u64::MAX),
            Err(Http3Error::QpackDecompressionFailed)
        );
    }

    #[test]
    fn partial_integer_rejects_overlong_high_bits() {
        let mut encoded = vec![0b11111];
        encoded.extend(std::iter::repeat_n(0b1000_0000, 9));
        encoded.push(0b0000_0010);
        assert_eq!(
            decode_int_partial(&encoded, 5),
            Err(Http3Error::QpackDecompressionFailed)
        );
    }

    #[test]
    fn encoder_instructions_can_arrive_incrementally() {
        let instructions =
            hex::decode("3fbd014a637573746f6d2d6b65790c637573746f6d2d76616c7565").unwrap();
        let mut decoder = QpackDecoder::with_max_capacity(220);
        for byte in &instructions[..instructions.len() - 1] {
            assert!(decoder
                .process_encoder_instructions(&[*byte])
                .unwrap()
                .is_empty());
        }
        assert_eq!(
            decoder
                .process_encoder_instructions(&instructions[instructions.len() - 1..])
                .unwrap(),
            vec![0x01]
        );
    }

    #[test]
    fn rejects_capacity_above_advertised_limit() {
        let mut decoder = QpackDecoder::with_max_capacity(64);
        let mut instruction = Vec::new();
        append_int(&mut instruction, 65, SET_DYNAMIC_TABLE_CAPACITY, 5).unwrap();
        assert_eq!(
            decoder.process_encoder_instructions(&instruction),
            Err(Http3Error::QpackEncoderStreamError)
        );
    }

    #[test]
    fn sensitive_fields_are_never_inserted() {
        let mut encoder = QpackEncoder::new();
        encoder.set_max_capacity(256).unwrap();
        let mut field_section = [0; 128];
        let (_, instructions) = encoder
            .encode_for_stream(
                0,
                &[Header::new(b"authorization", b"secret")],
                &mut field_section,
            )
            .unwrap();
        assert!(instructions.is_empty());
        assert_ne!(field_section[2] & 0x20, 0);
    }
}

mod dynamic_table;
mod huffman;
mod prefix_int;
mod static_table;
