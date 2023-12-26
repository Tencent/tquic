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

use bytes::Bytes;

use crate::codec;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::error::Error;
use crate::packet::PacketType;
use crate::qlog;
use crate::qlog::events::ErrorSpace;
use crate::qlog::events::QuicFrame;
use crate::qlog::events::StreamType;
use crate::qlog::events::TokenType;
use crate::ranges::RangeSet;
use crate::token::ResetToken;
use crate::ConnectionId;
use crate::Result;

/// The largest offset delivered on a stream cannot exceed 2^62-1, as it is not
/// possible to provide flow control credit for that data.
pub(crate) const MAX_STREAM_SIZE: u64 = 1 << 62;

pub(crate) const MAX_CRYPTO_OVERHEAD: usize = 8;
// Type (1) + Stream ID (8) + Offset (8) + Length (2)
pub(crate) const MAX_STREAM_OVERHEAD: usize = 19;

/// The QUIC frame is a unit of structured protocol information. Frames are
/// contained in QUIC packets.
#[derive(Clone, PartialEq, Eq)]
pub enum Frame {
    /// PADDING frame (type=0x00) has no semantic value and can be used to
    /// increase the size of a packet.
    /// Paddings represents one or more QUIC PADDING frames and can be processed
    /// more efficiently.
    Paddings { len: usize },

    /// PING frame (type=0x01) is used to verify that peers are still alive
    /// or to check reachability to the peer.
    Ping,

    /// ACK frame (types 0x02 and 0x03) is used to inform senders of packets
    /// they have received and processed. The ACK frame contains one or more
    /// ACK Ranges.
    Ack {
        ack_delay: u64,
        ack_ranges: RangeSet,
        ecn_counts: Option<EcnCounts>,
    },

    /// RESET_STREAM frame (type=0x04) is used to to abruptly terminate the
    /// sending part of a stream.
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },

    /// STOP_SENDING frame (type=0x05) is used to communicate that incoming data
    /// is being discarded on receipt per application request.
    StopSending { stream_id: u64, error_code: u64 },

    /// CRYPTO frame (type=0x06) is used to transmit cryptographic handshake
    /// messages.
    Crypto {
        offset: u64,
        length: usize,
        data: Bytes,
    },

    /// NEW_TOKEN frame (type=0x07) sent by the server is used to provide the
    /// client with a token to send in the header of an Initial packet for a
    /// future connection.
    NewToken { token: Vec<u8> },

    /// STREAM frame implicitly creates a stream and carry stream data.
    Stream {
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
        data: Bytes,
    },

    /// MAX_DATA frame (type=0x10) is used to inform the peer of the maximum
    /// amount of data that can be sent on the connection as a whole.
    MaxData { max: u64 },

    /// MAX_STREAM_DATA frame (type=0x11) is used to inform a peer of the
    /// maximum amount of data that can be sent on a stream.
    MaxStreamData { stream_id: u64, max: u64 },

    /// MAX_STREAMS frame with a type of 0x12 applies to bidirectional streams.
    /// MAX_STREAMS frame with a type of 0x13 applies to unidirectional streams
    MaxStreams { bidi: bool, max: u64 },

    /// A sender send a DATA_BLOCKED frame (type=0x14) when it wishes to
    /// send data but is unable to do so due to connection-level flow control
    DataBlocked { max: u64 },

    /// A sender send a STREAM_DATA_BLOCKED frame (type=0x15) when it wishes to
    /// send data but is unable to do so due to stream-level flow control.
    StreamDataBlocked { stream_id: u64, max: u64 },

    /// STREAMS_BLOCKED frame of type 0x16 is used to indicate reaching the
    /// bidirectional stream limit. STREAMS_BLOCKED frame of type 0x17 is used
    /// to indicate reaching the unidirectional stream limit.
    StreamsBlocked { bidi: bool, max: u64 },

    /// NEW_CONNECTION_ID frame (type=0x18) is used to provide the peer with
    /// alternative connection IDs that can be used to break linkability.
    NewConnectionId {
        seq_num: u64,
        retire_prior_to: u64,
        conn_id: ConnectionId,
        reset_token: ResetToken,
    },

    /// RETIRE_CONNECTION_ID frame (type=0x19) is used to indicate that the
    /// endpoint  will no longer use a connection ID that was issued by its peer.
    RetireConnectionId { seq_num: u64 },

    /// PATH_CHALLENGE frames (type=0x1a) is used to check reachability to the
    /// peer and for path validation during connection migration.
    PathChallenge { data: [u8; 8] },

    /// PATH_RESPONSE frame (type=0x1b) is sent in response to a PATH_CHALLENGE
    /// frame.
    PathResponse { data: [u8; 8] },

    /// CONNECTION_CLOSE frame (type=0x1c) is used to to notify the peer that
    /// the connection is being closed due to error of QUIC layer.
    ConnectionClose {
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },

    /// CONNECTION_CLOSE frame (type=0x1d) is used to notify the peer that the
    /// connection is being closed due to error of application.
    ApplicationClose { error_code: u64, reason: Vec<u8> },

    /// HANDSHAKE_DONE frame (type=0x1e) sent by the server is used to signal
    /// confirmation of the handshake to the client.
    HandshakeDone,

    /// PATH_ABANDON frame informs the peer to abandon a path.
    /// See draft-ietf-quic-multipath-05.
    PathAbandon {
        dcid_seq_num: u64,
        error_code: u64,
        reason: Vec<u8>,
    },

    /// PATH_STATUS Frame is used by endpoints to inform the peer of the current
    /// status of one path, and the peer should send packets according to the
    /// preference expressed in the frame.
    /// See draft-ietf-quic-multipath-05.
    PathStatus {
        dcid_seq_num: u64,
        seq_num: u64,
        status: u64,
    },
}

impl Frame {
    /// Decode a QUIC frame
    pub fn from_bytes(buf: &mut bytes::Bytes, pkt: PacketType) -> Result<(Frame, usize)> {
        let mut b = buf.as_ref();
        let len = b.len();

        let frame_type = b.read_varint()?;
        let frame = match frame_type {
            0x00 => {
                let mut len = 1;
                while !b.is_empty() && b[0] == 0x00 {
                    b.read_u8()?;
                    len += 1;
                }
                Frame::Paddings { len }
            }

            0x01 => Frame::Ping,

            0x02..=0x03 => {
                let (frame, len) = parse_ack_frame(frame_type, b)?;
                b.skip(len)?;
                frame
            }

            0x04 => Frame::ResetStream {
                stream_id: b.read_varint()?,
                error_code: b.read_varint()?,
                final_size: b.read_varint()?,
            },

            0x05 => Frame::StopSending {
                stream_id: b.read_varint()?,
                error_code: b.read_varint()?,
            },

            0x06 => {
                let offset = b.read_varint()?;
                let length = b.read_varint()? as usize;
                if length > b.len() {
                    return Err(Error::BufferTooShort);
                }
                let start = buf.len() - b.len();
                let data = buf.slice(start..(start + length));
                b.skip(length)?;
                Frame::Crypto {
                    offset,
                    length,
                    data,
                }
            }

            0x07 => Frame::NewToken {
                token: b.read_with_varint_length()?.to_vec(),
            },

            0x08..=0x0f => {
                let first = frame_type as u8;

                let stream_id = b.read_varint()?;
                let offset = if first & 0x04 != 0 {
                    b.read_varint()?
                } else {
                    0
                };
                let length = if first & 0x02 != 0 {
                    b.read_varint()? as usize
                } else {
                    b.len()
                };
                if offset + length as u64 >= MAX_STREAM_SIZE {
                    return Err(Error::FrameEncodingError);
                }
                let fin = first & 0x01 != 0;
                if length > b.len() {
                    return Err(Error::BufferTooShort);
                }
                let start = buf.len() - b.len();
                let data = buf.slice(start..(start + length));
                b.skip(length)?;

                Frame::Stream {
                    stream_id,
                    offset,
                    length,
                    fin,
                    data,
                }
            }

            0x10 => Frame::MaxData {
                max: b.read_varint()?,
            },

            0x11 => Frame::MaxStreamData {
                stream_id: b.read_varint()?,
                max: b.read_varint()?,
            },

            0x12 => Frame::MaxStreams {
                bidi: true,
                max: b.read_varint()?,
            },

            0x13 => Frame::MaxStreams {
                bidi: false,
                max: b.read_varint()?,
            },

            0x14 => Frame::DataBlocked {
                max: b.read_varint()?,
            },

            0x15 => Frame::StreamDataBlocked {
                stream_id: b.read_varint()?,
                max: b.read_varint()?,
            },

            0x16 => Frame::StreamsBlocked {
                bidi: true,
                max: b.read_varint()?,
            },

            0x17 => Frame::StreamsBlocked {
                bidi: false,
                max: b.read_varint()?,
            },

            0x18 => {
                let seq_num = b.read_varint()?;
                let retire_prior_to = b.read_varint()?;
                let cid = b.read_with_u8_length()?;
                Frame::NewConnectionId {
                    seq_num,
                    retire_prior_to,
                    conn_id: ConnectionId::new(&cid),
                    reset_token: ResetToken(
                        b.read(16)?.try_into().map_err(|_| Error::BufferTooShort)?,
                    ),
                }
            }

            0x19 => Frame::RetireConnectionId {
                seq_num: b.read_varint()?,
            },

            0x1a => Frame::PathChallenge {
                data: b.read(8)?.try_into().map_err(|_| Error::BufferTooShort)?,
            },

            0x1b => Frame::PathResponse {
                data: b.read(8)?.try_into().map_err(|_| Error::BufferTooShort)?,
            },

            0x1c => Frame::ConnectionClose {
                error_code: b.read_varint()?,
                frame_type: b.read_varint()?,
                reason: b.read_with_varint_length()?.to_vec(),
            },

            0x1d => Frame::ApplicationClose {
                error_code: b.read_varint()?,
                reason: b.read_with_varint_length()?.to_vec(),
            },

            0x1e => Frame::HandshakeDone,

            0x15228c05 => Frame::PathAbandon {
                dcid_seq_num: b.read_varint()?,
                error_code: b.read_varint()?,
                reason: b.read_with_varint_length()?.to_vec(),
            },

            0x15228c06 => Frame::PathStatus {
                dcid_seq_num: b.read_varint()?,
                seq_num: b.read_varint()?,
                status: b.read_varint()?,
            },

            _ => return Err(Error::FrameEncodingError),
        };

        if !Frame::validate_frame(pkt, &frame) {
            return Err(Error::InvalidPacket);
        }

        Ok((frame, len - b.len()))
    }

    fn validate_frame(pkt_type: PacketType, frame: &Frame) -> bool {
        match (pkt_type, &frame) {
            // PADDING and PING are allowed on all packet types.
            (_, Frame::Paddings { .. }) | (_, Frame::Ping { .. }) => true,

            // ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, and
            // RETIRE_CONNECTION_ID can't be sent on 0-RTT packets.
            (PacketType::ZeroRTT, Frame::Ack { .. }) => false,
            (PacketType::ZeroRTT, Frame::Crypto { .. }) => false,
            (PacketType::ZeroRTT, Frame::HandshakeDone) => false,
            (PacketType::ZeroRTT, Frame::NewToken { .. }) => false,
            (PacketType::ZeroRTT, Frame::PathResponse { .. }) => false,
            (PacketType::ZeroRTT, Frame::RetireConnectionId { .. }) => false,
            (PacketType::ZeroRTT, Frame::ConnectionClose { .. }) => false,

            // ACK, CRYPTO and CONNECTION_CLOSE can be sent on all other packet
            // types.
            (_, Frame::Ack { .. }) => true,
            (_, Frame::Crypto { .. }) => true,
            (_, Frame::ConnectionClose { .. }) => true,

            // All frames are allowed on 0-RTT and 1-RTT packets.
            (PacketType::OneRTT, _) => true,
            (PacketType::ZeroRTT, _) => true,

            // All other cases are forbidden.
            (..) => false,
        }
    }

    /// Encode a QUIC frame
    pub fn to_bytes(&self, mut b: &mut [u8]) -> Result<usize> {
        let len = b.len();

        match self {
            Frame::Paddings { len } => {
                let mut left = *len;
                while left > 0 {
                    b.write_varint(0x00)?;
                    left -= 1;
                }
            }

            Frame::Ping => {
                b.write_varint(0x01)?;
            }

            Frame::Ack {
                ack_delay,
                ack_ranges,
                ecn_counts,
            } => {
                if ecn_counts.is_none() {
                    b.write_varint(0x02)?;
                } else {
                    b.write_varint(0x03)?;
                }

                let mut it = ack_ranges.iter().rev();

                let first = it.next().unwrap();
                let ack_range_len = (first.end - 1) - first.start;

                b.write_varint(first.end - 1)?;
                b.write_varint(*ack_delay)?;
                b.write_varint(it.len() as u64)?;
                b.write_varint(ack_range_len)?;

                let mut smallest_ack = first.start;
                for ack_range in it {
                    let gap = smallest_ack - ack_range.end - 1;
                    let ack_range_len = (ack_range.end - 1) - ack_range.start;
                    b.write_varint(gap)?;
                    b.write_varint(ack_range_len)?;
                    smallest_ack = ack_range.start;
                }

                if let Some(ecn) = ecn_counts {
                    b.write_varint(ecn.ect0_count)?;
                    b.write_varint(ecn.ect1_count)?;
                    b.write_varint(ecn.ecn_ce_count)?;
                }
            }

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                b.write_varint(0x04)?;
                b.write_varint(*stream_id)?;
                b.write_varint(*error_code)?;
                b.write_varint(*final_size)?;
            }

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                b.write_varint(0x05)?;
                b.write_varint(*stream_id)?;
                b.write_varint(*error_code)?;
            }

            Frame::Crypto {
                offset,
                length,
                data,
            } => {
                let written = encode_crypto_header(*offset, *length as u64, b)?;
                b = &mut b[written..];
                b.write(data.as_ref())?;
            }

            Frame::NewToken { token } => {
                b.write_varint(0x07)?;
                b.write_varint(token.len() as u64)?;
                b.write(token)?;
            }

            Frame::Stream {
                stream_id,
                offset,
                length,
                fin,
                data,
            } => {
                let written = encode_stream_header(*stream_id, *offset, *length as u64, *fin, b)?;
                b = &mut b[written..];
                b.write(data.as_ref())?;
            }

            Frame::MaxData { max } => {
                b.write_varint(0x10)?;
                b.write_varint(*max)?;
            }

            Frame::MaxStreamData { stream_id, max } => {
                b.write_varint(0x11)?;
                b.write_varint(*stream_id)?;
                b.write_varint(*max)?;
            }

            Frame::MaxStreams { bidi, max } => {
                let t = if *bidi { 0x12 } else { 0x13 };
                b.write_varint(t)?;
                b.write_varint(*max)?;
            }

            Frame::DataBlocked { max } => {
                b.write_varint(0x14)?;
                b.write_varint(*max)?;
            }

            Frame::StreamDataBlocked { stream_id, max } => {
                b.write_varint(0x15)?;
                b.write_varint(*stream_id)?;
                b.write_varint(*max)?;
            }

            Frame::StreamsBlocked { bidi, max } => {
                let t = if *bidi { 0x16 } else { 0x17 };
                b.write_varint(t)?;
                b.write_varint(*max)?;
            }

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                b.write_varint(0x18)?;
                b.write_varint(*seq_num)?;
                b.write_varint(*retire_prior_to)?;
                b.write_u8(conn_id.len() as u8)?;
                b.write(conn_id.as_ref())?;
                b.write(reset_token.as_ref())?;
            }

            Frame::RetireConnectionId { seq_num } => {
                b.write_varint(0x19)?;
                b.write_varint(*seq_num)?;
            }

            Frame::PathChallenge { data } => {
                b.write_varint(0x1a)?;
                b.write(data.as_ref())?;
            }

            Frame::PathResponse { data } => {
                b.write_varint(0x1b)?;
                b.write(data.as_ref())?;
            }

            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                b.write_varint(0x1c)?;
                b.write_varint(*error_code)?;
                b.write_varint(*frame_type)?;
                b.write_varint(reason.len() as u64)?;
                b.write(reason.as_ref())?;
            }

            Frame::ApplicationClose { error_code, reason } => {
                b.write_varint(0x1d)?;
                b.write_varint(*error_code)?;
                b.write_varint(reason.len() as u64)?;
                b.write(reason.as_ref())?;
            }

            Frame::HandshakeDone => {
                b.write_varint(0x1e)?;
            }

            Frame::PathAbandon {
                dcid_seq_num,
                error_code,
                reason,
            } => {
                b.write_varint(0x15228c05)?;
                b.write_varint(*dcid_seq_num)?;
                b.write_varint(*error_code)?;
                b.write_varint(reason.len() as u64)?;
                b.write(reason.as_ref())?;
            }

            Frame::PathStatus {
                dcid_seq_num,
                seq_num,
                status,
            } => {
                b.write_varint(0x15228c06)?;
                b.write_varint(*dcid_seq_num)?;
                b.write_varint(*seq_num)?;
                b.write_varint(*status)?;
            }
        }

        Ok(len - b.len())
    }

    pub fn wire_len(&self) -> usize {
        match self {
            Frame::Paddings { len } => *len,

            Frame::Ping => 1,

            Frame::Ack {
                ack_delay,
                ack_ranges,
                ecn_counts,
            } => {
                let mut it = ack_ranges.iter().rev();

                let first = it.next().unwrap();
                let ack_block = (first.end - 1) - first.start;

                let mut len = 1
                    + codec::encode_varint_len(first.end - 1)
                    + codec::encode_varint_len(*ack_delay)
                    + codec::encode_varint_len(it.len() as u64)
                    + codec::encode_varint_len(ack_block);

                let mut smallest_ack = first.start;
                for block in it {
                    let gap = smallest_ack - block.end - 1;
                    let ack_block = (block.end - 1) - block.start;
                    len += codec::encode_varint_len(gap) + codec::encode_varint_len(ack_block);
                    smallest_ack = block.start;
                }

                if let Some(ecn) = ecn_counts {
                    len += codec::encode_varint_len(ecn.ect0_count)
                        + codec::encode_varint_len(ecn.ect1_count)
                        + codec::encode_varint_len(ecn.ecn_ce_count);
                }

                len
            }

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                1 + codec::encode_varint_len(*stream_id)
                    + codec::encode_varint_len(*error_code)
                    + codec::encode_varint_len(*final_size)
            }

            Frame::StopSending {
                stream_id,
                error_code,
            } => 1 + codec::encode_varint_len(*stream_id) + codec::encode_varint_len(*error_code),

            Frame::Crypto { offset, data, .. } => {
                1 + codec::encode_varint_len(*offset) + 2 + data.len()
            }

            Frame::NewToken { token } => {
                1 + codec::encode_varint_len(token.len() as u64) + token.len()
            }

            Frame::Stream {
                stream_id,
                offset,
                data,
                ..
            } => {
                1 + codec::encode_varint_len(*stream_id)
                    + codec::encode_varint_len(*offset)
                    + 2
                    + data.len()
            }

            Frame::MaxData { max } => 1 + codec::encode_varint_len(*max),

            Frame::MaxStreamData { stream_id, max } => {
                1 + codec::encode_varint_len(*stream_id) + codec::encode_varint_len(*max)
            }

            Frame::MaxStreams { max, .. } => 1 + codec::encode_varint_len(*max),

            Frame::DataBlocked { max } => 1 + codec::encode_varint_len(*max),

            Frame::StreamDataBlocked { stream_id, max } => {
                1 + codec::encode_varint_len(*stream_id) + codec::encode_varint_len(*max)
            }

            Frame::StreamsBlocked { max, .. } => 1 + codec::encode_varint_len(*max),

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                1 + codec::encode_varint_len(*seq_num)
                    + codec::encode_varint_len(*retire_prior_to)
                    + 1
                    + conn_id.len()
                    + reset_token.as_ref().len()
            }

            Frame::RetireConnectionId { seq_num } => 1 + codec::encode_varint_len(*seq_num),

            Frame::PathChallenge { .. } => 1 + 8,

            Frame::PathResponse { .. } => 1 + 8,

            Frame::ConnectionClose {
                frame_type,
                error_code,
                reason,
                ..
            } => {
                1 + codec::encode_varint_len(*error_code)
                    + codec::encode_varint_len(*frame_type)
                    + codec::encode_varint_len(reason.len() as u64)
                    + reason.len()
            }

            Frame::ApplicationClose { reason, error_code } => {
                1 + codec::encode_varint_len(*error_code)
                    + codec::encode_varint_len(reason.len() as u64)
                    + reason.len()
            }

            Frame::HandshakeDone => 1,

            Frame::PathAbandon {
                dcid_seq_num,
                error_code,
                reason,
                ..
            } => {
                // length of frame type (0x15228c05) is 4
                4 + codec::encode_varint_len(*dcid_seq_num)
                    + codec::encode_varint_len(*error_code)
                    + codec::encode_varint_len(reason.len() as u64)
                    + reason.len()
            }

            Frame::PathStatus {
                dcid_seq_num,
                seq_num,
                status,
                ..
            } => {
                // length of frame type (0x15228c06) is 4
                4 + codec::encode_varint_len(*dcid_seq_num)
                    + codec::encode_varint_len(*seq_num)
                    + codec::encode_varint_len(*status)
            }
        }
    }

    pub fn to_qlog(&self) -> QuicFrame {
        match self {
            Frame::Paddings { .. } => QuicFrame::Padding,

            Frame::Ping { .. } => QuicFrame::Ping,

            Frame::Ack {
                ack_delay,
                ack_ranges,
                ecn_counts,
            } => {
                let ack_delay = *ack_delay as f32 / 1000.0;
                let ack_ranges = qlog::events::AckedRanges::Double(
                    ack_ranges.iter().map(|r| (r.start, r.end - 1)).collect(),
                );
                let (ect0, ect1, ce) = match ecn_counts {
                    Some(ecn) => (
                        Some(ecn.ect0_count),
                        Some(ecn.ect1_count),
                        Some(ecn.ecn_ce_count),
                    ),
                    None => (None, None, None),
                };

                QuicFrame::Ack {
                    ack_delay: Some(ack_delay),
                    acked_ranges: Some(ack_ranges),
                    ect1,
                    ect0,
                    ce,
                }
            }

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => QuicFrame::ResetStream {
                stream_id: *stream_id,
                error_code: *error_code,
                final_size: *final_size,
            },

            Frame::StopSending {
                stream_id,
                error_code,
            } => QuicFrame::StopSending {
                stream_id: *stream_id,
                error_code: *error_code,
            },

            Frame::Crypto { offset, length, .. } => QuicFrame::Crypto {
                offset: *offset,
                length: *length as u64,
            },

            Frame::NewToken { .. } => QuicFrame::NewToken {
                token: qlog::events::Token {
                    token_type: Some(qlog::events::TokenType::Retry),
                    raw: None,
                    details: None,
                },
            },

            Frame::Stream {
                stream_id,
                offset,
                length,
                fin,
                ..
            } => QuicFrame::Stream {
                stream_id: *stream_id,
                offset: *offset,
                length: *length as u64,
                fin: Some(*fin),
                raw: None,
            },

            Frame::MaxData { max } => QuicFrame::MaxData { maximum: *max },

            Frame::MaxStreamData { stream_id, max } => QuicFrame::MaxStreamData {
                stream_id: *stream_id,
                maximum: *max,
            },

            Frame::MaxStreams { bidi, max } => QuicFrame::MaxStreams {
                stream_type: if *bidi {
                    StreamType::Bidirectional
                } else {
                    StreamType::Unidirectional
                },
                maximum: *max,
            },

            Frame::DataBlocked { max } => QuicFrame::DataBlocked { limit: *max },

            Frame::StreamDataBlocked { stream_id, max } => QuicFrame::StreamDataBlocked {
                stream_id: *stream_id,
                limit: *max,
            },

            Frame::StreamsBlocked { bidi, max } => QuicFrame::StreamsBlocked {
                stream_type: if *bidi {
                    StreamType::Bidirectional
                } else {
                    StreamType::Unidirectional
                },
                limit: *max,
            },

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => QuicFrame::NewConnectionId {
                sequence_number: *seq_num as u32,
                retire_prior_to: *retire_prior_to as u32,
                connection_id_length: Some(conn_id.len() as u8),
                connection_id: format!("{:?}", conn_id),
                stateless_reset_token: Some(format!("{:?}", reset_token)),
            },

            Frame::RetireConnectionId { seq_num } => QuicFrame::RetireConnectionId {
                sequence_number: *seq_num as u32,
            },

            Frame::PathChallenge { .. } => QuicFrame::PathChallenge { data: None },

            Frame::PathResponse { .. } => QuicFrame::PathResponse { data: None },

            Frame::ConnectionClose {
                error_code, reason, ..
            } => QuicFrame::ConnectionClose {
                error_space: Some(ErrorSpace::TransportError),
                error_code: Some(*error_code),
                error_code_value: None,
                reason: Some(String::from_utf8(reason.clone()).unwrap()),
                trigger_frame_type: None,
            },

            Frame::ApplicationClose { error_code, reason } => QuicFrame::ConnectionClose {
                error_space: Some(qlog::events::ErrorSpace::ApplicationError),
                error_code: Some(*error_code),
                error_code_value: None,
                reason: Some(String::from_utf8(reason.clone()).unwrap()),
                trigger_frame_type: None,
            },

            Frame::HandshakeDone => QuicFrame::HandshakeDone,

            Frame::PathAbandon { .. } => QuicFrame::Unknown {
                raw_frame_type: 0x15228c05,
                frame_type_value: None,
                raw: None,
            },

            Frame::PathStatus { .. } => QuicFrame::Unknown {
                raw_frame_type: 0x15228c06,
                frame_type_value: None,
                raw: None,
            },
        }
    }

    /// ACK, PADDING and CONNECTION_CLOSE are "non-ack-eliciting frames", and
    /// all other frames are "ack-eliciting fraems".
    pub fn ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Frame::Paddings { .. }
                | Frame::Ack { .. }
                | Frame::ApplicationClose { .. }
                | Frame::ConnectionClose { .. }
        )
    }

    /// PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID, and PADDING frames
    /// are "probing frames", and all other frames are "non-probing frames".
    pub fn probing(&self) -> bool {
        matches!(
            self,
            Frame::Paddings { .. }
                | Frame::NewConnectionId { .. }
                | Frame::PathChallenge { .. }
                | Frame::PathResponse { .. }
        )
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Frame::Paddings { len } => {
                write!(f, "PADDINGS len={len}")?;
            }

            Frame::Ping => {
                write!(f, "PING")?;
            }

            Frame::Ack {
                ack_delay,
                ack_ranges,
                ecn_counts,
            } => {
                write!(
                    f,
                    "ACK delay={ack_delay} ranges={ack_ranges:?} ecn_counts={ecn_counts:?}"
                )?;
            }

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                write!(
                    f,
                    "RESET_STREAM id={stream_id} err={error_code:x} size={final_size}"
                )?;
            }

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                write!(f, "STOP_SENDING id={stream_id} err={error_code:x}")?;
            }

            Frame::Crypto { offset, length, .. } => {
                write!(f, "CRYPTO off={} len={}", offset, length)?;
            }

            Frame::NewToken { .. } => {
                write!(f, "NEW_TOKEN")?;
            }

            Frame::Stream {
                stream_id,
                offset,
                length,
                fin,
                ..
            } => {
                write!(
                    f,
                    "STREAM id={} off={} len={} fin={}",
                    stream_id, offset, length, fin
                )?;
            }

            Frame::MaxData { max } => {
                write!(f, "MAX_DATA max={max}")?;
            }

            Frame::MaxStreamData { stream_id, max } => {
                write!(f, "MAX_STREAM_DATA id={stream_id} max={max}")?;
            }

            Frame::MaxStreams { bidi, max } => {
                write!(f, "MAX_STREAMS bidi={bidi} max={max}")?;
            }

            Frame::DataBlocked { max } => {
                write!(f, "DATA_BLOCKED max={max}")?;
            }

            Frame::StreamDataBlocked { stream_id, max } => {
                write!(f, "STREAM_DATA_BLOCKED id={stream_id} max={max}")?;
            }

            Frame::StreamsBlocked { bidi, max } => {
                write!(f, "STREAMS_BLOCKED bidi={bidi} max={max}")?;
            }

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                write!(
                    f,
                    "NEW_CONNECTION_ID seq={seq_num} retire_prior_to={retire_prior_to} \
                    cid={conn_id:02x?} reset_token={reset_token:?}",
                )?;
            }

            Frame::RetireConnectionId { seq_num } => {
                write!(f, "RETIRE_CONNECTION_ID seq={seq_num}")?;
            }

            Frame::PathChallenge { data } => {
                write!(f, "PATH_CHALLENGE data={data:02x?}")?;
            }

            Frame::PathResponse { data } => {
                write!(f, "PATH_RESPONSE data={data:02x?}")?;
            }

            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                write!(
                    f,
                    "CONNECTION_CLOSE err={error_code:x} frame={frame_type:x} reason={reason:x?}"
                )?;
            }

            Frame::ApplicationClose { error_code, reason } => {
                write!(f, "APPLICATION_CLOSE err={error_code:x} reason={reason:x?}")?;
            }

            Frame::HandshakeDone => {
                write!(f, "HANDSHAKE_DONE")?;
            }

            Frame::PathAbandon {
                dcid_seq_num,
                error_code,
                reason,
            } => {
                write!(
                    f,
                    "PATH_ABANDON dcid_seq_num={dcid_seq_num:x} err={error_code:x} reason={reason:x?}",
                )?;
            }

            Frame::PathStatus {
                dcid_seq_num,
                seq_num,
                status,
            } => {
                write!(
                    f,
                    "PATH_STATUS dcid_seq_num={dcid_seq_num:x} seq_num={seq_num:x} status={status:x}",
                )?;
            }
        }

        Ok(())
    }
}

/// Return the encoded length of CRYPTO frame header.
pub fn crypto_header_wire_len(offset: u64) -> usize {
    // Note: `encode_crypto_header()` encode length field in 2 bytes.
    // The maximum length of crypto data in a CRYPTO frame is 16383.
    1 + codec::encode_varint_len(offset) + 2
}

/// Encode header of CRYPTO frame to the given buffer.
pub fn encode_crypto_header(offset: u64, length: u64, mut b: &mut [u8]) -> Result<usize> {
    let len = b.len();

    b.write_varint(0x06)?;
    b.write_varint(offset)?;
    b.write_varint_with_len(length, 2)?;

    Ok(len - b.len())
}

/// Return the encoded length of STREAM frame header.
pub fn stream_header_wire_len(stream_id: u64, offset: u64) -> usize {
    // Note: `encode_stream_header()` encode length field in 2 bytes.
    // The maximum length of crypto data in a STREAM frame is 16383.
    1 + codec::encode_varint_len(stream_id) + codec::encode_varint_len(offset) + 2
}

/// Encode header of STREAM frame to the given buffer.
pub fn encode_stream_header(
    stream_id: u64,
    offset: u64,
    length: u64,
    fin: bool,
    mut b: &mut [u8],
) -> Result<usize> {
    let len = b.len();

    let mut frame_type: u8 = 0b00001110; // Always encode offset and length.
    if fin {
        frame_type |= 0x01;
    }
    b.write_varint(u64::from(frame_type))?;
    b.write_varint(stream_id)?;
    b.write_varint(offset)?;
    b.write_varint_with_len(length, 2)?;

    Ok(len - b.len())
}

/// The ACK frame uses the least significant bit of the type value (type 0x03)
/// to indicate ECN feedback and report receipt of QUIC packets with associated
/// ECN codepoints of ECT(0), ECT(1), or ECN-CE in the packet's IP header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcnCounts {
    /// The total number of packets received with the ECT(0) codepoint in the
    /// packet number space of the ACK frame.
    ect0_count: u64,

    /// The total number of packets received with the ECT(1) codepoint in the
    /// packet number space of the ACK frame.
    ect1_count: u64,

    /// The total number of packets received with the ECN-CE codepoint in the
    /// packet number space of the ACK frame.
    ecn_ce_count: u64,
}

fn parse_ack_frame(frame_type: u64, mut b: &[u8]) -> Result<(Frame, usize)> {
    let len = b.len();
    let mut ack_ranges = RangeSet::default();
    let first = frame_type as u8;

    // The largest packet number the peer is acknowledging
    let largest_ack = b.read_varint()?;

    // The acknowledgment delay in microseconds
    let ack_delay = b.read_varint()?;

    // The number of ACK Range fields in the frame.
    let range_count = b.read_varint()?;

    // The number of contiguous packets preceding the Largest Acknowledged that
    // are being acknowledged.
    let ack_range_len = b.read_varint()?;
    if largest_ack < ack_range_len {
        return Err(Error::FrameEncodingError);
    }
    let mut smallest_ack = largest_ack - ack_range_len;
    ack_ranges.insert(smallest_ack..largest_ack + 1);

    for _i in 0..range_count {
        // The number of contiguous unacknowledged packets preceding the packet
        // number one lower than the smallest in the preceding ACK Range.
        let gap = b.read_varint()?;
        if smallest_ack < 2 + gap {
            return Err(Error::FrameEncodingError);
        }
        let largest_ack = (smallest_ack - gap) - 2;

        // The number of contiguous acknowledged packets in the current ACK Range.
        let ack_range_len = b.read_varint()?;
        if largest_ack < ack_range_len {
            return Err(Error::FrameEncodingError);
        }
        smallest_ack = largest_ack - ack_range_len;

        ack_ranges.insert(smallest_ack..largest_ack + 1);
    }

    let ecn_counts = if first & 0x01 != 0 {
        Some(EcnCounts {
            // The total number of packets received with the ECT(0) codepoint
            // in the packet number space of the ACK frame.
            ect0_count: b.read_varint()?,
            // The total number of packets received with the ECT(1) codepoint
            // in the packet number space of the ACK frame.
            ect1_count: b.read_varint()?,
            // The total number of packets received with the ECN-CE codepoint
            // in the packet number space of the ACK frame.
            ecn_ce_count: b.read_varint()?,
        })
    } else {
        None
    };

    Ok((
        Frame::Ack {
            ack_delay,
            ack_ranges,
            ecn_counts,
        },
        len - b.len(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn paddings() -> Result<()> {
        let frame = Frame::Paddings { len: 128 };
        assert_eq!(format!("{:?}", &frame), "PADDINGS len=128");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 128);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!(
            (frame, 128),
            Frame::from_bytes(&mut buf, PacketType::OneRTT)?
        );
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        Ok(())
    }

    #[test]
    fn ping() -> Result<()> {
        let frame = Frame::Ping;
        assert_eq!(format!("{:?}", &frame), "PING");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 1);
        assert_eq!(&buf[..len], [0x01]);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 1), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        Ok(())
    }

    #[test]
    fn ack() -> Result<()> {
        let mut ranges = RangeSet::default();
        ranges.insert(0..8);
        ranges.insert(10..15);
        ranges.insert(21..30);
        let frame = Frame::Ack {
            ack_delay: 200000,
            ack_ranges: ranges,
            ecn_counts: Some(EcnCounts {
                ect0_count: 1,
                ect1_count: 2,
                ecn_ce_count: 3,
            }),
        };
        assert_eq!(
            format!("{:?}", &frame),
            "ACK delay=200000 \
            ranges=[0..7, 10..14, 21..29] \
            ecn_counts=Some(EcnCounts \
            { ect0_count: 1, ect1_count: 2, ecn_ce_count: 3 })"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 15);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!(
            (frame, 15),
            Frame::from_bytes(&mut buf, PacketType::OneRTT)?
        );
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_err());
        Ok(())
    }

    #[test]
    fn reset_stream() -> Result<()> {
        let frame = Frame::ResetStream {
            stream_id: 120,
            error_code: 3,
            final_size: 4192,
        };
        assert_eq!(
            format!("{:?}", &frame),
            "RESET_STREAM id=120 err=3 size=4192"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 6);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 6), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn stop_sending() -> Result<()> {
        let frame = Frame::StopSending {
            stream_id: 120,
            error_code: 3,
        };
        assert_eq!(format!("{:?}", &frame), "STOP_SENDING id=120 err=3");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 4);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 4), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn crypto() -> Result<()> {
        let data = Bytes::copy_from_slice(&[5; 50]);
        let frame = Frame::Crypto {
            offset: 1000,
            length: 50,
            data,
        };
        assert_eq!(format!("{:?}", &frame), "CRYPTO off=1000 len=50");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 55);
        assert_eq!(crypto_header_wire_len(800), 5);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!(
            (frame, 55),
            Frame::from_bytes(&mut buf, PacketType::OneRTT)?
        );
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_ok());
        Ok(())
    }

    #[test]
    fn new_token() -> Result<()> {
        let frame = Frame::NewToken {
            token: Vec::from("a stub address token"),
        };
        assert_eq!(format!("{:?}", &frame), "NEW_TOKEN");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 22);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!(
            (frame, 22),
            Frame::from_bytes(&mut buf, PacketType::OneRTT)?
        );
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn stream() -> Result<()> {
        let data = Bytes::copy_from_slice(&[7; 80]);
        let frame = Frame::Stream {
            stream_id: 4,
            offset: 800,
            length: 80,
            fin: false,
            data,
        };
        assert_eq!(
            format!("{:?}", &frame),
            "STREAM id=4 off=800 len=80 fin=false"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 86);
        assert_eq!(stream_header_wire_len(4, 800), 6);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!(
            (frame, 86),
            Frame::from_bytes(&mut buf, PacketType::OneRTT)?
        );
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn max_data() -> Result<()> {
        let frame = Frame::MaxData { max: 128000 };
        assert_eq!(format!("{:?}", &frame), "MAX_DATA max=128000");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 5);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 5), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn max_stream_data() -> Result<()> {
        let frame = Frame::MaxStreamData {
            stream_id: 8,
            max: 128000,
        };
        assert_eq!(format!("{:?}", &frame), "MAX_STREAM_DATA id=8 max=128000");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 6);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 6), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn max_streams_bidi() -> Result<()> {
        let frame = Frame::MaxStreams {
            bidi: true,
            max: 100,
        };
        assert_eq!(format!("{:?}", &frame), "MAX_STREAMS bidi=true max=100");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 3);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 3), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn max_streams_uni() -> Result<()> {
        let frame = Frame::MaxStreams {
            bidi: false,
            max: 200,
        };
        assert_eq!(format!("{:?}", &frame), "MAX_STREAMS bidi=false max=200");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 3);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 3), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn data_blocked() -> Result<()> {
        let frame = Frame::DataBlocked { max: 2049 };
        assert_eq!(format!("{:?}", &frame), "DATA_BLOCKED max=2049");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 3);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 3), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn stream_data_blocked() -> Result<()> {
        let frame = Frame::StreamDataBlocked {
            stream_id: 8,
            max: 2049,
        };
        assert_eq!(format!("{:?}", &frame), "STREAM_DATA_BLOCKED id=8 max=2049");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 4);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 4), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn streams_blocked_bidi() -> Result<()> {
        let frame = Frame::StreamsBlocked {
            bidi: true,
            max: 200,
        };
        assert_eq!(format!("{:?}", &frame), "STREAMS_BLOCKED bidi=true max=200");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 3);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 3), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn streams_blocked_uni() -> Result<()> {
        let frame = Frame::StreamsBlocked {
            bidi: false,
            max: 200,
        };
        assert_eq!(
            format!("{:?}", &frame),
            "STREAMS_BLOCKED bidi=false max=200"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 3);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 3), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn new_connection_id() -> Result<()> {
        let frame = Frame::NewConnectionId {
            seq_num: 20,
            retire_prior_to: 19,
            conn_id: ConnectionId {
                len: 20,
                data: [1; 20],
            },
            reset_token: ResetToken([2; 16]),
        };
        assert_eq!(
            format!("{:?}", &frame),
            "NEW_CONNECTION_ID \
            seq=20 retire_prior_to=19 \
            cid=0101010101010101010101010101010101010101 \
            reset_token=02020202020202020202020202020202"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 40);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!(
            (frame, 40),
            Frame::from_bytes(&mut buf, PacketType::OneRTT)?
        );
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn retire_connection_id() -> Result<()> {
        let frame = Frame::RetireConnectionId { seq_num: 100 };
        assert_eq!(format!("{:?}", &frame), "RETIRE_CONNECTION_ID seq=100");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 3);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 3), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn path_challenge() -> Result<()> {
        let frame = Frame::PathChallenge { data: [1; 8] };
        assert_eq!(
            format!("{:?}", &frame),
            "PATH_CHALLENGE \
            data=[01, 01, 01, 01, 01, 01, 01, 01]"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 9);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 9), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn path_response() -> Result<()> {
        let frame = Frame::PathResponse { data: [2; 8] };
        assert_eq!(
            format!("{:?}", &frame),
            "PATH_RESPONSE \
            data=[02, 02, 02, 02, 02, 02, 02, 02]"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 9);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 9), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn connection_close() -> Result<()> {
        let frame = Frame::ConnectionClose {
            error_code: 0xe,
            frame_type: 2,
            reason: vec![1, 2, 3, 4],
        };
        assert_eq!(
            format!("{:?}", &frame),
            "CONNECTION_CLOSE err=e frame=2 reason=[1, 2, 3, 4]"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 8);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 8), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_ok());
        Ok(())
    }

    #[test]
    fn application_close() -> Result<()> {
        let frame = Frame::ApplicationClose {
            error_code: 0xe,
            reason: vec![1, 2, 3, 4],
        };
        assert_eq!(
            format!("{:?}", &frame),
            "APPLICATION_CLOSE err=e reason=[1, 2, 3, 4]"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 7);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 7), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn handshake_done() -> Result<()> {
        let frame = Frame::HandshakeDone;
        assert_eq!(format!("{:?}", &frame), "HANDSHAKE_DONE");

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 1);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 1), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn path_abandon() -> Result<()> {
        let frame = Frame::PathAbandon {
            dcid_seq_num: 1,
            error_code: 0xf,
            reason: vec![1, 2, 3, 4],
        };
        assert_eq!(
            format!("{:?}", &frame),
            "PATH_ABANDON dcid_seq_num=1 err=f reason=[1, 2, 3, 4]"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 11);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!(
            (frame, 11),
            Frame::from_bytes(&mut buf, PacketType::OneRTT)?
        );
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn path_status() -> Result<()> {
        let frame = Frame::PathStatus {
            dcid_seq_num: 1,
            seq_num: 2,
            status: 3,
        };
        assert_eq!(
            format!("{:?}", &frame),
            "PATH_STATUS dcid_seq_num=1 seq_num=2 status=3"
        );

        let mut buf = [0; 128];
        let len = frame.to_bytes(&mut buf[..])?;
        assert_eq!(len, frame.wire_len());
        assert_eq!(len, 7);

        let mut buf = Bytes::copy_from_slice(&buf);
        assert_eq!((frame, 7), Frame::from_bytes(&mut buf, PacketType::OneRTT)?);
        assert!(Frame::from_bytes(&mut buf, PacketType::ZeroRTT).is_ok());
        assert!(Frame::from_bytes(&mut buf, PacketType::Initial).is_err());
        assert!(Frame::from_bytes(&mut buf, PacketType::Handshake).is_err());
        Ok(())
    }

    #[test]
    fn special_frames() -> Result<()> {
        assert_eq!(
            Frame::Ack {
                ack_delay: 200000,
                ack_ranges: RangeSet::default(),
                ecn_counts: None,
            }
            .ack_eliciting(),
            false
        );
        assert_eq!(
            Frame::ApplicationClose {
                error_code: 0x3,
                reason: vec![1, 2, 3]
            }
            .ack_eliciting(),
            false
        );
        assert_eq!(
            Frame::ConnectionClose {
                error_code: 0x3,
                frame_type: 1,
                reason: vec![1, 2, 3]
            }
            .ack_eliciting(),
            false
        );
        assert_eq!(
            Frame::NewConnectionId {
                seq_num: 1,
                retire_prior_to: 1,
                conn_id: ConnectionId::random(),
                reset_token: ResetToken([0xa; 16])
            }
            .probing(),
            true
        );
        assert_eq!(Frame::PathChallenge { data: [1; 8] }.probing(), true);
        assert_eq!(Frame::PathResponse { data: [1; 8] }.probing(), true);

        Ok(())
    }

    #[test]
    fn stream_buffer_too_short() -> Result<()> {
        let mut buf = Bytes::from_static(&[
            0x0e, 0x00, 0x00, 0x1c, 0x80, 0x00, 0xcf, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ]);
        assert_eq!(
            Frame::from_bytes(&mut buf, PacketType::OneRTT),
            Err(Error::BufferTooShort)
        );

        Ok(())
    }
}
