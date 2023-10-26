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
use log::*;

use super::frame;
use super::Http3Error;
use super::Result;
use crate::codec;
use crate::codec::Decoder;
use crate::codec::Encoder;

// HTTP/3 stream type identifiers.
// RFC9114 Reserved Stream Types: 0x1f * N + 0x21 for N = 0, 1, 2, ...
pub const HTTP3_CONTROL_STREAM_TYPE: u64 = 0x0;
pub const HTTP3_PUSH_STREAM_TYPE: u64 = 0x1;
pub const QPACK_ENCODER_STREAM_TYPE: u64 = 0x2;
pub const QPACK_DECODER_STREAM_TYPE: u64 = 0x3;

const INIT_STATE_BUF_SIZE: usize = 16;
const MAX_STATE_BUF_SIZE: usize = (1 << 24) - 1;

/// An HTTP/3 stream.
#[derive(Debug)]
pub struct Http3Stream {
    /// Whether the stream was created by the local endpoint.
    local: bool,

    /// The related quic transport stream's ID, which is used to interact with the quic transport.
    stream_id: u64,

    /// Stream's type when it is known.
    stream_type: Option<Http3StreamType>,

    /// Current parsing frame type.
    frame_type: Option<u64>,

    /// Stream state machine.
    state: Http3StateMachine,

    /// Whether the stream has been initialized by the peer endpoint.
    peer_initialized: bool,

    /// Whether the stream has been initialized by the local endpoint.
    local_initialized: bool,

    /// Whether all the application data with fin has been written to quic stream buffer.
    write_finished: bool,

    /// Whether the stream's data event has been triggered.
    data_event_triggered: bool,

    /// Whether the stream's priority has been initialized in HTTP/3 layer.
    /// Note that the HTTP/3 stream default priority may different from the underlying
    /// quic transport stream's priority.
    priority_initialized: bool,

    /// The last priority_update extracted from the PRIORITY_UPDATE frame sent by the peer.
    priority_update: Option<Vec<u8>>,

    /// Stream header blocked by flow control, buffered here until it can be sent fully.
    /// The tuple contains the encoded header block and whether it carries the fin flag.
    header_block: Option<(Bytes, bool)>,
}

impl Http3Stream {
    /// Create a new HTTP/3 stream.
    pub fn new(stream_id: u64, local: bool) -> Http3Stream {
        let (stream_type, state) = match crate::connection::stream::is_bidi(stream_id) {
            // The initial state of a bidirectional stream, i.e. request stream, is `FrameType`.
            true => (Some(Http3StreamType::Request), Http3StreamState::FrameType),

            // The initial state of a unidirectional stream is `StreamType`, because the stream
            // type is unknown until the first byte is read and parsed.
            false => (None, Http3StreamState::StreamType),
        };

        Http3Stream {
            local,
            stream_id,
            stream_type,

            frame_type: None,
            state: Http3StateMachine::new(state),

            peer_initialized: false,
            local_initialized: false,
            write_finished: false,
            data_event_triggered: false,
            priority_initialized: false,
            priority_update: None,
            header_block: None,
        }
    }

    /// Check if the frame type is allowed on the control stream.
    ///
    /// Note that this method doesn't check the stream's initiator.
    fn check_frame_on_control_stream(&mut self, frame_type: u64) -> Result<()> {
        match (frame_type, self.peer_initialized) {
            // Receive SETTINGS frame on control stream's first frame, mark the stream as initialized by remote.
            (frame::SETTINGS_FRAME_TYPE, false) => self.peer_initialized = true,

            // Each side MUST initiate a single control stream at the beginning of the connection and send
            // its SETTINGS frame as the first frame on this stream. If the first frame of the control stream
            // is any other frame type, this MUST be treated as a connection error of type H3_MISSING_SETTINGS.
            (_, false) => return Err(Http3Error::MissingSettings),

            // A SETTINGS frame MUST be sent as the first frame of each control stream (see Section 6.2.1) by each peer,
            // and it MUST NOT be sent subsequently. If an endpoint receives a second SETTINGS frame on the control stream,
            // the endpoint MUST respond with a connection error of type H3_FRAME_UNEXPECTED.
            (frame::SETTINGS_FRAME_TYPE, true) => return Err(Http3Error::FrameUnexpected),

            // RFC9114 7. Table 1: HTTP/3 Frames and Stream Type Overview
            // `DATA`, `HEADERS` and `PUSH_PROMISE` frames MUST NOT be sent on the control stream.
            (frame::DATA_FRAME_TYPE, true) => return Err(Http3Error::FrameUnexpected),
            (frame::HEADERS_FRAME_TYPE, true) => return Err(Http3Error::FrameUnexpected),
            (frame::PUSH_PROMISE_FRAME_TYPE, true) => return Err(Http3Error::FrameUnexpected),

            (_, true) => (),
        }

        Ok(())
    }

    /// Check if the frame type is allowed on the request stream.
    ///
    /// Note that this method doesn't check the stream's initiator.
    fn check_frame_on_request_stream(&mut self, frame_type: u64) -> Result<()> {
        match (frame_type, self.peer_initialized) {
            // Receive HEADERS frame on request stream's first frame, mark the stream as initialized by remote.
            (frame::HEADERS_FRAME_TYPE, false) => self.peer_initialized = true,

            // Receipt of an invalid sequence of frames MUST be treated as a connection error of type H3_FRAME_UNEXPECTED.
            // In particular, a DATA frame before any HEADERS frame, or a HEADERS or DATA frame after the trailing HEADERS
            // frame, is considered invalid.
            (frame::DATA_FRAME_TYPE, false) => return Err(Http3Error::FrameUnexpected),

            // RFC9114 7. Table 1: HTTP/3 Frames and Stream Type Overview
            // `CANCEL_PUSH`, `SETTINGS`, `GOAWAY`, and `MAX_PUSH_ID` frames MUST NOT be sent on the request stream.
            (frame::CANCEL_PUSH_FRAME_TYPE, _) => return Err(Http3Error::FrameUnexpected),
            (frame::SETTINGS_FRAME_TYPE, _) => return Err(Http3Error::FrameUnexpected),
            (frame::GOAWAY_FRAME_TYPE, _) => return Err(Http3Error::FrameUnexpected),
            (frame::MAX_PUSH_ID_FRAME_TYPE, _) => return Err(Http3Error::FrameUnexpected),

            // RFC9204 7.2. HTTP/3 PRIORITY_UPDATE Frame
            // The PRIORITY_UPDATE frame MUST be sent on the client control stream (see Section 6.2.1 of [HTTP/3]).
            // Receiving a PRIORITY_UPDATE frame on a stream other than the client control stream MUST be treated as
            // a connection error of type H3_FRAME_UNEXPECTED.
            (frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE, _) => {
                return Err(Http3Error::FrameUnexpected)
            }
            (frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE, _) => return Err(Http3Error::FrameUnexpected),

            // PUSH_PROMISE or Reserved Frames
            _ => (),
        }

        Ok(())
    }

    /// Check if the frame type is allowed on the push stream.
    fn check_frame_on_push_stream(&mut self, frame_type: u64) -> Result<()> {
        match frame_type {
            // RFC9114 7. Table 1: HTTP/3 Frames and Stream Type Overview
            // `CANCEL_PUSH`, `SETTINGS`, `PUSH_PROMISE`, `GOAWAY`, and `MAX_PUSH_ID` frames MUST NOT be sent on the push stream.
            frame::CANCEL_PUSH_FRAME_TYPE => return Err(Http3Error::FrameUnexpected),
            frame::SETTINGS_FRAME_TYPE => return Err(Http3Error::FrameUnexpected),
            frame::PUSH_PROMISE_FRAME_TYPE => return Err(Http3Error::FrameUnexpected),
            frame::GOAWAY_FRAME_TYPE => return Err(Http3Error::FrameUnexpected),
            frame::MAX_PUSH_ID_FRAME_TYPE => return Err(Http3Error::FrameUnexpected),

            // RFC9204 7.2. HTTP/3 PRIORITY_UPDATE Frame
            // The PRIORITY_UPDATE frame MUST be sent on the client control stream (see Section 6.2.1 of [HTTP/3]).
            // Receiving a PRIORITY_UPDATE frame on a stream other than the client control stream MUST be treated as
            // a connection error of type H3_FRAME_UNEXPECTED.
            frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE => return Err(Http3Error::FrameUnexpected),
            frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE => return Err(Http3Error::FrameUnexpected),

            _ => (),
        }

        Ok(())
    }

    /// Get the stream's type.
    pub fn stream_type(&self) -> Option<Http3StreamType> {
        self.stream_type
    }

    /// Set the stream's type and transition state.
    fn set_stream_type(&mut self, stream_type: Http3StreamType) -> Result<()> {
        self.stream_type = Some(stream_type);

        let state = match stream_type {
            // RFC9114 Control Streams
            // Each side MUST initiate a single control stream at the beginning of the connection and
            // send its SETTINGS frame as the first frame on this stream.
            //
            // Expressing HTTP Semantics in HTTP/3
            // An HTTP message (request or response) consists of:
            //  1.the header section, including message control data, sent as a single HEADERS frame,
            //  2.optionally, the content, if present, sent as a series of DATA frames, and
            //  3.optionally, the trailer section, if present, sent as a single HEADERS frame.
            Http3StreamType::Control | Http3StreamType::Request => Http3StreamState::FrameType,

            // RFC9114 Push Streams
            // A push stream is indicated by a stream type of 0x01, followed by the push ID of
            // the promise that it fulfills, encoded as a variable-length integer.
            Http3StreamType::Push => Http3StreamState::PushId,

            // RFC9204 QPACK encoder stream
            Http3StreamType::QpackEncoder => {
                self.peer_initialized = true;
                Http3StreamState::QpackEncoderInstruction
            }

            // RFC9204 QPACK decoder stream
            Http3StreamType::QpackDecoder => {
                self.peer_initialized = true;
                Http3StreamState::QpackDecoderInstruction
            }

            // Ignore unknown stream types.
            Http3StreamType::Unknown(_) => Http3StreamState::Skip,
        };

        // Transition to the next state, and resize the expected bytes needed to complete the state.
        self.transition_state(state, 1, true)?;

        Ok(())
    }

    /// Parse unidirectional stream type.
    pub fn parse_uni_stream_type(
        &mut self,
        conn: &mut crate::Connection,
    ) -> Result<Http3StreamType> {
        // Parse stream type id from quic stream bytes.
        let type_id = self.read_and_parse_varint(conn)?;

        // Get stream type from stream type id.
        let stream_type = Http3StreamType::from_id(type_id)?;
        // Set stream type and transition stream state.
        if let Err(e) = self.set_stream_type(stream_type) {
            conn.close(true, e.to_wire(), b"")?;
            return Err(e);
        }

        Ok(stream_type)
    }

    /// Set push ID and transition state to FrameType.
    fn set_push_id(&mut self, push_id: u64) -> Result<()> {
        // Ignore push ID temporarily.

        trace!(
            "stream {} set push id {:?}, transition state from {:?} to FrameType",
            self.stream_id,
            push_id,
            self.state()
        );

        // RFC9114 6.2.2. Push Streams
        // A push stream is indicated by a stream type of 0x01, followed by the push ID of the
        // promise that it fulfills, encoded as a variable-length integer. The remaining data on
        // this stream consists of HTTP/3 frames, as defined in Section 7.2, and fulfills a promised
        // server push by zero or more interim HTTP responses followed by a single final HTTP response,
        // as defined in Section 4.1. Server push and push IDs are described in Section 4.6.

        // Transition the stream state to FrameType and resize the expected bytes to 1.
        self.transition_state(Http3StreamState::FrameType, 1, true)?;

        Ok(())
    }

    /// Parse push id.
    pub fn parse_push_id(&mut self, conn: &mut crate::Connection) -> Result<()> {
        // Decode push_id from quic stream bytes.
        let push_id = self.read_and_parse_varint(conn)?;

        if let Err(e) = self.set_push_id(push_id) {
            conn.close(true, e.to_wire(), b"")?;
            return Err(e);
        }

        Ok(())
    }

    /// Set the current parsing frame type and transition state to FramePayloadLen.
    fn set_frame_type(&mut self, frame_type: u64) -> Result<()> {
        trace!(
            "stream {} set frame type {:?}, transition state from {:?} to FramePayloadLen",
            self.stream_id,
            frame_type,
            self.state()
        );

        // Check if the frame type is allowed on the current stream type.
        // Only Control, Request and Push streams can receive HTTP/3 frames.
        match self.stream_type {
            Some(Http3StreamType::Control) => {
                self.check_frame_on_control_stream(frame_type)?;
            }
            Some(Http3StreamType::Request) => {
                self.check_frame_on_request_stream(frame_type)?;
            }
            Some(Http3StreamType::Push) => {
                self.check_frame_on_push_stream(frame_type)?;
            }
            _ => return Err(Http3Error::FrameUnexpected),
        }

        self.frame_type = Some(frame_type);

        // Transition the stream state to FramePayloadLen and resize the expected bytes to 1,
        // which is needed to parse the frame payload length.
        self.transition_state(Http3StreamState::FramePayloadLen, 1, true)?;

        Ok(())
    }

    /// Parse frame type from quic stream bytes.
    pub fn parse_frame_type(&mut self, conn: &mut crate::Connection) -> Result<()> {
        // Decode frame type from quic stream bytes.
        let frame_type = self.read_and_parse_varint(conn)?;

        // Set current parsing frame type and transition state to FramePayloadLen.
        match self.set_frame_type(frame_type) {
            Err(Http3Error::FrameUnexpected) => {
                let msg = format!("unexpected frame type {frame_type}");
                conn.close(true, Http3Error::FrameUnexpected.to_wire(), msg.as_bytes())?;

                return Err(Http3Error::FrameUnexpected);
            }

            Err(e) => {
                let msg = format!("handle frame {frame_type} error");
                conn.close(true, e.to_wire(), msg.as_bytes())?;

                return Err(e);
            }

            _ => (),
        }

        Ok(())
    }

    /// Set the frame's payload length and transition state.
    fn set_frame_payload_len(&mut self, frame_payload_len: u64) -> Result<()> {
        let (state, resize) = match self.frame_type {
            // `DATA` frame payload will be read from the quic transport stream directly.
            // We transition state to Data, but not FramePayload, to avoid unnecessary copy.
            Some(frame::DATA_FRAME_TYPE) => (Http3StreamState::Data, false),

            // `GOAWAY`, `PUSH_PROMISE`, `CANCEL_PUSH`, `MAX_PUSH_ID` , `PRIORITY_UPDATE` always need
            // additional data. If the payload length is 0, it means that the frame is malformed.
            Some(
                frame::GOAWAY_FRAME_TYPE
                | frame::PUSH_PROMISE_FRAME_TYPE
                | frame::CANCEL_PUSH_FRAME_TYPE
                | frame::MAX_PUSH_ID_FRAME_TYPE
                | frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE
                | frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE,
            ) => {
                // Each frame's payload MUST contain exactly the fields identified in its description.
                // A frame payload that contains additional bytes after the identified fields or a frame
                // payload that terminates before the end of the identified fields MUST be treated as a
                // connection error of type H3_FRAME_ERROR.
                if frame_payload_len == 0 {
                    return Err(Http3Error::FrameError);
                }

                (Http3StreamState::FramePayload, true)
            }

            _ => (Http3StreamState::FramePayload, true),
        };

        // Transition the stream state to FramePayload and resize the expected bytes to the payload length if needed.
        self.transition_state(state, frame_payload_len as usize, resize)?;

        Ok(())
    }

    /// Parse frame payload length.
    pub fn parse_frame_payload_length(&mut self, conn: &mut crate::Connection) -> Result<()> {
        // Decode frame payload length from quic stream bytes.
        let payload_len = self.read_and_parse_varint(conn)?;

        // DATA frame would not be processed by `process_frame`, we trace it here.
        if Some(frame::DATA_FRAME_TYPE) == self.frame_type {
            trace!(
                "{:?} recv DATA frame on stream {}, payload_len={}",
                conn.trace_id(),
                self.stream_id,
                payload_len
            );
        }

        // Set current parsing frame payload length and transition state.
        if let Err(e) = self.set_frame_payload_len(payload_len) {
            conn.close(true, e.to_wire(), b"")?;
            return Err(e);
        }

        Ok(())
    }

    /// Read data from the related quic transport stream to fill the state buffer.
    ///
    /// Return `Http3Error::Done` if the state buffer is not complete.
    fn read_and_fill_buffer(&mut self, conn: &mut crate::Connection) -> Result<()> {
        // If there have enough data for the current state, return early.
        if self.state.ready() {
            return Ok(());
        }

        // Get the remaining space in the state buffer.
        let buf = &mut self.state.buf[self.state.write_off..self.state.expected_len];
        // Read data from the quic transport stream.
        let read = match conn.stream_read(self.stream_id, buf) {
            Ok((len, _)) => len,
            Err(e) => {
                trace!(
                    "{:?} stream {} read data from quic, error {:?}",
                    conn.trace_id(),
                    self.stream_id,
                    e
                );

                // The stream is not readable temporarily, reset data event state to false.
                if e == crate::Error::Done {
                    self.reset_data_event_state();
                }

                // Convert the quic transport error to http3 error.
                return Err(e.into());
            }
        };

        self.state.increase_off(read);

        trace!(
            "{:?} read {} bytes from quic stream {}, state: write_off {} expected_len {}",
            conn.trace_id(),
            read,
            self.stream_id,
            self.state.write_off,
            self.state.expected_len
        );

        // The state buffer still not enough to complete the state, reset data event state to false.
        if !self.state.ready() {
            self.reset_data_event_state();

            return Err(Http3Error::Done);
        }

        Ok(())
    }

    /// Read data from quic stream buffer and try to parse a varint from the bytes.
    fn read_and_parse_varint(&mut self, conn: &mut crate::Connection) -> Result<u64> {
        // Try to read enough data for parsing varint.
        self.read_and_fill_buffer(conn)?;

        // Decode varint from quic stream bytes.
        match self.state.parse_varint() {
            Ok(v) => Ok(v),
            Err(Http3Error::Done) => {
                // The length of varint is initially unknown and can only be determined in
                // `self.state.parse_varint()`. For this case, we should try to refill and
                // parse again.
                self.read_and_fill_buffer(conn)?;
                let varint = self.state.parse_varint()?;
                Ok(varint)
            }
            Err(e) => Err(e),
        }
    }

    /// Read data from quic stream buffer and try to parse an HTTP/3 frame from the bytes.
    fn parse_frame_payload_inner(
        &mut self,
        conn: &mut crate::Connection,
    ) -> Result<(frame::Http3Frame, u64)> {
        // Try to read enough data for parsing frame payload.
        self.read_and_fill_buffer(conn)?;

        // Processing a non-DATA frame, reset the data event.
        self.reset_data_event_state();

        let payload_len = self.state.expected_len as u64;

        let frame = frame::Http3Frame::decode_payload(
            self.frame_type.unwrap(),
            payload_len,
            &self.state.buf,
        )?;

        // Transition the stream state to FrameType and resize the expected bytes to 1.
        // Note that we don't known the expected bytes needed to complete the frame type,
        // so we just set it to 1 here, and it will be updated in `self.state.parse_varint()`.
        self.transition_state(Http3StreamState::FrameType, 1, true)?;

        Ok((frame, payload_len))
    }

    /// Parse frame payload.
    pub fn parse_frame_payload(
        &mut self,
        conn: &mut crate::Connection,
    ) -> Result<(frame::Http3Frame, u64)> {
        match self.parse_frame_payload_inner(conn) {
            Ok(v) => Ok(v),
            Err(Http3Error::Done) => Err(Http3Error::Done),
            Err(e) => {
                error!(
                    "{:?} stream {} parse frame {:?} error {:?}",
                    conn.trace_id(),
                    self.stream_id,
                    self.frame_type,
                    e
                );

                conn.close(true, e.to_wire(), b"parse frame error")?;

                Err(e)
            }
        }
    }

    /// Read DATA frame's payload from the quic transport stream buffer.
    pub fn read_data_from_quic(
        &mut self,
        conn: &mut crate::Connection,
        out: &mut [u8],
    ) -> Result<(usize, bool)> {
        let expected_len = std::cmp::min(out.len(), self.state.remaining_len());

        // Try to read data from the quic transport stream.
        let (len, fin) = match conn.stream_read(self.stream_id, &mut out[..expected_len]) {
            Ok(v) => v,
            Err(e) => {
                // `Error::Done` means that the stream is not readable temporarily.
                // We should reset data event state to false.
                if e == crate::Error::Done {
                    self.reset_data_event_state();
                }

                return Err(e.into());
            }
        };

        // Increase the state buffer's write offset.
        self.state.increase_off(len);

        // There are no more data can be read now, reset data event.
        if !conn.stream_readable(self.stream_id) {
            self.reset_data_event_state();
        }

        // The current DATA frame payload has been read completely, transition
        // the stream state to FrameType and resize the expected bytes to 1.
        if self.state.ready() {
            self.transition_state(Http3StreamState::FrameType, 1, true)?;
        }

        Ok((len, fin))
    }

    /// Update the stream's data triggered state.
    pub fn trigger_data_event(&mut self) -> bool {
        match self.data_event_triggered {
            false => {
                self.data_event_triggered = true;
                true
            }
            true => false,
        }
    }

    /// Reset the data event triggered state.
    fn reset_data_event_state(&mut self) {
        self.data_event_triggered = false;
    }

    /// Mark the stream's read part finished, only request and push streams can be marked as finished.
    pub fn mark_read_finished(&mut self) {
        let _ = self.transition_state(Http3StreamState::ReadFinished, 0, false);
    }

    /// Return true if the stream's write part has been finished.
    pub fn write_finished(&self) -> bool {
        self.write_finished
    }

    /// Mark the stream's write part finished, only request and push streams can be marked as finished.
    pub fn mark_write_finished(&mut self) {
        self.write_finished = true;
    }

    /// Return true if the stream's local part has been initialized.
    pub fn local_initialized(&self) -> bool {
        self.local_initialized
    }

    /// Mark the stream as locally initialized.
    pub fn mark_local_initialized(&mut self) {
        self.local_initialized = true
    }

    /// Return true if the stream's priority has been initialized.
    pub fn priority_initialized(&self) -> bool {
        self.priority_initialized
    }

    /// Mark the stream's priority as initialized.
    pub fn mark_priority_initialized(&mut self) {
        self.priority_initialized = true
    }

    /// Get the stream's current state.
    pub fn state(&self) -> Http3StreamState {
        self.state.state
    }

    /// Transition stream to the new state, and update the state fields optionally.
    fn transition_state(
        &mut self,
        new_state: Http3StreamState,
        new_len: usize,
        resize: bool,
    ) -> Result<()> {
        trace!(
            "stream {} state transition {:?} -> {:?}, new_len {}, resize {}",
            self.stream_id,
            self.state(),
            new_state,
            new_len,
            resize
        );

        self.state.transition(new_state, new_len, resize)
    }

    /// Buffer the stream's priority_update.
    pub fn set_priority_update(&mut self, priority_update: Option<Vec<u8>>) {
        self.priority_update = priority_update;
    }

    /// Take the stream's cached priority_update.
    pub fn take_priority_update(&mut self) -> Option<Vec<u8>> {
        self.priority_update.take()
    }

    /// Return true if there is a priority_update.
    pub fn has_priority_update(&self) -> bool {
        self.priority_update.is_some()
    }

    /// Buffer the header_block until it can be sent fully.
    pub fn set_header_block(&mut self, header_block: Option<(Bytes, bool)>) {
        self.header_block = header_block;
    }

    /// Take the header_block and leave a `None` in its place.
    pub fn take_header_block(&mut self) -> Option<(Bytes, bool)> {
        self.header_block.take()
    }

    /// Return true if header_block has not been sent.
    pub fn has_header_block(&self) -> bool {
        self.header_block.is_some()
    }
}

/// HTTP/3 stream types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Http3StreamType {
    Control,
    Request,
    Push,
    QpackEncoder,
    QpackDecoder,
    /// Unknown stream type, the type id is provided as associated data.
    Unknown(u64),
}

impl Http3StreamType {
    /// Map a stream type ID to a `Http3StreamType`.
    pub fn from_id(type_id: u64) -> Result<Http3StreamType> {
        match type_id {
            HTTP3_CONTROL_STREAM_TYPE => Ok(Http3StreamType::Control),
            HTTP3_PUSH_STREAM_TYPE => Ok(Http3StreamType::Push),
            QPACK_ENCODER_STREAM_TYPE => Ok(Http3StreamType::QpackEncoder),
            QPACK_DECODER_STREAM_TYPE => Ok(Http3StreamType::QpackDecoder),

            _ => Ok(Http3StreamType::Unknown(type_id)),
        }
    }

    // TODO: add a method for generating one reserved stream type
}

#[derive(Debug)]
struct Http3StateMachine {
    /// Stream's current state.
    state: Http3StreamState,

    /// Temporary buffer used to holding partial data for the stream's current state.
    buf: Vec<u8>,

    /// The expected bytes needed to make the state ready, when `write_off` reach this
    /// value, the state is ready.
    expected_len: usize,

    /// The buffer's write offset, which represents the number of bytes that have been
    /// read from the quic transport for the current state. Once it reaches `expected_len`,
    /// it indicates that the state can be processed.
    write_off: usize,
}

impl Http3StateMachine {
    fn new(state: Http3StreamState) -> Http3StateMachine {
        Http3StateMachine {
            state,
            // We preallocate some space to avoid multiple small memory allocations.
            buf: vec![0; INIT_STATE_BUF_SIZE],
            write_off: 0,
            // 1 byte is used to parse the initial varint length.
            expected_len: 1,
        }
    }

    fn ready(&self) -> bool {
        self.write_off == self.expected_len
    }

    fn resize(&mut self, new_len: usize, value: u8) {
        self.buf.resize(new_len, value);
    }

    fn remaining_len(&self) -> usize {
        self.expected_len - self.write_off
    }

    fn increase_off(&mut self, len: usize) {
        self.write_off += len;
    }

    fn transition(
        &mut self,
        new_state: Http3StreamState,
        new_len: usize,
        resize: bool,
    ) -> Result<()> {
        // The state buffer not always need in some states, e.g. DATA and FINISHED states.
        // We don't resize it in these states to avoid unnecessary memory operations.
        if resize {
            // We need to limit the maximum size to avoid DoS.
            if new_len > MAX_STATE_BUF_SIZE {
                return Err(Http3Error::ExcessiveLoad);
            }

            // Resize the state buffer to the new expected length.
            self.resize(new_len, 0);
        }

        self.state = new_state;
        self.write_off = 0;
        self.expected_len = new_len;

        Ok(())
    }

    /// Try to parse a variable-length integer from the buffer.
    fn parse_varint(&mut self) -> Result<u64> {
        if self.write_off == 1 {
            // Get the length of the varint.
            self.expected_len = codec::decode_varint_len(self.buf[0]);
            // Resize the buffer to match the expected length to complete the state.
            self.buf.resize(self.expected_len, 0);
        }

        // There are not enough data in the buffer to parse the varint, return early.
        if !self.ready() {
            return Err(Http3Error::Done);
        }

        let mut b = &self.buf[..];
        let varint = b.read_varint()?;

        Ok(varint)
    }
}

/// HTTP/3 stream states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Http3StreamState {
    /// Reading and parsing stream type, only used for unidirectional streams.
    StreamType,

    /// Reading and parsing the current frame's type.
    FrameType,

    /// Reading and parsing the current frame's payload length.
    FramePayloadLen,

    /// Reading and parsing the current frame's payload, excluding DATA frame.
    FramePayload,

    /// Reading and parsing DATA frame's payload.
    Data,

    /// Reading and parsing the push ID.
    PushId,

    /// Reading and parsing QPACK encoder instructions.
    QpackEncoderInstruction,

    /// Reading and parsing QPACK decoder instructions.
    QpackDecoderInstruction,

    /// Reading and skipping data.
    Skip,

    /// All stream data has been read, including the FIN flag.
    ReadFinished,
}

#[doc(hidden)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3::frame::*;

    /// Create a new request stream and check its initial state.
    fn create_request_stream(stream_id: u64, local: bool) -> Result<Http3Stream> {
        let stream = Http3Stream::new(stream_id, local);
        assert_eq!(stream.stream_type, Some(Http3StreamType::Request));
        assert_eq!(stream.state(), Http3StreamState::FrameType);
        Ok(stream)
    }

    /// Create a new unidirectional stream and check its initial state.
    fn create_uni_stream(stream_id: u64, local: bool) -> Result<Http3Stream> {
        let stream = Http3Stream::new(stream_id, local);
        assert_eq!(stream.stream_type, None);
        assert_eq!(stream.state(), Http3StreamState::StreamType);
        Ok(stream)
    }

    /// Try to parse one varint from stream buffer.
    pub fn read_and_parse_varint(
        stream: &mut Http3Stream,
        cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<u64> {
        // Try to read enough data for parsing varint.
        read_and_fill_buffer(stream, cursor)?;

        // Decode varint from quic stream bytes.
        match stream.state.parse_varint() {
            Ok(v) => Ok(v),
            Err(Http3Error::Done) => {
                // The length of varint is initially unknown and can only be determined in
                // state.parse_varint. For this case, we should try to refill and parse again.
                read_and_fill_buffer(stream, cursor)?;
                let varint = stream.state.parse_varint()?;
                Ok(varint)
            }
            Err(e) => Err(e),
        }
    }

    /// Parse push_id from the cursor and match it with the expected push_id.
    fn parse_push_id(
        stream: &mut Http3Stream,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        expected_push_id: u64,
    ) -> Result<()> {
        // Decode push_id from quic stream bytes.
        let push_id = read_and_parse_varint(stream, cursor)?;
        assert_eq!(push_id, expected_push_id);

        stream.set_push_id(push_id)
    }

    /// Parse the stream type from the cursor and match it with the expected stream type.
    fn parse_uni_stream_type(
        stream: &mut Http3Stream,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        expected_stream_type: u64,
    ) -> Result<()> {
        let stream_type = read_and_parse_varint(stream, cursor)?;
        assert_eq!(stream_type, expected_stream_type);
        stream.set_stream_type(Http3StreamType::from_id(stream_type).unwrap())?;

        Ok(())
    }

    /// Parse the frame type from the cursor and match it with the expected frame type.
    fn parse_frame_type(
        stream: &mut Http3Stream,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        expected_frame_type: u64,
    ) -> Result<()> {
        let frame_type = read_and_parse_varint(stream, cursor)?;

        assert_eq!(frame_type, expected_frame_type);
        stream.set_frame_type(frame_type)?;

        Ok(())
    }

    /// Parse the frame payload length from the cursor and match it with the expected frame payload length.
    fn parse_frame_payload_length(
        stream: &mut Http3Stream,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        expected_frame_payload_len: u64,
    ) -> Result<()> {
        let frame_payload_len = read_and_parse_varint(stream, cursor)?;

        assert_eq!(frame_payload_len, expected_frame_payload_len);
        stream.set_frame_payload_len(frame_payload_len)?;

        Ok(())
    }

    /// Parse the frame payload from the cursor.
    fn parse_frame_payload(
        stream: &mut Http3Stream,
        cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<(frame::Http3Frame, u64)> {
        // Try to read enough data for parsing frame payload.
        read_and_fill_buffer(stream, cursor)?;

        // Processing a non-DATA frame, reset the data event.
        stream.reset_data_event_state();

        let payload_len = stream.state.expected_len as u64;

        let frame = frame::Http3Frame::decode_payload(
            stream.frame_type.unwrap(),
            payload_len,
            &stream.state.buf,
        )?;

        // Transition the stream state to FrameType and resize the expected bytes to 1.
        // Note that we don't known the expected bytes needed to complete the frame type,
        // so we just set it to 1 here, and it will be updated in `self.state.parse_varint()`.
        stream.transition_state(Http3StreamState::FrameType, 1, true)?;

        Ok((frame, payload_len))
    }

    /// Parse one frame from the cursor and discard it.
    fn parse_and_discard_frame(
        stream: &mut Http3Stream,
        cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<()> {
        // 1. Parse frame type from the cursor bytes and set it to the stream.
        let frame_type = read_and_parse_varint(stream, cursor)?;
        stream.set_frame_type(frame_type)?;
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // 2. Parse frame payload length from the cursor bytes and set it to the stream.
        let frame_payload_len = read_and_parse_varint(stream, cursor)?;
        stream.set_frame_payload_len(frame_payload_len)?;
        assert_eq!(stream.state(), Http3StreamState::FramePayload);

        // 3. Parse the frame payload from the cursor bytes and discard it.
        parse_frame_payload(stream, cursor)?;
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        Ok(())
    }

    /// Try to read DATA frame's payload from the given cursor.
    fn read_data_from_quic(
        stream: &mut Http3Stream,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        out: &mut [u8],
    ) -> Result<usize> {
        // Note that `state_len - state_off` is the remaining length of the current DATA frame payload.
        let expected_len = std::cmp::min(out.len(), stream.state.remaining_len());
        // Try to read data from the given cursor.
        let len = std::io::Read::read(cursor, &mut out[..expected_len]).unwrap();

        stream.state.increase_off(len);

        // The current DATA frame payload has been read completely, transition
        // the stream state to FrameType and resize the expected bytes to 1.
        if stream.state.ready() {
            stream.transition_state(Http3StreamState::FrameType, 1, true)?;
        }

        Ok(len)
    }

    /// Try to read data from the given cursor to fill the state buffer.
    fn read_and_fill_buffer(
        stream: &mut Http3Stream,
        cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> Result<()> {
        // If there have enough data for the current state, return early.
        if stream.state.ready() {
            return Ok(());
        }

        // Get the remaining space in the state buffer.
        let buf = &mut stream.state.buf[stream.state.write_off..stream.state.expected_len];

        // Read data from the given cursor.
        let read = std::io::Read::read(cursor, buf).unwrap();

        stream.state.increase_off(read);

        // The state buffer still not enough to complete the state, return `Http3Error::Done`.
        if !stream.state.ready() {
            return Err(Http3Error::Done);
        }

        Ok(())
    }

    // Test Http3StreamType::from_id
    #[test]
    fn uni_stream_type_id() {
        for (type_id, stream_type) in vec![
            // RFC9114 Defined Uni Stream Types
            (0x0, Http3StreamType::Control),
            (0x1, Http3StreamType::Push),
            // RFC9204 Defined Uni Stream Types
            (0x2, Http3StreamType::QpackEncoder),
            (0x3, Http3StreamType::QpackDecoder),
            (0x4, Http3StreamType::Unknown(0x4)),
            // RFC9114 Reserved Stream Types: 0x1f * N + 0x21 for N = 0, 1, 2, ...
            (33, Http3StreamType::Unknown(33)),
            (64, Http3StreamType::Unknown(64)),
        ] {
            assert_eq!(Http3StreamType::from_id(type_id), Ok(stream_type));
        }
    }

    // Test Http3Stream::new
    #[test]
    fn stream_new() {
        for stream_id in vec![0, 1, 2, 3, 4, 5, 6, 7] {
            for local in [true, false] {
                let stream = Http3Stream::new(stream_id, local);
                let (stream_type, state) = match crate::connection::stream::is_bidi(stream_id) {
                    true => (Some(Http3StreamType::Request), Http3StreamState::FrameType),
                    false => (None, Http3StreamState::StreamType),
                };

                assert_eq!(stream.stream_type(), stream_type);
                assert_eq!(stream.state(), state);
                assert_eq!(stream.state.ready(), false);

                assert_eq!(stream.local_initialized(), false);
                assert_eq!(stream.local_initialized, false);
                assert_eq!(stream.peer_initialized, false);

                assert_eq!(stream.data_event_triggered, false);

                assert_eq!(stream.frame_type, None);
                assert_eq!(stream.has_priority_update(), false);

                assert_eq!(stream.has_header_block(), false);
                assert_eq!(stream.write_finished(), false);
            }
        }
    }

    // Test Http3Stream::transition_state anti DoS
    #[test]
    fn state_transition_anti_dos() {
        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        let frame = Http3Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            raw: Some(vec![]),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += frame.encode(&mut d[len..]).unwrap();

        let mut b = &mut d[len..];
        // Write a big-length payload GOAWAY frame.
        b.write_varint(frame::GOAWAY_FRAME_TYPE).unwrap();
        b.write_varint(MAX_STATE_BUF_SIZE as u64 + 1).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the stream type.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();

        // Parse and discard the SETTINGS frame.
        parse_and_discard_frame(&mut stream, &mut cursor).unwrap();

        // Parse the GOAWAY frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::GOAWAY_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the GOAWAY frame payload length.
        assert_eq!(
            parse_frame_payload_length(&mut stream, &mut cursor, MAX_STATE_BUF_SIZE as u64 + 1),
            Err(Http3Error::ExcessiveLoad)
        );
    }

    // Test Http3Stream::mark_read_finished
    #[test]
    fn mark_stream_read_finished() {
        // Create a client-initiated bidi stream, stream_id = 0.
        let mut stream = create_request_stream(0, false).unwrap();

        // Mark the stream's read-side as finished.
        stream.mark_read_finished();

        assert_eq!(stream.state(), Http3StreamState::ReadFinished);
        assert_eq!(stream.state.write_off, 0);
        assert_eq!(stream.state.expected_len, 0);
    }

    #[test]
    fn check_frame_on_control_stream() {
        // Create remote control streams.
        for stream_id in vec![
            2, // Client-initiated.
            3, // Server-initiated.
        ] {
            let mut stream = Http3Stream::new(stream_id, false);
            assert_eq!(stream.peer_initialized, false);

            // Stream not yet initialized, only SETTINGS frame is allowed.
            for frame_type in vec![
                frame::DATA_FRAME_TYPE,
                frame::HEADERS_FRAME_TYPE,
                frame::PUSH_PROMISE_FRAME_TYPE,
                frame::CANCEL_PUSH_FRAME_TYPE,
                // frame::SETTINGS_FRAME_TYPE,
                frame::GOAWAY_FRAME_TYPE,
                frame::MAX_PUSH_ID_FRAME_TYPE,
                frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE,
                frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE,
            ] {
                assert_eq!(
                    stream.check_frame_on_control_stream(frame_type),
                    Err(Http3Error::MissingSettings)
                );
            }

            // Receive SETTINGS frame, remote initialized.
            assert_eq!(
                stream.check_frame_on_control_stream(frame::SETTINGS_FRAME_TYPE),
                Ok(())
            );
            assert_eq!(stream.peer_initialized, true);

            // Duplicate SETTINGS frame is not allowed.
            assert_eq!(
                stream.check_frame_on_control_stream(frame::SETTINGS_FRAME_TYPE),
                Err(Http3Error::FrameUnexpected)
            );

            // RFC9114 7. Table 1: HTTP/3 Frames and Stream Type Overview
            // `DATA`, `HEADERS` and `PUSH_PROMISE` frames MUST NOT be sent on the control stream.
            for frame_type in vec![
                frame::DATA_FRAME_TYPE,
                frame::HEADERS_FRAME_TYPE,
                frame::PUSH_PROMISE_FRAME_TYPE,
            ] {
                assert_eq!(
                    stream.check_frame_on_control_stream(frame_type),
                    Err(Http3Error::FrameUnexpected)
                );
            }
        }
    }

    #[test]
    fn check_frame_on_push_stream() {
        let mut stream = Http3Stream::new(0, false);

        for frame_type in vec![
            frame::PUSH_PROMISE_FRAME_TYPE,
            frame::CANCEL_PUSH_FRAME_TYPE,
            frame::SETTINGS_FRAME_TYPE,
            frame::GOAWAY_FRAME_TYPE,
            frame::MAX_PUSH_ID_FRAME_TYPE,
            frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE,
            frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE,
        ] {
            assert_eq!(
                stream.check_frame_on_push_stream(frame_type),
                Err(Http3Error::FrameUnexpected)
            );
        }

        for frame_type in vec![frame::DATA_FRAME_TYPE, frame::HEADERS_FRAME_TYPE] {
            assert_eq!(stream.check_frame_on_push_stream(frame_type), Ok(()));
        }
    }

    #[test]
    fn check_frame_on_request_stream() {
        // Create client-initiated bidirectional streams.
        for local in vec![
            true,  // Client role.
            false, // Server role.
        ] {
            let mut stream = Http3Stream::new(0, local);
            assert_eq!(stream.peer_initialized, false);

            // Stream not yet initialized, only HEADERS frame is allowed.
            for frame_type in vec![
                frame::DATA_FRAME_TYPE,
                frame::CANCEL_PUSH_FRAME_TYPE,
                frame::SETTINGS_FRAME_TYPE,
                frame::GOAWAY_FRAME_TYPE,
                frame::MAX_PUSH_ID_FRAME_TYPE,
                frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE,
                frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE,
            ] {
                assert_eq!(
                    stream.check_frame_on_request_stream(frame_type),
                    Err(Http3Error::FrameUnexpected)
                );
            }

            // Receive HEADERS_FRAME_TYPE frame, remote initialized.
            assert_eq!(
                stream.check_frame_on_request_stream(frame::HEADERS_FRAME_TYPE),
                Ok(())
            );
            assert_eq!(stream.peer_initialized, true);

            // RFC9114 7. Table 1: HTTP/3 Frames and Stream Type Overview
            // `CANCEL_PUSH`, `SETTINGS`, `GOAWAY`, and `MAX_PUSH_ID` frames MUST NOT be sent on the request stream.
            //
            // RFC9204 7.2. HTTP/3 PRIORITY_UPDATE Frame
            // The PRIORITY_UPDATE frame MUST be sent on the client control stream (see Section 6.2.1 of [HTTP/3]).
            // Receiving a PRIORITY_UPDATE frame on a stream other than the client control stream MUST be treated as
            // a connection error of type H3_FRAME_UNEXPECTED.
            for frame_type in vec![
                frame::CANCEL_PUSH_FRAME_TYPE,
                frame::SETTINGS_FRAME_TYPE,
                frame::GOAWAY_FRAME_TYPE,
                frame::MAX_PUSH_ID_FRAME_TYPE,
                frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE,
                frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE,
            ] {
                assert_eq!(
                    stream.check_frame_on_request_stream(frame_type),
                    Err(Http3Error::FrameUnexpected)
                );
            }
        }
    }

    #[test]
    fn trigger_data_event() {
        // Create a new client-initiated bidirectional stream, stream_id = 0.
        let mut stream = create_request_stream(0, false).unwrap();

        assert_eq!(stream.trigger_data_event(), true);
        assert_eq!(stream.data_event_triggered, true);
        assert_eq!(stream.trigger_data_event(), false);
        assert_eq!(stream.data_event_triggered, true);
        stream.reset_data_event_state();
        assert_eq!(stream.data_event_triggered, false);
        assert_eq!(stream.trigger_data_event(), true);
    }

    // Process a normal SETTINGS frame on control stream.
    #[test]
    fn process_settings_frame_on_control_stream() {
        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = Http3Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            raw: Some(raw_settings),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        settings.encode(&mut d[len..]).unwrap();
        let expected_frame_payload_len: u64 = 6;

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the SETTINGS frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::SETTINGS_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);
        assert_eq!(stream.peer_initialized, true);

        // Parse the SETTINGS frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, expected_frame_payload_len).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayload);

        // Parse the SETTINGS frame payload.
        assert_eq!(
            parse_frame_payload(&mut stream, &mut cursor),
            Ok((settings, expected_frame_payload_len))
        );
        assert_eq!(stream.state(), Http3StreamState::FrameType);
    }

    // Process an empty SETTINGS frame on control stream, which is allowed in the HTTP/3 protocol.
    #[test]
    fn process_empty_settings_frame_on_control_stream() {
        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        let settings = Http3Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            raw: Some(vec![]),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        settings.encode(&mut d[len..]).unwrap();
        let expected_frame_payload_len: u64 = 0;

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the SETTINGS frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::SETTINGS_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the SETTINGS frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, expected_frame_payload_len).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayload);

        // Parse the SETTINGS frame payload.
        assert_eq!(
            parse_frame_payload(&mut stream, &mut cursor),
            Ok((settings, expected_frame_payload_len))
        );
        assert_eq!(stream.state(), Http3StreamState::FrameType);
    }

    // Process duplicate SETTINGS frame on control stream, which is invalid in HTTP/3 protocol.
    #[test]
    fn process_duplicate_settings_on_control_stream() {
        // RFC9114
        // A SETTINGS frame MUST be sent as the first frame of each control stream (see Section 6.2.1) by each peer,
        // and it MUST NOT be sent subsequently. If an endpoint receives a second SETTINGS frame on the control stream,
        // the endpoint MUST respond with a connection error of type H3_FRAME_UNEXPECTED.

        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = frame::Http3Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            raw: Some(raw_settings),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += settings.encode(&mut d[len..]).unwrap();
        let expected_frame_payload_len: u64 = 6;
        // Encode duplicate SETTINGS frame.
        settings.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the SETTINGS frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::SETTINGS_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the SETTINGS frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, expected_frame_payload_len).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayload);

        // Parse the SETTINGS frame payload.
        assert_eq!(
            parse_frame_payload(&mut stream, &mut cursor),
            Ok((settings, expected_frame_payload_len))
        );
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the second SETTINGS frame type.
        assert_eq!(
            parse_frame_type(&mut stream, &mut cursor, frame::SETTINGS_FRAME_TYPE),
            Err(Http3Error::FrameUnexpected)
        );
    }

    // Process goaway frame before SETTINGS frame on control stream.
    #[test]
    fn process_goaway_frame_before_settings_on_control_stream() {
        // RFC9114
        // Each side MUST initiate a single control stream at the beginning of the connection and send
        // its SETTINGS frame as the first frame on this stream. If the first frame of the control stream
        // is any other frame type, this MUST be treated as a connection error of type H3_MISSING_SETTINGS.

        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = frame::Http3Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            raw: Some(raw_settings),
        };

        let goaway = frame::Http3Frame::GoAway { id: 0 };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += goaway.encode(&mut d[len..]).unwrap();
        settings.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the GOAWAY frame type.
        assert_eq!(
            parse_frame_type(&mut stream, &mut cursor, frame::GOAWAY_FRAME_TYPE),
            Err(Http3Error::MissingSettings)
        );
    }

    // Process goaway frame after SETTINGS frame on control stream.
    #[test]
    fn process_goaway_frame_after_settings_on_control_stream() {
        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = frame::Http3Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            raw: Some(raw_settings),
        };

        let goaway = frame::Http3Frame::GoAway { id: 0 };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += settings.encode(&mut d[len..]).unwrap();
        goaway.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse and discard the SETTINGS frame.
        parse_and_discard_frame(&mut stream, &mut cursor).unwrap();

        // Parse the GOAWAY frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::GOAWAY_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the GOAWAY frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, 1).unwrap();

        // Parse the GOAWAY frame payload.
        assert_eq!(
            parse_frame_payload(&mut stream, &mut cursor),
            Ok((goaway, 1))
        );
    }

    // Process CANCEL_PUSH frame before SETTINGS frame on control stream.
    #[test]
    fn process_cancel_push_frame_before_settings_on_control_stream() {
        // RFC9114
        // Each side MUST initiate a single control stream at the beginning of the connection and send
        // its SETTINGS frame as the first frame on this stream. If the first frame of the control stream
        // is any other frame type, this MUST be treated as a connection error of type H3_MISSING_SETTINGS.

        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = frame::Http3Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            raw: Some(raw_settings),
        };

        let cancel_push = frame::Http3Frame::CancelPush { push_id: 5 };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += cancel_push.encode(&mut d[len..]).unwrap();
        settings.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the CANCEL_PUSH frame type.
        assert_eq!(
            parse_frame_type(&mut stream, &mut cursor, frame::CANCEL_PUSH_FRAME_TYPE),
            Err(Http3Error::MissingSettings)
        );
    }

    // Process CANCEL_PUSH frame after SETTINGS frame on control stream.
    #[test]
    fn process_cancel_push_frame_after_settings_on_control_stream() {
        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = frame::Http3Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            raw: Some(raw_settings),
        };

        let cancel_push = frame::Http3Frame::CancelPush { push_id: 5 };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += settings.encode(&mut d[len..]).unwrap();
        cancel_push.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse and discard the SETTINGS frame.
        parse_and_discard_frame(&mut stream, &mut cursor).unwrap();

        // Parse the CANCEL_PUSH frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::CANCEL_PUSH_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the CANCEL_PUSH frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, 1).unwrap();

        // Parse the CANCEL_PUSH frame payload.
        assert_eq!(
            parse_frame_payload(&mut stream, &mut cursor),
            Ok((cancel_push, 1))
        );
    }

    // Process MAX_PUSH_ID frame before SETTINGS frame on control stream.
    #[test]
    fn process_max_push_id_frame_before_settings_on_control_stream() {
        // RFC9114
        // Each side MUST initiate a single control stream at the beginning of the connection and send
        // its SETTINGS frame as the first frame on this stream. If the first frame of the control stream
        // is any other frame type, this MUST be treated as a connection error of type H3_MISSING_SETTINGS.

        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = frame::Http3Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            raw: Some(raw_settings),
        };

        let max_push_id = frame::Http3Frame::MaxPushId { push_id: 10 };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += max_push_id.encode(&mut d[len..]).unwrap();
        settings.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the MAX_PUSH_ID frame type.
        assert_eq!(
            parse_frame_type(&mut stream, &mut cursor, frame::MAX_PUSH_ID_FRAME_TYPE),
            Err(Http3Error::MissingSettings)
        );
    }

    // Process MAX_PUSH_ID frame after SETTINGS frame on control stream.
    #[test]
    fn process_max_push_id_frame_after_settings_on_control_stream() {
        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = frame::Http3Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            raw: Some(raw_settings),
        };

        let max_push_id = frame::Http3Frame::MaxPushId { push_id: 10 };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += settings.encode(&mut d[len..]).unwrap();
        max_push_id.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse and discard the SETTINGS frame.
        parse_and_discard_frame(&mut stream, &mut cursor).unwrap();

        // Parse the MAX_PUSH_ID frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::MAX_PUSH_ID_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the MAX_PUSH_ID frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, 1).unwrap();

        // Parse the MAX_PUSH_ID frame payload.
        assert_eq!(
            parse_frame_payload(&mut stream, &mut cursor),
            Ok((max_push_id, 1))
        );
    }

    // Process HEADERS(not-allowed) frame on control stream.
    #[test]
    fn process_headers_frame_on_control_stream() {
        let mut d = vec![0; 40];
        let mut b = &mut d[..];

        // Construct one fake HEADERS frame.
        let field_section = vec![0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71];
        let headers_frame = frame::Http3Frame::Headers { field_section };

        let raw_settings = vec![
            (SETTINGS_MAX_FIELD_SECTION_SIZE, 0),
            (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        ];

        let settings = frame::Http3Frame::Settings {
            max_field_section_size: Some(0),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: None,
            raw: Some(raw_settings),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += settings.encode(&mut d[len..]).unwrap();
        let expected_frame_payload_len: u64 = 6;
        headers_frame.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the unidirectional stream type and expect it to be HTTP3_CONTROL_STREAM_TYPE.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the SETTINGS frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::SETTINGS_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the SETTINGS frame payload length
        parse_frame_payload_length(&mut stream, &mut cursor, expected_frame_payload_len).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayload);

        // Parse the SETTINGS frame payload and discard it.
        assert_eq!(
            parse_frame_payload(&mut stream, &mut cursor),
            Ok((settings, expected_frame_payload_len))
        );
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the HEADERS frame type.
        assert_eq!(
            parse_frame_type(&mut stream, &mut cursor, frame::HEADERS_FRAME_TYPE),
            Err(Http3Error::FrameUnexpected)
        );
    }

    // Try to set frame_type on qpack encoder or decoder stream, which is not allowed.
    #[test]
    fn set_frame_type_on_qpack_stream() {
        // Client-initiated unidirectional streams.
        for (stream_id, stream_type) in [
            (6, QPACK_ENCODER_STREAM_TYPE),
            (10, QPACK_DECODER_STREAM_TYPE),
        ] {
            let mut d = vec![0; 128];
            let mut b = &mut d[..];

            // Create a unidirectional stream.
            let mut stream = create_uni_stream(stream_id, false).unwrap();
            let _ = b.write_varint(stream_type).unwrap();

            // Create a new cursor that wraps the encoded QUIC stream bytes.
            let mut cursor = std::io::Cursor::new(d);

            // Parse the unidirectional stream type and expect it same as stream_type.
            assert!(parse_uni_stream_type(&mut stream, &mut cursor, stream_type).is_ok());

            assert_eq!(
                stream.set_frame_type(frame::HEADERS_FRAME_TYPE),
                Err(Http3Error::FrameUnexpected)
            );
        }
    }

    // Process one new uni stream but there are no data in the stream.
    #[test]
    fn process_new_uni_stream_without_any_data() {
        // Client-initiated unidirectional streams.
        for (stream_id, stream_type) in [
            (2, HTTP3_CONTROL_STREAM_TYPE),
            (6, QPACK_ENCODER_STREAM_TYPE),
            (10, QPACK_DECODER_STREAM_TYPE),
        ] {
            let mut d = vec![0; 128];
            let mut b = &mut d[..];

            // Create a unidirectional stream.
            let mut stream = create_uni_stream(stream_id, false).unwrap();
            let _ = b.write_varint(stream_type).unwrap();

            // Create a new cursor that wraps the encoded QUIC stream bytes.
            let mut cursor = std::io::Cursor::new(d);

            // Parse the unidirectional stream type and expect it same as stream_type.
            assert!(parse_uni_stream_type(&mut stream, &mut cursor, stream_type).is_ok());
        }

        // Server-initiated unidirectional streams.
        for (stream_id, stream_type) in [
            (3, HTTP3_CONTROL_STREAM_TYPE),
            (7, QPACK_ENCODER_STREAM_TYPE),
            (11, QPACK_DECODER_STREAM_TYPE),
            (15, HTTP3_PUSH_STREAM_TYPE),
        ] {
            let mut d = vec![0; 128];
            let mut b = &mut d[..];

            // Create a unidirectional stream.
            let mut stream = create_uni_stream(stream_id, false).unwrap();
            let _ = b.write_varint(stream_type).unwrap();

            // Create a new cursor that wraps the encoded QUIC stream bytes.
            let mut cursor = std::io::Cursor::new(d);

            // Parse the unidirectional stream type and expect it same as stream_type.
            assert!(parse_uni_stream_type(&mut stream, &mut cursor, stream_type).is_ok());
        }
    }

    // Process one new request stream but there are no data in the stream.
    #[test]
    fn process_new_request_stream_without_any_data() {
        // Create a new client-initiated bidirectional stream, stream_id = 0.
        let mut stream = create_request_stream(0, false).unwrap();

        // Try to parse the frame type of the request stream.
        assert_eq!(stream.state.parse_varint(), Err(Http3Error::Done));
    }

    // Process one new request stream with a HEADERS frame and a DATA frame.
    #[test]
    fn process_new_request_stream_with_header_and_data() {
        // Create a new client-initiated bidirectional stream, stream_id = 0.
        let mut stream = create_request_stream(0, false).unwrap();

        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        let field_section = vec![0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71];
        let headers_frame = frame::Http3Frame::Headers {
            field_section: field_section.clone(),
        };

        let payload = vec![0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x80];
        let data_frame = frame::Http3Frame::Data {
            data: payload.clone(),
        };

        let len = headers_frame.encode(&mut b).unwrap();
        data_frame.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the HEADERS frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::HEADERS_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the HEADERS frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, field_section.len() as u64).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayload);

        // Parse the HEADERS frame payload and discard it.
        assert_eq!(
            parse_frame_payload(&mut stream, &mut cursor),
            Ok((headers_frame, field_section.len() as u64))
        );
        // After one frame is parsed, the stream state should be FrameType.
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the DATA frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::DATA_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the DATA frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, payload.len() as u64).unwrap();
        assert_eq!(stream.state(), Http3StreamState::Data);

        // Parse the DATA payload and discard it.
        let mut recv_buf = vec![0; payload.len()];
        assert_eq!(
            read_data_from_quic(&mut stream, &mut cursor, &mut recv_buf),
            Ok(payload.len())
        );
        assert_eq!(payload, recv_buf);

        // After one frame is parsed, the stream state should be FrameType.
        assert_eq!(stream.state(), Http3StreamState::FrameType);
    }

    // Process one new request stream with a HEADERS frame and a DATA frame,
    // but the DATA frame is coming before the HEADERS frame.
    #[test]
    fn process_data_frame_before_headers_frame_on_request_stream() {
        // RFC9114
        // Receipt of an invalid sequence of frames MUST be treated as a connection error of type H3_FRAME_UNEXPECTED.
        // In particular, a DATA frame before any HEADERS frame, or a HEADERS or DATA frame after the trailing HEADERS
        // frame, is considered invalid.

        // Create a new client-initiated bidirectional stream, stream_id = 0.
        let mut stream = create_request_stream(0, false).unwrap();

        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        let data_frame = frame::Http3Frame::Data {
            data: vec![0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71],
        };
        data_frame.encode(&mut b).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the DATA frame type from the request stream.
        assert_eq!(
            parse_frame_type(&mut stream, &mut cursor, frame::DATA_FRAME_TYPE),
            Err(Http3Error::FrameUnexpected)
        );
    }

    // Process one new push stream with a HEADERS frame and a DATA frame.
    #[test]
    fn process_new_push_stream_with_headers_and_data() {
        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        let field_section = vec![0x65, 0x66, 0x67, 0x68, 0x69, 0x70, 0x71];
        let headers_frame = frame::Http3Frame::Headers {
            field_section: field_section.clone(),
        };

        let payload = vec![0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x80];
        let data_frame = frame::Http3Frame::Data {
            data: payload.clone(),
        };

        let expected_push_id = 1;

        // Create a new server-initiated unidirectional stream, stream_id = 3.
        let mut stream = create_uni_stream(3, false).unwrap();
        let mut len = b.write_varint(HTTP3_PUSH_STREAM_TYPE).unwrap();
        len += b.write_varint(expected_push_id).unwrap();
        len += headers_frame.encode(&mut d[len..]).unwrap();
        data_frame.encode(&mut d[len..]).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the push stream type.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_PUSH_STREAM_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::PushId);

        // Parse the push ID.
        let _ = parse_push_id(&mut stream, &mut cursor, expected_push_id).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the HEADERS frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::HEADERS_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the HEADERS frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, field_section.len() as u64).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayload);

        // Parse the HEADERS frame payload.
        assert_eq!(
            parse_frame_payload(&mut stream, &mut cursor),
            Ok((headers_frame, field_section.len() as u64))
        );
        assert_eq!(stream.state(), Http3StreamState::FrameType);

        // Parse the DATA frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::DATA_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the DATA frame payload length.
        parse_frame_payload_length(&mut stream, &mut cursor, payload.len() as u64).unwrap();
        assert_eq!(stream.state(), Http3StreamState::Data);

        // Parse the DATA payload.
        let mut recv_buf = vec![0; payload.len()];
        assert_eq!(
            read_data_from_quic(&mut stream, &mut cursor, &mut recv_buf),
            Ok(payload.len())
        );
        assert_eq!(payload, recv_buf);

        assert_eq!(stream.state(), Http3StreamState::FrameType);
    }

    // Process reserved type stream.
    #[test]
    fn process_reserved_type_stream() {
        let mut d = vec![0; 20];
        let mut b = &mut d[..];

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        // RFC9114 Reserved Stream Type: 0x1f * N + 0x21
        let reserved_stream_type = 33;
        let _ = b.write_varint(reserved_stream_type);

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the stream type.
        parse_uni_stream_type(&mut stream, &mut cursor, reserved_stream_type).unwrap();
        assert_eq!(stream.state(), Http3StreamState::Skip);
    }

    // Process a zero-length GOAWAY frame on control stream.
    #[test]
    fn process_zero_length_goaway_frame_on_control_stream() {
        // RFC9114
        // Each frame's payload MUST contain exactly the fields identified in its description.
        // A frame payload that contains additional bytes after the identified fields or a frame
        // payload that terminates before the end of the identified fields MUST be treated as a
        // connection error of type H3_FRAME_ERROR.

        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        let frame = Http3Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            raw: Some(vec![]),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += frame.encode(&mut d[len..]).unwrap();

        let mut b = &mut d[len..];
        // Write a 0-length payload GOAWAY frame.
        b.write_varint(frame::GOAWAY_FRAME_TYPE).unwrap();
        b.write_varint(0).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the stream type.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();

        // Parse and discard the SETTINGS frame.
        parse_and_discard_frame(&mut stream, &mut cursor).unwrap();

        // Parse the GOAWAY frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::GOAWAY_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the GOAWAY frame payload length.
        assert_eq!(
            parse_frame_payload_length(&mut stream, &mut cursor, 0),
            Err(Http3Error::FrameError)
        );
    }

    // Process a zero-length PUSH_PROMISE frame on request stream.
    #[test]
    fn process_zero_length_push_promise_frame_on_request_stream() {
        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        // Create a new client-initiated bidirectional stream, stream_id = 0.
        let mut stream = create_request_stream(0, false).unwrap();

        // Write a 0-length payload PUSH_PROMISE frame.
        b.write_varint(frame::PUSH_PROMISE_FRAME_TYPE).unwrap();
        b.write_varint(0).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the PUSH_PROMISE frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::PUSH_PROMISE_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the PUSH_PROMISE frame payload length.
        assert_eq!(
            parse_frame_payload_length(&mut stream, &mut cursor, 0),
            Err(Http3Error::FrameError)
        );
    }

    // Process a zero-length CANCEL_PUSH frame on control stream.
    #[test]
    fn process_zero_length_cancel_push_frame_on_control_stream() {
        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        let frame = Http3Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            raw: Some(vec![]),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += frame.encode(&mut d[len..]).unwrap();

        let mut b = &mut d[len..];
        // Write a 0-length payload CANCEL_PUSH frame.
        b.write_varint(frame::CANCEL_PUSH_FRAME_TYPE).unwrap();
        b.write_varint(0).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the stream type.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();

        // Parse and discard the SETTINGS frame.
        parse_and_discard_frame(&mut stream, &mut cursor).unwrap();

        // Parse the CANCEL_PUSH frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::CANCEL_PUSH_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the CANCEL_PUSH frame payload length.
        assert_eq!(
            parse_frame_payload_length(&mut stream, &mut cursor, 0),
            Err(Http3Error::FrameError)
        );
    }

    // Process a zero-length MAX_PUSH_ID frame on control stream.
    #[test]
    fn process_zero_length_max_push_id_frame_on_control_stream() {
        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        let frame = Http3Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            raw: Some(vec![]),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += frame.encode(&mut d[len..]).unwrap();

        let mut b = &mut d[len..];
        // Write a 0-length payload MAX_PUSH_ID frame.
        b.write_varint(frame::MAX_PUSH_ID_FRAME_TYPE).unwrap();
        b.write_varint(0).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the stream type.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();

        // Parse and discard the SETTINGS frame.
        parse_and_discard_frame(&mut stream, &mut cursor).unwrap();

        // Parse the MAX_PUSH_ID frame type.
        parse_frame_type(&mut stream, &mut cursor, frame::MAX_PUSH_ID_FRAME_TYPE).unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the MAX_PUSH_ID frame payload length.
        assert_eq!(
            parse_frame_payload_length(&mut stream, &mut cursor, 0),
            Err(Http3Error::FrameError)
        );
    }

    // Process a zero-length PRIORITY_UPDATE_REQUEST frame on control stream.
    #[test]
    fn process_zero_length_priority_update_request_frame_on_control_stream() {
        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        let frame = Http3Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            raw: Some(vec![]),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += frame.encode(&mut d[len..]).unwrap();

        let mut b = &mut d[len..];
        // Write a 0-length payload PRIORITY_UPDATE_REQUEST frame.
        b.write_varint(frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE)
            .unwrap();
        b.write_varint(0).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the stream type.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();

        // Parse and discard the SETTINGS frame.
        parse_and_discard_frame(&mut stream, &mut cursor).unwrap();

        // Parse the PRIORITY_UPDATE_FRAME_REQUEST_TYPE frame type.
        parse_frame_type(
            &mut stream,
            &mut cursor,
            frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE,
        )
        .unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the PRIORITY_UPDATE_FRAME_REQUEST_TYPE frame payload length.
        assert_eq!(
            parse_frame_payload_length(&mut stream, &mut cursor, 0),
            Err(Http3Error::FrameError)
        );
    }

    // Process a zero-length PRIORITY_UPDATE_PUSH frame on control stream.
    #[test]
    fn process_zero_length_priority_update_push_frame_on_control_stream() {
        let mut d = vec![0; 128];
        let mut b = &mut d[..];

        let frame = Http3Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: None,
            raw: Some(vec![]),
        };

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        let mut len = b.write_varint(HTTP3_CONTROL_STREAM_TYPE).unwrap();
        len += frame.encode(&mut d[len..]).unwrap();

        let mut b = &mut d[len..];
        // Write a 0-length payload PRIORITY_UPDATE_PUSH frame.
        b.write_varint(frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE)
            .unwrap();
        b.write_varint(0).unwrap();

        // Create a new cursor that wraps the encoded QUIC stream bytes.
        let mut cursor = std::io::Cursor::new(d);

        // Parse the stream type.
        parse_uni_stream_type(&mut stream, &mut cursor, HTTP3_CONTROL_STREAM_TYPE).unwrap();

        // Parse and discard the SETTINGS frame.
        parse_and_discard_frame(&mut stream, &mut cursor).unwrap();

        // Parse the PRIORITY_UPDATE_FRAME_PUSH_TYPE frame type.
        parse_frame_type(
            &mut stream,
            &mut cursor,
            frame::PRIORITY_UPDATE_FRAME_PUSH_TYPE,
        )
        .unwrap();
        assert_eq!(stream.state(), Http3StreamState::FramePayloadLen);

        // Parse the PRIORITY_UPDATE_FRAME_PUSH_TYPE frame payload length.
        assert_eq!(
            parse_frame_payload_length(&mut stream, &mut cursor, 0),
            Err(Http3Error::FrameError)
        );
    }

    #[test]
    fn set_and_take_last_priority_update() {
        let priority_update = vec![0x65, 0x66, 0x67, 0x68, 0x69, 0x70];

        // Create a unidirectional stream, stream_id = 2.
        let mut stream = create_uni_stream(2, false).unwrap();
        assert_eq!(stream.has_priority_update(), false);
        stream.set_priority_update(Some(priority_update.clone()));
        assert_eq!(stream.has_priority_update(), true);
        assert_eq!(stream.take_priority_update(), Some(priority_update));
        assert_eq!(stream.take_priority_update(), None);
    }

    #[test]
    fn set_and_take_header_block() {
        let header_block = Bytes::from(vec![0x65, 0x66, 0x67, 0x68, 0x69, 0x70]);
        let fin = true;

        // Create a new client-initiated request stream, stream_id = 0.
        let mut stream = create_request_stream(0, false).unwrap();
        assert_eq!(stream.has_header_block(), false);
        stream.set_header_block(Some((header_block.clone(), fin)));
        assert_eq!(stream.has_header_block(), true);
        assert_eq!(stream.take_header_block(), Some((header_block, fin)));
        assert_eq!(stream.take_header_block(), None);
    }
}
