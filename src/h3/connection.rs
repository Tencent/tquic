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

use std::collections::hash_map;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::mem::MaybeUninit;
use std::sync::Arc;

use bytes::Bytes;
use bytes::BytesMut;
use log::*;

use super::frame;
use super::qpack;
use super::stream;
use super::Header;
use crate::codec;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::connection::stream::StreamIdHashMap;
use crate::connection::Connection;
use crate::h3::Http3Config;
use crate::h3::Http3Error;
use crate::h3::Http3Event;
use crate::h3::Http3Handler;
use crate::h3::NameValue;
use crate::h3::Result;
use stream::Http3Stream;
use stream::Http3StreamState;
use stream::Http3StreamType;

// RFC9218 4.1. Urgency
// The urgency (u) parameter value is Integer (see Section 3.3.1 of [STRUCTURED-FIELDS]),
// between 0 and 7 inclusive, in descending order of priority. The default is 3.
const PRIORITY_URGENCY_LOWER_BOUND: u8 = 0;
const PRIORITY_URGENCY_UPPER_BOUND: u8 = 7;
const PRIORITY_URGENCY_DEFAULT: u8 = 3;
// RFC9218 4.2. Incremental
// The incremental (i) parameter value is Boolean (see Section 3.3.6 of [STRUCTURED-FIELDS]).
// It indicates if an HTTP response can be processed incrementally, i.e., provide some meaningful
// output as chunks of the response arrive.
// The default value of the incremental parameter is false (0).
const PRIORITY_INCREMENTAL_DEFAULT: bool = false;
// Map HTTP/3 urgency to QUIC urgency in a linear way with this offset, i.e., 1 maps to 125.
const PRIORITY_URGENCY_OFFSET: u8 = 124;

const INITIAL_UNI_STREAM_ID_CLIENT: u64 = 0x2;
const INITIAL_UNI_STREAM_ID_SERVER: u64 = 0x3;

/// An HTTP/3 connection.
pub struct Http3Connection {
    /// Whether this is a server connection.
    is_server: bool,

    /// Collection of streams that are organized and accessed by stream ID.
    streams: StreamIdHashMap<Http3Stream>,

    /// Finished streams that need to be notified to the application.
    finished_streams: VecDeque<u64>,

    /// The local settings for the connection.
    local_settings: Http3Settings,
    /// The peer settings for the connection.
    peer_settings: Http3Settings,

    /// QPACK encoder.
    qpack_encoder: qpack::QpackEncoder,
    /// QPACK decoder.
    qpack_decoder: qpack::QpackDecoder,

    /// The streams for local QPACK.
    local_qpack_streams: QpackStreams,
    /// The streams for peer QPACK.
    peer_qpack_streams: QpackStreams,

    /// The next stream ID to be used for a request(bididirectional) stream.
    next_request_stream_id: u64,
    /// The next stream ID to be used for a unidirectional stream.
    next_uni_stream_id: u64,

    /// The control stream ID initiated by the local endpoint.
    local_control_stream_id: Option<u64>,
    /// The control stream ID initiated by the peer.
    peer_control_stream_id: Option<u64>,

    /// The ID of the GOAWAY frame sent by the local endpoint.
    local_goaway_id: Option<u64>,
    /// The ID of the GOAWAY frame received from the peer.
    peer_goaway_id: Option<u64>,

    /// The maximum push ID that the server can use in PUSH_PROMISE and CANCEL_PUSH frames.
    //  RFC9114 7.2.7 MAX_PUSH_ID
    //  The maximum push ID is unset when an HTTP/3 connection is created, meaning that a
    //  server cannot push until it receives a MAX_PUSH_ID frame. A client that wishes to
    //  manage the number of promised server pushes can increase the maximum push ID by
    //  sending MAX_PUSH_ID frames as the server fulfills or cancels server pushes.
    max_push_id: Option<u64>,

    /// Used to communicate with the application code.
    handler: Option<Arc<dyn Http3Handler>>,

    /// Unique trace id for deubg logging
    trace_id: String,
}

impl Http3Connection {
    /// Create a new HTTP/3 connection with the given configuration and role.
    fn new(config: &Http3Config, is_server: bool) -> Result<Http3Connection> {
        let initial_uni_stream_id = match is_server {
            true => INITIAL_UNI_STREAM_ID_SERVER,
            false => INITIAL_UNI_STREAM_ID_CLIENT,
        };

        Ok(Http3Connection {
            is_server,

            streams: Default::default(),

            finished_streams: VecDeque::new(),

            local_settings: Http3Settings {
                max_field_section_size: config.max_field_section_size,
                qpack_max_table_capacity: config.qpack_max_table_capacity,
                qpack_blocked_streams: config.qpack_blocked_streams,
                connect_protocol_enabled: None,
                raw: Default::default(),
            },

            peer_settings: Http3Settings {
                max_field_section_size: None,
                qpack_max_table_capacity: None,
                qpack_blocked_streams: None,
                connect_protocol_enabled: None,
                raw: Default::default(),
            },

            qpack_encoder: qpack::QpackEncoder::new(),
            qpack_decoder: qpack::QpackDecoder::new(),

            local_qpack_streams: QpackStreams {
                encoder_stream_id: None,
                decoder_stream_id: None,
            },

            peer_qpack_streams: QpackStreams {
                encoder_stream_id: None,
                decoder_stream_id: None,
            },

            next_request_stream_id: 0,
            next_uni_stream_id: initial_uni_stream_id,

            local_control_stream_id: None,
            peer_control_stream_id: None,

            local_goaway_id: None,
            peer_goaway_id: None,

            max_push_id: None,

            handler: None,

            trace_id: String::new(),
        })
    }

    /// Create a new HTTP/3 connection with the given QUIC transport connection and HTTP/3
    /// configuration, and initiate all HTTP/3 critical streams, including the control stream
    /// and QPACK encoder/decoder streams.
    pub fn new_with_quic_conn(
        conn: &mut Connection,
        config: &Http3Config,
    ) -> Result<Http3Connection> {
        // As a client, HTTP/3 connection can be created only when the QUIC connection is
        // established or in early data.
        #[allow(clippy::nonminimal_bool)]
        if !conn.is_server() && !(conn.is_established() || conn.is_in_early_data()) {
            error!(
                "{:?} Client must not create an HTTP/3 connection if the QUIC connection has not
                been established or is in early data, is_established {}, is_in_early_data {}",
                conn.trace_id(),
                conn.is_established(),
                conn.is_in_early_data()
            );
            return Err(Http3Error::InternalError);
        }

        // Create an HTTP/3 connection with the QUIC transport connection.
        let mut http3_conn = Http3Connection::new(config, conn.is_server())?;

        // Set trace id for debug logging
        http3_conn.trace_id = conn.trace_id().to_string();

        // Initiate all HTTP/3 critical streams, including the control stream and QPACK encoder/decoder streams.
        http3_conn.open_critical_streams(conn)?;

        Ok(http3_conn)
    }

    /// Return a mutable reference to the stream with the given ID if it exists,
    /// or try to create a new one with given paras otherwise.
    fn get_or_create(&mut self, stream_id: u64, local: bool) -> Result<&mut Http3Stream> {
        match self.streams.entry(stream_id) {
            // 1. Stream doesn't exist, try to create it.
            hash_map::Entry::Vacant(v) => {
                // RFC9114 6.1. Bidirectional Streams
                // HTTP/3 does not use server-initiated bidirectional streams, though
                // an extension could define a use for these streams. Clients MUST treat
                // receipt of a server-initiated bidirectional stream as a connection
                // error of type H3_STREAM_CREATION_ERROR unless such an extension has
                // been negotiated.
                if !self.is_server && crate::stream::is_bidi(stream_id) && !local {
                    Err(Http3Error::StreamCreationError)
                } else {
                    trace!("{} create new stream {}", self.trace_id, stream_id);
                    // Create a new HTTP/3 stream and insert it into streams map.
                    Ok(v.insert(Http3Stream::new(stream_id, local)))
                }
            }

            // 2.Stream already exists.
            hash_map::Entry::Occupied(v) => Ok(v.into_mut()),
        }
    }

    /// Update next request stream ID.
    fn update_next_request_stream_id(&mut self) -> Result<()> {
        if self.next_request_stream_id >= 1 << 62 {
            return Err(Http3Error::IdError);
        }

        self.next_request_stream_id += 4;
        Ok(())
    }

    /// Update next uni stream ID.
    fn update_next_uni_stream_id(&mut self) -> Result<()> {
        if self.next_uni_stream_id >= 1 << 62 {
            return Err(Http3Error::IdError);
        }

        self.next_uni_stream_id += 4;
        Ok(())
    }

    /// Set handler for HTTP/3 connection events.
    pub fn set_events_handler(&mut self, handler: Arc<dyn Http3Handler>) {
        self.handler = Some(handler);
    }

    /// Create a new HTTP/3 request stream.
    pub fn stream_new(&mut self, conn: &mut Connection) -> Result<u64> {
        self.stream_new_with_priority(conn, &Http3Priority::default())
    }

    /// Create a new HTTP/3 request stream with the given priority.
    pub fn stream_new_with_priority(
        &mut self,
        conn: &mut Connection,
        priority: &Http3Priority,
    ) -> Result<u64> {
        // Endpoint MUST NOT initiate new requests on the connection after receipt of
        // a GOAWAY frame from the peer.
        if self.peer_goaway_id.is_some() {
            return Err(Http3Error::IdError);
        }

        // Get the next available stream ID for new request.
        let stream_id = self.next_request_stream_id;

        // Create a new QUIC transport stream.
        conn.stream_new(stream_id, priority.map_to_quic(), priority.incremental)?;

        // Create a new HTTP/3 request stream and insert it into streams map.
        let mut stream = Http3Stream::new(stream_id, true);
        stream.mark_priority_initialized();
        self.streams.insert(stream_id, stream);

        // We only update next_request_stream_id when the new stream has been
        // created, to avoid skipping stream IDs.
        self.update_next_request_stream_id()?;

        trace!("{} create new stream {}", self.trace_id, stream_id);
        Ok(stream_id)
    }

    /// Close the given HTTP/3 stream.
    pub fn stream_close(&mut self, conn: &mut Connection, stream_id: u64) -> Result<()> {
        if stream_id % 4 != 0 {
            // Only support closing request stream.
            return Err(Http3Error::InternalError);
        }

        if !self.streams.contains_key(&stream_id) {
            // Stream doesn't exist, ignore the prioritization.
            return Ok(());
        }

        if !conn.stream_finished(stream_id) {
            info!(
                "{:?} stream {} shutdown read prematurely",
                self.trace_id, stream_id
            );
            let _ = conn.stream_shutdown(stream_id, crate::Shutdown::Read, 0);
        }

        let stream = self.streams.get(&stream_id).unwrap();
        if !stream.write_finished() {
            info!(
                "{:?} stream {} shutdown write prematurely",
                self.trace_id, stream_id
            );
            let _ = conn.stream_shutdown(stream_id, crate::Shutdown::Write, 0);
        }

        self.stream_destroy(stream_id);
        Ok(())
    }

    /// Destroy the given stream.
    pub fn stream_destroy(&mut self, stream_id: u64) {
        trace!("{} destroy stream {}", self.trace_id, stream_id);
        self.streams.remove(&stream_id);
    }

    /// Set priority for an HTTP/3 stream.
    pub fn stream_set_priority(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        priority: &Http3Priority,
    ) -> Result<()> {
        if !self.streams.contains_key(&stream_id) {
            // Stream doesn't exist, ignore the prioritization.
            return Ok(());
        }

        let urgency = priority.map_to_quic();
        conn.stream_set_priority(stream_id, urgency, priority.incremental)?;

        Ok(())
    }

    /// Encode HTTP/3 header fields into a field section with QPACK.
    fn encode_header_fields<T: NameValue>(&mut self, headers: &[T]) -> Result<Bytes> {
        // RFC9114: The default value of max_field_section_size is unlimited.
        let max_field_section_size = self
            .peer_settings
            .max_field_section_size
            .unwrap_or(u64::MAX);

        // RFC9114 4.2.2 Header Size Constraints
        // The size of a field list is calculated based on the uncompressed size of fields,
        // including the length of the name and value in bytes plus an overhead of 32 bytes
        // for each field.
        let headers_size = headers.iter().fold(0, |header_size, h| {
            header_size + h.value().len() + h.name().len() + 32
        });

        if headers_size as u64 > max_field_section_size {
            return Err(Http3Error::ExcessiveLoad);
        }

        let mut header_block = BytesMut::zeroed(headers_size);
        match self.qpack_encoder.encode(headers, header_block.as_mut()) {
            Ok(v) => {
                header_block.truncate(v);
                Ok(header_block.freeze())
            }
            Err(_) => Err(Http3Error::InternalError),
        }
    }

    /// Write HTTP/3 header block to quic stream buffer.
    fn send_header_block(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        header_block: Bytes,
        fin: bool,
    ) -> Result<()> {
        // HEADER_FRAME_TYPE(1Bytes) + header_block_len(1~8Bytes) <= 9Bytes.
        let mut bytes = BytesMut::zeroed(10);
        let mut b = bytes.as_mut();

        let header_block_len = header_block.len();
        let mut frame_header_len = b.write_varint(frame::HEADERS_FRAME_TYPE)?;
        frame_header_len += b.write_varint(header_block_len as u64)?;

        // We don't want to write headers multiple times, so we need to make sure
        // the stream has enough capacity to write the entire HEADERS frame.
        match conn.stream_writable(stream_id, frame_header_len + header_block_len) {
            Ok(true) => (),
            Ok(false) => {
                info!(
                    "{:?} stream {} send frame HEADERS len {} fin {} blocked, capacity {}",
                    conn.trace_id(),
                    stream_id,
                    frame_header_len + header_block_len,
                    fin,
                    conn.stream_capacity(stream_id).unwrap_or(0)
                );

                // Register want write event to quic transport.
                let _ = conn.stream_want_write(stream_id, true);

                let stream = self.streams.get_mut(&stream_id).unwrap();
                // If there are not enough capacity to write the header_block fully,
                // buffer it and write it again when the stream has enough capacity.
                // We cache the header_block in http/3 stack, eliminating the need for
                // the upper application to cache it.
                stream.set_header_block(Some((header_block, fin)));

                // Here we return `Http3Error::StreamBlocked` to the upper application,
                // so that the upper application can know that the stream is blocked by
                // flow control, and then the upper application can choose to wait for
                // the stream to be writable or do other appropriate actions.
                return Err(Http3Error::StreamBlocked);
            }
            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.stream_destroy(stream_id);
                }

                return Err(e.into());
            }
        };

        // Write HEADERS frame header.
        bytes.truncate(frame_header_len);
        conn.stream_write(stream_id, bytes.freeze(), false)?;
        // Write HEADERS frame payload.
        conn.stream_write(stream_id, header_block, fin)?;

        trace!(
            "{:?} stream {} send frame HEADERS len {} fin {}",
            conn.trace_id(),
            stream_id,
            header_block_len,
            fin
        );

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            // Current headers have been written to quic stream buffer,
            // if there is cached header_block, we should remove it.
            let _ = stream.take_header_block();

            // Mark stream has been initialized locally.
            stream.mark_local_initialized();

            if fin {
                stream.mark_write_finished();
            }
        }

        // All sending data has been written to quic stream buffer and all incoming data has been read,
        // so we can remove the stream from streams map immediately.
        if fin && conn.stream_finished(stream_id) {
            self.stream_destroy(stream_id);
        }

        Ok(())
    }

    /// Write HTTP/3 headers to quic stream buffer.
    pub fn send_headers<T: NameValue>(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        headers: &[T],
        fin: bool,
    ) -> Result<()> {
        if stream_id % 4 != 0 || !self.streams.contains_key(&stream_id) {
            return Err(Http3Error::FrameUnexpected);
        }

        let stream = self.streams.get_mut(&stream_id).unwrap();
        if !stream.priority_initialized() {
            let priority = Http3Priority::default();
            conn.stream_set_priority(stream_id, priority.map_to_quic(), priority.incremental)?;
            stream.mark_priority_initialized();
        }

        let header_block = self.encode_header_fields(headers)?;
        self.send_header_block(conn, stream_id, header_block, fin)
    }

    /// Write request or response body into quic transport stream's send buffer.
    pub fn send_body(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        mut body: Bytes,
        mut fin: bool,
    ) -> Result<usize> {
        // Only support sending body on request stream.
        if stream_id % 4 != 0 {
            return Err(Http3Error::FrameUnexpected);
        }

        // If stream doesn't exist, return `Http3Error::FrameUnexpected`.
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Http3Error::FrameUnexpected)?;

        if let Some((header_block, write_fin)) = stream.take_header_block() {
            // We should update fin flag if the application send empty body with fin.
            let write_fin = write_fin || (fin && body.is_empty());
            self.send_header_block(conn, stream_id, header_block, write_fin)?;

            // Here we return `Http3Error::NoError` to the upper application,
            // so that the upper application can know that the header_block has
            // been sent successfully, and then the upper application can choose
            // to send body or do other appropriate actions.
            return Err(Http3Error::NoError);
        }

        // Stream may be removed while send header_block.
        if !self
            .streams
            .get(&stream_id)
            .ok_or(Http3Error::FrameUnexpected)?
            .local_initialized()
        {
            // Stream header has not been sent yet, should not send body now.
            return Err(Http3Error::FrameUnexpected);
        }

        // Do nothing if the body is empty and the fin flag is false.
        if body.is_empty() && !fin {
            return Err(Http3Error::Done);
        }

        let send_capacity = match conn.stream_capacity(stream_id) {
            Ok(v) => v,
            Err(e) => {
                if conn.stream_finished(stream_id) {
                    self.stream_destroy(stream_id);
                }

                return Err(e.into());
            }
        };

        // Here, 1 == codec::encode_varint_len(DATA_FRAME_TYPE).
        let overhead = 1 + codec::encode_varint_len(body.len() as u64);

        // If there is not enough capacity, update writable threshold by `stream_writable`.
        if send_capacity < overhead {
            let _ = conn.stream_writable(stream_id, overhead + 1);

            // Register want write event to quic transport.
            let _ = conn.stream_want_write(stream_id, true);
            return Err(Http3Error::Done);
        }

        // Restrict the frame payload length to the stream's capacity.
        let body_len = body.len();
        let frame_len = std::cmp::min(body_len, send_capacity - overhead);

        // If we can not write all data to quic stream buffer, truncate the body to the stream's capacity,
        // and set the fin flag to false.
        if frame_len < body_len {
            body.truncate(frame_len);
            fin = false;
        }

        // Do nothing if the body is empty and the fin flag is false.
        if body.is_empty() && !fin {
            return Err(Http3Error::Done);
        }

        // DATA_FRAME_TYPE(1Bytes) + data_payload_len(1~8Bytes) <= 9Bytes.
        let mut bytes = BytesMut::zeroed(10);
        let mut b = bytes.as_mut();

        // Write the DATA frame header.
        let mut len = b.write_varint(frame::DATA_FRAME_TYPE)?;
        len += b.write_varint(frame_len as u64)?;
        bytes.truncate(len);
        conn.stream_write(stream_id, bytes.freeze(), false)?;
        // Write the DATA frame payload.
        let written = conn.stream_write(stream_id, body, fin)?;

        trace!(
            "{:?} stream {} send DATA frame written {} body_len {} fin {}",
            conn.trace_id(),
            stream_id,
            written,
            body_len,
            fin
        );

        if written < body_len {
            // After writing partial data, we may not require as much `overhead` capacity
            // and need to update the write threshold, try to notify remote endpoint that
            // the stream is blocked by flow control.
            // Here, 2 == codec::encode_varint_len(DATA_FRAME_TYPE) + 1, where 1 means at
            // least 1 byte of data can be written.
            let write_thresh = 2 + codec::encode_varint_len((body_len - written) as u64);
            let _ = conn.stream_writable(stream_id, write_thresh);

            // Register want write event to quic transport.
            let _ = conn.stream_want_write(stream_id, true);
        } else if fin {
            if conn.stream_finished(stream_id) {
                self.stream_destroy(stream_id);
            } else if let Some(stream) = self.streams.get_mut(&stream_id) {
                // If all data with fin flag has been written to quic stream buffer,
                // but the stream is not completed, mark it as write finished.
                stream.mark_write_finished();
            }
        }

        // Return the number of bytes written to the stream, the frame header is not included.
        Ok(written)
    }

    /// Read request or response body into the given buffer from quic transport stream.
    pub fn recv_body(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        out: &mut [u8],
    ) -> Result<usize> {
        let mut total_read = 0;

        // Attempt to read all buffered data in the QUIC transport stream buffer, even if it spans
        // across multiple HTTP/3 DATA frames.
        while total_read < out.len() {
            let stream = self.streams.get_mut(&stream_id).ok_or(Http3Error::Done)?;

            if stream.state() != Http3StreamState::Data {
                break;
            }

            let (read, fin) = match stream.read_data_from_quic(conn, &mut out[total_read..]) {
                Ok(v) => v,
                Err(Http3Error::Done) => break,
                Err(e) => return Err(e),
            };

            total_read += read;

            // No more data can be read.
            if read == 0 || fin {
                break;
            }

            // Try to process incoming data from the quic stream.
            match self.process_readable_request_stream(conn, stream_id, false) {
                // DATA event must not be triggered when not polling.
                Ok(_) => unreachable!(),
                Err(Http3Error::Done) => (),
                Err(e) => return Err(e),
            };

            // The stream's final size is known and we have read all data from transport.
            if conn.stream_finished(stream_id) {
                break;
            }
        }

        // All incoming data has been read by application, and the stream's final size is known,
        // mark the stream as finished.
        if conn.stream_finished(stream_id) {
            self.process_finished_stream(stream_id);
        }

        if total_read == 0 {
            return Err(Http3Error::Done);
        }

        Ok(total_read)
    }

    /// Send PRIORITY_UPDATE on the control stream with specified request stream ID and priority.
    ///
    /// If the underlying QUIC stream doesn't have enough capacity for the operation to complete,
    /// return [`Http3Error::StreamBlocked`] error. The application should retry the operation once
    /// the stream is reported as writable again.
    pub fn send_priority_update_for_request(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        priority: &Http3Priority,
    ) -> Result<()> {
        // The PRIORITY_UPDATE frame MUST be sent on the client control stream.
        if self.is_server || self.local_control_stream_id.is_none() {
            return Err(Http3Error::FrameUnexpected);
        }

        // The stream has been closed, we should not send PRIORITY_UPDATE frame for it.
        if conn.get_streams().is_closed(stream_id) {
            return Err(Http3Error::FrameUnexpected);
        }

        // RFC9218 7.2. HTTP/3 PRIORITY_UPDATE Frame
        // The request-stream variant of PRIORITY_UPDATE (type=0xF0700) MUST reference
        // a request stream. If a server receives a PRIORITY_UPDATE (type=0xF0700) for
        // a stream ID that is not a request stream, this MUST be treated as a connection
        // error of type H3_ID_ERROR. The stream ID MUST be within the client-initiated
        // bidirectional stream limit. If a server receives a PRIORITY_UPDATE (type=0xF0700)
        // with a stream ID that is beyond the stream limits, this SHOULD be treated as
        // a connection error of type H3_ID_ERROR.
        if stream_id % 4 != 0 || stream_id > conn.get_streams().peer_max_streams(true) {
            return Err(Http3Error::IdError);
        }

        let urgency = priority.subject_to_bound();
        let mut field_value = format!("u={urgency}");
        if priority.incremental {
            field_value.push_str(",i");
        }

        let priority_field_value = field_value.into_bytes();
        let frame_payload_len = codec::encode_varint_len(stream_id) + priority_field_value.len();

        // Here, 4 == codec::encode_varint_len(frame::PRIORITY_UPDATE_FRAME_REQUEST_TYPE)
        let overhead = 4
            + codec::encode_varint_len(stream_id)
            + codec::encode_varint_len(frame_payload_len as u64);

        let local_control_stream_id = self.local_control_stream_id.unwrap();

        // Make sure the control stream has enough capacity.
        match conn.stream_writable(
            local_control_stream_id,
            overhead + priority_field_value.len(),
        ) {
            Ok(true) => (),
            Ok(false) => {
                // Register want write event to quic transport.
                let _ = conn.stream_want_write(local_control_stream_id, true);
                return Err(Http3Error::StreamBlocked);
            }
            Err(e) => {
                return Err(e.into());
            }
        }

        trace!(
            "{:?} send frame PRIORITY_UPDATE for request {} with priority_field_value {:?}",
            conn.trace_id(),
            stream_id,
            priority_field_value,
        );

        let mut bytes = BytesMut::zeroed(overhead + priority_field_value.len());
        let frame = frame::Http3Frame::PriorityUpdateRequest {
            prioritized_element_id: stream_id,
            priority_field_value,
        };

        let frame_len = frame.encode(bytes.as_mut())?;
        bytes.truncate(frame_len);
        conn.stream_write(local_control_stream_id, bytes.freeze(), false)?;

        Ok(())
    }

    /// Take the last PRIORITY_UPDATE for the specified prioritized element ID.
    pub fn take_priority_update(&mut self, prioritized_element_id: u64) -> Result<Vec<u8>> {
        match self.streams.get_mut(&prioritized_element_id) {
            Some(stream) => stream.take_priority_update().ok_or(Http3Error::Done),
            None => Err(Http3Error::Done),
        }
    }

    /// Send GOAWAY frame with the given stream ID to close the connection gracefully.
    pub fn send_goaway(&mut self, conn: &mut Connection, mut id: u64) -> Result<()> {
        // We don't support server push right now, so the id from client's GOAWAY frame always be 0.
        // TODO: support server push and client initiated GOAWAY frames with id > 0
        if !self.is_server {
            id = 0;
        }

        // In the server-to-client direction, it carries a QUIC stream ID for a client-initiated
        // bidirectional stream encoded as a variable-length integer.
        if self.is_server && id % 4 != 0 {
            return Err(Http3Error::IdError);
        }

        if let Some(prev_goaway_id) = self.local_goaway_id {
            // An endpoint MAY send multiple GOAWAY frames indicating different identifiers,
            // but the identifier in each frame MUST NOT be greater than the identifier in
            // any previous frame, since clients might already have retried unprocessed requests
            // on another HTTP connection.
            if id > prev_goaway_id {
                return Err(Http3Error::IdError);
            }
        }

        // The GOAWAY frame is always sent on the control stream.
        // If the control stream is not available, return an error.
        if let Some(stream_id) = self.local_control_stream_id {
            // GOAWAY_FRAME_TYPE(1Bytes) + goaway_id encoded len(1Bytes) + goaway_id(1~8Bytes) <= 10Bytes.
            let mut bytes = BytesMut::zeroed(10);

            let frame = frame::Http3Frame::GoAway { id };
            let frame_len = frame.encode(bytes.as_mut())?;

            let stream_cap = conn.stream_capacity(stream_id)?;
            if stream_cap < frame_len {
                // Register want write event to quic transport.
                let _ = conn.stream_want_write(stream_id, true);
                return Err(Http3Error::StreamBlocked);
            }

            trace!("{:?} send GOAWAY frame {:?}", conn.trace_id(), frame);

            bytes.truncate(frame_len);
            conn.stream_write(stream_id, bytes.freeze(), false)?;

            self.local_goaway_id = Some(id);
            Ok(())
        } else {
            Err(Http3Error::InternalError)
        }
    }

    /// Return the raw settings received from the peer.
    pub fn peer_raw_settings(&self) -> Option<&[(u64, u64)]> {
        self.peer_settings.raw.as_deref()
    }

    /// Get the default priority for the given unidirectional stream type.
    fn uni_stream_default_priority(stream_type: u64) -> (u8, bool) {
        match stream_type {
            // Control and QPACK streams are critical to the operation of HTTP/3,
            // so they are given the highest priority for scheduling.
            stream::HTTP3_CONTROL_STREAM_TYPE
            | stream::QPACK_ENCODER_STREAM_TYPE
            | stream::QPACK_DECODER_STREAM_TYPE => (0, false),

            // Default priority(3 + 124) for push streams.
            stream::HTTP3_PUSH_STREAM_TYPE => (127, true),

            // Other streams are scheduled with the lowest priority.
            // Note that we only support control, QPACK encoder/decoder and push streams for now.
            _ => (255, false),
        }
    }

    /// Open a new unidirectional stream.
    fn open_uni_stream(&mut self, conn: &mut Connection, stream_type: u64) -> Result<u64> {
        let stream_id = self.next_uni_stream_id;

        let (urgency, incremental) = Self::uni_stream_default_priority(stream_type);

        // Note that `StreamLimitError` will be returned if the HTTP/3 critical
        // stream cannot be created due to the concurrency control limit.
        conn.stream_new(stream_id, urgency, incremental)?;

        // Uni stream_type encoded len(1~8Bytes).
        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        // Write the stream type to the quic stream send buffer.
        let len = b.write_varint(stream_type)?;
        bytes.truncate(len);
        conn.stream_write(stream_id, bytes.freeze(), false)?;

        // In order to ensure that stream IDs are not skipped, we calculate the next
        // available stream ID only after data has been successfully buffered.
        self.update_next_uni_stream_id()?;

        Ok(stream_id)
    }

    /// Open QPACK encoder stream.
    fn open_qpack_encoder_stream(&mut self, conn: &mut Connection) -> Result<()> {
        let stream_id = self.open_uni_stream(conn, stream::QPACK_ENCODER_STREAM_TYPE)?;

        // Record the stream ID of the local QPACK encoder stream.
        self.local_qpack_streams.encoder_stream_id = Some(stream_id);

        Ok(())
    }

    /// Open QPACK decoder stream.
    fn open_qpack_decoder_stream(&mut self, conn: &mut Connection) -> Result<()> {
        let stream_id = self.open_uni_stream(conn, stream::QPACK_DECODER_STREAM_TYPE)?;

        // Record the stream ID of the local QPACK decoder stream.
        self.local_qpack_streams.decoder_stream_id = Some(stream_id);

        Ok(())
    }

    /// Send SETTINGS frame to peer.
    fn send_settings_frame(&mut self, conn: &mut Connection, stream_id: u64) -> Result<()> {
        let frame = frame::Http3Frame::Settings {
            max_field_section_size: self.local_settings.max_field_section_size,
            qpack_max_table_capacity: self.local_settings.qpack_max_table_capacity,
            qpack_blocked_streams: self.local_settings.qpack_blocked_streams,
            connect_protocol_enabled: self.local_settings.connect_protocol_enabled,
            raw: Default::default(),
        };

        let mut bytes = BytesMut::zeroed(128);
        let frame_len = frame.encode(bytes.as_mut())?;
        bytes.truncate(frame_len);
        // RFC9114: Because the contents of the control stream are used to manage the behavior of other streams,
        // endpoints SHOULD provide enough flow-control credit to keep the peer's control stream from becoming blocked.
        conn.stream_write(stream_id, bytes.freeze(), false)?;

        trace!(
            "{:?} send SETTINGS frame on stream {} len {}",
            conn.trace_id(),
            stream_id,
            frame_len
        );

        Ok(())
    }

    /// Open control stream and send SETTINGS frame based on the HTTP/3 configuration.
    fn open_control_stream(&mut self, conn: &mut Connection) -> Result<()> {
        let stream_id = match self.open_uni_stream(conn, stream::HTTP3_CONTROL_STREAM_TYPE) {
            Ok(v) => v,
            Err(e) => {
                error!("{:?} open control stream failed: {:?}", conn.trace_id(), e);

                if e == Http3Error::Done {
                    return Err(Http3Error::InternalError);
                }

                return Err(e);
            }
        };

        // Record the stream ID of the local control stream.
        self.local_control_stream_id = Some(stream_id);

        // Send SETTINGS frame to peer.
        self.send_settings_frame(conn, stream_id)?;

        Ok(())
    }

    /// Open critical streams, including control, QPACK encoder and decoder streams.
    fn open_critical_streams(&mut self, conn: &mut Connection) -> Result<()> {
        // RFC9114 6.2. Unidirectional Streams
        // Each endpoint needs to create at least one unidirectional stream for the HTTP control stream.
        // QPACK requires two additional unidirectional streams, and other extensions might require
        // further streams. Therefore, the transport parameters sent by both clients and servers MUST
        // allow the peer to create at least three unidirectional streams. These transport parameters
        // SHOULD also provide at least 1,024 bytes of flow-control credit to each unidirectional stream.
        match self.open_control_stream(conn) {
            Ok(_) => (),

            Err(e) => {
                conn.close(true, e.to_wire(), b"open control stream failed")?;
                return Err(e);
            }
        };

        // Try to open QPACK encoder/decoder streams, but ignore errors if it fails
        // since we don't support QPACK dynamic table yet.
        self.open_qpack_encoder_stream(conn).ok();
        self.open_qpack_decoder_stream(conn).ok();

        Ok(())
    }

    /// Register control stream.
    fn register_control_stream(&mut self, conn: &mut Connection, stream_id: u64) -> Result<()> {
        // Only one control stream is allowed.
        if self.peer_control_stream_id.is_some() {
            error!(
                "{:?} received multiple control stream {}",
                conn.trace_id(),
                stream_id
            );

            // RFC9114 6.2.1 Control Streams
            // Only one control stream per peer is permitted; receipt of a
            // second stream claiming to be a control stream MUST be treated
            // as a connection error of type H3_STREAM_CREATION_ERROR.
            conn.close(
                true,
                Http3Error::StreamCreationError.to_wire(),
                b"multiple control streams received",
            )?;
            return Err(Http3Error::StreamCreationError);
        }

        trace!(
            "{:?} open peer's control stream {}",
            conn.trace_id(),
            stream_id
        );

        self.peer_control_stream_id = Some(stream_id);
        Ok(())
    }

    /// Register QPACK encoder stream.
    fn register_qpack_encoder_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<()> {
        // Only one QPACK encoder stream is allowed.
        if self.peer_qpack_streams.encoder_stream_id.is_some() {
            error!(
                "{:?} received multiple QPACK encoder stream {}",
                conn.trace_id(),
                stream_id
            );

            // RFC9204 4.2. Encoder and Decoder Streams
            // Each endpoint MUST initiate, at most, one encoder stream and,
            // at most, one decoder stream. Receipt of a second instance of
            // either stream type MUST be treated as a connection error of
            // type H3_STREAM_CREATION_ERROR.
            conn.close(
                true,
                Http3Error::StreamCreationError.to_wire(),
                b"multiple QPACK encoder streams received",
            )?;
            return Err(Http3Error::StreamCreationError);
        }

        trace!(
            "{:?} open peer's QPACK encoder stream {}",
            conn.trace_id(),
            stream_id
        );

        self.peer_qpack_streams.encoder_stream_id = Some(stream_id);
        Ok(())
    }

    /// Register QPACK decoder stream.
    fn register_qpack_decoder_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<()> {
        // Only one QPACK decoder stream is allowed.
        if self.peer_qpack_streams.decoder_stream_id.is_some() {
            error!(
                "{:?} received multiple QPACK decoder stream {}",
                conn.trace_id(),
                stream_id
            );

            // RFC9204 4.2. Encoder and Decoder Streams
            // Each endpoint MUST initiate, at most, one encoder stream and,
            // at most, one decoder stream. Receipt of a second instance of
            // either stream type MUST be treated as a connection error of
            // type H3_STREAM_CREATION_ERROR.
            conn.close(
                true,
                Http3Error::StreamCreationError.to_wire(),
                b"multiple QPACK decoder streams received",
            )?;
            return Err(Http3Error::StreamCreationError);
        }

        trace!(
            "{:?} open peer's QPACK decoder stream {}",
            conn.trace_id(),
            stream_id
        );

        self.peer_qpack_streams.decoder_stream_id = Some(stream_id);
        Ok(())
    }

    /// Register critical stream, maybe control, QPACK encoder or decoder stream.
    fn register_critical_stream(
        &mut self,
        conn: &mut Connection,
        stream_type: Http3StreamType,
        stream_id: u64,
    ) -> Result<()> {
        match stream_type {
            Http3StreamType::Control => {
                self.register_control_stream(conn, stream_id)?;
            }
            Http3StreamType::QpackEncoder => {
                self.register_qpack_encoder_stream(conn, stream_id)?;
            }
            Http3StreamType::QpackDecoder => {
                self.register_qpack_decoder_stream(conn, stream_id)?;
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    /// Receive an HTTP/3 HEADERS frame from the peer.
    fn on_headers_frame_received(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        field_section: Vec<u8>,
    ) -> Result<(u64, Http3Event)> {
        // RFC9114: The default value of max_field_section_size is unlimited.
        let max_field_section_size = self
            .local_settings
            .max_field_section_size
            .unwrap_or(u64::MAX);

        let headers = match self
            .qpack_decoder
            .decode(&field_section[..], max_field_section_size)
        {
            Ok(v) => v.0,
            Err(e) => {
                error!(
                    "{:?} stream {} qpack decode error: {:?}",
                    conn.trace_id(),
                    stream_id,
                    e
                );

                conn.close(true, e.to_wire(), b"qpack decompression failed")?;
                return Err(e);
            }
        };

        let headers_event = Http3Event::Headers {
            headers,
            fin: conn.stream_finished(stream_id),
        };

        Ok((stream_id, headers_event))
    }

    /// Receive an HTTP/3 DATA frame from the peer.
    fn on_data_frame_received(
        &mut self,
        _conn: &mut Connection,
        _stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        // Do nothing. The Data event is processed separately.
        Err(Http3Error::Done)
    }

    /// Receive an HTTP/3 GOAWAY frame from the peer.
    fn on_goaway_frame_received(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        id: u64,
    ) -> Result<(u64, Http3Event)> {
        // RFC9114 7.2.6. GOAWAY
        // In the server-to-client direction, it carries a QUIC stream ID for a client-initiated
        // bidirectional stream encoded as a variable-length integer. A client MUST treat receipt
        // of a GOAWAY frame containing a stream ID of any other type as a connection error of
        // type H3_ID_ERROR.
        if !self.is_server && id % 4 != 0 {
            conn.close(
                true,
                Http3Error::FrameUnexpected.to_wire(),
                b"client received GOAWAY on non-request stream",
            )?;

            return Err(Http3Error::IdError);
        }

        // RFC9114 5.2 Connection Shutdown
        // An endpoint MAY send multiple GOAWAY frames indicating different identifiers,
        // but the identifier in each frame MUST NOT be greater than the identifier in any
        // previous frame, since clients might already have retried unprocessed requests on
        // another HTTP connection. Receiving a GOAWAY containing a larger identifier than
        // previously received MUST be treated as a connection error of type H3_ID_ERROR.
        if let Some(prev_id) = self.peer_goaway_id {
            if id > prev_id {
                error!(
                    "{:?} recv GOAWAY on stream {} carries a larger ID {} than previously received {}",
                    conn.trace_id(),
                    stream_id,
                    id,
                    prev_id
                );

                conn.close(
                    true,
                    Http3Error::IdError.to_wire(),
                    b"GOAWAY carries a larger ID than previously received",
                )?;
                return Err(Http3Error::IdError);
            }
        }

        self.peer_goaway_id = Some(id);
        Ok((id, Http3Event::GoAway))
    }

    /// Receive an HTTP/3 MAX_PUSH_ID frame from the peer.
    fn on_max_push_id_frame_received(
        &mut self,
        conn: &mut Connection,
        _stream_id: u64,
        push_id: u64,
    ) -> Result<(u64, Http3Event)> {
        // A server MUST NOT send a MAX_PUSH_ID frame. A client MUST treat the receipt of a
        // MAX_PUSH_ID frame as a connection error of type H3_FRAME_UNEXPECTED.
        if !self.is_server {
            conn.close(
                true,
                Http3Error::FrameUnexpected.to_wire(),
                b"MAX_PUSH_ID received by client",
            )?;

            return Err(Http3Error::FrameUnexpected);
        }

        // A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of a MAX_PUSH_ID frame
        // that contains a smaller value than previously received MUST be treated as a connection
        // error of type H3_ID_ERROR.
        if Some(push_id) < self.max_push_id {
            conn.close(
                true,
                Http3Error::IdError.to_wire(),
                b"MAX_PUSH_ID reduced the max push ID",
            )?;

            return Err(Http3Error::IdError);
        }

        self.max_push_id = Some(push_id);
        Err(Http3Error::Done)
    }

    /// Receive an HTTP/3 PUSH_PROMISE frame from the peer.
    fn on_push_promise_frame_received(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        push_id: u64,
        _field_section: Vec<u8>,
    ) -> Result<(u64, Http3Event)> {
        // A client MUST NOT send a PUSH_PROMISE frame. A server MUST treat the receipt of
        // a PUSH_PROMISE frame as a connection error of type H3_FRAME_UNEXPECTED.
        if self.is_server {
            conn.close(
                true,
                Http3Error::FrameUnexpected.to_wire(),
                b"PUSH_PROMISE received by server",
            )?;

            return Err(Http3Error::FrameUnexpected);
        }

        // The PUSH_PROMISE frame (type=0x05) is used to carry a promised request header section
        // from server to client on a request stream.
        if stream_id % 4 != 0 {
            conn.close(
                true,
                Http3Error::FrameUnexpected.to_wire(),
                b"PUSH_PROMISE received on non-request stream",
            )?;

            return Err(Http3Error::FrameUnexpected);
        }

        // A server MUST NOT use a push ID that is larger than the client has provided in a
        // MAX_PUSH_ID frame (Section 7.2.7). A client MUST treat receipt of a PUSH_PROMISE
        // frame that contains a larger push ID than the client has advertised as a connection
        // error of H3_ID_ERROR.
        if Some(push_id) > self.max_push_id {
            conn.close(
                true,
                Http3Error::IdError.to_wire(),
                b"PUSH_PROMISE uses a larger push ID than the client has advertised",
            )?;

            return Err(Http3Error::IdError);
        }

        // Ignore the PUSH_PROMISE field_section temporarily.
        Err(Http3Error::Done)
    }

    /// Receive an HTTP/3 CANCEL_PUSH frame from the peer.
    fn on_cancel_push_frame_received(
        &mut self,
        _conn: &mut Connection,
        _stream_id: u64,
        _push_id: u64,
    ) -> Result<(u64, Http3Event)> {
        // Ignore CANCEL_PUSH frame temporarily.
        Err(Http3Error::Done)
    }

    /// Receive an HTTP/3 PRIORITY_UPDATE frame for request stream from the peer.
    fn on_priority_update_request_frame_received(
        &mut self,
        conn: &mut Connection,
        _stream_id: u64,
        prioritized_element_id: u64,
        priority_field_value: Vec<u8>,
    ) -> Result<(u64, Http3Event)> {
        // The PRIORITY_UPDATE frame MUST be sent on the client control stream (see Section 6.2.1 of [HTTP/3]).
        // Receiving a PRIORITY_UPDATE frame on a stream other than the client control stream MUST be treated
        // as a connection error of type H3_FRAME_UNEXPECTED.
        if !self.is_server {
            conn.close(
                true,
                Http3Error::FrameUnexpected.to_wire(),
                b"client received PRIORITY_UPDATE",
            )?;

            return Err(Http3Error::FrameUnexpected);
        }

        // The request-stream variant of PRIORITY_UPDATE (type=0xF0700) MUST reference a request stream.
        // If a server receives a PRIORITY_UPDATE (type=0xF0700) for a stream ID that is not a request
        // stream, this MUST be treated as a connection error of type H3_ID_ERROR.
        if prioritized_element_id % 4 != 0 {
            conn.close(
                true,
                Http3Error::IdError.to_wire(),
                b"PRIORITY_UPDATE for request stream with unexpected ID",
            )?;

            return Err(Http3Error::IdError);
        }

        // The stream ID MUST be within the client-initiated bidirectional stream limit. If a server receives
        // a PRIORITY_UPDATE (type=0xF0700) with a stream ID that is beyond the stream limits, this SHOULD be
        // treated as a connection error of type H3_ID_ERROR.
        let max_stream_id_limit = conn.get_streams().max_streams(true) * 4;
        if prioritized_element_id > max_stream_id_limit {
            conn.close(
                true,
                Http3Error::IdError.to_wire(),
                b"PRIORITY_UPDATE for request stream beyond the stream limits",
            )?;

            return Err(Http3Error::IdError);
        }

        // If the stream with given ID has been closed, discard the PRIORITY_UPDATE frame.
        if conn.get_streams().is_closed(prioritized_element_id) {
            trace!(
                "{:?} received PRIORITY_UPDATE for closed stream {}",
                conn.trace_id(),
                prioritized_element_id
            );
            return Err(Http3Error::Done);
        }

        // RFC9218 7. The PRIORITY_UPDATE Frame
        // A client MAY send a PRIORITY_UPDATE frame before the stream that it references is open.
        // Furthermore, HTTP/3 offers no guaranteed ordering across streams, which could cause the
        // frame to be received earlier than intended. Either case leads to a race condition where
        // a server receives a PRIORITY_UPDATE frame that references a request stream that is yet
        // to be opened. To solve this condition, for the purposes of scheduling, the most recently
        // received PRIORITY_UPDATE frame can be considered as the most up-to-date information that
        // overrides any other signal. Servers SHOULD buffer the most recently received PRIORITY_UPDATE
        // frame and apply it once the referenced stream is opened.
        //
        // If the stream with the given ID is yet to be opened, create it.
        let stream = match self.get_or_create(prioritized_element_id, false) {
            Ok(v) => v,
            Err(e) => {
                conn.close(true, e.to_wire(), b"")?;
                return Err(e);
            }
        };

        let had_priority_update = stream.has_priority_update();
        stream.set_priority_update(Some(priority_field_value));

        match had_priority_update {
            false => Ok((prioritized_element_id, Http3Event::PriorityUpdate)),
            // Do not trigger the PriorityUpdate event repeatedly.
            true => Err(Http3Error::Done),
        }
    }

    /// Receive an HTTP/3 PRIORITY_UPDATE frame for push stream from the peer.
    fn on_priority_update_push_frame_received(
        &mut self,
        conn: &mut Connection,
        _stream_id: u64,
        _prioritized_element_id: u64,
    ) -> Result<(u64, Http3Event)> {
        // The PRIORITY_UPDATE frame MUST be sent on the client control stream (see Section 6.2.1 of [HTTP/3]).
        // Receiving a PRIORITY_UPDATE frame on a stream other than the client control stream MUST be treated
        // as a connection error of type H3_FRAME_UNEXPECTED.
        if !self.is_server {
            conn.close(
                true,
                Http3Error::FrameUnexpected.to_wire(),
                b"client received PRIORITY_UPDATE",
            )?;

            return Err(Http3Error::FrameUnexpected);
        }

        // RFC9218 7.2 HTTP/3 PRIORITY_UPDATE Frame
        // The push-stream variant of PRIORITY_UPDATE (type=0xF0701) MUST reference a promised push stream.
        // If a server receives a PRIORITY_UPDATE (type=0xF0701) with a push ID that is greater than the maximum
        // push ID or that has not yet been promised, this MUST be treated as a connection error of type H3_ID_ERROR.

        // Ignore the PRIORITY_UPDATE frame temporarily.
        Err(Http3Error::Done)
    }

    /// Process an HTTP/3 frame received from the peer.
    fn process_frame(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        frame: frame::Http3Frame,
        payload_len: u64,
    ) -> Result<(u64, Http3Event)> {
        trace!(
            "{:?} stream {} recv frame {:?}, payload_len={}",
            conn.trace_id(),
            stream_id,
            frame,
            payload_len
        );

        match frame {
            frame::Http3Frame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                connect_protocol_enabled,
                raw,
                ..
            } => {
                self.peer_settings = Http3Settings {
                    max_field_section_size,
                    qpack_max_table_capacity,
                    qpack_blocked_streams,
                    connect_protocol_enabled,
                    raw,
                };
            }

            frame::Http3Frame::Headers { field_section } => {
                return self.on_headers_frame_received(conn, stream_id, field_section);
            }

            frame::Http3Frame::Data { .. } => {
                return self.on_data_frame_received(conn, stream_id);
            }

            frame::Http3Frame::GoAway { id } => {
                return self.on_goaway_frame_received(conn, stream_id, id);
            }

            frame::Http3Frame::MaxPushId { push_id } => {
                return self.on_max_push_id_frame_received(conn, stream_id, push_id);
            }

            frame::Http3Frame::PushPromise {
                push_id,
                field_section,
            } => {
                return self.on_push_promise_frame_received(
                    conn,
                    stream_id,
                    push_id,
                    field_section,
                );
            }

            frame::Http3Frame::CancelPush { push_id } => {
                return self.on_cancel_push_frame_received(conn, stream_id, push_id);
            }

            frame::Http3Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                return self.on_priority_update_request_frame_received(
                    conn,
                    stream_id,
                    prioritized_element_id,
                    priority_field_value,
                );
            }

            frame::Http3Frame::PriorityUpdatePush {
                prioritized_element_id,
                ..
            } => {
                return self.on_priority_update_push_frame_received(
                    conn,
                    stream_id,
                    prioritized_element_id,
                );
            }

            frame::Http3Frame::Unknown { .. } => (),
        }

        Err(Http3Error::Done)
    }

    /// Process readable QPACK encoder/decoder stream.
    fn process_readable_qpack_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        let mut d: [u8; 4096] = unsafe {
            #[allow(clippy::uninit_assumed_init, invalid_value)]
            MaybeUninit::uninit().assume_init()
        };

        // We don't support qpack dynamic table yet, so just read and discard all data.
        loop {
            conn.stream_read(stream_id, &mut d)?;
        }
    }

    /// Process readable HTTP/3 push stream.
    ///
    /// Note that the polling parameter indicates whether the current API is called via poll.
    /// If it is not called via poll, i.e. called via recv_body, do not trigger any events.
    fn process_readable_push_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        polling: bool,
    ) -> Result<(u64, Http3Event)> {
        // Here we get a new reference to the stream for each iteration, to solve the problem of
        // borrowing `self` for the entire duration of the loop, because we'll need to borrow it
        // again in inner block.
        while let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state() {
                Http3StreamState::PushId => {
                    stream.parse_push_id(conn)?;
                }

                Http3StreamState::FrameType => {
                    stream.parse_frame_type(conn)?;
                }

                Http3StreamState::FramePayloadLen => {
                    stream.parse_frame_payload_length(conn)?;
                }

                Http3StreamState::FramePayload => {
                    // For application-layer initiated streams with frame data, events are reported
                    // only when polling.
                    if !polling {
                        break;
                    }

                    let (frame, payload_len) = stream.parse_frame_payload(conn)?;
                    match self.process_frame(conn, stream_id, frame, payload_len) {
                        Ok(ev) => return Ok(ev),
                        // Done means that the frame has been processed, but there may be more data in the stream to process.
                        Err(Http3Error::Done) => {
                            // If the stream is finished, return early to avoid trying to read again on a closed stream.
                            if conn.stream_finished(stream_id) {
                                break;
                            }
                        }
                        Err(e) => return Err(e),
                    };
                }

                Http3StreamState::Data => {
                    // 1. If not polling, we don't need to trigger events.
                    // 2. If polling, we don't need to trigger events repeatedly during one poll.
                    if !polling || !stream.trigger_data_event() {
                        break;
                    }
                    return Ok((stream_id, Http3Event::Data));
                }

                Http3StreamState::ReadFinished => break,

                _ => unreachable!(),
            }
        }

        Err(Http3Error::Done)
    }

    /// Process readable HTTP/3 control stream.
    fn process_readable_control_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        // Here we get a new reference to the stream for each iteration, to solve the problem of
        // borrowing `self` for the entire duration of the loop, because we'll need to borrow it
        // again in inner block.
        while let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state() {
                Http3StreamState::FrameType => {
                    stream.parse_frame_type(conn)?;
                }

                Http3StreamState::FramePayloadLen => {
                    stream.parse_frame_payload_length(conn)?;
                }

                Http3StreamState::FramePayload => {
                    let (frame, payload_len) = stream.parse_frame_payload(conn)?;
                    match self.process_frame(conn, stream_id, frame, payload_len) {
                        Ok(ev) => return Ok(ev),
                        // Done means that the frame has been processed, but there may be more data in the stream to process.
                        Err(Http3Error::Done) => (),
                        Err(e) => return Err(e),
                    };
                }

                _ => unreachable!(),
            }
        }

        Err(Http3Error::Done)
    }

    /// Process a new unidirectional stream.
    fn process_new_uni_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        stream_type: Http3StreamType,
    ) -> Result<()> {
        match stream_type {
            Http3StreamType::Control
            | Http3StreamType::QpackEncoder
            | Http3StreamType::QpackDecoder => {
                // Register critical stream to HTTP/3 connection.
                self.register_critical_stream(conn, stream_type, stream_id)?;
            }

            Http3StreamType::Push => {
                // RFC9114 Push Streams
                // Only servers can push; if a server receives a client-initiated push stream,
                // this MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR.
                if self.is_server {
                    error!(
                        "{:?} server received push stream {}",
                        conn.trace_id(),
                        stream_id
                    );

                    conn.close(
                        true,
                        Http3Error::StreamCreationError.to_wire(),
                        b"server received push stream",
                    )?;
                    return Err(Http3Error::StreamCreationError);
                }
            }

            Http3StreamType::Unknown(type_id) => {
                error!(
                    "{:?} received unknown type {} stream {}",
                    conn.trace_id(),
                    type_id,
                    stream_id
                );
                // Unknown stream types, ignore it and shutdown the stream in the outer logic.
            }

            // Request stream always a bididirectional stream, so it won't reach here.
            Http3StreamType::Request => unreachable!(),
        }

        Ok(())
    }

    /// Process readable unidirectional stream, maybe control, push or QPACK encoder/decoder stream.
    ///
    /// Note that the polling parameter indicates whether the current API is called via poll.
    /// If it is not called via poll, i.e. called via recv_body, do not trigger any events.
    fn process_readable_uni_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        polling: bool,
    ) -> Result<(u64, Http3Event)> {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => return Err(Http3Error::Done),
        };

        // Stream's type still unknown, try to parse it first.
        if stream.state() == Http3StreamState::StreamType {
            let stream_type = stream.parse_uni_stream_type(conn)?;
            self.process_new_uni_stream(conn, stream_id, stream_type)?;
        }

        let stream = self.streams.get(&stream_id).unwrap();
        match stream.stream_type().unwrap() {
            Http3StreamType::Control => {
                return self.process_readable_control_stream(conn, stream_id);
            }

            Http3StreamType::Push => {
                return self.process_readable_push_stream(conn, stream_id, polling);
            }

            // Actually, Encoder and Decoder have different parsing instruction formats,
            // but since we don't support dynamic table, we handle them here.
            Http3StreamType::QpackEncoder | Http3StreamType::QpackDecoder => {
                return self.process_readable_qpack_stream(conn, stream_id);
            }

            Http3StreamType::Unknown(_) => {
                // Unknown stream types, ignore it and shutdown stream with H3_NO_ERROR(0x100).
                conn.stream_shutdown(stream_id, crate::Shutdown::Read, 0x100)?;
            }

            Http3StreamType::Request => unreachable!(),
        }

        Err(Http3Error::Done)
    }

    /// Process a readable HTTP/3 request stream, which is alaways a bididirectional stream.
    ///
    /// Note that the polling parameter indicates whether the current API is called via poll.
    /// If it is not called via poll, i.e. called via recv_body, do not trigger any events.
    fn process_readable_request_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        polling: bool,
    ) -> Result<(u64, Http3Event)> {
        // Here we get a new reference to the stream for each iteration, to solve the problem of
        // borrowing `self` for the entire duration of the loop, because we'll need to borrow it
        // again in inner block.
        while let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state() {
                Http3StreamState::FrameType => {
                    stream.parse_frame_type(conn)?;
                }

                Http3StreamState::FramePayloadLen => {
                    stream.parse_frame_payload_length(conn)?;
                }

                Http3StreamState::FramePayload => {
                    // Only trigger events when polling is true.
                    if !polling {
                        break;
                    }

                    let (frame, payload_len) = stream.parse_frame_payload(conn)?;
                    match self.process_frame(conn, stream_id, frame, payload_len) {
                        Ok(ev) => return Ok(ev),
                        // Done means that the frame has been processed, but there
                        // may still be more data in the stream to process.
                        Err(Http3Error::Done) => {
                            // If the stream is finished, return early to avoid
                            // attempting to read again on a finished stream.
                            if conn.stream_finished(stream_id) {
                                break;
                            }
                        }
                        Err(e) => return Err(e),
                    };
                }

                Http3StreamState::Data => {
                    // Only trigger Data event when polling is true and the Data event
                    // has not been triggered in current poll.
                    if !polling || !stream.trigger_data_event() {
                        break;
                    }
                    return Ok((stream_id, Http3Event::Data));
                }

                Http3StreamState::ReadFinished => break,

                _ => unreachable!(),
            }
        }

        Err(Http3Error::Done)
    }

    /// Process a readable HTTP/3 stream.
    ///
    /// Note that the polling parameter indicates whether the current API is called via poll.
    /// If it is not called via poll, i.e. called via recv_body, do not trigger any events.
    fn process_readable_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
        polling: bool,
    ) -> Result<(u64, Http3Event)> {
        // If the stream doesn't exist, try to create it.
        if let Err(e) = self.get_or_create(stream_id, false) {
            trace!(
                "{:?} get_or_create stream {} failed, error: {:?}",
                conn.trace_id(),
                stream_id,
                e
            );
            conn.close(true, e.to_wire(), b"")?;
            return Err(e);
        };

        match crate::stream::is_bidi(stream_id) {
            false => self.process_readable_uni_stream(conn, stream_id, polling),
            true => self.process_readable_request_stream(conn, stream_id, polling),
        }
    }

    /// Mark a request or push stream as finished, and add it to the list of finished streams.
    fn process_finished_stream(&mut self, stream_id: u64) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            if stream.state() == Http3StreamState::ReadFinished {
                return;
            }

            match stream.stream_type() {
                Some(Http3StreamType::Request) | Some(Http3StreamType::Push) => {
                    stream.mark_read_finished();
                    self.finished_streams.push_back(stream_id);
                }
                _ => (),
            };
        }
    }

    /// Check if the critical stream is in an open state.
    fn check_critical_stream_state(&mut self, conn: &mut Connection, stream_id: u64) -> Result<()> {
        // Critical streams MUST NOT be closed.
        //
        // RFC9114 6.2.1. Control Streams
        // If either control stream is closed at any point, this MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM.
        //
        // RFC9204 4.2. Encoder and Decoder Streams
        // The sender MUST NOT close either of these streams, and the receiver MUST NOT request that the sender close either of these streams.
        // Closure of either unidirectional stream type MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM.
        if conn.stream_finished(stream_id) {
            error!("{:?} critical stream {} closed", conn.trace_id(), stream_id);

            conn.close(
                true,
                Http3Error::ClosedCriticalStream.to_wire(),
                b"closed critical stream",
            )?;

            return Err(Http3Error::ClosedCriticalStream);
        }

        Ok(())
    }

    /// Process critical stream, maybe control, QPACK encoder or decoder stream.
    fn process_critical_stream(
        &mut self,
        conn: &mut Connection,
        stream_id: u64,
    ) -> Result<(u64, Http3Event)> {
        self.check_critical_stream_state(conn, stream_id)?;

        if !conn.stream_readable(stream_id) {
            return Err(Http3Error::Done);
        }

        match self.process_readable_uni_stream(conn, stream_id, true) {
            Ok(ev) => return Ok(ev),
            Err(Http3Error::Done) => (),
            Err(e) => return Err(e),
        };

        self.check_critical_stream_state(conn, stream_id)?;

        Err(Http3Error::Done)
    }

    /// Process known critical streams, including HTTP/3 control, QPACK encoder/decoder streams.
    fn process_critical_streams(&mut self, conn: &mut Connection) -> Result<(u64, Http3Event)> {
        // Note that HTTP/3 control stream should be processed first.
        for &stream_id in &[
            self.peer_control_stream_id,
            self.peer_qpack_streams.encoder_stream_id,
            self.peer_qpack_streams.decoder_stream_id,
        ] {
            if let Some(s) = stream_id {
                match self.process_critical_stream(conn, s) {
                    Ok(ev) => return Ok(ev),
                    // Everything is fine, continue.
                    Err(Http3Error::Done) => (),
                    Err(e) => return Err(e),
                }
            }
        }

        Err(Http3Error::Done)
    }

    // Process all readable HTTP/3 streams.
    fn process_readable_streams(&mut self, conn: &mut Connection) -> Result<(u64, Http3Event)> {
        for stream_id in conn.stream_readable_iter() {
            trace!("{:?} stream {} readable", conn.trace_id(), stream_id);

            let ev = match self.process_readable_stream(conn, stream_id, true) {
                Ok(v) => Some(v),
                // May have received an empty FIN.
                Err(Http3Error::Done) => None,
                // If the stream was reset, return a Reset event early, to avoid return a Finished event later.
                Err(Http3Error::TransportError(crate::Error::StreamReset(e))) => {
                    return Ok((stream_id, Http3Event::Reset(e)))
                }
                Err(e) => return Err(e),
            };

            if conn.stream_finished(stream_id) {
                trace!("{:?} stream {} finished", conn.trace_id(), stream_id);
                self.process_finished_stream(stream_id);

                // If the HTTP/3 stream has been finished for both reading and writing, we can remove it immediately.
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    if stream.write_finished() {
                        trace!("{:?} stream {} completed", conn.trace_id(), stream_id);
                        self.stream_destroy(stream_id);
                    }
                }
            }

            if let Some(ev) = ev {
                return Ok(ev);
            }
        }

        Err(Http3Error::Done)
    }

    /// Process HTTP/3 streams data and trigger events.
    ///
    /// On success, it returns a stream ID and an Http3Event, or Http3Error::Done when there
    /// are no events need to be report. On error, it returns an Http3Error.
    ///
    /// Note that all HTTP/3 events are edge-triggered, which means that applications will
    /// not receive the same event twice unless the event is re-armed.
    ///
    /// QUIC connection will be closed with the appropriate error code if an error occurs
    /// while processing HTTP/3 streams data.
    pub fn poll(&mut self, conn: &mut Connection) -> Result<(u64, Http3Event)> {
        // The underlying quic transport connection has been in a broken state, return early.
        if conn.local_error().is_some() {
            return Err(Http3Error::Done);
        }

        // Process finished HTTP/3 streams.
        if let Some(stream_id) = self.finished_streams.pop_front() {
            return Ok((stream_id, Http3Event::Finished));
        }

        // Process known critical streams, including HTTP/3 control, QPACK encoder/decoder streams.
        match self.process_critical_streams(conn) {
            Ok(ev) => return Ok(ev),
            // Everything is fine, continue.
            Err(Http3Error::Done) => (),
            Err(e) => return Err(e),
        }

        // Process all readable HTTP/3 streams.
        match self.process_readable_streams(conn) {
            Ok(ev) => return Ok(ev),
            // Everything is fine, continue.
            Err(Http3Error::Done) => (),
            Err(e) => return Err(e),
        }

        // Note that when receiving empty stream frames with the fin flag set,
        // we would not get an event from process_readable_streams, but it may
        // finished, we should return a `Finished` event.
        if let Some(stream_id) = self.finished_streams.pop_front() {
            return Ok((stream_id, Http3Event::Finished));
        }

        Err(Http3Error::Done)
    }

    /// Process internal events of all HTTP/3 streams on the connection.
    pub fn process_streams(&mut self, conn: &mut Connection) -> Result<()> {
        trace!("{:?} process streams", conn.trace_id());

        // Handler is not set, return early.
        if self.handler.is_none() {
            return Ok(());
        }

        // Note that we can not save handler before poll, otherwise the handler will be borrowed twice.
        loop {
            match self.poll(conn) {
                Ok((stream_id, Http3Event::Headers { headers, fin })) => {
                    self.handler
                        .as_ref()
                        .unwrap()
                        .on_stream_headers(stream_id, &mut Http3Event::Headers { headers, fin });
                }

                Ok((stream_id, Http3Event::Data)) => {
                    self.handler.as_ref().unwrap().on_stream_data(stream_id);
                }

                Ok((stream_id, Http3Event::Finished)) => {
                    self.handler.as_ref().unwrap().on_stream_finished(stream_id);
                }

                Ok((stream_id, Http3Event::Reset(e))) => {
                    self.handler.as_ref().unwrap().on_stream_reset(stream_id, e);
                }

                Ok((stream_id, Http3Event::PriorityUpdate)) => {
                    self.handler
                        .as_ref()
                        .unwrap()
                        .on_stream_priority_update(stream_id);
                }

                Ok((stream_id, Http3Event::GoAway)) => {
                    self.handler.as_ref().unwrap().on_conn_goaway(stream_id);
                }

                Err(Http3Error::Done) => {
                    break;
                }

                Err(e) => {
                    error!("{:?} process HTTP/3 streams error {:?}", conn.trace_id(), e);
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

/// An HTTP/3 settings.
struct Http3Settings {
    pub max_field_section_size: Option<u64>,
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
    pub connect_protocol_enabled: Option<u64>,
    pub raw: Option<Vec<(u64, u64)>>,
}

/// An endpoint's QPACK streams.
struct QpackStreams {
    pub encoder_stream_id: Option<u64>,
    pub decoder_stream_id: Option<u64>,
}

/// An extensible HTTP/3 Priority Parameters
#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Http3Priority {
    pub urgency: u8,
    pub incremental: bool,
}

impl Default for Http3Priority {
    /// Create a new Http3Priority with default urgency and incremental.
    fn default() -> Self {
        Http3Priority {
            urgency: PRIORITY_URGENCY_DEFAULT,
            incremental: PRIORITY_INCREMENTAL_DEFAULT,
        }
    }
}

impl Http3Priority {
    /// Create a new Http3Priority with the given urgency and incremental.
    pub const fn new(urgency: u8, incremental: bool) -> Self {
        Http3Priority {
            urgency,
            incremental,
        }
    }

    /// HTTP/3 priority urgency subject to protocol bound.
    fn subject_to_bound(&self) -> u8 {
        self.urgency
            .clamp(PRIORITY_URGENCY_LOWER_BOUND, PRIORITY_URGENCY_UPPER_BOUND)
    }

    /// Map HTTP/3 urgency to QUIC urgency.
    fn map_to_quic(&self) -> u8 {
        self.subject_to_bound() + PRIORITY_URGENCY_OFFSET
    }
}

impl TryFrom<&[u8]> for Http3Priority {
    type Error = crate::h3::Http3Error;

    /// Try to parse an Priority field value, which was encoded as a Dictionary.
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let dict = match sfv::Parser::parse_dictionary(value) {
            Ok(v) => v,
            Err(_) => return Err(Http3Error::Done),
        };

        let urgency = match dict.get("u") {
            Some(sfv::ListEntry::Item(item)) => match item.bare_item.as_int() {
                Some(v) => {
                    if (PRIORITY_URGENCY_LOWER_BOUND as i64..=PRIORITY_URGENCY_UPPER_BOUND as i64)
                        .contains(&v)
                    {
                        v as u8
                    } else {
                        PRIORITY_URGENCY_UPPER_BOUND
                    }
                }

                None => return Err(Http3Error::Done),
            },

            // Priority urgency must be an Integer, but not a List.
            Some(sfv::ListEntry::InnerList(_)) => return Err(Http3Error::Done),

            // Priority urgency parameter not found, use default value.
            None => PRIORITY_URGENCY_DEFAULT,
        };

        let incremental = match dict.get("i") {
            // Priority incremental must be a Boolean.
            Some(sfv::ListEntry::Item(item)) => item.bare_item.as_bool().ok_or(Http3Error::Done)?,

            // Priority incremental must be an Boolean, but not a List.
            Some(sfv::ListEntry::InnerList(_)) => return Err(Http3Error::Done),

            // Priority incremental parameter not found, use default value.
            None => PRIORITY_INCREMENTAL_DEFAULT,
        };

        Ok(Http3Priority::new(urgency, incremental))
    }
}

#[doc(hidden)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection;
    use crate::Config;
    use crate::Error;
    use crate::TlsConfig;
    use bytes::Buf;

    pub struct Session {
        pub pair: connection::tests::TestPair,
        pub client: Http3Connection,
        pub server: Http3Connection,
    }

    impl Session {
        /// Create a new HTTP/3 session.
        fn new() -> Result<Session> {
            let mut client_config = Session::new_test_config(false).unwrap();
            let mut server_config = Session::new_test_config(true).unwrap();

            let h3_config: Http3Config = Http3Config::new()?;

            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
        }

        /// Create a new HTTP/3 session with custom config.
        fn new_with_test_config(
            client_config: &mut Config,
            server_config: &mut Config,
            h3_config: &Http3Config,
        ) -> Result<Session> {
            // Create underlying QUIC connection pair.
            let mut pair = connection::tests::TestPair::new(client_config, server_config)?;

            // Establish QUIC session.
            pair.handshake()?;

            // Create HTTP/3 connection pair with underlying QUIC connection pair.
            let (client, server) = Session::http3_conn_pair_new(&mut pair, h3_config)?;

            Ok(Session {
                pair,
                client,
                server,
            })
        }

        /// Create default test config for HTTP/3
        fn new_test_config(is_server: bool) -> Result<Config> {
            let mut conf = Config::new()?;
            conf.set_initial_max_data(1500);
            conf.set_initial_max_stream_data_bidi_local(150);
            conf.set_initial_max_stream_data_bidi_remote(150);
            conf.set_initial_max_stream_data_uni(150);
            conf.set_initial_max_streams_bidi(5);
            conf.set_initial_max_streams_uni(5);
            conf.set_max_connection_window(1024 * 1024 * 3);
            conf.set_max_stream_window(1024 * 1024 * 1);
            conf.set_max_concurrent_conns(100);
            conf.enable_pacing(false);

            let application_protos = vec![b"h3".to_vec()];
            let tls_config = if !is_server {
                TlsConfig::new_client_config(application_protos, true)?
            } else {
                let mut tls_config = TlsConfig::new_server_config(
                    "src/tls/testdata/cert.crt",
                    "src/tls/testdata/cert.key",
                    application_protos,
                    true,
                )?;
                tls_config.set_ticket_key(&vec![0x73; 48])?;
                tls_config
            };
            conf.set_tls_config(tls_config);

            Ok(conf)
        }

        /// Create new HTTP/3 connection pair with underlying QUIC connection pair.
        fn http3_conn_pair_new(
            pair: &mut connection::tests::TestPair,
            config: &Http3Config,
        ) -> Result<(Http3Connection, Http3Connection)> {
            let mut client = Http3Connection::new_with_quic_conn(&mut pair.client, config)?;
            let mut server = Http3Connection::new_with_quic_conn(&mut pair.server, config)?;

            pair.move_forward().ok();

            // Promote the HTTP/3 connections go forward, and process data from the peer on critical streams.
            while client.poll(&mut pair.client).is_ok() {
                // There are no events that require handling by the upper layer application now.
            }
            while server.poll(&mut pair.server).is_ok() {
                // There are no events that require handling by the upper layer application now.
            }

            Ok((client, server))
        }

        /// Promote HTTP/3 pairs go forward.
        fn move_forward(&mut self) -> crate::Result<()> {
            self.pair.move_forward()
        }

        fn client_poll(&mut self) -> Result<(u64, Http3Event)> {
            self.client.poll(&mut self.pair.client)
        }

        fn server_poll(&mut self) -> Result<(u64, Http3Event)> {
            self.server.poll(&mut self.pair.server)
        }

        /// Construct a default request headers list.
        fn default_request_headers() -> Vec<Header> {
            vec![
                Header::new(b":method", b"GET"),
                Header::new(b":scheme", b"https"),
                Header::new(b":authority", b"example.org"),
                Header::new(b":path", b"/quic.html"),
                Header::new(b"user-agent", b"quicent"),
                Header::new(b"author", b"geek"),
            ]
        }

        /// Construct a default response headers list.
        fn default_response_headers() -> Vec<Header> {
            vec![
                Header::new(b":status", b"200"),
                Header::new(b"server", b"quicent"),
            ]
        }

        /// Calculate one HEADERS frame, which contains the given headers, size.
        fn calculate_headers_frame_size<T: NameValue>(
            h3_conn: &mut Http3Connection,
            headers: &[T],
        ) -> Result<usize> {
            let mut d = [0; 10];
            let mut b = &mut d[..];

            let header_block = h3_conn.encode_header_fields(&headers).unwrap();

            let header_block_len = header_block.len();
            let mut frame_header_len = b.write_varint(frame::HEADERS_FRAME_TYPE)?;
            frame_header_len += b.write_varint(header_block_len as u64)?;

            Ok(frame_header_len + header_block_len)
        }

        /// Client send a new request with default headers.
        ///
        /// Return stream_id and the headers list on success.
        pub fn send_request(&mut self, fin: bool) -> Result<(u64, Vec<Header>)> {
            let req_headers = Session::default_request_headers();

            // Create a new HTTP/3 request stream.
            let stream_id = self.client.stream_new(&mut self.pair.client)?;
            // Write request headers to the quic transport stream buffer.
            self.client
                .send_headers(&mut self.pair.client, stream_id, &req_headers, fin)?;

            // Wrap the request headers into a HEADERS frame and send it to the server.
            self.move_forward().ok();

            Ok((stream_id, req_headers))
        }

        /// Client create a new request stream and send the given headers.
        /// Return stream_id on success.
        pub fn send_request_with_custom_headers<T: NameValue>(
            &mut self,
            headers: &[T],
            fin: bool,
        ) -> Result<u64> {
            // Create a new HTTP/3 request stream.
            let stream_id = self.client.stream_new(&mut self.pair.client)?;
            // Write request headers to the quic transport stream buffer.
            self.client
                .send_headers(&mut self.pair.client, stream_id, headers, fin)?;

            // Wrap the request headers into a HEADERS frame and send it to the server.
            self.move_forward().ok();

            Ok(stream_id)
        }

        /// Server send a response for the given stream with default headers.
        ///
        /// Return the headers list on success.
        pub fn send_response(&mut self, stream_id: u64, fin: bool) -> Result<Vec<Header>> {
            let resp_headers = Session::default_response_headers();

            // Set stream priority.
            // This is unnecessary, but we do it for testing.
            self.server.stream_set_priority(
                &mut self.pair.server,
                stream_id,
                &Http3Priority::default(),
            )?;

            // Write response headers to the quic transport stream buffer.
            self.server
                .send_headers(&mut self.pair.server, stream_id, &resp_headers, fin)?;

            // Wrap the response headers into a HEADERS frame and send it to the client.
            self.move_forward().ok();

            Ok(resp_headers)
        }

        /// Client send default body to server.
        ///
        /// Return the body on success.
        pub fn client_send_body(&mut self, stream: u64, fin: bool) -> Result<Bytes> {
            let mut body = Bytes::from("Quic Century");

            // Write body to the quic transport stream buffer.
            let sent = self
                .client
                .send_body(&mut self.pair.client, stream, body.clone(), fin)?;

            // Wrap the body into a DATA frame and send it to the server.
            self.move_forward().ok();

            body.truncate(sent);
            Ok(body)
        }

        /// Client receive body from the server.
        ///
        /// Return the number of bytes received on success.
        pub fn client_recv_body(&mut self, stream: u64, buf: &mut [u8]) -> Result<usize> {
            self.client.recv_body(&mut self.pair.client, stream, buf)
        }

        /// Server send default body to client.
        ///
        /// Return the body on success.
        pub fn server_send_body(&mut self, stream: u64, fin: bool) -> Result<Bytes> {
            let mut body = Bytes::from("WeQuicTogether");

            // Write body to the quic transport stream buffer.
            let sent = self
                .server
                .send_body(&mut self.pair.server, stream, body.clone(), fin)?;

            // Wrap the body into a DATA frame and send it to the client.
            self.move_forward().ok();

            body.truncate(sent);
            Ok(body)
        }

        /// Server receive request body from the client.
        ///
        /// Return the number of bytes received on success.
        pub fn server_recv_body(&mut self, stream: u64, buf: &mut [u8]) -> Result<usize> {
            self.server.recv_body(&mut self.pair.server, stream, buf)
        }

        /// Client send a single HTTP/3 frame to server.
        pub fn client_send_frame(
            &mut self,
            stream_id: u64,
            frame: frame::Http3Frame,
            fin: bool,
        ) -> Result<()> {
            let mut bytes = BytesMut::zeroed(65535);
            let len = frame.encode(bytes.as_mut()).unwrap();
            bytes.truncate(len);

            self.pair
                .client
                .stream_write(stream_id, bytes.freeze(), fin)?;

            self.move_forward().ok();

            Ok(())
        }

        /// Server send a single HTTP/3 frame to client.
        pub fn server_send_frame(
            &mut self,
            stream_id: u64,
            frame: frame::Http3Frame,
            fin: bool,
        ) -> Result<()> {
            let mut bytes = BytesMut::zeroed(65535);
            let len = frame.encode(bytes.as_mut()).unwrap();
            bytes.truncate(len);

            self.pair
                .server
                .stream_write(stream_id, bytes.freeze(), fin)?;

            self.move_forward().ok();

            Ok(())
        }

        /// Client send the given data to the server on the given stream.
        pub fn client_send_custom_stream_data(
            &mut self,
            stream_id: u64,
            data: Bytes,
            fin: bool,
        ) -> Result<()> {
            self.pair.client.stream_write(stream_id, data, fin)?;

            self.move_forward().ok();

            Ok(())
        }

        /// Server send the given data to the client on the given stream.
        pub fn server_send_custom_stream_data(
            &mut self,
            stream_id: u64,
            data: Bytes,
            fin: bool,
        ) -> Result<()> {
            self.pair.server.stream_write(stream_id, data, fin)?;

            self.move_forward().ok();

            Ok(())
        }
    }

    struct TestHttp3Handler {
        headers: Option<Http3Event>,
        data: Option<Bytes>,
    }

    impl Http3Handler for TestHttp3Handler {
        fn on_stream_headers(&self, stream_id: u64, ev: &mut Http3Event) {
            trace!("on_stream_headers stream_id={}", stream_id);

            match ev {
                Http3Event::Headers { headers, .. } => {
                    for h in headers {
                        trace!("{} recv header: {:?}", stream_id, h);
                    }

                    assert_eq!(ev, &self.headers.clone().unwrap());
                }

                _ => unreachable!(),
            }
        }

        fn on_stream_data(&self, stream_id: u64) {
            trace!("on_stream_data stream_id={}", stream_id);
        }

        fn on_stream_finished(&self, stream_id: u64) {
            trace!("on_stream_finished stream_id={}", stream_id);
        }

        fn on_stream_reset(&self, stream_id: u64, error_code: u64) {
            trace!(
                "on_stream_reset stream_id={}, error_code={}",
                stream_id,
                error_code
            );
        }

        fn on_stream_priority_update(&self, stream_id: u64) {
            trace!("on_stream_priority_update stream_id={}", stream_id);
        }

        fn on_conn_goaway(&self, stream_id: u64) {
            trace!("on_conn_goaway stream_id={}", stream_id);
        }
    }

    #[test]
    fn http3_conn_new() {
        let h3_config = Http3Config::new().unwrap();
        let h3_client = Http3Connection::new(&h3_config, false).unwrap();
        let h3_server = Http3Connection::new(&h3_config, true).unwrap();

        assert_eq!(h3_client.next_uni_stream_id, 2);
        assert_eq!(h3_client.next_request_stream_id, 0);
        assert_eq!(h3_client.max_push_id, None);

        assert_eq!(h3_server.next_uni_stream_id, 3);
    }

    #[test]
    fn http3_client_create_conn_early() {
        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();

        // Create underlying QUIC connection pair.
        let mut pair =
            connection::tests::TestPair::new(&mut client_config, &mut server_config).unwrap();
        let h3_config = Http3Config::new().unwrap();

        // Client try to create HTTP/3 connection before QUIC handshake, and it should fail.
        assert_eq!(
            Http3Connection::new_with_quic_conn(&mut pair.client, &h3_config).err(),
            Some(Http3Error::InternalError)
        );

        // Establish QUIC session.
        pair.handshake().unwrap();

        // Client create HTTP/3 connection after QUIC handshake, and it should succeed.
        assert!(Http3Connection::new_with_quic_conn(&mut pair.client, &h3_config).is_ok());
    }

    #[test]
    fn get_or_create() {
        let h3_config = Http3Config::new().unwrap();
        let mut h3_conn = Http3Connection::new(&h3_config, false).unwrap();

        let stream = h3_conn.get_or_create(0, true).unwrap();
        assert!(!stream.priority_initialized());

        // Client found a server-initiated bidirectional stream.
        assert_eq!(
            h3_conn.get_or_create(4, false).err(),
            Some(Http3Error::StreamCreationError)
        );
    }

    #[test]
    fn update_next_stream_id() {
        let h3_config = Http3Config::new().unwrap();
        let mut h3_client = Http3Connection::new(&h3_config, false).unwrap();
        let mut h3_server = Http3Connection::new(&h3_config, true).unwrap();

        // Client
        assert_eq!(h3_client.next_request_stream_id, 0);
        assert_eq!(h3_client.next_uni_stream_id, 2);

        assert!(h3_client.update_next_request_stream_id().is_ok());
        h3_client.next_request_stream_id = (1 << 62) - 4;
        assert!(h3_client.update_next_request_stream_id().is_ok());
        assert_eq!(h3_client.next_request_stream_id, 1 << 62);
        assert_eq!(
            h3_client.update_next_request_stream_id(),
            Err(Http3Error::IdError)
        );

        assert!(h3_client.update_next_uni_stream_id().is_ok());
        h3_client.next_uni_stream_id = (1 << 62) - 2;
        assert!(h3_client.update_next_uni_stream_id().is_ok());
        assert_eq!(h3_client.next_uni_stream_id, (1 << 62) + 2);
        assert_eq!(
            h3_client.update_next_uni_stream_id(),
            Err(Http3Error::IdError)
        );

        // Server
        assert_eq!(h3_server.next_uni_stream_id, 3);
        assert!(h3_server.update_next_uni_stream_id().is_ok());
        h3_server.next_uni_stream_id = (1 << 62) - 1;
        assert!(h3_server.update_next_uni_stream_id().is_ok());
        assert_eq!(h3_server.next_uni_stream_id, (1 << 62) + 3);
        assert_eq!(
            h3_server.update_next_uni_stream_id(),
            Err(Http3Error::IdError)
        );
    }

    // Client send a request without body, and get a response without body from server.
    #[test]
    fn request_and_response_without_body() {
        let mut s = Session::new().unwrap();

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // Server receive the request headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server send a response without body.
        let resp_headers = s.send_response(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send a request without body, get a response with one data frame from server.
    #[test]
    fn request_without_body_response_one_data_frame() {
        let mut s = Session::new().unwrap();

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // Server receive the request headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server send response headers without final flag.
        let resp_headers = s.send_response(stream_id, false).unwrap();
        // Server send one data block with final flag.
        let body = s.server_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        // Client detect headers event and receive response headers.
        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));

        // Client detect data event and receive response body.
        let mut recv_buf = vec![0; body.len()];
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(s.client_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
        assert_eq!(recv_buf, body);

        // Client detect the end of the response.
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    /// Client send a request without body, get a response with multiple data frame from server.
    #[test]
    fn request_without_body_and_response_multi_data_frames() {
        let mut s = Session::new().unwrap();

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server send response headers without final flag.
        let resp_headers = s.send_response(stream_id, false).unwrap();

        let total_data_frames = 5;
        // Server send multiple data block without final flag.
        for _ in 0..total_data_frames - 1 {
            s.server_send_body(stream_id, false).unwrap();
        }

        // Server send one data block with final flag.
        let body = s.server_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        let mut recv_buf = vec![0; body.len()];
        for _ in 0..total_data_frames {
            assert_eq!(s.client_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
            assert_eq!(recv_buf, body);
        }

        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send a request with one DATA frame, get a response without body.
    #[test]
    fn request_with_one_data_frame_response_without_body() {
        let mut s = Session::new().unwrap();

        // Client send request headers without final flag.
        let (stream_id, req_headers) = s.send_request(false).unwrap();
        // Client send one data block with final flag.
        let body = s.client_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        let mut recv_buf = vec![0; body.len()];
        // Server receive request headers and data.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(s.server_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
        assert_eq!(recv_buf, body);
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server send a response without body.
        let resp_headers = s.send_response(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
    }

    // Client send a request with one DATA frame, get a response with one DATA frame.
    #[test]
    fn request_with_one_data_frame_response_with_one_data_frame() {
        let mut s = Session::new().unwrap();

        // Client send request headers without final flag.
        let (stream_id, req_headers) = s.send_request(false).unwrap();
        // Client send one data block with final flag.
        let req_body = s.client_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        let mut recv_buf = vec![0; req_body.len()];
        // Server receive request headers and data.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(
            s.server_recv_body(stream_id, &mut recv_buf),
            Ok(req_body.len())
        );
        assert_eq!(recv_buf, req_body);
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server send a response without final flag.
        let resp_headers = s.send_response(stream_id, false).unwrap();
        // Server send one data block with final flag.
        let resp_body = s.server_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Data)));

        let mut recv_buf = vec![0; resp_body.len()];
        assert_eq!(
            s.client_recv_body(stream_id, &mut recv_buf),
            Ok(resp_body.len())
        );
        assert_eq!(recv_buf, resp_body);

        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send a request with multiple DATA frames, get a response without body.
    #[test]
    fn request_with_multi_data_frames_response_without_body() {
        let mut s = Session::new().unwrap();

        // Client send request headers without final flag.
        let (stream_id, req_headers) = s.send_request(false).unwrap();

        let total_data_frames = 5;
        // Client send multiple data block without final flag.
        for _ in 0..total_data_frames - 1 {
            s.client_send_body(stream_id, false).unwrap();
        }

        // Client send one data block with final flag.
        let body = s.client_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        let mut recv_buf = vec![0; body.len()];
        // Server recv body cross multiple DATA frames.
        for _ in 0..total_data_frames {
            assert_eq!(s.server_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
            assert_eq!(recv_buf, body);
        }

        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server send a response without body.
        let resp_headers = s.send_response(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
    }

    // Client send a request with multiple DATA frames, get a response with multiple DATA frames.
    #[test]
    fn request_with_multi_data_frames_response_with_multi_data_frames() {
        let mut s = Session::new().unwrap();

        let total_data_frames = 5;

        // Client send request headers without final flag.
        let (stream_id, req_headers) = s.send_request(false).unwrap();

        // Client send multiple data block without final flag.
        for _ in 0..total_data_frames - 1 {
            s.client_send_body(stream_id, false).unwrap();
        }

        // Client send one data block with final flag.
        let body = s.client_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        // Server get request headers and data events.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        let mut recv_buf = vec![0; body.len()];
        // Server recv body cross multiple DATA frames.
        for _ in 0..total_data_frames {
            assert_eq!(s.server_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
            assert_eq!(recv_buf, body);
        }

        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server send response headers without final flag.
        let resp_headers = s.send_response(stream_id, false).unwrap();

        // Server send multiple data block without final flag.
        for _ in 0..total_data_frames - 1 {
            s.server_send_body(stream_id, false).unwrap();
        }

        // Server send one data block with final flag.
        let body = s.server_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        let mut recv_buf = vec![0; body.len()];
        for _ in 0..total_data_frames {
            assert_eq!(s.client_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
            assert_eq!(recv_buf, body);
        }

        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send multi requests with multi DATA frames, get responses with multi DATA frames.
    #[test]
    fn multi_requests_with_multi_data_frames_and_response_multi_data_frames() {
        let mut s = Session::new().unwrap();

        let total_requests = 5;

        let mut reqs = Vec::new();

        // Client send multiple requests headers without final flag.
        for i in 0..total_requests {
            let (stream_id, req) = s.send_request(false).unwrap();
            assert_eq!(stream_id, i * 4);
            reqs.push(req);
        }

        // Client send one data block without final flag for all requests in order.
        let req_body = s.client_send_body(0, false).unwrap();
        for i in 1..total_requests {
            s.client_send_body(i * 4, false).unwrap();
        }

        // Client send one data block with final flag for all requests in reverse order.
        for i in (0..total_requests).rev() {
            s.client_send_body(i * 4, true).unwrap();
        }

        let mut recv_buf = vec![0; req_body.len()];

        for _ in 0..reqs.len() {
            let (stream_id, ev) = s.server_poll().unwrap();
            let headers_event = Http3Event::Headers {
                headers: reqs[(stream_id / 4) as usize].clone(),
                fin: false,
            };
            assert_eq!(ev, headers_event);
            assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
            assert_eq!(
                s.server_recv_body(stream_id, &mut recv_buf),
                Ok(req_body.len())
            );
            assert_eq!(recv_buf, req_body);
            assert_eq!(s.client_poll(), Err(Http3Error::Done));

            assert_eq!(
                s.server_recv_body(stream_id, &mut recv_buf),
                Ok(req_body.len())
            );
            assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        }

        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        let mut resps = Vec::new();

        // Server send response headers without final flag for all requests in order.
        for i in 0..total_requests {
            let resp = s.send_response(i * 4, false).unwrap();
            resps.push(resp);
        }

        // Server send one data block without final flag for all requests in order.
        let resp_body = s.server_send_body(0, false).unwrap();
        for i in 1..total_requests {
            s.server_send_body(i * 4, false).unwrap();
        }

        // Server send one data block with final flag for all requests in reverse order.
        for i in (0..total_requests).rev() {
            s.server_send_body(i * 4, true).unwrap();
        }

        let mut recv_buf = vec![0; resp_body.len()];

        for _ in 0..resps.len() {
            let (stream_id, ev) = s.client_poll().unwrap();
            let headers_event = Http3Event::Headers {
                headers: resps[(stream_id / 4) as usize].clone(),
                fin: false,
            };
            assert_eq!(ev, headers_event);

            assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Data)));
            assert_eq!(
                s.client_recv_body(stream_id, &mut recv_buf),
                Ok(resp_body.len())
            );
            assert_eq!(recv_buf, resp_body);
            assert_eq!(s.server_poll(), Err(Http3Error::Done));

            assert_eq!(
                s.client_recv_body(stream_id, &mut recv_buf),
                Ok(resp_body.len())
            );
            assert_eq!(recv_buf, resp_body);
            assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        }

        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send a request without body, get a response with one DATA frame
    // and an empty FIN after reception from the server.
    #[test]
    fn request_without_body_response_one_data_frame_and_an_empty_fin() {
        let mut s = Session::new().unwrap();

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server send response headers without final flag.
        let resp_headers = s.send_response(stream_id, false).unwrap();
        // Server send one data block without final flag.
        let body = s.server_send_body(stream_id, false).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        let mut recv_buf = vec![0; body.len()];
        // Client get response headers and data.
        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(s.client_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
        assert_eq!(recv_buf, body);

        // Server write empty data block with final flag to quic transport stream buffer.
        assert_eq!(
            s.pair.server.stream_write(stream_id, Bytes::new(), true),
            Ok(0)
        );
        // Server send empty DATA frame with final flag.
        s.move_forward().ok();

        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client and server send body with empty data block with or without FIN flag.
    #[test]
    fn send_body_with_empty_data_block() {
        let mut s = Session::new().unwrap();

        // Client send request headers without FIN.
        let (stream_id, req_headers) = s.send_request(false).unwrap();
        assert_eq!(stream_id, 0);

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        // Client send empty data block without FIN.
        assert_eq!(
            s.client
                .send_body(&mut s.pair.client, stream_id, Bytes::new(), false),
            Err(Http3Error::Done)
        );
        // Client send empty data block with FIN.
        assert_eq!(
            s.client
                .send_body(&mut s.pair.client, stream_id, Bytes::new(), true),
            Ok(0)
        );

        s.move_forward().unwrap();

        let mut recv_buf = vec![0; 10];

        // Server receive request headers without FIN.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        // Server receive empty data block without FIN.
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(
            s.server_recv_body(stream_id, &mut recv_buf),
            Err(Http3Error::Done)
        );
        // Server read FIN.
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response headers without FIN.
        let resp_headers = s.send_response(stream_id, false).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        // Server send empty data block without FIN.
        assert_eq!(
            s.server
                .send_body(&mut s.pair.server, stream_id, Bytes::new(), false),
            Err(Http3Error::Done)
        );
        // Client send empty data block with FIN.
        assert_eq!(
            s.server
                .send_body(&mut s.pair.server, stream_id, Bytes::new(), true),
            Ok(0)
        );

        s.move_forward().unwrap();

        // Client receive response headers without FIN.
        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        // Client receive empty data block without FIN.
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(
            s.client_recv_body(stream_id, &mut recv_buf),
            Err(Http3Error::Done)
        );
        // Client read FIN.
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send request blocked by connection flow control.
    #[test]
    fn client_send_request_blocked_by_conn_flow_control() {
        // For convenience, we create an h3 connection to calculate the default HEADERS frame size.
        let h3_config = Http3Config::new().unwrap();
        let mut h3_client = Http3Connection::new(&h3_config, false).unwrap();

        let req_headers = Session::default_request_headers();
        let headers_frame_size =
            Session::calculate_headers_frame_size(&mut h3_client, &req_headers).unwrap();
        assert_eq!(headers_frame_size, 44);

        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        server_config.set_initial_max_data(2 * headers_frame_size as u64 - 1);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        // 1. Client send the first request headers with FIN.
        assert_eq!(
            s.send_request_with_custom_headers(&req_headers, true),
            Ok(0)
        );

        // 2. Client send the second request headers with FIN, but blocked by connection flow control.
        assert_eq!(
            s.send_request_with_custom_headers(&req_headers, true),
            Err(Http3Error::StreamBlocked)
        );

        // 3. Server receive request headers, and it will send MAX_DATA frame to client.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: true,
        };
        assert_eq!(s.server_poll(), Ok((0, headers_event)));
        assert_eq!(s.server_poll(), Ok((0, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        s.move_forward().unwrap();

        // 4. Client try to send the second request headers again, it should success(NoError).
        assert_eq!(
            s.client
                .send_body(&mut s.pair.client, 4, Bytes::new(), true),
            Err(Http3Error::NoError)
        );

        s.move_forward().unwrap();

        // 5. Server receive request headers with FIN.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: true,
        };
        assert_eq!(s.server_poll(), Ok((4, headers_event)));
        assert_eq!(s.server_poll(), Ok((4, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // 6. Server send response headers with FIN for stream 0.
        let resp_headers = s.send_response(0, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((0, headers_event)));
        assert_eq!(s.client_poll(), Ok((0, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        // 7. Server send response headers with FIN for stream 4.
        let resp_headers = s.send_response(4, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((4, headers_event)));
        assert_eq!(s.client_poll(), Ok((4, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send multiple requests blocked by connection flow control.
    #[test]
    fn client_send_multi_requests_blocked_by_conn_flow_control() {
        // For convenience, we create an h3 connection to calculate the default HEADERS frame size.
        let h3_config = Http3Config::new().unwrap();
        let mut h3_client = Http3Connection::new(&h3_config, false).unwrap();

        let req_headers = Session::default_request_headers();
        let headers_frame_size =
            Session::calculate_headers_frame_size(&mut h3_client, &req_headers).unwrap();
        assert_eq!(headers_frame_size, 44);

        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        server_config.set_initial_max_data(2 * headers_frame_size as u64 - 1);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        // 1. Client send request headers with FIN for stream 0, 4, 8 successively.
        // The second and the third request will be blocked by connection flow control.
        for (_stream_id, err) in [
            (0, Ok(0)),
            (4, Err(Http3Error::StreamBlocked)),
            (8, Err(Http3Error::StreamBlocked)),
        ] {
            assert_eq!(s.send_request_with_custom_headers(&req_headers, true), err);
        }

        // 2. Server receive request headers, and it will send MAX_DATA frame to client.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: true,
        };
        assert_eq!(s.server_poll(), Ok((0, headers_event)));
        assert_eq!(s.server_poll(), Ok((0, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        s.move_forward().unwrap();

        // 3. Client try to send request headers for stream 8, 4(reverse order) again, it should success(NoError).
        for stream_id in [8, 4] {
            // Client send empty data block with FIN to trigger sending request headers.
            assert_eq!(
                s.client
                    .send_body(&mut s.pair.client, stream_id, Bytes::new(), true),
                Err(Http3Error::NoError)
            );

            s.move_forward().unwrap();

            // Server receive request headers with FIN.
            let headers_event = Http3Event::Headers {
                headers: req_headers.clone(),
                fin: true,
            };

            assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
            assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
            assert_eq!(s.server_poll(), Err(Http3Error::Done));

            // Server send MAX_DATA
            s.move_forward().unwrap();
        }

        // 4. Server send response headers with FIN for stream 0, 4, 8.
        for stream_id in [0, 4, 8] {
            let resp_headers = s.send_response(stream_id, true).unwrap();
            let headers_event = Http3Event::Headers {
                headers: resp_headers,
                fin: true,
            };
            assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
            assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
            assert_eq!(s.client_poll(), Err(Http3Error::Done));
        }
    }

    // Client send request blocked by connection flow control, and the application
    // try to send request headers again use h3 api(send_headers).
    // In this case, we should ensure that the previous encoded header_block will be freed.
    #[test]
    fn client_send_request_blocked_by_conn_flow_control_and_try_by_send_headers() {
        // For convenience, we create an h3 connection to calculate the default HEADERS frame size.
        let h3_config = Http3Config::new().unwrap();
        let mut h3_client = Http3Connection::new(&h3_config, false).unwrap();

        let req_headers = Session::default_request_headers();
        let headers_frame_size =
            Session::calculate_headers_frame_size(&mut h3_client, &req_headers).unwrap();
        assert_eq!(headers_frame_size, 44);

        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        server_config.set_initial_max_data(2 * headers_frame_size as u64 - 1);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        // 1. Client send the first request headers with FIN.
        assert_eq!(
            s.send_request_with_custom_headers(&req_headers, true),
            Ok(0)
        );

        // 2. Client send the second request headers with FIN, but blocked by connection flow control.
        assert_eq!(
            s.send_request_with_custom_headers(&req_headers, true),
            Err(Http3Error::StreamBlocked)
        );

        // 3. Server receive request headers, and it will send MAX_DATA frame to client.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: true,
        };
        assert_eq!(s.server_poll(), Ok((0, headers_event)));
        assert_eq!(s.server_poll(), Ok((0, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        s.move_forward().unwrap();

        // 4. Client try to send the second request headers again, it should success(NoError).
        s.client
            .send_headers(&mut s.pair.client, 4, &req_headers, true)
            .unwrap();
        assert_eq!(
            s.client.streams.get_mut(&4).unwrap().has_header_block(),
            false
        );

        s.move_forward().unwrap();

        // 5. Server receive request headers with FIN.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: true,
        };
        assert_eq!(s.server_poll(), Ok((4, headers_event)));
        assert_eq!(s.server_poll(), Ok((4, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // 6. Server send response headers with FIN for stream 0.
        let resp_headers = s.send_response(0, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((0, headers_event)));
        assert_eq!(s.client_poll(), Ok((0, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        // 7. Server send response headers with FIN for stream 4.
        let resp_headers = s.send_response(4, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((4, headers_event)));
        assert_eq!(s.client_poll(), Ok((4, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send request with empty fin blocked by connection flow control.
    #[test]
    fn client_send_request_and_empty_fin_blocked_by_conn_flow_control() {
        // For convenience, we create an h3 connection to calculate the default HEADERS frame size.
        let h3_config = Http3Config::new().unwrap();
        let mut h3_client = Http3Connection::new(&h3_config, false).unwrap();

        let req_headers = Session::default_request_headers();
        let headers_frame_size =
            Session::calculate_headers_frame_size(&mut h3_client, &req_headers).unwrap();
        assert_eq!(headers_frame_size, 44);

        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        server_config.set_initial_max_data(2 * headers_frame_size as u64 - 1);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        // 1. Client send the first request headers with FIN.
        assert_eq!(
            s.send_request_with_custom_headers(&req_headers, true),
            Ok(0)
        );

        // 2. Client send the second request headers without FIN, but blocked by connection flow control.
        assert_eq!(
            s.send_request_with_custom_headers(&req_headers, false),
            Err(Http3Error::StreamBlocked)
        );
        // 3. Client send empty data block with FIN, but blocked by connection flow control.
        // Note that the h3 api will merge the FIN flag to the previous header block.
        assert_eq!(
            s.client
                .send_body(&mut s.pair.client, 4, Bytes::new(), true),
            Err(Http3Error::StreamBlocked)
        );

        s.move_forward().unwrap();

        // 4. Server receive request headers, and it will send MAX_DATA frame to client.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: true,
        };
        assert_eq!(s.server_poll(), Ok((0, headers_event)));
        assert_eq!(s.server_poll(), Ok((0, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        s.move_forward().unwrap();

        // 5. Client try to send the second request headers again, it should success(NoError).
        assert_eq!(
            s.client
                .send_body(&mut s.pair.client, 4, Bytes::new(), true),
            Err(Http3Error::NoError)
        );

        s.move_forward().unwrap();

        // 6. Server receive request headers with FIN.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: true,
        };
        assert_eq!(s.server_poll(), Ok((4, headers_event)));
        assert_eq!(s.server_poll(), Ok((4, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // 7. Server send response headers with FIN.
        let resp_headers = s.send_response(0, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((0, headers_event)));
        assert_eq!(s.client_poll(), Ok((0, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
        let resp_headers = s.send_response(4, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((4, headers_event)));
        assert_eq!(s.client_poll(), Ok((4, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send request with body blocked by connection flow control.
    #[test]
    fn client_send_request_with_body_blocked_by_conn_flow_control() {
        // For convenience, we create an h3 connection to calculate the default HEADERS frame size.
        let h3_config = Http3Config::new().unwrap();
        let mut h3_client = Http3Connection::new(&h3_config, false).unwrap();

        let req_headers = Session::default_request_headers();
        let headers_frame_size =
            Session::calculate_headers_frame_size(&mut h3_client, &req_headers).unwrap();
        assert_eq!(headers_frame_size, 44);

        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        server_config.set_initial_max_data(2 * headers_frame_size as u64 - 1);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        // 1. Client send the first request headers with FIN.
        assert_eq!(
            s.send_request_with_custom_headers(&req_headers, true),
            Ok(0)
        );

        // 2. Client send the second request headers without FIN, but blocked by connection flow control.
        assert_eq!(
            s.send_request_with_custom_headers(&req_headers, false),
            Err(Http3Error::StreamBlocked)
        );
        assert_eq!(s.client_send_body(4, true), Err(Http3Error::StreamBlocked));

        // 3. Server receive request headers, and it will send MAX_DATA frame to client.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: true,
        };
        assert_eq!(s.server_poll(), Ok((0, headers_event)));
        assert_eq!(s.server_poll(), Ok((0, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        s.move_forward().unwrap();

        // 4. Client try to send the second request headers again, it should success(NoError).
        // Note that the body would not be sent out here.
        assert_eq!(s.client_send_body(4, true), Err(Http3Error::NoError));

        s.move_forward().unwrap();

        // 5. Server receive request headers with FIN.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: false,
        };
        assert_eq!(s.server_poll(), Ok((4, headers_event)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // 6. Client send the second request body with FIN.
        let body = s.client_send_body(4, true).unwrap();
        assert_eq!(s.server_poll(), Ok((4, Http3Event::Data)));
        let mut recv_buf = vec![0; body.len() + 10];
        assert_eq!(s.server_recv_body(4, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.server_poll(), Ok((4, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // 7. Server send response headers with FIN for stream 0.
        let resp_headers = s.send_response(0, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((0, headers_event)));
        assert_eq!(s.client_poll(), Ok((0, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        // 8. Server send response headers with FIN for stream 4.
        let resp_headers = s.send_response(4, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((4, headers_event)));
        assert_eq!(s.client_poll(), Ok((4, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send request with body, but the entire body was blocked by connection flow control.
    #[test]
    fn client_send_request_with_entire_body_blocked_by_conn_flow_control() {
        // For convenience, we create an h3 connection to calculate the default HEADERS frame size.
        let h3_config = Http3Config::new().unwrap();
        let mut h3_client = Http3Connection::new(&h3_config, false).unwrap();

        let req_headers = Session::default_request_headers();
        let headers_frame_size =
            Session::calculate_headers_frame_size(&mut h3_client, &req_headers).unwrap();
        assert_eq!(headers_frame_size, 44);

        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        // Note:
        // 1) `5` is the non-request stream cost, it may need to be update in the future.
        // 2) `1` is used to make sure the capacity is not enough for the `DATA` frame header.
        server_config.set_initial_max_data(headers_frame_size as u64 + 5 + 1);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        // 1. Client send the first request headers without FIN.
        let (stream_id, req_headers) = s.send_request(false).unwrap();
        assert_eq!(s.client_send_body(stream_id, true), Err(Http3Error::Done));

        // 2. Server receive request headers, and it will send MAX_DATA frame to client.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: false,
        };
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        s.move_forward().unwrap();

        // 3. Client try to send more data, it should success.
        // Note that the body would not be sent out here.
        let body = s.client_send_body(stream_id, true).unwrap();

        s.move_forward().unwrap();

        // 4. Server receive body with FIN.
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        let mut recv_buf = vec![0; body.len()];
        assert_eq!(s.server_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // 5. Server send response headers with FIN.
        let resp_headers = s.send_response(stream_id, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send request with body, but the body was truncate because the connection flow control.
    #[test]
    fn client_send_request_but_body_truncated_by_conn_flow_control() {
        // For convenience, we create an h3 connection to calculate the default HEADERS frame size.
        let h3_config = Http3Config::new().unwrap();
        let mut h3_client = Http3Connection::new(&h3_config, false).unwrap();

        let req_headers = Session::default_request_headers();
        let headers_frame_size =
            Session::calculate_headers_frame_size(&mut h3_client, &req_headers).unwrap();
        assert_eq!(headers_frame_size, 44);

        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        // Note: `10` is used to make sure the capacity is not enough for the entire `DATA` frame.
        server_config.set_initial_max_data(headers_frame_size as u64 + 10);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        // 1. Client send the first request headers without FIN.
        let (stream_id, req_headers) = s.send_request(false).unwrap();
        // 2. Client try to send body with FIN.
        let body = s.client_send_body(stream_id, true).unwrap();

        // 3. Server receive request headers, and it will send MAX_DATA frame to client.
        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: false,
        };
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        let mut recv_buf = vec![0; body.len()];
        assert_eq!(s.server_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
        // Note: here must not be `Http3Event::Finished`, because the body was truncated.
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        s.move_forward().unwrap();

        // 4. Client try to send more data, it should success.
        // Note that the body would not be sent out here.
        let body = s.client_send_body(stream_id, true).unwrap();

        s.move_forward().unwrap();

        // 5. Server receive body with FIN.
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        let mut recv_buf = vec![0; body.len()];
        assert_eq!(s.server_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // 6. Server send response headers with FIN.
        let resp_headers = s.send_response(stream_id, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };
        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send goaway blocked by connection flow control.
    #[test]
    fn client_send_goaway_blocked_by_conn_flow_control() {
        let h3_config = Http3Config::new().unwrap();
        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        // Note:
        // 1) The 1st `5` is the non-request stream cost, it may need to be update in the future.
        // 2) The 2nd `2` is used to make sure the capacity is not enough for the `GOAWAY` frame(3Bytes).
        server_config.set_initial_max_data(5 + 2);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        assert_eq!(
            s.client.send_goaway(&mut s.pair.client, 1),
            Err(Http3Error::StreamBlocked)
        );

        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Client send a request without body, get a response without body
    // followed by an reserved frame with a FIN.
    #[test]
    fn request_without_body_response_without_body_but_with_reserved_frame() {
        let mut s = Session::new().unwrap();

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server send response headers without final flag.
        let resp_headers = s.send_response(stream_id, false).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        // Write a reserved type frame
        let mut bytes = BytesMut::zeroed(10);
        let mut b = bytes.as_mut();

        let reserved_frame_type = 31 * 148_764_065_110_560_899 + 33;
        let reserved_frame_payload = Bytes::from_static(b"QuicCentury");
        let reserved_frame_payload_len = reserved_frame_payload.len() as u64;

        let mut len = b.write_varint(reserved_frame_type).unwrap();
        len += b.write_varint(reserved_frame_payload_len).unwrap();
        bytes.truncate(len);

        // Write reserved frame header to the quic transport stream buffer.
        s.pair
            .server
            .stream_write(stream_id, bytes.freeze(), false)
            .unwrap();
        // Write reserved frame payload to the quic transport stream buffer.
        s.pair
            .server
            .stream_write(stream_id, reserved_frame_payload, true)
            .unwrap();

        s.move_forward().ok();

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send a request without body, but the server send DATA frame
    // before HEADERS frame.
    #[test]
    fn server_send_body_before_headers() {
        let mut s = Session::new().unwrap();

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        // Server try to send response body before response headers.
        assert_eq!(
            s.server_send_body(stream_id, true),
            Err(Http3Error::FrameUnexpected)
        );

        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send a request with bad encode header_block, server will decode error.
    #[test]
    fn client_send_bad_encode_header_block() {
        let mut s = Session::new().unwrap();

        let field_section = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Client send a request with bad encode header_block.
        assert!(s
            .client_send_frame(0, frame::Http3Frame::Headers { field_section }, true)
            .is_ok());

        assert_eq!(s.server_poll(), Err(Http3Error::QpackDecompressionFailed));
    }

    // Client send a request with large headers, it is not allowed.
    #[test]
    fn client_send_large_headers() {
        let mut h3_config: Http3Config = Http3Config::new().unwrap();
        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();

        let req_headers = Session::default_request_headers();
        let headers_size = req_headers.iter().fold(0, |header_size, h| {
            header_size + h.value().len() + h.name().len() + 32
        });

        h3_config.set_max_field_section_size((headers_size - 1) as u64);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        assert_eq!(s.send_request(true), Err(Http3Error::ExcessiveLoad));
    }

    // Client send a HEADERS frame with large headers, server will decode error.
    #[test]
    fn client_send_headers_frame_with_large_headers() {
        let mut h3_config: Http3Config = Http3Config::new().unwrap();
        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();

        let req_headers = Session::default_request_headers();
        let headers_size = req_headers.iter().fold(0, |header_size, h| {
            header_size + h.value().len() + h.name().len() + 32
        });

        h3_config.set_max_field_section_size((headers_size - 1) as u64);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        let mut field_section = vec![0; headers_size];
        let field_section_size = s
            .client
            .qpack_encoder
            .encode(&req_headers, &mut field_section)
            .unwrap();
        field_section.truncate(field_section_size);

        assert!(s
            .client_send_frame(0, frame::Http3Frame::Headers { field_section }, true)
            .is_ok());

        assert_eq!(
            s.server_poll().err(),
            Some(Http3Error::QpackDecompressionFailed)
        );
    }

    // Server send a HEADERS frame with large headers, client will decode error.
    #[test]
    fn server_send_headers_frame_with_large_headers() {
        let mut h3_config: Http3Config = Http3Config::new().unwrap();
        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();

        // In this case, resp_headers must larger than request headers size.
        let resp_headers = vec![
            Header::new(b":status", b"200"),
            Header::new(b"server", b"quicent"),
            Header::new(b"quic", b"century"),
            Header::new(b"we", b"quic"),
            Header::new(b"xxxxxx", b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            Header::new(b"yyyyyy", b"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"),
            Header::new(b"zzzzzz", b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
        ];

        let headers_size = resp_headers.iter().fold(0, |header_size, h| {
            header_size + h.value().len() + h.name().len() + 32
        });

        h3_config.set_max_field_section_size((headers_size - 1) as u64);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));

        let mut field_section = vec![0; headers_size];
        let field_section_size = s
            .client
            .qpack_encoder
            .encode(&resp_headers, &mut field_section)
            .unwrap();
        field_section.truncate(field_section_size);

        assert!(s
            .server_send_frame(0, frame::Http3Frame::Headers { field_section }, true)
            .is_ok());

        assert_eq!(
            s.client_poll().err(),
            Some(Http3Error::QpackDecompressionFailed)
        );
    }

    // Client shutdown write before server consume any data from quic stream buffer.
    #[test]
    fn client_shutdown_write_before_server_consume_any_quic_buffer_data() {
        let mut s = Session::new().unwrap();

        // Subcase1: Client send request headers without FIN flag.
        let (stream_id, _req_headers) = s.send_request(false).unwrap();

        // Client shutdown write in advance.
        let error_code = 7;
        assert_eq!(
            s.pair
                .client
                .stream_shutdown(stream_id, crate::Shutdown::Write, error_code),
            Ok(())
        );

        s.pair.move_forward().ok();

        // Server report just a Reset event.
        assert_eq!(
            s.server_poll(),
            Ok((stream_id, Http3Event::Reset(error_code)))
        );
        assert!(!s.pair.server.stream_readable(stream_id));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Subcase2: Client send request headers with FIN flag.
        let (stream_id, _req_headers) = s.send_request(true).unwrap();

        // Client shutdown write in advance.
        assert_eq!(
            s.pair
                .client
                .stream_shutdown(stream_id, crate::Shutdown::Write, error_code),
            Ok(())
        );

        s.pair.move_forward().ok();

        // Server report just a Reset event.
        assert_eq!(
            s.server_poll(),
            Ok((stream_id, Http3Event::Reset(error_code)))
        );
        assert!(!s.pair.server.stream_readable(stream_id));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Client shutdown write before server consume all data from quic stream buffer.
    // 1. Client send request headers + data + fin;
    // 2. Server read headers and some data, but not read fin;
    // 3. Client shutdown write, which will trigger quic transport to send RESET_STREAM to server;
    // 4. Server should poll Reset event but not Finished event.
    #[test]
    fn client_shutdown_write_before_server_consume_all_quic_buffer_data() {
        let mut s = Session::new().unwrap();

        // Client send request headers without FIN flag.
        let (stream_id, req_headers) = s.send_request(false).unwrap();
        // Client send one data block with final flag.
        let req_body = s.client_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        let mut recv_buf = vec![0; req_body.len() - 1];
        // Server receive request headers and data.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(
            s.server_recv_body(stream_id, &mut recv_buf),
            Ok(req_body.len() - 1)
        );
        assert_eq!(recv_buf, req_body[..(req_body.len() - 1)]);
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Client shutdown write in advance.
        let error_code = 7;
        assert_eq!(
            s.pair
                .client
                .stream_shutdown(stream_id, crate::Shutdown::Write, error_code),
            Ok(())
        );

        s.pair.move_forward().ok();

        // Server report just a Reset event.
        // Note that the stream's current state is `Data`, application should use recv_body,
        // but not server_poll to get the data, otherwise it will return a Finished event.
        assert_eq!(
            s.server_recv_body(stream_id, &mut recv_buf),
            Err(Http3Error::TransportError(crate::Error::StreamReset(
                error_code
            )))
        );
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Server shutdown write before client consume any data from quic stream buffer.
    #[test]
    fn server_shutdown_write_before_client_consume_any_quic_buffer_data() {
        let mut s = Session::new().unwrap();

        // Subcase1: Client send request headers without FIN flag.
        let (stream_id, req_headers) = s.send_request(false).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        // Server receive headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response without FIN flag.
        s.send_response(stream_id, false).unwrap();

        // Server shutdown write in advance.
        let error_code = 7;
        assert_eq!(
            s.pair
                .server
                .stream_shutdown(stream_id, crate::Shutdown::Write, error_code),
            Ok(())
        );

        s.pair.move_forward().ok();

        // Client report just a Reset event.
        assert_eq!(
            s.client_poll(),
            Ok((stream_id, Http3Event::Reset(error_code)))
        );
        assert!(!s.pair.server.stream_readable(stream_id));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Subcase2: Client send request headers with FIN flag.
        let (stream_id, req_headers) = s.send_request(true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // Server receive headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response with FIN flag.
        s.send_response(stream_id, true).unwrap();

        // Server shutdown write by conn.stream_shutdown, return Done,
        // because the stream has been remove from server.streams.
        let error_code = 7;
        assert_eq!(
            s.pair
                .server
                .stream_shutdown(stream_id, crate::Shutdown::Write, error_code),
            Err(Error::Done)
        );

        // Server send RESET_STREAM frame, shutdown write side.
        let error_code = 42;
        let frame = [crate::frame::Frame::ResetStream {
            stream_id,
            error_code,
            final_size: 13,
        }];

        // Client build packet and send it to server.
        s.pair
            .build_packet_and_send(crate::packet::PacketType::OneRTT, &frame, true)
            .unwrap();

        s.pair.move_forward().ok();

        // Client report just a Reset event.
        assert_eq!(
            s.client_poll(),
            Ok((stream_id, Http3Event::Reset(error_code)))
        );
        assert!(!s.pair.server.stream_readable(stream_id));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Server shutdown write before client consume all data from quic stream buffer.
    // 1. Client send request headers + fin;
    // 2. Server read headers with fin;
    // 3. Server send response headers + data, but without fin;
    // 4. Server shutdown write, which will trigger quic transport to send RESET_STREAM to client;
    // 5. Client should poll Reset event but not Finished event.
    #[test]
    fn server_shutdown_write_before_client_consume_all_quic_buffer_data() {
        let mut s = Session::new().unwrap();

        // Client send request headers without FIN flag.
        let (stream_id, req_headers) = s.send_request(true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // Server receive request headers and data.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response without FIN flag.
        let resp_headers = s.send_response(stream_id, false).unwrap();
        // Server send one data block without FIN flag.
        let body = s.server_send_body(stream_id, false).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        // Client detect headers event and receive response headers.
        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));

        // Client detect data event and receive some response body.
        let mut recv_buf = vec![0; body.len() - 1];
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(
            s.client_recv_body(stream_id, &mut recv_buf),
            Ok(body.len() - 1)
        );
        assert_eq!(recv_buf, body[..(body.len() - 1)]);

        // Server shutdown write in advance.
        let error_code = 7;
        assert_eq!(
            s.pair
                .server
                .stream_shutdown(stream_id, crate::Shutdown::Write, error_code),
            Ok(())
        );

        s.pair.move_forward().ok();

        // Client report just a Reset event.
        // Note that the stream's current state is `Data`, application should use recv_body,
        // but not client_poll to get the data, otherwise it will return a Finished event.
        assert_eq!(
            s.client_recv_body(stream_id, &mut recv_buf),
            Err(Http3Error::TransportError(crate::Error::StreamReset(
                error_code
            )))
        );
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Client send request headers, data and RESET_STREAM frame before stream write finished.
    #[test]
    fn client_send_request_and_reset_stream_before_write_finished() {
        let mut s = Session::new().unwrap();

        // Client send a request without FIN flag.
        let (stream_id, req_headers) = s.send_request(false).unwrap();
        // Client send one data block without final flag.
        let req_body = s.client_send_body(stream_id, false).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        let mut recv_buf = vec![0; req_body.len()];
        // Server receive headers and data.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(
            s.server_recv_body(stream_id, &mut recv_buf),
            Ok(req_body.len())
        );
        assert_eq!(recv_buf, req_body);
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response and close stream.
        let resp_headers = s.send_response(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        // Client send RESET_STREAM, shutdown write side.
        let error_code = 42;
        let frame = [crate::frame::Frame::ResetStream {
            stream_id,
            error_code,
            final_size: 128, // Must larger than the sent offset in s.send_request.
        }];

        // Client build packet and send it to server.
        s.pair
            .build_packet_and_send(crate::packet::PacketType::OneRTT, &frame, false)
            .unwrap();

        // Server report Reset event for the stream.
        assert_eq!(
            s.server_poll(),
            Ok((stream_id, Http3Event::Reset(error_code)))
        );
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Client send RESET_STREAM again, server should not trigger another Reset event.
        s.pair
            .build_packet_and_send(crate::packet::PacketType::OneRTT, &frame, false)
            .unwrap();
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Client send request headers and RESET_STREAM frame before stream write finished.
    #[test]
    fn client_send_request_headers_and_reset_stream_before_write_finished() {
        let mut s = Session::new().unwrap();

        // Client send a request without FIN flag.
        let (stream_id, req_headers) = s.send_request(false).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        // Server receive headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response and close stream.
        let resp_headers = s.send_response(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        // Client send RESET_STREAM, shutdown write side.
        let error_code = 42;
        let frame = [crate::frame::Frame::ResetStream {
            stream_id,
            error_code,
            final_size: 128, // Must larger than the sent offset in s.send_request.
        }];

        // Client build packet and send it to server.
        s.pair
            .build_packet_and_send(crate::packet::PacketType::OneRTT, &frame, false)
            .unwrap();

        // Server report Reset event for the stream.
        assert_eq!(
            s.server_poll(),
            Ok((stream_id, Http3Event::Reset(error_code)))
        );
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Client send RESET_STREAM again, server should not trigger another Reset event.
        s.pair
            .build_packet_and_send(crate::packet::PacketType::OneRTT, &frame, false)
            .unwrap();
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Server send response on closed request stream.
    #[test]
    fn server_send_response_on_closed_request_stream() {
        let mut s = Session::new().unwrap();

        // Client send a request with FIN flag.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // Server receive request headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response with FIN flag.
        s.send_response(stream_id, true).unwrap();

        // Server send response again, but the stream has been closed.
        assert_eq!(
            s.send_response(stream_id, true),
            Err(Http3Error::FrameUnexpected)
        );
    }

    // Client or server send body on unexpected stream.
    #[test]
    fn send_body_on_unexpected_stream() {
        let mut s = Session::new().unwrap();

        for &stream_id in &[
            s.client.local_control_stream_id,
            s.client.local_qpack_streams.encoder_stream_id,
            s.client.local_qpack_streams.decoder_stream_id,
            s.client.peer_control_stream_id,
            s.client.peer_qpack_streams.encoder_stream_id,
            s.client.peer_qpack_streams.decoder_stream_id,
        ] {
            if let Some(sid) = stream_id {
                assert_eq!(
                    s.client_send_body(sid, true),
                    Err(Http3Error::FrameUnexpected)
                );

                assert_eq!(
                    s.server_send_body(sid, true),
                    Err(Http3Error::FrameUnexpected)
                );
            }
        }
    }

    // Client send a PRIORITY_UPDATE(request) for request stream.
    #[test]
    fn client_send_priority_update_request() {
        let mut s = Session::new().unwrap();

        let stream_id = 4;
        // Subcase1: Stream does not exist.
        assert_eq!(
            s.server.take_priority_update(stream_id),
            Err(Http3Error::Done)
        );

        // Subcase2: Client send priority update for request stream, non-incremental.
        s.client
            .send_priority_update_for_request(
                &mut s.pair.client,
                stream_id,
                &Http3Priority {
                    urgency: 3,
                    incremental: false,
                },
            )
            .unwrap();

        s.move_forward().ok();

        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::PriorityUpdate)));

        let priority_value = s.server.take_priority_update(stream_id).unwrap();
        assert_eq!(
            Http3Priority::try_from(priority_value.as_slice()),
            Ok(Http3Priority {
                urgency: 3,
                incremental: false
            })
        );

        // Subcase3: Client send priority update for request stream, incremental.
        s.client
            .send_priority_update_for_request(
                &mut s.pair.client,
                stream_id,
                &Http3Priority {
                    urgency: 3,
                    incremental: true,
                },
            )
            .unwrap();

        s.move_forward().ok();

        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::PriorityUpdate)));

        let priority_value = s.server.take_priority_update(stream_id).unwrap();
        assert_eq!(
            Http3Priority::try_from(priority_value.as_slice()),
            Ok(Http3Priority {
                urgency: 3,
                incremental: true
            })
        );

        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Client send a PRIORITY_UPDATE(request) before request.
    #[test]
    fn client_send_priority_update_before_request() {
        let mut s = Session::new().unwrap();

        let stream_id = 0;
        // 1. Client send priority update(non-incremental) before request.
        s.client
            .send_priority_update_for_request(
                &mut s.pair.client,
                stream_id,
                &Http3Priority {
                    urgency: 3,
                    incremental: false,
                },
            )
            .unwrap();

        s.move_forward().ok();

        // 2. Server receive priority update.
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::PriorityUpdate)));

        let priority_value = s.server.take_priority_update(stream_id).unwrap();
        assert_eq!(
            Http3Priority::try_from(priority_value.as_slice()),
            Ok(Http3Priority {
                urgency: 3,
                incremental: false
            })
        );

        // Stream's priority is not initialized, the underlying quic stream is not opened, in server side.
        let stream = s.server.streams.get(&stream_id).unwrap();
        assert!(!stream.priority_initialized());

        // 3. Client send request headers
        let (stream_id, req_headers) = s.send_request(true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // 4. Server receive request headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Stream's priority is not initialized, the underlying quic stream is not opened, in server side.
        let stream = s.server.streams.get(&stream_id).unwrap();
        assert!(!stream.priority_initialized());

        // 5. Server send response without FIN flag.
        let resp_headers = s.send_response(stream_id, false).unwrap();

        // After server send response, the stream's priority is initialized.
        let stream = s.server.streams.get(&stream_id).unwrap();
        assert!(stream.priority_initialized());

        // 6. Server send one data block with FIN flag.
        let body = s.server_send_body(stream_id, true).unwrap();

        // 7. Client receive response headers and data.
        let mut recv_buf = vec![0; body.len()];
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Data)));
        assert_eq!(s.client_recv_body(stream_id, &mut recv_buf), Ok(body.len()));
        assert_eq!(recv_buf, body);
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send multi PRIORITY_UPDATE(request) for request stream continuously.
    #[test]
    fn client_send_multi_priority_update_request() {
        let mut s = Session::new().unwrap();

        let stream_id = 4;

        // Client send priority update for request stream(4).
        s.client
            .send_priority_update_for_request(
                &mut s.pair.client,
                stream_id,
                &Http3Priority {
                    urgency: 3,
                    incremental: true,
                },
            )
            .unwrap();

        s.move_forward().ok();

        // Send another priority update for the same stream before server poll.
        s.client
            .send_priority_update_for_request(
                &mut s.pair.client,
                stream_id,
                &Http3Priority {
                    urgency: 5,
                    incremental: false,
                },
            )
            .unwrap();

        s.move_forward().ok();

        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::PriorityUpdate)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        let priority_value = s.server.take_priority_update(stream_id).unwrap();
        assert_eq!(
            Http3Priority::try_from(priority_value.as_slice()),
            Ok(Http3Priority {
                urgency: 5,
                incremental: false
            })
        );

        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Client send a PRIORITY_UPDATE(request) for request stream, but stream_id
    // exceed the peer's max stream limits.
    #[test]
    fn client_send_priority_update_request_exceed_stream_limits() {
        let mut s = Session::new().unwrap();

        let stream_id = s.pair.server.get_streams().max_streams(true) * 4 + 4;

        // Client send priority update for request stream by h3 api, but stream_id exceed
        // the peer's max stream limits, so it will return IdError.
        assert_eq!(
            s.client.send_priority_update_for_request(
                &mut s.pair.client,
                stream_id,
                &Http3Priority {
                    urgency: 3,
                    incremental: true,
                },
            ),
            Err(Http3Error::IdError)
        );

        // Client send priority update for request stream by h3 frame, but stream_id exceed
        // the peer's max stream limits.
        let frame = frame::Http3Frame::PriorityUpdateRequest {
            prioritized_element_id: stream_id,
            priority_field_value: b"u=4, i".to_vec(),
        };

        s.client_send_frame(s.client.local_control_stream_id.unwrap(), frame, false)
            .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::IdError));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Client send a PRIORITY_UPDATE(request) for a closed stream.
    #[test]
    fn client_send_priority_update_request_on_closed_stream() {
        let mut s = Session::new().unwrap();

        // Client send a request with FIN flag.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // Server receive request headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response with FIN flag.
        let resp_headers = s.send_response(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        // Client receive response headers and finished event.
        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        // Client send priority update for request stream by h3 api, which has been closed.
        // It will return FrameUnexpected.
        assert_eq!(
            s.client.send_priority_update_for_request(
                &mut s.pair.client,
                stream_id,
                &Http3Priority {
                    urgency: 3,
                    incremental: true,
                },
            ),
            Err(Http3Error::FrameUnexpected)
        );

        s.move_forward().ok();

        // Client send priority update for request stream by h3 frame, which has been closed.
        let frame = frame::Http3Frame::PriorityUpdateRequest {
            prioritized_element_id: stream_id,
            priority_field_value: b"u=4, i".to_vec(),
        };

        s.client_send_frame(s.client.local_control_stream_id.unwrap(), frame, false)
            .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Client send a PRIORITY_UPDATE(push) for push stream.
    #[test]
    fn client_send_priority_update_push() {
        let mut s = Session::new().unwrap();

        s.client_send_frame(
            s.client.local_control_stream_id.unwrap(),
            frame::Http3Frame::PriorityUpdatePush {
                prioritized_element_id: 5,
                priority_field_value: b"u=4, i".to_vec(),
            },
            false,
        )
        .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Client send a PRIORITY_UPDATE(request) for non-request stream.
    #[test]
    fn client_send_priority_update_request_for_non_request() {
        let mut s = Session::new().unwrap();

        // Client send PRIORITY_UPDATE for non-request stream by h3 api.
        assert_eq!(
            s.client.send_priority_update_for_request(
                &mut s.pair.client,
                1,
                &Http3Priority {
                    urgency: 3,
                    incremental: false,
                },
            ),
            Err(Http3Error::IdError)
        );

        // Client send PRIORITY_UPDATE for non-request stream by h3 frame.
        s.client_send_frame(
            s.client.local_control_stream_id.unwrap(),
            frame::Http3Frame::PriorityUpdateRequest {
                prioritized_element_id: 1,
                priority_field_value: b"u=4, i".to_vec(),
            },
            false,
        )
        .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::IdError));
    }

    // Client send PRIORITY_UPDATE(request) blocked by connection flow control.
    #[test]
    fn client_send_priority_update_request_blocked_by_conn_flow_control() {
        let h3_config = Http3Config::new().unwrap();
        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        // Note:
        // 1) The 1st `5` is the non-request stream cost, it may need to be update in the future.
        // 2) The 2nd `8` is used to make sure the capacity is not enough for the `PRIORITY_UPDATE` frame.
        server_config.set_initial_max_data(5 + 8);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        assert_eq!(
            s.client.send_priority_update_for_request(
                &mut s.pair.client,
                0,
                &Http3Priority {
                    urgency: 3,
                    incremental: false,
                },
            ),
            Err(Http3Error::StreamBlocked)
        );

        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Server send a PRIORITY_UPDATE(request) for request stream.
    #[test]
    fn server_send_priority_update_request() {
        let mut s = Session::new().unwrap();

        // Server send PRIORITY_UPDATE for request stream by h3 api.
        assert_eq!(
            s.server.send_priority_update_for_request(
                &mut s.pair.server,
                0,
                &Http3Priority {
                    urgency: 3,
                    incremental: false,
                },
            ),
            Err(Http3Error::FrameUnexpected)
        );

        // Server send PRIORITY_UPDATE for request stream by h3 frame.
        s.server_send_frame(
            s.server.local_control_stream_id.unwrap(),
            frame::Http3Frame::PriorityUpdateRequest {
                prioritized_element_id: 0,
                priority_field_value: b"u=5, i".to_vec(),
            },
            false,
        )
        .unwrap();

        assert_eq!(s.client_poll(), Err(Http3Error::FrameUnexpected));
    }

    // Server send a PRIORITY_UPDATE(push) for push stream.
    #[test]
    fn server_send_priority_update_push() {
        let mut s = Session::new().unwrap();

        s.server_send_frame(
            s.server.local_control_stream_id.unwrap(),
            frame::Http3Frame::PriorityUpdatePush {
                prioritized_element_id: 5,
                priority_field_value: b"u=4, i".to_vec(),
            },
            false,
        )
        .unwrap();

        assert_eq!(s.client_poll(), Err(Http3Error::FrameUnexpected));
    }

    #[test]
    fn parse_extensible_priority() {
        for (priority, urgency, incremental) in [
            ("", PRIORITY_URGENCY_DEFAULT, PRIORITY_INCREMENTAL_DEFAULT),
            ("i", PRIORITY_URGENCY_DEFAULT, true),
            ("i=?0", PRIORITY_URGENCY_DEFAULT, false),
            ("i=?1", PRIORITY_URGENCY_DEFAULT, true),
            ("u=0", 0, PRIORITY_INCREMENTAL_DEFAULT),
            ("u=0, i", 0, true),
            ("u=0, i=?0", 0, false),
            ("u=0, i=?1", 0, true),
            ("u=3", 3, PRIORITY_INCREMENTAL_DEFAULT),
            ("u=3, i", 3, true),
            ("u=3, i=?0", 3, false),
            ("u=3, i=?1", 3, true),
            ("u=7", 7, PRIORITY_INCREMENTAL_DEFAULT),
            ("u=7, i", 7, true),
            ("u=7, i=?0", 7, false),
            ("u=7, i=?1", 7, true),
            // Boundary value
            (
                "u=8",
                PRIORITY_URGENCY_UPPER_BOUND,
                PRIORITY_INCREMENTAL_DEFAULT,
            ),
            ("u=8, i", PRIORITY_URGENCY_UPPER_BOUND, true),
            ("u=8, i=?0", PRIORITY_URGENCY_UPPER_BOUND, false),
            ("u=8, i=?1", PRIORITY_URGENCY_UPPER_BOUND, true),
            (
                "u=-1",
                PRIORITY_URGENCY_UPPER_BOUND,
                PRIORITY_INCREMENTAL_DEFAULT,
            ),
            ("u=-1, i", PRIORITY_URGENCY_UPPER_BOUND, true),
            ("u=-1, i=?0", PRIORITY_URGENCY_UPPER_BOUND, false),
            ("u=-1, i=?1", PRIORITY_URGENCY_UPPER_BOUND, true),
            ("u=3, quic", 3, PRIORITY_INCREMENTAL_DEFAULT),
            ("u=3, i, quic", 3, true),
            ("u=3, i=?0, quic", 3, false),
            ("u=3, i=?1, quic", 3, true),
            ("u=5;quic", 5, PRIORITY_INCREMENTAL_DEFAULT),
            ("u=5;quic, i", 5, true),
            ("u=5;quic, i=?0", 5, false),
            ("u=5;quic, i=?1", 5, true),
            ("u=5;quic, i;century", 5, true),
            ("u=5;quic, i=?0;century", 5, false),
            ("u=5;quic, i=?1;century", 5, true),
        ] {
            assert_eq!(
                Http3Priority::try_from(priority.as_ref()).unwrap(),
                Http3Priority {
                    urgency,
                    incremental
                }
            );
        }

        // Invalid priority, try_from will return Http3Error::Done
        for priority in [
            "0",
            "u=0.2",
            "u=x",
            "u=1,",
            "i=x",
            "i=?x",
            "i=?true",
            // urgency is a sfv::ListEntry::InnerList
            "u=(x y), i",
            // incremental is a sfv::ListEntry::InnerList
            "u=1, i=(x y)",
        ] {
            assert_eq!(
                Http3Priority::try_from(priority.as_ref()),
                Err(Http3Error::Done)
            );
        }
    }

    // Client send multiple GOAWAY frames with decreasing push_id.
    #[test]
    fn client_send_goaway_decrease_push_id() {
        let mut s = Session::new().unwrap();

        // Note that: we don't support server push yet, so the push_id
        // sent by client is always 0 for now.

        // Client send a GOAWAY frame with push_id 100.
        s.client.send_goaway(&mut s.pair.client, 100).unwrap();
        s.move_forward().ok();
        assert_eq!(s.server_poll(), Ok((0, Http3Event::GoAway)));

        // Client send a GOAWAY frame with push_id 50.
        s.client.send_goaway(&mut s.pair.client, 50).unwrap();
        s.move_forward().ok();
        assert_eq!(s.server_poll(), Ok((0, Http3Event::GoAway)));

        // Client send a GOAWAY frame with push_id 25.
        s.client.send_goaway(&mut s.pair.client, 25).unwrap();
        s.move_forward().ok();
        assert_eq!(s.server_poll(), Ok((0, Http3Event::GoAway)));

        // Client send a GOAWAY frame with push_id 0.
        s.client.send_goaway(&mut s.pair.client, 0).unwrap();
        s.move_forward().ok();
        assert_eq!(s.server_poll(), Ok((0, Http3Event::GoAway)));
    }

    // Server send multiple GOAWAY frames with decreasing stream_id.
    #[test]
    fn server_send_goaway_decrease_stream_id() {
        let mut s = Session::new().unwrap();

        // Server send a GOAWAY frame with stream_id 256.
        s.server.send_goaway(&mut s.pair.server, 256).unwrap();
        s.move_forward().ok();
        assert_eq!(s.client_poll(), Ok((256, Http3Event::GoAway)));

        // Server send a GOAWAY frame with stream_id 128.
        s.server.send_goaway(&mut s.pair.server, 128).unwrap();
        s.move_forward().ok();
        assert_eq!(s.client_poll(), Ok((128, Http3Event::GoAway)));

        // Server send a GOAWAY frame with stream_id 64.
        s.server.send_goaway(&mut s.pair.server, 64).unwrap();
        s.move_forward().ok();
        assert_eq!(s.client_poll(), Ok((64, Http3Event::GoAway)));

        // Server send a GOAWAY frame with stream_id 0.
        s.server.send_goaway(&mut s.pair.server, 0).unwrap();
        s.move_forward().ok();
        assert_eq!(s.client_poll(), Ok((0, Http3Event::GoAway)));
    }

    // Server send multiple GOAWAY frames with increasing stream_id.
    #[test]
    fn server_send_goaway_increase_stream_id() {
        let mut s = Session::new().unwrap();

        // Server send a GOAWAY frame with stream_id 64.
        s.server.send_goaway(&mut s.pair.server, 64).unwrap();
        s.move_forward().ok();
        assert_eq!(s.client_poll(), Ok((64, Http3Event::GoAway)));

        // Server send a GOAWAY frame with stream_id 128 by h3 api, client cannot receive it.
        assert_eq!(
            s.server.send_goaway(&mut s.pair.server, 128),
            Err(Http3Error::IdError)
        );

        // Server send a GOAWAY frame with stream_id 128 by quic api, client will treat it as a connection error of type H3_ID_ERROR.
        s.server_send_frame(
            s.server.local_control_stream_id.unwrap(),
            frame::Http3Frame::GoAway { id: 128 },
            false,
        )
        .unwrap();
        assert_eq!(s.client_poll(), Err(Http3Error::IdError));
    }

    // Server send GOAWAY frame with invalid stream_id.
    #[test]
    fn server_send_goaway_with_invalid_id() {
        let mut s = Session::new().unwrap();

        // Server send invalid GOAWAY by h3 api, client cannot receive it.
        assert_eq!(
            s.server.send_goaway(&mut s.pair.server, 1),
            Err(Http3Error::IdError)
        );

        // Server send invalid GOAWAY by quic api, client will treat it as a connection error of type H3_ID_ERROR.
        s.server_send_frame(
            s.server.local_control_stream_id.unwrap(),
            frame::Http3Frame::GoAway { id: 1 },
            false,
        )
        .unwrap();
        assert_eq!(s.client_poll(), Err(Http3Error::IdError));
    }

    // Server try to send GOAWAY frame on an uninitialized control stream.
    #[test]
    fn server_send_goaway_on_uninitialized_control_stream() {
        let mut s = Session::new().unwrap();

        let h3_config = Http3Config::new().unwrap();
        let mut http3_conn = Http3Connection::new(&h3_config, false).unwrap();

        assert_eq!(
            http3_conn.send_goaway(&mut s.pair.server, 0),
            Err(Http3Error::InternalError)
        );
    }

    // Client try to create new request after receiving GOAWAY frame.
    #[test]
    fn client_send_request_after_recv_goaway() {
        let mut s = Session::new().unwrap();

        s.server.send_goaway(&mut s.pair.server, 64).unwrap();
        s.move_forward().ok();

        assert_eq!(s.client_poll(), Ok((64, Http3Event::GoAway)));
        assert_eq!(s.send_request(true), Err(Http3Error::IdError));
    }

    // Client try to create massive requests which exceed the peer's concurrcy limit.
    #[test]
    fn client_send_massive_requests_exceed_concurrency_limit() {
        let max_bidi_streams = 3;
        let h3_config: Http3Config = Http3Config::new().unwrap();
        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        server_config.set_initial_max_streams_bidi(max_bidi_streams);

        let mut s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config)
                .unwrap();

        for _ in 0..max_bidi_streams {
            s.send_request(true).unwrap();
        }

        // The last request will exceed the concurrency limit.
        assert_eq!(
            s.send_request(true),
            Err(Http3Error::TransportError(crate::Error::StreamLimitError))
        );
    }

    // Server try to create request stream.
    #[test]
    fn server_create_request_stream() {
        let mut s = Session::new().unwrap();
        assert_eq!(
            s.server.stream_new(&mut s.pair.server),
            Err(Http3Error::TransportError(crate::Error::StreamStateError))
        );
    }

    // Client try to send headers on non-request stream.
    #[test]
    fn client_send_headers_on_non_request_stream() {
        let mut s = Session::new().unwrap();

        let headers = Session::default_request_headers();
        assert_eq!(
            s.client.send_headers(
                &mut s.pair.client,
                s.client.local_control_stream_id.unwrap(),
                &headers,
                true
            ),
            Err(Http3Error::FrameUnexpected)
        );
    }

    // Server try to send headers on non-request stream.
    #[test]
    fn server_send_headers_on_non_request_stream() {
        let mut s = Session::new().unwrap();

        let headers = Session::default_request_headers();
        assert_eq!(
            s.server.send_headers(
                &mut s.pair.server,
                s.server.local_control_stream_id.unwrap(),
                &headers,
                true
            ),
            Err(Http3Error::FrameUnexpected)
        );
    }

    // Server open control stream failed because of stream limit error.
    #[test]
    fn server_open_control_stream_failed() {
        let h3_config: Http3Config = Http3Config::new().unwrap();
        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();
        server_config.set_initial_max_streams_uni(0);

        assert_eq!(
            Session::new_with_test_config(&mut client_config, &mut server_config, &h3_config).err(),
            Some(Http3Error::TransportError(crate::Error::StreamLimitError))
        );
    }

    // Client send MAX_PUSH_ID frame.
    #[test]
    fn client_send_max_push_id() {
        let mut s = Session::new().unwrap();

        s.client_send_frame(
            s.client.local_control_stream_id.unwrap(),
            frame::Http3Frame::MaxPushId { push_id: 4 },
            false,
        )
        .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::Done));
        assert_eq!(s.server.max_push_id, Some(4));

        s.client_send_frame(
            s.client.local_control_stream_id.unwrap(),
            frame::Http3Frame::MaxPushId { push_id: 8 },
            false,
        )
        .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::Done));
        assert_eq!(s.server.max_push_id, Some(8));

        s.client_send_frame(
            s.client.local_control_stream_id.unwrap(),
            frame::Http3Frame::MaxPushId { push_id: 2 },
            false,
        )
        .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::IdError));
    }

    // Client send MAX_PUSH_ID frame on request stream.
    #[test]
    fn client_send_max_push_id_frame_on_request_stream() {
        let mut s = Session::new().unwrap();

        s.client_send_frame(4, frame::Http3Frame::MaxPushId { push_id: 2 }, false)
            .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::FrameUnexpected));
    }

    // Server send a MAX_PUSH_ID frame.
    #[test]
    fn server_send_max_push_id_frame() {
        let mut s = Session::new().unwrap();

        s.server_send_frame(
            s.server.local_control_stream_id.unwrap(),
            frame::Http3Frame::MaxPushId { push_id: 2 },
            false,
        )
        .unwrap();

        assert_eq!(s.client_poll(), Err(Http3Error::FrameUnexpected));
    }

    // Server poll after connection error.
    #[test]
    fn server_poll_after_connection_error() {
        let mut s = Session::new().unwrap();

        // Client send a GOAWAY frame, server detect a connection error.
        s.client_send_frame(4, frame::Http3Frame::GoAway { id: 2 }, false)
            .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::FrameUnexpected));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Client send a request without body.
        let (stream_id, _) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        // Server poll will return Http3Error::Done immediately.
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Server send PUSH_PROMISE frame on request stream.
    #[test]
    fn server_send_push_promise_on_request_stream() {
        let mut s = Session::new().unwrap();
        let max_push_id = 4;

        // Client send a MAX_PUSH_ID frame to server.
        s.client_send_frame(
            s.client.local_control_stream_id.unwrap(),
            frame::Http3Frame::MaxPushId { push_id: 4 },
            false,
        )
        .unwrap();
        s.client.max_push_id = Some(max_push_id);

        // Server update max_push_id.
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
        assert_eq!(s.server.max_push_id, Some(max_push_id));

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let header_block = s.client.encode_header_fields(&req_headers).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));

        // Server send PUSH_PROMISE frame on request stream.
        s.server_send_frame(
            stream_id,
            frame::Http3Frame::PushPromise {
                push_id: 1,
                field_section: header_block.into(),
            },
            false,
        )
        .unwrap();

        // We don't support push_promise completely yet, client will ignore the field_section of the PUSH_PROMISE frame.
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        let resp_headers = s.send_response(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
    }

    // Server send PUSH_PROMISE frame on request stream before the client send any MAX_PUSH_ID frame.
    #[test]
    fn server_send_push_promise_before_client_update_max_push_id() {
        let mut s = Session::new().unwrap();

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let header_block = s.client.encode_header_fields(&req_headers).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));

        // Server send PUSH_PROMISE frame on request stream with a larger push_id than the client advertised.
        s.server_send_frame(
            stream_id,
            frame::Http3Frame::PushPromise {
                push_id: 0,
                field_section: header_block.into(),
            },
            false,
        )
        .unwrap();

        assert_eq!(s.client_poll(), Err(Http3Error::IdError));
    }

    // Server send PUSH_PROMISE frame on request stream with a larger push_id than the client advertised.
    #[test]
    fn server_send_push_promise_with_a_larger_push_id() {
        let mut s = Session::new().unwrap();
        let max_push_id = 4;

        // Client send a MAX_PUSH_ID frame to server.
        s.client_send_frame(
            s.client.local_control_stream_id.unwrap(),
            frame::Http3Frame::MaxPushId { push_id: 4 },
            false,
        )
        .unwrap();
        s.client.max_push_id = Some(max_push_id);

        // Server update max_push_id.
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
        assert_eq!(s.server.max_push_id, Some(max_push_id));

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let header_block = s.client.encode_header_fields(&req_headers).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));

        // Server send PUSH_PROMISE frame on request stream with a larger push_id than the client advertised.
        s.server_send_frame(
            stream_id,
            frame::Http3Frame::PushPromise {
                push_id: max_push_id + 1,
                field_section: header_block.into(),
            },
            false,
        )
        .unwrap();

        assert_eq!(s.client_poll(), Err(Http3Error::IdError));
    }

    // Server send PUSH_PROMISE frame on non-request stream.
    #[test]
    fn server_send_push_promise_frame_on_non_request_stream() {
        let mut s = Session::new().unwrap();

        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let header_block = s.client.encode_header_fields(&req_headers).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));

        // Server send PUSH_PROMISE frame on control stream.
        s.server_send_frame(
            s.server.local_control_stream_id.unwrap(),
            frame::Http3Frame::PushPromise {
                push_id: 1,
                field_section: header_block.into(),
            },
            false,
        )
        .unwrap();
        assert_eq!(s.client_poll(), Err(Http3Error::FrameUnexpected));

        s.send_response(stream_id, true).unwrap();
        // Client poll will return Http3Error::Done immediately because of the connection error.
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send PUSH_PROMISE frame to server.
    #[test]
    fn client_send_push_promise() {
        let mut s = Session::new().unwrap();

        s.client_send_frame(
            4,
            frame::Http3Frame::PushPromise {
                push_id: 1,
                field_section: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            },
            false,
        )
        .unwrap();

        assert_eq!(s.server_poll(), Err(Http3Error::FrameUnexpected));
    }

    // Client send CANCEL_PUSH frame to server on control stream.
    #[test]
    fn client_send_cancel_push_on_control_stream() {
        let mut s = Session::new().unwrap();

        s.client_send_frame(
            s.client.local_control_stream_id.unwrap(),
            frame::Http3Frame::CancelPush { push_id: 0 },
            false,
        )
        .unwrap();

        // We don't support push completely yet, server will ignore the push_id in the CANCEL_PUSH frame.
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }

    // Server send CANCEL_PUSH frame to client on control stream.
    #[test]
    fn server_send_cancel_push_on_control_stream() {
        let mut s = Session::new().unwrap();

        s.server_send_frame(
            s.server.local_control_stream_id.unwrap(),
            frame::Http3Frame::CancelPush { push_id: 0 },
            false,
        )
        .unwrap();

        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send CANCEL_PUSH frame on request stream.
    #[test]
    fn client_send_cancel_push_on_request_stream() {
        let mut s = Session::new().unwrap();

        let (stream_id, req_headers) = s.send_request(false).unwrap();

        s.client_send_frame(
            stream_id,
            frame::Http3Frame::CancelPush { push_id: 0 },
            false,
        )
        .unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Err(Http3Error::FrameUnexpected));
    }

    // Server send CANCEL_PUSH frame on request stream.
    #[test]
    fn server_send_cancel_push_on_request_stream() {
        let mut s = Session::new().unwrap();

        let (stream_id, req_headers) = s.send_request(true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));

        let resp_headers = s.send_response(stream_id, false).unwrap();

        s.server_send_frame(
            stream_id,
            frame::Http3Frame::CancelPush { push_id: 0 },
            true,
        )
        .unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Err(Http3Error::FrameUnexpected));
    }

    // Server send push stream.
    #[test]
    fn server_send_push_stream() {
        let mut s = Session::new().unwrap();
        let max_push_id = 4;

        // 1. Client send a MAX_PUSH_ID frame to server.
        s.client_send_frame(
            s.client.local_control_stream_id.unwrap(),
            frame::Http3Frame::MaxPushId { push_id: 4 },
            false,
        )
        .unwrap();
        s.client.max_push_id = Some(max_push_id);

        // Server update max_push_id.
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
        assert_eq!(s.server.max_push_id, Some(max_push_id));

        // 2. Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let header_block = s.client.encode_header_fields(&req_headers).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers.clone(),
            fin: true,
        };

        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));

        // 3. Server send PUSH_PROMISE frame on request stream.
        let push_id = 3;
        s.server_send_frame(
            stream_id,
            frame::Http3Frame::PushPromise {
                push_id,
                field_section: header_block.clone().into(),
            },
            false,
        )
        .unwrap();

        // We don't support push_promise completely yet, client will ignore the field_section of the PUSH_PROMISE frame.
        assert_eq!(s.client_poll(), Err(Http3Error::Done));

        // 4. Server send a response without body.
        let resp_headers = s.send_response(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Finished)));

        // 5. Server send a push stream.
        let push_stream_id = s
            .server
            .open_uni_stream(&mut s.pair.server, stream::HTTP3_PUSH_STREAM_TYPE)
            .unwrap();

        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        // Write push_id to quic stream buffer.
        let len = b.write_varint(push_id).unwrap();
        bytes.truncate(len);
        s.pair
            .server
            .stream_write(push_stream_id, bytes.freeze(), false)
            .unwrap();

        s.server_send_frame(
            push_stream_id,
            frame::Http3Frame::Headers {
                field_section: header_block.clone().into(),
            },
            false,
        )
        .unwrap();
        let payload = vec![0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x80];
        s.server_send_frame(
            push_stream_id,
            frame::Http3Frame::Data {
                data: payload.clone(),
            },
            true,
        )
        .unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        assert_eq!(s.client_poll(), Ok((push_stream_id, headers_event)));
        assert_eq!(s.client_poll(), Ok((push_stream_id, Http3Event::Data)));
        assert_eq!(s.client_poll(), Err(Http3Error::Done));
    }

    // Client send push stream.
    #[test]
    fn client_send_push_stream() {
        let mut s = Session::new().unwrap();

        let push_stream_id = s
            .client
            .open_uni_stream(&mut s.pair.client, stream::HTTP3_PUSH_STREAM_TYPE)
            .unwrap();

        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        // Write push_id to quic stream buffer.
        let len = b.write_varint(0).unwrap();
        bytes.truncate(len);
        s.pair
            .client
            .stream_write(push_stream_id, bytes.freeze(), false)
            .unwrap();

        s.move_forward().ok();

        assert_eq!(s.server_poll(), Err(Http3Error::StreamCreationError));
    }

    // Default settings of client and server.
    #[test]
    fn default_settings() {
        let s = Session::new().unwrap();

        let client_settings = s.client.peer_raw_settings().unwrap();
        assert!(client_settings.is_empty());

        let server_settings = s.server.peer_raw_settings().unwrap();
        assert!(server_settings.is_empty());
    }

    // Customized settings of client and server.
    #[test]
    fn customized_settings() {
        let max_field_section_size = 65536;
        let qpack_max_table_capacity = 1024;
        let qpack_blocked_streams = 2;

        let mut client_config = Session::new_test_config(false).unwrap();
        let mut server_config = Session::new_test_config(true).unwrap();

        let mut h3_config = Http3Config::new().unwrap();
        h3_config.set_max_field_section_size(max_field_section_size);
        h3_config.set_qpack_max_table_capacity(qpack_max_table_capacity);
        h3_config.set_qpack_blocked_streams(2);

        let s =
            Session::new_with_test_config(&mut client_config, &mut server_config, &mut h3_config)
                .unwrap();

        let client_settings = s.client.peer_raw_settings().unwrap();
        assert_eq!(client_settings.len(), 3);
        assert_eq!(
            s.client.peer_settings.max_field_section_size,
            Some(max_field_section_size)
        );
        assert_eq!(
            s.client.peer_settings.qpack_max_table_capacity,
            Some(qpack_max_table_capacity)
        );
        assert_eq!(
            s.client.peer_settings.qpack_blocked_streams,
            Some(qpack_blocked_streams)
        );
        assert_eq!(s.client.peer_settings.connect_protocol_enabled, None);

        let server_settings = s.server.peer_raw_settings().unwrap();
        assert_eq!(server_settings.len(), 3);
        assert_eq!(
            s.server.peer_settings.max_field_section_size,
            Some(max_field_section_size)
        );
        assert_eq!(
            s.server.peer_settings.qpack_max_table_capacity,
            Some(qpack_max_table_capacity)
        );
        assert_eq!(
            s.server.peer_settings.qpack_blocked_streams,
            Some(qpack_blocked_streams)
        );
        assert_eq!(s.server.peer_settings.connect_protocol_enabled, None);
    }

    // Client try to open multiple control streams.
    #[test]
    fn client_open_multiple_control_streams() {
        let mut s = Session::new().unwrap();

        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        let len = b.write_varint(stream::HTTP3_CONTROL_STREAM_TYPE).unwrap();
        bytes.truncate(len);

        s.pair
            .client
            .stream_write(s.client.next_uni_stream_id, bytes.freeze(), false)
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.server_poll(), Err(Http3Error::StreamCreationError));
    }

    // Server try to open multiple control streams.
    #[test]
    fn server_open_multiple_control_streams() {
        let mut s = Session::new().unwrap();

        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        let len = b.write_varint(stream::HTTP3_CONTROL_STREAM_TYPE).unwrap();
        bytes.truncate(len);

        s.pair
            .server
            .stream_write(s.server.next_uni_stream_id, bytes.freeze(), false)
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.client_poll(), Err(Http3Error::StreamCreationError));
    }

    // Client close the control stream.
    #[test]
    fn client_close_control_stream() {
        let mut s = Session::new().unwrap();

        s.pair
            .client
            .stream_write(
                s.client.local_control_stream_id.unwrap(),
                Bytes::new(),
                true,
            )
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.server_poll(), Err(Http3Error::ClosedCriticalStream));
    }

    // Server close the control stream.
    #[test]
    fn server_close_control_stream() {
        let mut s = Session::new().unwrap();

        s.pair
            .server
            .stream_write(
                s.server.local_control_stream_id.unwrap(),
                Bytes::new(),
                true,
            )
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.client_poll(), Err(Http3Error::ClosedCriticalStream));
    }

    // Client try to open multiple QPACK encoder streams.
    #[test]
    fn client_open_multiple_qpack_encoder_streams() {
        let mut s = Session::new().unwrap();

        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        let len = b.write_varint(stream::QPACK_ENCODER_STREAM_TYPE).unwrap();
        bytes.truncate(len);

        s.pair
            .client
            .stream_write(s.client.next_uni_stream_id, bytes.freeze(), false)
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.server_poll(), Err(Http3Error::StreamCreationError));
    }

    // Client try to open multiple QPACK decoder streams.
    #[test]
    fn client_open_multiple_qpack_decoder_streams() {
        let mut s = Session::new().unwrap();

        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        let len = b.write_varint(stream::QPACK_DECODER_STREAM_TYPE).unwrap();
        bytes.truncate(len);

        s.pair
            .client
            .stream_write(s.client.next_uni_stream_id, bytes.freeze(), false)
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.server_poll(), Err(Http3Error::StreamCreationError));
    }

    // Server try to open multiple QPACK encoder streams.
    #[test]
    fn server_open_multiple_qpack_encoder_streams() {
        let mut s = Session::new().unwrap();

        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        let len = b.write_varint(stream::QPACK_ENCODER_STREAM_TYPE).unwrap();
        bytes.truncate(len);

        s.pair
            .server
            .stream_write(s.server.next_uni_stream_id, bytes.freeze(), false)
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.client_poll(), Err(Http3Error::StreamCreationError));
    }

    // Server try to open multiple QPACK decoder streams.
    #[test]
    fn server_open_multiple_qpack_decoder_streams() {
        let mut s = Session::new().unwrap();

        let mut bytes = BytesMut::zeroed(8);
        let mut b = bytes.as_mut();

        let len = b.write_varint(stream::QPACK_DECODER_STREAM_TYPE).unwrap();
        bytes.truncate(len);

        s.pair
            .server
            .stream_write(s.server.next_uni_stream_id, bytes.freeze(), false)
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.client_poll(), Err(Http3Error::StreamCreationError));
    }

    // Client close QPACK encoder stream.
    #[test]
    fn client_close_qpack_encoder_stream() {
        let mut s = Session::new().unwrap();

        s.pair
            .client
            .stream_write(
                s.client.local_qpack_streams.encoder_stream_id.unwrap(),
                Bytes::new(),
                true,
            )
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.server_poll(), Err(Http3Error::ClosedCriticalStream));
    }

    // Client close QPACK decoder stream.
    #[test]
    fn client_close_qpack_decoder_stream() {
        let mut s = Session::new().unwrap();

        s.pair
            .client
            .stream_write(
                s.client.local_qpack_streams.decoder_stream_id.unwrap(),
                Bytes::new(),
                true,
            )
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.server_poll(), Err(Http3Error::ClosedCriticalStream));
    }

    // Server close QPACK encoder stream.
    #[test]
    fn server_close_qpack_encoder_stream() {
        let mut s = Session::new().unwrap();

        s.pair
            .server
            .stream_write(
                s.server.local_qpack_streams.encoder_stream_id.unwrap(),
                Bytes::new(),
                true,
            )
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.client_poll(), Err(Http3Error::ClosedCriticalStream));
    }

    // Server close QPACK decoder stream.
    #[test]
    fn server_close_qpack_decoder_stream() {
        let mut s = Session::new().unwrap();

        s.pair
            .server
            .stream_write(
                s.server.local_qpack_streams.decoder_stream_id.unwrap(),
                Bytes::new(),
                true,
            )
            .unwrap();

        s.move_forward().ok();
        assert_eq!(s.client_poll(), Err(Http3Error::ClosedCriticalStream));
    }

    // Process_streams without register http3 event handler.
    #[test]
    fn process_streams_without_register_handler() {
        let mut s = Session::new().unwrap();

        assert!(s.client.process_streams(&mut s.pair.client).is_ok());
        assert!(s.server.process_streams(&mut s.pair.server).is_ok());
    }

    // Process_streams without data.
    #[test]
    fn process_streams_without_data() {
        let mut s = Session::new().unwrap();

        // Client send a request without body.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        assert_eq!(stream_id, 0);

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        let server_handler = Arc::new(TestHttp3Handler {
            headers: Some(headers_event),
            data: None,
        });
        s.server.set_events_handler(server_handler.clone());

        // Server process_streams, events: headers + finished.
        assert!(s.server.process_streams(&mut s.pair.server).is_ok());
        assert!(s.server.process_streams(&mut s.pair.server).is_ok());

        // Server send a response without body.
        let resp_headers = s.send_response(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        let client_handler = Arc::new(TestHttp3Handler {
            headers: Some(headers_event),
            data: None,
        });
        s.client.set_events_handler(client_handler.clone());

        // Client process_streams, events: headers + finished.
        assert!(s.client.process_streams(&mut s.pair.client).is_ok());
        assert!(s.client.process_streams(&mut s.pair.client).is_ok());
    }

    // Process_streams with data.
    #[test]
    fn process_streams_with_data() {
        let mut s = Session::new().unwrap();

        // Client send a request with body.
        let (stream_id, req_headers) = s.send_request(false).unwrap();
        assert_eq!(stream_id, 0);
        let req_body = s.client_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        let server_handler = Arc::new(TestHttp3Handler {
            headers: Some(headers_event),
            data: Some(req_body),
        });
        s.server.set_events_handler(server_handler.clone());

        // Server process_streams, events: headers + data + finished.
        assert!(s.server.process_streams(&mut s.pair.server).is_ok());
        assert!(s.server.process_streams(&mut s.pair.server).is_ok());

        // Server send a response with body.
        let resp_headers = s.send_response(stream_id, false).unwrap();
        let resp_body = s.server_send_body(stream_id, true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: false,
        };

        let client_handler = Arc::new(TestHttp3Handler {
            headers: Some(headers_event),
            data: Some(resp_body),
        });
        s.client.set_events_handler(client_handler.clone());

        // Client process_streams, events: headers + data + finished.
        assert!(s.client.process_streams(&mut s.pair.client).is_ok());
        assert!(s.client.process_streams(&mut s.pair.client).is_ok());
    }

    // Client or server try to close a non-exist stream.
    #[test]
    fn close_no_exist_stream() {
        let mut s = Session::new().unwrap();

        for stream_id in [0, 4, 8] {
            assert_eq!(s.client.stream_close(&mut s.pair.client, stream_id), Ok(()));
            assert_eq!(s.server.stream_close(&mut s.pair.server, stream_id), Ok(()));
        }
    }

    // Client or server try to close non-request stream.
    #[test]
    fn close_non_request_stream() {
        let mut s = Session::new().unwrap();

        for stream_id in [1, 2, 3] {
            assert_eq!(
                s.client.stream_close(&mut s.pair.client, stream_id),
                Err(Http3Error::InternalError)
            );
            assert_eq!(
                s.server.stream_close(&mut s.pair.server, stream_id),
                Err(Http3Error::InternalError)
            );
        }
    }

    // Client close request before server consume any data from quic stream buffer.
    #[test]
    fn client_close_request_before_server_consume_any_quic_buffer_data() {
        let mut s = Session::new().unwrap();

        // Subcase1: Client send request headers without FIN flag.
        let (stream_id, _req_headers) = s.send_request(false).unwrap();

        // Client close request in advance, which will trigger a RESET_STREAM frame and a STOP_SENDING frame.
        assert_eq!(s.client.stream_close(&mut s.pair.client, stream_id), Ok(()));
        s.pair.move_forward().ok();

        // Server report just a Reset event.
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Reset(0))));
        assert!(!s.pair.server.stream_readable(stream_id));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
        assert_eq!(
            s.send_response(stream_id, true),
            Err(Http3Error::TransportError(crate::Error::StreamStateError))
        );

        // Subcase2: Client send request headers with FIN flag.
        let (stream_id, req_headers) = s.send_request(true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // Client close request in advance, which will trigger a STOP_SENDING frame.
        assert_eq!(s.client.stream_close(&mut s.pair.client, stream_id), Ok(()));
        s.pair.move_forward().ok();

        // Server report headers event with FIN flag.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
        assert_eq!(
            s.send_response(stream_id, true),
            Err(Http3Error::TransportError(crate::Error::StreamStateError))
        );
    }

    // Server close request before client consume any data from quic stream buffer.
    #[test]
    fn server_close_request_before_client_consume_any_quic_buffer_data() {
        let mut s = Session::new().unwrap();

        // Subcase1: Client send request headers without FIN flag, and server send response headers without FIN flag.
        let (stream_id, req_headers) = s.send_request(false).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: false,
        };

        // Server receive headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response without FIN flag.
        s.send_response(stream_id, false).unwrap();

        // Server close request in advance, which will trigger a RESET_STREAM frame and a STOP_SENDING frame.
        assert_eq!(s.server.stream_close(&mut s.pair.server, stream_id), Ok(()));
        s.pair.move_forward().ok();

        // Client report just a Reset event.
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Reset(0))));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Subcase2: Client send request headers with FIN flag, and server send response without FIN flag.
        let (stream_id, req_headers) = s.send_request(true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // Server receive headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response without FIN flag, which will trigger a RESET_STREAM frame.
        s.send_response(stream_id, false).unwrap();

        // Server close request, which will trigger a RESET_STREAM frame frame.
        assert_eq!(s.server.stream_close(&mut s.pair.server, stream_id), Ok(()));
        s.pair.move_forward().ok();

        // Client report just a Reset event.
        assert_eq!(s.client_poll(), Ok((stream_id, Http3Event::Reset(0))));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Subcase3: Client send request headers with FIN flag, and Server send response with FIN flag.
        let (stream_id, req_headers) = s.send_request(true).unwrap();

        let headers_event = Http3Event::Headers {
            headers: req_headers,
            fin: true,
        };

        // Server receive headers.
        assert_eq!(s.server_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Ok((stream_id, Http3Event::Finished)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));

        // Server send response with FIN flag.
        let resp_headers = s.send_response(stream_id, true).unwrap();
        let headers_event = Http3Event::Headers {
            headers: resp_headers,
            fin: true,
        };

        // Server close request, which should not trigger RESET_STREAM or STOP_SENDING frame frame.
        assert_eq!(s.server.stream_close(&mut s.pair.server, stream_id), Ok(()));
        s.pair.move_forward().ok();

        // Client report headers event with FIN flag.
        assert_eq!(s.client_poll(), Ok((stream_id, headers_event)));
        assert_eq!(s.server_poll(), Err(Http3Error::Done));
    }
}
