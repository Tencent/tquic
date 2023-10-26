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

//! Implementation of HTTP/3 and QPACK.

use std::fmt;
use std::fmt::Write;

/// Result type for HTTP/3 operations.
pub type Result<T> = std::result::Result<T, Http3Error>;

/// An HTTP/3 configuration.
#[derive(Default)]
pub struct Http3Config {
    /// A limit on the maximum size of the message header an endpoint will
    /// accept on an individual HTTP message.
    max_field_section_size: Option<u64>,

    /// The decoder limits the maximum value the encoder is permitted to set
    /// for the dynamic table capacity.
    qpack_max_table_capacity: Option<u64>,

    /// The decoder specifies an upper bound on the number of streams that
    /// can be blocked using the SETTINGS_QPACK_BLOCKED_STREAMS setting.
    qpack_blocked_streams: Option<u64>,
}

impl Http3Config {
    /// Create default HTTP/3 configuration.
    pub const fn new() -> Result<Http3Config> {
        Ok(Http3Config {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
        })
    }

    /// Set the `SETTINGS_MAX_FIELD_SECTION_SIZE` setting.
    /// The default value is unlimited.
    pub fn set_max_field_section_size(&mut self, v: u64) {
        self.max_field_section_size = Some(v);
    }

    /// Set the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` setting.
    /// The default value is `0`.
    pub fn set_qpack_max_table_capacity(&mut self, v: u64) {
        self.qpack_max_table_capacity = Some(v);
    }

    /// Set the `SETTINGS_QPACK_BLOCKED_STREAMS` setting.
    /// The default value is `0`.
    pub fn set_qpack_blocked_streams(&mut self, v: u64) {
        self.qpack_blocked_streams = Some(v);
    }
}

/// An HTTP/3 connection event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Http3Event {
    /// HTTP/3 headers were received on request stream.
    Headers {
        /// HTTP/3 header fields are represented as a list of name-value pairs.
        /// Note that the application is responsible for validating the headers.
        headers: Vec<Header>,

        /// Whether the stream consists of only headers and no data.
        fin: bool,
    },

    /// Data was received on a request or push stream.
    ///
    /// Note that `Data` event was edge-triggered, so the application must try to
    /// read all data from the stream until `Done` value is returned.
    Data,

    /// Stream's read side is finished.
    ///
    /// Note that the stream's write side may still be open.
    Finished,

    /// RESET_STREAM was received from the peer.
    ///
    /// The error code received from the peer is provided as a associated data.
    Reset(u64),

    /// GOAWAY was received from the peer.
    GoAway,

    /// PRIORITY_UPDATE was received from the peer.
    ///
    /// Note that `PriorityUpdate` event was edge-triggered, it will not be triggered
    /// again until the last PRIORITY_UPDATE has been read.
    PriorityUpdate,
}

/// An HTTP/3 header list.
pub struct Http3Headers<'a> {
    pub(crate) headers: &'a Vec<Header>,
}

/// A trait for types with name and value.
pub trait NameValue {
    /// Return the name.
    fn name(&self) -> &[u8];

    /// Return the value.
    fn value(&self) -> &[u8];
}

impl NameValue for (&[u8], &[u8]) {
    fn name(&self) -> &[u8] {
        self.0
    }

    fn value(&self) -> &[u8] {
        self.1
    }
}

/// A raw HTTP header with owned name-value pair.
#[derive(Clone, PartialEq, Eq)]
pub struct Header(Vec<u8>, Vec<u8>);

impl Header {
    pub fn new(name: &[u8], value: &[u8]) -> Self {
        Self(name.to_vec(), value.to_vec())
    }
}

impl NameValue for Header {
    fn name(&self) -> &[u8] {
        &self.0
    }

    fn value(&self) -> &[u8] {
        &self.1
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('"')?;
        fmt_readable(&self.0, f)?;
        f.write_str(": ")?;
        fmt_readable(&self.1, f)?;
        f.write_char('"')
    }
}

fn fmt_readable(hdr: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    match std::str::from_utf8(hdr) {
        Ok(s) => f.write_str(&s.escape_default().to_string()),
        Err(_) => write!(f, "{hdr:?}"),
    }
}

/// A raw HTTP header with non-owned name-value pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRef<'a>(&'a [u8], &'a [u8]);

impl<'a> HeaderRef<'a> {
    pub const fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self(name, value)
    }
}

impl<'a> NameValue for HeaderRef<'a> {
    fn name(&self) -> &[u8] {
        self.0
    }

    fn value(&self) -> &[u8] {
        self.1
    }
}

/// The Http3Handler lists the callbacks used by the Http3Connection to
/// communicate with the user application code.
pub trait Http3Handler {
    /// Called when the stream got headers.
    fn on_stream_headers(&self, stream_id: u64, event: &mut Http3Event);

    /// Called when the stream has buffered data to read.
    fn on_stream_data(&self, stream_id: u64);

    /// Called when the stream is finished.
    fn on_stream_finished(&self, stream_id: u64);

    /// Called when the stream receives a RESET_STREAM frame from the peer.
    fn on_stream_reset(&self, stream_id: u64, error_code: u64);

    /// Called when the stream priority is updated.
    fn on_stream_priority_update(&self, stream_id: u64);

    /// Called when the connection receives a GOAWAY frame from the peer.
    fn on_conn_goaway(&self, stream_id: u64);
}

pub use error::Http3Error;

#[path = "qpack/qpack.rs"]
mod qpack;

pub mod connection;
mod error;
mod frame;
mod stream;
