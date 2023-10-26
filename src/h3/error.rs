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

use std::fmt;
use std::fmt::Write;

/// An HTTP/3 error.
/// See RFC 9114 and RFC 9204.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Http3Error {
    /// This is used when the connection or stream needs to be closed, but there
    /// is no error to signal.
    NoError,

    /// Peer violated protocol requirements in a way that does not match a more
    /// specific error code or endpoint declines to use the more specific error
    /// code.
    GeneralProtocolError,

    /// An internal error has occurred in the HTTP stack.
    InternalError,

    /// The endpoint detected that its peer created a stream that it will not
    /// accept.
    StreamCreationError,

    /// A stream required by the HTTP/3 connection was closed or reset.
    ClosedCriticalStream,

    /// A frame was received that was not permitted in the current state or on
    /// the current stream.
    FrameUnexpected,

    /// A frame that fails to satisfy layout requirements or with an invalid
    /// size was received.
    FrameError,

    /// The endpoint detected that its peer is exhibiting a behavior that might
    /// be generating excessive load.
    ExcessiveLoad,

    /// A stream ID or push ID was used incorrectly, such as exceeding a limit,
    /// reducing a limit, or being reused.
    IdError,

    /// An endpoint detected an error in the payload of a SETTINGS frame.
    SettingsError,

    /// No SETTINGS frame was received at the beginning of the control stream.
    MissingSettings,

    /// A server rejected a request without performing any application
    /// processing.
    RequestRejected,

    /// The request or its response (including pushed response) is cancelled.
    RequestCancelled,

    /// The client's stream terminated without containing a fully formed request.
    RequestIncomplete,

    /// An HTTP message was malformed and cannot be processed.
    MessageError,

    /// The TCP connection established in response to a CONNECT request was
    /// reset or abnormally closed.
    ConnectError,

    /// The requested operation cannot be served over HTTP/3. The peer should
    /// retry over HTTP/1.1.
    VersionFallback,

    /// The decoder failed to interpret an encoded field section and is not
    /// able to continue decoding that field section.
    QpackDecompressionFailed,

    /// The decoder failed to interpret an encoder instruction received on the
    /// encoder stream.
    QpackEncoderStreamError,

    /// The encoder failed to interpret a decoder instruction received on the
    /// decoder stream.
    QpackDecoderStreamError,

    /* Note: Private error codes are as follows */
    /// Error originated from the transport layer.
    TransportError(crate::Error),

    /// The stream is blocked by flow control, may be stream or connection level.
    /// The application can retry later or do other appropriate actions.
    StreamBlocked,

    /// There is no error or no work to do
    Done,
}

impl Http3Error {
    pub fn to_wire(&self) -> u64 {
        match self {
            Http3Error::NoError => 0x100,
            Http3Error::GeneralProtocolError => 0x101,
            Http3Error::InternalError => 0x102,
            Http3Error::StreamCreationError => 0x103,
            Http3Error::ClosedCriticalStream => 0x104,
            Http3Error::FrameUnexpected => 0x105,
            Http3Error::FrameError => 0x106,
            Http3Error::ExcessiveLoad => 0x107,
            Http3Error::IdError => 0x108,
            Http3Error::SettingsError => 0x109,
            Http3Error::MissingSettings => 0x10A,
            Http3Error::RequestRejected => 0x10B,
            Http3Error::RequestCancelled => 0x10C,
            Http3Error::RequestIncomplete => 0x10D,
            Http3Error::MessageError => 0x10E,
            Http3Error::ConnectError => 0x10F,
            Http3Error::VersionFallback => 0x110,
            Http3Error::QpackDecompressionFailed => 0x200,
            Http3Error::QpackEncoderStreamError => 0x201,
            Http3Error::QpackDecoderStreamError => 0x202,
            Http3Error::TransportError { .. } => 0x102,
            Http3Error::StreamBlocked => 0x102,
            Http3Error::Done { .. } => 0x102,
        }
    }

    #[cfg(feature = "ffi")]
    pub(crate) fn to_c(self) -> libc::ssize_t {
        match self {
            Http3Error::NoError => 0,
            Http3Error::Done => -1,
            Http3Error::GeneralProtocolError => -2,
            Http3Error::InternalError => -3,
            Http3Error::StreamCreationError => -4,
            Http3Error::ClosedCriticalStream => -5,
            Http3Error::FrameUnexpected => -6,
            Http3Error::FrameError => -7,
            Http3Error::ExcessiveLoad => -8,
            Http3Error::IdError => -9,
            Http3Error::SettingsError => -10,
            Http3Error::MissingSettings => -11,
            // -12 reserved
            Http3Error::StreamBlocked => -13,
            Http3Error::RequestRejected => -14,
            Http3Error::RequestCancelled => -15,
            Http3Error::RequestIncomplete => -16,
            Http3Error::MessageError => -17,
            Http3Error::ConnectError => -18,
            Http3Error::VersionFallback => -19,
            Http3Error::QpackDecompressionFailed => -20,
            Http3Error::QpackEncoderStreamError => -21,
            Http3Error::QpackDecoderStreamError => -22,

            Http3Error::TransportError(quic_error) => quic_error.to_c() - 1000,
        }
    }
}

impl std::fmt::Display for Http3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Http3Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<crate::error::Error> for Http3Error {
    fn from(err: crate::error::Error) -> Self {
        match err {
            crate::error::Error::Done => Http3Error::Done,
            _ => Http3Error::TransportError(err),
        }
    }
}
