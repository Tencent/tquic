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

//! Error type for quic operations.

use crate::frame::Frame;

use strum::IntoEnumIterator;
use strum_macros::EnumIter;

/// QUIC transport error.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug, Default, PartialEq, Eq, EnumIter)]
pub enum Error {
    /// An endpoint uses this with CONNECTION_CLOSE to signal that the
    /// connection is being closed abruptly in the absence of any error.
    #[default]
    NoError,

    /// The endpoint encountered an internal error and cannot continue with the
    /// connection
    InternalError,

    /// The server refused to accept a new connection.
    ConnectionRefused,

    /// An endpoint received more data than it permitted in its advertised data
    /// limits
    FlowControlError,

    /// An endpoint received a frame for a stream identifier that exceeded its
    /// advertised stream limit for the corresponding stream type
    StreamLimitError,

    /// An endpoint received a frame for a stream that was not in a state that
    /// permitted that frame;
    StreamStateError,

    /// (1) An endpoint received a STREAM frame containing data that exceeded
    /// the previously established final size,
    /// (2) an endpoint received a STREAM frame or a RESET_STREAM frame
    /// containing a final size that was lower than the size of stream data
    /// that was already received, or
    /// (3) an endpoint received a STREAM frame or a RESET_STREAM frame
    /// containing a different final size to the one already established.
    FinalSizeError,

    /// An endpoint received a frame that was badly formatted -- for instance,
    /// a frame of an unknown type or an ACK frame that has more acknowledgment
    /// ranges than the remainder of the packet could carry.
    FrameEncodingError,

    /// An endpoint received transport parameters that were badly formatted,
    /// included an invalid value, omitted a mandatory transport parameter,
    /// included a forbidden transport parameter, or were otherwise in error.
    TransportParameterError,

    /// The number of connection IDs provided by the peer exceeds the advertised
    /// active_connection_id_limit.
    ConnectionIdLimitError,

    /// An endpoint detected an error with protocol compliance that was not
    /// covered by more specific error codes.
    ProtocolViolation,

    /// A server received a client Initial that contained an invalid Token field.
    InvalidToken,

    /// The application or application protocol caused the connection to be
    /// closed.
    ApplicationError,

    /// An endpoint has received more data in CRYPTO frames than it can buffer.
    CryptoBufferExceeded,

    /// An endpoint detected errors in performing key updates.
    KeyUpdateError,

    /// An endpoint has reached the confidentiality or integrity limit for the
    /// AEAD algorithm used by the given connection.
    AeadLimitReached,

    /// An endpoint has determined that the network path is incapable of
    /// supporting QUIC. An endpoint is unlikely to receive a CONNECTION_CLOSE
    /// frame carrying this code except when the path does not support a large
    /// enough MTU.
    NoViablePath,

    /// The cryptographic handshake failed. A range of 256 values is reserved
    /// for carrying error codes specific to the cryptographic handshake.
    CryptoError(u8),

    /// An endpoint detected a multipath error with protocol compliance that
    /// was not covered by more specific error codes.
    MultipathProtocolViolation,

    /* Note: Private error codes are as follows */
    /// There is no more work to do.
    Done,

    /// The provided buffer is too short.
    BufferTooShort,

    /// The provided packet cannot be parsed because its version is unknown.
    UnknownVersion,

    /// The provided packet cannot be parsed.
    InvalidPacket,

    /// The operation cannot be completed because it was attempted in an
    /// invalid state.
    InvalidState(String),

    /// The operation on the connection is invalid.
    InvalidOperation(String),

    /// The configuration is invalid.
    InvalidConfig(String),

    /// A server received a client Initial that contained an expired Token.
    ExpiredToken,

    /// A cryptographic operation failed.
    CryptoFail,

    /// The TLS handshake failed.
    TlsFail(String),

    /// The specified stream was stopped by the peer.
    ///
    /// The error code sent as part of the `STOP_SENDING` frame is provided as
    /// associated data.
    StreamStopped(u64),

    /// The specified stream was reset by the peer.
    ///
    /// The error code sent as part of the `RESET_STREAM` frame is provided as
    /// associated data.
    StreamReset(u64),

    /// I/O error.
    IoError(String),
}

impl Error {
    /// Return the wire value of the error.
    /// See RFC 9000 Section 22.5
    pub(crate) fn to_wire(&self) -> u64 {
        match *self {
            Error::NoError => 0x0,
            Error::InternalError => 0x1,
            Error::ConnectionRefused => 0x2,
            Error::FlowControlError => 0x3,
            Error::StreamLimitError => 0x4,
            Error::StreamStateError => 0x5,
            Error::FinalSizeError => 0x6,
            Error::FrameEncodingError => 0x7,
            Error::TransportParameterError => 0x8,
            Error::ConnectionIdLimitError => 0x9,
            Error::ProtocolViolation => 0x0a,
            Error::InvalidToken => 0x0b,
            Error::ApplicationError => 0x0c,
            Error::CryptoBufferExceeded => 0x0d,
            Error::KeyUpdateError => 0x0e,
            Error::AeadLimitReached => 0x0f,
            Error::NoViablePath => 0x10,
            Error::CryptoError(v) => v as u64,
            Error::MultipathProtocolViolation => 0x1001d76d3ded42f3,
            _ => 0x0,
        }
    }

    /// Return the error number using by the C caller.
    pub(crate) fn to_errno(&self) -> libc::ssize_t {
        match self {
            Error::NoError => 0,
            Error::InternalError => -1,
            Error::ConnectionRefused => -2,
            Error::FlowControlError => -3,
            Error::StreamLimitError => -4,
            Error::StreamStateError => -5,
            Error::FinalSizeError => -6,
            Error::FrameEncodingError => -7,
            Error::TransportParameterError => -8,
            Error::ConnectionIdLimitError => -9,
            Error::ProtocolViolation => -10,
            Error::InvalidToken => -11,
            Error::ApplicationError => -12,
            Error::CryptoBufferExceeded => -13,
            Error::KeyUpdateError => -14,
            Error::AeadLimitReached => -15,
            Error::NoViablePath => -16,
            Error::CryptoError(_) => -17,
            Error::MultipathProtocolViolation => -18,
            Error::Done => -100,
            Error::BufferTooShort => -101,
            Error::UnknownVersion => -102,
            Error::InvalidPacket => -103,
            Error::InvalidState(_) => -104,
            Error::InvalidOperation(_) => -105,
            Error::InvalidConfig(_) => -106,
            Error::ExpiredToken => -107,
            Error::CryptoFail => -108,
            Error::TlsFail(_) => -109,
            Error::StreamStopped(_) => -110,
            Error::StreamReset(_) => -111,
            Error::IoError(_) => -112,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(format!("{}", err))
    }
}

/// Represents information carried by `CONNECTION_CLOSE` frames.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionError {
    /// Whether the error came from the application or the QUIC layer.
    pub is_app: bool,

    /// Indicates the reason for closing this connection.
    pub error_code: u64,

    /// Frame type that triggered the error.
    pub frame: Option<Frame>,

    /// Additional diagnostic information.
    pub reason: Vec<u8>,
}

impl std::fmt::Debug for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "is_app={:?} ", self.is_app)?;
        write!(f, "error_code={:?} ", self.error_code)?;
        match std::str::from_utf8(&self.reason) {
            Ok(v) => write!(f, "reason={:?}", v)?,
            Err(_) => write!(f, "reason={:?}", self.reason)?,
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error::IoError;

    #[test]
    fn error_to_wire() {
        let mut found_internal_err = false;
        for err in Error::iter() {
            if err == Error::NoError {
                assert!(err.to_wire() == 0);
                continue;
            }
            if err == Error::Done {
                found_internal_err = true;
            }
            if found_internal_err {
                assert_eq!(err.to_wire(), 0);
                continue;
            }
            if let Error::CryptoError(_) = err {
                assert_eq!(err.to_wire(), 0);
            } else {
                assert!(err.to_wire() > 0);
            }
        }
    }

    #[test]
    fn error_to_errno() {
        for err in Error::iter() {
            if err == Error::NoError {
                assert_eq!(err.to_errno(), 0);
            } else {
                assert!(err.to_errno() < 0);
            }
        }
    }

    #[test]
    fn io_error() {
        use std::error::Error;
        let e = std::io::Error::from(std::io::ErrorKind::UnexpectedEof);
        let e = super::Error::from(e);

        assert_eq!(format!("{}", e), "IoError(\"unexpected end of file\")");
        assert!(e.source().is_none());
    }

    #[test]
    fn connection_error() {
        let e = ConnectionError {
            is_app: false,
            error_code: 0,
            frame: None,
            reason: vec![],
        };
        assert_eq!(format!("{:?}", e), "is_app=false error_code=0 reason=\"\"");

        let e = ConnectionError {
            is_app: true,
            error_code: 1,
            frame: None,
            reason: vec![0x97, 0x61, 0x6C],
        };
        assert_eq!(
            format!("{:?}", e),
            "is_app=true error_code=1 reason=[151, 97, 108]"
        );
    }
}
