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

use crate::codec;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::h3::Http3Error;
use crate::h3::Result;

pub const DATA_FRAME_TYPE: u64 = 0x0;
pub const HEADERS_FRAME_TYPE: u64 = 0x1;
pub const CANCEL_PUSH_FRAME_TYPE: u64 = 0x3;
pub const SETTINGS_FRAME_TYPE: u64 = 0x4;
pub const PUSH_PROMISE_FRAME_TYPE: u64 = 0x5;
pub const GOAWAY_FRAME_TYPE: u64 = 0x7;
pub const MAX_PUSH_ID_FRAME_TYPE: u64 = 0xD;
pub const PRIORITY_UPDATE_FRAME_REQUEST_TYPE: u64 = 0xF0700;
pub const PRIORITY_UPDATE_FRAME_PUSH_TYPE: u64 = 0xF0701;

pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;

const MAX_SETTINGS_PAYLOAD_SIZE: u64 = 256;

#[derive(Clone, PartialEq, Eq)]
pub enum Http3Frame {
    /// DATA frames (type=0x00) convey arbitrary, variable-length sequences of
    /// bytes associated with HTTP request or response content.
    Data { data: Vec<u8> },

    /// The HEADERS frame (type=0x01) is used to carry an HTTP field section
    /// that is encoded using QPACK.
    Headers { field_section: Vec<u8> },

    /// The CANCEL_PUSH frame (type=0x03) is used to request cancellation of
    /// a server push prior to the push stream being received.
    CancelPush { push_id: u64 },

    /// The SETTINGS frame (type=0x04) conveys configuration parameters that
    /// affect how endpoints communicate, such as preferences and constraints
    /// on peer behavior.
    Settings {
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        connect_protocol_enabled: Option<u64>,
        raw: Option<Vec<(u64, u64)>>,
    },

    /// The PUSH_PROMISE frame (type=0x05) is used to carry a promised request
    /// header section from server to client on a request stream.
    PushPromise {
        push_id: u64,
        field_section: Vec<u8>,
    },

    /// The GOAWAY frame (type=0x07) is used to initiate graceful shutdown of
    /// an HTTP/3 connection by either endpoint.
    GoAway { id: u64 },

    /// The MAX_PUSH_ID frame (type=0x0d) is used by clients to control the
    /// number of server pushes that the server can initiate.
    MaxPushId { push_id: u64 },

    /// The HTTP/3 PRIORITY_UPDATE frame (type=0xF0700) is used by clients to
    /// signal the initial priority of a response, or to reprioritize a response.
    PriorityUpdateRequest {
        prioritized_element_id: u64,
        priority_field_value: Vec<u8>,
    },

    /// The HTTP/3 PRIORITY_UPDATE frame (type=0xF0701) is used by clients to
    /// reprioritize a push stream.
    PriorityUpdatePush {
        prioritized_element_id: u64,
        priority_field_value: Vec<u8>,
    },

    /// Implementations MUST ignore unknown or unsupported values in all
    /// extensible protocol elements.
    Unknown { raw_type: u64, payload_length: u64 },
}

impl Http3Frame {
    /// Encode an HTTP/3 frame.
    pub fn encode(&self, mut b: &mut [u8]) -> Result<usize> {
        let len = b.len();

        match self {
            Http3Frame::Data { data } => {
                b.write_varint(DATA_FRAME_TYPE)?;
                b.write_varint(data.len() as u64)?;
                b.write(data.as_ref())?;
            }

            Http3Frame::Headers { field_section } => {
                b.write_varint(HEADERS_FRAME_TYPE)?;
                b.write_varint(field_section.len() as u64)?;
                b.write(field_section.as_ref())?;
            }

            Http3Frame::CancelPush { push_id } => {
                b.write_varint(CANCEL_PUSH_FRAME_TYPE)?;
                b.write_varint(codec::encode_varint_len(*push_id) as u64)?;
                b.write_varint(*push_id)?;
            }

            Http3Frame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                connect_protocol_enabled,
                ..
            } => {
                let len = Self::encode_settings_frame(
                    *max_field_section_size,
                    *qpack_max_table_capacity,
                    *qpack_blocked_streams,
                    *connect_protocol_enabled,
                    b,
                )?;
                b = &mut b[len..];
            }

            Http3Frame::PushPromise {
                push_id,
                field_section,
            } => {
                let len = codec::encode_varint_len(*push_id) + field_section.len();
                b.write_varint(PUSH_PROMISE_FRAME_TYPE)?;
                b.write_varint(len as u64)?;
                b.write_varint(*push_id)?;
                b.write(field_section.as_ref())?;
            }

            Http3Frame::GoAway { id } => {
                b.write_varint(GOAWAY_FRAME_TYPE)?;
                b.write_varint(codec::encode_varint_len(*id) as u64)?;
                b.write_varint(*id)?;
            }

            Http3Frame::MaxPushId { push_id } => {
                b.write_varint(MAX_PUSH_ID_FRAME_TYPE)?;
                b.write_varint(codec::encode_varint_len(*push_id) as u64)?;
                b.write_varint(*push_id)?;
            }

            Http3Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                let len =
                    codec::encode_varint_len(*prioritized_element_id) + priority_field_value.len();
                b.write_varint(PRIORITY_UPDATE_FRAME_REQUEST_TYPE)?;
                b.write_varint(len as u64)?;
                b.write_varint(*prioritized_element_id)?;
                b.write(priority_field_value)?;
            }

            Http3Frame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                let len =
                    codec::encode_varint_len(*prioritized_element_id) + priority_field_value.len();
                b.write_varint(PRIORITY_UPDATE_FRAME_PUSH_TYPE)?;
                b.write_varint(len as u64)?;
                b.write_varint(*prioritized_element_id)?;
                b.write(priority_field_value)?;
            }

            Http3Frame::Unknown { .. } => unreachable!(),
        }

        Ok(len - b.len())
    }

    /// Decode an HTTP/3 frame.
    pub fn decode(mut buf: &[u8]) -> Result<Http3Frame> {
        let frame_type = buf.read_varint()?;
        let payload_length = buf.read_varint()?;
        Self::decode_payload(frame_type, payload_length, buf)
    }

    /// Decode the payload of an HTTP/3 frame.
    ///
    /// Note: It is recommended to read the payload of the DATA frame
    /// directly through the QUIC stream API instead of `decode_payload()`
    pub fn decode_payload(
        frame_type: u64,
        payload_length: u64,
        mut buf: &[u8],
    ) -> Result<Http3Frame> {
        let frame = match frame_type {
            DATA_FRAME_TYPE => Http3Frame::Data {
                data: buf.read(payload_length as usize)?,
            },

            HEADERS_FRAME_TYPE => Http3Frame::Headers {
                field_section: buf.read(payload_length as usize)?,
            },

            CANCEL_PUSH_FRAME_TYPE => Http3Frame::CancelPush {
                push_id: buf.read_varint()?,
            },

            SETTINGS_FRAME_TYPE => Self::decode_settings_frame(payload_length, buf)?,

            PUSH_PROMISE_FRAME_TYPE => Self::decode_push_promise(payload_length, buf)?,

            GOAWAY_FRAME_TYPE => Http3Frame::GoAway {
                id: buf.read_varint()?,
            },

            MAX_PUSH_ID_FRAME_TYPE => Http3Frame::MaxPushId {
                push_id: buf.read_varint()?,
            },

            PRIORITY_UPDATE_FRAME_REQUEST_TYPE | PRIORITY_UPDATE_FRAME_PUSH_TYPE => {
                Self::decode_priority_update(frame_type, payload_length, buf)?
            }

            _ => Http3Frame::Unknown {
                raw_type: frame_type,
                payload_length,
            },
        };

        Ok(frame)
    }

    /// Encode the HTTP/3 Settings frame.
    fn encode_settings_frame(
        max_field_section_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
        connect_protocol_enabled: Option<u64>,
        mut buf: &mut [u8],
    ) -> Result<usize> {
        let buf_len = buf.len();

        // calculate length of the settings frame
        let mut frame_len = 0;
        if let Some(val) = max_field_section_size {
            frame_len += codec::encode_varint_len(SETTINGS_MAX_FIELD_SECTION_SIZE);
            frame_len += codec::encode_varint_len(val);
        }
        if let Some(val) = qpack_max_table_capacity {
            frame_len += codec::encode_varint_len(SETTINGS_QPACK_MAX_TABLE_CAPACITY);
            frame_len += codec::encode_varint_len(val);
        }
        if let Some(val) = qpack_blocked_streams {
            frame_len += codec::encode_varint_len(SETTINGS_QPACK_BLOCKED_STREAMS);
            frame_len += codec::encode_varint_len(val);
        }
        if let Some(val) = connect_protocol_enabled {
            frame_len += codec::encode_varint_len(SETTINGS_ENABLE_CONNECT_PROTOCOL);
            frame_len += codec::encode_varint_len(val);
        }

        // write the type/length/payload fields
        buf.write_varint(SETTINGS_FRAME_TYPE)?;
        buf.write_varint(frame_len as u64)?;
        if let Some(val) = max_field_section_size {
            buf.write_varint(SETTINGS_MAX_FIELD_SECTION_SIZE)?;
            buf.write_varint(val)?;
        }
        if let Some(val) = qpack_max_table_capacity {
            buf.write_varint(SETTINGS_QPACK_MAX_TABLE_CAPACITY)?;
            buf.write_varint(val)?;
        }
        if let Some(val) = qpack_blocked_streams {
            buf.write_varint(SETTINGS_QPACK_BLOCKED_STREAMS)?;
            buf.write_varint(val)?;
        }
        if let Some(val) = connect_protocol_enabled {
            buf.write_varint(SETTINGS_ENABLE_CONNECT_PROTOCOL)?;
            buf.write_varint(val)?;
        }

        Ok(buf_len - buf.len())
    }

    /// Parse payload of an HTTP/3 SETTINGS frame.
    fn decode_settings_frame(payload_length: u64, mut b: &[u8]) -> Result<Http3Frame> {
        if payload_length > MAX_SETTINGS_PAYLOAD_SIZE {
            return Err(Http3Error::ExcessiveLoad);
        }

        let mut max_field_section_size = None;
        let mut qpack_max_table_capacity = None;
        let mut qpack_blocked_streams = None;
        let mut connect_protocol_enabled = None;
        let mut raw = Vec::new();

        while !b.is_empty() {
            let identifier = b.read_varint()?;
            let value = b.read_varint()?;
            raw.push((identifier, value));

            match identifier {
                SETTINGS_MAX_FIELD_SECTION_SIZE => {
                    max_field_section_size = Some(value);
                }
                SETTINGS_QPACK_MAX_TABLE_CAPACITY => {
                    qpack_max_table_capacity = Some(value);
                }
                SETTINGS_QPACK_BLOCKED_STREAMS => {
                    qpack_blocked_streams = Some(value);
                }
                SETTINGS_ENABLE_CONNECT_PROTOCOL => {
                    if value > 1 {
                        return Err(Http3Error::SettingsError);
                    }
                    connect_protocol_enabled = Some(value);
                }
                // Setting identifiers that were defined in [HTTP/2] where there is
                // no corresponding HTTP/3 setting have also been reserved. These
                // reserved settings MUST NOT be sent, and their receipt MUST be
                // treated as a connection error of type H3_SETTINGS_ERROR.
                0x0 | 0x2 | 0x3 | 0x4 | 0x5 => return Err(Http3Error::SettingsError),
                // Unknown Settings parameters must be ignored.
                _ => (),
            }
        }

        Ok(Http3Frame::Settings {
            max_field_section_size,
            qpack_max_table_capacity,
            qpack_blocked_streams,
            connect_protocol_enabled,
            raw: Some(raw),
        })
    }

    /// Parse payload of HTTP/3 PUSH_PROMISE frame.
    fn decode_push_promise(payload_length: u64, mut b: &[u8]) -> Result<Http3Frame> {
        let push_id = b.read_varint()?;
        let field_section_len = payload_length - codec::encode_varint_len(push_id) as u64;
        let field_section = b.read(field_section_len as usize)?;

        Ok(Http3Frame::PushPromise {
            push_id,
            field_section,
        })
    }

    /// Parse payload of HTTP/3 PRIORITY_UPDATE frame.
    fn decode_priority_update(
        frame_type: u64,
        payload_length: u64,
        mut b: &[u8],
    ) -> Result<Http3Frame> {
        let prioritized_element_id = b.read_varint()?;
        let priority_field_value_len =
            payload_length - codec::encode_varint_len(prioritized_element_id) as u64;
        let priority_field_value = b.read(priority_field_value_len as usize)?;

        match frame_type {
            PRIORITY_UPDATE_FRAME_REQUEST_TYPE => Ok(Http3Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            }),
            PRIORITY_UPDATE_FRAME_PUSH_TYPE => Ok(Http3Frame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            }),
            _ => unreachable!(),
        }
    }
}

impl std::fmt::Debug for Http3Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Http3Frame::Data { data } => {
                write!(f, "DATA len={:?}", data.len())?;
            }

            Http3Frame::Headers { .. } => {
                write!(f, "HEADERS")?;
            }

            Http3Frame::CancelPush { push_id } => {
                write!(f, "CANCEL_PUSH push_id={push_id}")?;
            }

            Http3Frame::Settings {
                max_field_section_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
                raw,
                ..
            } => {
                write!(
                    f,
                    "SETTINGS max_field_section={max_field_section_size:?} \
                       qpack_max_table={qpack_max_table_capacity:?} \
                       qpack_blocked={qpack_blocked_streams:?} raw={raw:?}"
                )?;
            }

            Http3Frame::PushPromise {
                push_id,
                field_section,
            } => {
                write!(
                    f,
                    "PUSH_PROMISE push_id={} len={}",
                    push_id,
                    field_section.len()
                )?;
            }

            Http3Frame::GoAway { id } => {
                write!(f, "GOAWAY id={id}")?;
            }

            Http3Frame::MaxPushId { push_id } => {
                write!(f, "MAX_PUSH_ID push_id={push_id}")?;
            }

            Http3Frame::PriorityUpdateRequest {
                prioritized_element_id,
                priority_field_value,
            } => {
                write!(
                    f,
                    "PRIORITY_UPDATE request id={} priority_field_len={}",
                    prioritized_element_id,
                    priority_field_value.len()
                )?;
            }

            Http3Frame::PriorityUpdatePush {
                prioritized_element_id,
                priority_field_value,
            } => {
                write!(
                    f,
                    "PRIORITY_UPDATE push id={} priority_field_len={}",
                    prioritized_element_id,
                    priority_field_value.len()
                )?;
            }

            Http3Frame::Unknown { raw_type, .. } => {
                write!(f, "UNKNOWN raw_type={raw_type}",)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3::Result;
    use rand;
    use rand::RngCore;

    fn new_test_data(len: usize) -> Vec<u8> {
        let mut data = vec![0; len];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }

    fn test_encode_and_decode(frame: &Http3Frame) -> Result<()> {
        let mut buf = [0; 128];
        let len = frame.encode(&mut buf)?;

        let frame2 = Http3Frame::decode(&buf[..len])?;
        assert_eq!(*frame, frame2);
        Ok(())
    }

    #[test]
    fn data_frame() {
        let frame = Http3Frame::Data {
            data: new_test_data(16),
        };

        test_encode_and_decode(&frame).unwrap();
        assert_eq!(format!("{:?}", frame), "DATA len=16");
    }

    #[test]
    fn headers_frame() {
        let frame = Http3Frame::Headers {
            field_section: new_test_data(16),
        };

        test_encode_and_decode(&frame).unwrap();
        assert_eq!(format!("{:?}", frame), "HEADERS");
    }

    #[test]
    fn cancel_push_frame() {
        let frame = Http3Frame::CancelPush { push_id: 0 };

        test_encode_and_decode(&frame).unwrap();
        assert_eq!(format!("{:?}", frame), "CANCEL_PUSH push_id=0");
    }

    #[test]
    fn settings_frame() {
        let frame = Http3Frame::Settings {
            max_field_section_size: Some(1024),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            connect_protocol_enabled: Some(1),
            raw: Some(vec![
                (SETTINGS_MAX_FIELD_SECTION_SIZE, 1024),
                (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
                (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
                (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
            ]),
        };

        test_encode_and_decode(&frame).unwrap();
        assert_eq!(
            format!("{:?}", frame),
            "SETTINGS max_field_section=Some(1024) qpack_max_table=Some(0) \
            qpack_blocked=Some(0) raw=Some([(6, 1024), (1, 0), (7, 0), (8, 1)])",
        );
    }

    #[test]
    fn settings_frame_with_invalid_h3_connect_protocol_enabled() {
        let raw_settings = vec![(SETTINGS_ENABLE_CONNECT_PROTOCOL, 9)];
        let frame = Http3Frame::Settings {
            max_field_section_size: None,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
            connect_protocol_enabled: Some(9),
            raw: Some(raw_settings),
        };
        assert_eq!(
            test_encode_and_decode(&frame),
            Err(Http3Error::SettingsError)
        );
    }

    #[test]
    fn settings_frame_with_prohibited_h2_identifier() {
        let frame_payload_len = 2u64;
        let frame_hdr_len = 2;
        let mut d = [SETTINGS_FRAME_TYPE as u8, frame_payload_len as u8, 0x0, 1];

        let prohibited_values = [0x0, 0x2, 0x3, 0x4, 0x5];
        for val in prohibited_values {
            // write SETTING type field with a prohibited value
            d[frame_hdr_len] = val;
            assert_eq!(
                Http3Frame::decode_payload(
                    SETTINGS_FRAME_TYPE,
                    frame_payload_len,
                    &d[frame_hdr_len..]
                ),
                Err(Http3Error::SettingsError)
            );
        }
    }

    #[test]
    fn settings_frame_too_large() {
        let frame_payload_len = MAX_SETTINGS_PAYLOAD_SIZE + 1;
        let frame_hdr_len = 2;
        let d = [SETTINGS_FRAME_TYPE as u8, frame_payload_len as u8, 0x1, 1];

        assert_eq!(
            Http3Frame::decode_payload(
                SETTINGS_FRAME_TYPE,
                frame_payload_len as u64,
                &d[frame_hdr_len..]
            ),
            Err(Http3Error::ExcessiveLoad)
        );
    }

    #[test]
    fn push_promise_frame() {
        let frame = Http3Frame::PushPromise {
            push_id: 0,
            field_section: new_test_data(16),
        };

        test_encode_and_decode(&frame).unwrap();
        assert_eq!(format!("{:?}", frame), "PUSH_PROMISE push_id=0 len=16");
    }

    #[test]
    fn goaway_frame() {
        let frame = Http3Frame::GoAway { id: 16 };

        test_encode_and_decode(&frame).unwrap();
        assert_eq!(format!("{:?}", frame), "GOAWAY id=16");
    }

    #[test]
    fn max_push_id_frame() {
        let frame = Http3Frame::MaxPushId { push_id: 128 };

        test_encode_and_decode(&frame).unwrap();
        assert_eq!(format!("{:?}", frame), "MAX_PUSH_ID push_id=128");
    }

    #[test]
    fn priority_update_request_frame() {
        let frame = Http3Frame::PriorityUpdateRequest {
            prioritized_element_id: 4,
            priority_field_value: new_test_data(16),
        };

        test_encode_and_decode(&frame).unwrap();
        assert_eq!(
            format!("{:?}", frame),
            "PRIORITY_UPDATE request id=4 priority_field_len=16"
        );
    }

    #[test]
    fn priority_update_push_frame() {
        let frame = Http3Frame::PriorityUpdatePush {
            prioritized_element_id: 10,
            priority_field_value: new_test_data(16),
        };

        test_encode_and_decode(&frame).unwrap();
        assert_eq!(
            format!("{:?}", frame),
            "PRIORITY_UPDATE push id=10 priority_field_len=16"
        );
    }

    #[test]
    fn unknown_frame() {
        let frame = Http3Frame::Unknown {
            raw_type: 200,
            payload_length: 150,
        };
        assert_eq!(format!("{:?}", frame), "UNKNOWN raw_type=200");

        let buf = [0; 12];
        assert_eq!(Http3Frame::decode_payload(200, 150, &buf[..]), Ok(frame));
    }
}
