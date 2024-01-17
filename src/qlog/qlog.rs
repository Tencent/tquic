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

//! An implementation of the qlog main logging schema, QUIC event definitions
//! and HTTP/3 and QPACK event definitions.

use std::time::Instant;

use serde::Deserialize;
use serde::Serialize;

use self::events::Event;
use self::events::EventData;
use self::events::EventImportance;
use self::events::PacketHeader;
use crate::Error;
use crate::Result;

/// The qlog_version is 0.4 for draft-ietf-quic-qlog-main-schema-07
pub const QLOG_VERSION: &str = "0.4";

/// The serialization format for QlogFileSeq is JSON-SEQ
/// See RFC 7464: JavaScript Object Notation (JSON) Text Sequences
pub const JSON_TEXT_SEQS: &str = "JSON-SEQ";

/// A qlog file using the QlogFileSeq schema can be serialized to a streamable
/// JSON format called JSON Text Sequences (JSON-SEQ) ([RFC7464])
/// See draft-ietf-quic-qlog-main-schema-07
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QlogFileSeq {
    /// The qlog_format field MUST have the value "JSON-SEQ".
    pub qlog_format: String,

    /// The qlog_version field MUST have the value "0.4".
    pub qlog_version: String,

    /// The title field provide additional free-text information about the file.
    pub title: Option<String>,

    /// The description field provide additional free-text information about
    /// the file.
    pub description: Option<String>,

    /// The trace field contains a singular trace metadata. All qlog events in
    /// the file are related to this trace.
    pub trace: TraceSeq,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TraceSeq {
    pub title: Option<String>,
    pub description: Option<String>,
    pub common_fields: Option<CommonFields>,
    pub vantage_point: VantagePoint,
}

impl TraceSeq {
    pub fn new(
        title: Option<String>,
        description: Option<String>,
        common_fields: Option<CommonFields>,
        vantage_point: VantagePoint,
    ) -> Self {
        TraceSeq {
            title,
            description,
            common_fields,
            vantage_point,
        }
    }
}

/// Describes the vantage point from which the trace originates.
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct VantagePoint {
    /// Name of the vantage point.
    pub name: Option<String>,

    /// Type of vantage point may be Client/Server/Network/Unknown.
    pub r#type: VantagePointType,

    /// The flow field is only required if the type is "network". It is used to
    /// disambiguate events like "packet sent" and "packet received".
    pub flow: Option<VantagePointType>,
}

impl VantagePoint {
    /// Return a Server or Client VantagePoint
    pub fn new(name: Option<String>, is_server: bool) -> VantagePoint {
        let vp_type = if is_server {
            VantagePointType::Server
        } else {
            VantagePointType::Client
        };

        Self {
            name,
            r#type: vp_type,
            flow: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum VantagePointType {
    /// Endpoint which initiates the connection
    Client,

    /// Endpoint which accepts the connection
    Server,

    /// Observer in between client and server
    Network,

    Unknown,
}

/// The configuration field can be viewed as a generic metadata field that tools
/// can fill with their own fields, based on per-tool logic.
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Configuration {
    /// The time_offset field indicates by how many milliseconds the starting
    /// time of the current trace should be offset. This is useful when
    /// comparing logs taken from various systems, where clocks might not be
    /// perfectly synchronous.
    pub time_offset: Option<f64>,

    /// The original_uris field is used when merging multiple individual qlog
    /// files or other source files
    pub original_uris: Option<Vec<String>>,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            time_offset: Some(0.0),
            original_uris: None,
        }
    }
}

/// qlog uses the "common_fields" list to indicate fields that are shared
/// by all events in this component trace.
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct CommonFields {
    /// The employed format is indicated in the "time_format" field, which
    /// allows one of three values: "absolute", "delta" or "relative"
    pub time_format: Option<String>,

    /// The "reference_time" value is typically the first absolute timestamp.
    pub reference_time: Option<f64>,

    /// The "protocol_type" array field indicates to which protocols (or
    /// protocol "stacks") this event belongs. This allows a single qlog file
    /// to aggregate traces of different protocols.
    pub protocol_type: Option<Vec<String>>,

    /// A server implementation might choose to log events for all incoming
    /// connections in a single large (streamed) qlog file. As such, we need
    /// a method for splitting up events belonging to separate logical entities.
    /// The simplest way to perform this splitting is by associating a "group
    /// identifier" to each event that indicates to which conceptual "group"
    ///  each event belongs.
    pub group_id: Option<String>,
}

/// Qlog writer using the QlogFileSeq schema
pub struct QlogWriter {
    /// The top-level element in this schema that defines only a small set of
    /// "header" fields and an array of component traces.
    qlog: QlogFileSeq,

    /// Events below this level will not be written out.
    level: EventImportance,

    /// The underlying writer for qlog streaming
    writer: Box<dyn std::io::Write + Send + Sync>,

    /// Whether the top-level element (QlogFileSeq) has been written
    ready: bool,

    /// The created time for the QlogWriter
    start_time: std::time::Instant,
}

impl QlogWriter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        title: Option<String>,
        description: Option<String>,
        trace: TraceSeq,
        level: EventImportance,
        writer: Box<dyn std::io::Write + Send + Sync>,
        start_time: std::time::Instant,
    ) -> Self {
        let qlog = QlogFileSeq {
            qlog_format: crate::qlog::JSON_TEXT_SEQS.to_string(),
            qlog_version: crate::qlog::QLOG_VERSION.to_string(),
            title,
            description,
            trace,
        };

        QlogWriter {
            qlog,
            level,
            writer,
            ready: false,
            start_time,
        }
    }

    /// Start qlog serialization and write the QlogFileSeq.
    pub fn start(&mut self) -> Result<()> {
        if self.ready {
            return Err(Error::Done);
        }

        self.writer.as_mut().write_all(b" ")?;
        serde_json::to_writer(self.writer.as_mut(), &self.qlog).map_err(|_| Error::Done)?;
        self.writer.as_mut().write_all(b"\n")?;
        self.ready = true;
        Ok(())
    }

    /// Flush qlog serialization data.
    pub fn flush(&mut self) -> Result<()> {
        if !self.ready {
            return Err(Error::InvalidState("expect ready state".into()));
        }

        self.writer.as_mut().flush()?;
        Ok(())
    }

    /// Write an event in JSON-SEQ format.
    pub fn add_event(&mut self, event: Event) -> Result<()> {
        self.check(event.importance())?;

        self.writer.as_mut().write_all(b" ")?;
        serde_json::to_writer(self.writer.as_mut(), &event).map_err(|_| Error::Done)?;
        self.writer.as_mut().write_all(b"\n")?;
        Ok(())
    }

    /// Write an event in JSON-SEQ format.
    pub fn add_event_data(&mut self, time: Instant, event_data: EventData) -> Result<()> {
        let event = Event::new(self.relative_time(time), event_data);
        self.add_event(event)
    }

    /// Return whether the event should be written
    fn check(&self, ei: EventImportance) -> Result<()> {
        if !self.ready {
            return Err(Error::InvalidState("not ready".into()));
        }
        if !ei.is_contained_in(&self.level) {
            return Err(Error::Done);
        }
        Ok(())
    }

    /// Return the relative time for the writer.
    pub fn relative_time(&self, time: Instant) -> f32 {
        let duration = time.duration_since(self.start_time);
        duration.as_secs_f32() * 1000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qlog::events::tests::new_test_pkt_hdr;
    use crate::qlog::events::ConnectionState;
    use crate::qlog::events::EventData;
    use crate::qlog::events::PacketType;
    use crate::qlog::events::QuicFrame;
    use crate::qlog::events::QuicPacketSent;
    use crate::qlog::events::RawInfo;

    pub fn new_test_trace_seq() -> TraceSeq {
        TraceSeq::new(
            Some("qlog trace".to_string()),
            Some("qlog trace description".to_string()),
            None,
            VantagePoint {
                name: None,
                r#type: VantagePointType::Server,
                flow: None,
            },
        )
    }

    #[test]
    fn qlog_writer_operations() -> Result<()> {
        let writer = std::io::Cursor::new(Vec::<u8>::new());
        let mut qlog_writer = QlogWriter::new(
            Some("title".to_string()),
            Some("description".to_string()),
            new_test_trace_seq(),
            EventImportance::Base,
            Box::new(writer),
            std::time::Instant::now(),
        );

        // Add an event before the QlogWriter is started
        let event1 = Event::new(
            0.0,
            EventData::ConnectivityConnectionStateUpdated {
                old: None,
                new: ConnectionState::HandshakeCompleted,
            },
        );
        assert!(qlog_writer.add_event(event1.clone()).is_err());

        // Start the QlogWriter
        qlog_writer.start()?;
        assert_eq!(qlog_writer.start(), Err(Error::Done));

        // Add an Event
        qlog_writer.add_event(event1)?;

        // Add an Event with lower importance
        let event2 = EventData::RecoveryMarkedForRetransmit {
            frames: vec![QuicFrame::Ping],
        };
        assert_eq!(
            qlog_writer.add_event_data(Instant::now(), event2),
            Err(Error::Done)
        );

        // Add an EventData
        let event3 = Event::new(
            0.0,
            EventData::ConnectivityConnectionStateUpdated {
                old: None,
                new: ConnectionState::HandshakeConfirmed,
            },
        );
        qlog_writer.add_event(event3)?;

        // Flush the QlogWriter
        qlog_writer.flush()?;

        // Check written logs
        let w: &Box<std::io::Cursor<Vec<u8>>> = unsafe { std::mem::transmute(&qlog_writer.writer) };
        let log = std::str::from_utf8(w.as_ref().get_ref()).unwrap();

        assert_eq!(
            log,
            r#" {"qlog_format":"JSON-SEQ","qlog_version":"0.4","title":"title","description":"description","trace":{"title":"qlog trace","description":"qlog trace description","vantage_point":{"type":"server"}}}
 {"time":0.0,"name":"connectivity:connection_state_updated","data":{"new":"handshake_completed"}}
 {"time":0.0,"name":"connectivity:connection_state_updated","data":{"new":"handshake_confirmed"}}
"#
        );

        Ok(())
    }
}

pub mod events;
