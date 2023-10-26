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

//! An implementation of the qlog [main logging schema], [QUIC event definitions]
//! and [HTTP/3 and QPACK event definitions].

use std::time::Instant;

use serde::Deserialize;
use serde::Serialize;

use self::events::Event;
use self::events::EventData;
use self::events::EventImportance;
use self::events::PacketHeader;
use crate::Error;
use crate::Result;

pub const QLOG_VERSION: &str = "0.3";

/// A qlog file should be able to contain several individual traces and logs
/// from multiple vantage points that are in some way related.
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone)]
pub struct Qlog {
    /// The required "qlog_version" field MUST have a value of "0.3" for
    /// draft-ietf-quic-qlog-main-schema-05
    pub qlog_version: String,

    /// As qlog can be serialized in a variety of ways, the "qlog_format" field
    /// is used to indicate which serialization option was chosen.
    pub qlog_format: String,

    /// Name of this particular qlog file
    pub title: Option<String>,

    /// Description for this group of traces
    pub description: Option<String>,

    /// In a real-life deployment with a large amount of generated logs, it can
    /// be useful to sort and filter logs based on some basic summarized or
    /// aggregated data (e.g., log length, packet loss rate, log location,
    /// presence of error events, ...).
    pub summary: Option<String>,

    /// It is often advantageous to group several related qlog traces together
    /// in a single file. The "traces" array contains a list of individual qlog
    /// traces.
    pub traces: Vec<Trace>,
}

/// In the normal use case however, a trace is a log of a single data flow
/// collected at a single location or vantage point.
#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Trace {
    /// The vantage_point field describes the vantage point from which the
    /// trace originates
    pub vantage_point: VantagePoint,

    /// Name of this particular trace
    pub title: Option<String>,

    /// Description for this trace
    pub description: Option<String>,

    /// The configuration field can be viewed as a generic metadata field that
    /// tools can fill with their own fields, based on per-tool logic.
    pub configuration: Option<Configuration>,

    /// qlog uses the "common_fields" list to indicate fields that are shared
    /// by all events in this component trace. This prevents these fields from
    /// being logged for each individual event.
    pub common_fields: Option<CommonFields>,

    /// The exact conceptual definition of a Trace can be fluid. For example,
    /// a trace could contain all events for a single connection, for a single
    /// endpoint, for a single measurement interval, for a single protocol, etc.
    pub events: Vec<Event>,
}

impl Trace {
    pub fn new(
        vantage_point: VantagePoint,
        title: Option<String>,
        description: Option<String>,
        configuration: Option<Configuration>,
        common_fields: Option<CommonFields>,
    ) -> Self {
        Trace {
            vantage_point,
            title,
            description,
            configuration,
            common_fields,
            events: Vec::new(),
        }
    }

    /// Append an Event to a Trace
    pub fn push_event(&mut self, event: Event) {
        self.events.push(event);
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
    // Return a Server or Client VantagePoint
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
    /// A server implementation might choose to log events for all incoming
    /// connections in a single large (streamed) qlog file. As such, we need
    /// a method for splitting up events belonging to separate logical entities.
    /// The simplest way to perform this splitting is by associating a "group
    /// identifier" to each event that indicates to which conceptual "group"
    ///  each event belongs.
    pub group_id: Option<String>,

    /// The "protocol_type" array field indicates to which protocols (or
    /// protocol "stacks") this event belongs. This allows a single qlog file
    /// to aggregate traces of different protocols.
    pub protocol_type: Option<Vec<String>>,

    /// The "reference_time" value is typically the first absolute timestamp.
    pub reference_time: Option<f64>,

    /// The employed format is indicated in the "time_format" field, which
    /// allows one of three values: "absolute", "delta" or "relative"
    pub time_format: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QlogSeq {
    pub qlog_version: String,
    pub qlog_format: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub summary: Option<String>,
    pub trace: TraceSeq,
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TraceSeq {
    pub vantage_point: VantagePoint,
    pub title: Option<String>,
    pub description: Option<String>,
    pub configuration: Option<Configuration>,
    pub common_fields: Option<CommonFields>,
}

impl TraceSeq {
    pub fn new(
        vantage_point: VantagePoint,
        title: Option<String>,
        description: Option<String>,
        configuration: Option<Configuration>,
        common_fields: Option<CommonFields>,
    ) -> Self {
        TraceSeq {
            vantage_point,
            title,
            description,
            configuration,
            common_fields,
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum QlogWriterState {
    Initial,
    Ready,
    Finished,
}

pub struct QlogWriter {
    start_time: std::time::Instant,
    writer: Box<dyn std::io::Write + Send + Sync>,
    qlog: QlogSeq,
    state: QlogWriterState,
    level: EventImportance,
}

impl QlogWriter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        qlog_version: String,
        title: Option<String>,
        description: Option<String>,
        summary: Option<String>,
        start_time: std::time::Instant,
        trace: TraceSeq,
        level: EventImportance,
        writer: Box<dyn std::io::Write + Send + Sync>,
    ) -> Self {
        let qlog = QlogSeq {
            qlog_version,
            qlog_format: "JSON-SEQ".to_string(),
            title,
            description,
            summary,
            trace,
        };

        QlogWriter {
            start_time,
            writer,
            qlog,
            state: QlogWriterState::Initial,
            level,
        }
    }

    /// Start qlog streaming serialization.
    pub fn start(&mut self) -> Result<()> {
        if self.state != QlogWriterState::Initial {
            return Err(Error::Done);
        }

        self.writer.as_mut().write_all(b" ")?;
        serde_json::to_writer(self.writer.as_mut(), &self.qlog).map_err(|_| Error::Done)?;
        self.writer.as_mut().write_all(b"\n")?;
        self.state = QlogWriterState::Ready;
        Ok(())
    }

    /// Finish qlog streaming serialization.
    pub fn finish(&mut self) -> Result<()> {
        if self.state != QlogWriterState::Ready {
            return Err(Error::InvalidState("expect ready state".into()));
        }

        self.state = QlogWriterState::Finished;
        self.writer.as_mut().flush()?;
        Ok(())
    }

    /// Write a JSON-SEQ-serialized Event.
    pub fn add_event(&mut self, event: Event) -> Result<()> {
        self.check(event.importance())?;

        self.writer.as_mut().write_all(b" ")?;
        serde_json::to_writer(self.writer.as_mut(), &event).map_err(|_| Error::Done)?;
        self.writer.as_mut().write_all(b"\n")?;
        Ok(())
    }

    /// Write a JSON-SEQ-serialized Event.
    pub fn add_event_data(&mut self, time: Instant, event_data: EventData) -> Result<()> {
        let event = Event::new(self.relative_time(time), event_data);
        self.add_event(event)
    }

    /// Return whether the event should be written
    fn check(&self, ei: EventImportance) -> Result<()> {
        if self.state != QlogWriterState::Ready {
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
    use crate::qlog::events::RawInfo;
    use crate::qlog::events::TransportPacketSent;

    pub fn new_test_trace_seq() -> TraceSeq {
        TraceSeq::new(
            VantagePoint {
                name: None,
                r#type: VantagePointType::Server,
                flow: None,
            },
            Some("qlog trace".to_string()),
            Some("qlog trace description".to_string()),
            Some(Configuration::default()),
            None,
        )
    }

    fn new_test_trace() -> Trace {
        Trace::new(
            VantagePoint {
                name: None,
                r#type: VantagePointType::Server,
                flow: None,
            },
            Some("qlog trace".to_string()),
            Some("qlog trace description".to_string()),
            Some(Configuration::default()),
            None,
        )
    }

    #[test]
    fn serialize_traces() {
        let mut cases = Vec::<(Trace, String)>::new();

        // trace without events
        let trace = new_test_trace();
        let trace_str = r#"{
  "vantage_point": {
    "type": "server"
  },
  "title": "qlog trace",
  "description": "qlog trace description",
  "configuration": {
    "time_offset": 0.0
  },
  "events": []
}"#;
        cases.push((trace, trace_str.to_string()));

        // trace with single transport event
        let mut trace = new_test_trace();
        trace.push_event(Event::new(
            0.0,
            EventData::TransportPacketSent {
                header: new_test_pkt_hdr(PacketType::Initial),
                frames: Some(
                    vec![QuicFrame::Stream {
                        stream_id: 0,
                        offset: 0,
                        length: 100,
                        fin: Some(true),
                        raw: None,
                    }]
                    .into(),
                ),
                is_coalesced: None,
                retry_token: None,
                stateless_reset_token: None,
                supported_versions: None,
                raw: Some(RawInfo {
                    length: Some(1200),
                    payload_length: Some(1173),
                    data: None,
                }),
                datagram_id: None,
                send_at_time: None,
                trigger: None,
            },
        ));

        let trace_str = r#"{
  "vantage_point": {
    "type": "server"
  },
  "title": "qlog trace",
  "description": "qlog trace description",
  "configuration": {
    "time_offset": 0.0
  },
  "events": [
    {
      "time": 0.0,
      "name": "transport:packet_sent",
      "data": {
        "header": {
          "packet_type": "initial",
          "packet_number": 0,
          "version": "1",
          "scil": 8,
          "dcil": 8,
          "scid": "0102030405060708",
          "dcid": "0807060504030201"
        },
        "raw": {
          "length": 1200,
          "payload_length": 1173
        },
        "frames": [
          {
            "frame_type": "stream",
            "stream_id": 0,
            "offset": 0,
            "length": 100,
            "fin": true
          }
        ]
      }
    }
  ]
}"#;
        cases.push((trace, trace_str.to_string()));

        // Check serialization string
        for (trace, trace_string) in cases {
            let serialized = serde_json::to_string_pretty(&trace).unwrap();
            assert_eq!(serialized, trace_string);

            let deserialized: Trace = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, trace);
        }
    }

    #[test]
    fn qlog_writer_operations() -> Result<()> {
        let writer = std::io::Cursor::new(Vec::<u8>::new());
        let mut qlog_writer = QlogWriter::new(
            "version".to_string(),
            Some("title".to_string()),
            Some("description".to_string()),
            None,
            std::time::Instant::now(),
            new_test_trace_seq(),
            EventImportance::Base,
            Box::new(writer),
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

        // Stop the QlogWriter
        qlog_writer.finish()?;
        assert!(qlog_writer.finish().is_err());

        // Check written logs
        let w: &Box<std::io::Cursor<Vec<u8>>> = unsafe { std::mem::transmute(&qlog_writer.writer) };
        let log = std::str::from_utf8(w.as_ref().get_ref()).unwrap();

        assert_eq!(
            log,
            r#" {"qlog_version":"version","qlog_format":"JSON-SEQ","title":"title","description":"description","trace":{"vantage_point":{"type":"server"},"title":"qlog trace","description":"qlog trace description","configuration":{"time_offset":0.0}}}
 {"time":0.0,"name":"connectivity:connection_state_updated","data":{"new":"handshake_completed"}}
 {"time":0.0,"name":"connectivity:connection_state_updated","data":{"new":"handshake_confirmed"}}
"#
        );

        Ok(())
    }
}

pub mod events;
