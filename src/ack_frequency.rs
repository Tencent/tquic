// Copyright (c) 2026 The TQUIC Authors.
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

//! State shared by the sending and receiving sides of ACK Frequency.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::error::Error;
use crate::frame::Frame;
use crate::Result;

/// Requested Max Ack Delay values are invalid when they are 2^14 milliseconds
/// or greater.
pub(crate) const MAX_REQUESTED_ACK_DELAY: u64 = (1 << 14) * 1000;

/// The values carried by an ACK_FREQUENCY frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AckFrequencyParams {
    pub sequence_number: u64,
    pub ack_eliciting_threshold: u64,
    pub requested_max_ack_delay: u64,
    pub reordering_threshold: u64,
}

impl AckFrequencyParams {
    pub fn into_frame(self) -> Frame {
        Frame::AckFrequency {
            sequence_number: self.sequence_number,
            ack_eliciting_threshold: self.ack_eliciting_threshold,
            requested_max_ack_delay: self.requested_max_ack_delay,
            reordering_threshold: self.reordering_threshold,
        }
    }
}

/// The latest acknowledgment policy received from the peer.
#[derive(Clone, Debug, Default)]
pub(crate) struct AckFrequencyReceiverState {
    params: Option<AckFrequencyParams>,
}

impl AckFrequencyReceiverState {
    /// Process an ACK_FREQUENCY frame. Returns true when it supersedes the
    /// current policy and false when it is stale.
    pub fn on_frame(
        &mut self,
        params: AckFrequencyParams,
        min_ack_delay: Option<u64>,
    ) -> Result<bool> {
        let min_ack_delay = min_ack_delay.ok_or(Error::ProtocolViolation)?;
        if self
            .params
            .is_some_and(|current| params.sequence_number <= current.sequence_number)
        {
            return Ok(false);
        }

        if params.requested_max_ack_delay < min_ack_delay
            || params.requested_max_ack_delay >= MAX_REQUESTED_ACK_DELAY
        {
            return Err(Error::ProtocolViolation);
        }

        self.params = Some(params);
        Ok(true)
    }

    pub fn params(&self) -> Option<AckFrequencyParams> {
        self.params
    }
}

/// Tracks acknowledged and in-flight ACK_FREQUENCY frames for PTO calculation.
#[derive(Clone, Debug, Default)]
pub(crate) struct AckFrequencySenderState {
    acknowledged: Option<AckFrequencyParams>,
    in_flight: BTreeMap<u64, AckFrequencyParams>,
}

impl AckFrequencySenderState {
    pub fn on_frame_sent(&mut self, params: AckFrequencyParams) {
        self.in_flight.insert(params.sequence_number, params);
    }

    pub fn on_frame_acked(&mut self, params: AckFrequencyParams) {
        if self.acknowledged.map_or(true, |current| {
            params.sequence_number > current.sequence_number
        }) {
            self.acknowledged = Some(params);
        }

        // Processing a newer frame supersedes all older acknowledgment policies.
        self.in_flight
            .retain(|sequence, _| *sequence > params.sequence_number);
    }

    pub fn effective_max_ack_delay(&self, transport_max_ack_delay: Duration) -> Duration {
        let acknowledged = self
            .acknowledged
            .map(|p| Duration::from_micros(p.requested_max_ack_delay))
            .unwrap_or(transport_max_ack_delay);

        self.in_flight.values().fold(acknowledged, |delay, p| {
            delay.max(Duration::from_micros(p.requested_max_ack_delay))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(sequence_number: u64, delay: u64) -> AckFrequencyParams {
        AckFrequencyParams {
            sequence_number,
            ack_eliciting_threshold: 1,
            requested_max_ack_delay: delay,
            reordering_threshold: 1,
        }
    }

    #[test]
    fn receiver_rejects_invalid_delay_and_ignores_stale_frames() {
        let mut state = AckFrequencyReceiverState::default();
        assert_eq!(
            state.on_frame(params(1, 999), None),
            Err(Error::ProtocolViolation)
        );
        assert_eq!(
            state.on_frame(params(1, 999), Some(1000)),
            Err(Error::ProtocolViolation)
        );
        assert_eq!(
            state.on_frame(params(1, MAX_REQUESTED_ACK_DELAY), Some(0)),
            Err(Error::ProtocolViolation)
        );

        assert_eq!(state.on_frame(params(2, 1000), Some(1000)), Ok(true));
        assert_eq!(state.on_frame(params(1, 0), Some(1000)), Ok(false));
        assert_eq!(state.params(), Some(params(2, 1000)));
    }

    #[test]
    fn sender_uses_largest_in_flight_delay_until_acknowledged() {
        let mut state = AckFrequencySenderState::default();
        let transport_delay = Duration::from_millis(25);
        assert_eq!(
            state.effective_max_ack_delay(transport_delay),
            transport_delay
        );

        state.on_frame_sent(params(0, 50_000));
        state.on_frame_sent(params(1, 10_000));
        assert_eq!(
            state.effective_max_ack_delay(transport_delay),
            Duration::from_millis(50)
        );

        state.on_frame_acked(params(1, 10_000));
        assert_eq!(
            state.effective_max_ack_delay(transport_delay),
            Duration::from_millis(10)
        );
    }
}
