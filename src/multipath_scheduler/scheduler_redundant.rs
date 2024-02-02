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

use log::*;
use std::time::Instant;

use crate::connection::path::PathMap;
use crate::connection::space::BufferType;
use crate::connection::space::PacketNumSpaceMap;
use crate::connection::space::SentPacket;
use crate::connection::stream::StreamMap;
use crate::frame::Frame;
use crate::multipath_scheduler::MultipathScheduler;
use crate::Error;
use crate::MultipathConfig;
use crate::Result;

/// RedundantScheduler sends all packets redundantly on all available paths.
///
/// The scheduler utilizes additional bandwidth to minimize latency, thereby
/// reducing the overall flow completion time for applications with bounded
/// bandwidth requirements that can be met by a single path.
/// In scenarios where two paths with varying available bandwidths are present,
/// it ensures a goodput at least equivalent to the best single path.
pub struct RedundantScheduler {}

impl RedundantScheduler {
    pub fn new(_conf: &MultipathConfig) -> RedundantScheduler {
        RedundantScheduler {}
    }
}

impl MultipathScheduler for RedundantScheduler {
    /// Select a path with sufficient congestion window.
    fn on_select(
        &mut self,
        paths: &mut PathMap,
        spaces: &mut PacketNumSpaceMap,
        streams: &mut StreamMap,
    ) -> Result<usize> {
        for (pid, path) in paths.iter() {
            // Skip the path that is not ready for sending non-probing packets.
            if !path.active() || !path.recovery.can_send() {
                continue;
            }
            return Ok(pid);
        }
        Err(Error::Done)
    }

    /// Try to reinject the sent packet to other available paths.
    fn on_sent(
        &mut self,
        packet: &SentPacket,
        now: Instant,
        path_id: usize,
        paths: &mut PathMap,
        spaces: &mut PacketNumSpaceMap,
        streams: &mut StreamMap,
    ) {
        if packet.buffer_flags.has_buffered() {
            return;
        }

        // Reinject the frames to other active paths.
        for (pid, path) in paths.iter() {
            if pid == path_id || !path.active() {
                continue;
            }
            let space = match spaces.get_mut(path.space_id) {
                Some(space) => space,
                None => return,
            };
            for frame in &packet.frames {
                if let Frame::Stream { .. } = frame {
                    debug!("RedundantScheduler: inject {:?} on path {:?}", frame, pid);
                    space.buffered.push_back(frame.clone(), BufferType::High);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multipath_scheduler::tests::MultipathTester;

    #[test]
    fn redundant_select() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 50)?;

        let mut s = RedundantScheduler {};
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);

        t.set_path_active(0, false)?;
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 1);

        t.set_path_active(1, false)?;
        assert_eq!(
            s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams),
            Err(Error::Done)
        );
        Ok(())
    }
}
