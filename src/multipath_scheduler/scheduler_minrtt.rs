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

use crate::connection::path::PathMap;
use crate::connection::space::PacketNumSpaceMap;
use crate::connection::stream::StreamMap;
use crate::multipath_scheduler::MultipathScheduler;
use crate::Error;
use crate::MultipathConfig;
use crate::Result;

/// MinRttScheduler prioritizes sending data on the path with the lowest RTT
/// until its cwnd is fully utilized, and then proceeds to send data on the path
/// with the next highest RTT.
///
/// The scheduler aims to optimize throughput and achieve load balancing, making
/// it particularly advantageous for bulk transfer applications in heterogeneous
/// networks.
pub struct MinRttScheduler {}

impl MinRttScheduler {
    pub fn new(_conf: &MultipathConfig) -> MinRttScheduler {
        MinRttScheduler {}
    }
}

impl MultipathScheduler for MinRttScheduler {
    /// Select the path with the minimum RTT and sufficient congestion window.
    fn on_select(
        &mut self,
        paths: &mut PathMap,
        spaces: &mut PacketNumSpaceMap,
        streams: &mut StreamMap,
    ) -> Result<usize> {
        let mut best = None;

        for (pid, path) in paths.iter() {
            // Skip the path that is not ready for sending non-probing packets.
            if !path.active() || !path.recovery.can_send() {
                continue;
            }

            // Select the path with the minimum srtt
            let srtt = path.recovery.rtt.smoothed_rtt();
            match best {
                None => best = Some((pid, srtt)),
                Some((_, rtt)) => {
                    if srtt < rtt {
                        best = Some((pid, srtt));
                    }
                }
            }
        }

        match best {
            Some((i, _)) => Ok(i),
            None => Err(Error::Done),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multipath_scheduler::tests::*;

    #[test]
    fn minrtt_single_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;

        let mut s = MinRttScheduler {};
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        Ok(())
    }

    #[test]
    fn minrtt_multi_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 50)?;
        t.add_path("127.0.0.1:443", "127.0.0.3:8443", 150)?;
        t.add_path("127.0.0.1:443", "127.0.0.4:8443", 100)?;

        let mut s = MinRttScheduler {};
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 1);

        t.set_path_active(1, false)?;
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 3);

        Ok(())
    }

    #[test]
    fn minrtt_no_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.set_path_active(0, false)?;

        let mut s = MinRttScheduler {};
        assert_eq!(
            s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams),
            Err(Error::Done)
        );
        Ok(())
    }
}
