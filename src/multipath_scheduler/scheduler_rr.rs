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
use crate::Path;
use crate::Result;

/// RoundRobinScheduler iterates over the available paths and select the next
/// one whose congestion window is open.
///
/// The simple scheduler aims to guarantee that the capacity of each path is
/// fully utilized as the distribution across all path is equal. It is for
/// testing purposes only.
pub struct RoundRobinScheduler {
    last: Option<usize>,
}

impl RoundRobinScheduler {
    pub fn new(_conf: &MultipathConfig) -> RoundRobinScheduler {
        RoundRobinScheduler { last: None }
    }
}

impl RoundRobinScheduler {
    /// Iterate and find the last used path
    fn find_last(&self, iter: &mut slab::Iter<Path>, last: usize) -> bool {
        for (pid, _) in iter.by_ref() {
            if pid != last {
                continue;
            }
            return true;
        }
        false
    }

    /// Try to select an available path
    fn select(&mut self, iter: &mut slab::Iter<Path>) -> Option<usize> {
        for (pid, path) in iter.by_ref() {
            // Skip the path that is not ready for sending non-probing packets.
            if !path.active() || !path.recovery.can_send() {
                continue;
            }

            self.last = Some(pid);
            return Some(pid);
        }
        None
    }
}

impl MultipathScheduler for RoundRobinScheduler {
    /// Select the next path with sufficient congestion window.
    fn on_select(
        &mut self,
        paths: &mut PathMap,
        spaces: &mut PacketNumSpaceMap,
        streams: &mut StreamMap,
    ) -> Result<usize> {
        let mut iter = paths.iter();
        let mut exist_last = false;

        // Iterate and find the last used path
        if let Some(last) = self.last {
            if self.find_last(&mut iter, last) {
                exist_last = true;
            } else {
                // The last path has been abandoned
                iter = paths.iter();
            }
        }

        // Find the next available path
        if let Some(pid) = self.select(&mut iter) {
            return Ok(pid);
        }
        if !exist_last {
            return Err(Error::Done);
        }

        let mut iter = paths.iter();
        if let Some(pid) = self.select(&mut iter) {
            return Ok(pid);
        }
        Err(Error::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multipath_scheduler::tests::*;

    #[test]
    fn round_robin_single_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;

        let mut s = RoundRobinScheduler::new(&MultipathConfig::default());
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        Ok(())
    }

    #[test]
    fn round_robin_multi_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 50)?;
        t.add_path("127.0.0.1:443", "127.0.0.3:8443", 150)?;
        t.add_path("127.0.0.1:443", "127.0.0.4:8443", 100)?;

        let mut s = RoundRobinScheduler::new(&MultipathConfig::default());
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 1);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 2);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 3);

        t.set_path_active(1, false)?;
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 2);

        t.set_path_active(3, false)?;
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        Ok(())
    }

    #[test]
    fn round_robin_no_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.set_path_active(0, false)?;

        let mut s = RoundRobinScheduler::new(&MultipathConfig::default());
        assert_eq!(
            s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams),
            Err(Error::Done)
        );
        Ok(())
    }
}
