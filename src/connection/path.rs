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

use std::cmp;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time;

use slab::Slab;

use super::recovery::Recovery;
use super::timer;
use crate::connection::SpaceId;
use crate::error::Error;
use crate::multipath_scheduler::MultipathScheduler;
use crate::RecoveryConfig;
use crate::Result;
use crate::TIMER_GRANULARITY;

pub(crate) const INITIAL_CHAL_TIMEOUT: u64 = 25;

pub(crate) const MAX_PROBING_TIMEOUTS: usize = 8;

/// The states about the path validation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathState {
    /// The path validation failed
    Failed,

    /// No path validation has been performed.
    Unknown,

    /// The path is under validation.
    Validating,

    /// The remote address has been validated, but not the path MTU.
    ValidatingMTU,

    /// The path has been validated.
    Validated,
}

/// A network path on which QUIC packets can be sent.
pub struct Path {
    /// The local address.
    local_addr: SocketAddr,

    /// The remote address.
    remote_addr: SocketAddr,

    /// Source CID sequence number used over that path.
    pub(crate) scid_seq: Option<u64>,

    /// Destination CID sequence number used over that path.
    pub(crate) dcid_seq: Option<u64>,

    /// Is this path used to send non-probing packets. By default, the initial
    /// path is active and the others are not active.
    active: bool,

    /// Loss recovery and congestion control.
    pub(crate) recovery: Recovery,

    /// Statistics about the path.
    pub(super) stats: PathStats,

    /// The current validation state of the path.
    state: PathState,

    /// Received path challenge data.
    recv_chals: VecDeque<[u8; 8]>,

    /// Pending challenge data with the size of the packet containing them.
    sent_chals: VecDeque<([u8; 8], usize, time::Instant)>,

    /// Whether it requires sending PATH_CHALLENGE?
    need_send_challenge: bool,

    /// Number of consecutive path probing packets lost.
    lost_chal: usize,

    /// The maximum challenge size that got acknowledged.
    max_challenge_size: usize,

    /// Whether the peer's address has been verified.
    pub(super) verified_peer_address: bool,

    /// Whether the peer has verified our address.
    pub(super) peer_verified_local_address: bool,

    /// Total bytes the server can send before the client's address is verified.
    pub(super) max_send_bytes: usize,

    /// Trace id.
    trace_id: String,

    /// Packet number space for current path in MPQUIC mode.
    pub(crate) space_id: SpaceId,

    /// Whether the path has been abandoned in MPQUIC mode.
    pub(super) is_abandon: bool,
}

impl Path {
    /// Create a new path
    pub(crate) fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        is_initial: bool,
        conf: &RecoveryConfig,
        trace_id: &str,
    ) -> Self {
        let (state, scid_seq, dcid_seq) = if is_initial {
            (PathState::Validated, Some(0), Some(0))
        } else {
            (PathState::Unknown, None, None)
        };

        Self {
            local_addr,
            remote_addr,
            scid_seq,
            dcid_seq,
            active: false,
            recovery: Recovery::new(conf),
            stats: PathStats::default(),
            state,
            recv_chals: VecDeque::new(),
            sent_chals: VecDeque::new(),
            need_send_challenge: false,
            lost_chal: 0,
            max_challenge_size: 0,
            verified_peer_address: false,
            peer_verified_local_address: false,
            max_send_bytes: 0,
            trace_id: trace_id.to_string(),
            space_id: SpaceId::Data,
            is_abandon: false,
        }
    }

    /// Update trace id, appending path id.
    #[doc(hidden)]
    pub fn update_trace_id(&mut self, path_id: usize) {
        self.trace_id.push_str(&(format!("-{}", path_id)));
        self.recovery.set_trace_id(&self.trace_id);
    }

    /// Return the local address of the path.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Return the remote address of the path.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Handle incoming PATH_CHALLENGE data.
    pub(super) fn on_path_chal_received(&mut self, data: [u8; 8]) {
        self.recv_chals.push_back(data);
        self.peer_verified_local_address = true;
    }

    /// Handle incoming PATH_RESPONSE data.
    pub(super) fn on_path_resp_received(&mut self, data: [u8; 8], multipath: bool) {
        if self.state == PathState::Validated {
            return;
        }

        self.verified_peer_address = true;
        self.lost_chal = 0;

        // The 4-tuple is reachable, but we didn't check Path MTU yet.
        let mut challenge_size = 0;
        self.sent_chals.retain(|(d, s, _)| {
            if *d == data {
                challenge_size = *s;
                false
            } else {
                true
            }
        });
        self.max_challenge_size = std::cmp::max(self.max_challenge_size, challenge_size);
        self.promote_to(PathState::ValidatingMTU);

        // The MTU was validated
        if self.max_challenge_size >= crate::MIN_CLIENT_INITIAL_LEN {
            self.promote_to(PathState::Validated);
            self.set_active(multipath);
            self.sent_chals.clear();
            return;
        }

        // If the MTU was not validated, probe again.
        self.need_send_challenge = true;
    }

    /// Fetch a received challenge data item.
    pub(super) fn pop_recv_chal(&mut self) -> Option<[u8; 8]> {
        self.recv_chals.pop_front()
    }

    /// Return whether path validation has been initialed.
    pub(super) fn path_chal_initiated(&self) -> bool {
        self.need_send_challenge
    }

    /// Request path validation.
    pub(super) fn initiate_path_chal(&mut self) {
        self.need_send_challenge = true;
    }

    /// Handle sent event of PATH_CHALLENGE
    pub(super) fn on_path_chal_sent(
        &mut self,
        data: [u8; 8],
        pkt_size: usize,
        sent_time: time::Instant,
    ) {
        self.promote_to(PathState::Validating);
        self.need_send_challenge = false;

        // Use exponential back-off because the RTT of the new path is unknown.
        let loss_time =
            sent_time + time::Duration::from_millis(INITIAL_CHAL_TIMEOUT << self.lost_chal);

        self.sent_chals.push_back((data, pkt_size, loss_time));
    }

    /// Handle timeout of PATH_CHALLENGE
    pub(super) fn on_path_chal_timeout(&mut self, now: time::Instant) {
        if self.state != PathState::Validating && self.state != PathState::ValidatingMTU {
            return;
        }

        // Remove the lost challenges.
        while let Some(first_chal) = self.sent_chals.front() {
            if first_chal.2 > now {
                return;
            }

            self.sent_chals.pop_front();
            self.lost_chal += 1;

            if self.lost_chal < MAX_PROBING_TIMEOUTS {
                // Try to initiate path validation again.
                self.initiate_path_chal();
            } else {
                // The Path validation eventually failed.
                self.state = PathState::Failed;
                self.active = false;
                self.sent_chals.clear();
                return;
            }
        }
    }

    /// Whether PATH_CHALLENGE or PATH_RESPONSE should be sent on the path.
    pub(super) fn need_send_validation_frames(&self) -> bool {
        self.need_send_challenge || !self.recv_chals.is_empty()
    }

    /// Promote the path to the provided state.
    fn promote_to(&mut self, state: PathState) {
        if self.state < state {
            self.state = state;
        }
    }

    /// Return whether the path is validated.
    pub fn validated(&self) -> bool {
        self.state == PathState::Validated
    }

    /// Return whether the path is used to send non-probing packets.
    pub fn active(&self) -> bool {
        self.active && self.dcid_seq.is_some()
    }

    /// Set the active state of the path
    pub(crate) fn set_active(&mut self, v: bool) {
        self.active = v;
    }

    /// Return whether the path is unused.
    fn unused(&self) -> bool {
        !self.active && self.dcid_seq.is_none()
    }

    /// Return statistics about the path
    pub fn stats(&self) -> &PathStats {
        &self.stats
    }

    /// Return the validation state of the path
    pub fn state(&self) -> PathState {
        self.state
    }
}

impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "local={:?} ", self.local_addr)?;
        write!(f, "remote={:?}", self.remote_addr)?;
        Ok(())
    }
}

/// Statistics about a path.
#[derive(Debug, Default)]
pub struct PathStats {
    /// The number of QUIC packets received.
    pub recv_count: usize,

    /// The number of QUIC packets sent.
    pub sent_count: usize,

    /// The number of QUIC packets lost.
    pub lost_count: usize,

    /// The number of received bytes.
    pub recv_bytes: u64,

    /// The number of sent bytes.
    pub sent_bytes: u64,

    /// The number of lost bytes.
    pub lost_bytes: u64,
}

/// Path manager for a QUIC connection
pub(crate) struct PathMap {
    /// The paths of the connection. Each path has a path identifier
    /// used by `addrs`.
    paths: Slab<Path>,

    /// The maximum number of paths allowed.
    max_paths: usize,

    /// The mapping from the (local `SocketAddr`, peer `SocketAddr`) to the
    /// `Path` identifier.
    addrs: BTreeMap<(SocketAddr, SocketAddr), usize>,

    /// Whether the multipath extension is successfully negotiated.
    is_multipath: bool,

    /// Whether it serves as a server.
    is_server: bool,
}

impl PathMap {
    pub fn new(mut initial_path: Path, max_paths: usize, is_server: bool) -> Self {
        // As it is the first path, it is active by default.
        initial_path.active = true;
        let local_addr = initial_path.local_addr;
        let remote_addr = initial_path.remote_addr;

        let mut paths = Slab::with_capacity(2);
        let active_path_id = paths.insert(initial_path);

        if let Some(path) = paths.get_mut(active_path_id) {
            path.update_trace_id(active_path_id);
        }

        let mut addrs = BTreeMap::new();
        addrs.insert((local_addr, remote_addr), active_path_id);

        Self {
            paths,
            max_paths,
            addrs,
            is_multipath: false,
            is_server,
        }
    }

    /// Get an immutable reference to the path identified by `path_id`
    pub fn get(&self, path_id: usize) -> Result<&Path> {
        self.paths.get(path_id).ok_or(Error::InternalError)
    }

    /// Get an mutable reference to the path identified by `path_id`
    pub fn get_mut(&mut self, path_id: usize) -> Result<&mut Path> {
        self.paths.get_mut(path_id).ok_or(Error::InternalError)
    }

    /// Get the `Path` identifier related to the given `addrs`.
    ///
    /// The address tuple `addrs` is (local address, remote address)
    pub fn get_path_id(&self, addrs: &(SocketAddr, SocketAddr)) -> Option<usize> {
        self.addrs.get(addrs).copied()
    }

    /// Get an mutable reference to the active path.
    pub fn get_active(&self) -> Result<&Path> {
        Ok(self.get_active_with_path_id()?.1)
    }

    /// Get an mutable reference to the active path.
    pub fn get_active_mut(&mut self) -> Result<&mut Path> {
        let path = self.paths.iter_mut().find(|(_, p)| p.active);
        Ok(path.ok_or(Error::InternalError)?.1)
    }

    /// Get the `Path` identifier related to the active path.
    pub fn get_active_path_id(&self) -> Result<usize> {
        Ok(self.get_active_with_path_id()?.0)
    }

    /// Get an mutable reference to the active path with the value of the
    /// path identifier. If there is no active path, returns `None`.
    pub fn get_active_with_path_id(&self) -> Result<(usize, &Path)> {
        self.paths
            .iter()
            .find(|(_, p)| p.active)
            .ok_or(Error::InternalError)
    }

    /// Insert a new path
    pub fn insert_path(&mut self, path: Path) -> Result<usize> {
        // eliminate an unused path if the maximum paths limit is reached
        if self.paths.len() >= self.max_paths {
            let (pid_to_remove, _) = self
                .paths
                .iter()
                .find(|(_, p)| p.unused()) // TODO: or failed path ?
                .ok_or(Error::Done)?;
            let path = self.paths.remove(pid_to_remove);
            self.addrs.remove(&(path.local_addr, path.remote_addr));
        }

        // insert new path
        let local_addr = path.local_addr;
        let remote_addr = path.remote_addr;

        let pid = self.paths.insert(path);
        self.addrs.insert((local_addr, remote_addr), pid);
        Ok(pid)
    }

    /// Return an immutable iterator over all existing paths.
    pub fn iter(&self) -> slab::Iter<Path> {
        self.paths.iter()
    }

    /// Return a mutable iterator over all existing paths.
    pub fn iter_mut(&mut self) -> slab::IterMut<Path> {
        self.paths.iter_mut()
    }

    /// Return the number of all paths
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Process a PATH_CHALLENGE frame on the give path
    pub fn on_path_chal_received(&mut self, path_id: usize, data: [u8; 8]) {
        if let Some(path) = self.paths.get_mut(path_id) {
            path.on_path_chal_received(data);
        }
    }

    /// Process a PATH_RESPONSE frame on the give path
    pub fn on_path_resp_received(&mut self, path_id: usize, data: [u8; 8]) {
        if let Some(path) = self.paths.get_mut(path_id) {
            path.on_path_resp_received(data, self.is_multipath);
        }
    }

    /// Handle the sent event of PATH_CHALLENGE.
    pub fn on_path_chal_sent(
        &mut self,
        path_id: usize,
        data: [u8; 8],
        pkt_size: usize,
        sent_time: time::Instant,
    ) -> Result<()> {
        let path = self.get_mut(path_id)?;
        path.on_path_chal_sent(data, pkt_size, sent_time);

        Ok(())
    }

    /// Handle timeout of PATH_CHALLENGE.
    pub fn on_path_chal_timeout(&mut self, now: time::Instant) {
        for (_, path) in self.paths.iter_mut() {
            path.on_path_chal_timeout(now);
        }
    }

    /// Return the lowest loss timer value among all paths.
    pub fn min_loss_detection_timer(&self) -> Option<time::Instant> {
        self.paths
            .iter()
            .filter_map(|(_, p)| p.recovery.loss_detection_timer())
            .min()
    }

    /// Return the minimum timeout among all paths.
    pub fn min_path_chal_timer(&self) -> Option<time::Instant> {
        self.paths
            .iter()
            .filter_map(|(_, p)| p.sent_chals.front())
            .min_by_key(|&(_, _, loss_time)| loss_time)
            .map(|&(_, _, loss_time)| loss_time)
    }

    /// Promote to multipath mode.
    pub fn enable_multipath(&mut self) {
        self.is_multipath = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion_control::CongestionControlAlgorithm;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn new_test_recovery_config() -> RecoveryConfig {
        RecoveryConfig {
            max_datagram_size: 1200,
            max_ack_delay: time::Duration::from_millis(0),
            congestion_control_algorithm: CongestionControlAlgorithm::Bbr,
            min_congestion_window: 2_u64,
            initial_congestion_window: 10_u64,
            initial_rtt: crate::INITIAL_RTT,
            pto_linear_factor: crate::DEFAULT_PTO_LINEAR_FACTOR,
            max_pto: crate::MAX_PTO,
        }
    }

    fn new_path_mgr(
        clients: &Vec<SocketAddr>,
        server: SocketAddr,
        path_num: usize,
        is_server: bool,
    ) -> Result<PathMap> {
        assert!(clients.len() > 0);

        let conf = new_test_recovery_config();
        let initial_path = Path::new(clients[0], server, true, &conf, "");
        let mut path_mgr = PathMap::new(initial_path, path_num, is_server);
        for i in 1..clients.len() {
            let new_path = Path::new(clients[i], server, false, &conf, "");
            path_mgr.insert_path(new_path)?;
        }
        Ok(path_mgr)
    }

    #[test]
    fn path_initial() -> Result<()> {
        let client_addrs = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9443,
        )];
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let mut path_mgr = new_path_mgr(&client_addrs, server_addr, 8, false)?;
        assert_eq!(path_mgr.len(), 1);
        assert_eq!(path_mgr.iter().count(), 1);
        assert_eq!(path_mgr.iter_mut().count(), 1);

        let client_addr = client_addrs[0];
        let pid = path_mgr
            .get_path_id(&(client_addr, server_addr))
            .ok_or(Error::InternalError)?;
        assert_eq!(pid, 0);
        assert_eq!(path_mgr.get(pid)?.local_addr(), client_addr);
        assert_eq!(path_mgr.get(pid)?.remote_addr(), server_addr);
        assert_eq!(path_mgr.get(pid)?.active(), true);
        assert_eq!(path_mgr.get(pid)?.unused(), false);
        assert_eq!(path_mgr.get(pid)?.stats().recv_count, 0);
        assert_eq!(path_mgr.get(pid)?.stats().sent_count, 0);
        assert_eq!(path_mgr.get_active()?.local_addr(), client_addr);
        assert_eq!(path_mgr.get_active_mut()?.remote_addr(), server_addr);
        assert_eq!(path_mgr.get_active_path_id()?, 0);

        Ok(())
    }

    #[test]
    fn client_path_validation() -> Result<()> {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let conf = new_test_recovery_config();
        let initial_path = Path::new(client_addr, server_addr, true, &conf, "");
        let mut path_mgr = PathMap::new(initial_path, 8, false);

        // Add a new path and initiate path validation
        let client_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let new_path = Path::new(client_addr1, server_addr, false, &conf, "");
        path_mgr.insert_path(new_path)?;
        assert_eq!(path_mgr.len(), 2);

        let pid = path_mgr
            .get_path_id(&(client_addr1, server_addr))
            .ok_or(Error::InternalError)?;
        path_mgr.get_mut(pid)?.initiate_path_chal();
        assert!(path_mgr.get_mut(pid)?.need_send_validation_frames());
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), true);

        // Fake sending of PATH_CHALLENGE
        let data = rand::random::<[u8; 8]>();
        let now = time::Instant::now();
        path_mgr.on_path_chal_sent(pid, data, 100, now)?;
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validating);

        // Fake receiving of unmatched PATH_RESPONSE
        path_mgr.on_path_resp_received(pid, [0xab; 8]);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::ValidatingMTU);

        // Fake receiving of PATH_RESPONSE
        path_mgr.on_path_resp_received(pid, data);
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), true);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::ValidatingMTU);

        // Fake sending of PATH_CHALLENGE
        path_mgr.on_path_chal_sent(pid, data, 1300, now)?;

        // Fake receiving of PATH_RESPONSE
        path_mgr.on_path_resp_received(pid, data);
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), true);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validated);
        assert_eq!(path_mgr.get_mut(pid)?.sent_chals.len(), 0);

        // Fake receiving of depulicated PATH_RESPONSE
        path_mgr.on_path_resp_received(pid, data);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), true);

        // Timeout event
        path_mgr.on_path_chal_timeout(now + time::Duration::from_millis(INITIAL_CHAL_TIMEOUT));
        assert_eq!(path_mgr.get_mut(pid)?.lost_chal, 0);
        assert_eq!(path_mgr.get_mut(pid)?.sent_chals.len(), 0);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validated);

        Ok(())
    }

    #[test]
    fn server_path_validation() -> Result<()> {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let conf = new_test_recovery_config();
        let initial_path = Path::new(server_addr, client_addr, true, &conf, "");
        let mut path_mgr = PathMap::new(initial_path, 2, false);

        // Fake receiving of an packet on a new path 1
        let client_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let new_path = Path::new(server_addr, client_addr1, false, &conf, "");
        let pid = path_mgr.insert_path(new_path)?;
        assert_eq!(path_mgr.len(), 2);
        assert_eq!(pid, 1);

        // Fake receiving of PATH_CHALLENGE
        let data = rand::random::<[u8; 8]>();
        path_mgr.on_path_chal_received(pid, data);
        assert_eq!(path_mgr.get_mut(pid)?.recv_chals.len(), 1);

        // Fake sending of PATH_RESPONSE
        let chal = path_mgr.get_mut(pid)?.pop_recv_chal();
        assert_eq!(chal, Some(data));

        // Fake receiving of an packet on a new path 2
        let client_addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9445);
        let new_path = Path::new(server_addr, client_addr2, false, &conf, "");
        let pid = path_mgr.insert_path(new_path)?;
        assert_eq!(path_mgr.len(), 2);
        assert_eq!(path_mgr.get_mut(pid)?.remote_addr(), client_addr2);

        // Fake receiving of PATH_CHALLENGE
        let data = rand::random::<[u8; 8]>();
        path_mgr.on_path_chal_received(pid, data);
        assert_eq!(path_mgr.get_mut(pid)?.recv_chals.len(), 1);

        // Fake sending of PATH_RESPONSE
        let chal = path_mgr.get_mut(pid)?.pop_recv_chal();
        assert_eq!(chal, Some(data));

        Ok(())
    }

    #[test]
    fn path_chal_timeout() -> Result<()> {
        let clients = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444),
        ];
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let mut path_mgr = new_path_mgr(&clients, server_addr, 8, false)?;
        assert_eq!(path_mgr.len(), 2);

        let pid = path_mgr
            .get_path_id(&(clients[1], server_addr))
            .ok_or(Error::InternalError)?;
        path_mgr.get_mut(pid)?.initiate_path_chal();
        assert!(path_mgr.get_mut(pid)?.need_send_validation_frames());
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), true);

        // Fake sending of PATH_CHALLENGE.
        let data = rand::random::<[u8; 8]>();
        let now = time::Instant::now();
        path_mgr.on_path_chal_sent(pid, data, 1300, now)?;
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validating);

        // Not expired.
        path_mgr.on_path_chal_timeout(now + time::Duration::from_millis(1));
        assert_eq!(path_mgr.get_mut(pid)?.sent_chals.len(), 1);
        assert_eq!(path_mgr.get_mut(pid)?.lost_chal, 0);
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);

        // Timeout.
        let mut next_timeout = now;
        for i in 0..MAX_PROBING_TIMEOUTS {
            next_timeout += time::Duration::from_millis(INITIAL_CHAL_TIMEOUT << i);

            path_mgr.on_path_chal_timeout(next_timeout);
            assert_eq!(path_mgr.get_mut(pid)?.lost_chal, i + 1);
            assert_eq!(path_mgr.get_mut(pid)?.sent_chals.len(), 0);

            if i != MAX_PROBING_TIMEOUTS - 1 {
                assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), true);
                assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validating);

                let data = rand::random::<[u8; 8]>();
                path_mgr.on_path_chal_sent(pid, data, 1300, next_timeout)?;
                assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);
            }
        }
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Failed);
        assert_eq!(path_mgr.get_mut(pid)?.active(), false);
        assert_eq!(path_mgr.get_mut(pid)?.lost_chal, MAX_PROBING_TIMEOUTS);

        Ok(())
    }

    #[test]
    fn min_path_chal_timeout() -> Result<()> {
        let clients = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9445),
        ];
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let mut path_mgr = new_path_mgr(&clients, server_addr, 8, false)?;
        assert_eq!(path_mgr.len(), 3);
        assert!(path_mgr.min_path_chal_timer().is_none());

        let pid1 = path_mgr
            .get_path_id(&(clients[1], server_addr))
            .ok_or(Error::InternalError)?;
        let pid2 = path_mgr
            .get_path_id(&(clients[2], server_addr))
            .ok_or(Error::InternalError)?;

        // Fake sending of PATH_CHALLENGE on the first path.
        let now = time::Instant::now();
        let sent_time1 = now;
        let data = rand::random::<[u8; 8]>();
        path_mgr.on_path_chal_sent(pid1, data, 1300, sent_time1)?;
        assert_eq!(path_mgr.get_mut(pid1)?.state, PathState::Validating);
        let timeout1 = sent_time1 + time::Duration::from_millis(INITIAL_CHAL_TIMEOUT);
        assert_eq!(path_mgr.min_path_chal_timer(), Some(timeout1));

        // Fake sending of PATH_CHALLENGE on the second path.
        let sent_time2 = now + time::Duration::from_millis(1);
        path_mgr.on_path_chal_sent(pid2, data, 1300, sent_time2)?;
        assert_eq!(path_mgr.get_mut(pid2)?.state, PathState::Validating);
        let timeout2 = sent_time2 + time::Duration::from_millis(INITIAL_CHAL_TIMEOUT);
        assert_eq!(path_mgr.min_path_chal_timer(), Some(timeout1));

        // Fake receiving of PATH_RESPONSE on the first path.
        path_mgr.on_path_resp_received(pid1, data);
        assert_eq!(path_mgr.min_path_chal_timer(), Some(timeout2));

        Ok(())
    }
}
