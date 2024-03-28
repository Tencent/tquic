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

use std::collections::VecDeque;

use crate::error::Error;
use crate::frame::Frame;
use crate::token::ResetToken;
use crate::ConnectionId;
use crate::Result;

const MAX_CIDS_COUNT: u64 = 16;

/// Connection Id and related metadata.
#[derive(Default)]
pub struct ConnectionIdItem {
    /// The Connection ID.
    pub cid: ConnectionId,

    /// The associated sequence number.
    pub seq: u64,

    /// The associated reset token.
    pub reset_token: Option<u128>,

    /// The path using the Connection ID.
    pub path_id: Option<usize>,
}

/// A set of ConnectionIDItems
#[derive(Default)]
struct ConnectionIdDeque {
    /// The inner `VecDeque`.
    queue: VecDeque<ConnectionIdItem>,

    /// The maximum items of the `VecDeque`.
    capacity: usize,
}

impl ConnectionIdDeque {
    /// Create a bounded ConnectionIdItem queue.
    fn new(capacity: usize) -> Self {
        let queue = VecDeque::with_capacity(1);
        Self { queue, capacity }
    }

    /// Find a ConnectionIdItem with the given sequence.
    fn get(&self, seq: u64) -> Option<&ConnectionIdItem> {
        self.queue.iter().find(|cid| cid.seq == seq)
    }

    /// Find a ConnectionIdItem with the given sequence.
    fn get_mut(&mut self, seq: u64) -> Option<&mut ConnectionIdItem> {
        self.queue.iter_mut().find(|cid| cid.seq == seq)
    }

    /// Insert the given ConnectionIdItem.
    ///
    /// The caller must not add an invalid duplicated cid
    fn insert(&mut self, cid: ConnectionIdItem) -> Result<()> {
        if self.queue.len() == self.capacity {
            return Err(Error::ConnectionIdLimitError);
        }
        self.queue.push_back(cid);
        Ok(())
    }

    /// Remove all items.
    fn clear(&mut self) {
        self.queue.clear();
    }

    /// Remove the ConnectionIdItem with given sequence.
    fn remove(&mut self, seq: u64) -> Result<Option<ConnectionIdItem>> {
        if self.queue.is_empty() {
            return Err(Error::InternalError);
        }
        if self.queue.len() == 1 && self.get(seq).is_some() {
            return Err(Error::InternalError);
        }

        Ok(self
            .queue
            .iter()
            .position(|cid| cid.seq == seq)
            .and_then(|i| self.queue.remove(i)))
    }

    /// Remove all the cids whose seq is lower than the given `seq`
    fn remove_lower(&mut self, seq: u64, mut f: impl FnMut(&ConnectionIdItem)) {
        self.queue.retain(|cid| {
            if cid.seq < seq {
                f(cid);
                false
            } else {
                true
            }
        });
    }

    /// Enlarge the maximum capacity of the ConnectionIdItem queue.
    fn enlarge(&mut self, capacity: usize) {
        if capacity > self.capacity {
            self.capacity = capacity;
        }
    }

    /// Return the number of items.
    fn len(&self) -> usize {
        self.queue.len()
    }

    /// Return an iterator over the ConnectionIdItem queue.
    fn iter(&self) -> impl Iterator<Item = &ConnectionIdItem> {
        self.queue.iter()
    }
}

/// ConnectionIdMgr maintains all the Connection IDs on a QUIC connection
#[derive(Default)]
pub struct ConnectionIdMgr {
    /// All the destination connection IDs provided by our peer.
    dcids: ConnectionIdDeque,

    /// All the source connection IDs we provide to our peer.
    scids: ConnectionIdDeque,

    /// The maximum number of destination connection IDs from peer that this
    /// endpoint is willing to store.
    dcid_limit: usize,

    /// The maximum number of source connection IDs our peer allows us.
    scid_limit: usize,

    /// Whether the host use zero-length Source Connection ID.
    zero_length_scid: bool,

    /// Whether the host use zero-length Destination Connection ID.
    zero_length_dcid: bool,

    /// Next sequence number of source Connection ID to use.
    next_scid_seq: u64,

    /// "Retire Prior To" value to advertise to the peer.
    retire_prior_to: u64,

    /// Source Connection IDs that should be announced to the peer.
    scids_to_advertise: VecDeque<u64>,

    /// Largest "Retire Prior To" advertised by the peer.
    largest_peer_retire_prior_to: u64,

    /// Retired Destination Connection IDs that should be announced to the peer.
    dcids_to_retire: VecDeque<u64>,
}

impl ConnectionIdMgr {
    pub fn new(
        dcid_limit: usize,
        initial_scid: &ConnectionId,
        initial_path_id: usize,
        reset_token: Option<u128>,
    ) -> Self {
        let scid_limit = 2;
        let mut scids = ConnectionIdDeque::new(scid_limit * 2 - 1);
        _ = scids.insert(
            // Adding initial scid is always successful
            ConnectionIdItem {
                cid: *initial_scid,
                seq: 0,
                reset_token,
                path_id: Some(initial_path_id),
            },
        );

        let dcids = ConnectionIdDeque::new(dcid_limit * 2 - 1);

        ConnectionIdMgr {
            scids,
            dcids,
            dcid_limit,
            scid_limit,
            zero_length_scid: initial_scid.is_empty(),
            next_scid_seq: 1,
            ..Default::default()
        }
    }

    /// Initial the peer cid for the connection.
    pub fn set_initial_dcid(
        &mut self,
        cid: ConnectionId,
        reset_token: Option<u128>,
        path_id: Option<usize>,
    ) {
        self.zero_length_dcid = cid.is_empty();

        self.dcids.clear();
        let _ = self.dcids.insert(ConnectionIdItem {
            // always success
            cid,
            seq: 0,
            reset_token,
            path_id,
        });
    }

    /// Set the maximum number of source CIDs our peer allows us.
    pub fn set_scid_limit(&mut self, limit: u64) {
        let limit = std::cmp::min(limit, MAX_CIDS_COUNT) as usize;
        let limit = std::cmp::max(limit, 2); // It must be at least 2.

        self.scid_limit = limit;
        // We should track up to (2 * source_conn_id_limit - 1) source
        // CIDs when the host wants to force their renewal.
        self.scids.enlarge(2 * limit - 1);
    }

    /// Get the Source CID with the given sequence.
    pub fn get_scid(&self, seq: u64) -> Result<&ConnectionIdItem> {
        self.scids.get(seq).ok_or(Error::InternalError)
    }

    /// Get the Destination CID with the given sequence.
    pub fn get_dcid(&self, seq: u64) -> Result<&ConnectionIdItem> {
        self.dcids.get(seq).ok_or(Error::InternalError)
    }

    /// Find the sequence number and path id of the give Source CID.
    pub fn find_scid(&self, scid: &ConnectionId) -> Option<(u64, Option<usize>)> {
        self.scids.iter().find_map(|c| {
            if c.cid == *scid {
                Some((c.seq, c.path_id))
            } else {
                None
            }
        })
    }

    /// Mark the Source CID is used by the given path
    pub fn mark_scid_used(&mut self, scid_seq: u64, path_id: usize) -> Result<()> {
        let e = self.scids.get_mut(scid_seq).ok_or(Error::InternalError)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    /// Mark the Destination CID is used by the given path
    pub fn mark_dcid_used(&mut self, dcid_seq: u64, path_id: usize) -> Result<()> {
        let e = self.dcids.get_mut(dcid_seq).ok_or(Error::InternalError)?;
        e.path_id = Some(path_id);
        Ok(())
    }

    /// Return the number of unused Source CIDs
    pub fn unused_scids(&self) -> usize {
        self.scids
            .iter()
            .filter(|cid| cid.path_id.is_none())
            .count()
    }

    /// Return the number of unused Destination CIDs
    pub fn unused_dcids(&self) -> usize {
        if self.zero_length_dcid {
            return 0;
        }
        self.dcids.iter().filter(|e| e.path_id.is_none()).count()
    }

    /// Return the minimum active Source CID sequence.
    fn lowest_active_scid_seq(&self) -> Result<u64> {
        self.scids
            .iter()
            .filter_map(|cid| {
                if cid.seq >= self.retire_prior_to {
                    Some(cid.seq)
                } else {
                    None
                }
            })
            .min()
            .ok_or(Error::InternalError)
    }

    /// Get the lowest Destination CID that is not associated to a path.
    pub fn lowest_unused_dcid_seq(&self) -> Option<u64> {
        self.dcids
            .iter()
            .filter_map(|cid| {
                if cid.path_id.is_none() {
                    Some(cid.seq)
                } else {
                    None
                }
            })
            .min()
    }

    /// Add a new Source CID
    pub fn add_scid(
        &mut self,
        cid: ConnectionId,
        reset_token: Option<u128>,
        advertise: bool,
        path_id: Option<usize>,
        retire_if_needed: bool,
    ) -> Result<u64> {
        if self.zero_length_scid {
            return Err(Error::InternalError);
        }

        // Check the limit of source CIDs
        if self.scids.len() >= self.scid_limit {
            if !retire_if_needed {
                return Err(Error::ConnectionIdLimitError);
            }
            // The lowest scid need to be retired
            self.retire_prior_to = self.lowest_active_scid_seq()? + 1;
        }

        let seq = self.next_scid_seq;
        if seq != 0 && reset_token.is_none() {
            return Err(Error::InternalError);
        }
        self.scids.insert(ConnectionIdItem {
            cid,
            seq,
            reset_token,
            path_id,
        })?;
        self.next_scid_seq += 1;

        self.mark_scid_to_advertise(seq, advertise);
        Ok(seq)
    }

    /// Add a new destination CID from a NEW_CONNECTION_ID frame
    ///
    /// It returns the cids which should be retired and the affected paths.
    pub fn add_dcid(
        &mut self,
        cid: ConnectionId,
        seq: u64,
        reset_token: u128,
        retire_prior_to: u64,
    ) -> Result<Vec<(u64, usize)>> {
        if self.zero_length_dcid {
            return Err(Error::ProtocolViolation);
        }

        let mut retired_path_ids = Vec::new();

        // If an endpoint receives a NEW_CONNECTION_ID frame that repeats a
        // previously issued connection ID with a different Stateless Reset
        // Token field value or a different Sequence Number field value, or if
        // a sequence number is used for different connection IDs, the endpoint
        // MAY treat that receipt as a connection error of type
        // PROTOCOL_VIOLATION. (RFC 9000 Section 19.15)
        if let Some(e) = self.dcids.iter().find(|e| e.cid == cid || e.seq == seq) {
            if e.cid != cid || e.seq != seq || e.reset_token != Some(reset_token) {
                return Err(Error::ProtocolViolation);
            }
            return Ok(retired_path_ids);
        }

        // The value in the Retire Prior To field MUST be less than or equal to
        // the value in the Sequence Number field. Receiving a value in the
        // Retire Prior To field that is greater than that in the Sequence
        // Number field MUST be treated as a connection error of type
        // FRAME_ENCODING_ERROR. (RFC 9000 Section 19.15)
        if retire_prior_to > seq {
            return Err(Error::ProtocolViolation);
        }

        // An endpoint that receives a NEW_CONNECTION_ID frame with a sequence
        // number smaller than the Retire Prior To field of a previously
        // received NEW_CONNECTION_ID frame MUST send a corresponding
        // RETIRE_CONNECTION_ID frame that retires the newly received connection
        // ID, unless it has already done so for that sequence number.
        // (RFC 9000 Section 19.15)
        if seq < self.largest_peer_retire_prior_to && !self.dcids_to_retire.contains(&seq) {
            self.dcids_to_retire.push_back(seq);
            self.check_dcids_to_retire()?;
            return Ok(retired_path_ids);
        }

        let cid_item = ConnectionIdItem {
            cid,
            seq,
            reset_token: Some(reset_token),
            path_id: None,
        };

        // A receiver MUST ignore any Retire Prior To fields that do not
        // increase the largest received Retire Prior To value.
        if retire_prior_to > self.largest_peer_retire_prior_to {
            let retired = &mut self.dcids_to_retire;
            self.dcids.remove_lower(retire_prior_to, |cid| {
                retired.push_back(cid.seq);
                if let Some(pid) = cid.path_id {
                    retired_path_ids.push((cid.seq, pid));
                }
            });
            self.largest_peer_retire_prior_to = retire_prior_to;
            self.check_dcids_to_retire()?;
        }

        // After processing a NEW_CONNECTION_ID frame and adding and retiring
        // active connection IDs, if the number of active connection IDs exceeds
        // the value advertised in its active_connection_id_limit transport
        // parameter, an endpoint MUST close the connection with an error of type
        // CONNECTION_ID_LIMIT_ERROR.
        self.dcids.insert(cid_item)?;

        Ok(retired_path_ids)
    }

    /// Check and limit the total number of dcids to be retried.
    fn check_dcids_to_retire(&self) -> Result<()> {
        // An attacker might flood the server with NEW_CONNECTION_ID frames, and
        // force it to respond with numerous RETIRE_CONNECTION_ID frames. If the
        // attacker ignores these responses, a large queue of unacknowledged
        // RETIRE_CONNECTION_ID frames will accumulate on the server. Over time,
        // this could exhaust the server's memory.
        //
        // The endpoint should limit the number of queued RETIRE_CONNECTION)ID
        // frames and break the connection if the peer exceeds this limit.
        if self.dcids_to_retire.len() > self.dcid_limit * 4 {
            return Err(Error::ProtocolViolation);
        }
        Ok(())
    }

    /// Retire the Source CID from a RETIRE_CONNECTION_ID frame
    pub fn retire_scid(&mut self, seq: u64, pkt_dcid: &ConnectionId) -> Result<Option<usize>> {
        // Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number
        // greater than any previously sent to the peer MUST be treated as a
        // connection error of type PROTOCOL_VIOLATION
        if seq >= self.next_scid_seq {
            return Err(Error::ProtocolViolation);
        }

        let pid = if let Some(e) = self.scids.remove(seq)? {
            // The sequence number specified in a RETIRE_CONNECTION_ID frame
            // MUST NOT refer to the Destination Connection ID field of the
            // packet in which the frame is contained. The peer MAY treat this
            // as a connection error of type PROTOCOL_VIOLATION.
            if e.cid == *pkt_dcid {
                return Err(Error::ProtocolViolation);
            }
            // Retiring this SCID may increase the retire prior to.
            self.retire_prior_to = self.lowest_active_scid_seq()?;
            e.path_id
        } else {
            None
        };

        Ok(pid)
    }

    /// Add or remove the source CID to be advertised to the peer.
    pub fn mark_scid_to_advertise(&mut self, seq: u64, advertise: bool) {
        if advertise {
            self.scids_to_advertise.push_back(seq);
        } else {
            self.scids_to_advertise.retain(|s| *s != seq)
        }
    }

    /// Add or remove the destination CID to be advertised to the
    /// peer through RETIRE_CONNECTION_ID frames.
    pub fn mark_dcid_to_retire(&mut self, seq: u64, retire: bool) {
        if retire {
            self.dcids_to_retire.push_back(seq);
        } else {
            self.dcids_to_retire.retain(|s| *s != seq);
        }
    }

    /// Get a source CID requiring to be advertised to the peer through the
    /// NEW_CONNECTION_ID frame, if any.
    pub fn next_scid_to_advertise(&self) -> Option<u64> {
        self.scids_to_advertise.front().copied()
    }

    /// Get a destination CID requiring to be retired through the
    /// RETIRE_CONNECTION_ID frame, if any.
    pub fn next_dcid_to_retire(&self) -> Option<u64> {
        self.dcids_to_retire.front().copied()
    }

    /// Create NEW_CONNECTION_ID for the given CID.
    pub fn create_new_connection_id_frame(&self, seq: u64) -> Result<Frame> {
        let item = self.scids.get(seq).ok_or(Error::InternalError)?;

        let frame = Frame::NewConnectionId {
            seq_num: seq,
            retire_prior_to: self.retire_prior_to,
            conn_id: item.cid,
            reset_token: ResetToken(item.reset_token.ok_or(Error::InternalError)?.to_be_bytes()),
        };
        Ok(frame)
    }

    /// Whether NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frames should be sent.
    pub fn need_send_cid_control_frames(&self) -> bool {
        !self.dcids_to_retire.is_empty() || !self.scids_to_advertise.is_empty()
    }

    /// Return true if the Destination CID is zero length
    pub fn zero_length_dcid(&self) -> bool {
        self.zero_length_dcid
    }

    /// Return true if the source CID is zero length
    pub fn zero_length_scid(&self) -> bool {
        self.zero_length_scid
    }

    /// Return an iterator over destination ConnectionIdItem
    pub fn dcid_iter(&self) -> impl Iterator<Item = &ConnectionIdItem> {
        self.dcids.iter()
    }

    /// Return an iterator over source ConnectionIdItem
    pub fn scid_iter(&self) -> impl Iterator<Item = &ConnectionIdItem> {
        self.scids.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_test_cid_mgr() -> ConnectionIdMgr {
        let scid0 = ConnectionId::random();
        let dcid0 = ConnectionId::random();
        let mut cids = ConnectionIdMgr::new(2, &scid0, 0, None);
        cids.set_scid_limit(2);
        cids.set_initial_dcid(dcid0, None, Some(0));
        cids
    }

    #[test]
    fn cid_queue() -> Result<()> {
        let mut queue = ConnectionIdDeque::new(1);
        assert_eq!(queue.len(), 0);
        assert!(queue.remove(0).is_err());

        assert_eq!(
            queue.insert(ConnectionIdItem {
                cid: ConnectionId::random(),
                seq: 0,
                reset_token: None,
                path_id: None
            }),
            Ok(())
        );
        assert_eq!(
            queue.insert(ConnectionIdItem {
                cid: ConnectionId::random(),
                seq: 1,
                reset_token: None,
                path_id: None
            }),
            Err(Error::ConnectionIdLimitError)
        );
        assert!(queue.remove(0).is_err());

        Ok(())
    }

    #[test]
    fn find_cid() -> Result<()> {
        let scid0 = ConnectionId::random();
        let dcid0 = ConnectionId::random();
        let mut cids = ConnectionIdMgr::new(8, &scid0, 0, None);
        cids.set_scid_limit(8);
        cids.set_initial_dcid(dcid0, None, Some(0));

        assert_eq!(cids.zero_length_scid(), false);
        assert_eq!(cids.zero_length_dcid(), false);
        assert_eq!(cids.get_scid(0)?.cid, scid0);
        assert_eq!(cids.get_dcid(0)?.cid, dcid0);
        assert!(cids.get_scid(1).is_err());
        assert!(cids.get_dcid(1).is_err());

        assert_eq!(cids.find_scid(&scid0), Some((0, Some(0))));
        assert_eq!(cids.find_scid(&dcid0), None);

        Ok(())
    }

    #[test]
    fn add_new_scid() -> Result<()> {
        let mut cids = new_test_cid_mgr();
        assert_eq!(cids.unused_scids(), 0);
        assert_eq!(cids.next_scid_to_advertise(), None);

        // Add an invalid scid without reset token
        let scid1 = ConnectionId::random();
        assert_eq!(
            cids.add_scid(scid1, None, true, None, false),
            Err(Error::InternalError)
        );

        // Add a valid scid
        cids.add_scid(scid1, Some(1), true, None, false)?;
        assert_eq!(cids.unused_scids(), 1);
        assert_eq!(cids.next_scid_to_advertise(), Some(1));
        assert_eq!(cids.need_send_cid_control_frames(), true);

        // Try to add more scid
        let scid2 = ConnectionId::random();
        assert_eq!(
            cids.add_scid(scid2, Some(2), true, None, false),
            Err(Error::ConnectionIdLimitError)
        );

        // Fake sending of NEW_CONNECTION_ID; mark it as advertised
        let frame = cids.create_new_connection_id_frame(1)?;
        assert_eq!(
            frame,
            Frame::NewConnectionId {
                seq_num: 1,
                retire_prior_to: 0,
                conn_id: scid1,
                reset_token: ResetToken(1_u128.to_be_bytes()),
            }
        );

        cids.mark_scid_to_advertise(1, false);
        assert_eq!(cids.unused_scids(), 1);
        assert_eq!(cids.next_scid_to_advertise(), None);
        assert_eq!(cids.need_send_cid_control_frames(), false);

        // Fake receiving packet using scid1; mark it as used
        cids.mark_scid_used(1, 1)?;
        assert_eq!(cids.unused_scids(), 0);
        assert_eq!(cids.next_scid_to_advertise(), None);

        Ok(())
    }

    #[test]
    fn retire_old_scid() -> Result<()> {
        let mut cids = new_test_cid_mgr();

        // Add a new scid
        let scid1 = ConnectionId::random();
        cids.add_scid(scid1, Some(1), true, None, false)?;
        assert_eq!(cids.unused_scids(), 1);

        // Fake sending of NEW_CONNECTION_ID
        cids.mark_scid_to_advertise(1, false);
        assert_eq!(cids.need_send_cid_control_frames(), false);

        // Fake receiving of RETIRE_CONNECTION_ID
        let pid = cids.retire_scid(0, &scid1)?;
        assert_eq!(pid, Some(0));
        assert!(cids.get_scid(0).is_err());
        assert_eq!(cids.unused_scids(), 1);
        assert_eq!(cids.next_scid_to_advertise(), None);

        // Fake receiving of duplicated RETIRE_CONNECTION_ID
        let pid = cids.retire_scid(0, &scid1)?;
        assert_eq!(pid, None);

        Ok(())
    }

    #[test]
    fn add_new_dcid() -> Result<()> {
        let mut cids = new_test_cid_mgr();
        assert_eq!(cids.unused_dcids(), 0);
        assert_eq!(cids.largest_peer_retire_prior_to, 0);

        // Fake receiving of NEW_CONNECTION_ID
        let dcid1 = ConnectionId::random();
        let affected_paths = cids.add_dcid(dcid1, 2, 2, 2)?;
        assert_eq!(cids.unused_dcids(), 1);
        assert_eq!(cids.largest_peer_retire_prior_to, 2);
        assert_eq!(cids.dcids_to_retire.len(), 1);
        assert_eq!(cids.need_send_cid_control_frames(), true);
        assert_eq!(affected_paths.len(), 1);

        let (dcid_seq, pid) = affected_paths[0];
        assert_eq!(dcid_seq, 0);
        assert_eq!(pid, 0);

        // Assign unused dcid for affected path
        let unused_dcid = cids.lowest_unused_dcid_seq();
        assert_eq!(unused_dcid, Some(2));

        cids.mark_dcid_used(2, 0)?;
        assert_eq!(cids.unused_dcids(), 0);

        // Fake receiving of a reordered NEW_CONNECTION_ID with seq lower than
        // largest_peer_retire_prior_to
        let dcid2 = ConnectionId::random();
        let affected_paths = cids.add_dcid(dcid2, 1, 1, 1)?;
        assert_eq!(affected_paths.len(), 0);
        assert_eq!(cids.dcids_to_retire.len(), 2);

        Ok(())
    }

    #[test]
    fn retire_new_dcid() -> Result<()> {
        let mut cids = new_test_cid_mgr();

        // Fake receiving of NEW_CONNECTION_ID
        let dcid1 = ConnectionId::random();
        cids.add_dcid(dcid1, 1, 1, 1)?;

        assert_eq!(cids.next_dcid_to_retire(), Some(0));
        assert_eq!(cids.need_send_cid_control_frames(), true);

        // Fake sending of RETIRE_CONNECTION_ID
        cids.mark_dcid_to_retire(0, false);
        assert_eq!(cids.next_dcid_to_retire(), None);
        assert_eq!(cids.need_send_cid_control_frames(), false);

        // Fake lost of RETIRE_CONNECTION_ID
        cids.mark_dcid_to_retire(0, true);
        assert_eq!(cids.next_dcid_to_retire(), Some(0));
        assert_eq!(cids.need_send_cid_control_frames(), true);

        Ok(())
    }

    #[test]
    fn zero_length_cid() -> Result<()> {
        let scid0 = ConnectionId {
            len: 0,
            data: [0; 20],
        };
        let dcid0 = ConnectionId {
            len: 0,
            data: [0; 20],
        };
        let mut cids = ConnectionIdMgr::new(2, &scid0, 0, None);
        cids.set_initial_dcid(dcid0, None, Some(0));

        assert!(cids.zero_length_scid());
        assert!(cids.zero_length_dcid());

        assert_eq!(cids.unused_scids(), 0);
        assert_eq!(cids.unused_dcids(), 0);

        assert!(cids
            .add_scid(ConnectionId::random(), None, false, None, false)
            .is_err());
        assert!(cids.add_dcid(ConnectionId::random(), 1, 1, 1).is_err());

        Ok(())
    }

    #[test]
    fn new_scid_exceed_limit() -> Result<()> {
        let mut cids = new_test_cid_mgr();
        cids.add_scid(ConnectionId::random(), Some(1), true, None, false)?;

        // Add more scid (retire_if_needed=false)
        let scid2 = ConnectionId::random();
        assert_eq!(
            cids.add_scid(scid2, Some(2), true, None, false),
            Err(Error::ConnectionIdLimitError)
        );

        // Add more scid (retire_if_needed=true)
        assert_eq!(cids.add_scid(scid2, Some(2), true, None, true), Ok(2));
        assert_eq!(cids.lowest_active_scid_seq()?, 1);

        Ok(())
    }

    #[test]
    fn invalid_new_connection_id() -> Result<()> {
        let scid0 = ConnectionId::random();
        let dcid0 = ConnectionId::random();
        let mut cids = ConnectionIdMgr::new(2, &scid0, 0, None);
        cids.set_initial_dcid(dcid0, Some(0), Some(0));

        // Fake receiving of NEW_CONNECTION_ID that repeats a previously issued
        // CID with a different sequence number
        assert_eq!(cids.add_dcid(dcid0, 1, 0, 0), Err(Error::ProtocolViolation));

        // Fake receiving of NEW_CONNECTION_ID that repeats a previously issued
        // CID with a different reset token
        assert_eq!(cids.add_dcid(dcid0, 0, 1, 0), Err(Error::ProtocolViolation));

        // Fake receiving of NEW_CONNECTION_ID that carrys a new issued CID with
        // a duplicated sequence number
        assert_eq!(
            cids.add_dcid(ConnectionId::random(), 0, 1, 0),
            Err(Error::ProtocolViolation)
        );

        // Fake receiving of NEW_CONNECTION_ID that carrys a new issued CID with
        // an invalid Retire Prior To field
        assert_eq!(
            cids.add_dcid(ConnectionId::random(), 1, 1, 2),
            Err(Error::ProtocolViolation)
        );

        // Fake receiving of a duplicated NEW_CONNECTION_ID
        assert!(cids.add_dcid(dcid0, 0, 0, 0).is_ok());

        Ok(())
    }

    #[test]
    fn invalid_retire_connection_id() -> Result<()> {
        let scid0 = ConnectionId::random();
        let dcid0 = ConnectionId::random();
        let mut cids = ConnectionIdMgr::new(2, &scid0, 0, None);
        cids.set_initial_dcid(dcid0, Some(0), Some(0));
        let scid1 = ConnectionId::random();
        cids.add_scid(scid1, Some(1), true, None, false)?;

        // Fake sending of NEW_CONNECTION_ID
        cids.mark_scid_to_advertise(1, false);

        // Fake receiving of RETIRE_CONNECTION_ID that carrys invalid sequence number
        assert_eq!(cids.retire_scid(2, &scid1), Err(Error::ProtocolViolation));

        // Fake receiving of RETIRE_CONNECTION_ID that use an unexpected path
        assert_eq!(cids.retire_scid(0, &scid0), Err(Error::ProtocolViolation));

        Ok(())
    }

    #[test]
    fn new_connection_id_flood() -> Result<()> {
        let dcid_limit = 8;
        let scid0 = ConnectionId::random();
        let dcid0 = ConnectionId::random();
        let mut cids = ConnectionIdMgr::new(dcid_limit, &scid0, 0, None);
        cids.set_initial_dcid(dcid0, Some(0), Some(0));

        let max_dcids_to_retire = dcid_limit * 4;
        for i in 1..50 {
            // Fake receiving of NEW_CONNECTION_ID that retries a previously issued CID
            let dcid = ConnectionId::random();
            let ret = cids.add_dcid(dcid, i, i as u128, i);
            if cids.dcids_to_retire.len() > max_dcids_to_retire {
                assert_eq!(ret, Err(Error::ProtocolViolation));
            }
        }
        assert!(cids.dcids_to_retire.len() <= max_dcids_to_retire + 1);

        Ok(())
    }
}
