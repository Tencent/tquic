// Copyright (c) 2024 bondq — TEMPO multipath scheduler (added to the TQUIC fork).
//
// TEMPO is an arrival-time (earliest-delivery-path-first) scheduler. For each
// packet it predicts the time the packet would ARRIVE at the receiver on every
// eligible path and picks the earliest:
//
//     arrival_i = bytes_in_flight_i / pacing_rate_i + smoothed_rtt_i / 2
//
// The first term is how long the path's current backlog takes to drain at its
// (BBR-estimated) rate; the second is the one-way propagation delay. Selecting
// the minimum distributes load in proportion to each path's capacity AND keeps
// packets arriving near-ordered, so a SINGLE stream aggregates across
// heterogeneous paths — unlike MinRtt, which concentrates on the lowest-RTT
// path and never spills while BBR keeps it un-full.

use crate::connection::path::PathMap;
use crate::connection::space::PacketNumSpaceMap;
use crate::connection::stream::StreamMap;
use crate::multipath_scheduler::MultipathScheduler;
use crate::Error;
use crate::MultipathConfig;
use crate::Result;

pub struct TempoScheduler {}

impl TempoScheduler {
    pub fn new(_conf: &MultipathConfig) -> TempoScheduler {
        TempoScheduler {}
    }
}

impl MultipathScheduler for TempoScheduler {
    fn on_select(
        &mut self,
        paths: &mut PathMap,
        _spaces: &mut PacketNumSpaceMap,
        _streams: &mut StreamMap,
    ) -> Result<usize> {
        let max_srtt = paths.max_srtt;
        let mut best: Option<(usize, f64)> = None;
        let mut best_unhealthy: Option<(usize, f64)> = None;
        for (pid, path) in paths.iter_mut() {
            if !path.active() || !path.recovery.can_send() {
                continue;
            }
            let srtt = path.recovery.rtt.smoothed_rtt().as_secs_f64();
            let owd = srtt / 2.0;
            let inflight = path.recovery.bytes_in_flight as f64;
            // rate = BBR pacing-rate estimate (bytes/sec); fall back to
            // cwnd/srtt when pacing rate is unavailable.
            let rate = match path.recovery.congestion.pacing_rate() {
                Some(r) if r > 0 => r as f64,
                _ => {
                    let cwnd = path.recovery.congestion.congestion_window() as f64;
                    if srtt > 0.0 {
                        (cwnd / srtt).max(1.0e6)
                    } else {
                        1.0e8
                    }
                }
            };
            let arrival = inflight / rate + owd;
            // Blackhole-suspect paths are only used when no healthy path can.
            let slot = if path.unhealthy_with(max_srtt) {
                &mut best_unhealthy
            } else {
                &mut best
            };
            match slot {
                None => *slot = Some((pid, arrival)),
                Some((_, a)) => {
                    if arrival < *a {
                        *slot = Some((pid, arrival));
                    }
                }
            }
        }
        match best.or(best_unhealthy) {
            Some((i, _)) => Ok(i),
            None => Err(Error::Done),
        }
    }
}
