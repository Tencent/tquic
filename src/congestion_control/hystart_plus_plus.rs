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

//! HyStart++: Modified Slow Start for TCP.
//!
//! HyStart++, a simple modification to the slow start phase of congestion
//! control algorithms. Slow start can overshoot the ideal send rate in many cases,
//! causing high packet loss and poor performance. HyStart++ uses increase in
//! round-trip delay as a heuristic to find an exit point before possible overshoot.
//! It also adds a mitigation to prevent jitter from causing premature slow start exit.
//!
//! See <https://www.rfc-editor.org/rfc/rfc9406.html>.

use std::time::Duration;
use std::time::Instant;

/// Tuning constants. Lower bound of the delay increase sensitivity.
///
/// Smaller values of `MIN_RTT_THRESH` may cause spurious exits from slow start.
///
/// See <https://www.rfc-editor.org/rfc/rfc9406.html#name-tuning-constants-and-other->.
const MIN_RTT_THRESH: Duration = Duration::from_millis(4);

/// Tuning constants. Upper bound of the delay increase sensitivity.
///
/// Larger values of `MAX_RTT_THRESH` may result in slow start not exiting until loss is
/// encountered for connections on large RTT paths.
///
/// See <https://www.rfc-editor.org/rfc/rfc9406.html#name-tuning-constants-and-other->.
const MAX_RTT_THRESH: Duration = Duration::from_millis(16);

/// Tuning constants. A fraction of RTT to compute the delay threshold.
///
/// A smaller value would mean a larger threshold and thus less sensitivity to delay
/// increase, and vice versa.
///
/// See <https://www.rfc-editor.org/rfc/rfc9406.html#name-tuning-constants-and-other->.
const MIN_RTT_DIVISOR: u32 = 8;

/// Tuning constants. The least sample counts in one round.
///
/// Using lower values of `N_RTT_SAMPLE` will lower the accuracy of the measured RTT for
/// the round; higher values will improve accuracy at the cost of more processing.
///
/// See <https://www.rfc-editor.org/rfc/rfc9406.html#name-tuning-constants-and-other->.
pub const N_RTT_SAMPLE: u32 = 8;

/// Tuning constants. A divisor factor to make slow start less aggressive.
///
/// MUST be at least `2`.
/// See <https://www.rfc-editor.org/rfc/rfc9406.html#name-tuning-constants-and-other->.
pub const CSS_GROWTH_DIVISOR: u32 = 4;

/// Tuning constants. The max lasting rounds in Conservative Slow Start (CSS).
///
/// Smaller values may miss detecting jitter, and larger values may limit performance.
///
/// See <https://www.rfc-editor.org/rfc/rfc9406.html#name-tuning-constants-and-other->.
pub const CSS_ROUNDS: u32 = 5;

/// Tuning constants. The max congestion window growth in MSS.
///
/// `L` values smaller than infinity may suffer performance problems due to slow cwnd growth in
/// high-speed networks. For non-paced implementations, `L` values smaller than `8` may suffer
/// performance problems due to slow cwnd growth in high-speed networks; `L` values larger than
/// `8` may cause an increase in burstiness and thereby loss rates, and result in poor performance.
///
/// See <https://www.rfc-editor.org/rfc/rfc9406.html#name-tuning-constants-and-other->.
const HYSTART_L: u32 = 64;

/// HyStart++ phase.
#[derive(Debug, PartialEq)]
enum HystartPhase {
    /// Hystart++ is in standard slow start.
    InStandardSlowStart,

    /// Hystart++ is in CSS phase.
    InConservativeSlowStart,

    /// Hystart++ exited and should enter congestion avoidance.
    Exited,
}

/// Implementation of HyStart++.
pub struct HystartPlusPlus {
    /// Whether Hystart++ is enabled.
    enabled: bool,

    /// Whether in Conservative Slow Start phase.
    phase: HystartPhase,

    /// lastRoundMinRTT: MinRTT in last round.
    last_round_min_rtt: Duration,

    /// currentRoundMinRTT: MinRTT in current round.
    current_round_min_rtt: Duration,

    /// RTT sample count in current round.
    rtt_sample_count: u32,

    /// The last sent packet number, for updating round.
    last_sent_pkt_num: u64,

    /// Max acked packet number.
    max_acked_packet_num: u64,

    /// windowEnd: the end packet number of current round.
    window_end: u64,

    /// Conservative Slow Start round count.
    css_round_count: u32,

    /// cssBaselineMinRtt: Conservative Slow Start baseline minRTT.
    css_baseline_min_rtt: Duration,
}

impl std::fmt::Debug for HystartPlusPlus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Hystart ")?;
        write!(f, "Hystart_enabled={:?} ", self.enabled)?;
        write!(f, "phase={:?} ", self.phase)?;
        write!(
            f,
            "last_round_min_rtt={:?} ",
            self.last_round_min_rtt.as_millis()
        )?;
        write!(
            f,
            "current_round_min_rtt={:?} ",
            self.current_round_min_rtt.as_millis()
        )?;
        write!(f, "rtt_sample_count={:?} ", self.rtt_sample_count)?;
        write!(f, "last_sent_pkt_num={:?} ", self.last_sent_pkt_num)?;
        write!(f, "max_acked_pkt_num={:?} ", self.max_acked_packet_num)?;
        write!(f, "window_end={:?} ", self.window_end)?;
        write!(f, "css_round_count={:?} ", self.css_round_count)?;
        write!(
            f,
            "css_baseline_min_rtt={:?} ",
            self.css_baseline_min_rtt.as_millis()
        )?;

        Ok(())
    }
}

impl HystartPlusPlus {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            phase: HystartPhase::InStandardSlowStart,
            last_round_min_rtt: Duration::MAX,
            current_round_min_rtt: Duration::MAX,
            rtt_sample_count: 0,
            last_sent_pkt_num: 0,
            max_acked_packet_num: 0,
            window_end: 0,
            css_round_count: 0,
            css_baseline_min_rtt: Duration::MAX,
        }
    }

    /// Whether Hystart++ is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether Hystart++ has exited.
    pub fn has_exited(&self) -> bool {
        self.phase == HystartPhase::Exited
    }

    /// Whether in conservative slow start phase.
    pub fn in_conservative_slow_start(&self) -> bool {
        self.phase == HystartPhase::InConservativeSlowStart
    }

    /// Whether in standard slow start phase.
    pub fn in_standard_slow_start(&self) -> bool {
        self.phase == HystartPhase::InStandardSlowStart
    }

    /// Process sending packets, update round trip end if necessary.
    pub fn on_sent(&mut self, pkt_num: u64) {
        self.last_sent_pkt_num = pkt_num;
    }

    /// Process received ACK, determine which phase is in.
    pub fn on_ack(&mut self, pkt_num: u64, acked_bytes: u64, rtt: Duration) {
        if !self.enabled && !self.has_exited() {
            return;
        }

        self.max_acked_packet_num = pkt_num.max(self.max_acked_packet_num);

        // Keep track of the minimum observed RTT.
        self.current_round_min_rtt = self.current_round_min_rtt.min(rtt);

        self.rtt_sample_count += 1;

        // Check to see if delay increase triggers slow start exit.
        // See <https://www.rfc-editor.org/rfc/rfc9406.html#name-algorithm-details>.
        match self.phase {
            HystartPhase::InStandardSlowStart => {
                if self.rtt_sample_count >= N_RTT_SAMPLE
                    && self.current_round_min_rtt != Duration::MAX
                    && self.last_round_min_rtt != Duration::MAX
                {
                    let rtt_thresh = (self.last_round_min_rtt / MIN_RTT_DIVISOR)
                        .clamp(MIN_RTT_THRESH, MAX_RTT_THRESH);

                    if self.current_round_min_rtt
                        >= self.last_round_min_rtt.saturating_add(rtt_thresh)
                    {
                        self.css_baseline_min_rtt = self.current_round_min_rtt;
                        self.phase = HystartPhase::InConservativeSlowStart;
                    }
                }
            }
            HystartPhase::InConservativeSlowStart => {
                if self.rtt_sample_count >= N_RTT_SAMPLE
                    && self.current_round_min_rtt < self.css_baseline_min_rtt
                {
                    // Slow start exit was spurious, resume standard slow start.
                    self.css_baseline_min_rtt = Duration::MAX;
                    self.phase = HystartPhase::InStandardSlowStart;
                    self.css_round_count = 0;
                }
            }
            _ => (),
        };
    }

    /// Update round after processing ranges of ACKs.
    pub fn end_ack(&mut self) {
        if !self.enabled() && !self.has_exited() {
            return;
        }

        // Update round.
        if self.max_acked_packet_num > self.window_end {
            // Round ends, start a new round
            self.window_end = self.last_sent_pkt_num;

            // lastRoundMinRTT = currentRoundMinRTT
            // currentRoundMinRTT = infinity
            // rttSampleCount = 0
            // See <https://www.rfc-editor.org/rfc/rfc9406.html#name-algorithm-details>.
            self.last_round_min_rtt = self.current_round_min_rtt;
            self.current_round_min_rtt = Duration::MAX;
            self.rtt_sample_count = 0;

            // CSS lasts at most CSS_ROUNDS rounds.
            if self.in_conservative_slow_start() {
                self.css_round_count += 1;
                if self.css_round_count >= CSS_ROUNDS {
                    // Enter congestion avoidance.
                    self.css_round_count = 0;
                    self.phase = HystartPhase::Exited;
                }
            }
        }
    }

    /// Exit HyStart++ if congestion event happens, enter congestion avoidance.
    pub fn on_congestion_event(&mut self) {
        if self.enabled {
            self.window_end = 0;
            self.phase = HystartPhase::Exited;
        }
    }

    /// Congestion window increment.
    pub fn cwnd_increment(&self, acked_bytes: u64, max_datagram_size: u64) -> u64 {
        match self.phase {
            HystartPhase::InStandardSlowStart => {
                acked_bytes.min(HYSTART_L as u64 * max_datagram_size)
            }
            HystartPhase::InConservativeSlowStart => {
                (acked_bytes / CSS_GROWTH_DIVISOR as u64).min(HYSTART_L as u64 * max_datagram_size)
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct AckPacket {
        pkt_num: u64,
        acked_bytes: u64,
        rtt: Duration,
    }

    #[test]
    fn hystart_on_event() {
        let mut hspp = HystartPlusPlus::new(true);

        assert_eq!(hspp.enabled(), true);
        assert_eq!(hspp.in_standard_slow_start(), true);

        let max_datagram_size: u64 = 1350; // Just for test.
        let acked_bytes: u64 = max_datagram_size;
        let pkt_num: u64 = 1;
        let mut rtt_ms: Vec<Duration> = Vec::new();
        let mut ack_packets: Vec<AckPacket> = Vec::new();
        let min_round_rtt_in_ms: Vec<u64> = vec![
            30, // Round 1. Initial slow start.
            32, // Round 2. Still in slow start.
            38, // Round 3. Switch to CSS. Baseline 38ms.
            40, // Round 4. Still in CSS.
            36, // Round 5. CSS switch to slow start.
            42, // Round 6. Switch to CSS. Baseline 42ms. CSS round 1.
            43, // Round 7. Still in CSS. CSS round 2.
            44, // Round 8. Still in CSS. CSS round 3.
            45, // Round 9. Still in CSS. CSS round 4.
            46, // Round 10. Still in CSS. CSS round 5. After this round, switch to Congestion Avoidance.
        ];

        let n_rounds: usize = min_round_rtt_in_ms.len();
        let sample_cnt: u64 = N_RTT_SAMPLE as u64 * n_rounds as u64;

        assert_eq!(min_round_rtt_in_ms.len(), n_rounds);

        for round in 0..n_rounds {
            for i in 0..N_RTT_SAMPLE {
                rtt_ms.push(
                    Duration::from_millis(min_round_rtt_in_ms[round])
                        + Duration::from_millis(i as u64),
                );
            }
        }

        for i in 0..sample_cnt {
            ack_packets.push(AckPacket {
                pkt_num: i + 1,
                acked_bytes: acked_bytes,
                rtt: rtt_ms[i as usize],
            });
        }

        let mut round: usize = 0;

        // Round 1. -> standard slow start (SSS).
        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            println!("sent {}", i);
            hspp.on_sent((i + 1) as u64);
        }
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(
            hspp.last_sent_pkt_num,
            (round + 1) as u64 * N_RTT_SAMPLE as u64
        );

        // Receive ACKs. Round 1.
        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            hspp.on_ack(
                ack_packets[i as usize].pkt_num,
                ack_packets[i as usize].acked_bytes,
                ack_packets[i as usize].rtt,
            );
            println!("{:?}", hspp);
        }

        assert_eq!(
            hspp.max_acked_packet_num,
            (round + 1) as u64 * N_RTT_SAMPLE as u64
        );

        assert_eq!(hspp.last_round_min_rtt, Duration::MAX);
        assert_eq!(
            hspp.current_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.rtt_sample_count, N_RTT_SAMPLE);

        hspp.end_ack();
        assert_eq!(hspp.in_standard_slow_start(), true);
        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.current_round_min_rtt, Duration::MAX);
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(hspp.window_end, hspp.last_sent_pkt_num);

        // Round 2. SSS -> SSS.
        round += 1;

        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            println!("sent {}", i);
            hspp.on_sent((i + 1) as u64);
        }
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(
            hspp.last_sent_pkt_num,
            (round + 1) as u64 * N_RTT_SAMPLE as u64
        );

        // Receive ACKs.
        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            hspp.on_ack(
                ack_packets[i as usize].pkt_num,
                ack_packets[i as usize].acked_bytes,
                ack_packets[i as usize].rtt,
            );
            println!("{:?}", hspp);
        }

        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round.saturating_sub(1)])
        );
        assert_eq!(
            hspp.current_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.rtt_sample_count, N_RTT_SAMPLE);

        hspp.end_ack();

        // Still in standard slow start.
        assert_eq!(hspp.in_standard_slow_start(), true);
        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.current_round_min_rtt, Duration::MAX);
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(hspp.window_end, hspp.last_sent_pkt_num);

        // Congestion window increment in SSS.
        assert_eq!(
            hspp.cwnd_increment(acked_bytes * N_RTT_SAMPLE as u64, max_datagram_size),
            acked_bytes * N_RTT_SAMPLE as u64
        );

        // Round 3. SSS -> conservative slow start (CSS).
        round += 1;

        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            println!("sent {}", i);
            hspp.on_sent((i + 1) as u64);
        }
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(
            hspp.last_sent_pkt_num,
            (round + 1) as u64 * N_RTT_SAMPLE as u64
        );

        // Receive ACKs.
        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            hspp.on_ack(
                ack_packets[i as usize].pkt_num,
                ack_packets[i as usize].acked_bytes,
                ack_packets[i as usize].rtt,
            );
            println!("{:?}", hspp);
        }

        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round.saturating_sub(1)])
        );
        assert_eq!(
            hspp.current_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.rtt_sample_count, N_RTT_SAMPLE);

        hspp.end_ack();

        // In CSS.
        assert_eq!(hspp.in_conservative_slow_start(), true);
        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.current_round_min_rtt, Duration::MAX);
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(hspp.window_end, hspp.last_sent_pkt_num);

        // Round 3. CSS -> CSS.
        round += 1;

        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            println!("sent {}", i);
            hspp.on_sent((i + 1) as u64);
        }
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(
            hspp.last_sent_pkt_num,
            (round + 1) as u64 * N_RTT_SAMPLE as u64
        );

        // Receive ACKs.
        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            hspp.on_ack(
                ack_packets[i as usize].pkt_num,
                ack_packets[i as usize].acked_bytes,
                ack_packets[i as usize].rtt,
            );
            println!("{:?}", hspp);
        }

        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round.saturating_sub(1)])
        );
        assert_eq!(
            hspp.current_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.rtt_sample_count, N_RTT_SAMPLE);

        hspp.end_ack();

        // Still in standard slow start.
        assert_eq!(hspp.in_conservative_slow_start(), true);
        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.current_round_min_rtt, Duration::MAX);
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(hspp.window_end, hspp.last_sent_pkt_num);

        // Congestion window increment in CSS.
        assert_eq!(
            hspp.cwnd_increment(acked_bytes * N_RTT_SAMPLE as u64, max_datagram_size),
            acked_bytes * N_RTT_SAMPLE as u64 / CSS_GROWTH_DIVISOR as u64
        );

        // Round 4. CSS -> SSS.
        round += 1;

        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            println!("sent {}", i);
            hspp.on_sent((i + 1) as u64);
        }
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(
            hspp.last_sent_pkt_num,
            (round + 1) as u64 * N_RTT_SAMPLE as u64
        );

        // Receive ACKs.
        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            hspp.on_ack(
                ack_packets[i as usize].pkt_num,
                ack_packets[i as usize].acked_bytes,
                ack_packets[i as usize].rtt,
            );
            println!("{:?}", hspp);
        }

        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round.saturating_sub(1)])
        );
        assert_eq!(
            hspp.current_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.rtt_sample_count, N_RTT_SAMPLE);

        hspp.end_ack();

        // In CSS.
        assert_eq!(hspp.in_standard_slow_start(), true);
        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.current_round_min_rtt, Duration::MAX);
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(hspp.window_end, hspp.last_sent_pkt_num);

        // Round 5. SSS -> CSS.
        round += 1;

        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            println!("sent {}", i);
            hspp.on_sent((i + 1) as u64);
        }
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(
            hspp.last_sent_pkt_num,
            (round + 1) as u64 * N_RTT_SAMPLE as u64
        );

        // Receive ACKs.
        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            hspp.on_ack(
                ack_packets[i as usize].pkt_num,
                ack_packets[i as usize].acked_bytes,
                ack_packets[i as usize].rtt,
            );
            println!("{:?}", hspp);
        }

        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round.saturating_sub(1)])
        );
        assert_eq!(
            hspp.current_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.rtt_sample_count, N_RTT_SAMPLE);

        hspp.end_ack();

        // In CSS.
        assert_eq!(hspp.in_conservative_slow_start(), true);
        assert_eq!(hspp.css_round_count, 1);
        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.current_round_min_rtt, Duration::MAX);
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(hspp.window_end, hspp.last_sent_pkt_num);

        // Round 6 - 9. CSS -> CSS
        let loop_start = round;
        for idx in loop_start + 1..loop_start + CSS_ROUNDS as usize - 1 {
            round = idx;
            println!("==> round = {}", round);

            for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
                println!("sent {}", i);
                hspp.on_sent((i + 1) as u64);
            }
            assert_eq!(hspp.rtt_sample_count, 0);
            assert_eq!(
                hspp.last_sent_pkt_num,
                (round + 1) as u64 * N_RTT_SAMPLE as u64
            );

            // Receive ACKs.
            for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
                hspp.on_ack(
                    ack_packets[i as usize].pkt_num,
                    ack_packets[i as usize].acked_bytes,
                    ack_packets[i as usize].rtt,
                );
                println!("{:?}", hspp);
            }

            assert_eq!(
                hspp.last_round_min_rtt,
                Duration::from_millis(min_round_rtt_in_ms[round.saturating_sub(1)])
            );
            assert_eq!(
                hspp.current_round_min_rtt,
                Duration::from_millis(min_round_rtt_in_ms[round])
            );
            assert_eq!(hspp.rtt_sample_count, N_RTT_SAMPLE);

            hspp.end_ack();

            // In CSS.
            assert_eq!(hspp.in_conservative_slow_start(), true);
            assert_eq!(
                hspp.last_round_min_rtt,
                Duration::from_millis(min_round_rtt_in_ms[round])
            );
            assert_eq!(hspp.current_round_min_rtt, Duration::MAX);
            assert_eq!(hspp.rtt_sample_count, 0);
            assert_eq!(hspp.window_end, hspp.last_sent_pkt_num);
        }

        // Round 10. CSS -> Congestion Avoidance (CA).
        assert_eq!(hspp.css_round_count, CSS_ROUNDS - 1);

        round = loop_start + CSS_ROUNDS as usize - 1;
        println!("==> round = {}", round);

        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            println!("sent {}", i);
            hspp.on_sent((i + 1) as u64);
        }
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(
            hspp.last_sent_pkt_num,
            (round + 1) as u64 * N_RTT_SAMPLE as u64
        );

        // Receive ACKs.
        for i in round * N_RTT_SAMPLE as usize..(round + 1) * N_RTT_SAMPLE as usize {
            hspp.on_ack(
                ack_packets[i as usize].pkt_num,
                ack_packets[i as usize].acked_bytes,
                ack_packets[i as usize].rtt,
            );
            println!("{:?}", hspp);
        }

        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round.saturating_sub(1)])
        );
        assert_eq!(
            hspp.current_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.rtt_sample_count, N_RTT_SAMPLE);

        hspp.end_ack();

        // Switch from CSS to CA.
        assert_eq!(hspp.has_exited(), true);
        assert_eq!(
            hspp.last_round_min_rtt,
            Duration::from_millis(min_round_rtt_in_ms[round])
        );
        assert_eq!(hspp.current_round_min_rtt, Duration::MAX);
        assert_eq!(hspp.rtt_sample_count, 0);
        assert_eq!(hspp.window_end, hspp.last_sent_pkt_num);

        // Do not increase congestion window if hystart++ exited.
        assert_eq!(hspp.cwnd_increment(acked_bytes, max_datagram_size), 0);
    }
}
