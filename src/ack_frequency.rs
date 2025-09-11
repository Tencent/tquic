use crate::connection::path::Path;
use dyn_clone::DynClone;

use std::cmp;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::ranges::RangeSet;
use crate::{frame::Frame, RecoveryConfig, Result, TransportParams};

/// Parameters from an ACK_FREQUENCY frame, either sent or received.
#[derive(Clone, Debug, PartialEq)]
pub struct AckFrequencyParams {
    pub seq_num: u64,
    pub ack_eliciting_threshold: u64,
    pub req_max_ack_delay: u64, // in microseconds
    pub reordering_threshold: u64,
}

/// An ACK_FREQUENCY frame that has been sent but not yet acknowledged.
#[derive(Clone, Debug)]
pub struct InflightAckFrequencyFrame {
    pub pkt_num: u64,
    pub params: AckFrequencyParams,
}

/// Manages the state of sent ACK_FREQUENCY frames for PTO calculation.
#[derive(Default, Debug)]
pub struct AckFrequencySenderState {
    /// Parameters sent to the peer and acknowledged.
    sent_params: Option<AckFrequencyParams>,

    /// Frames that have been sent but not yet acknowledged.
    inflight_frames: VecDeque<InflightAckFrequencyFrame>,
}

impl AckFrequencySenderState {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn on_ack_frequency_frame_sent(&mut self, pkt_num: u64, frame: &Frame) {
        if let Frame::AckFrequency {
            seq_num,
            ack_eliciting_threshold,
            req_max_ack_delay,
            reordering_threshold,
        } = frame
        {
            let params = AckFrequencyParams {
                seq_num: *seq_num,
                ack_eliciting_threshold: *ack_eliciting_threshold,
                req_max_ack_delay: *req_max_ack_delay,
                reordering_threshold: *reordering_threshold,
            };
            self.inflight_frames
                .push_back(InflightAckFrequencyFrame { pkt_num, params });
        }
    }

    pub fn on_acks_received(&mut self, ack_ranges: &RangeSet) {
        let mut latest_acked_inflight: Option<InflightAckFrequencyFrame> = None;

        self.inflight_frames.retain(|frame| {
            if ack_ranges.contains(frame.pkt_num) {
                if latest_acked_inflight
                    .as_ref()
                    .map_or(true, |latest| frame.pkt_num > latest.pkt_num)
                {
                    latest_acked_inflight = Some(frame.clone());
                }
                false // Remove from inflight_frames
            } else {
                true // Keep in inflight_frames
            }
        });

        if let Some(acked) = latest_acked_inflight {
            self.sent_params = Some(acked.params);
        }
    }

    pub fn get_pto_options(
        &self,
        ack_eliciting_in_flight: u64,
        max_ack_delay: Duration,
    ) -> PtoOptions {
        // 1. Calculate effective_max_ack_delay
        let mut effective_max_ack_delay = max_ack_delay;
        if let Some(sent_params) = &self.sent_params {
            effective_max_ack_delay = Duration::from_micros(sent_params.req_max_ack_delay);
        }
        for frame in &self.inflight_frames {
            effective_max_ack_delay = cmp::max(
                effective_max_ack_delay,
                Duration::from_micros(frame.params.req_max_ack_delay),
            );
        }

        // 2. Calculate exclude_ack_delay
        let mut exclude_ack_delay = false;
        if let Some(params) = &self.sent_params {
            if ack_eliciting_in_flight > params.ack_eliciting_threshold
                && params.reordering_threshold > 0
            {
                exclude_ack_delay = true;
            }
        }

        PtoOptions {
            effective_max_ack_delay,
            exclude_ack_delay,
        }
    }
}

/// Options returned by the manager to guide PTO calculation.
#[derive(Default, Debug)]
pub struct PtoOptions {
    pub effective_max_ack_delay: Duration,
    pub exclude_ack_delay: bool,
}

/// An interface for managing the QUIC ACK Frequency extension.

pub trait AckFrequencyManager: DynClone + Send {
    fn on_ack_received(&mut self, stats: &AckFrequencyPathStats) -> Option<Frame>;

    fn on_ack_frequency_frame_received(
        &mut self,
        seq_num: u64,
        ack_eliciting_threshold: u64,
        req_max_ack_delay: u64,
        reordering_threshold: u64,
        local_transport_params: &TransportParams,
    ) -> Result<()>;

    fn get_ack_schedule_params(
        &self,
        recovery_conf: &RecoveryConfig,
        peer_transport_params: &TransportParams,
    ) -> (u64, Duration, u64);
}

dyn_clone::clone_trait_object!(AckFrequencyManager);

/// The default implementation for the AckFrequencyManager trait.
#[derive(Default, Clone)]
pub struct DefaultAckFrequencyManager {
    /// Parameters received from the peer.
    peer_params: Option<AckFrequencyParams>,

    /// The last parameters we sent to the peer.
    last_sent_params: Option<AckFrequencyParams>,

    /// The sequence number for the next ACK_FREQUENCY frame we send.
    next_seq_num: u64,
}

impl DefaultAckFrequencyManager {
    pub fn new() -> Self {
        Default::default()
    }
}

impl AckFrequencyManager for DefaultAckFrequencyManager {
    fn on_ack_received(&mut self, stats: &AckFrequencyPathStats) -> Option<Frame> {
        let req_max_ack_delay = (stats.srtt.as_micros() as f64 * 0.025).round() as u64;

        let ack_eliciting_threshold = if stats.max_datagram_size > 0 {
            ((stats.cwnd as f64 * 0.025) / (stats.max_datagram_size as f64)) as u64
        } else {
            1
        };

        let new_params = AckFrequencyParams {
            seq_num: self.next_seq_num,
            ack_eliciting_threshold,
            req_max_ack_delay: if stats.min_ack_delay > req_max_ack_delay {
                stats.min_ack_delay
            } else {
                req_max_ack_delay
            },
            reordering_threshold: 3, // Per QUIC-RECOVERY recommendation
        };

        // Only send an update if the parameters have changed.
        if let Some(last_sent) = &self.last_sent_params {
            let threshold_diff = (new_params.ack_eliciting_threshold as f64
                - last_sent.ack_eliciting_threshold as f64)
                .abs();
            let threshold_no_change = if last_sent.ack_eliciting_threshold == 0 {
                threshold_diff == 0.0
            } else {
                (threshold_diff / last_sent.ack_eliciting_threshold as f64) < 0.1
            };

            let delay_diff =
                (new_params.req_max_ack_delay as f64 - last_sent.req_max_ack_delay as f64).abs();
            let delay_no_change = if last_sent.req_max_ack_delay == 0 {
                delay_diff == 0.0
            } else {
                (delay_diff / last_sent.req_max_ack_delay as f64) < 0.1
            };

            if threshold_no_change && delay_no_change {
                return None;
            }
        }

        self.last_sent_params = Some(new_params.clone());
        self.next_seq_num += 1;

        Some(Frame::AckFrequency {
            seq_num: new_params.seq_num,
            ack_eliciting_threshold: new_params.ack_eliciting_threshold,
            req_max_ack_delay: new_params.req_max_ack_delay,
            reordering_threshold: new_params.reordering_threshold,
        })
    }

    fn on_ack_frequency_frame_received(
        &mut self,
        seq_num: u64,
        ack_eliciting_threshold: u64,
        req_max_ack_delay: u64,
        reordering_threshold: u64,
        local_transport_params: &TransportParams,
    ) -> Result<()> {
        if let Some(min_ack_delay) = local_transport_params.min_ack_delay {
            if req_max_ack_delay < min_ack_delay {
                return Err(crate::Error::ProtocolViolation);
            }
        }
        if req_max_ack_delay >= (1 << 14) * 1000 {
            return Err(crate::Error::ProtocolViolation);
        }

        if let Some(params) = &self.peer_params {
            if seq_num <= params.seq_num {
                return Ok(());
            }
        }

        self.peer_params = Some(AckFrequencyParams {
            seq_num,
            ack_eliciting_threshold,
            req_max_ack_delay,
            reordering_threshold,
        });

        Ok(())
    }

    fn get_ack_schedule_params(
        &self,
        recovery_conf: &RecoveryConfig,
        peer_transport_params: &TransportParams,
    ) -> (u64, Duration, u64) {
        if let Some(params) = &self.peer_params {
            (
                params.ack_eliciting_threshold + 1,
                Duration::from_micros(params.req_max_ack_delay),
                params.reordering_threshold,
            )
        } else {
            (
                recovery_conf.ack_eliciting_threshold,
                Duration::from_millis(peer_transport_params.max_ack_delay),
                1,
            )
        }
    }
}

/// Statistics about a path, provided to the AckFrequencyManager.
pub struct AckFrequencyPathStats {
    pub min_ack_delay: u64, // in microseconds
    pub srtt: Duration,
    pub min_rtt: Duration,
    pub cwnd: u64,
    pub bytes_in_flight: u64,
    pub max_datagram_size: usize,
}

/// Statistics about the recovery state, provided to the AckFrequencyManager.
#[derive(Default)]
pub struct RecoveryStats {
    pub ack_eliciting_in_flight: u64,
}

/// Events that might trigger sending an IMMEDIATE_ACK frame.
pub enum SendEvent {
    Pto,
    Pmtu,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::tests::TestPair;
    use crate::{Config, TransportParams};
    use std::time::Duration;

    #[test]
    fn ack_frequency_negotiation() {
        let mut client_config = Config::new().unwrap();
        client_config.enable_ack_frequency(1000);
        let mut server_config = Config::new().unwrap();
        server_config.enable_ack_frequency(2000);

        let cert_file = "fuzz/conf/cert.crt";
        let key_file = "fuzz/conf/cert.key";
        let protos = vec![b"h3".to_vec()];
        let server_tls_config =
            crate::TlsConfig::new_server_config(cert_file, key_file, protos.clone(), false)
                .unwrap();
        server_config.set_tls_config(server_tls_config);

        let client_tls_config = crate::TlsConfig::new_client_config(protos, false).unwrap();
        client_config.set_tls_config(client_tls_config);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config).unwrap();
        test_pair.handshake().unwrap();

        assert_eq!(
            test_pair.client.peer_transport_params().min_ack_delay,
            Some(2000)
        );
        assert_eq!(
            test_pair.server.peer_transport_params().min_ack_delay,
            Some(1000)
        );
    }

    #[test]
    fn ack_frequency_sender_state_new() {
        let state = AckFrequencySenderState::new();
        assert!(state.sent_params.is_none());
        assert!(state.inflight_frames.is_empty());
    }

    #[test]
    fn ack_frequency_sender_state_on_ack_frequency_frame_sent() {
        let mut state = AckFrequencySenderState::new();
        let frame = Frame::AckFrequency {
            seq_num: 1,
            ack_eliciting_threshold: 2,
            req_max_ack_delay: 3,
            reordering_threshold: 4,
        };
        state.on_ack_frequency_frame_sent(100, &frame);

        assert_eq!(state.inflight_frames.len(), 1);
        let inflight = &state.inflight_frames[0];
        assert_eq!(inflight.pkt_num, 100);
        assert_eq!(inflight.params.seq_num, 1);
        assert_eq!(inflight.params.ack_eliciting_threshold, 2);
        assert_eq!(inflight.params.req_max_ack_delay, 3);
        assert_eq!(inflight.params.reordering_threshold, 4);

        // Test with a non-ack frequency frame
        let frame = Frame::Paddings { len: 0 };
        state.on_ack_frequency_frame_sent(101, &frame);
        assert_eq!(state.inflight_frames.len(), 1);
    }

    #[test]
    fn ack_frequency_sender_state_on_acks_received() {
        let mut state = AckFrequencySenderState::new();
        let frame1 = Frame::AckFrequency {
            seq_num: 1,
            ack_eliciting_threshold: 2,
            req_max_ack_delay: 3,
            reordering_threshold: 4,
        };
        let frame2 = Frame::AckFrequency {
            seq_num: 2,
            ack_eliciting_threshold: 5,
            req_max_ack_delay: 6,
            reordering_threshold: 7,
        };
        state.on_ack_frequency_frame_sent(100, &frame1);
        state.on_ack_frequency_frame_sent(102, &frame2);

        let mut ack_ranges = RangeSet::new(1);
        ack_ranges.insert(100..101);

        state.on_acks_received(&ack_ranges);

        assert_eq!(state.inflight_frames.len(), 1);
        assert_eq!(state.inflight_frames[0].pkt_num, 102);
        assert!(state.sent_params.is_some());
        let params = state.sent_params.as_ref().unwrap();
        assert_eq!(params.seq_num, 1);

        // Ack the second frame
        let mut ack_ranges = RangeSet::new(1);
        ack_ranges.insert(102..103);
        state.on_acks_received(&ack_ranges);

        assert!(state.inflight_frames.is_empty());
        let params = state.sent_params.as_ref().unwrap();
        assert_eq!(params.seq_num, 2);
    }

    #[test]
    fn ack_frequency_sender_state_on_acks_received_multiple() {
        let mut state = AckFrequencySenderState::new();
        state.on_ack_frequency_frame_sent(
            100,
            &Frame::AckFrequency {
                seq_num: 1,
                ack_eliciting_threshold: 2,
                req_max_ack_delay: 3,
                reordering_threshold: 4,
            },
        );
        state.on_ack_frequency_frame_sent(
            101,
            &Frame::AckFrequency {
                seq_num: 2,
                ack_eliciting_threshold: 5,
                req_max_ack_delay: 6,
                reordering_threshold: 7,
            },
        );
        state.on_ack_frequency_frame_sent(
            103,
            &Frame::AckFrequency {
                seq_num: 3,
                ack_eliciting_threshold: 8,
                req_max_ack_delay: 9,
                reordering_threshold: 10,
            },
        );

        let mut ack_ranges = RangeSet::new(2);
        ack_ranges.insert(100..102); // acks pkt 100 and 101

        state.on_acks_received(&ack_ranges);

        assert_eq!(state.inflight_frames.len(), 1);
        assert_eq!(state.inflight_frames[0].pkt_num, 103);
        assert!(state.sent_params.is_some());
        // latest acked is 101 (seq_num 2)
        assert_eq!(state.sent_params.as_ref().unwrap().seq_num, 2);
    }

    #[test]
    fn ack_frequency_sender_state_get_pto_options() {
        let mut state = AckFrequencySenderState::new();
        let max_ack_delay = Duration::from_millis(25);

        // 1. No sent_params, no inflight
        let options = state.get_pto_options(0, max_ack_delay);
        assert_eq!(options.effective_max_ack_delay, max_ack_delay);
        assert!(!options.exclude_ack_delay);

        // 2. With sent_params
        state.sent_params = Some(AckFrequencyParams {
            seq_num: 1,
            ack_eliciting_threshold: 5,
            req_max_ack_delay: 10_000, // 10ms
            reordering_threshold: 3,
        });
        let options = state.get_pto_options(4, max_ack_delay);
        assert_eq!(
            options.effective_max_ack_delay,
            Duration::from_micros(10_000)
        );
        assert!(!options.exclude_ack_delay);

        // 3. exclude_ack_delay should be true
        let options = state.get_pto_options(6, max_ack_delay);
        assert_eq!(
            options.effective_max_ack_delay,
            Duration::from_micros(10_000)
        );
        assert!(options.exclude_ack_delay);

        // 4. exclude_ack_delay should be false if reordering_threshold is 0
        state.sent_params.as_mut().unwrap().reordering_threshold = 0;
        let options = state.get_pto_options(6, max_ack_delay);
        assert!(!options.exclude_ack_delay);
        state.sent_params.as_mut().unwrap().reordering_threshold = 3;

        // 5. With inflight frames
        state.on_ack_frequency_frame_sent(
            100,
            &Frame::AckFrequency {
                seq_num: 2,
                ack_eliciting_threshold: 5,
                req_max_ack_delay: 20_000, // 20ms
                reordering_threshold: 3,
            },
        );
        state.on_ack_frequency_frame_sent(
            101,
            &Frame::AckFrequency {
                seq_num: 3,
                ack_eliciting_threshold: 5,
                req_max_ack_delay: 15_000, // 15ms
                reordering_threshold: 3,
            },
        );
        let options = state.get_pto_options(6, max_ack_delay);
        // max(10ms, 20ms, 15ms) = 20ms
        assert_eq!(
            options.effective_max_ack_delay,
            Duration::from_micros(20_000)
        );
        assert!(options.exclude_ack_delay);
    }

    #[test]
    fn default_ack_frequency_manager_new() {
        let manager = DefaultAckFrequencyManager::new();
        assert!(manager.peer_params.is_none());
        assert!(manager.last_sent_params.is_none());
        assert_eq!(manager.next_seq_num, 0);
    }

    #[test]
    fn default_ack_frequency_manager_on_ack_received() {
        let mut manager = DefaultAckFrequencyManager::new();
        let stats = AckFrequencyPathStats {
            min_ack_delay: 1000, // 1ms
            srtt: Duration::from_millis(100),
            min_rtt: Duration::from_millis(50),
            cwnd: 15000,
            bytes_in_flight: 5000,
            max_datagram_size: 1500,
        };

        // First time, should send a frame
        let frame = manager.on_ack_received(&stats);
        assert!(frame.is_some());
        if let Some(Frame::AckFrequency {
            seq_num,
            ack_eliciting_threshold,
            req_max_ack_delay,
            reordering_threshold,
        }) = frame
        {
            assert_eq!(seq_num, 0);
            assert_eq!(ack_eliciting_threshold, 0); // 15000 * 0.025 / 1500 = 0.25 -> 0
            assert_eq!(req_max_ack_delay, 2500); // 100ms * 0.025
            assert_eq!(reordering_threshold, 3);
        } else {
            panic!("Expected AckFrequency frame");
        }
        assert_eq!(manager.next_seq_num, 1);
        assert!(manager.last_sent_params.is_some());

        // Second time, params not changed enough, should not send
        let frame = manager.on_ack_received(&stats);
        assert!(frame.is_none());

        // Change params enough to trigger a new frame
        let stats2 = AckFrequencyPathStats {
            min_ack_delay: 2000,
            cwnd: 30000,
            srtt: Duration::from_millis(200),
            ..stats
        };
        let frame = manager.on_ack_received(&stats2);
        assert!(frame.is_some());
        if let Some(Frame::AckFrequency {
            seq_num,
            ack_eliciting_threshold,
            req_max_ack_delay,
            ..
        }) = frame
        {
            assert_eq!(seq_num, 1);
            assert_eq!(ack_eliciting_threshold, 0); // 30000 * 0.025 / 1500 = 0.5 -> 0
            assert_eq!(req_max_ack_delay, 5000); // 200ms * 0.025
        } else {
            panic!("Expected AckFrequency frame");
        }
        assert_eq!(manager.next_seq_num, 2);

        // Test with max_datagram_size = 0
        let stats3 = AckFrequencyPathStats {
            max_datagram_size: 0,
            ..stats2
        };
        let frame = manager.on_ack_received(&stats3);
        assert!(frame.is_some());
        if let Some(Frame::AckFrequency {
            seq_num,
            ack_eliciting_threshold,
            ..
        }) = frame
        {
            assert_eq!(seq_num, 2);
            assert_eq!(ack_eliciting_threshold, 1);
        } else {
            panic!("Expected AckFrequency frame");
        }
    }

    #[test]
    fn default_ack_frequency_manager_on_ack_frequency_frame_received() {
        let mut manager = DefaultAckFrequencyManager::new();
        let mut local_transport_params = TransportParams::default();
        local_transport_params.min_ack_delay = Some(100); // 100us

        // Valid frame
        let result = manager.on_ack_frequency_frame_received(1, 2, 200, 3, &local_transport_params);
        assert!(result.is_ok());
        assert!(manager.peer_params.is_some());
        let params = manager.peer_params.as_ref().unwrap();
        assert_eq!(params.seq_num, 1);
        assert_eq!(params.ack_eliciting_threshold, 2);
        assert_eq!(params.req_max_ack_delay, 200);
        assert_eq!(params.reordering_threshold, 3);

        // Old sequence number, should be ignored
        let result = manager.on_ack_frequency_frame_received(0, 5, 500, 5, &local_transport_params);
        assert!(result.is_ok());
        let params = manager.peer_params.as_ref().unwrap();
        assert_eq!(params.seq_num, 1); // Unchanged

        // New sequence number
        let result = manager.on_ack_frequency_frame_received(2, 5, 500, 5, &local_transport_params);
        assert!(result.is_ok());
        let params = manager.peer_params.as_ref().unwrap();
        assert_eq!(params.seq_num, 2); // Changed

        // Invalid: req_max_ack_delay < min_ack_delay
        let result = manager.on_ack_frequency_frame_received(3, 2, 50, 3, &local_transport_params);
        assert!(matches!(result, Err(crate::Error::ProtocolViolation)));

        // Invalid: req_max_ack_delay too large
        let result = manager.on_ack_frequency_frame_received(
            3,
            2,
            (1 << 14) * 1000,
            3,
            &local_transport_params,
        );
        assert!(matches!(result, Err(crate::Error::ProtocolViolation)));
    }

    #[test]
    fn default_ack_frequency_manager_get_ack_schedule_params() {
        let mut manager = DefaultAckFrequencyManager::new();
        let recovery_conf = RecoveryConfig::default();
        let peer_transport_params = TransportParams::default();

        // No peer params yet
        let (threshold, delay, reorder_thresh) =
            manager.get_ack_schedule_params(&recovery_conf, &peer_transport_params);
        assert_eq!(threshold, recovery_conf.ack_eliciting_threshold);
        assert_eq!(
            delay,
            Duration::from_millis(peer_transport_params.max_ack_delay)
        );
        assert_eq!(reorder_thresh, 1);

        // With peer params
        manager.peer_params = Some(AckFrequencyParams {
            seq_num: 1,
            ack_eliciting_threshold: 10,
            req_max_ack_delay: 5000, // 5ms
            reordering_threshold: 5,
        });
        let (threshold, delay, reorder_thresh) =
            manager.get_ack_schedule_params(&recovery_conf, &peer_transport_params);
        assert_eq!(threshold, 11); // 10 + 1
        assert_eq!(delay, Duration::from_micros(5000));
        assert_eq!(reorder_thresh, 5);
    }
}
