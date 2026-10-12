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

use std::collections::HashSet;

use clap::builder::PossibleValue;
use clap::ValueEnum;
use log::debug;
use rand::Rng;

use tquic::PacketHeader;
use tquic::PacketType;

/// Packet loss strategy configuration
#[derive(Clone, Debug, Default)]
pub struct PacketLossConfig {
    /// Random packet loss rate (0.0 to 1.0)
    pub loss_rate: f64,
    /// Specific packet numbers to drop
    pub drop_packet_numbers: HashSet<u64>,
    /// Packet types to drop
    pub drop_packet_types: HashSet<PacketType>,
    /// Whether to apply loss to incoming packets
    pub drop_incoming: bool,
    /// Whether to apply loss to outgoing packets
    pub drop_outgoing: bool,
}

impl PacketLossConfig {
    /// Create a new PacketLossConfig with default values
    pub fn new() -> Self {
        Self {
            loss_rate: 0.0,
            drop_packet_numbers: HashSet::new(),
            drop_packet_types: HashSet::new(),
            drop_incoming: true,
            drop_outgoing: true,
        }
    }

    /// Set random loss rate
    pub fn with_loss_rate(mut self, rate: f64) -> Self {
        self.loss_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Add specific packet numbers to drop
    pub fn with_drop_packet_numbers(mut self, numbers: Vec<u64>) -> Self {
        self.drop_packet_numbers.extend(numbers);
        self
    }

    /// Add specific packet types to drop
    pub fn with_drop_packet_types(mut self, types: Vec<PacketType>) -> Self {
        self.drop_packet_types.extend(types);
        self
    }

    /// Set incoming packet loss
    pub fn with_drop_incoming(mut self, drop: bool) -> Self {
        self.drop_incoming = drop;
        self
    }

    /// Set outgoing packet loss
    pub fn with_drop_outgoing(mut self, drop: bool) -> Self {
        self.drop_outgoing = drop;
        self
    }
}

/// Packet loss simulator
#[derive(Debug)]
pub struct PacketLossSimulator {
    config: PacketLossConfig,
    rng: rand::rngs::ThreadRng,
}

impl PacketLossSimulator {
    /// Create a new PacketLossSimulator
    pub fn new(config: PacketLossConfig) -> Self {
        Self {
            config,
            rng: rand::thread_rng(),
        }
    }

    /// Check if an incoming packet should be dropped
    pub fn should_drop_incoming(&mut self, packet_data: &[u8], dcid_len: usize) -> bool {
        if !self.config.drop_incoming {
            return false;
        }
        self.should_drop_packet(packet_data, dcid_len)
    }

    /// Check if an outgoing packet should be dropped
    pub fn should_drop_outgoing(&mut self, packet_data: &[u8], dcid_len: usize) -> bool {
        if !self.config.drop_outgoing {
            return false;
        }
        self.should_drop_packet(packet_data, dcid_len)
    }

    /// Internal method to determine if a packet should be dropped
    fn should_drop_packet(&mut self, packet_data: &[u8], dcid_len: usize) -> bool {
        // Try to parse packet header
        let (header, _) = match PacketHeader::from_bytes(packet_data, dcid_len) {
            Ok(result) => result,
            Err(e) => {
                debug!("Failed to parse packet header for loss simulation: {:?}", e);
                return false;
            }
        };

        // Check packet type filter
        if self.config.drop_packet_types.contains(&header.pkt_type) {
            debug!("Dropping packet due to type filter: {:?}", header.pkt_type);
            return true;
        }

        // Check packet number filter
        if self.config.drop_packet_numbers.contains(&header.pkt_num) {
            debug!(
                "Dropping packet due to packet number filter: {}",
                header.pkt_num
            );
            return true;
        }

        // Check random loss rate
        if self.config.loss_rate > 0.0 {
            let random_value: f64 = self.rng.gen();
            if random_value < self.config.loss_rate {
                debug!(
                    "Dropping packet due to random loss (rate: {}, value: {})",
                    self.config.loss_rate, random_value
                );
                return true;
            }
        }

        false
    }
}

/// Supported packet loss types for CLI
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossPacketType {
    Initial,
    ZeroRTT,
    Handshake,
    OneRTT,
    Retry,
    VersionNegotiation,
}

impl LossPacketType {
    /// Convert to TQUIC PacketType
    pub fn to_packet_type(&self) -> PacketType {
        match self {
            Self::Initial => PacketType::Initial,
            Self::ZeroRTT => PacketType::ZeroRTT,
            Self::Handshake => PacketType::Handshake,
            Self::OneRTT => PacketType::OneRTT,
            Self::Retry => PacketType::Retry,
            Self::VersionNegotiation => PacketType::VersionNegotiation,
        }
    }
}

impl ValueEnum for LossPacketType {
    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(match self {
            Self::Initial => PossibleValue::new("initial"),
            Self::ZeroRTT => PossibleValue::new("0rtt"),
            Self::Handshake => PossibleValue::new("handshake"),
            Self::OneRTT => PossibleValue::new("1rtt"),
            Self::Retry => PossibleValue::new("retry"),
            Self::VersionNegotiation => PossibleValue::new("version_negotiation"),
        })
    }

    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Initial,
            Self::ZeroRTT,
            Self::Handshake,
            Self::OneRTT,
            Self::Retry,
            Self::VersionNegotiation,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_loss_config_creation() {
        let config = PacketLossConfig::new()
            .with_loss_rate(0.1)
            .with_drop_packet_numbers(vec![1, 2, 3])
            .with_drop_packet_types(vec![PacketType::Initial])
            .with_drop_incoming(true)
            .with_drop_outgoing(false);

        assert_eq!(config.loss_rate, 0.1);
        assert!(config.drop_packet_numbers.contains(&1));
        assert!(config.drop_packet_types.contains(&PacketType::Initial));
        assert!(config.drop_incoming);
        assert!(!config.drop_outgoing);
    }

    #[test]
    fn test_loss_rate_clamping() {
        let config1 = PacketLossConfig::new().with_loss_rate(-0.5);
        assert_eq!(config1.loss_rate, 0.0);

        let config2 = PacketLossConfig::new().with_loss_rate(1.5);
        assert_eq!(config2.loss_rate, 1.0);
    }

    #[test]
    fn test_loss_packet_type_conversion() {
        assert_eq!(
            LossPacketType::Initial.to_packet_type(),
            PacketType::Initial
        );
        assert_eq!(LossPacketType::OneRTT.to_packet_type(), PacketType::OneRTT);
    }
}
