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

use std::fmt::Display;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time;

use bytes::Bytes;
use bytes::BytesMut;
use rand::RngCore;
use ring::aead;

use self::PacketType::*;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::connection::space::SpaceId;
use crate::qlog;
use crate::ranges;
use crate::tls;
use crate::tls::Level;
use crate::tls::Open;
use crate::tls::Seal;
use crate::ConnectionId;
use crate::Error;
use crate::Result;
use crate::MAX_CID_LEN;

/// The most significant bit (0x80) of the first byte is set to 1 for
/// packet that use the long header.
const HEADER_LONG_FORM_BIT: u8 = 0x80;

/// The fixed bit of the first byte of packet header.
const HEADER_FIXED_BIT: u8 = 0x40;

/// The bit indicating the key phase for 1RTT packets.
const HEADER_KEY_PHASE_BIT: u8 = 0x04;

/// The packet type bits for packet that use the long header.
const PKT_TYPE_MASK: u8 = 0x30;

/// In packet that contain a Packet Number field, the least significant two
/// bits (those with a mask of 0x03) of the first byte contain the length of
/// the Packet Number field.
const PKT_NUM_LEN_MASK: u8 = 0x03;

/// The packet number field is 1 to 4 bytes long.
const MAX_PKT_NUM_LEN: usize = 4;

/// The cipher suites defined in TLS13 (other than TLS_AES_128_CCM_8_SHA256)
/// have 16-byte expansions and 16-byte header protection samples.
const SAMPLE_LEN: usize = 16;

/// The secret key for computing Retry Integrity Tag using AEAD_AES_128_GCM
/// algorithm. It is 128 bits equal to 0xbe0c690b9f66575a1d766b54e368c84e.
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// The nonce for computing Retry Integrity Tag using AEAD_AES_128_GCM
/// algorithm. It is 96 bits equal to 0x461599d35d632bf2239825bb.
const RETRY_INTEGRITY_NONCE_V1: [u8; aead::NONCE_LEN] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// QUIC packet type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    /// The Version Negotiation packet is a response to a client packet that
    /// contains a version that is not supported by the server.
    VersionNegotiation,

    /// Initial packet carries the first CRYPTO frames sent by the client and
    /// server to perform key exchange.
    Initial,

    /// 0-RTT packet is used to carry "early" data from the client to the
    /// server as part of the first flight, prior to handshake completion.
    ZeroRTT,

    /// Handshake packet is used to carry cryptographic handshake messages and
    /// acknowledgments from the server and client.
    Handshake,

    /// Retry packet carries an address validation token created by the server.
    /// It is used by a server that wishes to perform a retry
    Retry,

    /// 1-RTT packet is used after the version and 1-RTT keys are negotiated.
    OneRTT,
}

impl PacketType {
    /// Get encryption level for the given packet type.
    ///
    /// Data is protected using a number of encryption levels: Initial keys,
    /// Early data (0-RTT) keys, Handshake keys, Application data (1-RTT) keys.
    /// See RFC 9001 Section 2.1
    pub fn to_level(self) -> Result<Level> {
        match self {
            Initial => Ok(Level::Initial),
            ZeroRTT => Ok(Level::ZeroRTT),
            Handshake => Ok(Level::Handshake),
            OneRTT => Ok(Level::OneRTT),
            _ => Err(Error::InternalError),
        }
    }

    /// Get packet number space for the given packet type.
    ///
    /// Packet numbers are divided into three spaces in QUIC: Initial space,
    /// Handshake space, Application data space.
    /// See RFC 9000 Section 12.3
    pub fn to_space(self) -> Result<SpaceId> {
        match self {
            Initial => Ok(SpaceId::Initial),
            Handshake => Ok(SpaceId::Handshake),
            ZeroRTT | OneRTT => Ok(SpaceId::Data),
            _ => Err(Error::InternalError),
        }
    }

    /// Get the packet type for Qlog.
    pub fn to_qlog(self) -> qlog::events::PacketType {
        match self {
            VersionNegotiation => qlog::events::PacketType::VersionNegotiation,
            Initial => qlog::events::PacketType::Initial,
            ZeroRTT => qlog::events::PacketType::ZeroRtt,
            Handshake => qlog::events::PacketType::Handshake,
            Retry => qlog::events::PacketType::Retry,
            OneRTT => qlog::events::PacketType::OneRtt,
        }
    }
}

/// QUIC packet header.
///
/// In order to simplify the processing of packet header, a generic header type
/// is intentionally used here.
#[derive(Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// The type of the packet.
    pub pkt_type: PacketType,

    /// The version in the long header packet.
    pub version: u32,

    /// The destination connection ID.
    pub dcid: ConnectionId,

    /// The source connection ID in long header packet.
    pub scid: ConnectionId,

    /// The length of the packet number.
    pub pkt_num_len: usize,

    /// The packet number.
    pub pkt_num: u64,

    /// The address verification token (Initial/Retry).
    pub token: Option<Vec<u8>>,

    /// The key phase bit (OneRTT).
    pub key_phase: bool,
}

impl PacketHeader {
    /// Encode a QUIC packet header to the given buffer.
    ///
    /// The Length/Packet Number field are intentionally not written to the
    /// buffer for the moment.
    /// See RFC 9000 Section 17 Packet Formats
    pub fn to_bytes(&self, mut buf: &mut [u8]) -> Result<usize> {
        let len = buf.len();

        // Encode in short header form for OneRTT.
        //
        // 1-RTT Packet {
        //   Header Form (1) = 0,
        //   Fixed Bit (1) = 1,
        //   Spin Bit (1),
        //   Reserved Bits (2),
        //   Key Phase (1),
        //   Packet Number Length (2),
        //   Destination Connection ID (0..160),
        //   Packet Number (8..32),
        //   Packet Payload (8..),
        // }
        if self.pkt_type == OneRTT {
            let mut first = HEADER_FIXED_BIT;
            if self.key_phase {
                first |= HEADER_KEY_PHASE_BIT;
            }
            first |= self.pkt_num_len.saturating_sub(1) as u8;
            buf.write_u8(first)?;
            buf.write(&self.dcid)?;
            return Ok(len - buf.len());
        }

        // Encode in long header form.
        //
        // Long Header Packet {
        //   Header Form (1) = 1,
        //   Fixed Bit (1) = 1,
        //   Long Packet Type (2),
        //   Type-Specific Bits (4),
        //   Version (32),
        //   Destination Connection ID Length (8),
        //   Destination Connection ID (0..160),
        //   Source Connection ID Length (8),
        //   Source Connection ID (0..160),
        //   Type-Specific Payload (..),
        // }
        let mut first = HEADER_LONG_FORM_BIT | HEADER_FIXED_BIT;
        let pkt_type: u8 = match self.pkt_type {
            Initial => 0x00,
            ZeroRTT => 0x01,
            Handshake => 0x02,
            Retry => 0x03,
            _ => return Err(Error::InternalError),
        };
        first |= pkt_type << 4;
        first |= self.pkt_num_len.saturating_sub(1) as u8;
        buf.write_u8(first)?;
        buf.write_u32(self.version)?;
        buf.write_u8(self.dcid.len() as u8)?;
        buf.write(&self.dcid)?;
        buf.write_u8(self.scid.len() as u8)?;
        buf.write(&self.scid)?;

        // Type specific fields for Initial and Retry
        match self.pkt_type {
            Initial => match self.token {
                // Token length and Token
                Some(ref v) => {
                    buf.write_varint(v.len() as u64)?;
                    buf.write(v)?;
                }
                None => {
                    buf.write_varint(0)?;
                }
            },
            Retry => {
                // Token
                buf.write(self.token.as_ref().unwrap())?;
            }
            _ => (),
        }

        Ok(len - buf.len())
    }

    /// Decode a QUIC packet header from the given buffer.
    ///
    /// The `dcid_len` is required for parsing OneRTT packets.
    /// The Length/Packet Number field in packet header are intentionally not
    /// read from the buffer for the moment.
    ///
    /// See RFC 9000 Section 17 Packet Formats
    pub fn from_bytes(mut buf: &[u8], dcid_len: usize) -> Result<(PacketHeader, usize)> {
        let len = buf.len();
        let first = buf.read_u8()?;

        // Decode in short header form for 1-RTT.
        if !PacketHeader::long_header(first) {
            let dcid = buf.read(dcid_len)?;

            return Ok((
                PacketHeader {
                    pkt_type: OneRTT,
                    version: 0,
                    dcid: ConnectionId::new(&dcid),
                    scid: ConnectionId::default(),
                    pkt_num: 0,
                    pkt_num_len: 0,
                    token: None,
                    key_phase: false,
                },
                len - buf.len(),
            ));
        }

        // Decode in long header form.
        let version = buf.read_u32()?;
        let pkt_type = if version == 0 {
            VersionNegotiation
        } else {
            match (first & PKT_TYPE_MASK) >> 4 {
                0x00 => Initial,
                0x01 => ZeroRTT,
                0x02 => Handshake,
                0x03 => Retry,
                _ => return Err(Error::InvalidPacket),
            }
        };

        let dcid_len = buf.read_u8()?;
        if crate::version_is_supported(version) && dcid_len > MAX_CID_LEN as u8 {
            return Err(Error::InvalidPacket);
        }
        let dcid = buf.read(dcid_len as usize)?;
        let scid_len = buf.read_u8()?;
        if crate::version_is_supported(version) && scid_len > MAX_CID_LEN as u8 {
            return Err(Error::InvalidPacket);
        }
        let scid = buf.read(scid_len as usize)?;

        // Type specific fields for Initial and Retry
        let mut token: Option<Vec<u8>> = None;
        match pkt_type {
            Initial => {
                let token_len = buf.read_varint()?;
                if token_len > 0 {
                    token = Some(buf.read(token_len as usize)?);
                }
            }
            Retry => {
                // Exclude the integrity tag from the token.
                if buf.len() < aead::AES_128_GCM.tag_len() {
                    return Err(Error::InvalidPacket);
                }
                let token_len = buf.len() - aead::AES_128_GCM.tag_len();
                token = Some(buf.read(token_len)?);
            }
            _ => (),
        };

        Ok((
            PacketHeader {
                pkt_type,
                version,
                dcid: ConnectionId::new(&dcid),
                scid: ConnectionId::new(&scid),
                pkt_num: 0,
                pkt_num_len: 0,
                token,
                key_phase: false,
            },
            len - buf.len(),
        ))
    }

    /// Return true if the packet has a long header.
    fn long_header(header_first_byte: u8) -> bool {
        header_first_byte & HEADER_LONG_FORM_BIT != 0
    }
}

impl std::fmt::Debug for PacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.pkt_type)?;
        if self.pkt_type != OneRTT {
            write!(f, " ver={:x}", self.version)?;
        }

        write!(f, " dcid={:?}", self.dcid)?;
        if self.pkt_type != OneRTT {
            write!(f, " scid={:?}", self.scid)?;
        }

        if let Some(ref token) = self.token {
            write!(f, " token=")?;
            for b in token {
                write!(f, "{b:02x}")?;
            }
        }
        if self.pkt_type == OneRTT {
            write!(f, " key_phase={}", self.key_phase)?;
        }

        Ok(())
    }
}

/// Encrypt payload and header fields of a QUIC packet.
///
/// The `pkt_buf` is the raw data of packet in plaintext.
/// The `pkt_num` is the packet sequence number.
/// The `pkt_num_len` is the encoded length of packet sequence number.
/// The `payload_len` is the length of packet payload in plaintext.
/// The `payload_offset` is the offset of packet payload in `pkt_buf`.
///
/// See RFC 9001 Section 5.3
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_packet(
    pkt_buf: &mut [u8],
    cid_seq: Option<u32>,
    pkt_num: u64,
    pkt_num_len: usize,
    payload_len: usize,
    payload_offset: usize,
    extra_in: Option<&[u8]>,
    aead: &Seal,
) -> Result<usize> {
    if pkt_buf.len() < payload_offset + payload_len {
        return Err(Error::BufferTooShort);
    }

    // Packet header starts from the first byte of either the short or long
    // header, up to and including the unprotected packet number.
    let (pkt_hdr, payload) = pkt_buf.split_at_mut(payload_offset);

    // Encrypt packet payload
    let ciphertext_len = aead.seal(
        cid_seq,
        pkt_num,     // for nonce
        pkt_hdr,     // associated data
        payload,     // plaintext
        payload_len, // length of plaintext
        extra_in,
    )?;

    // Encrypt packet header fields
    encrypt_header(pkt_hdr, pkt_num_len, payload, aead)?;

    Ok(payload_offset + ciphertext_len)
}

/// Apply header protection for a QUIC packet.
///
/// Header protection is applied after packet protection is applied.
/// See RFC 9001 Section 5.4.1
fn encrypt_header(
    hdr_buf: &mut [u8],
    pkt_num_len: usize,
    payload: &[u8],
    aead: &Seal,
) -> Result<()> {
    // The sample of ciphertext is taken starting from an offset of 4 bytes
    // after the start of the Packet Number field.
    let sample_start = MAX_PKT_NUM_LEN - pkt_num_len;
    let sample = &payload[sample_start..sample_start + SAMPLE_LEN];

    // The ciphertext of the packet is sampled and used as input to an
    // encryption algorithm. The output is a 5-byte mask that is applied to
    // the protected header fields using exclusive OR.
    let mask = aead.new_mask(sample)?;

    // The four least significant bits of the first byte are protected for
    // packets with long headers; the five least significant bits of the first
    // byte are protected for packets with short headers.
    let (first, rest) = hdr_buf.split_at_mut(1);
    if PacketHeader::long_header(first[0]) {
        first[0] ^= mask[0] & 0x0f;
    } else {
        first[0] ^= mask[0] & 0x1f;
    }

    // Mask the Packet Number field. It is the last field in packet header.
    let (_, pkt_num_buf) = rest.split_at_mut(rest.len() - pkt_num_len);
    for i in 0..pkt_num_len {
        pkt_num_buf[i] ^= mask[i + 1];
    }

    Ok(())
}

/// Decrypt payload of a QUIC packet.
///
/// The `pkt_buf` is the raw data of a QUIC packet.
/// The `paylaod_offset` is the offset of packet payload in `pkt_buf`.
/// The `payload_len` is the length of pacekt payload (other than the value of Length field).
/// The `pkt_num` is the decrypted and decoded packet number.
#[allow(unexpected_cfgs)]
pub(crate) fn decrypt_payload(
    pkt_buf: &mut [u8],
    payload_offset: usize,
    payload_len: usize,
    cid_seq: Option<u32>,
    pkt_num: u64,
    aead: &Open,
) -> Result<bytes::Bytes> {
    if pkt_buf.len() < payload_offset + payload_len {
        return Err(Error::BufferTooShort);
    }

    let (header_buf, payload_buf) = pkt_buf.split_at_mut(payload_offset);
    let payload_buf = &mut payload_buf[..payload_len];
    let mut plaintext = BytesMut::zeroed(payload_len);

    if cfg!(feature = "fuzzing") {
        // Not touch payload for fuzz testing
        return Ok(Bytes::copy_from_slice(payload_buf));
    }

    let payload_len = aead.open(
        cid_seq,
        pkt_num,
        header_buf,
        payload_buf,
        &mut plaintext[..],
    )?;
    plaintext.truncate(payload_len);
    Ok(plaintext.freeze())
}

/// Remove header protection of a QUIC packet.
///
/// The `pkt_buf` is the raw data of a QUIC packet.
/// The `pkt_num_offset` is the offset of Packet Number field in `pkt_buf`.
/// The `hdr` is the partially parsed header return by PacketHeader::from().
pub(crate) fn decrypt_header(
    pkt_buf: &mut [u8],
    pkt_num_offset: usize,
    hdr: &mut PacketHeader,
    aead: &Open,
) -> Result<()> {
    if pkt_buf.len() < pkt_num_offset + MAX_PKT_NUM_LEN + SAMPLE_LEN {
        return Err(Error::BufferTooShort);
    }

    let mut first = pkt_buf[0];
    let sample_start = pkt_num_offset + MAX_PKT_NUM_LEN;
    let sample = &pkt_buf[sample_start..sample_start + SAMPLE_LEN];

    // Remove protection of bits in the first byte
    let mask = aead.new_mask(sample)?;
    if PacketHeader::long_header(first) {
        first ^= mask[0] & 0x0f;
    } else {
        first ^= mask[0] & 0x1f;
    }

    // Remove protection of packet number field
    let pkt_num_len = usize::from((first & PKT_NUM_LEN_MASK) + 1);
    let pkt_num_buf = &mut pkt_buf[pkt_num_offset..pkt_num_offset + pkt_num_len];
    for i in 0..pkt_num_len {
        pkt_num_buf[i] ^= mask[i + 1];
    }

    // Extract packet number corresponding to the length.
    let pkt_num = {
        let mut b: &[u8] = pkt_num_buf;
        match pkt_num_len {
            1 => u64::from(b.read_u8()?),
            2 => u64::from(b.read_u16()?),
            3 => u64::from(b.read_u24()?),
            4 => u64::from(b.read_u32()?),
            _ => return Err(Error::InvalidPacket),
        }
    };

    // Write the decrypted first byte back into the packet buffer.
    pkt_buf[0] = first;

    // Update the parsed packet header
    hdr.pkt_num_len = pkt_num_len;
    hdr.pkt_num = pkt_num;
    if hdr.pkt_type == OneRTT {
        hdr.key_phase = (first & HEADER_KEY_PHASE_BIT) != 0;
    }
    Ok(())
}

/// Decode packet number after header protection has been removed.
///
/// The `largest_pn` is the largest packet number that has been successfully
/// processed in the current packet number space.
/// The `truncated_pn` is the value of the Packet Number field.
/// The `pkt_num_len` is the number of bits in the Packet Number field.
/// See RFC 9000 Section A.3 Sample Packet Number Decoding Algorithm
pub(crate) fn decode_packet_num(largest_pn: u64, truncated_pn: u64, pkt_num_len: usize) -> u64 {
    let pn_nbits = pkt_num_len * 8;
    let expected_pn = largest_pn + 1;
    let pn_win = 1 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    // The incoming packet number should be greater than expected_pn - pn_hwin
    // and less than or equal to expected_pn + pn_hwin .
    //
    // This means we cannot just strip the trailing bits from expected_pn and
    // add the truncated_pn because that might yield a value outside the window.
    //
    // The following code calculates a candidate value and makes sure it's
    // within the packet number window.
    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;
    if candidate_pn + pn_hwin <= expected_pn && candidate_pn < (1 << 62) - pn_win {
        return candidate_pn + pn_win;
    }
    if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
        return candidate_pn - pn_win;
    }
    candidate_pn
}

/// Encode the truncated packet number.
pub(crate) fn encode_packet_num(pkt_num: u64, mut buf: &mut [u8]) -> Result<usize> {
    let len = packet_num_len(pkt_num)?;
    match len {
        1 => buf.write_u8(pkt_num as u8)?,
        2 => buf.write_u16(pkt_num as u16)?,
        3 => buf.write_u24(pkt_num as u32)?,
        4 => buf.write_u32(pkt_num as u32)?,
        _ => return Err(Error::InvalidPacket),
    };

    Ok(len)
}

/// Return the length of encoded packet number.
///
/// Packet numbers are encoded in 1 to 4 bytes. The number of bits required to
/// represent the packet number is reduced by including only the least
/// significant bits of the packet number.
/// See RFC 9000 Section 17.1
pub(crate) fn packet_num_len(pkt_num: u64) -> Result<usize> {
    let len = if pkt_num < u64::from(u8::MAX) {
        1
    } else if pkt_num < u64::from(u16::MAX) {
        2
    } else if pkt_num < 16_777_215u64 {
        3
    } else if pkt_num < u64::from(u32::MAX) {
        4
    } else {
        return Err(Error::InvalidPacket);
    };
    Ok(len)
}

/// Encode a Version Negotiation packet to the given buffer
///
/// The `scid` is the source CID of the Version Negotiation packet.
/// The `dcid` is the destination CID of the Version Negotiation packet.
pub fn version_negotiation(scid: &[u8], dcid: &[u8], mut buf: &mut [u8]) -> Result<usize> {
    let len = buf.len();

    let first = rand::random::<u8>() | HEADER_LONG_FORM_BIT;
    buf.write_u8(first)?;

    // A Version Negotiation packet is inherently not version specific. It will
    // be identified as a Version Negotiation packet based on the Version field
    // having a value of 0.
    buf.write_u32(0)?;

    buf.write_u8(dcid.len() as u8)?;
    buf.write(dcid)?;
    buf.write_u8(scid.len() as u8)?;
    buf.write(scid)?;

    // The remainder of the Version Negotiation packet is a list of 32-bit
    // versions that the server supports
    buf.write_u32(crate::QUIC_VERSION_V1)?;

    Ok(len - buf.len())
}

/// Encode a Retry packet to the given buffer
///
/// The `scid` is the scid of Retry packet.
/// The `dcid` is the scid of Retry packet.
/// The `odcid` is the original dcid of the Initial packet.
pub fn retry(
    scid: &[u8],
    dcid: &[u8],
    odcid: &[u8],
    token: &[u8],
    version: u32,
    out: &mut [u8],
) -> Result<usize> {
    if !crate::version_is_supported(version) {
        return Err(Error::UnknownVersion);
    }

    // Prepare Retry packet header
    let hdr = PacketHeader {
        pkt_type: Retry,
        version,
        dcid: ConnectionId::new(dcid),
        scid: ConnectionId::new(scid),
        pkt_num: 0,
        pkt_num_len: 0,
        token: Some(token.to_vec()),
        key_phase: false,
    };
    let hdr_len = hdr.to_bytes(out)?;

    // Compute and add integrity tag
    let tag = compute_retry_integrity_tag(&out[..hdr_len], odcid, version)?;
    let mut out = &mut out[hdr_len..];
    out.write(tag.as_ref())?;

    Ok(hdr_len + tag.as_ref().len())
}

/// Compute the Retry Packet Integrity Tag
///
/// See RFC 9001 Section 5.8 Retry Packet Integrity.
fn compute_retry_integrity_tag(retry_hdr: &[u8], odcid: &[u8], _version: u32) -> Result<aead::Tag> {
    // The Retry Pseudo-Packet is computed by taking the transmitted Retry
    // packet, removing the Retry Integrity Tag, and prepending the two
    // following fields: Original DCID Length, Original DCID
    let mut pseudo_pkt = vec![0_u8; 1 + odcid.len() + retry_hdr.len()];
    let mut pb = pseudo_pkt.as_mut_slice();
    pb.write_u8(odcid.len() as u8)?;
    pb.write(odcid)?;
    pb.write(retry_hdr)?;

    // The Retry Integrity Tag is a 128-bit field that is computed as the output
    // of AEAD_AES_128_GCM; The plaintext is empty; The associated data is the
    // contents of the Retry Pseudo-Packet
    let (key, nonce) = (&RETRY_INTEGRITY_KEY_V1, RETRY_INTEGRITY_NONCE_V1);
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, key).map_err(|_| Error::CryptoFail)?,
    );
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let aad = aead::Aad::from(&pseudo_pkt);
    key.seal_in_place_separate_tag(nonce, aad, &mut [])
        .map_err(|_| Error::CryptoFail)
}

/// Verify integrity tag of Retry packet
///
/// The `buf` is the octets of Retry packet.
/// The `odicd` is the original destination cid.
pub fn verify_retry_integrity_tag(buf: &mut [u8], odcid: &[u8], version: u32) -> Result<()> {
    let len = aead::AES_128_GCM.tag_len();
    if buf.len() < len {
        return Err(Error::BufferTooShort);
    }

    let hdr_buf = &buf[..buf.len() - len];
    let tag = compute_retry_integrity_tag(hdr_buf, odcid, version)?;
    ring::constant_time::verify_slices_are_equal(&buf[buf.len() - len..], tag.as_ref())
        .map_err(|_| Error::CryptoFail)?;

    Ok(())
}

/// Encode a Stateless Reset packet to the given buffer
///
/// The `pkt_len` is the length of Stateless Reset packet.
/// The `token` is the Stateless Reset token.
pub fn stateless_reset(pkt_len: usize, token: &[u8], mut out: &mut [u8]) -> Result<usize> {
    if pkt_len > out.len() {
        return Err(Error::BufferTooShort);
    }
    if pkt_len < crate::MIN_RESET_PACKET_LEN {
        return Err(Error::InternalError);
    }
    if token.len() != crate::RESET_TOKEN_LEN {
        return Err(Error::InternalError);
    }

    // The layout of Stateless Reset packet:
    //
    // Stateless Reset {
    //   Fixed Bits (2) = 1,
    //   Unpredictable Bits (38..),
    //   Stateless Reset Token (128),
    // }

    // Write the Unpredictable Bits
    let unpredict_len = pkt_len - crate::RESET_TOKEN_LEN;
    rand::thread_rng().fill_bytes(&mut out[..unpredict_len]);

    // Set the 2 fixed bits
    out[0] = (out[0] & 0b0011_1111) | HEADER_FIXED_BIT;

    // Write the Stateless Reset Token
    out = &mut out[unpredict_len..];
    out.write(token)?;
    Ok(pkt_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::ResetToken;
    use std::net::Ipv4Addr;
    use std::net::SocketAddrV4;

    #[test]
    fn initial_pkt() -> Result<()> {
        // initial packet without token
        let mut initial_hdr = PacketHeader {
            pkt_type: PacketType::Initial,
            version: 1,
            dcid: ConnectionId {
                len: 20,
                data: [1; 20],
            },
            scid: ConnectionId {
                len: 20,
                data: [3; 20],
            },
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            key_phase: false,
        };
        assert_eq!(
            format!("{:?}", initial_hdr),
            "Initial ver=1 \
            dcid=0101010101010101010101010101010101010101 \
            scid=0303030303030303030303030303030303030303"
        );

        let mut buf = [0; 128];
        let len = initial_hdr.to_bytes(&mut buf)?;
        assert_eq!(
            (initial_hdr.clone(), len),
            PacketHeader::from_bytes(&mut buf, 20)?
        );

        // initial packet with token
        initial_hdr.token = Some(vec![4; 24]);
        assert_eq!(
            format!("{:?}", initial_hdr),
            "Initial ver=1 \
            dcid=0101010101010101010101010101010101010101 \
            scid=0303030303030303030303030303030303030303 \
            token=040404040404040404040404040404040404040404040404"
        );
        let len = initial_hdr.to_bytes(&mut buf)?;
        assert_eq!((initial_hdr, len), PacketHeader::from_bytes(&mut buf, 20)?);
        Ok(())
    }

    #[test]
    fn handshake_pkt() -> Result<()> {
        let hsk_hdr = PacketHeader {
            pkt_type: PacketType::Handshake,
            version: 1,
            dcid: ConnectionId {
                len: 20,
                data: [0xa; 20],
            },
            scid: ConnectionId {
                len: 20,
                data: [0xb; 20],
            },
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            key_phase: false,
        };
        assert_eq!(
            format!("{:?}", hsk_hdr),
            "Handshake ver=1 \
            dcid=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a \
            scid=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        );

        let mut buf = [0; 128];
        let len = hsk_hdr.to_bytes(&mut buf)?;
        assert_eq!((hsk_hdr, len), PacketHeader::from_bytes(&mut buf, 20)?);
        Ok(())
    }

    #[test]
    fn zero_rtt_pkt() -> Result<()> {
        let zero_rtt_hdr = PacketHeader {
            pkt_type: PacketType::ZeroRTT,
            version: 1,
            dcid: ConnectionId {
                len: 20,
                data: [0xc; 20],
            },
            scid: ConnectionId {
                len: 20,
                data: [0xd; 20],
            },
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            key_phase: false,
        };
        assert_eq!(
            format!("{:?}", zero_rtt_hdr),
            "ZeroRTT ver=1 \
            dcid=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c \
            scid=0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"
        );

        let mut buf = [0; 128];
        let len = zero_rtt_hdr.to_bytes(&mut buf)?;
        assert_eq!((zero_rtt_hdr, len), PacketHeader::from_bytes(&mut buf, 20)?);
        Ok(())
    }

    #[test]
    fn one_rtt_pkt() -> Result<()> {
        // One rtt packet with key_phase clear
        let mut one_rtt_hdr = PacketHeader {
            pkt_type: PacketType::OneRTT,
            version: 0,
            dcid: ConnectionId {
                len: 20,
                data: [0xc; 20],
            },
            scid: ConnectionId::default(),
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            key_phase: false,
        };
        assert_eq!(
            format!("{:?}", one_rtt_hdr),
            "OneRTT \
            dcid=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c key_phase=false"
        );

        let mut buf = [0; 128];
        let len = one_rtt_hdr.to_bytes(&mut buf)?;
        assert_eq!(
            (one_rtt_hdr.clone(), len),
            PacketHeader::from_bytes(&mut buf, 20)?
        );

        // One rtt packet with key_phase set
        one_rtt_hdr.key_phase = true;
        assert_eq!(
            format!("{:?}", one_rtt_hdr),
            "OneRTT \
            dcid=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c key_phase=true"
        );
        one_rtt_hdr.to_bytes(&mut buf)?;
        // Note: key phase is encrypted and not parsed by from_bytes()
        assert_eq!(PacketHeader::from_bytes(&mut buf, 20)?.0.key_phase, false);

        Ok(())
    }

    #[test]
    fn version_negotiation_pkt() -> Result<()> {
        let scid = ConnectionId {
            len: 20,
            data: [0xc; 20],
        };
        let dcid = ConnectionId {
            len: 20,
            data: [0xd; 20],
        };

        let mut buf = [0; 128];
        let len = version_negotiation(&scid, &dcid, &mut buf)?;

        let br = &buf[..len];
        let (hdr, hdr_len) = PacketHeader::from_bytes(br, 20)?;
        assert_eq!(hdr.pkt_type, PacketType::VersionNegotiation);
        assert_eq!(hdr.scid, scid);
        assert_eq!(hdr.dcid, dcid);
        assert_eq!(len, hdr_len + 4);
        assert_eq!(
            format!("{:?}", hdr),
            "VersionNegotiation ver=0 \
            dcid=0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d \
            scid=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
        );

        let mut br = &buf[hdr_len..];
        let ver = br.read_u32()?;
        assert_eq!(ver, crate::QUIC_VERSION_V1);

        assert_eq!(hdr.to_bytes(&mut buf), Err(Error::InternalError));
        Ok(())
    }

    #[test]
    fn retry_pkt() -> Result<()> {
        let scid = ConnectionId {
            len: 20,
            data: [0xc; 20],
        };
        let dcid = ConnectionId {
            len: 20,
            data: [0xd; 20],
        };
        let odcid = ConnectionId {
            len: 20,
            data: [0xe; 20],
        };
        let token = [
            0x71, 0x75, 0x69, 0x63, 0xc0, 0xa8, 0x01, 0x0a, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
            0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
        ];

        let mut buf = [0; 128];
        let len = retry(
            &scid,
            &dcid,
            &odcid,
            &token,
            crate::QUIC_VERSION_V1,
            &mut buf,
        )?;

        let br = &buf[..len];
        let (hdr, hdr_len) = PacketHeader::from_bytes(br, 20)?;
        assert_eq!(hdr.pkt_type, PacketType::Retry);
        assert_eq!(hdr.scid, scid);
        assert_eq!(hdr.dcid, dcid);
        assert_eq!(hdr.version, crate::QUIC_VERSION_V1);
        assert_eq!(hdr.token, Some(token.to_vec()));
        assert_eq!(hdr_len, len - aead::AES_128_GCM.tag_len());
        assert_eq!(
            format!("{:?}", hdr),
            "Retry ver=1 \
            dcid=0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d \
            scid=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c \
            token=71756963c0a8010a0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"
        );

        verify_retry_integrity_tag(&mut buf[..len], &odcid, crate::QUIC_VERSION_V1)?;
        Ok(())
    }

    #[test]
    fn stateless_reset_pkt() -> Result<()> {
        let token = [0xc; crate::RESET_TOKEN_LEN];
        let mut buf = [0; 128];
        assert_eq!(
            stateless_reset(64, &token, &mut buf[..10]),
            Err(Error::BufferTooShort)
        );
        assert_eq!(
            stateless_reset(16, &token, &mut buf),
            Err(Error::InternalError)
        );
        assert_eq!(
            stateless_reset(64, &token[..10], &mut buf),
            Err(Error::InternalError)
        );

        let len = stateless_reset(64, &token, &mut buf)?;
        let buf = &buf[..len];
        assert_eq!(buf[0] & 0b1100_0000, 0b0100_0000); // The 2 fixed bytes is 01
        assert_eq!(ResetToken::from_bytes(buf)?.0, token);

        Ok(())
    }

    #[test]
    fn packet_type() -> Result<()> {
        let test_cases = [
            (
                PacketType::Initial,
                Ok(Level::Initial),
                Ok(SpaceId::Initial),
            ),
            (
                PacketType::Handshake,
                Ok(Level::Handshake),
                Ok(SpaceId::Handshake),
            ),
            (
                PacketType::ZeroRTT,
                Ok(Level::ZeroRTT),
                Ok(SpaceId::Data), // app data
            ),
            (
                PacketType::OneRTT,
                Ok(Level::OneRTT),
                Ok(SpaceId::Data), // app data
            ),
            (
                PacketType::VersionNegotiation,
                Err(Error::InternalError),
                Err(Error::InternalError),
            ),
            (
                PacketType::Retry,
                Err(Error::InternalError),
                Err(Error::InternalError),
            ),
        ];

        for case in test_cases {
            let pkt_type = case.0;
            assert_eq!(pkt_type.to_level(), case.1);
            assert_eq!(pkt_type.to_space(), case.2);
        }
        Ok(())
    }

    #[test]
    fn packet_num() -> Result<()> {
        let test_cases = [
            (0, Ok(1)),
            (254, Ok(1)),
            (255, Ok(2)),
            (65534, Ok(2)),
            (65535, Ok(3)),
            (16777214, Ok(3)),
            (16777215, Ok(4)),
        ];

        let mut buf = [0; 4];
        for case in test_cases {
            let pkt_num = case.0;
            let len = encode_packet_num(pkt_num, &mut buf[..]);
            assert_eq!(len, case.1);
        }
        Ok(())
    }

    #[test]
    fn packet_cid_len() -> Result<()> {
        // packets with invalid cid length
        let pkts = [
            [
                0xc0, 0x00, 0x00, 0x00, 0x01, 0x15, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x14, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x00,
            ],
            [
                0xc0, 0x00, 0x00, 0x00, 0x01, 0x14, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x15, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                0x03, 0x03, 0x03, 0x03, 0x03, 0x00,
            ],
        ];

        for pkt in pkts {
            assert_eq!(
                PacketHeader::from_bytes(&pkt[..], 20),
                Err(Error::InvalidPacket)
            );
        }
        Ok(())
    }

    /// Unit test for RFC 9001 Section A.2 example
    #[test]
    fn client_initial_protection() -> Result<()> {
        let mut pkt = [
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            0x00, 0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34, 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68,
            0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b, 0xd8, 0xba, 0xb9, 0x36,
            0xb4, 0x7d, 0x92, 0xec, 0x35, 0x6c, 0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27, 0xcd,
            0x44, 0x9f, 0x63, 0x30, 0x00, 0x99, 0xf3, 0x99, 0x1c, 0x26, 0x0e, 0xc4, 0xc6, 0x0d,
            0x17, 0xb3, 0x1f, 0x84, 0x29, 0x15, 0x7b, 0xb3, 0x5a, 0x12, 0x82, 0xa6, 0x43, 0xa8,
            0xd2, 0x26, 0x2c, 0xad, 0x67, 0x50, 0x0c, 0xad, 0xb8, 0xe7, 0x37, 0x8c, 0x8e, 0xb7,
            0x53, 0x9e, 0xc4, 0xd4, 0x90, 0x5f, 0xed, 0x1b, 0xee, 0x1f, 0xc8, 0xaa, 0xfb, 0xa1,
            0x7c, 0x75, 0x0e, 0x2c, 0x7a, 0xce, 0x01, 0xe6, 0x00, 0x5f, 0x80, 0xfc, 0xb7, 0xdf,
            0x62, 0x12, 0x30, 0xc8, 0x37, 0x11, 0xb3, 0x93, 0x43, 0xfa, 0x02, 0x8c, 0xea, 0x7f,
            0x7f, 0xb5, 0xff, 0x89, 0xea, 0xc2, 0x30, 0x82, 0x49, 0xa0, 0x22, 0x52, 0x15, 0x5e,
            0x23, 0x47, 0xb6, 0x3d, 0x58, 0xc5, 0x45, 0x7a, 0xfd, 0x84, 0xd0, 0x5d, 0xff, 0xfd,
            0xb2, 0x03, 0x92, 0x84, 0x4a, 0xe8, 0x12, 0x15, 0x46, 0x82, 0xe9, 0xcf, 0x01, 0x2f,
            0x90, 0x21, 0xa6, 0xf0, 0xbe, 0x17, 0xdd, 0xd0, 0xc2, 0x08, 0x4d, 0xce, 0x25, 0xff,
            0x9b, 0x06, 0xcd, 0xe5, 0x35, 0xd0, 0xf9, 0x20, 0xa2, 0xdb, 0x1b, 0xf3, 0x62, 0xc2,
            0x3e, 0x59, 0x6d, 0x11, 0xa4, 0xf5, 0xa6, 0xcf, 0x39, 0x48, 0x83, 0x8a, 0x3a, 0xec,
            0x4e, 0x15, 0xda, 0xf8, 0x50, 0x0a, 0x6e, 0xf6, 0x9e, 0xc4, 0xe3, 0xfe, 0xb6, 0xb1,
            0xd9, 0x8e, 0x61, 0x0a, 0xc8, 0xb7, 0xec, 0x3f, 0xaf, 0x6a, 0xd7, 0x60, 0xb7, 0xba,
            0xd1, 0xdb, 0x4b, 0xa3, 0x48, 0x5e, 0x8a, 0x94, 0xdc, 0x25, 0x0a, 0xe3, 0xfd, 0xb4,
            0x1e, 0xd1, 0x5f, 0xb6, 0xa8, 0xe5, 0xeb, 0xa0, 0xfc, 0x3d, 0xd6, 0x0b, 0xc8, 0xe3,
            0x0c, 0x5c, 0x42, 0x87, 0xe5, 0x38, 0x05, 0xdb, 0x05, 0x9a, 0xe0, 0x64, 0x8d, 0xb2,
            0xf6, 0x42, 0x64, 0xed, 0x5e, 0x39, 0xbe, 0x2e, 0x20, 0xd8, 0x2d, 0xf5, 0x66, 0xda,
            0x8d, 0xd5, 0x99, 0x8c, 0xca, 0xbd, 0xae, 0x05, 0x30, 0x60, 0xae, 0x6c, 0x7b, 0x43,
            0x78, 0xe8, 0x46, 0xd2, 0x9f, 0x37, 0xed, 0x7b, 0x4e, 0xa9, 0xec, 0x5d, 0x82, 0xe7,
            0x96, 0x1b, 0x7f, 0x25, 0xa9, 0x32, 0x38, 0x51, 0xf6, 0x81, 0xd5, 0x82, 0x36, 0x3a,
            0xa5, 0xf8, 0x99, 0x37, 0xf5, 0xa6, 0x72, 0x58, 0xbf, 0x63, 0xad, 0x6f, 0x1a, 0x0b,
            0x1d, 0x96, 0xdb, 0xd4, 0xfa, 0xdd, 0xfc, 0xef, 0xc5, 0x26, 0x6b, 0xa6, 0x61, 0x17,
            0x22, 0x39, 0x5c, 0x90, 0x65, 0x56, 0xbe, 0x52, 0xaf, 0xe3, 0xf5, 0x65, 0x63, 0x6a,
            0xd1, 0xb1, 0x7d, 0x50, 0x8b, 0x73, 0xd8, 0x74, 0x3e, 0xeb, 0x52, 0x4b, 0xe2, 0x2b,
            0x3d, 0xcb, 0xc2, 0xc7, 0x46, 0x8d, 0x54, 0x11, 0x9c, 0x74, 0x68, 0x44, 0x9a, 0x13,
            0xd8, 0xe3, 0xb9, 0x58, 0x11, 0xa1, 0x98, 0xf3, 0x49, 0x1d, 0xe3, 0xe7, 0xfe, 0x94,
            0x2b, 0x33, 0x04, 0x07, 0xab, 0xf8, 0x2a, 0x4e, 0xd7, 0xc1, 0xb3, 0x11, 0x66, 0x3a,
            0xc6, 0x98, 0x90, 0xf4, 0x15, 0x70, 0x15, 0x85, 0x3d, 0x91, 0xe9, 0x23, 0x03, 0x7c,
            0x22, 0x7a, 0x33, 0xcd, 0xd5, 0xec, 0x28, 0x1c, 0xa3, 0xf7, 0x9c, 0x44, 0x54, 0x6b,
            0x9d, 0x90, 0xca, 0x00, 0xf0, 0x64, 0xc9, 0x9e, 0x3d, 0xd9, 0x79, 0x11, 0xd3, 0x9f,
            0xe9, 0xc5, 0xd0, 0xb2, 0x3a, 0x22, 0x9a, 0x23, 0x4c, 0xb3, 0x61, 0x86, 0xc4, 0x81,
            0x9e, 0x8b, 0x9c, 0x59, 0x27, 0x72, 0x66, 0x32, 0x29, 0x1d, 0x6a, 0x41, 0x82, 0x11,
            0xcc, 0x29, 0x62, 0xe2, 0x0f, 0xe4, 0x7f, 0xeb, 0x3e, 0xdf, 0x33, 0x0f, 0x2c, 0x60,
            0x3a, 0x9d, 0x48, 0xc0, 0xfc, 0xb5, 0x69, 0x9d, 0xbf, 0xe5, 0x89, 0x64, 0x25, 0xc5,
            0xba, 0xc4, 0xae, 0xe8, 0x2e, 0x57, 0xa8, 0x5a, 0xaf, 0x4e, 0x25, 0x13, 0xe4, 0xf0,
            0x57, 0x96, 0xb0, 0x7b, 0xa2, 0xee, 0x47, 0xd8, 0x05, 0x06, 0xf8, 0xd2, 0xc2, 0x5e,
            0x50, 0xfd, 0x14, 0xde, 0x71, 0xe6, 0xc4, 0x18, 0x55, 0x93, 0x02, 0xf9, 0x39, 0xb0,
            0xe1, 0xab, 0xd5, 0x76, 0xf2, 0x79, 0xc4, 0xb2, 0xe0, 0xfe, 0xb8, 0x5c, 0x1f, 0x28,
            0xff, 0x18, 0xf5, 0x88, 0x91, 0xff, 0xef, 0x13, 0x2e, 0xef, 0x2f, 0xa0, 0x93, 0x46,
            0xae, 0xe3, 0x3c, 0x28, 0xeb, 0x13, 0x0f, 0xf2, 0x8f, 0x5b, 0x76, 0x69, 0x53, 0x33,
            0x41, 0x13, 0x21, 0x19, 0x96, 0xd2, 0x00, 0x11, 0xa1, 0x98, 0xe3, 0xfc, 0x43, 0x3f,
            0x9f, 0x25, 0x41, 0x01, 0x0a, 0xe1, 0x7c, 0x1b, 0xf2, 0x02, 0x58, 0x0f, 0x60, 0x47,
            0x47, 0x2f, 0xb3, 0x68, 0x57, 0xfe, 0x84, 0x3b, 0x19, 0xf5, 0x98, 0x40, 0x09, 0xdd,
            0xc3, 0x24, 0x04, 0x4e, 0x84, 0x7a, 0x4f, 0x4a, 0x0a, 0xb3, 0x4f, 0x71, 0x95, 0x95,
            0xde, 0x37, 0x25, 0x2d, 0x62, 0x35, 0x36, 0x5e, 0x9b, 0x84, 0x39, 0x2b, 0x06, 0x10,
            0x85, 0x34, 0x9d, 0x73, 0x20, 0x3a, 0x4a, 0x13, 0xe9, 0x6f, 0x54, 0x32, 0xec, 0x0f,
            0xd4, 0xa1, 0xee, 0x65, 0xac, 0xcd, 0xd5, 0xe3, 0x90, 0x4d, 0xf5, 0x4c, 0x1d, 0xa5,
            0x10, 0xb0, 0xff, 0x20, 0xdc, 0xc0, 0xc7, 0x7f, 0xcb, 0x2c, 0x0e, 0x0e, 0xb6, 0x05,
            0xcb, 0x05, 0x04, 0xdb, 0x87, 0x63, 0x2c, 0xf3, 0xd8, 0xb4, 0xda, 0xe6, 0xe7, 0x05,
            0x76, 0x9d, 0x1d, 0xe3, 0x54, 0x27, 0x01, 0x23, 0xcb, 0x11, 0x45, 0x0e, 0xfc, 0x60,
            0xac, 0x47, 0x68, 0x3d, 0x7b, 0x8d, 0x0f, 0x81, 0x13, 0x65, 0x56, 0x5f, 0xd9, 0x8c,
            0x4c, 0x8e, 0xb9, 0x36, 0xbc, 0xab, 0x8d, 0x06, 0x9f, 0xc3, 0x3b, 0xd8, 0x01, 0xb0,
            0x3a, 0xde, 0xa2, 0xe1, 0xfb, 0xc5, 0xaa, 0x46, 0x3d, 0x08, 0xca, 0x19, 0x89, 0x6d,
            0x2b, 0xf5, 0x9a, 0x07, 0x1b, 0x85, 0x1e, 0x6c, 0x23, 0x90, 0x52, 0x17, 0x2f, 0x29,
            0x6b, 0xfb, 0x5e, 0x72, 0x40, 0x47, 0x90, 0xa2, 0x18, 0x10, 0x14, 0xf3, 0xb9, 0x4a,
            0x4e, 0x97, 0xd1, 0x17, 0xb4, 0x38, 0x13, 0x03, 0x68, 0xcc, 0x39, 0xdb, 0xb2, 0xd1,
            0x98, 0x06, 0x5a, 0xe3, 0x98, 0x65, 0x47, 0x92, 0x6c, 0xd2, 0x16, 0x2f, 0x40, 0xa2,
            0x9f, 0x0c, 0x3c, 0x87, 0x45, 0xc0, 0xf5, 0x0f, 0xba, 0x38, 0x52, 0xe5, 0x66, 0xd4,
            0x45, 0x75, 0xc2, 0x9d, 0x39, 0xa0, 0x3f, 0x0c, 0xda, 0x72, 0x19, 0x84, 0xb6, 0xf4,
            0x40, 0x59, 0x1f, 0x35, 0x5e, 0x12, 0xd4, 0x39, 0xff, 0x15, 0x0a, 0xab, 0x76, 0x13,
            0x49, 0x9d, 0xbd, 0x49, 0xad, 0xab, 0xc8, 0x67, 0x6e, 0xef, 0x02, 0x3b, 0x15, 0xb6,
            0x5b, 0xfc, 0x5c, 0xa0, 0x69, 0x48, 0x10, 0x9f, 0x23, 0xf3, 0x50, 0xdb, 0x82, 0x12,
            0x35, 0x35, 0xeb, 0x8a, 0x74, 0x33, 0xbd, 0xab, 0xcb, 0x90, 0x92, 0x71, 0xa6, 0xec,
            0xbc, 0xb5, 0x8b, 0x93, 0x6a, 0x88, 0xcd, 0x4e, 0x8f, 0x2e, 0x6f, 0xf5, 0x80, 0x01,
            0x75, 0xf1, 0x13, 0x25, 0x3d, 0x8f, 0xa9, 0xca, 0x88, 0x85, 0xc2, 0xf5, 0x52, 0xe6,
            0x57, 0xdc, 0x60, 0x3f, 0x25, 0x2e, 0x1a, 0x8e, 0x30, 0x8f, 0x76, 0xf0, 0xbe, 0x79,
            0xe2, 0xfb, 0x8f, 0x5d, 0x5f, 0xbb, 0xe2, 0xe3, 0x0e, 0xca, 0xdd, 0x22, 0x07, 0x23,
            0xc8, 0xc0, 0xae, 0xa8, 0x07, 0x8c, 0xdf, 0xcb, 0x38, 0x68, 0x26, 0x3f, 0xf8, 0xf0,
            0x94, 0x00, 0x54, 0xda, 0x48, 0x78, 0x18, 0x93, 0xa7, 0xe4, 0x9a, 0xd5, 0xaf, 0xf4,
            0xaf, 0x30, 0x0c, 0xd8, 0x04, 0xa6, 0xb6, 0x27, 0x9a, 0xb3, 0xff, 0x3a, 0xfb, 0x64,
            0x49, 0x1c, 0x85, 0x19, 0x4a, 0xab, 0x76, 0x0d, 0x58, 0xa6, 0x06, 0x65, 0x4f, 0x9f,
            0x44, 0x00, 0xe8, 0xb3, 0x85, 0x91, 0x35, 0x6f, 0xbf, 0x64, 0x25, 0xac, 0xa2, 0x6d,
            0xc8, 0x52, 0x44, 0x25, 0x9f, 0xf2, 0xb1, 0x9c, 0x41, 0xb9, 0xf9, 0x6f, 0x3c, 0xa9,
            0xec, 0x1d, 0xde, 0x43, 0x4d, 0xa7, 0xd2, 0xd3, 0x92, 0xb9, 0x05, 0xdd, 0xf3, 0xd1,
            0xf9, 0xaf, 0x93, 0xd1, 0xaf, 0x59, 0x50, 0xbd, 0x49, 0x3f, 0x5a, 0xa7, 0x31, 0xb4,
            0x05, 0x6d, 0xf3, 0x1b, 0xd2, 0x67, 0xb6, 0xb9, 0x0a, 0x07, 0x98, 0x31, 0xaa, 0xf5,
            0x79, 0xbe, 0x0a, 0x39, 0x01, 0x31, 0x37, 0xaa, 0xc6, 0xd4, 0x04, 0xf5, 0x18, 0xcf,
            0xd4, 0x68, 0x40, 0x64, 0x7e, 0x78, 0xbf, 0xe7, 0x06, 0xca, 0x4c, 0xf5, 0xe9, 0xc5,
            0x45, 0x3e, 0x9f, 0x7c, 0xfd, 0x2b, 0x8b, 0x4c, 0x8d, 0x16, 0x9a, 0x44, 0xe5, 0x5c,
            0x88, 0xd4, 0xa9, 0xa7, 0xf9, 0x47, 0x42, 0x41, 0xe2, 0x21, 0xaf, 0x44, 0x86, 0x00,
            0x18, 0xab, 0x08, 0x56, 0x97, 0x2e, 0x19, 0x4c, 0xd9, 0x34,
        ];

        let dcid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let crypto_frame = [
            0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed, 0x03, 0x03, 0xeb, 0xf8, 0xfa, 0x56,
            0xf1, 0x29, 0x39, 0xb9, 0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e, 0xc4, 0x0b, 0xb8, 0x63,
            0xcf, 0xd3, 0xe8, 0x68, 0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b, 0x69, 0x48, 0x4c,
            0x00, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
            0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
            0x63, 0x6f, 0x6d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06,
            0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05, 0x04, 0x61,
            0x6c, 0x70, 0x6e, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33,
            0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x93, 0x70, 0xb2, 0xc9, 0xca, 0xa4,
            0x7f, 0xba, 0xba, 0xf4, 0x55, 0x9f, 0xed, 0xba, 0x75, 0x3d, 0xe1, 0x71, 0xfa, 0x71,
            0xf5, 0x0f, 0x1c, 0xe1, 0x5d, 0x43, 0xe9, 0x94, 0xec, 0x74, 0xd7, 0x48, 0x00, 0x2b,
            0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05,
            0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x00, 0x2d, 0x00,
            0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x39, 0x00, 0x32, 0x04,
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80, 0x00, 0xff,
            0xff, 0x07, 0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10, 0x01, 0x04, 0x80, 0x00,
            0x75, 0x30, 0x09, 0x01, 0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57,
            0x08, 0x06, 0x04, 0x80, 0x00, 0xff, 0xff,
        ];

        // Parse QUIC packet header
        let (mut hdr, read) = PacketHeader::from_bytes(&pkt[..], 0)?;
        let (length, pkt_num_off) = {
            let mut b = &pkt[read..];
            (b.read_varint()? as usize, pkt.len() - b.len())
        };
        assert_eq!(hdr.pkt_type, PacketType::Initial);
        assert_eq!(hdr.version, crate::QUIC_VERSION_V1);
        assert_eq!(&hdr.dcid[..], &dcid[..]);
        assert_eq!(hdr.scid.len(), 0);
        assert_eq!(hdr.token, None);

        // Decrypt QUIC packet header on the server
        let (open, _) = tls::derive_initial_secrets(&hdr.dcid, hdr.version, true)?;
        decrypt_header(&mut pkt[..], pkt_num_off, &mut hdr, &open)?;
        assert_eq!(hdr.pkt_num_len, 4);

        hdr.pkt_num = decode_packet_num(0, hdr.pkt_num, hdr.pkt_num_len);
        assert_eq!(hdr.pkt_num, 2);

        // Decrypt QUIC packet payload
        let payload_off = pkt_num_off + hdr.pkt_num_len;
        let payload_len = length - hdr.pkt_num_len;
        let plaintext = decrypt_payload(
            &mut pkt[..],
            payload_off,
            payload_len,
            None,
            hdr.pkt_num,
            &open,
        )?;
        assert_eq!(plaintext[..crypto_frame.len()], crypto_frame);

        Ok(())
    }

    /// Unit test for RFC 9001 Section A.3 example
    #[test]
    fn server_initial_protection() -> Result<()> {
        let mut pkt = [
            0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62,
            0xb5, 0x00, 0x40, 0x75, 0xc0, 0xd9, 0x5a, 0x48, 0x2c, 0xd0, 0x99, 0x1c, 0xd2, 0x5b,
            0x0a, 0xac, 0x40, 0x6a, 0x58, 0x16, 0xb6, 0x39, 0x41, 0x00, 0xf3, 0x7a, 0x1c, 0x69,
            0x79, 0x75, 0x54, 0x78, 0x0b, 0xb3, 0x8c, 0xc5, 0xa9, 0x9f, 0x5e, 0xde, 0x4c, 0xf7,
            0x3c, 0x3e, 0xc2, 0x49, 0x3a, 0x18, 0x39, 0xb3, 0xdb, 0xcb, 0xa3, 0xf6, 0xea, 0x46,
            0xc5, 0xb7, 0x68, 0x4d, 0xf3, 0x54, 0x8e, 0x7d, 0xde, 0xb9, 0xc3, 0xbf, 0x9c, 0x73,
            0xcc, 0x3f, 0x3b, 0xde, 0xd7, 0x4b, 0x56, 0x2b, 0xfb, 0x19, 0xfb, 0x84, 0x02, 0x2f,
            0x8e, 0xf4, 0xcd, 0xd9, 0x37, 0x95, 0xd7, 0x7d, 0x06, 0xed, 0xbb, 0x7a, 0xaf, 0x2f,
            0x58, 0x89, 0x18, 0x50, 0xab, 0xbd, 0xca, 0x3d, 0x20, 0x39, 0x8c, 0x27, 0x64, 0x56,
            0xcb, 0xc4, 0x21, 0x58, 0x40, 0x7d, 0xd0, 0x74, 0xee,
        ];

        let odcid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let scid: [u8; 8] = [0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];

        let crypto_frame = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03,
            0x03, 0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67, 0x78,
            0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d, 0xc5, 0x43,
            0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0,
            0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28, 0x7c, 0x83,
            0x4d, 0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00, 0x02, 0x03,
            0x04,
        ];

        // Parse QUIC packet header
        let (mut hdr, read) = PacketHeader::from_bytes(&pkt[..], 0)?;
        let (length, pkt_num_off) = {
            let mut b = &pkt[read..];
            (b.read_varint()? as usize, pkt.len() - b.len())
        };
        assert_eq!(hdr.pkt_type, PacketType::Initial);
        assert_eq!(hdr.version, crate::QUIC_VERSION_V1);
        assert_eq!(hdr.dcid.len(), 0);
        assert_eq!(&hdr.scid[..], &scid[..]);
        assert_eq!(hdr.token, None);

        // Decrypt QUIC packet header on the client
        let (open, _) = tls::derive_initial_secrets(&odcid, hdr.version, false)?;
        decrypt_header(&mut pkt[..], pkt_num_off, &mut hdr, &open)?;
        assert_eq!(hdr.pkt_num_len, 2);

        hdr.pkt_num = decode_packet_num(0, hdr.pkt_num, hdr.pkt_num_len);
        assert_eq!(hdr.pkt_num, 1);

        // Decrypt QUIC packet payload
        let payload_off = pkt_num_off + hdr.pkt_num_len;
        let payload_len = length - hdr.pkt_num_len;
        let plaintext = decrypt_payload(
            &mut pkt[..],
            payload_off,
            payload_len,
            None,
            hdr.pkt_num,
            &open,
        )?;
        assert_eq!(plaintext[..crypto_frame.len()], crypto_frame);

        Ok(())
    }

    /// Unit test for RFC 9001 Section A.5 example
    #[test]
    fn onertt_chacha20_protection() -> Result<()> {
        let pkt_hdr_data = [0x42, 0x00, 0xbf, 0xf4];
        let pkt_num = 654_360_564;
        let pkt_num_len = 3;
        let pkt_payload = [01];

        let secret = [
            0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42, 0x27, 0x48, 0xad,
            0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3,
            0x0f, 0x21, 0x63, 0x2b,
        ];

        let pkt_expected = [
            0x4c, 0xfe, 0x41, 0x89, 0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57,
            0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b, 0xfb,
        ];

        let (hdr, _) = PacketHeader::from_bytes(&pkt_hdr_data[..], 0)?;
        assert_eq!(hdr.pkt_type, PacketType::OneRTT);

        let mut out = vec![0_u8; pkt_expected.len()];
        let mut b = out.as_mut_slice();
        b.write(&pkt_hdr_data)?;
        b.write(&pkt_payload)?;

        let aead = Seal::new_with_secret(tls::Algorithm::ChaCha20Poly1305, secret.to_vec())?;
        let written = encrypt_packet(
            out.as_mut_slice(),
            None,
            pkt_num,
            pkt_num_len,
            pkt_payload.len(),
            pkt_hdr_data.len(),
            None,
            &aead,
        )?;
        assert_eq!(written, pkt_expected.len());
        assert_eq!(&out[..written], &pkt_expected[..]);
        Ok(())
    }

    #[test]
    fn multipath_protection() -> Result<()> {
        let mut out = vec![0_u8; 128];
        let pkt_hdr = PacketHeader {
            pkt_type: PacketType::OneRTT,
            version: 0,
            dcid: ConnectionId::random(),
            scid: ConnectionId::default(),
            pkt_num: 10,
            pkt_num_len: packet_num_len(10)?,
            token: None,
            key_phase: false,
        };
        let pkt_payload = [01, 02, 03, 04];
        let cid_seq = Some(2);
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);

        // encode the packet header and payload
        let mut written = pkt_hdr.to_bytes(&mut out)?;
        written += encode_packet_num(pkt_hdr.pkt_num, &mut out[written..])?;
        let (payload_off, payload_end) = (written, written + pkt_payload.len());
        out[payload_off..payload_end].copy_from_slice(&pkt_payload);

        // encrypt the packet header and payload
        let seal = Seal::new_with_secret(tls::Algorithm::ChaCha20Poly1305, secret.to_vec())?;
        let written = encrypt_packet(
            out.as_mut_slice(),
            cid_seq,
            pkt_hdr.pkt_num,
            pkt_hdr.pkt_num_len,
            pkt_payload.len(),
            payload_off,
            None,
            &seal,
        )?;
        out.truncate(written);

        // decode and decrypt packet header
        let (mut hdr, read) = PacketHeader::from_bytes(&out, crate::MAX_CID_LEN)?;
        assert_eq!(hdr.pkt_type, pkt_hdr.pkt_type);
        assert_eq!(hdr.dcid, pkt_hdr.dcid);
        assert_eq!(hdr.key_phase, pkt_hdr.key_phase);

        let open = Open::new_with_secret(tls::Algorithm::ChaCha20Poly1305, secret.to_vec())?;
        decrypt_header(&mut out, read, &mut hdr, &open)?;
        assert_eq!(hdr.pkt_num_len, pkt_hdr.pkt_num_len);
        assert_eq!(hdr.pkt_num, pkt_hdr.pkt_num);

        // decrypt packet payload
        let payload_off = read + hdr.pkt_num_len;
        let payload_len = out.len() - read - hdr.pkt_num_len;
        let plaintext = decrypt_payload(
            &mut out,
            payload_off,
            payload_len,
            cid_seq,
            hdr.pkt_num,
            &open,
        )?;
        assert_eq!(&pkt_payload[..], &plaintext);

        Ok(())
    }

    #[test]
    fn buffer_too_short() -> Result<()> {
        let mut buf = [0; 1];
        let br = &buf[..];

        assert_eq!(PacketHeader::from_bytes(br, 20), Err(Error::BufferTooShort));

        let bw = &mut buf[..];
        let (open, _) =
            tls::derive_initial_secrets(&ConnectionId::random(), crate::QUIC_VERSION_V1, false)?;
        let mut hdr = PacketHeader {
            pkt_type: PacketType::OneRTT,
            version: 0,
            dcid: ConnectionId::random(),
            scid: ConnectionId::default(),
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            key_phase: false,
        };
        assert_eq!(
            decrypt_header(bw, 10, &mut hdr, &open),
            Err(Error::BufferTooShort)
        );
        assert_eq!(
            decrypt_payload(bw, 10, 10, None, 0, &open),
            Err(Error::BufferTooShort)
        );

        assert_eq!(
            verify_retry_integrity_tag(bw, &ConnectionId::random(), crate::QUIC_VERSION_V1),
            Err(Error::BufferTooShort)
        );

        Ok(())
    }
}
