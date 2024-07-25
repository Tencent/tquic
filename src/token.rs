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

use std::fmt;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time;
use std::time::Duration;

use ring::aead;
use ring::hmac;

use self::AddressTokenType::*;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::error::Error;
use crate::ConnectionId;
use crate::Result;
use crate::RESET_TOKEN_LEN;

/// Type of token for address validation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AddressTokenType {
    /// The token is delivered to the client during connection establishment
    /// with the Retry packet.
    RetryToken = 0,

    /// The token is delivered to the client in a previous connection using the
    /// NEW_TOKEN frame.
    ResumeToken = 1,
}

/// QUIC uses an address token in the Initial packet to provide address validation
/// prior to completing the handshake.
#[derive(Debug)]
pub struct AddressToken {
    /// Type of the address token.
    pub token_type: AddressTokenType,

    /// Time of the token issued.
    pub issued: time::SystemTime,

    /// Client address.
    pub address: SocketAddr,

    /// Original destination cid
    pub odcid: Option<ConnectionId>,

    /// Retry source cid
    pub rscid: Option<ConnectionId>,
}

impl AddressToken {
    /// Generate a Retry token
    pub fn new_retry_token(
        address: SocketAddr,
        odcid: ConnectionId,
        rscid: ConnectionId,
    ) -> AddressToken {
        AddressToken {
            token_type: RetryToken,
            issued: time::SystemTime::now(),
            address,
            odcid: Some(odcid),
            rscid: Some(rscid),
        }
    }

    /// Generate a Resume token
    pub fn new_resume_token(address: SocketAddr) -> AddressToken {
        AddressToken {
            token_type: ResumeToken,
            issued: time::SystemTime::now(),
            address,
            odcid: None,
            rscid: None,
        }
    }

    /// Encode the address token.
    pub fn encode(&self, key: &aead::LessSafeKey) -> Result<Vec<u8>> {
        let max_len = AddressToken::max_token_len(key);
        let mut token = vec![0u8; max_len];
        let nonce = rand::random::<[u8; aead::NONCE_LEN]>();

        // Write token header: label/token type/nonce
        let mut buf = token.as_mut_slice();
        buf.write(b"quic")?;
        buf.write_u8(self.token_type as u8)?;
        buf.write(&nonce)?;
        let hdr_len = max_len - buf.len();

        // Write token body: issued time/original dcid
        let seconds = self.issue_time()?;
        buf.write_u64(seconds)?;
        if self.token_type == RetryToken {
            if let Some(odcid) = self.odcid {
                buf.write_u8(odcid.len() as u8)?;
                buf.write(&odcid)?;
            } else {
                return Err(Error::InternalError);
            }
        }
        let token_len = max_len - buf.len();

        // Encrypt the token body with additional authenticated data:
        // client ip address, optional port/retry scid
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let aad =
            AddressToken::additional_data(self.token_type, &self.address, self.rscid.as_ref())?;
        let aad = aead::Aad::from(&aad);
        token.truncate(token_len);
        let mut buf = token.split_off(hdr_len);

        key.seal_in_place_append_tag(nonce, aad, &mut buf)
            .map_err(|_| Error::InternalError)?;
        token.append(&mut buf);

        Ok(token)
    }

    /// Decode and validate the address token from the client Initial packet.
    ///
    /// The `token` is the data of token field in the Initial packet.
    /// The `address` is the source address of the Initial packet.
    /// The `pkt_dcid` is the destination cid in the Initial packet.
    ///
    /// Note: The decoded AddressToken also carries odcid/rscid to facilitate
    /// the server to authenticate cids.
    /// - RetryToken: the odcid is decrypted and extracted from the token;
    ///   the rscid is copied from the dcid of the Initial packet with retry
    ///   token.
    /// - ResumeToken: the odcid is copied from the dcid of the Initial packet
    ///   with resume token; the rscid is None and not applicable.
    ///
    /// See RFC 9000 Figure 7/8: Use of Connection IDs in a Handshake.
    pub fn decode(
        key: &aead::LessSafeKey,
        token: &mut [u8],
        address: &SocketAddr,
        pkt_dcid: &ConnectionId,
        lifetime: Duration,
    ) -> Result<AddressToken> {
        // Decode the token header
        let mut buf: &[u8] = token;
        let label = buf.read(4)?;
        if label != b"quic" {
            return Err(Error::InvalidToken);
        }

        let token_type = buf.read_u8()?;
        let token_type = match token_type {
            0 => RetryToken,
            1 => ResumeToken,
            _ => return Err(Error::InvalidToken),
        };

        let nonce = buf.read(aead::NONCE_LEN)?;
        let hdr_len = token.len() - buf.len();

        // When the handshake includes a Retry, the DCID of client Initial
        // packet with retry token is the retry source connection id created by
        // the server.
        let rscid = if token_type == RetryToken {
            Some(pkt_dcid)
        } else {
            None
        };

        // Decrypt the token body and authenticate the additional data
        let nonce =
            aead::Nonce::try_assume_unique_for_key(&nonce).map_err(|_| Error::InternalError)?;
        let aad = AddressToken::additional_data(token_type, address, rscid)?;
        let aad = aead::Aad::from(&aad);
        let buf = &mut token[hdr_len..];
        key.open_in_place(nonce, aad, buf)
            .map_err(|_| Error::InvalidToken)?;

        // Extract and check the timestamp
        let mut buf = &token[hdr_len..];
        let issued = buf.read_u64()?;
        let issued = match time::UNIX_EPOCH.checked_add(Duration::from_secs(issued)) {
            Some(v) => v,
            None => return Err(Error::InvalidToken),
        };

        if let Ok(duration) = issued.elapsed() {
            if duration > lifetime {
                // token expired
                return Err(Error::InvalidToken);
            }
        } else {
            // token timestamp invalid (issued > now)
            return Err(Error::InvalidToken);
        }

        // Extract the original dcid
        let odcid = if token_type == RetryToken {
            let cid_len = buf.read_u8()?;
            match cid_len {
                0 => None,
                1..=20 => {
                    let cid = buf.read(cid_len as usize)?;
                    Some(ConnectionId::new(&cid))
                }
                _ => return Err(Error::InvalidToken),
            }
        } else {
            Some(*pkt_dcid)
        };

        Ok(AddressToken {
            token_type,
            issued,
            address: *address,
            odcid,
            rscid: rscid.copied(),
        })
    }

    /// Return epoch time in seconds
    fn issue_time(&self) -> Result<u64> {
        self.issued
            .duration_since(time::UNIX_EPOCH)
            .map(|x| x.as_secs())
            .map_err(|_| Error::InternalError)
    }

    /// Return the additional data to be authenticated.
    fn additional_data(
        token_type: AddressTokenType,
        address: &SocketAddr,
        rscid: Option<&ConnectionId>,
    ) -> Result<Vec<u8>> {
        const MAX_LEN: usize = 16 + 2 + 20;
        let mut data = vec![0u8; MAX_LEN];

        // client ip address
        let mut buf = data.as_mut_slice();
        let addr = match address.ip() {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        buf.write(&addr)?;

        // client port/retry scid
        if token_type == RetryToken {
            buf.write_u16(address.port())?;
            if let Some(rscid) = rscid {
                buf.write(rscid)?;
            } else {
                return Err(Error::InternalError);
            }
        }
        let len = MAX_LEN - buf.len();
        data.truncate(len);

        Ok(data)
    }

    /// Return the max length of the encoded token.
    fn max_token_len(key: &aead::LessSafeKey) -> usize {
        4 + 1 + aead::NONCE_LEN + 8 + 21 + key.algorithm().tag_len()
    }

    /// Return the type of the address token.
    pub fn token_type(token: &[u8]) -> Result<AddressTokenType> {
        if token.len() < 5 {
            return Err(Error::InvalidToken);
        }
        match token[4] {
            0 => Ok(RetryToken),
            1 => Ok(ResumeToken),
            _ => Err(Error::InvalidToken),
        }
    }
}

/// A stateless reset token is specific to a connection ID. An endpoint issues
/// a stateless reset token by including the value in the Stateless Reset Token
/// field of a NEW_CONNECTION_ID frame.
#[derive(Copy, Clone, Hash, Default, PartialEq, Eq)]
pub struct ResetToken(pub [u8; RESET_TOKEN_LEN]);

impl ResetToken {
    pub(crate) fn new(data: &[u8]) -> Result<Self> {
        if data.len() < crate::RESET_TOKEN_LEN {
            return Err(Error::BufferTooShort);
        }
        let mut token = ResetToken::default();
        token.0.clone_from_slice(data);
        Ok(token)
    }

    /// Creata a Stateless Reset token for the given CID.
    pub(crate) fn generate(key: &hmac::Key, id: &ConnectionId) -> Self {
        let tag = hmac::sign(key, id);

        let mut token = ResetToken::default();
        token.0.clone_from_slice(&tag.as_ref()[..RESET_TOKEN_LEN]);
        token
    }

    /// Decode a Reset Token from a Stateless Reset packet
    pub(crate) fn from_bytes(buf: &[u8]) -> Result<Self> {
        // A Stateless Reset uses an entire UDP datagram. The Unpredictable Bits
        // field needs to include at least 38 bits of data (or 5 bytes, less the
        // two fixed bits). The last 16 bytes of the datagram contain a
        // stateless reset token.
        if buf.len() < crate::MIN_RESET_PACKET_LEN {
            return Err(Error::BufferTooShort);
        }
        let mut token = ResetToken::default();
        token.0.copy_from_slice(&buf[buf.len() - RESET_TOKEN_LEN..]);
        Ok(token)
    }

    /// Encode a Reset Token to a 128 bit integer
    pub(crate) fn to_u128(self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    /// Decode a Reset Token from a 128 bit integer
    pub(crate) fn from_u128(v: u128) -> ResetToken {
        ResetToken(v.to_be_bytes())
    }
}

impl std::ops::Deref for ResetToken {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::aead::LessSafeKey;
    use ring::aead::UnboundKey;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    fn cmp_address_token(a: &AddressToken, b: &AddressToken) -> bool {
        let duration = if a.issued > b.issued {
            a.issued.duration_since(b.issued).unwrap()
        } else {
            b.issued.duration_since(a.issued).unwrap()
        };
        duration < Duration::from_secs(1)
            && a.token_type == b.token_type
            && a.address == b.address
            && a.rscid == b.rscid
            && if a.token_type == RetryToken {
                a.odcid == b.odcid
            } else {
                true // ignore odcid for ResumeToken
            }
    }

    #[test]
    fn address_token_normal() -> Result<()> {
        let ip4 = Ipv4Addr::new(192, 168, 1, 1);
        let ip6 = Ipv6Addr::new(0x26, 0, 0x1c9, 0, 0, 0xafc8, 0x10, 0x1);
        let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &[1; 16]).unwrap());
        let cid0 = ConnectionId {
            len: 0,
            data: [0; 20],
        };
        let lifetime = Duration::from_secs(86400);

        let retry_token_tests = [
            AddressToken::new_retry_token(
                SocketAddr::new(IpAddr::V4(ip4), 8888),
                ConnectionId::random(),
                ConnectionId::random(),
            ),
            AddressToken::new_retry_token(
                SocketAddr::new(IpAddr::V6(ip6), 8888),
                ConnectionId::random(),
                ConnectionId::random(),
            ),
            AddressToken::new_retry_token(
                SocketAddr::new(IpAddr::V6(ip6), 8888),
                cid0,
                ConnectionId::random(),
            ),
            AddressToken::new_retry_token(
                SocketAddr::new(IpAddr::V6(ip6), 8888),
                ConnectionId::random(),
                cid0,
            ),
            AddressToken::new_retry_token(SocketAddr::new(IpAddr::V6(ip6), 8888), cid0, cid0),
        ];
        for token in retry_token_tests {
            let mut buf = token.encode(&key)?;
            cmp_address_token(
                &token,
                &AddressToken::decode(
                    &key,
                    &mut buf,
                    &token.address,
                    &token.rscid.unwrap(),
                    lifetime,
                )?,
            );
        }

        let resume_token_tests = [
            AddressToken::new_resume_token(SocketAddr::new(IpAddr::V4(ip4), 0)),
            AddressToken::new_resume_token(SocketAddr::new(IpAddr::V6(ip6), 0)),
        ];
        for token in resume_token_tests {
            let mut buf = token.encode(&key)?;
            cmp_address_token(
                &token,
                &AddressToken::decode(
                    &key,
                    &mut buf,
                    &token.address,
                    &ConnectionId::random(),
                    lifetime,
                )?,
            );
        }

        Ok(())
    }

    #[test]
    fn address_token_invalid() -> Result<()> {
        let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &[1; 16]).unwrap());
        let ip4 = Ipv4Addr::new(192, 168, 1, 1);
        let lifetime = Duration::from_secs(86400);

        for token in [
            AddressToken {
                token_type: RetryToken,
                issued: time::SystemTime::now(),
                address: SocketAddr::new(IpAddr::V4(ip4), 8888),
                odcid: None,
                rscid: Some(ConnectionId::random()),
            },
            AddressToken {
                token_type: RetryToken,
                issued: time::SystemTime::now(),
                address: SocketAddr::new(IpAddr::V4(ip4), 8888),
                odcid: Some(ConnectionId::random()),
                rscid: None,
            },
            AddressToken {
                token_type: RetryToken,
                issued: time::SystemTime::now(),
                address: SocketAddr::new(IpAddr::V4(ip4), 8888),
                odcid: None,
                rscid: None,
            },
        ] {
            assert!(token.encode(&key).is_err());
        }

        for (mut buf, ip) in [
            // unexpected label is `quiu`
            (
                [
                    0x71, 0x75, 0x69, 0x75, 0x00, 0xa3, 0x2c, 0xba, 0x33, 0x00, 0x7c, 0x54, 0xdb,
                    0xd3, 0xb3, 0x50, 0x0f, 0xff, 0x80, 0x2a, 0x18, 0x01, 0x4f, 0x67, 0xa1, 0x39,
                    0x06, 0xcf, 0x95, 0xfc, 0x2b, 0x5f, 0xf7, 0xe2, 0x34, 0x81, 0x62, 0x72, 0x79,
                    0xd5, 0x17, 0x18, 0x91, 0x7f, 0x56, 0x01, 0xde, 0xf6, 0x20, 0x61, 0x7c, 0xd1,
                    0x7c, 0x44, 0xec, 0xce, 0xeb, 0x72, 0xe6, 0x63, 0x81, 0xb2,
                ],
                SocketAddr::new(IpAddr::V4(ip4), 8888),
            ),
            // unexpected token type 0x02
            (
                [
                    0x71, 0x75, 0x69, 0x63, 0x02, 0xa3, 0x2c, 0xba, 0x33, 0x00, 0x7c, 0x54, 0xdb,
                    0xd3, 0xb3, 0x50, 0x0f, 0xff, 0x80, 0x2a, 0x18, 0x01, 0x4f, 0x67, 0xa1, 0x39,
                    0x06, 0xcf, 0x95, 0xfc, 0x2b, 0x5f, 0xf7, 0xe2, 0x34, 0x81, 0x62, 0x72, 0x79,
                    0xd5, 0x17, 0x18, 0x91, 0x7f, 0x56, 0x01, 0xde, 0xf6, 0x20, 0x61, 0x7c, 0xd1,
                    0x7c, 0x44, 0xec, 0xce, 0xeb, 0x72, 0xe6, 0x63, 0x81, 0xb2,
                ],
                SocketAddr::new(IpAddr::V4(ip4), 8888),
            ),
            // unmatchd address
            (
                [
                    0x71, 0x75, 0x69, 0x63, 0x02, 0xa3, 0x2c, 0xba, 0x33, 0x00, 0x7c, 0x54, 0xdb,
                    0xd3, 0xb3, 0x50, 0x0f, 0xff, 0x80, 0x2a, 0x18, 0x01, 0x4f, 0x67, 0xa1, 0x39,
                    0x06, 0xcf, 0x95, 0xfc, 0x2b, 0x5f, 0xf7, 0xe2, 0x34, 0x81, 0x62, 0x72, 0x79,
                    0xd5, 0x17, 0x18, 0x91, 0x7f, 0x56, 0x01, 0xde, 0xf6, 0x20, 0x61, 0x7c, 0xd1,
                    0x7c, 0x44, 0xec, 0xce, 0xeb, 0x72, 0xe6, 0x63, 0x81, 0xb2,
                ],
                SocketAddr::new(IpAddr::V4(ip4), 8889),
            ),
        ] {
            assert!(
                AddressToken::decode(&key, &mut buf, &ip, &ConnectionId::random(), lifetime)
                    .is_err()
            );
        }

        Ok(())
    }

    #[test]
    fn reset_token() -> Result<()> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[]);
        let c1 = ConnectionId::random();
        let c2 = ConnectionId::random();
        assert_eq!(
            ResetToken::generate(&key, &c1),
            ResetToken::generate(&key, &c1)
        );
        assert_ne!(
            ResetToken::generate(&key, &c1),
            ResetToken::generate(&key, &c2)
        );

        let buf = [1; crate::RESET_TOKEN_LEN - 1];
        assert_eq!(ResetToken::new(&buf), Err(Error::BufferTooShort));
        assert_eq!(ResetToken::from_bytes(&buf), Err(Error::BufferTooShort));

        let token = ResetToken::generate(&key, &c1);
        assert_eq!(ResetToken::from_u128(token.to_u128()), token);
        assert_eq!(token.to_u128().to_be_bytes(), token.0);

        Ok(())
    }
}
