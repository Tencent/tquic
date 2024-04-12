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

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use bytes::Buf;
use bytes::BufMut;

use crate::error::Error;
use crate::Result;

/// The maximum value for QUIC variable-length integer encoding
/// See RFC 9000 Section 16
pub const VINT_MAX: u64 = 4_611_686_018_427_387_903;

/// Encoder for QUIC wire data
pub trait Encoder {
    /// Write an unsigned 8 bit integer to self.
    fn write_u8(&mut self, n: u8) -> Result<usize>;

    /// Write an unsigned 16 bit integer to self in big-endian byte order.
    fn write_u16(&mut self, n: u16) -> Result<usize>;

    /// Write an unsigned 24 bit integer to self in big-endian byte order.
    fn write_u24(&mut self, n: u32) -> Result<usize>;

    /// Write an unsigned 32 bit integer to self in big-endian byte order.
    fn write_u32(&mut self, n: u32) -> Result<usize>;

    /// Write an unsigned 64 bit integer to self in the big-endian byte order.
    fn write_u64(&mut self, n: u64) -> Result<usize>;

    /// Write an unsigned 64 bit integer to self in QUIC variable length integer encoding.
    fn write_varint(&mut self, n: u64) -> Result<usize>;

    /// Write an unsigned 64 bit integer to self in QUIC variable length integer encoding.
    /// The encoded size is required to be `len`.
    fn write_varint_with_len(&mut self, n: u64, len: usize) -> Result<usize>;

    /// Write a slice to self.
    fn write(&mut self, src: &[u8]) -> Result<usize>;

    /// Write an IPv4Addr to self in the big-endian byte order.
    fn write_ipv4_addr(&mut self, addr: &Ipv4Addr) -> Result<usize>;

    /// Write an IPv6Addr to self in the big-endian byte order.
    fn write_ipv6_addr(&mut self, addr: &Ipv6Addr) -> Result<usize>;
}

/// Decoder for QUIC wire data
pub trait Decoder {
    /// Read an unsigned 8 bit integer from self.
    fn read_u8(&mut self) -> Result<u8>;

    /// Read an unsigned 16 bit integer from self in big-endian byte order.
    fn read_u16(&mut self) -> Result<u16>;

    /// Read an unsigned 24 bit integer from self in big-endian byte order.
    fn read_u24(&mut self) -> Result<u32>;

    /// Read an unsigned 32 bit integer from self in big-endian byte order.
    fn read_u32(&mut self) -> Result<u32>;

    /// Read an unsigned 64 bit integer from self in big-endian byte order.
    fn read_u64(&mut self) -> Result<u64>;

    /// Read an unsigned 64 bit integer from self in QUIC variable length integer encoding.
    fn read_varint(&mut self) -> Result<u64>;

    /// Read `len` bytes inside self.
    fn read(&mut self, len: usize) -> Result<Vec<u8>>;

    /// Read an varint N and then read N bytes inside self.
    fn read_with_varint_length(&mut self) -> Result<Vec<u8>>;

    /// Read an u8 integer N and then read N bytes inside self.
    fn read_with_u8_length(&mut self) -> Result<Vec<u8>>;

    /// Skip len bytes inside self.
    fn skip(&mut self, len: usize) -> Result<()>;

    /// Read an IPv4Addr from self in big-endian byte order.
    fn read_ipv4_addr(&mut self) -> Result<Ipv4Addr>;

    /// Read an IPv6Addr from self in big-endian byte order.
    fn read_ipv6_addr(&mut self) -> Result<Ipv6Addr>;
}

impl Encoder for &mut [u8] {
    fn write_u8(&mut self, n: u8) -> Result<usize> {
        if self.remaining_mut() < 1 {
            return Err(Error::BufferTooShort);
        }
        self.put_u8(n);
        Ok(1)
    }

    fn write_u16(&mut self, n: u16) -> Result<usize> {
        if self.remaining_mut() < 2 {
            return Err(Error::BufferTooShort);
        }
        self.put_u16(n);
        Ok(2)
    }

    fn write_u24(&mut self, n: u32) -> Result<usize> {
        if self.remaining_mut() < 3 {
            return Err(Error::BufferTooShort);
        }
        self.put_u8(((n & 0x00FF_0000) >> 16) as u8);
        self.put_u16((n & 0xFFFF) as u16);
        Ok(3)
    }

    fn write_u32(&mut self, n: u32) -> Result<usize> {
        if self.remaining_mut() < 4 {
            return Err(Error::BufferTooShort);
        }
        self.put_u32(n);
        Ok(4)
    }

    fn write_u64(&mut self, n: u64) -> Result<usize> {
        if self.remaining_mut() < 8 {
            return Err(Error::BufferTooShort);
        }
        self.put_u64(n);
        Ok(8)
    }

    fn write_varint(&mut self, n: u64) -> Result<usize> {
        let len = encode_varint_len(n);
        self.write_varint_with_len(n, len)
    }

    fn write_varint_with_len(&mut self, n: u64, len: usize) -> Result<usize> {
        // Note: Values do not need to be encoded on the minimum number of
        // bytes necessary, with the sole exception of the Frame Type field.
        if self.remaining_mut() < len {
            return Err(Error::BufferTooShort);
        }

        match len {
            1 => self.put_u8(n as u8),
            2 => {
                self.put_u16(n as u16 | 0x4000);
            }
            4 => {
                self.put_u32(n as u32 | 0x8000_0000);
            }
            8 => {
                self.put_u64(n | 0xc000_0000_0000_0000);
            }
            _ => unreachable!(),
        };

        Ok(len)
    }

    fn write(&mut self, src: &[u8]) -> Result<usize> {
        if self.remaining_mut() < src.len() {
            return Err(Error::BufferTooShort);
        }
        self.put_slice(src);
        Ok(src.len())
    }

    fn write_ipv4_addr(&mut self, addr: &Ipv4Addr) -> Result<usize> {
        if self.remaining_mut() < 4 {
            return Err(Error::BufferTooShort);
        }
        self.put_slice(&addr.octets());
        Ok(4)
    }

    fn write_ipv6_addr(&mut self, addr: &Ipv6Addr) -> Result<usize> {
        if self.remaining_mut() < 16 {
            return Err(Error::BufferTooShort);
        }
        self.put_slice(&addr.octets());
        Ok(16)
    }
}

impl Decoder for &[u8] {
    fn read_u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(Error::BufferTooShort);
        }
        Ok(self.get_u8())
    }

    fn read_u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            return Err(Error::BufferTooShort);
        }
        Ok(self.get_u16())
    }

    fn read_u24(&mut self) -> Result<u32> {
        if self.remaining() < 3 {
            return Err(Error::BufferTooShort);
        }
        let mut n = self.get_u16() as u32;
        n <<= 8;
        n += self.get_u8() as u32;
        Ok(n)
    }

    fn read_u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(Error::BufferTooShort);
        }
        Ok(self.get_u32())
    }

    fn read_u64(&mut self) -> Result<u64> {
        if self.remaining() < 8 {
            return Err(Error::BufferTooShort);
        }
        Ok(self.get_u64())
    }

    fn read_varint(&mut self) -> Result<u64> {
        if self.remaining() < 1 {
            return Err(Error::BufferTooShort);
        }
        let first = self[0];
        let len = decode_varint_len(first);
        if self.remaining() < len {
            return Err(Error::BufferTooShort);
        }

        let v = match len {
            1 => u64::from(self.read_u8()?),
            2 => u64::from(self.read_u16()? & 0x3fff),
            4 => u64::from(self.read_u32()? & 0x3fffffff),
            8 => self.read_u64()? & 0x3fffffffffffffff,
            _ => unreachable!(),
        };

        Ok(v)
    }

    fn read(&mut self, len: usize) -> Result<Vec<u8>> {
        if self.remaining() < len {
            return Err(Error::BufferTooShort);
        }

        let mut vec = vec![0; len];
        self.copy_to_slice(&mut vec[..]);

        Ok(vec)
    }

    fn read_with_varint_length(&mut self) -> Result<Vec<u8>> {
        let len = self.read_varint()?;
        self.read(len as usize)
    }

    fn read_with_u8_length(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u8()?;
        self.read(len as usize)
    }

    fn skip(&mut self, len: usize) -> Result<()> {
        if self.remaining() < len {
            return Err(Error::BufferTooShort);
        }
        *self = &self[len..];
        Ok(())
    }

    fn read_ipv4_addr(&mut self) -> Result<Ipv4Addr> {
        if self.remaining() < 4 {
            return Err(Error::BufferTooShort);
        }
        let mut addr = [0; 4];
        self.copy_to_slice(&mut addr);
        Ok(addr.into())
    }

    fn read_ipv6_addr(&mut self) -> Result<Ipv6Addr> {
        if self.remaining() < 16 {
            return Err(Error::BufferTooShort);
        }
        let mut addr = [0; 16];
        self.copy_to_slice(&mut addr);
        Ok(addr.into())
    }
}

/// Return the length of a varint.
///
/// The QUIC variable-length integer encoding reserves the two most significant bits of the first
/// byte to encode the base-2 logarithm of the integer encoding length in bytes. The integer value
/// is encoded on the remaining bits, in network byte order.
pub fn decode_varint_len(first: u8) -> usize {
    match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    }
}

/// Return the encoding length of an int using variable-length integer encoding.
///
/// See RFC 9000 Section 16 Table 4 Summary of Integer Encodings.
pub fn encode_varint_len(n: u64) -> usize {
    if n <= 63 {
        1
    } else if n <= 16383 {
        2
    } else if n <= 1_073_741_823 {
        4
    } else if n <= 4_611_686_018_427_387_903 {
        8
    } else {
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;
    use std::net::SocketAddrV4;
    use std::net::SocketAddrV6;

    #[test]
    fn codec_uint() -> Result<()> {
        let mut buf = [0_u8; 32];
        let mut len = 0;

        let mut bw = &mut buf[..];
        len += bw.write_u8(0x01)?;
        len += bw.write_u16(0x0102)?;
        len += bw.write_u24(0x010203)?;
        len += bw.write_u32(0x01020304)?;
        len += bw.write_u64(0x0102030405060708)?;
        let exp = [
            0x01_u8, // u8
            0x01, 0x02, // u16
            0x01, 0x02, 0x03, // u24
            0x01, 0x02, 0x03, 0x04, // u32
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // u64
        ];
        assert_eq!(len, exp.len());
        assert_eq!(buf[..len], exp);

        let mut br = &buf[..];
        assert_eq!(br.read_u8()?, 0x01);
        assert_eq!(br.read_u16()?, 0x0102);
        assert_eq!(br.read_u24()?, 0x010203);
        assert_eq!(br.read_u32()?, 0x01020304);
        assert_eq!(br.read_u64()?, 0x0102030405060708);
        Ok(())
    }

    #[test]
    fn codec_varint() -> Result<()> {
        let mut buf = [0_u8; 8];
        let data = [
            (
                151_288_809_941_952_652,
                vec![0xc2_u8, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
            (494_878_333, vec![0x9d_u8, 0x7f, 0x3e, 0x7d]),
            (15_293, vec![0x7b_u8, 0xbd]),
            (37, vec![0x25_u8]),
        ];

        for (n, b) in data.iter() {
            let mut br = &b[..];
            assert_eq!(br.read_varint()?, *n);

            let mut bw = &mut buf[..];
            let len = bw.write_varint(*n)?;
            assert_eq!(buf[..len], b[..]);
        }
        Ok(())
    }

    #[test]
    fn codec_bytes() -> Result<()> {
        let mut buf = [0_u8; 8];
        let data = [0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06];

        let mut bw = &mut buf[..];
        let len = bw.write(&data[..])?;

        let mut br = &buf[..];
        assert_eq!(br.read(len)?[..], data[..]);
        Ok(())
    }

    #[test]
    fn codec_ip_addr() -> Result<()> {
        let mut buf = [0; 20];
        let ipv4_addr = Ipv4Addr::new(192, 168, 1, 1);
        let ipv6_addr = Ipv6Addr::new(0x26, 0, 0x1c9, 0, 0, 0xafc8, 0x10, 0x1);

        let mut bw = &mut buf[..];
        let len = bw.write_ipv4_addr(&ipv4_addr)?;
        assert_eq!(len, 4);
        let len = bw.write_ipv6_addr(&ipv6_addr)?;
        assert_eq!(len, 16);

        let mut br = &buf[..];
        assert_eq!(br.read_ipv4_addr()?, ipv4_addr);
        assert_eq!(br.read_ipv6_addr()?, ipv6_addr);
        Ok(())
    }

    #[test]
    fn buffer_too_short() -> Result<()> {
        let mut buf = [255; 16];
        let mut br = &buf[0..0];
        assert!(br.read_u8().is_err());
        assert!(br.read_u16().is_err());
        assert!(br.read_u24().is_err());
        assert!(br.read_u32().is_err());
        assert!(br.read_u64().is_err());
        assert!(br.read_varint().is_err());
        assert!(br.read(1).is_err());
        assert!(br.skip(1).is_err());
        assert!(br.read_ipv4_addr().is_err());
        assert!(br.read_ipv6_addr().is_err());
        let mut br = &buf[0..1];
        assert!(br.read_varint().is_err());

        let mut bw = &mut buf[0..0];
        assert!(bw.write_u8(1).is_err());
        assert!(bw.write_u16(1).is_err());
        assert!(bw.write_u24(1).is_err());
        assert!(bw.write_u32(1).is_err());
        assert!(bw.write_u64(1).is_err());
        assert!(bw.write_varint(1).is_err());
        let data = [1; 10];
        assert!(bw.write(&data[..]).is_err());
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        assert!(bw.write_ipv4_addr(&addr).is_err());
        let addr = Ipv6Addr::new(0x26, 0, 0x1c9, 0, 0, 0xafc8, 0x10, 0x1);
        assert!(bw.write_ipv6_addr(&addr).is_err());

        Ok(())
    }
}
