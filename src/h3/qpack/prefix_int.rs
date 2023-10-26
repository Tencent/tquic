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

use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::h3::Http3Error;
use crate::h3::Result;

/// Encode an integer using QPACK integer representation.                                           
///
/// An integer is represented in two parts: a prefix that fills the current
/// octet and an optional list of octets that are used if the integer value
/// does not fit within the prefix. The number of bits of the prefix (called N)
/// is a parameter of the integer representation.
/// See RFC 7541 Section 5.1
///
/// The `i` is the integer to be encoded.
/// The `n` is the number of bits of the prefix.
/// The most significant bits of the `first` carrys the placeholder bits. Its
/// number of bits is `8-n`.
pub fn encode_int(mut i: u64, first: u8, n: usize, mut buf: &mut [u8]) -> Result<usize> {
    let buf_len = buf.len();

    // If the integer value is small enough, i.e., strictly less than 2^N-1,
    // it is encoded within the N-bit prefix.
    let mask = 2u64.pow(n as u32) - 1;
    if i < mask {
        buf.write_u8(first | i as u8)?;
        return Ok(buf_len - buf.len());
    }

    // Otherwise, all the bits of the prefix are set to 1, and the value,
    // decreased by 2^N-1, is encoded using a list of one or more octets.
    buf.write_u8(first | mask as u8)?;
    i -= mask;
    while i >= 128 {
        // The most significant bit of each octet is used as a continuation
        // flag: its value is set to 1 except for the last octet in the list.
        buf.write_u8((i % 128 + 128) as u8)?;
        i >>= 7;
    }
    buf.write_u8(i as u8)?;

    Ok(buf_len - buf.len())
}

/// Decode an integer using Qpack integer representation.                                           
///
/// The `n` is the number of bits of the prefix.
pub fn decode_int(mut buf: &[u8], n: usize) -> Result<(u64, usize)> {
    let buf_len = buf.len();

    let mask = 2u64.pow(n as u32) - 1;
    let mut val = u64::from(buf.read_u8()?);
    val &= mask;
    if val < mask {
        return Ok((val, 1));
    }

    let mut shift = 0;
    while !buf.is_empty() {
        let byte = buf.read_u8()?;
        let inc = u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(Http3Error::QpackDecompressionFailed)?;
        val = val
            .checked_add(inc)
            .ok_or(Http3Error::QpackDecompressionFailed)?;
        shift += 7;

        if byte & 0x80 == 0 {
            return Ok((val, buf_len - buf.len()));
        }
    }

    Err(Http3Error::QpackDecompressionFailed)
}

#[cfg(test)]
mod test {
    use super::*;

    /// Unit test for RFC 7541 Appendix C.1
    #[test]
    fn prefix_int_normal() {
        let cases = [
            (10, 5, vec![0b01010]),
            (1337, 5, vec![0b11111, 0b10011010, 0b00001010]),
            (42, 8, vec![0b101010]),
        ];

        for c in cases {
            let (value, prefix, mut buf) = c;
            let buf_len = buf.len();
            assert_eq!(decode_int(&mut buf, prefix), Ok((value, buf_len)));

            let mut out = [0; 4];
            let enc_len = encode_int(value, 0, prefix, &mut out).unwrap();
            assert_eq!(&buf, &out[..enc_len]);
        }
    }

    #[test]
    fn decode_int_without_end_flag() {
        let mut buf = vec![0b11111, 0b10011010, 0b10001010];
        assert!(decode_int(&mut buf, 5).is_err());
    }

    #[test]
    fn decode_int_empty_buf() {
        let mut buf = vec![];
        assert!(decode_int(&mut buf, 5).is_err());
    }

    #[test]
    fn decode_int_too_big() {
        let mut buf = vec![
            0b11111, 0b10011010, 0b10001010, 0b10001010, 0b10001010, 0b10001010, 0b10001010,
            0b10001010, 0b10001010,
        ];
        assert!(decode_int(&mut buf, 5).is_err());
    }
}
