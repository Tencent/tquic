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

//! HTTP/3 header compression (QPACK).

use log::trace;

use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::h3::qpack::prefix_int::*;
use crate::h3::qpack::static_table::*;
use crate::h3::Header;
use crate::h3::Http3Error;
use crate::h3::NameValue;
use crate::h3::Result;

/// An indexed field line representation starts with the '1' 1-bit pattern,
/// followed by the 'T' bit, indicating whether the reference is into the
/// static or dynamic table.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 1 | T |      Index (6+)       |
/// +---+---+-----------------------+
const INDEXED: u8 = 0b1000_0000;

/// An indexed field line with post-Base index representation starts with
/// the '0001' 4-bit pattern.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 0 | 0 | 1 |  Index (4+)   |
/// +---+---+---+---+---------------+
const INDEXED_WITH_POST_BASE: u8 = 0b0001_0000;

/// A literal field line with name reference representation starts with
/// the '01' 2-bit pattern.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 1 | N | T |Name Index (4+)|
/// +---+---+---+---+---------------+
/// | H |     Value Length (7+)     |
/// +---+---------------------------+
/// |  Value String (Length bytes)  |
/// +-------------------------------+
const LITERAL_WITH_NAME_REF: u8 = 0b0100_0000;

/// A literal field line with post-Base name reference representation
/// starts with the '0000' 4-bit pattern.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
/// +---+---+---+---+---+-----------+
/// | H |     Value Length (7+)     |
/// +---+---------------------------+
/// |  Value String (Length bytes)  |
/// +-------------------------------+
const LITERAL_WITH_POST_BASE: u8 = 0b0000_0000;

/// The literal field line with literal name representation starts with
/// the '001' 3-bit pattern.
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// | 0 | 0 | 1 | N | H |NameLen(3+)|
/// +---+---+---+---+---+-----------+
/// |  Name String (Length bytes)   |
/// +---+---------------------------+
/// | H |     Value Length (7+)     |
/// +---+---------------------------+
/// |  Value String (Length bytes)  |
/// +-------------------------------+
const LITERAL: u8 = 0b0010_0000;

/// Each representation corresponds to a single field line. It reference the
/// static table or the dynamic table in a particular state, but do not modify
/// that state.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Representation {
    /// An indexed field line representation identifies an entry in the static
    /// table or an entry in the dynamic table with an absolute index less than
    /// the value of the Base
    Indexed,

    /// An indexed field line with post-Base index representation identifies an
    /// entry in the dynamic table with an absolute index greater than or equal
    /// to the value of the Base.
    IndexedWithPostBase,

    /// A literal field line with name reference representation encodes a field
    /// line where the field name matches the field name of an entry in the
    /// static table or the field name of an entry in the dynamic table with an
    /// absolute index less than the value of the Base.
    LiteralWithNameRef,

    /// A literal field line with post-Base name reference representation encodes
    /// a field line where the field name matches the field name of a dynamic
    /// table entry with an absolute index greater than or equal to the value of
    /// the Base.
    LiteralWithPostBase,

    /// The literal field line with literal name representation encodes a field
    /// name and a field value as string literals.
    Literal,
}

impl Representation {
    pub fn from(b: u8) -> Representation {
        if b & INDEXED == INDEXED {
            return Representation::Indexed;
        }
        if b & LITERAL_WITH_NAME_REF == LITERAL_WITH_NAME_REF {
            return Representation::LiteralWithNameRef;
        }
        if b & LITERAL == LITERAL {
            return Representation::Literal;
        }
        if b & INDEXED_WITH_POST_BASE == INDEXED_WITH_POST_BASE {
            return Representation::IndexedWithPostBase;
        }
        Representation::LiteralWithPostBase
    }
}

/// A QPACK encoder.
#[derive(Default)]
pub struct QpackEncoder {}

impl QpackEncoder {
    pub fn new() -> QpackEncoder {
        QpackEncoder::default()
    }

    /// Encode a list of headers into a QPACK field section.
    pub fn encode<T: NameValue>(&mut self, headers: &[T], out: &mut [u8]) -> Result<usize> {
        // Required Insert Count.
        let mut off = encode_int(0, 0, 8, out)?;

        // Base.
        off += encode_int(0, 0, 7, &mut out[off..])?;

        for hdr in headers {
            match encode_static(hdr) {
                // Encode as statically indexed.
                Some((idx, true)) => {
                    const STATIC: u8 = 0x40;
                    off += encode_int(idx, INDEXED | STATIC, 6, &mut out[off..])?;
                    trace!("QpackEncoder Indexed index={} static=true", idx);
                }

                // Encode value as literal with static name reference.
                Some((idx, false)) => {
                    const STATIC: u8 = 0x10;
                    off += encode_int(idx, LITERAL_WITH_NAME_REF | STATIC, 4, &mut out[off..])?;
                    off += self.encode_str(hdr.value(), 7, &mut out[off..])?;
                    trace!(
                        "QpackDecoder Literal with name refer name_idx={} static=true",
                        idx
                    );
                }

                // Encode as fully literal.
                None => {
                    let len = huffman::encode_output_length(hdr.name(), true);
                    if len < hdr.name().len() {
                        off += encode_int(len as u64, LITERAL | 0x08, 3, &mut out[off..])?;
                        off += huffman::encode(hdr.name(), &mut out[off..], true)?;
                    } else {
                        off += encode_int(hdr.name().len() as u64, LITERAL, 3, &mut out[off..])?;
                        let mut buf = &mut out[off..];
                        off += buf.write(&hdr.name().to_ascii_lowercase())?;
                    }
                    off += self.encode_str(hdr.value(), 7, &mut out[off..])?;
                    trace!(
                        "QpackDecoder Literal name={:?} value={:?}",
                        hdr.name(),
                        hdr.value()
                    );
                }
            };
        }

        Ok(off)
    }

    /// Encode a string in huffman encoding or literal.
    fn encode_str(&mut self, v: &[u8], prefix: usize, buf: &mut [u8]) -> Result<usize> {
        let len = huffman::encode_output_length(v, false);
        if len < v.len() {
            let mut off = encode_int(len as u64, 0x80, prefix, buf)?;
            off += huffman::encode(v, &mut buf[off..], false)?;
            Ok(off)
        } else {
            let mut off = encode_int(v.len() as u64, 0, prefix, buf)?;
            let mut buf = &mut buf[off..];
            off += buf.write(v)?;
            Ok(off)
        }
    }
}

/// A QPACK decoder.
#[derive(Default)]
pub struct QpackDecoder {}

impl QpackDecoder {
    pub fn new() -> QpackDecoder {
        QpackDecoder::default()
    }

    /// Decode a QPACK header block into a list of headers.
    pub fn decode(&mut self, mut buf: &[u8], max_size: u64) -> Result<(Vec<Header>, usize)> {
        let buf_len = buf.len();
        let mut out = Vec::new();
        let mut left = max_size;

        let (req_insert_count, off) = decode_int(buf, 8)?;
        buf = &buf[off..];
        let (base, off) = decode_int(buf, 7)?;
        buf = &buf[off..];
        trace!(
            "QpackDecoder Header count={} base={}",
            req_insert_count,
            base
        );

        while !buf.is_empty() {
            let first = buf[0];
            match Representation::from(first) {
                Representation::Indexed => {
                    const STATIC: u8 = 0x40;
                    let static_idx = first & STATIC == STATIC;
                    let (index, off) = decode_int(buf, 6)?;
                    buf = &buf[off..];

                    trace!("QpackDecoder Indexed index={} static={}", index, static_idx);
                    if !static_idx {
                        // TODO: implement dynamic table
                        return Err(Http3Error::QpackDecompressionFailed);
                    }

                    let (name, value) = decode_static(index)?;
                    left = left
                        .checked_sub((name.len() + value.len() + 32) as u64)
                        .ok_or(Http3Error::QpackDecompressionFailed)?;
                    out.push(Header(name.to_vec(), value.to_vec()));
                }

                Representation::IndexedWithPostBase => {
                    let (index, _) = decode_int(buf, 4)?;
                    trace!("QpackDecoder Indexed With Post Base index={}", index);
                    // TODO: implement dynamic table
                    return Err(Http3Error::QpackDecompressionFailed);
                }

                Representation::LiteralWithNameRef => {
                    const STATIC: u8 = 0x10;
                    let static_idx = first & STATIC == STATIC;
                    let (name_idx, off) = decode_int(buf, 4)?;
                    buf = &buf[off..];
                    let (value, off) = self.decode_str(buf)?;
                    buf = &buf[off..];
                    trace!(
                        "QpackDecoder Literal With Name refer name_idx={} static={} value={:?}",
                        name_idx,
                        static_idx,
                        value
                    );

                    if !static_idx {
                        // TODO: implement dynamic table
                        return Err(Http3Error::QpackDecompressionFailed);
                    }

                    let (name, _) = decode_static(name_idx)?;
                    left = left
                        .checked_sub((name.len() + value.len() + 32) as u64)
                        .ok_or(Http3Error::QpackDecompressionFailed)?;
                    out.push(Header(name.to_vec(), value));
                }

                Representation::LiteralWithPostBase => {
                    trace!("QpackDecoder Literal With Post Base");
                    // TODO: implement dynamic table
                    return Err(Http3Error::QpackDecompressionFailed);
                }

                Representation::Literal => {
                    let name_huff = buf[0] & 0x08 == 0x08;
                    let (name_len, off) = decode_int(buf, 3)?;
                    buf = &buf[off..];

                    let name = buf.read(name_len as usize)?;
                    let name = if name_huff {
                        huffman::decode(&name)?
                    } else {
                        name.to_vec()
                    };

                    let name = name.to_vec();
                    let (value, off) = self.decode_str(buf)?;
                    buf = &buf[off..];
                    trace!("QpackDecoder Literal name={:?} value={:?}", name, value);

                    left = left
                        .checked_sub((name.len() + value.len() + 32) as u64)
                        .ok_or(Http3Error::QpackDecompressionFailed)?;
                    out.push(Header(name, value));
                }
            }
        }

        Ok((out, buf_len - buf.len()))
    }

    /// Decode a string in huffman encoding or literal.
    fn decode_str(&self, mut buf: &[u8]) -> Result<(Vec<u8>, usize)> {
        if buf.is_empty() {
            return Err(Http3Error::QpackDecompressionFailed);
        }

        let buf_len = buf.len();
        let huff = buf[0] & 0x80 == 0x80;
        let (str_len, off) = decode_int(buf, 7)?;
        buf = &buf[off..];

        let str_val = buf.read(str_len as usize)?;
        let val = if huff {
            huffman::decode(&str_val)?
        } else {
            str_val.to_vec()
        };

        Ok((val, buf_len - buf.len()))
    }

    /// Process control instructions from the encoder.
    pub fn process(&mut self, _buf: &mut [u8]) -> Result<()> {
        // TODO: support instructions
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3;

    #[test]
    fn static_table() {
        let mut encoded = [0u8; 158];

        for (k, v, index) in static_table::STATIC_ENCODE_TABLE {
            assert_eq!(static_table::STATIC_DECODE_TABLE[index as usize].0, k);
            assert_eq!(static_table::STATIC_DECODE_TABLE[index as usize].1, v);
        }

        let headers = vec![
            h3::Header::new(b":authority", b""),
            h3::Header::new(b":path", b"/"),
            h3::Header::new(b"age", b"0"),
            h3::Header::new(b"content-disposition", b""),
            h3::Header::new(b"content-length", b"0"),
            h3::Header::new(b"cookie", b""),
            h3::Header::new(b"date", b""),
            h3::Header::new(b"etag", b""),
            h3::Header::new(b"if-modified-since", b""),
            h3::Header::new(b"if-none-match", b""),
            h3::Header::new(b"last-modified", b""),
            h3::Header::new(b"link", b""),
            h3::Header::new(b"location", b""),
            h3::Header::new(b"referer", b""),
            h3::Header::new(b"set-cookie", b""),
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":method", b"DELETE"),
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b":method", b"HEAD"),
            h3::Header::new(b":method", b"OPTIONS"),
            h3::Header::new(b":method", b"POST"),
            h3::Header::new(b":method", b"PUT"),
            h3::Header::new(b":scheme", b"http"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":status", b"103"),
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b":status", b"304"),
            h3::Header::new(b":status", b"404"),
            h3::Header::new(b":status", b"503"),
            h3::Header::new(b"accept", b"*/*"),
            h3::Header::new(b"accept", b"application/dns-message"),
            h3::Header::new(b"accept-encoding", b"gzip, deflate, br"),
            h3::Header::new(b"accept-ranges", b"bytes"),
            h3::Header::new(b"access-control-allow-headers", b"cache-control"),
            h3::Header::new(b"access-control-allow-headers", b"content-type"),
            h3::Header::new(b"access-control-allow-origin", b"*"),
            h3::Header::new(b"cache-control", b"max-age=0"),
            h3::Header::new(b"cache-control", b"max-age=2592000"),
            h3::Header::new(b"cache-control", b"max-age=604800"),
            h3::Header::new(b"cache-control", b"no-cache"),
            h3::Header::new(b"cache-control", b"no-store"),
            h3::Header::new(b"cache-control", b"public, max-age=31536000"),
            h3::Header::new(b"content-encoding", b"br"),
            h3::Header::new(b"content-encoding", b"gzip"),
            h3::Header::new(b"content-type", b"application/dns-message"),
            h3::Header::new(b"content-type", b"application/javascript"),
            h3::Header::new(b"content-type", b"application/json"),
            h3::Header::new(b"content-type", b"application/x-www-form-urlencoded"),
            h3::Header::new(b"content-type", b"image/gif"),
            h3::Header::new(b"content-type", b"image/jpeg"),
            h3::Header::new(b"content-type", b"image/png"),
            h3::Header::new(b"content-type", b"text/css"),
            h3::Header::new(b"content-type", b"text/html; charset=utf-8"),
            h3::Header::new(b"content-type", b"text/plain"),
            h3::Header::new(b"content-type", b"text/plain;charset=utf-8"),
            h3::Header::new(b"range", b"bytes=0-"),
            h3::Header::new(b"strict-transport-security", b"max-age=31536000"),
            h3::Header::new(
                b"strict-transport-security",
                b"max-age=31536000; includesubdomains",
            ),
            h3::Header::new(
                b"strict-transport-security",
                b"max-age=31536000; includesubdomains; preload",
            ),
            h3::Header::new(b"vary", b"accept-encoding"),
            h3::Header::new(b"vary", b"origin"),
            h3::Header::new(b"x-content-type-options", b"nosniff"),
            h3::Header::new(b"x-xss-protection", b"1; mode=block"),
            h3::Header::new(b":status", b"100"),
            h3::Header::new(b":status", b"204"),
            h3::Header::new(b":status", b"206"),
            h3::Header::new(b":status", b"302"),
            h3::Header::new(b":status", b"400"),
            h3::Header::new(b":status", b"403"),
            h3::Header::new(b":status", b"421"),
            h3::Header::new(b":status", b"425"),
            h3::Header::new(b":status", b"500"),
            h3::Header::new(b"accept-language", b""),
            h3::Header::new(b"access-control-allow-credentials", b"FALSE"),
            h3::Header::new(b"access-control-allow-credentials", b"TRUE"),
            h3::Header::new(b"access-control-allow-headers", b"*"),
            h3::Header::new(b"access-control-allow-methods", b"get"),
            h3::Header::new(b"access-control-allow-methods", b"get, post, options"),
            h3::Header::new(b"access-control-allow-methods", b"options"),
            h3::Header::new(b"access-control-expose-headers", b"content-length"),
            h3::Header::new(b"access-control-request-headers", b"content-type"),
            h3::Header::new(b"access-control-request-method", b"get"),
            h3::Header::new(b"access-control-request-method", b"post"),
            h3::Header::new(b"alt-svc", b"clear"),
            h3::Header::new(b"authorization", b""),
            h3::Header::new(
                b"content-security-policy",
                b"script-src 'none'; object-src 'none'; base-uri 'none'",
            ),
            h3::Header::new(b"early-data", b"1"),
            h3::Header::new(b"expect-ct", b""),
            h3::Header::new(b"forwarded", b""),
            h3::Header::new(b"if-range", b""),
            h3::Header::new(b"origin", b""),
            h3::Header::new(b"purpose", b"prefetch"),
            h3::Header::new(b"server", b""),
            h3::Header::new(b"timing-allow-origin", b"*"),
            h3::Header::new(b"upgrade-insecure-requests", b"1"),
            h3::Header::new(b"user-agent", b""),
            h3::Header::new(b"x-forwarded-for", b""),
            h3::Header::new(b"x-frame-options", b"deny"),
            h3::Header::new(b"x-frame-options", b"sameorigin"),
        ];

        let mut enc = QpackEncoder::new();
        assert_eq!(enc.encode(&headers, &mut encoded), Ok(encoded.len()));

        let mut dec = QpackDecoder::new();
        assert_eq!(
            dec.decode(&mut encoded, u64::MAX),
            Ok((headers, encoded.len()))
        );
    }

    #[test]
    fn qpack_encode_and_decode() {
        let cases = [
            // Indexed
            (
                vec![h3::Header::new(b":status", b"200")],
                vec![0x00, 0x00, 0xd9],
            ),
            // Indexed name with literal value
            (
                vec![h3::Header::new(b":path", b"/index.html")],
                vec![
                    0x00, 0x00, 0x51, 0x88, 0x60, 0xd5, 0x48, 0x5f, 0x2b, 0xce, 0x9a, 0x68,
                ],
            ),
            // Literal name and value
            (
                vec![h3::Header::new(b"x-proto", b"QUIC")],
                vec![
                    0x00, 0x00, 0x2d, 0xf2, 0xb5, 0x76, 0x1d, 0x27, 0x04, 0x51, 0x55, 0x49, 0x43,
                ],
            ),
        ];

        let mut buf = [0u8; 64];
        let mut encoder = QpackEncoder::new();
        let mut decoder = QpackDecoder::new();

        for (headers, encoded) in cases {
            assert_eq!(encoder.encode(&headers, &mut buf), Ok(encoded.len()));
            assert_eq!(&encoded[..], &buf[..encoded.len()]);

            assert_eq!(
                decoder.decode(&encoded, 1024 * 16),
                Ok((headers, encoded.len()))
            );
        }
    }

    #[test]
    fn qpack_encode_lower_case() {
        let headers_original = vec![
            crate::h3::Header::new(b":StatuS", b"200"),
            crate::h3::Header::new(b":PatH", b"/Index.html"),
            crate::h3::Header::new(b"X-Proto", b"QUIC"),
        ];
        let headers_expected = vec![
            crate::h3::Header::new(b":status", b"200"),
            crate::h3::Header::new(b":path", b"/Index.html"),
            crate::h3::Header::new(b"x-proto", b"QUIC"),
        ];

        let mut buf = [0u8; 64];
        let mut enc = QpackEncoder::new();
        let mut dec = QpackDecoder::new();

        let len = enc.encode(&headers_original, &mut buf).unwrap();
        let headers_out = dec.decode(&buf[..len], 1024 * 16).unwrap().0;
        assert_eq!(headers_expected, headers_out);
    }

    #[test]
    fn qpack_ascii_range() {
        let headers = vec![
            crate::h3::Header::new(b"location", b"^	$"),
            crate::h3::Header::new(b"~!@#$%^&*()_+", b"quic"),
            crate::h3::Header::new(b" ", b"hello"),
        ];

        let mut buf = [0u8; 64];
        let mut enc = QpackEncoder::new();
        let mut dec = QpackDecoder::new();

        let len = enc.encode(&headers, &mut buf).unwrap();
        let headers2 = dec.decode(&buf[..len], 1024 * 16).unwrap().0;
        assert_eq!(headers, headers2);
    }

    #[test]
    fn qpack_decode_empty_buffer() {
        let buf = vec![];
        let mut dec = QpackDecoder::new();
        assert!(dec.decode(&buf, 1024 * 16).is_err());
    }
}

mod huffman;
mod prefix_int;
mod static_table;
