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

use std::ops::Range;

use crate::h3::Http3Error;
use crate::h3::NameValue;
use crate::h3::Result;

/// Return the matched index in the static table.
pub fn encode_static<T: NameValue>(h: &T) -> Option<(u64, bool)> {
    let mut name_match = None;

    if let Some(name_range) = find_static_table_range(h.name()) {
        for i in name_range {
            if STATIC_ENCODE_TABLE[i].1.is_empty() {
                // Match a Field with name and empty value.
                return Some((STATIC_ENCODE_TABLE[i].2, false));
            }

            if h.value().len() == STATIC_ENCODE_TABLE[i].1.len()
                && h.value() == STATIC_ENCODE_TABLE[i].1
            {
                // Match a Field with name and value.
                return Some((STATIC_ENCODE_TABLE[i].2, true));
            }

            if name_match.is_none() {
                // Field name matched but field value not matched.
                name_match = Some((STATIC_ENCODE_TABLE[i].2, false));
            }
        }
    }

    name_match
}

/// Return the field for the given index.
pub fn decode_static(idx: u64) -> Result<(&'static [u8], &'static [u8])> {
    if idx >= STATIC_DECODE_TABLE.len() as u64 {
        return Err(Http3Error::QpackDecompressionFailed);
    }

    Ok(STATIC_DECODE_TABLE[idx as usize])
}

fn find_static_table_range(name: &[u8]) -> Option<Range<usize>> {
    match name.len() {
        3 => {
            if name.eq_ignore_ascii_case(b"age") {
                return Some(43..44);
            }
            None
        }
        4 => {
            if name.eq_ignore_ascii_case(b"date") {
                return Some(69..70);
            } else if name.eq_ignore_ascii_case(b"etag") {
                return Some(71..72);
            } else if name.eq_ignore_ascii_case(b"link") {
                return Some(78..79);
            } else if name.eq_ignore_ascii_case(b"vary") {
                return Some(92..94);
            }
            None
        }
        5 => {
            if name.eq_ignore_ascii_case(b":path") {
                return Some(8..9);
            } else if name.eq_ignore_ascii_case(b"range") {
                return Some(82..83);
            }
            None
        }
        6 => {
            if name.eq_ignore_ascii_case(b"accept") {
                return Some(25..27);
            } else if name.eq_ignore_ascii_case(b"cookie") {
                return Some(68..69);
            } else if name.eq_ignore_ascii_case(b"origin") {
                return Some(80..81);
            } else if name.eq_ignore_ascii_case(b"server") {
                return Some(84..85);
            }
            None
        }
        7 => {
            if name.eq_ignore_ascii_case(b":method") {
                return Some(1..8);
            } else if name.eq_ignore_ascii_case(b":scheme") {
                return Some(9..11);
            } else if name.eq_ignore_ascii_case(b":status") {
                return Some(11..25);
            } else if name.eq_ignore_ascii_case(b"alt-svc") {
                return Some(44..45);
            } else if name.eq_ignore_ascii_case(b"purpose") {
                return Some(81..82);
            } else if name.eq_ignore_ascii_case(b"referer") {
                return Some(83..84);
            }
            None
        }
        8 => {
            if name.eq_ignore_ascii_case(b"if-range") {
                return Some(76..77);
            } else if name.eq_ignore_ascii_case(b"location") {
                return Some(79..80);
            }
            None
        }
        9 => {
            if name.eq_ignore_ascii_case(b"expect-ct") {
                return Some(72..73);
            } else if name.eq_ignore_ascii_case(b"forwarded") {
                return Some(73..74);
            }
            None
        }
        10 => {
            if name.eq_ignore_ascii_case(b":authority") {
                return Some(0..1);
            } else if name.eq_ignore_ascii_case(b"early-data") {
                return Some(70..71);
            } else if name.eq_ignore_ascii_case(b"set-cookie") {
                return Some(85..86);
            } else if name.eq_ignore_ascii_case(b"user-agent") {
                return Some(91..92);
            }
            None
        }
        12 => {
            if name.eq_ignore_ascii_case(b"content-type") {
                return Some(57..68);
            }
            None
        }
        13 => {
            if name.eq_ignore_ascii_case(b"accept-ranges") {
                return Some(29..30);
            } else if name.eq_ignore_ascii_case(b"authorization") {
                return Some(45..46);
            } else if name.eq_ignore_ascii_case(b"cache-control") {
                return Some(46..52);
            } else if name.eq_ignore_ascii_case(b"if-none-match") {
                return Some(75..76);
            } else if name.eq_ignore_ascii_case(b"last-modified") {
                return Some(77..78);
            }
            None
        }
        14 => {
            if name.eq_ignore_ascii_case(b"content-length") {
                return Some(55..56);
            }
            None
        }
        15 => {
            if name.eq_ignore_ascii_case(b"accept-encoding") {
                return Some(27..28);
            } else if name.eq_ignore_ascii_case(b"accept-language") {
                return Some(28..29);
            } else if name.eq_ignore_ascii_case(b"x-forwarded-for") {
                return Some(95..96);
            } else if name.eq_ignore_ascii_case(b"x-frame-options") {
                return Some(96..98);
            }
            None
        }
        16 => {
            if name.eq_ignore_ascii_case(b"content-encoding") {
                return Some(53..55);
            } else if name.eq_ignore_ascii_case(b"x-xss-protection") {
                return Some(98..99);
            }
            None
        }
        17 => {
            if name.eq_ignore_ascii_case(b"if-modified-since") {
                return Some(74..75);
            }
            None
        }
        19 => {
            if name.eq_ignore_ascii_case(b"content-disposition") {
                return Some(52..53);
            } else if name.eq_ignore_ascii_case(b"timing-allow-origin") {
                return Some(89..90);
            }
            None
        }
        22 => {
            if name.eq_ignore_ascii_case(b"x-content-type-options") {
                return Some(94..95);
            }
            None
        }
        23 => {
            if name.eq_ignore_ascii_case(b"content-security-policy") {
                return Some(56..57);
            }
            None
        }
        25 => {
            if name.eq_ignore_ascii_case(b"strict-transport-security") {
                return Some(86..89);
            } else if name.eq_ignore_ascii_case(b"upgrade-insecure-requests") {
                return Some(90..91);
            }
            None
        }
        27 => {
            if name.eq_ignore_ascii_case(b"access-control-allow-origin") {
                return Some(38..39);
            }
            None
        }
        28 => {
            if name.eq_ignore_ascii_case(b"access-control-allow-headers") {
                return Some(32..35);
            } else if name.eq_ignore_ascii_case(b"access-control-allow-methods") {
                return Some(35..38);
            }
            None
        }
        29 => {
            if name.eq_ignore_ascii_case(b"access-control-expose-headers") {
                return Some(39..40);
            } else if name.eq_ignore_ascii_case(b"access-control-request-method") {
                return Some(41..43);
            }
            None
        }
        30 => {
            if name.eq_ignore_ascii_case(b"access-control-request-headers") {
                return Some(40..41);
            }
            None
        }
        32 => {
            if name.eq_ignore_ascii_case(b"access-control-allow-credentials") {
                return Some(30..32);
            }
            None
        }

        _ => None,
    }
}

/// The static table consists of a predefined list of field lines, each of
/// which has a fixed index over time. All entries in the static table have
/// a name and a value. However, values can be empty. Each entry is
/// identified by a unique index.
///
/// See RFC 9204 Appendix A
pub(crate) const STATIC_ENCODE_TABLE: [(&[u8], &[u8], u64); 99] = [
    (b":authority", b"", 0),
    (b":method", b"CONNECT", 15),
    (b":method", b"DELETE", 16),
    (b":method", b"GET", 17),
    (b":method", b"HEAD", 18),
    (b":method", b"OPTIONS", 19),
    (b":method", b"POST", 20),
    (b":method", b"PUT", 21),
    (b":path", b"/", 1),
    (b":scheme", b"http", 22),
    (b":scheme", b"https", 23),
    (b":status", b"100", 63),
    (b":status", b"103", 24),
    (b":status", b"200", 25),
    (b":status", b"204", 64),
    (b":status", b"206", 65),
    (b":status", b"302", 66),
    (b":status", b"304", 26),
    (b":status", b"400", 67),
    (b":status", b"403", 68),
    (b":status", b"404", 27),
    (b":status", b"421", 69),
    (b":status", b"425", 70),
    (b":status", b"500", 71),
    (b":status", b"503", 28),
    (b"accept", b"*/*", 29),
    (b"accept", b"application/dns-message", 30),
    (b"accept-encoding", b"gzip, deflate, br", 31),
    (b"accept-language", b"", 72),
    (b"accept-ranges", b"bytes", 32),
    (b"access-control-allow-credentials", b"FALSE", 73),
    (b"access-control-allow-credentials", b"TRUE", 74),
    (b"access-control-allow-headers", b"*", 75),
    (b"access-control-allow-headers", b"cache-control", 33),
    (b"access-control-allow-headers", b"content-type", 34),
    (b"access-control-allow-methods", b"get", 76),
    (b"access-control-allow-methods", b"get, post, options", 77),
    (b"access-control-allow-methods", b"options", 78),
    (b"access-control-allow-origin", b"*", 35),
    (b"access-control-expose-headers", b"content-length", 79),
    (b"access-control-request-headers", b"content-type", 80),
    (b"access-control-request-method", b"get", 81),
    (b"access-control-request-method", b"post", 82),
    (b"age", b"0", 2),
    (b"alt-svc", b"clear", 83),
    (b"authorization", b"", 84),
    (b"cache-control", b"max-age=0", 36),
    (b"cache-control", b"max-age=2592000", 37),
    (b"cache-control", b"max-age=604800", 38),
    (b"cache-control", b"no-cache", 39),
    (b"cache-control", b"no-store", 40),
    (b"cache-control", b"public, max-age=31536000", 41),
    (b"content-disposition", b"", 3),
    (b"content-encoding", b"br", 42),
    (b"content-encoding", b"gzip", 43),
    (b"content-length", b"0", 4),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
        85,
    ),
    (b"content-type", b"application/dns-message", 44),
    (b"content-type", b"application/javascript", 45),
    (b"content-type", b"application/json", 46),
    (b"content-type", b"application/x-www-form-urlencoded", 47),
    (b"content-type", b"image/gif", 48),
    (b"content-type", b"image/jpeg", 49),
    (b"content-type", b"image/png", 50),
    (b"content-type", b"text/css", 51),
    (b"content-type", b"text/html; charset=utf-8", 52),
    (b"content-type", b"text/plain", 53),
    (b"content-type", b"text/plain;charset=utf-8", 54),
    (b"cookie", b"", 5),
    (b"date", b"", 6),
    (b"early-data", b"1", 86),
    (b"etag", b"", 7),
    (b"expect-ct", b"", 87),
    (b"forwarded", b"", 88),
    (b"if-modified-since", b"", 8),
    (b"if-none-match", b"", 9),
    (b"if-range", b"", 89),
    (b"last-modified", b"", 10),
    (b"link", b"", 11),
    (b"location", b"", 12),
    (b"origin", b"", 90),
    (b"purpose", b"prefetch", 91),
    (b"range", b"bytes=0-", 55),
    (b"referer", b"", 13),
    (b"server", b"", 92),
    (b"set-cookie", b"", 14),
    (b"strict-transport-security", b"max-age=31536000", 56),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
        57,
    ),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
        58,
    ),
    (b"timing-allow-origin", b"*", 93),
    (b"upgrade-insecure-requests", b"1", 94),
    (b"user-agent", b"", 95),
    (b"vary", b"accept-encoding", 59),
    (b"vary", b"origin", 60),
    (b"x-content-type-options", b"nosniff", 61),
    (b"x-forwarded-for", b"", 96),
    (b"x-frame-options", b"deny", 97),
    (b"x-frame-options", b"sameorigin", 98),
    (b"x-xss-protection", b"1; mode=block", 62),
];

pub(crate) const STATIC_DECODE_TABLE: [(&[u8], &[u8]); 99] = [
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains",
    ),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload",
    ),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_table_min_index() {
        assert!(decode_static(0).is_ok());
    }

    #[test]
    fn static_table_size() {
        assert_eq!(STATIC_DECODE_TABLE.len(), 99);
    }

    #[test]
    fn static_table_index() {
        for (name, value, index) in STATIC_ENCODE_TABLE {
            assert_eq!(STATIC_DECODE_TABLE[index as usize].0, name);
            assert_eq!(STATIC_DECODE_TABLE[index as usize].1, value);
        }
    }

    #[test]
    fn encode_static_with_name_and_value() {
        let name: &[u8] = b":method";
        let value: &[u8] = b"GET";
        assert_eq!(encode_static(&(name, value)), Some((17, true)));
    }

    #[test]
    fn encode_static_with_name_only() {
        let name: &[u8] = b"cookie";
        let value: &[u8] = b"id=100";
        assert_eq!(encode_static(&(name, value)), Some((5, false)));
    }

    #[test]
    fn encode_static_with_value_not_match() {
        let names = vec![
            "agf",
            "varz",
            "rangf",
            "serves",
            "referes",
            "locatioo",
            "forwardef",
            "user-agenu",
            "content-typf",
            "last-modifiee",
            "content-lengti",
            "x-frame-optiont",
            "x-xss-protectioo",
            "if-modified-sincf",
            "timing-allow-origio",
            "x-content-type-optiont",
            "content-security-policz",
            "strict-transport-securitz",
            "access-control-allow-origio",
            "access-control-allow-headert",
            "access-control-expose-headert",
            "access-control-request-headert",
            "access-control-allow-credentialt",
        ];

        let value: &[u8] = b"UNKNOWN";
        for name in names {
            assert_eq!(encode_static(&(name.as_bytes(), value)), None);
        }
    }

    #[test]
    fn encode_static_with_name_not_match() {
        let name: &[u8] = b":methob";
        let value: &[u8] = b"CALL";
        assert_eq!(encode_static(&(name, value)), None);
    }

    #[test]
    fn decode_static_name_and_value() {
        let name: &[u8] = b":method";
        let value: &[u8] = b"GET";
        assert_eq!(decode_static(17), Ok((name, value)));
    }

    #[test]
    fn decode_static_invalid_index() {
        assert_eq!(decode_static(99), Err(Http3Error::QpackDecompressionFailed))
    }
}
