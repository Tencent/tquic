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

use ring::aead;
use ring::hkdf;

use crate::Error;
use crate::Result;

struct OutLen(usize);

impl hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand_label(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> Result<()> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let out_len = (out.len() as u16).to_be_bytes();
    let label_len = (LABEL_PREFIX.len() + label.len()) as u8;
    let info = [&out_len, &[label_len][..], LABEL_PREFIX, label, &[0][..]];
    prk.expand(&info, OutLen(out.len()))
        .map_err(|_| Error::CryptoFail)?
        .fill(out)
        .map_err(|_| Error::CryptoFail)
}

pub fn derive_initial_secret(secret: &[u8], _version: u32) -> hkdf::Prk {
    const INITIAL_SALT: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    hkdf::Salt::new(hkdf::HKDF_SHA256, &INITIAL_SALT).extract(secret)
}

pub fn derive_client_initial_secret(prk: &hkdf::Prk, out: &mut [u8]) -> Result<()> {
    hkdf_expand_label(prk, b"client in", out)
}

pub fn derive_server_initial_secret(prk: &hkdf::Prk, out: &mut [u8]) -> Result<()> {
    hkdf_expand_label(prk, b"server in", out)
}

pub fn derive_pkt_key(algor: hkdf::Algorithm, secret: &[u8], out: &mut [u8]) -> Result<()> {
    let prk = hkdf::Prk::new_less_safe(algor, secret);
    hkdf_expand_label(&prk, b"quic key", out)
}

pub fn derive_pkt_iv(algor: hkdf::Algorithm, secret: &[u8], out: &mut [u8]) -> Result<()> {
    let prk = hkdf::Prk::new_less_safe(algor, secret);
    hkdf_expand_label(&prk, b"quic iv", out)
}

pub fn derive_hdr_key(algor: hkdf::Algorithm, secret: &[u8], out: &mut [u8]) -> Result<()> {
    let prk = hkdf::Prk::new_less_safe(algor, secret);
    hkdf_expand_label(&prk, b"quic hp", out)
}

pub fn derive_next_packet_key(algor: hkdf::Algorithm, secret: &[u8], out: &mut [u8]) -> Result<()> {
    let prk = hkdf::Prk::new_less_safe(algor, secret);
    hkdf_expand_label(&prk, b"quic ku", out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit test for RFC 9001 Section A.1 Keys.
    #[test]
    fn derive_initial_secrets() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let mut secret = [0; 32];
        let mut pkt_key = [0; 16];
        let mut pkt_iv = [0; 12];
        let mut hdr_key = [0; 16];
        let algor = hkdf::HKDF_SHA256;
        let initial_secret = derive_initial_secret(&dcid, crate::QUIC_VERSION_V1);

        // Derive client initial secret.
        assert!(derive_client_initial_secret(&initial_secret, &mut secret).is_ok());
        let expected_client_initial_secret = [
            0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03,
            0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f,
            0x6c, 0x35, 0x7a, 0xea,
        ];
        assert_eq!(&secret, &expected_client_initial_secret);

        // Derive client packet key.
        assert!(derive_pkt_key(algor, &secret, &mut pkt_key).is_ok());
        let expected_client_pkt_key = [
            0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
            0xa2, 0x2d,
        ];
        assert_eq!(&pkt_key, &expected_client_pkt_key);

        // Derive client packet iv.
        assert!(derive_pkt_iv(algor, &secret, &mut pkt_iv).is_ok());
        let expected_client_pkt_iv = [
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
        ];
        assert_eq!(&pkt_iv, &expected_client_pkt_iv);

        // Derive client header protection key.
        assert!(derive_hdr_key(algor, &secret, &mut hdr_key).is_ok());
        let expected_client_hdr_key = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
            0xed, 0xd2,
        ];
        assert_eq!(&hdr_key, &expected_client_hdr_key);

        // Derive server initial secret.
        assert!(derive_server_initial_secret(&initial_secret, &mut secret).is_ok());
        let expected_server_initial_secret = [
            0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44,
            0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a,
            0xcd, 0xda, 0x95, 0x1b,
        ];
        assert_eq!(&secret, &expected_server_initial_secret);

        // Derive server packet key.
        assert!(derive_pkt_key(algor, &secret, &mut pkt_key).is_ok());
        let expected_server_pkt_key = [
            0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06,
            0x7e, 0x37,
        ];
        assert_eq!(&pkt_key, &expected_server_pkt_key);

        // Derive server packet iv.
        assert!(derive_pkt_iv(algor, &secret, &mut pkt_iv).is_ok());
        let expected_server_pkt_iv = [
            0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e,
        ];
        assert_eq!(&pkt_iv, &expected_server_pkt_iv);

        // Derive server header protection key.
        assert!(derive_hdr_key(algor, &secret, &mut hdr_key).is_ok());
        let expected_server_hdr_key = [
            0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea,
            0xa3, 0x14,
        ];
        assert_eq!(&hdr_key, &expected_server_hdr_key);
    }

    /// Unit test for RFC 9001 Section A.5 ChaCha20-Poly1305 Short Header Packet.
    #[test]
    fn derive_chacha20_secrets() {
        let secret = [
            0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42, 0x27, 0x48, 0xad,
            0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3,
            0x0f, 0x21, 0x63, 0x2b,
        ];
        let algor = hkdf::HKDF_SHA256;

        // Derive packet key.
        let mut pkt_key = [0; 32];
        assert!(derive_pkt_key(algor, &secret, &mut pkt_key).is_ok());
        let expected_pkt_key = [
            0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c,
            0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79,
            0xfb, 0x23, 0xe1, 0xc8,
        ];
        assert_eq!(&pkt_key, &expected_pkt_key);

        // Derive packet iv.
        let mut pkt_iv = [0; 12];
        assert!(derive_pkt_iv(algor, &secret, &mut pkt_iv).is_ok());
        let expected_pkt_iv = [
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44,
        ];
        assert_eq!(&pkt_iv, &expected_pkt_iv);

        // Derive header protection key.
        let mut hdr_key = [0; 32];
        assert!(derive_hdr_key(algor, &secret, &mut hdr_key).is_ok());
        let expected_hdr_key = [
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc,
            0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b,
            0x0a, 0xb7, 0xa7, 0xa4,
        ];
        assert_eq!(&hdr_key, &expected_hdr_key);

        // Update packet key.
        let mut updated_pkt_key = [0; 32];
        assert!(derive_next_packet_key(algor, &secret, &mut updated_pkt_key).is_ok());
        let expected_updated_pkt_key = [
            0x12, 0x23, 0x50, 0x47, 0x55, 0x03, 0x6d, 0x55, 0x63, 0x42, 0xee, 0x93, 0x61, 0xd2,
            0x53, 0x42, 0x1a, 0x82, 0x6c, 0x9e, 0xcd, 0xf3, 0xc7, 0x14, 0x86, 0x84, 0xb3, 0x6b,
            0x71, 0x48, 0x81, 0xf9,
        ];
        assert_eq!(&updated_pkt_key, &expected_updated_pkt_key);
    }
}
