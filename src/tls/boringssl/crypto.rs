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

use std::mem::MaybeUninit;

use libc::c_int;
use libc::c_void;
use ring::aead;
use ring::hkdf;

use crate::tls::key;
use crate::Error;
use crate::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    /// The algorithm of header protection.
    pub fn hp_algor(self) -> &'static aead::quic::Algorithm {
        match self {
            Algorithm::Aes128Gcm => &aead::quic::AES_128,
            Algorithm::Aes256Gcm => &aead::quic::AES_256,
            Algorithm::ChaCha20Poly1305 => &aead::quic::CHACHA20,
        }
    }

    /// Return HMAC-based Extract-and-Expand Key Derivation Function.
    pub fn hkdf_algor(self) -> hkdf::Algorithm {
        match self {
            Algorithm::Aes128Gcm => hkdf::HKDF_SHA256,
            Algorithm::Aes256Gcm => hkdf::HKDF_SHA384,
            Algorithm::ChaCha20Poly1305 => hkdf::HKDF_SHA256,
        }
    }

    /// The key length.
    pub fn key_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::Aes256Gcm => 32,
            Algorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// The length of AEAD tag.
    pub fn tag_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 16,
            Algorithm::Aes256Gcm => 16,
            Algorithm::ChaCha20Poly1305 => 16,
        }
    }

    /// The length of AEAD nonce.
    /// Note: The QUIC MultiPath extension cannot be used together with a
    /// algorithm that has a nonce less than 12.
    pub fn nonce_len(self) -> usize {
        match self {
            Algorithm::Aes128Gcm => 12,
            Algorithm::Aes256Gcm => 12,
            Algorithm::ChaCha20Poly1305 => 12,
        }
    }
}

struct HeaderKey {
    key: aead::quic::HeaderProtectionKey,
    raw: Vec<u8>,
}

impl HeaderKey {
    fn new(algor: Algorithm, hp_key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            key: aead::quic::HeaderProtectionKey::new(algor.hp_algor(), &hp_key)
                .map_err(|_| Error::CryptoFail)?,
            raw: hp_key,
        })
    }
}

struct PacketKey {
    ctx: EvpAeadCtx,
    nonce: Vec<u8>,
}

impl PacketKey {
    fn new(algor: Algorithm, key: Vec<u8>, iv: Vec<u8>) -> Result<Self> {
        Ok(Self {
            ctx: new_aead_ctx(algor, &key)?,
            nonce: iv,
        })
    }
}

/// AEAD encryption.
pub struct Seal {
    algor: Algorithm,
    secret: Vec<u8>,
    hdr_key: HeaderKey,
    pkt_key: PacketKey,
}

impl Seal {
    /// Create a new Seal.
    fn new(
        algor: Algorithm,
        secret: Vec<u8>,
        hp_key: Vec<u8>,
        key: Vec<u8>,
        iv: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self {
            algor,
            secret,
            hdr_key: HeaderKey::new(algor, hp_key)?,
            pkt_key: PacketKey::new(algor, key, iv)?,
        })
    }

    /// Create a new Seal with secret.
    pub fn new_with_secret(algor: Algorithm, secret: Vec<u8>) -> Result<Self> {
        let mut key = vec![0; algor.key_len()];
        let mut iv = vec![0; algor.nonce_len()];
        let mut hp_key = vec![0; algor.key_len()];
        key::derive_pkt_key(algor.hkdf_algor(), &secret, &mut key)?;
        key::derive_pkt_iv(algor.hkdf_algor(), &secret, &mut iv)?;
        key::derive_hdr_key(algor.hkdf_algor(), &secret, &mut hp_key)?;

        Self::new(algor, secret, hp_key, key, iv)
    }

    /// Derive next packet key.
    pub fn derive_next_packet_key(&self) -> Result<Self> {
        let mut next_secret = vec![0; self.secret.len()];
        key::derive_next_packet_key(self.algor.hkdf_algor(), &self.secret, &mut next_secret)?;
        let mut next_key = Self::new_with_secret(self.algor, next_secret)?;

        // The header protection key is not updated.
        next_key.hdr_key = HeaderKey::new(self.algor, self.hdr_key.raw.clone())?;

        Ok(next_key)
    }

    /// Encrypt the plaintext and authenticate it in place.
    pub fn seal(
        &self,
        cid_seq: Option<u32>,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        let tag_len = self.algor().tag_len();
        let mut out_tag_len = tag_len;
        let (extra_in_ptr, extra_in_len) = match extra_in {
            Some(v) => (v.as_ptr(), v.len()),
            None => (std::ptr::null(), 0),
        };
        if in_len + tag_len + extra_in_len > buf.len() {
            return Err(Error::CryptoFail);
        }

        let nonce = build_nonce(&self.pkt_key.nonce, cid_seq, counter);
        let rc = unsafe {
            EVP_AEAD_CTX_seal_scatter(
                &self.pkt_key.ctx,
                buf.as_mut_ptr(),
                buf[in_len..].as_mut_ptr(),
                &mut out_tag_len,
                tag_len + extra_in_len,
                nonce.as_ptr(),
                nonce.len(),
                buf.as_ptr(),
                in_len,
                extra_in_ptr,
                extra_in_len,
                ad.as_ptr(),
                ad.len(),
            )
        };
        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(in_len + out_tag_len)
    }

    /// Generate header protection mask.
    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        self.hdr_key
            .key
            .new_mask(sample)
            .map_err(|_| Error::CryptoFail)
    }

    pub fn algor(&self) -> Algorithm {
        self.algor
    }
}

/// AEAD decryption.
pub struct Open {
    algor: Algorithm,
    secret: Vec<u8>,
    hdr_key: HeaderKey,
    pkt_key: PacketKey,
}

impl Open {
    /// Create a new Open.
    fn new(
        algor: Algorithm,
        secret: Vec<u8>,
        hp_key: Vec<u8>,
        key: Vec<u8>,
        iv: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self {
            algor,
            secret,
            hdr_key: HeaderKey::new(algor, hp_key)?,
            pkt_key: PacketKey::new(algor, key, iv)?,
        })
    }

    /// Create a new Open with secret.
    pub fn new_with_secret(algor: Algorithm, secret: Vec<u8>) -> Result<Self> {
        let mut key = vec![0; algor.key_len()];
        let mut iv = vec![0; algor.nonce_len()];
        let mut hp_key = vec![0; algor.key_len()];
        key::derive_pkt_key(algor.hkdf_algor(), &secret, &mut key)?;
        key::derive_pkt_iv(algor.hkdf_algor(), &secret, &mut iv)?;
        key::derive_hdr_key(algor.hkdf_algor(), &secret, &mut hp_key)?;

        Self::new(algor, secret, hp_key, key, iv)
    }

    /// Derive next packet key.
    pub fn derive_next_packet_key(&self) -> Result<Self> {
        let mut next_secret = vec![0; self.secret.len()];
        key::derive_next_packet_key(self.algor.hkdf_algor(), &self.secret, &mut next_secret)?;
        let mut next_key = Self::new_with_secret(self.algor, next_secret)?;

        // The header protection key is not updated.
        next_key.hdr_key = HeaderKey::new(self.algor, self.hdr_key.raw.clone())?;

        Ok(next_key)
    }

    /// Decrypt the ciphertext into plaintext.
    pub fn open(
        &self,
        cid_seq: Option<u32>,
        counter: u64,
        ad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize> {
        let tag_len = self.algor().tag_len();
        let mut out_len = match ciphertext.len().checked_sub(tag_len) {
            Some(n) => n,
            None => return Err(Error::CryptoFail),
        };
        if plaintext.len() < out_len {
            return Err(Error::CryptoFail);
        }

        let max_out_len = out_len;
        let nonce = build_nonce(&self.pkt_key.nonce, cid_seq, counter);
        let rc = unsafe {
            EVP_AEAD_CTX_open(
                &self.pkt_key.ctx,
                plaintext.as_mut_ptr(),
                &mut out_len,
                max_out_len,
                nonce.as_ptr(),
                nonce.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                ad.as_ptr(),
                ad.len(),
            )
        };
        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(out_len)
    }

    /// Generate header protection mask.
    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        self.hdr_key
            .key
            .new_mask(sample)
            .map_err(|_| Error::CryptoFail)
    }

    /// Return the AEAD algorithm.
    pub fn algor(&self) -> Algorithm {
        self.algor
    }
}

/// Derive initial secrets.
pub fn derive_initial_secrets(cid: &[u8], version: u32, is_server: bool) -> Result<(Open, Seal)> {
    let mut secret = [0; 32];
    let aead = Algorithm::Aes128Gcm;
    let key_len = aead.key_len();
    let nonce_len = aead.nonce_len();
    let initial_secret = key::derive_initial_secret(cid, version);

    // Derive client keys.
    let mut client_key = vec![0; key_len];
    let mut client_iv = vec![0; nonce_len];
    let mut client_hp_key = vec![0; key_len];
    key::derive_client_initial_secret(&initial_secret, &mut secret)?;
    key::derive_pkt_key(aead.hkdf_algor(), &secret, &mut client_key)?;
    key::derive_pkt_iv(aead.hkdf_algor(), &secret, &mut client_iv)?;
    key::derive_hdr_key(aead.hkdf_algor(), &secret, &mut client_hp_key)?;

    // Derive server keys.
    let mut server_key = vec![0; key_len];
    let mut server_iv = vec![0; nonce_len];
    let mut server_hp_key = vec![0; key_len];
    key::derive_server_initial_secret(&initial_secret, &mut secret)?;
    key::derive_pkt_key(aead.hkdf_algor(), &secret, &mut server_key)?;
    key::derive_pkt_iv(aead.hkdf_algor(), &secret, &mut server_iv)?;
    key::derive_hdr_key(aead.hkdf_algor(), &secret, &mut server_hp_key)?;

    if is_server {
        return Ok((
            Open::new(aead, secret.to_vec(), client_hp_key, client_key, client_iv)?,
            Seal::new(aead, secret.to_vec(), server_hp_key, server_key, server_iv)?,
        ));
    }

    Ok((
        Open::new(aead, secret.to_vec(), server_hp_key, server_key, server_iv)?,
        Seal::new(aead, secret.to_vec(), client_hp_key, client_key, client_iv)?,
    ))
}

fn evp_aead_algor(algor: &Algorithm) -> *const EvpAead {
    match algor {
        Algorithm::Aes128Gcm => unsafe { EVP_aead_aes_128_gcm() },
        Algorithm::Aes256Gcm => unsafe { EVP_aead_aes_256_gcm() },
        Algorithm::ChaCha20Poly1305 => unsafe { EVP_aead_chacha20_poly1305() },
    }
}

fn new_aead_ctx(algor: Algorithm, key: &[u8]) -> Result<EvpAeadCtx> {
    let mut ctx = MaybeUninit::uninit();

    let ctx = unsafe {
        let rc = EVP_AEAD_CTX_init(
            ctx.as_mut_ptr(),
            evp_aead_algor(&algor),
            key.as_ptr(),
            algor.key_len(),
            algor.tag_len(),
            std::ptr::null_mut(),
        );
        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        ctx.assume_init()
    };

    Ok(ctx)
}

// Calculated a nonce for AEAD algorithm.
//
// `cid_seq` is None when multipath is not negotiated.
//
// Note: All the AEADs we support use 96-bit nonces.
fn build_nonce(iv: &[u8], cid_seq: Option<u32>, counter: u64) -> [u8; aead::NONCE_LEN] {
    let mut nonce = [0; aead::NONCE_LEN];
    nonce.copy_from_slice(iv);

    // XOR the four first bytes of the IV with the cid_seq.
    if let Some(cid_seq) = cid_seq {
        for (a, b) in nonce[0..4].iter_mut().zip(cid_seq.to_be_bytes().iter()) {
            *a ^= b;
        }
    }

    // XOR the last bytes of the IV with the counter.
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }

    nonce
}

#[repr(transparent)]
struct EvpAead(c_void);

#[repr(C)]
struct EvpAeadCtx {
    aead: libc::uintptr_t,
    opaque: [u8; 580],
    alignment: u64,
    tag_len: u8,
}

extern "C" {
    fn EVP_aead_aes_128_gcm() -> *const EvpAead;

    fn EVP_aead_aes_256_gcm() -> *const EvpAead;

    fn EVP_aead_chacha20_poly1305() -> *const EvpAead;

    /// Initialize ctx for the given AEAD algorithm.
    fn EVP_AEAD_CTX_init(
        ctx: *mut EvpAeadCtx,
        aead: *const EvpAead,
        key: *const u8,
        key_len: usize,
        tag_len: usize,
        engine: *mut c_void,
    ) -> c_int;

    /// Authenticate `in_len` bytes from `input` and `ad_len` bytes from `ad` and decrypts at most `in_len` bytes into `out`.
    fn EVP_AEAD_CTX_open(
        ctx: *const EvpAeadCtx,
        out: *mut u8,
        out_len: *mut usize,
        max_out_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        input: *const u8,
        in_len: usize,
        ad: *const u8,
        ad_len: usize,
    ) -> c_int;

    /// Encrypt and authenticate `in_len` bytes from `input` and authenticate `ad_len` bytes from `ad`. Write `in_len` bytes of ciphertext to `out` and the authentication tag to `out_tag`.
    fn EVP_AEAD_CTX_seal_scatter(
        ctx: *const EvpAeadCtx,
        out: *mut u8,
        out_tag: *mut u8,
        out_tag_len: *mut usize,
        max_out_tag_len: usize,
        nonce: *const u8,
        nonce_len: usize,
        input: *const u8,
        in_len: usize,
        extra_in: *const u8,
        extra_in_len: usize,
        ad: *const u8,
        ad_len: usize,
    ) -> c_int;
}
