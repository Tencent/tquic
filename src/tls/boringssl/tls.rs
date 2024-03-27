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

use std::ffi;
use std::io::Write;
use std::ptr;
use std::slice;

use libc::c_char;
use libc::c_int;
use libc::c_long;
use libc::c_uint;
use libc::c_void;
use log::trace;

use crate::codec::Decoder;
use crate::tls;
use crate::tls::boringssl::crypto;
use crate::tls::key;
use crate::tls::TlsSessionData;
use crate::Error;
use crate::Result;

#[repr(transparent)]
struct SslMethod(c_void);

#[repr(transparent)]
pub struct SslCtx(c_void);

#[repr(transparent)]
struct Ssl(c_void);

#[repr(transparent)]
struct SslCipher(c_void);

#[repr(transparent)]
struct SslSession(c_void);

#[repr(transparent)]
struct X509VerifyParam(c_void);

#[repr(transparent)]
struct StackOf(c_void);

#[repr(transparent)]
struct CryptoBuffer(c_void);

#[repr(transparent)]
struct CryptoExData(c_void);

#[repr(C)]
struct SslQuicMethod {
    set_read_secret: extern "C" fn(
        ssl: *mut Ssl,
        level: tls::Level,
        cipher: *const SslCipher,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int,

    set_write_secret: extern "C" fn(
        ssl: *mut Ssl,
        level: tls::Level,
        cipher: *const SslCipher,
        secret: *const u8,
        secret_len: usize,
    ) -> c_int,

    add_handshake_data:
        extern "C" fn(ssl: *mut Ssl, level: tls::Level, data: *const u8, len: usize) -> c_int,

    flush_flight: extern "C" fn(ssl: *mut Ssl) -> c_int,

    send_alert: extern "C" fn(ssl: *mut Ssl, level: tls::Level, alert: u8) -> c_int,
}

#[repr(C)]
enum SslEarlyDataReason {
    // The handshake has not progressed far enough for the 0-RTT status to be known.
    Unknown = 0,
    // 0-RTT is disabled for this connection.
    Disabled = 1,
    // 0-RTT was accepted.
    Accepted = 2,
    // The negotiated protocol version does not support 0-RTT.
    ProtocolVersion = 3,
    // The peer declined to offer or accept 0-RTT for an unknown reason.
    PeerDeclined = 4,
    // The client did not offer a session.
    NoSessionOffered = 5,
    // The server declined to resume the session.
    SessionNotResumed = 6,
    // The session does not support 0-RTT.
    UnsupportedForSession = 7,
    // The server sent a HelloRetryRequest.
    HelloRetryRequest = 8,
    // The negotiated ALPN protocol did not match the session.
    AlpnMismatch = 9,
    // The connection negotiated Channel ID, which is incompatible with 0-RTT.
    ChannelId = 10,
    // Value 11 is reserved. (It has historically |ssl_early_data_token_binding|.)
    // The client and server ticket age were too far apart.
    TicketAgeSkew = 12,
    // QUIC parameters differ between this connection and the original.
    QuicParameterMismatch = 13,
    // The application settings did not match the session.
    AlpsMismatch = 14,
}

/// Called when TLS context is being destroyed.
/// See https://commondatastorage.googleapis.com/chromium-boringssl-docs/ex_data.h.html
extern "C" fn context_data_free(
    parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut CryptoExData,
    _index: c_int,
    arg1: c_long,
    _argp: *mut c_void,
) {
    if parent.is_null() || ptr.is_null() || arg1 != 0 {
        return;
    }

    unsafe {
        // `ptr` is the ALPN data set by `SSL_CTX_set_ex_data`.
        let _ = Box::from_raw(ptr as *mut Vec<Vec<u8>>);
    };
}

lazy_static::lazy_static! {
    /// Boringssl extra data index for tls context.
    pub static ref CONTEXT_DATA_INDEX: c_int = unsafe {
        SSL_CTX_get_ex_new_index(0, ptr::null(), ptr::null(), ptr::null(), context_data_free)
    };

    /// Boringssl extra data index for tls session.
    pub static ref SESSION_DATA_INDEX: c_int = unsafe {
        SSL_get_ex_new_index(0, ptr::null(), ptr::null(), ptr::null(), ptr::null())
    };
}

static SSL_QUIC_METHOD: SslQuicMethod = SslQuicMethod {
    set_read_secret,
    set_write_secret,
    add_handshake_data,
    flush_flight,
    send_alert,
};

/// Rust wrapper of SSL_CTX which holds various configuration and data relevant
/// to SSL/TLS session establishment.
pub(crate) struct Context {
    ctx_raw: *mut SslCtx,
    owned: bool,
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.owned {
            unsafe { SSL_CTX_free(self.as_mut_ptr()) }
        }
    }
}

impl Context {
    /// Create a new TLS context.
    pub fn new() -> Result<Context> {
        unsafe {
            let ctx_raw = SSL_CTX_new(TLS_method());

            let mut ctx = Context {
                ctx_raw,
                owned: true,
            };

            ctx.set_session_callback();
            ctx.set_default_verify_paths()?;
            Ok(ctx)
        }
    }

    /// Create a new TLS context with SSL_CTX.
    /// The caller is responsible for the memory of SSL_CTX when use this function.
    pub fn new_with_ssl_ctx(ssl_ctx: *mut SslCtx) -> Context {
        Self {
            ctx_raw: ssl_ctx,
            owned: false,
        }
    }

    /// Return the mutable pointer of the inner SSL_CTX.
    pub fn as_mut_ptr(&mut self) -> *mut SslCtx {
        self.ctx_raw
    }

    /// Return the const pointer of the inner SSL_CTX.
    pub fn as_ptr(&self) -> *const SslCtx {
        self.ctx_raw
    }

    /// Create a new TLS session.
    pub fn new_session(&self) -> Result<Session> {
        unsafe {
            let ssl = SSL_new(self.as_ptr());
            Ok(Session::new(ssl))
        }
    }

    /// Specify the locations at which CA certificates for verification purposes are located.
    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        let file = ffi::CString::new(file)
            .map_err(|e| Error::TlsFail(format!("file name({:?}) format error: {:?}", file, e)))?;
        match unsafe {
            SSL_CTX_load_verify_locations(self.as_mut_ptr(), file.as_ptr(), std::ptr::null())
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "load verify locations from file({:?}) failed",
                file
            ))),
        }
    }

    /// Specify the locations at which CA certificates for verification purposes are located.
    pub fn load_verify_locations_from_directory(&mut self, path: &str) -> Result<()> {
        let path = ffi::CString::new(path)
            .map_err(|e| Error::TlsFail(format!("path name({:?}) format error: {:?}", path, e)))?;
        match unsafe {
            SSL_CTX_load_verify_locations(self.as_mut_ptr(), std::ptr::null(), path.as_ptr())
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "load verify locations from path({:?}) failed",
                path
            ))),
        }
    }

    /// Load a certificate chain from file into ctx. The certificates must be in
    /// PEM format and must be sorted starting with the subject's certificate
    /// (actual client or server certificate), followed by intermediate CA
    /// certificates if applicable, and ending at the highest level (root) CA.
    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file)
            .map_err(|e| Error::TlsFail(format!("file name({:?}) format error: {:?}", file, e)))?;
        match unsafe { SSL_CTX_use_certificate_chain_file(self.as_mut_ptr(), cstr.as_ptr()) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "use certificate chain file({:?}) failed",
                file
            ))),
        }
    }

    /// Add the first private key found in file to ctx.
    pub fn use_private_key_file(&mut self, file: &str) -> Result<()> {
        let cstr = ffi::CString::new(file)
            .map_err(|e| Error::TlsFail(format!("file name({:?}) format error: {:?}", file, e)))?;
        match unsafe { SSL_CTX_use_PrivateKey_file(self.as_mut_ptr(), cstr.as_ptr(), 1) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "use private key file({:?}) failed",
                file
            ))),
        }
    }

    /// Load trust anchors from directory in OpenSSL's hashed directory format.
    fn set_default_verify_paths(&mut self) -> Result<()> {
        match unsafe { SSL_CTX_set_default_verify_paths(self.as_mut_ptr()) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(
                "set default verify paths failed".to_string(),
            )),
        }
    }

    /// Set the callback function that is called whenever a new session was negotiated.
    pub fn set_session_callback(&mut self) {
        unsafe {
            SSL_CTX_set_session_cache_mode(
                self.as_mut_ptr(),
                0x0001, // SSL_SESS_CACHE_CLIENT
            );

            SSL_CTX_sess_set_new_cb(self.as_mut_ptr(), new_session);
        };
    }

    /// Configure certificate verification behavior.
    /// True: make server certificate errors fatal.
    /// False: verify the server certificate but not make errors fatal.
    pub fn set_verify(&mut self, verify: bool) {
        let mode = i32::from(verify);

        unsafe {
            SSL_CTX_set_verify(self.as_mut_ptr(), mode, ptr::null());
        }
    }

    /// Set the TLS key logging callback. This callback is called whenever TLS
    /// key material is generated or received, in order to allow applications
    /// to store this keying material for debugging purposes.
    pub fn enable_keylog(&mut self) {
        unsafe {
            SSL_CTX_set_keylog_callback(self.as_mut_ptr(), keylog);
        }
    }

    /// Set the list of protocols available to be negotiated for the client, or
    /// Set the application callback cb used by a server to select which
    /// protocol to use for the incoming connection.
    pub fn set_alpn(&mut self, v: Vec<Vec<u8>>) -> Result<()> {
        let mut protos: Vec<u8> = Vec::new();
        for proto in &v {
            protos.push(proto.len() as u8);
            protos.extend_from_slice(proto);
        }

        let v = Box::new(v);
        unsafe {
            SSL_CTX_set_ex_data(
                self.as_mut_ptr(),
                *CONTEXT_DATA_INDEX,
                Box::into_raw(v) as *const c_void,
            );
        }

        unsafe {
            SSL_CTX_set_alpn_select_cb(self.as_mut_ptr(), select_alpn, ptr::null_mut());
        }

        // SSL_CTX_set_alpn_protos() returns 0 on success.
        match unsafe { SSL_CTX_set_alpn_protos(self.as_mut_ptr(), protos.as_ptr(), protos.len()) } {
            0 => Ok(()),
            _ => Err(Error::TlsFail("SSL set alpn failed".to_string())),
        }
    }

    /// Set ctx's session ticket key material
    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        match unsafe { SSL_CTX_set_tlsext_ticket_keys(self.as_mut_ptr(), key.as_ptr(), key.len()) }
        {
            1 => Ok(()),
            _ => Err(Error::TlsFail("set ticket key failed".to_string())),
        }
    }

    /// Set whether early data is allowed to be used with resumptions using ctx.
    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        let enabled = i32::from(enabled);

        unsafe {
            SSL_CTX_set_early_data_enabled(self.as_mut_ptr(), enabled);
        }
    }
}

fn get_ctx_data_from_ptr<'a, T>(ptr: *mut SslCtx, idx: c_int) -> Option<&'a mut T> {
    unsafe {
        let data = SSL_CTX_get_ex_data(ptr, idx) as *mut T;
        data.as_mut()
    }
}

unsafe impl std::marker::Send for Context {}

unsafe impl std::marker::Sync for Context {}

/// Rust wrapper of SSL which is needed to hold the data for a TLS/SSL connection.
/// It inherits the settings of the underlying context ctx.
pub struct Session {
    /// The raw pointer to the SSL object.
    ptr: *mut Ssl,

    /// SSL_process_quic_post_handshake should be called when whenever
    /// SSL_provide_quic_data is called to process the provided data.
    provided_data_outstanding: bool,
}

impl Session {
    fn new(ptr: *mut Ssl) -> Session {
        Session {
            ptr,
            provided_data_outstanding: false,
        }
    }

    /// Obtain result code for TLS/SSL I/O operation.
    pub fn get_error(&self, ret_code: c_int) -> c_int {
        unsafe { SSL_get_error(self.as_ptr(), ret_code) }
    }

    pub fn init(&mut self, is_server: bool) -> Result<()> {
        self.set_state(is_server);
        const TLS1_3_VERSION: u16 = 0x0304;
        self.set_min_proto_version(TLS1_3_VERSION);
        self.set_max_proto_version(TLS1_3_VERSION);
        self.set_quic_method()?;
        self.set_quic_early_data_context(b"quic")?;
        self.set_quiet_shutdown(true);

        Ok(())
    }

    /// Set ssl to work in client or server mode.
    pub fn set_state(&mut self, is_server: bool) {
        unsafe {
            if is_server {
                SSL_set_accept_state(self.as_mut_ptr());
            } else {
                SSL_set_connect_state(self.as_mut_ptr());
            }
        }
    }

    /// Store arbitrary user data into the or SSL object. The user must supply
    /// a unique index.
    pub fn set_ex_data<T>(&mut self, idx: c_int, data: *const T) -> Result<()> {
        match unsafe {
            let ptr = data as *const c_void;
            SSL_set_ex_data(self.as_mut_ptr(), idx, ptr)
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail("SSL set extra data failed".to_string())),
        }
    }

    /// Configure the QUIC callback functions.
    pub fn set_quic_method(&mut self) -> Result<()> {
        match unsafe { SSL_set_quic_method(self.as_mut_ptr(), &SSL_QUIC_METHOD) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail("SSL set quic method failed".to_string())),
        }
    }

    /// Configure a context string in QUIC servers for accepting early data.
    /// If a resumption connection offers early data, the server will check if
    /// the value matches that of the connection which minted the ticket. If
    /// not, resumption still succeeds but early data is rejected.
    pub fn set_quic_early_data_context(&mut self, context: &[u8]) -> Result<()> {
        match unsafe {
            SSL_set_quic_early_data_context(self.as_mut_ptr(), context.as_ptr(), context.len())
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(
                "SSL set quic early data context failed".to_string(),
            )),
        }
    }

    /// Set the minimum protocol version for ssl to version.
    pub fn set_min_proto_version(&mut self, version: u16) {
        unsafe { SSL_set_min_proto_version(self.as_mut_ptr(), version) }
    }

    /// Set the maximum protocol version for ssl to version.
    pub fn set_max_proto_version(&mut self, version: u16) {
        unsafe { SSL_set_max_proto_version(self.as_mut_ptr(), version) }
    }

    /// Set quiet shutdown on ssl. If enabled, SSL_shutdown will not send a
    /// close_notify alert or wait for one from the peer.
    pub fn set_quiet_shutdown(&mut self, mode: bool) {
        unsafe { SSL_set_quiet_shutdown(self.as_mut_ptr(), i32::from(mode)) }
    }

    /// Configure ssl to advertise name in the server_name extension for client.
    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        let cstr = ffi::CString::new(name)
            .map_err(|_| Error::TlsFail("host name format error".to_string()))?;
        let rc = unsafe { SSL_set_tlsext_host_name(self.as_mut_ptr(), cstr.as_ptr()) };
        self.map_result_ssl(rc, None)?;

        // Retrieve an internal pointer to the verification parameters for ssl
        let param = unsafe { SSL_get0_param(self.as_mut_ptr()) };

        // Set the expected DNS hostname to name clearing any previously specified hostname.
        match unsafe { X509_VERIFY_PARAM_set1_host(param, cstr.as_ptr(), name.len()) } {
            1 => Ok(()),
            _ => Err(Error::TlsFail(format!(
                "SSL set host name({:?}) failed",
                name
            ))),
        }
    }

    /// Set a callback that is called to select a certificate.
    pub fn set_cert_cb(&mut self) {
        unsafe { SSL_set_cert_cb(self.as_mut_ptr(), select_cert, std::ptr::null_mut()) }
    }

    /// Configure ssl to send params in the quic_transport_parameters extension
    /// in either the ClientHello or EncryptedExtensions handshake message.
    pub fn set_quic_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        let rc =
            unsafe { SSL_set_quic_transport_params(self.as_mut_ptr(), buf.as_ptr(), buf.len()) };
        self.map_result_ssl(rc, None)
    }

    /// Return the value of the quic_transport_parameters extension sent by the
    /// peer.
    pub fn quic_transport_params(&self) -> &[u8] {
        let mut ptr: *const u8 = ptr::null();
        let mut len: usize = 0;

        unsafe {
            SSL_get_peer_quic_transport_params(self.as_ptr(), &mut ptr, &mut len);
        }

        if len == 0 {
            return &mut [];
        }
        unsafe { slice::from_raw_parts(ptr, len) }
    }

    /// Return the selected protocol.
    pub fn alpn_protocol(&self) -> &[u8] {
        let mut ptr: *const u8 = ptr::null();
        let mut len: u32 = 0;

        unsafe {
            SSL_get0_alpn_selected(self.as_ptr(), &mut ptr, &mut len);
        }

        if len == 0 {
            return &mut [];
        }
        unsafe { slice::from_raw_parts(ptr, len as usize) }
    }

    /// Return the server name.
    pub fn server_name(&self) -> Option<&str> {
        let s = unsafe {
            let ptr = SSL_get_servername(
                self.as_ptr(),
                0, // TLSEXT_NAMETYPE_host_name
            );

            if ptr.is_null() {
                return None;
            }
            ffi::CStr::from_ptr(ptr)
        };

        s.to_str().ok()
    }

    /// Set session to be used when the TLS/SSL connection is to be established.
    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        let ctx = unsafe { SSL_get_SSL_CTX(self.as_ptr()) };
        if ctx.is_null() {
            return Err(Error::TlsFail("SSL context is null".to_string()));
        }

        let session = unsafe { SSL_SESSION_from_bytes(session.as_ptr(), session.len(), ctx) };
        if session.is_null() {
            return Err(Error::TlsFail("SSL session is null".to_string()));
        }

        match unsafe {
            let rc = SSL_set_session(self.as_mut_ptr(), session);
            SSL_SESSION_free(session);
            rc
        } {
            1 => Ok(()),
            _ => Err(Error::TlsFail("SSL set session failed".to_string())),
        }
    }

    /// Provide data from QUIC at a particular encryption level level.
    pub fn provide_data(&mut self, level: tls::Level, buf: &[u8]) -> Result<()> {
        self.provided_data_outstanding = true;
        let rc =
            unsafe { SSL_provide_quic_data(self.as_mut_ptr(), level, buf.as_ptr(), buf.len()) };
        self.map_result_ssl(rc, None)
    }

    /// Continue the current handshake.
    pub fn do_handshake(&mut self, session_data: &mut tls::TlsSessionData) -> Result<()> {
        self.set_ex_data(*SESSION_DATA_INDEX, session_data)?;
        let rc = unsafe { SSL_do_handshake(self.as_mut_ptr()) };
        self.set_ex_data::<tls::TlsSessionData>(*SESSION_DATA_INDEX, std::ptr::null())?;

        self.set_transport_error(session_data, rc);
        self.map_result_ssl(rc, Some(session_data))
    }

    /// Processes any data that QUIC has provided after the handshake has
    /// completed. This includes NewSessionTicket messages sent by the server.
    pub fn process_post_handshake(&mut self, session_data: &mut tls::TlsSessionData) -> Result<()> {
        // If SSL_provide_quic_data hasn't been called since we last called
        // SSL_process_quic_post_handshake, then there's nothing to do.
        if !self.provided_data_outstanding {
            return Ok(());
        }
        self.provided_data_outstanding = false;

        self.set_ex_data(*SESSION_DATA_INDEX, session_data)?;
        let rc = unsafe { SSL_process_quic_post_handshake(self.as_mut_ptr()) };
        self.set_ex_data::<tls::TlsSessionData>(*SESSION_DATA_INDEX, std::ptr::null())?;

        self.set_transport_error(session_data, rc);
        self.map_result_ssl(rc, Some(session_data))
    }

    /// Resets ssl after an early data reject. All 0-RTT state is discarded,
    /// including any pending SSL_write calls. The caller should treat ssl
    /// as a logically fresh connection.
    pub fn reset_early_data_reject(&mut self) {
        unsafe { SSL_reset_early_data_reject(self.as_mut_ptr()) };
    }

    /// Return the current write encryption level.
    pub fn write_level(&self) -> tls::Level {
        unsafe { SSL_quic_write_level(self.as_ptr()) }
    }

    /// Return the cipher suite used by ssl.
    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        let cipher = map_result_ptr(unsafe { SSL_get_current_cipher(self.as_ptr()) });
        get_cipher_from_ptr(cipher.ok()?).ok()
    }

    /// Return a human-readable name for the curve used by ssl.
    pub fn curve(&self) -> Option<String> {
        let curve = unsafe {
            let curve_id = SSL_get_curve_id(self.as_ptr());
            if curve_id == 0 {
                return None;
            }

            let curve_name = SSL_get_curve_name(curve_id);
            match ffi::CStr::from_ptr(curve_name).to_str() {
                Ok(v) => v,
                Err(_) => return None,
            }
        };

        Some(curve.to_string())
    }

    /// Returns a human-readable name for signature algorithm used by the peer.
    pub fn peer_sign_algor(&self) -> Option<String> {
        let sigalg = unsafe {
            let sigalg_id = SSL_get_peer_signature_algorithm(self.as_ptr());
            if sigalg_id == 0 {
                return None;
            }

            let sigalg_name = SSL_get_signature_algorithm_name(sigalg_id, 1);
            match ffi::CStr::from_ptr(sigalg_name).to_str() {
                Ok(v) => v,
                Err(_) => return None,
            }
        };

        Some(sigalg.to_string())
    }

    /// Return the peer's certificate chain.
    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        let cert_chain = unsafe {
            let chain = map_result_ptr(SSL_get0_peer_certificates(self.as_ptr())).ok()?;

            let num = sk_num(chain);
            if num <= 0 {
                return None;
            }

            let mut cert_chain = vec![];
            for i in 0..num {
                let buffer = map_result_ptr(sk_value(chain, i) as *const CryptoBuffer).ok()?;
                let out_len = CRYPTO_BUFFER_len(buffer);
                if out_len == 0 {
                    return None;
                }

                let out = CRYPTO_BUFFER_data(buffer);
                let slice = slice::from_raw_parts(out, out_len);
                cert_chain.push(slice);
            }
            cert_chain
        };

        Some(cert_chain)
    }

    /// Return the peer's certificate.
    pub fn peer_cert(&self) -> Option<&[u8]> {
        let peer_cert = unsafe {
            let chain = map_result_ptr(SSL_get0_peer_certificates(self.as_ptr())).ok()?;
            if sk_num(chain) <= 0 {
                return None;
            }

            let buffer = map_result_ptr(sk_value(chain, 0) as *const CryptoBuffer).ok()?;
            let out_len = CRYPTO_BUFFER_len(buffer);
            if out_len == 0 {
                return None;
            }

            let out = CRYPTO_BUFFER_data(buffer);
            slice::from_raw_parts(out, out_len)
        };

        Some(peer_cert)
    }

    pub fn early_data_reason(&self) -> Result<Option<&str>> {
        let reason = unsafe {
            let reason = SSL_early_data_reason_string(SSL_get_early_data_reason(self.as_ptr()));
            match ffi::CStr::from_ptr(reason).to_str() {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::TlsFail(format!(
                        "early data reason format error {:?}",
                        e
                    )))
                }
            }
        };

        Ok(Some(reason))
    }

    /// Return true if ssl has a completed handshake.
    pub fn is_completed(&self) -> bool {
        unsafe { SSL_in_init(self.as_ptr()) == 0 }
    }

    /// Return true if ssl performed an abbreviated handshake.
    pub fn is_resumed(&self) -> bool {
        unsafe { SSL_session_reused(self.as_ptr()) == 1 }
    }

    /// Return true if ssl has a pending handshake that has progressed enough
    /// to send or receive early data.
    pub fn is_in_early_data(&self) -> bool {
        unsafe { SSL_in_early_data(self.as_ptr()) == 1 }
    }

    /// Resets ssl to allow another connection.
    pub fn clear(&mut self) -> Result<()> {
        let rc = unsafe { SSL_clear(self.as_mut_ptr()) };
        self.map_result_ssl(rc, None)
    }

    fn as_ptr(&self) -> *const Ssl {
        self.ptr
    }

    fn as_mut_ptr(&mut self) -> *mut Ssl {
        self.ptr
    }

    /// Convert SSL error.
    fn map_result_ssl(
        &mut self,
        bssl_result: c_int,
        session_data: Option<&mut tls::TlsSessionData>,
    ) -> Result<()> {
        match bssl_result {
            1 => Ok(()),

            _ => {
                let ssl_err = self.get_error(bssl_result);
                match ssl_err {
                    // SSL_ERROR_SSL
                    1 => {
                        let ssl_err = get_ssl_error()?;
                        trace!("SSL error: {}", ssl_err);
                        Err(Error::TlsFail(format!("SSL error: {}", ssl_err)))
                    }

                    // SSL_ERROR_WANT_READ
                    2 => Err(Error::Done),

                    // SSL_ERROR_WANT_WRITE
                    3 => Err(Error::Done),

                    // SSL_ERROR_WANT_X509_LOOKUP
                    4 => Err(Error::Done),

                    // SSL_ERROR_SYSCALL
                    5 => Err(Error::TlsFail("SSL error, syscall".to_string())),

                    // SSL_ERROR_PENDING_SESSION
                    11 => Err(Error::Done),

                    // SSL_ERROR_PENDING_CERTIFICATE
                    12 => Err(Error::Done),

                    // SSL_ERROR_WANT_PRIVATE_KEY_OPERATION
                    13 => Err(Error::Done),

                    // SSL_ERROR_PENDING_TICKET
                    14 => Err(Error::Done),

                    // SSL_ERROR_EARLY_DATA_REJECTED
                    15 => {
                        self.reset_early_data_reject();
                        if let Some(session_data) = session_data {
                            trace!("{} early data rejected", session_data.trace_id);
                            session_data.early_data_rejected = true;
                        }
                        Err(Error::Done)
                    }

                    // SSL_ERROR_WANT_CERTIFICATE_VERIFY
                    16 => Err(Error::Done),

                    _ => Err(Error::TlsFail("SSL error, unknown".to_string())),
                }
            }
        }
    }

    fn set_transport_error(&mut self, session_data: &mut tls::TlsSessionData, bssl_result: c_int) {
        if self.get_error(bssl_result) == 1 {
            // SSL_ERROR_SSL error.
            // See https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_get_error
            if session_data.error.is_none() {
                session_data.error = Some(tls::TlsError {
                    error_code: 0x01,
                    reason: Vec::new(),
                })
            }
        }
    }
}

unsafe impl std::marker::Send for Session {}

unsafe impl std::marker::Sync for Session {}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { SSL_free(self.as_mut_ptr()) }
    }
}

fn get_sess_data_from_ptr<'a, T>(ptr: *mut Ssl, idx: c_int) -> Option<&'a mut T> {
    unsafe {
        let data = SSL_get_ex_data(ptr, idx) as *mut T;
        data.as_mut()
    }
}

fn get_cipher_from_ptr(cipher: *const SslCipher) -> Result<crypto::Algorithm> {
    let cipher_id = unsafe { SSL_CIPHER_get_id(cipher) };

    let algor = match cipher_id {
        0x0300_1301 => crypto::Algorithm::Aes128Gcm,
        0x0300_1302 => crypto::Algorithm::Aes256Gcm,
        0x0300_1303 => crypto::Algorithm::ChaCha20Poly1305,
        _ => return Err(Error::TlsFail("unsupported cipher".to_string())),
    };

    Ok(algor)
}

/// set_read_secret configures the read secret and cipher suite for the given
/// encryption level. It returns one on success and zero to terminate the
/// handshake with an error. It will be called at most once per encryption
/// level.
extern "C" fn set_read_secret(
    ssl: *mut Ssl,
    level: tls::Level,
    cipher: *const SslCipher,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    trace!(
        "{} set read secret level {:?}",
        session_data.trace_id,
        level
    );

    let keys = &mut session_data.key_collection[level];

    let aead = match get_cipher_from_ptr(cipher) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if level != tls::Level::ZeroRTT || session_data.is_server {
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };

        let open = match crypto::Open::new_with_secret(aead, secret) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        keys.open = Some(open);
    }

    1
}

/// set_write_secret configures the write secret and cipher suite for the given
/// encryption level. It will be called at most once per encryption level.
extern "C" fn set_write_secret(
    ssl: *mut Ssl,
    level: tls::Level,
    cipher: *const SslCipher,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    trace!(
        "{} set write secret level {:?}",
        session_data.trace_id,
        level
    );

    let keys = &mut session_data.key_collection[level];

    let aead = match get_cipher_from_ptr(cipher) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if level != tls::Level::ZeroRTT || !session_data.is_server {
        let secret = unsafe { slice::from_raw_parts(secret, secret_len) };

        let seal = match crypto::Seal::new_with_secret(aead, secret) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        keys.seal = Some(seal);
    }

    1
}

/// add_handshake_data adds handshake data to the current flight at the given
/// encryption level. It returns one on success and zero on error.
extern "C" fn add_handshake_data(
    ssl: *mut Ssl,
    level: tls::Level,
    data: *const u8,
    len: usize,
) -> c_int {
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    trace!(
        "{} write message level {:?} len {}",
        session_data.trace_id,
        level,
        len
    );

    let buf = unsafe { slice::from_raw_parts(data, len) };
    if session_data.write_method.is_none()
        || (session_data.write_method.as_mut().unwrap())(level, buf).is_err()
    {
        return 0;
    }

    1
}

/// flush_flight is called when the current flight is complete and should be
/// written to the transport.
/// Nothing is done since the crypto data is sent separately, see try_write_crypto_frame.
extern "C" fn flush_flight(_ssl: *mut Ssl) -> c_int {
    1
}

/// send_alert sends a fatal alert at the specified encryption level. It
/// returns one on success and zero on error.
extern "C" fn send_alert(ssl: *mut Ssl, level: tls::Level, alert: u8) -> c_int {
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    trace!(
        "{} send alert level {:?} alert {:x}",
        session_data.trace_id,
        level,
        alert
    );

    const TLS_ALERT_ERROR: u64 = 0x100;
    let error: u64 = TLS_ALERT_ERROR + u64::from(alert);
    session_data.error = Some(tls::TlsError {
        error_code: error,
        reason: Vec::new(),
    });

    1
}

/// A callback to log key material. This is intended for debugging use with
/// tools like Wireshark. The cb function should log line followed by a
/// newline, synchronizing with any concurrent access to the log.
///
/// The output is NSS key log format which is described in:
/// https://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format.
extern "C" fn keylog(ssl: *mut Ssl, line: *const c_char) {
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return,
    };

    if let Some(keylog) = &mut session_data.keylog {
        let data = unsafe { ffi::CStr::from_ptr(line).to_bytes() };

        let mut full_line = Vec::with_capacity(data.len() + 1);
        full_line.extend_from_slice(data);
        full_line.push(b'\n');

        keylog.write_all(&full_line[..]).ok();
    }
}

/// A callback function that is called during ClientHello processing in order to
/// select an ALPN protocol from the client's list of offered protocols.
extern "C" fn select_alpn(
    ssl: *mut Ssl,
    out: *mut *const u8,
    out_len: *mut u8,
    inp: *mut u8,
    in_len: c_uint,
    _arg: *mut c_void,
) -> c_int {
    // Get customized session data.
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 3, // SSL_TLSEXT_ERR_NOACK
    };

    // Get customized context data.
    let ctx = unsafe { SSL_get_SSL_CTX(ssl) };
    let application_protos = match get_ctx_data_from_ptr::<Vec<Vec<u8>>>(ctx, *CONTEXT_DATA_INDEX) {
        Some(v) => v,
        None => return 3, // SSL_TLSEXT_ERR_NOACK
    };

    if application_protos.is_empty() {
        return 3; // SSL_TLSEXT_ERR_NOACK
    }

    // Select an ALPN protocol.
    let mut protos = unsafe { slice::from_raw_parts(inp, in_len as usize) };
    while let Ok(proto) = protos.read_with_u8_length() {
        let found = application_protos.iter().any(|expected| {
            trace!(
                "{} peer ALPN {:?} expected {:?}",
                session_data.trace_id,
                std::str::from_utf8(proto.as_ref()),
                std::str::from_utf8(expected.as_slice())
            );

            if expected.len() == proto.len() && expected.as_slice() == proto.as_slice() {
                unsafe {
                    *out = expected.as_slice().as_ptr();
                    *out_len = expected.len() as u8;
                }
                return true;
            }

            false
        });

        if found {
            return 0; // SSL_TLSEXT_ERR_OK
        }
    }

    3 // SSL_TLSEXT_ERR_NOACK
}

/// A callback function that is called after extensions have been processed, but before the
/// resumption decision has been made.
extern "C" fn select_cert(ssl: *mut Ssl, _arg: *mut c_void) -> c_int {
    // Get customized session data.
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    // Get server name.
    let server_name = unsafe {
        let ptr = SSL_get_servername(
            ssl, 0, // TLSEXT_NAMETYPE_host_name
        );
        if ptr.is_null() {
            trace!("{} no server name", session_data.trace_id);
            return 1;
        }
        ffi::CStr::from_ptr(ptr)
    };

    let server_name = server_name.to_str();
    if server_name.is_err() {
        trace!("{} server name invalid", session_data.trace_id);
        return 1;
    }
    let server_name = server_name.unwrap();

    trace!("{} select cert for {}", session_data.trace_id, server_name);
    if let Some(config_selector) = &session_data.conf_selector {
        // Select customized tls config based on the server name.
        let tls_config = config_selector.select(server_name);
        if tls_config.is_none() {
            trace!(
                "{} select cert for {} failed.",
                session_data.trace_id,
                server_name
            );
            return 0;
        }

        // Apply the customized tls config for the SSL connection.
        let tls_ctx = &tls_config.unwrap().tls_ctx;
        let ssl_ctx = unsafe { SSL_set_SSL_CTX(ssl, tls_ctx.as_ptr()) };
        if ssl_ctx.is_null() {
            trace!("{} set SSL_CTX failed", session_data.trace_id);
            return 0;
        }
    }

    1
}

/// A callback to be called when a new session is established and ready to be cached.
extern "C" fn new_session(ssl: *mut Ssl, ssl_session: *mut SslSession) -> c_int {
    let session_data = match get_sess_data_from_ptr::<tls::TlsSessionData>(ssl, *SESSION_DATA_INDEX)
    {
        Some(v) => v,
        None => return 0,
    };

    let session = Session::new(ssl);
    let peer_params = session.quic_transport_params();

    // Get SSL session.
    let session_bytes = unsafe {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        if SSL_SESSION_to_bytes(ssl_session, &mut out, &mut out_len) == 0 {
            return 0;
        }

        let session_bytes = std::slice::from_raw_parts(out, out_len).to_vec();
        OPENSSL_free(out as *mut c_void);
        session_bytes
    };

    let mut buffer = Vec::with_capacity(8 + peer_params.len() + 8 + session_bytes.len());

    // Encode SSL session data.
    let session_bytes_len = session_bytes.len() as u64;
    if buffer.write(&session_bytes_len.to_be_bytes()).is_err() {
        std::mem::forget(session);
        return 0;
    }
    if buffer.write(&session_bytes).is_err() {
        std::mem::forget(session);
        return 0;
    }

    // Encode peer transport parameters.
    let peer_params_len = peer_params.len() as u64;
    if buffer.write(&peer_params_len.to_be_bytes()).is_err() {
        std::mem::forget(session);
        return 0;
    }
    if buffer.write(peer_params).is_err() {
        std::mem::forget(session);
        return 0;
    }

    session_data.session = Some(buffer);

    std::mem::forget(session);
    0
}

fn map_result_ptr<'a, T>(bssl_result: *const T) -> Result<&'a T> {
    match unsafe { bssl_result.as_ref() } {
        Some(v) => Ok(v),
        None => Err(Error::TlsFail("pointer as reference error".to_string())),
    }
}

fn get_ssl_error() -> Result<String> {
    let err = [0; 1024];

    unsafe {
        let e = ERR_peek_error();
        ERR_error_string_n(e, err.as_ptr(), err.len());
    }

    let err = std::str::from_utf8(&err)
        .map_err(|e| Error::TlsFail(format!("ssl error message format incorrect: {:?}", e)))?;

    Ok(err.trim_end_matches('\0').to_string())
}

extern "C" {
    /// SSL_METHOD used for TLS connections.
    fn TLS_method() -> *const SslMethod;

    /// Return a newly-allocated SslCtx with default settings or NULL on error.
    fn SSL_CTX_new(method: *const SslMethod) -> *mut SslCtx;

    /// Release memory associated with ctx.
    fn SSL_CTX_free(ctx: *mut SslCtx);

    /// Configure certificate for ctx.
    fn SSL_CTX_use_certificate_chain_file(ctx: *mut SslCtx, file: *const c_char) -> c_int;

    /// Configure private key for ctx.
    fn SSL_CTX_use_PrivateKey_file(ctx: *mut SslCtx, file: *const c_char, ty: c_int) -> c_int;

    /// Load trust anchors from file.
    fn SSL_CTX_load_verify_locations(
        ctx: *mut SslCtx,
        file: *const c_char,
        path: *const c_char,
    ) -> c_int;

    /// Load trust anchors from directory in OpenSSL's hashed directory format.
    fn SSL_CTX_set_default_verify_paths(ctx: *mut SslCtx) -> c_int;

    /// Configure certificate verification behavior.
    fn SSL_CTX_set_verify(ctx: *mut SslCtx, mode: c_int, cb: *const c_void);

    /// Configure a callback to log key material.
    fn SSL_CTX_set_keylog_callback(
        ctx: *mut SslCtx,
        cb: extern "C" fn(ssl: *mut Ssl, line: *const c_char),
    );

    /// Set session ticket key.
    fn SSL_CTX_set_tlsext_ticket_keys(ctx: *mut SslCtx, key: *const u8, key_len: usize) -> c_int;

    /// Set the client ALPN protocol list.
    /// protos must be in wire-format (i.e. a series of non-empty, 8-bit length-prefixed strings),
    /// or the empty string to disable ALPN.
    /// Return zero on success and one on failure.
    fn SSL_CTX_set_alpn_protos(ctx: *mut SslCtx, protos: *const u8, protos_len: usize) -> c_int;

    /// Set a callback function on ctx that is called during ClientHello processing in order to
    /// select an ALPN protocol from the client's list of offered protocols.
    fn SSL_CTX_set_alpn_select_cb(
        ctx: *mut SslCtx,
        cb: extern "C" fn(
            ssl: *mut Ssl,
            out: *mut *const u8,
            out_len: *mut u8,
            inp: *mut u8,
            in_len: c_uint,
            arg: *mut c_void,
        ) -> c_int,
        arg: *mut c_void,
    );

    /// Set whether early data is allowed.
    fn SSL_CTX_set_early_data_enabled(ctx: *mut SslCtx, enabled: i32);

    /// Set the session cache mode.
    fn SSL_CTX_set_session_cache_mode(ctx: *mut SslCtx, mode: c_int) -> c_int;

    /// Set the callback to be called when a new session is established and ready to be cached.
    fn SSL_CTX_sess_set_new_cb(
        ctx: *mut SslCtx,
        cb: extern "C" fn(ssl: *mut Ssl, session: *mut SslSession) -> c_int,
    );

    /// Get the new index of allocated for SSL_CTX extra data.
    fn SSL_CTX_get_ex_new_index(
        argl: c_long,
        argp: *const c_void,
        unused: *const c_void,
        dup_unused: *const c_void,
        free_func: extern "C" fn(
            parent: *mut c_void,
            ptr: *mut c_void,
            ad: *mut CryptoExData,
            index: c_int,
            arg1: c_long,
            argp: *mut c_void,
        ),
    ) -> c_int;

    /// Store arbitrary user data into the SSL object. The user must supply a
    /// unique index which they can subsequently use to retrieve the data
    /// using SSL*_get_ex_data().
    fn SSL_CTX_set_ex_data(ctx: *mut SslCtx, idx: c_int, ptr: *const c_void) -> c_int;

    /// Return the user data indexed by the unique index.
    fn SSL_CTX_get_ex_data(ctx: *mut SslCtx, idx: c_int) -> *mut c_void;

    /// Change ssl's SSL_CTX. ssl will use the certificate-related settings from ctx,
    /// and SSL_get_SSL_CTX will report ctx.
    /// This function may be used during the callbacks registered by
    /// SSL_CTX_set_select_certificate_cb, SSL_CTX_set_tlsext_servername_callback, and
    /// SSL_CTX_set_cert_cb or when the handshake is paused from them.
    /// It is typically used to switch certificates based on SNI.
    /// Note the session cache and related settings will continue to use the initial SSL_CTX.
    fn SSL_set_SSL_CTX(ssl: *mut Ssl, ssl_ctx: *const SslCtx) -> *mut SslCtx;

    /// Return SslCtx associated with ssl.
    fn SSL_get_SSL_CTX(ssl: *const Ssl) -> *mut SslCtx;

    /// Get the new index of allocated for SSL extra data.
    fn SSL_get_ex_new_index(
        argl: c_long,
        argp: *const c_void,
        unused: *const c_void,
        dup_unused: *const c_void,
        free_func: *const c_void,
    ) -> c_int;

    /// Return a newly-allocated Ssl with default settings or NULL on error.
    fn SSL_new(ctx: *const SslCtx) -> *mut Ssl;

    /// Set a callback that is called to select a certificate.
    /// The callback returns one on success, zero on internal error, and a negative number
    /// on failure or to pause the handshake.
    /// The callback will be called after extensions have been processed, but before the resumption
    /// decision has been made.
    fn SSL_set_cert_cb(
        ssl: *mut Ssl,
        cb: extern "C" fn(ssl: *mut Ssl, arg: *mut c_void) -> c_int,
        arg: *mut c_void,
    );

    /// Configure ssl to be a server.
    fn SSL_set_accept_state(ssl: *mut Ssl);

    /// Configure ssl to be a client.
    fn SSL_set_connect_state(ssl: *mut Ssl);

    /// Store arbitrary user data into the SSL object. The user must supply a
    /// unique index which they can subsequently use to retrieve the data
    /// using SSL*_get_ex_data().
    fn SSL_set_ex_data(ssl: *mut Ssl, idx: c_int, ptr: *const c_void) -> c_int;

    /// Return the user data indexed by the unique index.
    fn SSL_get_ex_data(ssl: *mut Ssl, idx: c_int) -> *mut c_void;

    /// Configure the quic_transport_parameters extension in either the ClientHello or EncryptedExtensions.
    fn SSL_set_quic_transport_params(ssl: *mut Ssl, params: *const u8, params_len: usize) -> c_int;

    /// Get the quic_transport_parameters extension sent by the peer.
    fn SSL_get_peer_quic_transport_params(
        ssl: *const Ssl,
        out_params: *mut *const u8,
        out_params_len: *mut usize,
    );

    /// For a client, configure the session resumption.
    fn SSL_set_session(ssl: *mut Ssl, session: *mut SslSession) -> c_int;

    /// Set the minimum TLS protocol versions to be used.
    fn SSL_set_min_proto_version(ssl: *mut Ssl, version: u16);

    /// Set the maximum TLS protocol versions to be used.
    fn SSL_set_max_proto_version(ssl: *mut Ssl, version: u16);

    /// Set quiet shutdown mode.
    fn SSL_set_quiet_shutdown(ssl: *mut Ssl, mode: c_int);

    /// For a client, set the hostname to be used for SNI.
    fn SSL_set_tlsext_host_name(ssl: *mut Ssl, name: *const c_char) -> c_int;

    /// Configure the QUIC hooks.
    fn SSL_set_quic_method(ssl: *mut Ssl, quic_method: *const SslQuicMethod) -> c_int;

    /// For a server, configure a context string for accepting early data.
    fn SSL_set_quic_early_data_context(
        ssl: *mut Ssl,
        context: *const u8,
        context_len: usize,
    ) -> c_int;

    /// Provide data from QUIC at a particular encryption level.
    fn SSL_provide_quic_data(
        ssl: *mut Ssl,
        level: tls::Level,
        data: *const u8,
        len: usize,
    ) -> c_int;

    /// Process any data that QUIC has provided after the handshake has completed.
    fn SSL_process_quic_post_handshake(ssl: *mut Ssl) -> c_int;

    /// Reset ssl after an early data reject.
    fn SSL_reset_early_data_reject(ssl: *mut Ssl);

    /// Continue the current handshake.
    fn SSL_do_handshake(ssl: *mut Ssl) -> c_int;

    /// Return the current write encryption level.
    fn SSL_quic_write_level(ssl: *const Ssl) -> tls::Level;

    /// Return true if performed an abbreviated handshake.
    fn SSL_session_reused(ssl: *const Ssl) -> c_int;

    /// Return true if the handshake is pending.
    fn SSL_in_init(ssl: *const Ssl) -> c_int;

    /// Return true if the pending handshake has progressed enough to send or receive early data.
    fn SSL_in_early_data(ssl: *const Ssl) -> c_int;

    /// Return error code for the last error that occurred on ssl.
    fn SSL_get_error(ssl: *const Ssl, ret_code: c_int) -> c_int;

    /// Return current cipher suite.
    fn SSL_get_current_cipher(ssl: *const Ssl) -> *const SslCipher;

    /// Return the id of the current cipher suite.
    fn SSL_get_curve_id(ssl: *const Ssl) -> u16;

    /// Return the name of the current cipher suite.
    fn SSL_get_curve_name(curve: u16) -> *const c_char;

    /// Return the signature algorithm used by the peer.
    fn SSL_get_peer_signature_algorithm(ssl: *const Ssl) -> u16;

    /// Return a human-readable name of the signature algorithm used by the peer.
    fn SSL_get_signature_algorithm_name(sigalg: u16, include_curve: i32) -> *const c_char;

    /// Return ssl's X509VerifyParam for certificate verification.
    fn SSL_get0_param(ssl: *mut Ssl) -> *mut X509VerifyParam;

    /// Return the peer's certificate chain.
    fn SSL_get0_peer_certificates(ssl: *const Ssl) -> *const StackOf;

    /// Get the selected ALPN protocol.
    fn SSL_get0_alpn_selected(ssl: *const Ssl, out: *mut *const u8, out_len: *mut u32);

    /// For a server, return the hostname supplied by the client.
    fn SSL_get_servername(ssl: *const Ssl, ty: c_int) -> *const c_char;

    /// Return details why 0-RTT was accepted or rejected on ssl.
    fn SSL_get_early_data_reason(ssl: *const Ssl) -> SslEarlyDataReason;

    /// Return a string representation for reason, or NULL if reason is unknown.
    fn SSL_early_data_reason_string(reason: SslEarlyDataReason) -> *const c_char;

    /// Reset ssl to allow another connection.
    fn SSL_clear(ssl: *mut Ssl) -> c_int;

    /// Release memory associated with ssl.
    fn SSL_free(ssl: *mut Ssl);

    /// Return cipher's non-IANA id.
    fn SSL_CIPHER_get_id(cipher: *const SslCipher) -> c_uint;

    /// Serialize session to bytes.
    fn SSL_SESSION_to_bytes(
        session: *const SslSession,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> c_int;

    /// Parse bytes into a session.
    fn SSL_SESSION_from_bytes(
        input: *const u8,
        input_len: usize,
        ctx: *const SslCtx,
    ) -> *mut SslSession;

    /// Decrements the reference count of session.
    /// If it reaches zero, all data referenced by session and session itself are released.
    fn SSL_SESSION_free(session: *mut SslSession);

    /// Set cerfificate verification hostname.
    fn X509_VERIFY_PARAM_set1_host(
        param: *mut X509VerifyParam,
        name: *const c_char,
        namelen: usize,
    ) -> c_int;

    /// Return the number of elements in stack.
    fn sk_num(stack: *const StackOf) -> c_int;

    /// Return the pointer to the element at idx in stack.
    fn sk_value(stack: *const StackOf, idx: c_int) -> *mut c_void;

    /// Return the length, in bytes, of the data contained in buffer.
    fn CRYPTO_BUFFER_len(buffer: *const CryptoBuffer) -> usize;

    /// Return a pointer to the data contained in buffer.
    fn CRYPTO_BUFFER_data(buffer: *const CryptoBuffer) -> *const u8;

    /// Get the packed error code for the least recent error but do not remove it from the queue.
    fn ERR_peek_error() -> c_uint;

    /// Generate a human-readable error string for err.
    fn ERR_error_string_n(err: c_uint, buf: *const u8, len: usize);

    /// Release memory associated with ptr.
    fn OPENSSL_free(ptr: *mut c_void);
}
