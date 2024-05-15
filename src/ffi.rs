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

// Note: The API is not stable and may change in future versions.

use std::ffi;
use std::io::Write;
use std::mem;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::os::fd::FromRawFd;
use std::ptr;
use std::rc::Rc;
use std::slice;
use std::str::FromStr;
use std::sync::atomic;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::in6_addr;
use libc::in_addr;
use libc::iovec;
use libc::sa_family_t;
use libc::size_t;
use libc::sockaddr;
use libc::sockaddr_in;
use libc::sockaddr_in6;
use libc::sockaddr_storage;
use libc::socklen_t;
use libc::ssize_t;
use libc::AF_INET;
use libc::AF_INET6;

use crate::codec::Decoder;
use crate::error::Error;
use crate::h3::connection::Http3Connection;
use crate::h3::connection::Http3Priority;
use crate::h3::Http3Config;
use crate::h3::Http3Event;
use crate::h3::Http3Headers;
use crate::h3::NameValue;
use crate::qlog::events;
use crate::tls::SslCtx;
use crate::tls::TlsConfig;
use crate::Config;
use crate::Connection;
use crate::Endpoint;
use crate::Result;
use crate::Shutdown;
use crate::*;

/// Check whether the protocol version is supported.
#[no_mangle]
pub extern "C" fn quic_version_is_supported(version: u32) -> bool {
    crate::version_is_supported(version)
}

struct LogWriter {
    cb: extern "C" fn(data: *const u8, data_len: size_t, argp: *mut c_void),
    argp: std::sync::atomic::AtomicPtr<c_void>,
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (self.cb)(
            buf.as_ptr(),
            buf.len(),
            self.argp.load(atomic::Ordering::Relaxed),
        );
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl log::Log for LogWriter {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let line = format!("{}: {}\n", record.target(), record.args());
        (self.cb)(
            line.as_ptr(),
            line.len(),
            self.argp.load(atomic::Ordering::Relaxed),
        );
    }

    fn flush(&self) {}
}

/// Create default configuration.
/// The caller is responsible for the memory of the Config and should properly
/// destroy it by calling `quic_config_free`.
#[no_mangle]
pub extern "C" fn quic_config_new() -> *mut Config {
    match Config::new() {
        Ok(conf) => Box::into_raw(Box::new(conf)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy a Config instance.
#[no_mangle]
pub extern "C" fn quic_config_free(config: *mut Config) {
    unsafe {
        let _ = Box::from_raw(config);
    };
}

/// Set the `max_idle_timeout` transport parameter in milliseconds.
#[no_mangle]
pub extern "C" fn quic_config_set_max_idle_timeout(config: &mut Config, v: u64) {
    config.set_max_idle_timeout(v);
}

/// Set handshake timeout in milliseconds. Zero turns the timeout off.
#[no_mangle]
pub extern "C" fn quic_config_set_max_handshake_timeout(config: &mut Config, v: u64) {
    config.set_max_handshake_timeout(v);
}

/// Set the `max_udp_payload_size` transport parameter in bytes. It limits
/// the size of UDP payloads that the endpoint is willing to receive.
#[no_mangle]
pub extern "C" fn quic_config_set_recv_udp_payload_size(config: &mut Config, v: u16) {
    config.set_recv_udp_payload_size(v);
}

/// Enable the Datagram Packetization Layer Path MTU Discovery
/// default value is true.
#[no_mangle]
pub extern "C" fn enable_dplpmtud(config: &mut Config, v: bool) {
    config.enable_dplpmtud(v);
}

/// Set the maximum outgoing UDP payload size in bytes.
/// It corresponds to the maximum datagram size that DPLPMTUD tries to discovery.
/// The default value is `1200` which means let DPLPMTUD choose a value.
#[no_mangle]
pub extern "C" fn quic_config_set_send_udp_payload_size(config: &mut Config, v: usize) {
    config.set_send_udp_payload_size(v);
}

/// Set the `initial_max_data` transport parameter. It means the initial
/// value for the maximum amount of data that can be sent on the connection.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_data(config: &mut Config, v: u64) {
    config.set_initial_max_data(v);
}

/// Set the `initial_max_stream_data_bidi_local` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_stream_data_bidi_local(config: &mut Config, v: u64) {
    config.set_initial_max_stream_data_bidi_local(v);
}

/// Set the `initial_max_stream_data_bidi_remote` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_stream_data_bidi_remote(config: &mut Config, v: u64) {
    config.set_initial_max_stream_data_bidi_remote(v);
}

/// Set the `initial_max_stream_data_uni` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_stream_data_uni(config: &mut Config, v: u64) {
    config.set_initial_max_stream_data_uni(v);
}

/// Set the `initial_max_streams_bidi` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_streams_bidi(config: &mut Config, v: u64) {
    config.set_initial_max_streams_bidi(v);
}

/// Set the `initial_max_streams_uni` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_streams_uni(config: &mut Config, v: u64) {
    config.set_initial_max_streams_uni(v);
}

/// Set the `ack_delay_exponent` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_ack_delay_exponent(config: &mut Config, v: u64) {
    config.set_ack_delay_exponent(v);
}

/// Set the `max_ack_delay` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_max_ack_delay(config: &mut Config, v: u64) {
    config.set_max_ack_delay(v);
}

/// Set congestion control algorithm that the connection would use.
#[no_mangle]
pub extern "C" fn quic_config_set_congestion_control_algorithm(
    config: &mut Config,
    v: CongestionControlAlgorithm,
) {
    config.set_congestion_control_algorithm(v);
}

/// Set the initial congestion window in packets.
/// The default value is 10.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_congestion_window(config: &mut Config, v: u64) {
    config.set_initial_congestion_window(v);
}

/// Set the minimal congestion window in packets.
/// The default value is 2.
#[no_mangle]
pub extern "C" fn quic_config_set_min_congestion_window(config: &mut Config, v: u64) {
    config.set_min_congestion_window(v);
}

/// Set the initial RTT in milliseconds. The default value is 333ms.
/// The configuration should be changed with caution. Setting a value less than the default
/// will cause retransmission of handshake packets to be more aggressive.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_rtt(config: &mut Config, v: u64) {
    config.set_initial_rtt(v);
}

/// Set the linear factor for calculating the probe timeout.
/// The endpoint do not backoff the first `v` consecutive probe timeouts.
/// The default value is `0`.
/// The configuration should be changed with caution. Setting a value greater than the default
/// will cause retransmission to be more aggressive.
#[no_mangle]
pub extern "C" fn quic_config_set_pto_linear_factor(config: &mut Config, v: u64) {
    config.set_pto_linear_factor(v);
}

/// Set the upper limit of probe timeout in milliseconds.
/// A Probe Timeout (PTO) triggers the sending of one or two probe datagrams and enables a
/// connection to recover from loss of tail packets or acknowledgments.
/// See RFC 9002 Section 6.2.
#[no_mangle]
pub extern "C" fn quic_config_set_max_pto(config: &mut Config, v: u64) {
    config.set_max_pto(v);
}

/// Set the `active_connection_id_limit` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_active_connection_id_limit(config: &mut Config, v: u64) {
    config.set_active_connection_id_limit(v);
}

/// Set the `enable_multipath` transport parameter.
/// The default value is false. (Experimental)
#[no_mangle]
pub extern "C" fn quic_config_enable_multipath(config: &mut Config, enabled: bool) {
    config.enable_multipath(enabled);
}

/// Set the multipath scheduling algorithm
/// The default value is MultipathAlgorithm::MinRtt
#[no_mangle]
pub extern "C" fn quic_config_set_multipath_algorithm(config: &mut Config, v: MultipathAlgorithm) {
    config.set_multipath_algorithm(v);
}

/// Set the maximum size of the connection flow control window.
#[no_mangle]
pub extern "C" fn quic_config_set_max_connection_window(config: &mut Config, v: u64) {
    config.set_max_connection_window(v);
}

/// Set the maximum size of the stream flow control window.
#[no_mangle]
pub extern "C" fn quic_config_set_max_stream_window(config: &mut Config, v: u64) {
    config.set_max_stream_window(v);
}

/// Set the Maximum number of concurrent connections.
#[no_mangle]
pub extern "C" fn quic_config_set_max_concurrent_conns(config: &mut Config, v: u32) {
    config.set_max_concurrent_conns(v);
}

/// Set the key for reset token generation. The token_key_len should be not less
/// than 64.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_set_reset_token_key(
    config: &mut Config,
    token_key: *const u8,
    token_key_len: size_t,
) -> c_int {
    const RTK_LEN: usize = 64;
    if token_key_len < RTK_LEN {
        let e = Error::InvalidConfig("reset token key".into());
        return e.to_errno() as c_int;
    };

    let token_key = unsafe { slice::from_raw_parts(token_key, RTK_LEN) };
    let mut key = [0; RTK_LEN];
    key.copy_from_slice(token_key);
    config.set_reset_token_key(key);
    0
}

/// Set the lifetime of address token.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_set_address_token_lifetime(config: &mut Config, seconds: u64) {
    config.set_address_token_lifetime(seconds);
}

/// Set the key for address token generation. It also enables retry.
/// The token_key_len should be a multiple of 16.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_set_address_token_key(
    config: &mut Config,
    token_keys: *const u8,
    token_keys_len: size_t,
) -> c_int {
    const ATK_LEN: usize = 16;
    if token_keys_len < ATK_LEN || token_keys_len % ATK_LEN != 0 {
        let e = Error::InvalidConfig("address token key".into());
        return e.to_errno() as c_int;
    }

    let mut token_keys = unsafe { slice::from_raw_parts(token_keys, token_keys_len) };
    let mut keys = Vec::new();
    while !token_keys.is_empty() {
        let mut key = [0u8; ATK_LEN];
        key.copy_from_slice(&token_keys[..ATK_LEN]);
        keys.push(key);
        token_keys = &token_keys[ATK_LEN..];
    }

    match config.set_address_token_key(keys) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set whether stateless retry is allowed. Default is not allowed.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_enable_retry(config: &mut Config, enabled: bool) {
    config.enable_retry(enabled);
}

/// Set whether stateless reset is allowed.
/// Applicable to Endpoint only.
#[no_mangle]
pub extern "C" fn quic_config_enable_stateless_reset(config: &mut Config, enabled: bool) {
    config.enable_stateless_reset(enabled);
}

/// Set the length of source cid. The length should not be greater than 20.
/// Applicable to Endpoint only.
#[no_mangle]
pub extern "C" fn quic_config_set_cid_len(config: &mut Config, v: u8) {
    config.set_cid_len(v as usize);
}

/// Set the batch size for sending packets.
/// Applicable to Endpoint only.
#[no_mangle]
pub extern "C" fn quic_config_set_send_batch_size(config: &mut Config, v: u16) {
    config.set_send_batch_size(v as usize);
}

/// Set the buffer size for disordered zerortt packets on the server.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_set_zerortt_buffer_size(config: &mut Config, v: u16) {
    config.set_zerortt_buffer_size(v as usize);
}

/// Create a new TlsConfig.
/// The caller is responsible for the memory of the TlsConfig and should properly
/// destroy it by calling `quic_tls_config_free`.
#[no_mangle]
pub extern "C" fn quic_tls_config_new() -> *mut TlsConfig {
    match TlsConfig::new() {
        Ok(tls_config) => Box::into_raw(Box::new(tls_config)),
        Err(_) => ptr::null_mut(),
    }
}

/// Create a new TlsConfig with SSL_CTX.
/// When using raw SSL_CTX, TlsSession::session() and TlsSession::set_keylog() won't take effect.
/// The caller is responsible for the memory of TlsConfig and SSL_CTX when use this function.
#[no_mangle]
pub extern "C" fn quic_tls_config_new_with_ssl_ctx(ssl_ctx: *mut SslCtx) -> *mut TlsConfig {
    Box::into_raw(Box::new(TlsConfig::new_with_ssl_ctx(ssl_ctx)))
}

fn convert_application_protos(protos: *const *const c_char, proto_num: isize) -> Vec<Vec<u8>> {
    let mut application_protos = vec![];
    for i in 0..proto_num {
        let proto = unsafe { (*protos).offset(i) };
        if proto.is_null() {
            continue;
        }

        let proto = unsafe { ffi::CStr::from_ptr(proto).to_bytes().to_vec() };
        application_protos.push(proto);
    }

    application_protos
}

/// Create a new client side TlsConfig.
/// The caller is responsible for the memory of the TlsConfig and should properly
/// destroy it by calling `quic_tls_config_free`.
#[no_mangle]
pub extern "C" fn quic_tls_config_new_client_config(
    protos: *const *const c_char,
    proto_num: isize,
    enable_early_data: bool,
) -> *mut TlsConfig {
    if protos.is_null() {
        return ptr::null_mut();
    }

    let application_protos = convert_application_protos(protos, proto_num);
    match TlsConfig::new_client_config(application_protos, enable_early_data) {
        Ok(tls_config) => Box::into_raw(Box::new(tls_config)),
        Err(_) => ptr::null_mut(),
    }
}

/// Create a new server side TlsConfig.
/// The caller is responsible for the memory of the TlsConfig and should properly
/// destroy it by calling `quic_tls_config_free`.
#[no_mangle]
pub extern "C" fn quic_tls_config_new_server_config(
    cert_file: *const c_char,
    key_file: *const c_char,
    protos: *const *const c_char,
    proto_num: isize,
    enable_early_data: bool,
) -> *mut TlsConfig {
    if cert_file.is_null() || key_file.is_null() || protos.is_null() {
        return ptr::null_mut();
    }

    let application_protos = convert_application_protos(protos, proto_num);
    let cert_file = unsafe {
        match ffi::CStr::from_ptr(cert_file).to_str() {
            Ok(cert_file) => cert_file,
            Err(_) => return ptr::null_mut(),
        }
    };
    let key_file = unsafe {
        match ffi::CStr::from_ptr(key_file).to_str() {
            Ok(key_file) => key_file,
            Err(_) => return ptr::null_mut(),
        }
    };
    match TlsConfig::new_server_config(&cert_file, &key_file, application_protos, enable_early_data)
    {
        Ok(tls_config) => Box::into_raw(Box::new(tls_config)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy a TlsConfig instance.
#[no_mangle]
pub extern "C" fn quic_tls_config_free(tls_config: *mut TlsConfig) {
    unsafe {
        let _ = Box::from_raw(tls_config);
    };
}

/// Set whether early data is allowed.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_early_data_enabled(tls_config: &mut TlsConfig, enable: bool) {
    tls_config.set_early_data_enabled(enable)
}

/// Set the list of supported application protocols.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_application_protos(
    tls_config: &mut TlsConfig,
    protos: *const *const c_char,
    proto_num: isize,
) -> c_int {
    if protos.is_null() {
        return -1;
    }

    let application_protos = convert_application_protos(protos, proto_num);
    match tls_config.set_application_protos(application_protos) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set session ticket key for server.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_ticket_key(
    tls_config: &mut TlsConfig,
    ticket_key: *const u8,
    ticket_key_len: size_t,
) -> c_int {
    let ticket_key = unsafe { slice::from_raw_parts(ticket_key, ticket_key_len) };
    match tls_config.set_ticket_key(&ticket_key) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set the certificate verification behavior.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_verify(tls_config: &mut TlsConfig, verify: bool) {
    tls_config.set_verify(verify)
}

/// Set the PEM-encoded certificate file.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_certificate_file(
    tls_config: &mut TlsConfig,
    cert_file: *const c_char,
) -> c_int {
    if cert_file.is_null() {
        return -1;
    }

    let cert_file = unsafe {
        match ffi::CStr::from_ptr(cert_file).to_str() {
            Ok(cert_file) => cert_file,
            Err(_) => return -1,
        }
    };
    match tls_config.set_certificate_file(&cert_file) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set the PEM-encoded private key file.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_private_key_file(
    tls_config: &mut TlsConfig,
    key_file: *const c_char,
) -> c_int {
    if key_file.is_null() {
        return -1;
    }

    let key_file = unsafe {
        match ffi::CStr::from_ptr(key_file).to_str() {
            Ok(key_file) => key_file,
            Err(_) => return -1,
        }
    };
    match tls_config.set_private_key_file(&key_file) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set CA certificates.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_ca_certs(
    tls_config: &mut TlsConfig,
    ca_path: *const c_char,
) -> c_int {
    if ca_path.is_null() {
        return -1;
    }

    let ca_path = unsafe {
        match ffi::CStr::from_ptr(ca_path).to_str() {
            Ok(ca_path) => ca_path,
            Err(_) => return -1,
        }
    };
    match tls_config.set_ca_certs(&ca_path) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set TLS config selector.
#[no_mangle]
pub extern "C" fn quic_config_set_tls_selector(
    config: &mut Config,
    methods: *const TlsConfigSelectMethods,
    context: TlsConfigSelectorContext,
) {
    let selector = TlsConfigSelector { methods, context };
    config.set_tls_config_selector(Arc::new(selector));
}

/// Set TLS config.
///
/// Note: Config doesn't own the TlsConfig when using this function.
/// It is the responsibility of the caller to release it.
#[no_mangle]
pub extern "C" fn quic_config_set_tls_config(config: &mut Config, tls_config: *mut TlsConfig) {
    if tls_config.is_null() {
        return;
    }

    let tls_config = unsafe { tls_config.as_mut().unwrap() };
    let tls_config = TlsConfig::new_with_ssl_ctx(tls_config.ssl_ctx());
    config.set_tls_config(tls_config);
}

/// Create a QUIC endpoint.
///
/// The caller is responsible for the memory of the Endpoint and properly
/// destroy it by calling `quic_endpoint_free`.
///
/// Note: The endpoint doesn't own the underlying resources provided by the C
/// caller. It is the responsibility of the caller to ensure that these
/// resources outlive the endpoint and release them correctly.
#[no_mangle]
pub extern "C" fn quic_endpoint_new(
    config: *mut Config,
    is_server: bool,
    handler_methods: *const TransportMethods,
    handler_ctx: TransportContext,
    sender_methods: *const PacketSendMethods,
    sender_ctx: PacketSendContext,
) -> *mut Endpoint {
    let config = unsafe { Box::from_raw(config) };
    let handler = Box::new(TransportHandler {
        methods: handler_methods,
        context: handler_ctx,
    });
    let sender = Rc::new(PacketSendHandler {
        methods: sender_methods,
        context: sender_ctx,
    });
    let e = Endpoint::new(config.clone(), is_server, handler, sender);
    Box::into_raw(config);
    Box::into_raw(Box::new(e))
}

/// Destroy a QUIC endpoint.
#[no_mangle]
pub extern "C" fn quic_endpoint_free(endpoint: *mut Endpoint) {
    unsafe {
        let _ = Box::from_raw(endpoint);
    };
}

/// Create a client connection.
/// If success, the output parameter `index` carrys the index of the connection.
/// Note: The `config` specific to the endpoint or server is irrelevant and will be disregarded.
#[no_mangle]
pub extern "C" fn quic_endpoint_connect(
    endpoint: &mut Endpoint,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
    server_name: *const c_char,
    session: *const u8,
    session_len: size_t,
    token: *const u8,
    token_len: size_t,
    config: *const Config,
    index: *mut u64,
) -> c_int {
    let local = sock_addr_from_c(local, local_len);
    let remote = sock_addr_from_c(remote, remote_len);

    let server_name = if !server_name.is_null() {
        Some(unsafe {
            ffi::CStr::from_ptr(server_name)
                .to_str()
                .unwrap_or_default()
        })
    } else {
        None
    };

    let session = if session_len > 0 {
        Some(unsafe { slice::from_raw_parts(session, session_len) })
    } else {
        None
    };
    let token = if token_len > 0 {
        Some(unsafe { slice::from_raw_parts(token, token_len) })
    } else {
        None
    };
    let config = if !config.is_null() {
        Some(unsafe { &(*config) })
    } else {
        None
    };

    match endpoint.connect(local, remote, server_name, session, token, config) {
        Ok(idx) => {
            if !index.is_null() {
                unsafe {
                    *index = idx;
                }
            }
            0
        }
        Err(e) => e.to_errno() as i32,
    }
}

/// Process an incoming UDP datagram.
#[no_mangle]
pub extern "C" fn quic_endpoint_recv(
    endpoint: &mut Endpoint,
    buf: *mut u8,
    buf_len: size_t,
    info: &PacketInfo,
) -> c_int {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };

    let info: crate::PacketInfo = info.into();
    match endpoint.recv(buf, &info) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

/// Return the amount of time until the next timeout event.
#[no_mangle]
pub extern "C" fn quic_endpoint_timeout(endpoint: &Endpoint) -> u64 {
    match endpoint.timeout() {
        Some(v) => v.as_millis() as u64,
        None => std::u64::MAX,
    }
}

/// Process timeout events on the endpoint.
#[no_mangle]
pub extern "C" fn quic_endpoint_on_timeout(endpoint: &mut Endpoint) {
    let now = Instant::now();
    endpoint.on_timeout(now);
}

/// Process internal events of all tickable connections.
#[no_mangle]
pub extern "C" fn quic_endpoint_process_connections(endpoint: &mut Endpoint) -> c_int {
    match endpoint.process_connections() {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

/// Check whether the given connection exists.
#[no_mangle]
pub extern "C" fn quic_endpoint_exist_connection(
    endpoint: &mut Endpoint,
    cid: *const u8,
    cid_len: size_t,
) -> bool {
    let cid = unsafe { slice::from_raw_parts(cid, cid_len) };
    endpoint.conn_exist(ConnectionId::new(cid))
}

/// Get the connection by index
#[no_mangle]
pub extern "C" fn quic_endpoint_get_connection(
    endpoint: &mut Endpoint,
    index: u64,
) -> *mut Connection {
    match endpoint.conn_get_mut(index) {
        Some(v) => v,
        None => ptr::null_mut(),
    }
}

/// Gracefully or forcibly shutdown the endpoint.
/// If `force` is false, cease creating new connections and wait for all
/// active connections to close. Otherwise, forcibly close all the active
/// connections.
#[no_mangle]
pub extern "C" fn quic_endpoint_close(endpoint: &mut Endpoint, force: bool) {
    endpoint.close(force)
}

/// Get index of the connection
#[no_mangle]
pub extern "C" fn quic_conn_index(conn: &mut Connection) -> u64 {
    conn.index().unwrap_or(u64::MAX)
}

/// Check whether the connection is a server connection.
#[no_mangle]
pub extern "C" fn quic_conn_is_server(conn: &mut Connection) -> bool {
    conn.is_server()
}

/// Check whether the connection handshake is complete.
#[no_mangle]
pub extern "C" fn quic_conn_is_established(conn: &mut Connection) -> bool {
    conn.is_established()
}

/// Check whether the connection is created by a resumed handshake.
#[no_mangle]
pub extern "C" fn quic_conn_is_resumed(conn: &mut Connection) -> bool {
    conn.is_resumed()
}

/// Check whether the connection has a pending handshake that has progressed
/// enough to send or receive early data.
#[no_mangle]
pub extern "C" fn quic_conn_is_in_early_data(conn: &mut Connection) -> bool {
    conn.is_in_early_data()
}

/// Check whether the established connection works in multipath mode.
#[no_mangle]
pub extern "C" fn quic_conn_is_multipath(conn: &mut Connection) -> bool {
    conn.is_multipath()
}

/// Return the negotiated application level protocol.
#[no_mangle]
pub extern "C" fn quic_conn_application_proto(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) {
    let proto = conn.application_proto();
    *out = proto.as_ptr();
    *out_len = proto.len();
}

/// Return the server name in the TLS SNI extension.
#[no_mangle]
pub extern "C" fn quic_conn_server_name(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) {
    if let Some(name) = conn.server_name() {
        *out = name.as_ptr();
        *out_len = name.len();
    } else {
        *out = ptr::null_mut();
        *out_len = 0;
    }
}

/// Return the session data used by resumption.
#[no_mangle]
pub extern "C" fn quic_conn_session(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) {
    match conn.session() {
        Some(session) => {
            *out = session.as_ptr();
            *out_len = session.len();
        }
        None => *out_len = 0,
    }
}

/// Return details why 0-RTT was accepted or rejected.
#[no_mangle]
pub extern "C" fn quic_conn_early_data_reason(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) -> c_int {
    match conn.early_data_reason() {
        Ok(reason) => {
            match reason {
                Some(reason) => {
                    *out = reason.as_ptr();
                    *out_len = reason.len();
                }
                None => *out_len = 0,
            }
            0
        }
        Err(e) => e.to_errno() as i32,
    }
}

/// Add a new path on the client connection.
#[no_mangle]
pub extern "C" fn quic_conn_add_path(
    conn: &mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
    index: *mut u64,
) -> c_int {
    let local = sock_addr_from_c(local, local_len);
    let remote = sock_addr_from_c(remote, remote_len);

    match conn.add_path(local, remote) {
        Ok(idx) => {
            if !index.is_null() {
                unsafe {
                    *index = idx;
                }
            }
            0
        }
        Err(e) => e.to_errno() as i32,
    }
}

/// Remove a path on the client connection.
#[no_mangle]
pub extern "C" fn quic_conn_abandon_path(
    conn: &mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
) -> c_int {
    let local = sock_addr_from_c(local, local_len);
    let remote = sock_addr_from_c(remote, remote_len);

    match conn.abandon_path(local, remote) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

/// Migrate the client connection to the specified path.
#[no_mangle]
pub extern "C" fn quic_conn_migrate_path(
    conn: &mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
) -> c_int {
    let local = sock_addr_from_c(local, local_len);
    let remote = sock_addr_from_c(remote, remote_len);

    match conn.migrate_path(local, remote) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

#[repr(C)]
pub struct PathAddress {
    local_addr: sockaddr_storage,
    local_addr_len: socklen_t,
    remote_addr: sockaddr_storage,
    remote_addr_len: socklen_t,
}

/// Return an iterator over path addresses.
/// The caller should properly destroy it by calling `quic_four_tuple_iter_free`.
#[no_mangle]
pub extern "C" fn quic_conn_paths(conn: &mut Connection) -> *mut FourTupleIter {
    let iter = Box::new(conn.paths_iter());
    Box::into_raw(iter)
}

/// Destroy the FourTupleIter
#[no_mangle]
pub extern "C" fn quic_conn_path_iter_free(iter: *mut FourTupleIter) {
    unsafe {
        let _ = Box::from_raw(iter);
    };
}

/// Return the address of the next path.
#[no_mangle]
pub extern "C" fn quic_conn_path_iter_next(iter: &mut FourTupleIter, a: &mut PathAddress) -> bool {
    if let Some(v) = iter.next() {
        a.local_addr_len = sock_addr_to_c(&v.local, &mut a.local_addr);
        a.remote_addr_len = sock_addr_to_c(&v.remote, &mut a.remote_addr);
        return true;
    }
    false
}

/// Return the address of the active path
#[no_mangle]
pub extern "C" fn quic_conn_active_path(conn: &Connection, a: &mut PathAddress) -> bool {
    if let Ok(v) = conn.get_active_path() {
        a.local_addr_len = sock_addr_to_c(&v.local_addr(), &mut a.local_addr);
        a.remote_addr_len = sock_addr_to_c(&v.remote_addr(), &mut a.remote_addr);
        return true;
    }
    false
}

/// Return the trace id of the connection
#[no_mangle]
pub extern "C" fn quic_conn_trace_id(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) {
    let id = conn.trace_id();
    *out = id.as_ptr();
    *out_len = id.len();
}

/// Check whether the connection is draining.
#[no_mangle]
pub extern "C" fn quic_conn_is_draining(conn: &mut Connection) -> bool {
    conn.is_draining()
}

/// Check whether the connection is closing.
#[no_mangle]
pub extern "C" fn quic_conn_is_closed(conn: &mut Connection) -> bool {
    conn.is_closed()
}

/// Check whether the connection was closed due to idle timeout.
#[no_mangle]
pub extern "C" fn quic_conn_is_idle_timeout(conn: &mut Connection) -> bool {
    conn.is_idle_timeout()
}

/// Check whether the connection was closed due to stateless reset.
#[no_mangle]
pub extern "C" fn quic_conn_is_reset(conn: &mut Connection) -> bool {
    conn.is_reset()
}

/// Returns the error from the peer, if any.
#[no_mangle]
pub extern "C" fn quic_conn_peer_error(
    conn: &mut Connection,
    is_app: *mut bool,
    error_code: *mut u64,
    reason: &mut *const u8,
    reason_len: &mut size_t,
) -> bool {
    match &conn.peer_error() {
        Some(conn_err) => unsafe {
            *is_app = conn_err.is_app;
            *error_code = conn_err.error_code;
            *reason = conn_err.reason.as_ptr();
            *reason_len = conn_err.reason.len();
            true
        },
        None => false,
    }
}

/// Returns the local error, if any.
#[no_mangle]
pub extern "C" fn quic_conn_local_error(
    conn: &mut Connection,
    is_app: *mut bool,
    error_code: *mut u64,
    reason: &mut *const u8,
    reason_len: &mut size_t,
) -> bool {
    match &conn.local_error() {
        Some(conn_err) => unsafe {
            *is_app = conn_err.is_app;
            *error_code = conn_err.error_code;
            *reason = conn_err.reason.as_ptr();
            *reason_len = conn_err.reason.len();
            true
        },
        None => false,
    }
}

/// Set user context for the connection.
#[no_mangle]
pub extern "C" fn quic_conn_set_context(conn: &mut Connection, data: *mut c_void) {
    conn.set_context(Context(data))
}

/// Get user context for the connection.
#[no_mangle]
pub extern "C" fn quic_conn_context(conn: &mut Connection) -> *mut c_void {
    match conn.context() {
        Some(v) => v.downcast_mut::<Context>().unwrap().0,
        None => ptr::null_mut(),
    }
}

/// Set the callback of keylog output.
/// `cb` is a callback function that will be called for each keylog.
/// `data` is a keylog message and `argp` is user-defined data that will be passed to the callback.
#[no_mangle]
pub extern "C" fn quic_conn_set_keylog(
    conn: &mut Connection,
    cb: extern "C" fn(data: *const u8, data_len: size_t, argp: *mut c_void),
    argp: *mut c_void,
) {
    let argp = atomic::AtomicPtr::new(argp);
    let writer = Box::new(LogWriter { cb, argp });
    conn.set_keylog(Box::new(writer));
}

/// Set keylog file.
#[no_mangle]
pub extern "C" fn quic_conn_set_keylog_fd(conn: &mut Connection, fd: c_int) {
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(file);
    conn.set_keylog(Box::new(writer));
}

/// Set the callback of qlog output.
/// `cb` is a callback function that will be called for each qlog.
/// `data` is a qlog message and `argp` is user-defined data that will be passed to the callback.
/// `title` and `desc` respectively refer to the "title" and "description" sections of qlog.
#[no_mangle]
pub extern "C" fn quic_conn_set_qlog(
    conn: &mut Connection,
    cb: extern "C" fn(data: *const u8, data_len: size_t, argp: *mut c_void),
    argp: *mut c_void,
    title: *const c_char,
    desc: *const c_char,
) {
    let argp = atomic::AtomicPtr::new(argp);
    let writer = Box::new(LogWriter { cb, argp });
    let title = unsafe { ffi::CStr::from_ptr(title).to_str().unwrap() };
    let description = unsafe { ffi::CStr::from_ptr(desc).to_str().unwrap() };

    conn.set_qlog(
        Box::new(writer),
        title.to_string(),
        format!("{} id={}", description, conn.trace_id()),
    );
}

/// Set qlog file.
#[no_mangle]
pub extern "C" fn quic_conn_set_qlog_fd(
    conn: &mut Connection,
    fd: c_int,
    title: *const c_char,
    desc: *const c_char,
) {
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(file);
    let title = unsafe { ffi::CStr::from_ptr(title).to_str().unwrap() };
    let description = unsafe { ffi::CStr::from_ptr(desc).to_str().unwrap() };

    conn.set_qlog(
        Box::new(writer),
        title.to_string(),
        format!("{} id={}", description, conn.trace_id()),
    );
}

/// Close the connection.
#[no_mangle]
pub extern "C" fn quic_conn_close(
    conn: &mut Connection,
    app: bool,
    err: u64,
    reason: *const u8,
    reason_len: size_t,
) -> c_int {
    let reason = unsafe { slice::from_raw_parts(reason, reason_len) };
    match conn.close(app, err, reason) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set want write flag for a stream.
#[no_mangle]
pub extern "C" fn quic_stream_wantwrite(
    conn: &mut Connection,
    stream_id: u64,
    want: bool,
) -> c_int {
    match conn.stream_want_write(stream_id, want) {
        Ok(_) | Err(Error::Done) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set want read flag for a stream.
#[no_mangle]
pub extern "C" fn quic_stream_wantread(conn: &mut Connection, stream_id: u64, want: bool) -> c_int {
    match conn.stream_want_read(stream_id, want) {
        Ok(_) | Err(Error::Done) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Read data from a stream.
#[no_mangle]
pub extern "C" fn quic_stream_read(
    conn: &mut Connection,
    stream_id: u64,
    out: *mut u8,
    out_len: size_t,
    fin: &mut bool,
) -> ssize_t {
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    let (out_len, out_fin) = match conn.stream_read(stream_id, out) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    *fin = out_fin;
    out_len as ssize_t
}

/// Write data to a stream.
#[no_mangle]
pub extern "C" fn quic_stream_write(
    conn: &mut Connection,
    stream_id: u64,
    buf: *const u8,
    buf_len: size_t,
    fin: bool,
) -> ssize_t {
    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };
    let buf = Bytes::copy_from_slice(buf);
    match conn.stream_write(stream_id, buf, fin) {
        Ok(v) => v as ssize_t,
        Err(e) => e.to_errno() as ssize_t,
    }
}

/// Create a new quic stream with the given id and priority.
/// This is a low-level API for stream creation. It is recommended to use
/// `quic_stream_bidi_new` for bidirectional streams or `quic_stream_uni_new`
/// for unidrectional streams.
#[no_mangle]
pub extern "C" fn quic_stream_new(
    conn: &mut Connection,
    stream_id: u64,
    urgency: u8,
    incremental: bool,
) -> c_int {
    match conn.stream_new(stream_id, urgency, incremental) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Create a new quic bidiectional stream with the given priority.
/// If success, the output parameter `stream_id` carrys the id of the created stream.
#[no_mangle]
pub extern "C" fn quic_stream_bidi_new(
    conn: &mut Connection,
    urgency: u8,
    incremental: bool,
    stream_id: &mut u64,
) -> c_int {
    match conn.stream_bidi_new(urgency, incremental) {
        Ok(id) => {
            *stream_id = id;
            0
        }
        Err(e) => e.to_errno() as c_int,
    }
}

/// Create a new quic uniectional stream with the given priority.
/// If success, the output parameter `stream_id` carrys the id of the created stream.
#[no_mangle]
pub extern "C" fn quic_stream_uni_new(
    conn: &mut Connection,
    urgency: u8,
    incremental: bool,
    stream_id: &mut u64,
) -> c_int {
    match conn.stream_uni_new(urgency, incremental) {
        Ok(id) => {
            *stream_id = id;
            0
        }
        Err(e) => e.to_errno() as c_int,
    }
}

/// Shutdown stream reading or writing.
#[no_mangle]
pub extern "C" fn quic_stream_shutdown(
    conn: &mut Connection,
    stream_id: u64,
    direction: Shutdown,
    err: u64,
) -> c_int {
    match conn.stream_shutdown(stream_id, direction, err) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set the priority for a stream.
#[no_mangle]
pub extern "C" fn quic_stream_set_priority(
    conn: &mut Connection,
    stream_id: u64,
    urgency: u8,
    incremental: bool,
) -> c_int {
    match conn.stream_set_priority(stream_id, urgency, incremental) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Return the stream’s send capacity in bytes.
#[no_mangle]
pub extern "C" fn quic_stream_capacity(conn: &mut Connection, stream_id: u64) -> ssize_t {
    match conn.stream_capacity(stream_id) {
        Ok(v) => v as ssize_t,
        Err(e) => e.to_errno() as ssize_t,
    }
}

/// Return true if all the data has been read from the stream.
#[no_mangle]
pub extern "C" fn quic_stream_finished(conn: &mut Connection, stream_id: u64) -> bool {
    conn.stream_finished(stream_id)
}

#[repr(transparent)]
struct Context(*mut c_void);

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

/// Set user context for a stream.
#[no_mangle]
pub extern "C" fn quic_stream_set_context(
    conn: &mut Connection,
    stream_id: u64,
    data: *mut c_void,
) -> c_int {
    match conn.stream_set_context(stream_id, Context(data)) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Return the stream’s user context.
#[no_mangle]
pub extern "C" fn quic_stream_context(conn: &mut Connection, stream_id: u64) -> *mut c_void {
    match conn.stream_context(stream_id) {
        Some(v) => v.downcast_mut::<Context>().unwrap().0,
        None => ptr::null_mut(),
    }
}

#[repr(transparent)]
pub struct TlsConfigSelectorContext(*mut c_void);

#[repr(C)]
pub struct TlsConfigSelectMethods {
    pub get_default: fn(ctx: *mut c_void) -> *mut TlsConfig,
    pub select:
        fn(ctx: *mut c_void, server_name: *const u8, server_name_len: size_t) -> *mut TlsConfig,
}

#[repr(C)]
pub struct TlsConfigSelector {
    pub methods: *const TlsConfigSelectMethods,
    pub context: TlsConfigSelectorContext,
}

unsafe impl Send for TlsConfigSelector {}
unsafe impl Sync for TlsConfigSelector {}

impl crate::tls::TlsConfigSelector for TlsConfigSelector {
    fn get_default(&self) -> Option<Arc<TlsConfig>> {
        let tls_config = unsafe { ((*self.methods).get_default)(self.context.0) };
        if tls_config.is_null() {
            return None;
        }

        let tls_config = unsafe { tls_config.as_mut().unwrap() };
        let tls_config = Arc::new(TlsConfig::new_with_ssl_ctx(tls_config.ssl_ctx()));
        Some(tls_config)
    }

    fn select(&self, server_name: &str) -> Option<Arc<TlsConfig>> {
        let tls_config = unsafe {
            ((*self.methods).select)(
                self.context.0,
                server_name.as_ptr(),
                server_name.len() as size_t,
            )
        };
        if tls_config.is_null() {
            return None;
        }

        let tls_config = unsafe { tls_config.as_mut().unwrap() };
        let tls_config = Arc::new(TlsConfig::new_with_ssl_ctx(tls_config.ssl_ctx()));
        Some(tls_config)
    }
}

#[repr(C)]
pub struct TransportMethods {
    /// Called when a new connection has been created. This callback is called
    /// as soon as connection object is created inside the endpoint, but
    /// before the handshake is done. This callback is optional.
    pub on_conn_created: Option<fn(tctx: *mut c_void, conn: &mut Connection)>,

    /// Called when the handshake is completed. This callback is optional.
    pub on_conn_established: Option<fn(tctx: *mut c_void, conn: &mut Connection)>,

    /// Called when the connection is closed. The connection is no longer
    /// accessible after this callback returns. It is a good time to clean up
    /// the connection context. This callback is optional.
    pub on_conn_closed: Option<fn(tctx: *mut c_void, conn: &mut Connection)>,

    /// Called when the stream is created. This callback is optional.
    pub on_stream_created: Option<fn(tctx: *mut c_void, conn: &mut Connection, stream_id: u64)>,

    /// Called when the stream is readable. This callback is called when either
    /// there are bytes to be read or an error is ready to be collected. This
    /// callback is optional.
    pub on_stream_readable: Option<fn(tctx: *mut c_void, conn: &mut Connection, stream_id: u64)>,

    /// Called when the stream is writable. This callback is optional.
    pub on_stream_writable: Option<fn(tctx: *mut c_void, conn: &mut Connection, stream_id: u64)>,

    /// Called when the stream is closed. The stream is no longer accessible
    /// after this callback returns. It is a good time to clean up the stream
    /// context. This callback is optional.
    pub on_stream_closed: Option<fn(tctx: *mut c_void, conn: &mut Connection, stream_id: u64)>,

    /// Called when client receives a token in NEW_TOKEN frame. This callback
    /// is optional.
    pub on_new_token:
        Option<fn(tctx: *mut c_void, conn: &mut Connection, token: *const u8, token_len: size_t)>,
}

#[repr(transparent)]
pub struct TransportContext(*mut c_void);

/// cbindgen:no-export
#[repr(C)]
pub struct TransportHandler {
    pub methods: *const TransportMethods,
    pub context: TransportContext,
}

impl crate::TransportHandler for TransportHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        unsafe {
            if let Some(f) = (*self.methods).on_conn_created {
                f(self.context.0, conn);
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        unsafe {
            if let Some(f) = (*self.methods).on_conn_established {
                f(self.context.0, conn);
            }
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        unsafe {
            if let Some(f) = (*self.methods).on_conn_closed {
                f(self.context.0, conn);
            }
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_created {
                f(self.context.0, conn, stream_id);
            }
        }
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_readable {
                f(self.context.0, conn, stream_id);
            }
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_writable {
                f(self.context.0, conn, stream_id);
            }
        }
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_closed {
                f(self.context.0, conn, stream_id);
            }
        }
    }

    fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>) {
        let token_len = token.len() as size_t;
        let token = token.as_ptr();
        unsafe {
            if let Some(f) = (*self.methods).on_new_token {
                f(self.context.0, conn, token, token_len);
            }
        }
    }
}

#[repr(C)]
pub struct PacketSendMethods {
    /// Called when the connection is sending packets out.
    /// On success, `on_packets_send()` returns the number of messages sent. If
    /// this is less than count, the connection will retry with a further
    /// `on_packets_send()` call to send the remaining messages. This callback
    /// is mandatory.
    pub on_packets_send:
        fn(psctx: *mut c_void, pkts: *mut PacketOutSpec, count: libc::c_uint) -> libc::c_int,
}

#[repr(transparent)]
pub struct PacketSendContext(*mut c_void);

/// cbindgen:no-export
#[repr(C)]
pub struct PacketSendHandler {
    pub methods: *const PacketSendMethods,
    pub context: PacketSendContext,
}

impl crate::PacketSendHandler for PacketSendHandler {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, crate::PacketInfo)]) -> Result<usize> {
        let mut pkt_specs: Vec<PacketOutSpec> = Vec::with_capacity(pkts.len());
        let mut iovecs: Vec<iovec> = Vec::with_capacity(pkts.len());
        let mut src_addrs: Vec<sockaddr_storage> = Vec::with_capacity(pkts.len());
        let mut dst_addrs: Vec<sockaddr_storage> = Vec::with_capacity(pkts.len());

        // Prepare packets to be send
        for (i, (pkt, info)) in pkts.iter().enumerate() {
            let iov = iovec {
                iov_base: pkt.as_ptr() as *mut c_void,
                iov_len: pkt.len(),
            };
            let mut src_addr: sockaddr_storage = unsafe { mem::zeroed() };
            let src_addr_len = sock_addr_to_c(&info.src, &mut src_addr);
            let mut dst_addr: sockaddr_storage = unsafe { mem::zeroed() };
            let dst_addr_len = sock_addr_to_c(&info.dst, &mut dst_addr);

            iovecs.push(iov);
            src_addrs.push(src_addr);
            dst_addrs.push(dst_addr);

            let pkt_spec = PacketOutSpec {
                iov: &iovecs[i] as *const _ as *mut _,
                iovlen: 1,
                src_addr: &src_addrs[i] as *const _ as *const c_void,
                src_addr_len,
                dst_addr: &dst_addrs[i] as *const _ as *const c_void,
                dst_addr_len,
            };

            pkt_specs.push(pkt_spec);
        }

        // Send packets out
        let count = unsafe {
            ((*self.methods).on_packets_send)(
                self.context.0,
                pkt_specs.as_mut_ptr(),
                pkts.len() as libc::c_uint,
            )
        };
        if count > 0 {
            Ok(count as usize)
        } else if count == 0 {
            Err(Error::Done)
        } else {
            Err(Error::InternalError)
        }
    }
}

fn sock_addr_from_c(addr: &sockaddr, addr_len: socklen_t) -> SocketAddr {
    match addr.sa_family as i32 {
        AF_INET => {
            assert!(addr_len as usize == std::mem::size_of::<sockaddr_in>());
            let in4 = unsafe { *(addr as *const _ as *const sockaddr_in) };
            let addr = Ipv4Addr::from(u32::from_be(in4.sin_addr.s_addr));
            let port = u16::from_be(in4.sin_port);
            SocketAddrV4::new(addr, port).into()
        }
        AF_INET6 => {
            assert!(addr_len as usize == std::mem::size_of::<sockaddr_in6>());
            let in6 = unsafe { *(addr as *const _ as *const sockaddr_in6) };
            let addr = Ipv6Addr::from(in6.sin6_addr.s6_addr);
            let port = u16::from_be(in6.sin6_port);
            let scope_id = in6.sin6_scope_id;
            SocketAddrV6::new(addr, port, in6.sin6_flowinfo, scope_id).into()
        }
        _ => unimplemented!("unsupported address type"),
    }
}

fn sock_addr_to_c(addr: &SocketAddr, out: &mut sockaddr_storage) -> socklen_t {
    let sin_port = addr.port().to_be();

    match addr {
        SocketAddr::V4(addr) => unsafe {
            let sa_len = std::mem::size_of::<sockaddr_in>();
            let out_in = out as *mut _ as *mut sockaddr_in;
            let sin_addr = in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            };
            *out_in = sockaddr_in {
                sin_family: AF_INET as sa_family_t,
                sin_addr,
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin_len: sa_len as u8,
                sin_port,
                sin_zero: std::mem::zeroed(),
            };
            sa_len as socklen_t
        },

        SocketAddr::V6(addr) => unsafe {
            let sa_len = std::mem::size_of::<sockaddr_in6>();
            let out_in6 = out as *mut _ as *mut sockaddr_in6;
            let sin6_addr = in6_addr {
                s6_addr: addr.ip().octets(),
            };
            *out_in6 = sockaddr_in6 {
                sin6_family: AF_INET6 as sa_family_t,
                sin6_addr,
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin6_len: sa_len as u8,
                sin6_port: sin_port,
                sin6_flowinfo: addr.flowinfo(),
                sin6_scope_id: addr.scope_id(),
            };
            sa_len as socklen_t
        },
    }
}

/// Meta information of an incoming packet.
#[repr(C)]
pub struct PacketInfo<'a> {
    src: &'a sockaddr,
    src_len: socklen_t,
    dst: &'a sockaddr,
    dst_len: socklen_t,
}

impl<'a> From<&PacketInfo<'a>> for crate::PacketInfo {
    fn from(info: &PacketInfo) -> crate::PacketInfo {
        crate::PacketInfo {
            src: sock_addr_from_c(info.src, info.src_len),
            dst: sock_addr_from_c(info.dst, info.dst_len),
            time: Instant::now(),
        }
    }
}

/// Data and meta information of an outgoing packet.
#[repr(C)]
pub struct PacketOutSpec {
    iov: *const iovec,
    iovlen: size_t,
    src_addr: *const c_void,
    src_addr_len: socklen_t,
    dst_addr: *const c_void,
    dst_addr_len: socklen_t,
}

/// Create default config for HTTP3.
#[no_mangle]
pub extern "C" fn http3_config_new() -> *mut Http3Config {
    match Http3Config::new() {
        Ok(c) => Box::into_raw(Box::new(c)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy the HTTP3 config.
#[no_mangle]
pub extern "C" fn http3_config_free(config: *mut Http3Config) {
    unsafe {
        let _ = Box::from_raw(config);
    };
}

/// Set the `SETTINGS_MAX_FIELD_SECTION_SIZE` setting.
/// By default no limit is enforced.
#[no_mangle]
pub extern "C" fn http3_config_set_max_field_section_size(config: &mut Http3Config, v: u64) {
    config.set_max_field_section_size(v);
}

/// Set the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` setting.
/// The default value is `0`.
#[no_mangle]
pub extern "C" fn http3_config_set_qpack_max_table_capacity(config: &mut Http3Config, v: u64) {
    config.set_qpack_max_table_capacity(v);
}

/// Set the `SETTINGS_QPACK_BLOCKED_STREAMS` setting.
/// The default value is `0`.
#[no_mangle]
pub extern "C" fn http3_config_set_qpack_blocked_streams(config: &mut Http3Config, v: u64) {
    config.set_qpack_blocked_streams(v);
}

/// Create an HTTP/3 connection using the given QUIC connection. It also
/// initiate the HTTP/3 handshake by opening all control streams and sending
/// the local settings.
#[no_mangle]
pub extern "C" fn http3_conn_new(
    quic_conn: &mut Connection,
    config: &mut Http3Config,
) -> *mut Http3Connection {
    match Http3Connection::new_with_quic_conn(quic_conn, config) {
        Ok(c) => Box::into_raw(Box::new(c)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy the HTTP/3 connection.
#[no_mangle]
pub extern "C" fn http3_conn_free(conn: *mut Http3Connection) {
    unsafe {
        let _ = Box::from_raw(conn);
    };
}

/// Send goaway with the given id.
#[no_mangle]
pub extern "C" fn http3_send_goaway(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    id: u64,
) -> i64 {
    match conn.send_goaway(quic_conn, id) {
        Ok(()) => 0,
        Err(e) => e.to_errno() as i64,
    }
}

/// Set HTTP/3 connection events handler.
#[no_mangle]
pub extern "C" fn http3_conn_set_events_handler(
    conn: &mut Http3Connection,
    methods: *const Http3Methods,
    context: Http3Context,
) {
    let handler = Http3Handler { methods, context };
    conn.set_events_handler(Arc::new(handler));
}

/// Process HTTP/3 settings.
#[no_mangle]
pub extern "C" fn http3_for_each_setting(
    conn: &Http3Connection,
    cb: extern "C" fn(identifier: u64, value: u64, argp: *mut c_void) -> c_int,
    argp: *mut c_void,
) -> c_int {
    match conn.peer_raw_settings() {
        Some(raw) => {
            for setting in raw {
                let rc = cb(setting.0, setting.1, argp);

                if rc != 0 {
                    return rc;
                }
            }
            0
        }

        None => -1,
    }
}

/// Process internal events of all streams of the specified HTTP/3 connection.
#[no_mangle]
pub extern "C" fn http3_conn_process_streams(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
) -> c_int {
    match conn.process_streams(quic_conn) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

/// Process HTTP/3 headers.
#[no_mangle]
pub extern "C" fn http3_for_each_header(
    headers: &Http3Headers,
    cb: extern "C" fn(
        name: *const u8,
        name_len: size_t,
        value: *const u8,
        value_len: size_t,
        argp: *mut c_void,
    ) -> c_int,
    argp: *mut c_void,
) -> c_int {
    for h in headers.headers {
        let rc = cb(
            h.name().as_ptr(),
            h.name().len(),
            h.value().as_ptr(),
            h.value().len(),
            argp,
        );
        if rc != 0 {
            return rc;
        }
    }

    0
}

/// Return true if all the data has been read from the stream.
#[no_mangle]
pub extern "C" fn http3_stream_read_finished(conn: &mut Connection, stream_id: u64) -> bool {
    conn.stream_finished(stream_id)
}

/// Create a new HTTP/3 request stream.
/// On success the stream ID is returned.
#[no_mangle]
pub extern "C" fn http3_stream_new(conn: &mut Http3Connection, quic_conn: &mut Connection) -> i64 {
    match conn.stream_new_with_priority(quic_conn, &Http3Priority::default()) {
        Ok(v) => v as i64,
        Err(e) => e.to_errno() as i64,
    }
}

/// Create a new HTTP/3 request stream with the given priority.
/// On success the stream ID is returned.
#[no_mangle]
pub extern "C" fn http3_stream_new_with_priority(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    priority: &Http3Priority,
) -> i64 {
    match conn.stream_new_with_priority(quic_conn, priority) {
        Ok(v) => v as i64,
        Err(e) => e.to_errno() as i64,
    }
}

/// Close the given HTTP/3 stream.
#[no_mangle]
pub extern "C" fn http3_stream_close(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
) -> c_int {
    match conn.stream_close(quic_conn, stream_id) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set priority for an HTTP/3 stream.
#[no_mangle]
pub extern "C" fn http3_stream_set_priority(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    priority: &Http3Priority,
) -> c_int {
    match conn.stream_set_priority(quic_conn, stream_id, priority) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

#[repr(C)]
pub struct Header {
    name: *mut u8,
    name_len: usize,
    value: *mut u8,
    value_len: usize,
}

/// Send HTTP/3 request or response headers on the given stream.
#[no_mangle]
pub extern "C" fn http3_send_headers(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    headers: *const Header,
    headers_len: size_t,
    fin: bool,
) -> c_int {
    let h3_headers = headers_from_ptr(headers, headers_len);

    match conn.send_headers(quic_conn, stream_id, &h3_headers, fin) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Send HTTP/3 request or response body on the given stream.
#[no_mangle]
pub extern "C" fn http3_send_body(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    body: *const u8,
    body_len: size_t,
    fin: bool,
) -> ssize_t {
    if body_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let body = unsafe { slice::from_raw_parts(body, body_len) };
    match conn.send_body(quic_conn, stream_id, Bytes::copy_from_slice(body), fin) {
        Ok(v) => v as ssize_t,
        Err(e) => e.to_errno(),
    }
}

/// Read request/response body from the given stream.
#[no_mangle]
pub extern "C" fn http3_recv_body(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    out: *mut u8,
    out_len: size_t,
) -> ssize_t {
    if out_len > <ssize_t>::max_value() as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match conn.recv_body(quic_conn, stream_id, out) {
        Ok(v) => v as ssize_t,
        Err(e) => e.to_errno(),
    }
}

/// Parse HTTP/3 priority data.
#[no_mangle]
#[cfg(feature = "sfv")]
pub extern "C" fn http3_parse_extensible_priority(
    priority: *const u8,
    priority_len: size_t,
    parsed: &mut Http3Priority,
) -> c_int {
    let priority = unsafe { slice::from_raw_parts(priority, priority_len) };

    match Http3Priority::try_from(priority) {
        Ok(v) => {
            parsed.urgency = v.urgency;
            parsed.incremental = v.incremental;
            0
        }
        Err(e) => e.to_errno() as c_int,
    }
}

/// Send a PRIORITY_UPDATE frame on the control stream with specified
/// request stream ID and priority.
#[no_mangle]
pub extern "C" fn http3_send_priority_update_for_request(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    priority: &Http3Priority,
) -> c_int {
    match conn.send_priority_update_for_request(quic_conn, stream_id, priority) {
        Ok(()) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Take the last PRIORITY_UPDATE for the given stream.
#[no_mangle]
pub extern "C" fn http3_take_priority_update(
    conn: &mut Http3Connection,
    prioritized_element_id: u64,
    cb: extern "C" fn(
        priority_field_value: *const u8,
        priority_field_value_len: size_t,
        argp: *mut c_void,
    ) -> c_int,
    argp: *mut c_void,
) -> c_int {
    match conn.take_priority_update(prioritized_element_id) {
        Ok(priority) => {
            let rc = cb(priority.as_ptr(), priority.len(), argp);
            if rc != 0 {
                return rc;
            }
            0
        }

        Err(e) => e.to_errno() as c_int,
    }
}

/// Convert HTTP/3 header.
fn headers_from_ptr<'a>(ptr: *const Header, len: size_t) -> Vec<h3::HeaderRef<'a>> {
    let headers = unsafe { slice::from_raw_parts(ptr, len) };

    let mut out = Vec::new();
    for h in headers {
        out.push({
            let name = unsafe { slice::from_raw_parts(h.name, h.name_len) };
            let value = unsafe { slice::from_raw_parts(h.value, h.value_len) };
            h3::HeaderRef::new(name, value)
        });
    }

    out
}

/// Set logger.
/// `cb` is a callback function that will be called for each log message.
/// `data` is a '\n' terminated log message and `argp` is user-defined data that will be passed to
/// the callback.
/// `level` represents the log level.
#[no_mangle]
pub extern "C" fn quic_set_logger(
    cb: extern "C" fn(data: *const u8, data_len: size_t, argp: *mut c_void),
    argp: *mut c_void,
    level: log::LevelFilter,
) {
    let argp = atomic::AtomicPtr::new(argp);
    let logger = Box::new(LogWriter { cb, argp });
    let _ = log::set_boxed_logger(logger);
    log::set_max_level(level);
}

#[repr(C)]
pub struct Http3Methods {
    /// Called when the stream got headers.
    pub on_stream_headers:
        Option<fn(ctx: *mut c_void, stream_id: u64, headers: &Http3Headers, fin: bool)>,

    /// Called when the stream has buffered data to read.
    pub on_stream_data: Option<fn(ctx: *mut c_void, stream_id: u64)>,

    /// Called when the stream is finished.
    pub on_stream_finished: Option<fn(ctx: *mut c_void, stream_id: u64)>,

    /// Called when the stream receives a RESET_STREAM frame from the peer.
    pub on_stream_reset: Option<fn(ctx: *mut c_void, stream_id: u64, error_code: u64)>,

    /// Called when the stream priority is updated.
    pub on_stream_priority_update: Option<fn(ctx: *mut c_void, stream_id: u64)>,

    /// Called when the connection receives a GOAWAY frame from the peer.
    pub on_conn_goaway: Option<fn(ctx: *mut c_void, stream_id: u64)>,
}

#[repr(transparent)]
pub struct Http3Context(*mut c_void);

#[repr(C)]
pub struct Http3Handler {
    pub methods: *const Http3Methods,
    pub context: Http3Context,
}

unsafe impl Send for Http3Handler {}
unsafe impl Sync for Http3Handler {}

impl crate::h3::Http3Handler for Http3Handler {
    fn on_stream_headers(&self, stream_id: u64, ev: &mut Http3Event) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_headers {
                let (headers, fin) = match ev {
                    Http3Event::Headers { headers, fin } => (Http3Headers { headers }, *fin),
                    _ => unreachable!(),
                };

                f(self.context.0, stream_id, &headers, fin);
            }
        }
    }

    fn on_stream_data(&self, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_data {
                f(self.context.0, stream_id);
            }
        }
    }

    fn on_stream_finished(&self, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_finished {
                f(self.context.0, stream_id);
            }
        }
    }

    fn on_stream_reset(&self, stream_id: u64, error_code: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_reset {
                f(self.context.0, stream_id, error_code);
            }
        }
    }

    fn on_stream_priority_update(&self, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_priority_update {
                f(self.context.0, stream_id);
            }
        }
    }

    fn on_conn_goaway(&self, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_conn_goaway {
                f(self.context.0, stream_id);
            }
        }
    }
}
