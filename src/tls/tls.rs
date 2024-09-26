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

use std::mem;
use std::ops::Index;
use std::ops::IndexMut;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use log::trace;
use strum::EnumCount;
use strum::IntoEnumIterator;
use strum_macros::EnumCount;
use strum_macros::EnumIter;

use crate::codec::Decoder;
use crate::connection::space::PacketNumSpace;
use crate::connection::timer::Timer;
use crate::connection::timer::TimerTable;
use crate::packet::PacketHeader;
use crate::packet::PacketType;
use crate::ConnectionId;
use crate::Error;
use crate::Result;

pub use boringssl::crypto::derive_initial_secrets;
pub use boringssl::crypto::Algorithm;
pub use boringssl::crypto::Open;
pub use boringssl::crypto::Seal;
pub use boringssl::tls::SslCtx;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, EnumCount)]
pub enum Level {
    Initial,
    ZeroRTT,
    Handshake,
    OneRTT,
}

impl From<Level> for usize {
    fn from(level: Level) -> Self {
        level as usize
    }
}

impl<T> Index<Level> for [T]
where
    T: Sized,
{
    type Output = T;

    fn index(&self, level: Level) -> &Self::Output {
        self.index(usize::from(level))
    }
}

impl<T> IndexMut<Level> for [T]
where
    T: Sized,
{
    fn index_mut(&mut self, level: Level) -> &mut Self::Output {
        self.index_mut(usize::from(level))
    }
}

pub struct TlsConfig {
    /// Boringssl SSL context.
    tls_ctx: boringssl::tls::Context,
}

impl TlsConfig {
    /// Create a new TlsConfig.
    pub fn new() -> Result<Self> {
        let mut tls_ctx = boringssl::tls::Context::new()?;
        tls_ctx.enable_keylog();

        Ok(Self { tls_ctx })
    }

    /// Create a new TlsConfig with SSL_CTX.
    /// When using raw SSL_CTX, TlsSession::session() and TlsSession::set_keylog() won't take effect.
    /// The caller is responsible for the memory of SSL_CTX when use this function.
    pub fn new_with_ssl_ctx(ssl_ctx: *mut boringssl::tls::SslCtx) -> Self {
        let tls_ctx = boringssl::tls::Context::new_with_ssl_ctx(ssl_ctx);

        Self { tls_ctx }
    }

    /// Create a new client side TlsConfig.
    pub fn new_client_config(
        application_protos: Vec<Vec<u8>>,
        enable_early_data: bool,
    ) -> Result<Self> {
        let mut tls_config = Self::new()?;
        tls_config.set_application_protos(application_protos)?;
        tls_config.set_early_data_enabled(enable_early_data);

        Ok(tls_config)
    }

    /// Create a new server side TlsConfig.
    pub fn new_server_config(
        cert_file: &str,
        key_file: &str,
        application_protos: Vec<Vec<u8>>,
        enable_early_data: bool,
    ) -> Result<Self> {
        let mut tls_config = Self::new()?;
        tls_config.set_certificate_file(cert_file)?;
        tls_config.set_private_key_file(key_file)?;
        tls_config.set_application_protos(application_protos)?;
        tls_config.set_early_data_enabled(enable_early_data);
        // TLS 1.3 sets a limit of seven days on the time between the original
        // connection and any attempt to use 0-RTT.
        tls_config.set_session_timeout(7 * 24 * 60 * 60);

        Ok(tls_config)
    }

    /// Set whether early data is allowed.
    pub fn set_early_data_enabled(&mut self, enable_early_data: bool) {
        self.tls_ctx.set_early_data_enabled(enable_early_data)
    }

    /// Set the session lifetime in seconds
    pub fn set_session_timeout(&mut self, timeout: u32) {
        self.tls_ctx.set_session_psk_dhe_timeout(timeout)
    }

    /// Set the list of supported application protocols.
    pub fn set_application_protos(&mut self, application_protos: Vec<Vec<u8>>) -> Result<()> {
        self.tls_ctx.set_alpn(application_protos)
    }

    /// Set session ticket key for server.
    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        self.tls_ctx.set_ticket_key(key)
    }

    /// Set the certificate verification behavior.
    pub fn set_verify(&mut self, verify: bool) {
        self.tls_ctx.set_verify(verify)
    }

    /// Set the PEM-encoded certificate file
    pub fn set_certificate_file(&mut self, cert_file: &str) -> Result<()> {
        self.tls_ctx.use_certificate_chain_file(cert_file)
    }

    /// Set the PEM-encoded private key file
    pub fn set_private_key_file(&mut self, key_file: &str) -> Result<()> {
        self.tls_ctx.use_private_key_file(key_file)
    }

    /// Set CA certificates.
    pub fn set_ca_certs(&mut self, ca_path: &str) -> Result<()> {
        let path = Path::new(ca_path);
        if path.is_file() {
            self.tls_ctx.load_verify_locations_from_file(ca_path)?;
        } else {
            self.tls_ctx.load_verify_locations_from_directory(ca_path)?;
        }

        Ok(())
    }

    /// Get the underlying SSL_CTX.
    pub(crate) fn ssl_ctx(&mut self) -> *mut boringssl::tls::SslCtx {
        self.tls_ctx.as_mut_ptr()
    }
}

impl TlsConfig {
    /// Create new TlsSession.
    pub(crate) fn new_session(
        &self,
        host_name: Option<&str>,
        is_server: bool,
    ) -> Result<TlsSession> {
        let mut session = self.tls_ctx.new_session()?;
        session.init(is_server)?;
        if !is_server {
            if let Some(host_name) = host_name {
                session.set_host_name(host_name)?;
            }
        }

        Ok(TlsSession {
            session,
            data: TlsSessionData {
                key_collection: [
                    Keys::default(),
                    Keys::default(),
                    Keys::default(),
                    Keys::default(),
                ],
                session: None,
                keylog: None,
                is_server,
                error: None,
                trace_id: "".to_string(),
                write_method: None,
                conf_selector: None,
                early_data_rejected: false,
            },
            current_key_phase: false,
            prev_key: None,
            next_key: None,
        })
    }
}

pub(crate) struct DefaultTlsConfigSelector {
    pub tls_config: Arc<TlsConfig>,
}

impl TlsConfigSelector for DefaultTlsConfigSelector {
    /// Get default TLS config.
    fn get_default(&self) -> Option<Arc<TlsConfig>> {
        Some(self.tls_config.clone())
    }

    /// Find TLS config according to server name.
    fn select(&self, _server_name: &str) -> Option<Arc<TlsConfig>> {
        Some(self.tls_config.clone())
    }
}

/// Used for selecting TLS config according to SNI.
pub trait TlsConfigSelector: Send + Sync {
    /// Get default TLS config.
    fn get_default(&self) -> Option<Arc<TlsConfig>>;

    /// Find TLS config according to server name.
    fn select(&self, server_name: &str) -> Option<Arc<TlsConfig>>;
}

#[derive(Default)]
pub struct Keys {
    pub open: Option<Open>,
    pub seal: Option<Seal>,
}

pub type WriteMethod = Box<dyn FnMut(Level, &[u8]) -> Result<()>>;
type KeyLog = Box<dyn std::io::Write + Send + Sync>;

pub struct TlsSessionData {
    key_collection: [Keys; Level::COUNT],
    session: Option<Vec<u8>>,
    keylog: Option<KeyLog>,
    is_server: bool,
    error: Option<TlsError>,
    trace_id: String,
    write_method: Option<WriteMethod>,
    conf_selector: Option<Arc<dyn TlsConfigSelector>>,
    early_data_rejected: bool,
}

pub(crate) struct TlsSession {
    /// Boringssl TLS session.
    session: boringssl::tls::Session,

    /// TLS session data.
    data: TlsSessionData,

    /// Current key phase.
    current_key_phase: bool,

    /// Keys for previous key phase.
    prev_key: Option<Keys>,

    /// Keys for next key phase.
    next_key: Option<Keys>,
}

impl TlsSession {
    /// Set write method.
    pub fn set_write_method(&mut self, write_method: WriteMethod) {
        self.data.write_method = Some(write_method);
    }

    /// Set transport parameters sent in the quic_transport_parameters extension.
    pub fn set_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        self.session.set_quic_transport_params(buf)
    }

    /// Set session for resumption.
    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        self.session.set_session(session)
    }

    /// Set key logger.
    pub fn set_keylog(&mut self, keylog: KeyLog) {
        self.data.keylog = Some(keylog)
    }

    /// Set trace id.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.data.trace_id = trace_id.to_string();
    }

    /// Set TLS config selector.
    pub fn set_config_selector(&mut self, conf_selector: Arc<dyn TlsConfigSelector>) {
        self.data.conf_selector = Some(conf_selector);
        self.session.set_cert_cb();
    }

    /// Derive initial secrets.
    pub fn derive_initial_secrets(&mut self, cid: &ConnectionId, version: u32) -> Result<()> {
        let (open, seal) =
            boringssl::crypto::derive_initial_secrets(cid, version, self.data.is_server)?;
        self.data.key_collection[Level::Initial] = Keys {
            open: Some(open),
            seal: Some(seal),
        };
        Ok(())
    }

    /// Get the keys for the given encryption level.
    pub fn get_keys(&self, level: Level) -> &Keys {
        &self.data.key_collection[level]
    }

    /// Drop the keys for the given encryption level.
    pub fn drop_keys(&mut self, level: Level) {
        self.data.key_collection[level] = Keys::default();
    }

    /// Derive next keys.
    fn derive_keys(&self) -> Result<Keys> {
        let key = &self.data.key_collection[Level::OneRTT];
        if key.open.is_none() || key.seal.is_none() {
            return Err(Error::TlsFail("derive not available now".into()));
        }

        Ok(Keys {
            open: Some(key.open.as_ref().unwrap().derive_next_packet_key()?),
            seal: Some(key.seal.as_ref().unwrap().derive_next_packet_key()?),
        })
    }

    /// Select decryption key.
    pub fn select_key(
        &mut self,
        confirmed: bool,
        enable_multipath: bool,
        hdr: &PacketHeader,
        space: &PacketNumSpace,
    ) -> Result<(&Open, bool)> {
        if !confirmed
            || hdr.pkt_type != PacketType::OneRTT
            || self.current_key_phase == hdr.key_phase
            || enable_multipath
        {
            trace!("{} select current key", self.data.trace_id);
            let key = self.get_keys(hdr.pkt_type.to_level()?);
            return Ok((key.open.as_ref().ok_or(Error::InternalError)?, false));
        }

        if let Some(first_pkt_num_recv) = space.first_pkt_num_recv {
            if hdr.pkt_num > first_pkt_num_recv {
                trace!("{} select next key", self.data.trace_id);

                if self.next_key.is_none() {
                    self.next_key = Some(self.derive_keys()?);
                }
                let next_key = self.next_key.as_ref().unwrap();
                return Ok((next_key.open.as_ref().ok_or(Error::InternalError)?, true));
            }
        }

        if let Some(prev_key) = &self.prev_key {
            trace!("{} select previous key", self.data.trace_id);

            return Ok((prev_key.open.as_ref().ok_or(Error::InternalError)?, false));
        }

        trace!("{} previous key already discarded", self.data.trace_id);
        Err(Error::Done)
    }

    /// Update key.
    fn update_key(&mut self, space: &mut PacketNumSpace) -> Result<()> {
        if self.next_key.is_none() {
            self.next_key = Some(self.derive_keys()?);
        }

        self.current_key_phase = !self.current_key_phase;
        self.prev_key = Some(mem::replace(
            &mut self.data.key_collection[Level::OneRTT],
            self.next_key.take().unwrap(),
        ));
        space.first_pkt_num_recv = None;
        space.first_pkt_num_sent = None;

        Ok(())
    }

    /// Try to update key after receiving a packet.
    pub fn try_update_key(
        &mut self,
        timers: &mut TimerTable,
        space: &mut PacketNumSpace,
        attempt_key_update: bool,
        hdr: &PacketHeader,
        now: Instant,
        max_pto: Option<Duration>,
    ) -> Result<()> {
        if attempt_key_update {
            self.update_key(space)?;
        }

        if space.first_pkt_num_recv.is_none() && self.current_key_phase == hdr.key_phase {
            space.first_pkt_num_recv = Some(hdr.pkt_num);

            if self.prev_key.is_some() {
                if let Some(duration) = max_pto {
                    // An endpoint SHOULD retain old read keys for no more than three times the PTO after
                    // having received a packet protected using the new keys. After this period, old read
                    // keys and their corresponding secrets SHOULD be discarded.
                    // See RFC 9001 Section 6.5.
                    timers.set(Timer::KeyDiscard, now + duration * 3);
                }
            }
        }

        Ok(())
    }

    /// If a key update is allowed to initiate.
    fn key_update_allowed(&self, enable_multipath: bool, space: &PacketNumSpace) -> Result<bool> {
        if enable_multipath {
            // TODO: support key update in multipath scenario.
            return Ok(false);
        }

        if let Some(first_pkt_num_sent) = space.first_pkt_num_sent {
            if first_pkt_num_sent <= space.largest_acked_pkt {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Initiate a key update.
    pub fn initiate_key_update(
        &mut self,
        space: &mut PacketNumSpace,
        enable_multipath: bool,
    ) -> Result<()> {
        if !self.key_update_allowed(enable_multipath, space)? {
            return Err(Error::Done);
        }

        self.update_key(space)
    }

    /// Discard the previous key.
    pub fn discard_prev_key(&mut self) {
        self.prev_key = None;
    }

    /// Return the current key phase.
    pub fn current_key_phase(&self) -> bool {
        self.current_key_phase
    }

    /// Get overhead size of Seal operation
    pub fn get_overhead(&self, level: Level) -> Option<usize> {
        self.data.key_collection[level]
            .seal
            .as_ref()
            .map(|seal| seal.algor().tag_len())
    }

    /// Provide data read from QUIC at a particular encryption level and
    /// advance the current handshake.
    pub fn provide(&mut self, level: Level, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Err(Error::TlsFail("no data".to_string()));
        }

        self.session.provide_data(level, buf)?;
        self.process()
    }

    /// Process the current handshake.
    /// If no handshake is in progress, initialize a new one.
    pub fn process(&mut self) -> Result<()> {
        if self.session.is_completed() {
            return self.session.process_post_handshake(&mut self.data);
        }

        self.session.do_handshake(&mut self.data)?;
        if self.session.is_completed() {
            self.data.conf_selector = None;
        }

        Ok(())
    }

    /// Reset tls session state.
    pub fn clear(&mut self) -> Result<()> {
        self.session.clear()
    }

    /// Get tls error.
    pub fn error(&self) -> Option<&TlsError> {
        match self.data.error {
            Some(ref err) => Some(err),
            _ => None,
        }
    }

    pub fn session(&self) -> Option<&[u8]> {
        self.data.session.as_deref()
    }

    /// Return true if tls session has a pending handshake that has progressed enough
    /// to send or receive early data.
    pub fn is_in_early_data(&self) -> bool {
        self.session.is_in_early_data()
    }

    pub fn is_completed(&self) -> bool {
        self.session.is_completed()
    }

    pub fn is_resumed(&self) -> bool {
        self.session.is_resumed()
    }

    pub fn peer_transport_params(&self) -> &[u8] {
        self.session.quic_transport_params()
    }

    pub fn write_level(&self) -> Level {
        self.session.write_level()
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        self.session.alpn_protocol()
    }

    pub fn server_name(&self) -> Option<&str> {
        self.session.server_name()
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        self.session.peer_cert()
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        self.session.peer_cert_chain()
    }

    pub fn cipher(&self) -> Option<boringssl::crypto::Algorithm> {
        self.session.cipher()
    }

    pub fn curve(&self) -> Option<String> {
        self.session.curve()
    }

    pub fn peer_sign_algor(&self) -> Option<String> {
        self.session.peer_sign_algor()
    }

    pub fn early_data_reason(&self) -> Result<Option<&str>> {
        self.session.early_data_reason()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsError {
    /// The error code carried by the `CONNECTION_CLOSE` frame.
    pub error_code: u64,

    /// The reason carried by the `CONNECTION_CLOSE` frame.
    pub reason: Vec<u8>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rand;
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::rc::Rc;

    fn create_client_session(
        hostname: Option<&str>,
        resumption: Option<&[u8]>,
        enable_early_data: bool,
    ) -> Result<TlsSession> {
        let tls_config = TlsConfig::new_client_config(vec![b"h3".to_vec()], enable_early_data)?;
        let mut tls_session = tls_config.new_session(hostname, false)?;
        if let Some(mut b) = resumption {
            let session_len = b
                .read_u64()
                .map_err(|_| Error::TlsFail("Invalid session resumption format.".to_string()))?
                as usize;
            let session_bytes = b
                .read(session_len)
                .map_err(|_| Error::TlsFail("Invalid session resumption format.".to_string()))?;
            tls_session.set_session(session_bytes.as_slice())?;
        }
        tls_session.set_keylog(Box::new(Vec::new()));
        tls_session.set_transport_params(b"tp")?;
        tls_session.derive_initial_secrets(&ConnectionId::new(b"dcid"), crate::QUIC_VERSION_V1)?;
        Ok(tls_session)
    }

    fn new_server_config(
        session_ticket_key: Vec<u8>,
        enable_early_data: bool,
        application_protos: Vec<Vec<u8>>,
        cert_file: &str,
        key_file: &str,
    ) -> Result<TlsConfig> {
        let mut tls_config = TlsConfig::new_server_config(
            cert_file,
            key_file,
            application_protos.to_vec(),
            enable_early_data,
        )?;
        tls_config.set_ticket_key(&session_ticket_key)?;

        Ok(tls_config)
    }

    fn create_server_session(
        session_ticket_key: Vec<u8>,
        enable_early_data: bool,
    ) -> Result<TlsSession> {
        let tls_config = new_server_config(
            session_ticket_key,
            enable_early_data,
            vec![b"h3".to_vec()],
            "./src/tls/testdata/cert.crt",
            "./src/tls/testdata/cert.key",
        )?;

        let mut tls_session = tls_config.new_session(Some("example.org"), true)?;
        tls_session.set_keylog(Box::new(Vec::new()));
        tls_session.set_transport_params(b"tp")?;
        tls_session.derive_initial_secrets(&ConnectionId::new(b"dcid"), crate::QUIC_VERSION_V1)?;
        Ok(tls_session)
    }

    fn generate_tls_session_data_buf(
        tls_session: &mut TlsSession,
    ) -> Rc<RefCell<VecDeque<DataBuf>>> {
        let data_buf: VecDeque<DataBuf> = VecDeque::new();
        let data_buf = Rc::new(RefCell::new(data_buf));
        let cloned_data_buf = Rc::clone(&data_buf);
        let write_method = move |level: Level, buf: &[u8]| {
            cloned_data_buf.borrow_mut().push_back(DataBuf {
                level,
                buf: buf.to_vec(),
            });
            Ok(())
        };
        tls_session.set_write_method(Box::new(write_method));
        data_buf
    }

    struct DataBuf {
        level: Level,
        buf: Vec<u8>,
    }

    struct TlsSessionPair {
        client: TlsSession,
        client_out_queue: Rc<RefCell<VecDeque<DataBuf>>>,

        server: TlsSession,
        server_out_queue: Rc<RefCell<VecDeque<DataBuf>>>,
    }

    impl TlsSessionPair {
        fn new(
            client_resumption: Option<&[u8]>,
            client_enable_early_data: bool,
            server_session_ticket_key: Vec<u8>,
            server_enable_early_data: bool,
        ) -> Result<TlsSessionPair> {
            Self::new_with_hostname(
                Some("example.org"),
                client_resumption,
                client_enable_early_data,
                server_session_ticket_key,
                server_enable_early_data,
            )
        }

        fn new_with_hostname(
            client_hostname: Option<&str>,
            client_resumption: Option<&[u8]>,
            client_enable_early_data: bool,
            server_session_ticket_key: Vec<u8>,
            server_enable_early_data: bool,
        ) -> Result<TlsSessionPair> {
            let mut client = create_client_session(
                client_hostname,
                client_resumption,
                client_enable_early_data,
            )?;
            let client_out_queue = generate_tls_session_data_buf(&mut client);

            let mut server =
                create_server_session(server_session_ticket_key, server_enable_early_data)?;
            let server_out_queue = generate_tls_session_data_buf(&mut server);
            Ok(TlsSessionPair {
                client,
                client_out_queue,
                server,
                server_out_queue,
            })
        }

        fn new_with_tls_config(
            client_config: &TlsConfig,
            server_config: &TlsConfig,
        ) -> Result<TlsSessionPair> {
            let mut client = client_config.new_session(Some("example.org"), false)?;
            client.set_keylog(Box::new(Vec::new()));
            client.set_transport_params(b"tp")?;
            client.derive_initial_secrets(&ConnectionId::new(b"dcid"), crate::QUIC_VERSION_V1)?;
            let client_out_queue = generate_tls_session_data_buf(&mut client);

            let mut server = server_config.new_session(Some("example.org"), true)?;
            server.set_keylog(Box::new(Vec::new()));
            server.set_transport_params(b"tp")?;
            server.derive_initial_secrets(&ConnectionId::new(b"dcid"), crate::QUIC_VERSION_V1)?;
            let server_out_queue = generate_tls_session_data_buf(&mut server);

            Ok(TlsSessionPair {
                client,
                client_out_queue,
                server,
                server_out_queue,
            })
        }

        fn do_handshake(&mut self, client_should_in_early_data: bool) -> Result<()> {
            match self.client.process() {
                Ok(_) => {}
                Err(Error::Done) => {}
                Err(e) => {
                    return Err(e);
                }
            };

            if self.client.is_in_early_data() != client_should_in_early_data {
                return Err(Error::TlsFail(
                    "Early data state of client is not expected.".to_string(),
                ));
            }

            while !(self.client.is_completed() && self.server.is_completed()) {
                while !self.client_out_queue.borrow_mut().is_empty() {
                    let data_buf = self.client_out_queue.borrow_mut().pop_front();
                    let data_buf = data_buf.unwrap();
                    match self.server.provide(data_buf.level, &data_buf.buf) {
                        Ok(_) => break,
                        Err(Error::Done) => {}
                        Err(e) => {
                            return Err(e);
                        }
                    };
                }

                while !self.server_out_queue.borrow_mut().is_empty() {
                    let data_buf = self.server_out_queue.borrow_mut().pop_front();
                    let data_buf = data_buf.unwrap();
                    match self.client.provide(data_buf.level, &data_buf.buf) {
                        Ok(_) => break,
                        Err(Error::Done) => {}
                        Err(e) => {
                            return Err(e);
                        }
                    };
                }

                if self.client.data.early_data_rejected {
                    match self.client.process() {
                        Ok(_) => {}
                        Err(Error::Done) => {}
                        Err(e) => {
                            return Err(e);
                        }
                    };
                }
            }
            Ok(())
        }

        fn check_key(
            seal: Option<&boringssl::crypto::Seal>,
            open: Option<&boringssl::crypto::Open>,
        ) -> Result<()> {
            if seal.is_none() || open.is_none() {
                return Err(Error::TlsFail("Key is not ready.".to_string()));
            }

            let seal = seal.unwrap();
            let open = open.unwrap();

            let plaintext = rand::random::<[u8; 32]>();
            let data_len = 10;

            let mut ciphertext = plaintext.clone();
            let counter = rand::random();
            let rsize = seal.seal(None, counter, b"ad", &mut ciphertext, data_len, None)?;

            let mut out = rand::random::<[u8; 32]>();
            let out_len = open.open(None, counter, b"ad", &ciphertext[..rsize], &mut out)?;

            if out[..out_len] != plaintext[..data_len] {
                return Err(Error::CryptoFail);
            }
            Ok(())
        }

        fn check_keys(&self, should_have_zero_rtt: bool) -> Result<()> {
            if self.server.get_keys(Level::ZeroRTT).open.is_some() != should_have_zero_rtt {
                return Err(Error::TlsFail(
                    "server should have zero rtt open key".to_string(),
                ));
            }

            for level in Level::iter() {
                if level == Level::ZeroRTT && !should_have_zero_rtt {
                    continue;
                }

                let client_keys = self.client.get_keys(level);
                let server_keys = self.server.get_keys(level);

                Self::check_key(client_keys.seal.as_ref(), server_keys.open.as_ref())?;
                if level != Level::ZeroRTT {
                    Self::check_key(server_keys.seal.as_ref(), client_keys.open.as_ref())?;
                }
            }
            Ok(())
        }
    }

    #[test]
    fn cert_or_key_format_error() -> Result<()> {
        let mut tls_config = TlsConfig::new()?;

        // Load ca from file failed.
        assert!(tls_config
            .set_ca_certs("./src/tls/testdata/error.crt")
            .is_err());

        // Load cert failed.
        assert!(tls_config
            .set_certificate_file("./src/tls/testdata/error.crt")
            .is_err());

        // Load key failed.
        assert!(tls_config
            .set_private_key_file("./src/tls/testdata/error.key")
            .is_err());

        Ok(())
    }

    #[test]
    fn invalid_cstring_file() -> Result<()> {
        let mut tls_config = TlsConfig::new()?;
        let funcs: Vec<Box<dyn Fn(&mut TlsConfig, &str) -> Result<()>>> = vec![
            Box::new(TlsConfig::set_ca_certs),
            Box::new(TlsConfig::set_certificate_file),
            Box::new(TlsConfig::set_private_key_file),
        ];
        let file = "invalid\0file";
        for func in &funcs {
            match func(&mut tls_config, file) {
                Err(Error::TlsFail(err)) => assert!(err.contains("format error")),
                Err(_) | Ok(_) => assert!(false),
            }
        }

        Ok(())
    }

    #[test]
    fn invalid_cstring_hostname() -> Result<()> {
        let mut client = create_client_session(None, None, false)?;
        match client.session.set_host_name("invalid\0hostname") {
            Err(Error::TlsFail(err)) => assert!(err.contains("host name format error")),
            Err(_) | Ok(_) => assert!(false),
        }

        Ok(())
    }

    #[test]
    fn invalid_ticket_key() -> Result<()> {
        let mut tls_config = TlsConfig::new()?;
        let session_ticket_key = vec![0x0a; 1];
        assert!(tls_config.set_ticket_key(&session_ticket_key).is_err());

        Ok(())
    }

    #[test]
    fn invalid_alpn() -> Result<()> {
        let mut tls_config = TlsConfig::new()?;
        assert!(tls_config.set_application_protos(vec![vec![]]).is_err());

        Ok(())
    }

    #[test]
    fn full_handshake() -> Result<()> {
        let session_ticket_key = vec![0x0a; 48];
        let mut tls_session_pair = TlsSessionPair::new(None, true, session_ticket_key, true)?;

        // 1-RTT handshake.
        tls_session_pair.do_handshake(false)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(!tls_session_pair.client.is_resumed());
        assert!(tls_session_pair.client.peer_cert_chain().is_some());
        assert_eq!(tls_session_pair.client.peer_cert_chain().unwrap().len(), 1);
        assert!(tls_session_pair.server.is_completed());
        assert!(!tls_session_pair.server.is_resumed());

        // Check tls session parameters.
        assert!(tls_session_pair.client.peer_cert().is_some());
        assert!(tls_session_pair.server.peer_cert().is_none());
        assert!(tls_session_pair.client.peer_cert_chain().is_some());
        assert!(tls_session_pair.server.peer_cert_chain().is_none());
        assert!(tls_session_pair.client.curve().is_some());
        assert!(tls_session_pair.server.curve().is_some());
        assert!(tls_session_pair.client.cipher().is_some());
        assert!(tls_session_pair.server.cipher().is_some());
        assert!(tls_session_pair.client.server_name() == Some("example.org"));
        assert!(tls_session_pair.client.peer_transport_params() == b"tp");
        assert!(tls_session_pair.server.peer_transport_params() == b"tp");
        assert!(tls_session_pair.client.alpn_protocol() == b"h3");
        assert!(tls_session_pair.server.alpn_protocol() == b"h3");
        assert!(tls_session_pair.client.write_level() == Level::OneRTT);
        assert!(tls_session_pair.server.write_level() == Level::OneRTT);
        assert!(tls_session_pair.client.error().is_none());
        assert!(tls_session_pair.server.error().is_none());
        assert!(tls_session_pair.client.peer_sign_algor().is_some());
        assert!(tls_session_pair.server.peer_sign_algor() == None);
        assert!(
            tls_session_pair.client.get_overhead(Level::OneRTT)
                == tls_session_pair.server.get_overhead(Level::OneRTT)
        );
        assert!(tls_session_pair.client.data.keylog.is_some());
        assert!(tls_session_pair.server.data.keylog.is_some());
        tls_session_pair.check_keys(false)?;

        // Drop keys.
        tls_session_pair.client.drop_keys(Level::Initial);
        assert!(tls_session_pair
            .client
            .get_keys(Level::Initial)
            .seal
            .is_none());
        assert!(tls_session_pair
            .client
            .get_keys(Level::Initial)
            .open
            .is_none());
        assert!(tls_session_pair
            .client
            .get_overhead(Level::Initial)
            .is_none());

        // Clear session.
        tls_session_pair.client.clear()?;
        tls_session_pair.server.clear()?;
        assert!(tls_session_pair.client.write_level() == Level::Initial);
        assert!(tls_session_pair.server.write_level() == Level::Initial);

        Ok(())
    }

    #[test]
    fn resume_handshake_server_support_early_data() -> Result<()> {
        let session_ticket_key = vec![0x0a; 48];
        let mut tls_session_pair =
            TlsSessionPair::new(None, true, session_ticket_key.clone(), true)?;

        // 1-RTT handshake.
        tls_session_pair.do_handshake(false)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(!tls_session_pair.client.is_resumed());
        assert!(tls_session_pair.server.is_completed());
        assert!(!tls_session_pair.server.is_resumed());

        // 0-RTT handshake.
        let resumption = tls_session_pair.client.session();
        let mut tls_session_pair = TlsSessionPair::new(resumption, true, session_ticket_key, true)?;
        tls_session_pair.do_handshake(true)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(tls_session_pair.client.is_resumed());
        assert!(tls_session_pair.server.is_completed());
        assert!(tls_session_pair.server.is_resumed());
        tls_session_pair.check_keys(true)
    }

    #[test]
    fn resume_handshake_server_not_support_early_data() -> Result<()> {
        let session_ticket_key = vec![0x0a; 48];
        let mut tls_session_pair =
            TlsSessionPair::new(None, true, session_ticket_key.clone(), false)?;

        // 1-RTT handshake.
        tls_session_pair.do_handshake(false)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(!tls_session_pair.client.is_resumed());
        assert!(tls_session_pair.server.is_completed());
        assert!(!tls_session_pair.server.is_resumed());

        // 0-RTT handshake.
        let resumption = tls_session_pair.client.session();
        let mut tls_session_pair =
            TlsSessionPair::new(resumption, true, session_ticket_key.clone(), false)?;
        tls_session_pair.do_handshake(false)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(tls_session_pair.client.is_resumed());
        assert!(tls_session_pair.server.is_completed());
        assert!(tls_session_pair.server.is_resumed());
        tls_session_pair.check_keys(false)
    }

    #[test]
    fn resume_handshake_early_data_rejected() -> Result<()> {
        let session_ticket_key = vec![0x0a; 48];
        let mut tls_session_pair =
            TlsSessionPair::new(None, true, session_ticket_key.clone(), true)?;

        // 1-RTT handshake.
        tls_session_pair.do_handshake(false)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(!tls_session_pair.client.is_resumed());
        assert!(tls_session_pair.server.is_completed());
        assert!(!tls_session_pair.server.is_resumed());

        // 0-RTT handshake.
        let resumption = tls_session_pair.client.session();
        let mut tls_session_pair =
            TlsSessionPair::new(resumption, true, session_ticket_key.clone(), false)?;
        tls_session_pair.do_handshake(true)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(tls_session_pair.client.is_resumed());
        assert!(tls_session_pair.client.data.early_data_rejected);
        assert!(tls_session_pair.server.is_completed());
        assert!(tls_session_pair.server.is_resumed());
        tls_session_pair.check_keys(false)
    }

    #[test]
    fn resume_handshake_ticket_key_change() -> Result<()> {
        let session_ticket_key = vec![0x0a; 48];
        let mut tls_session_pair = TlsSessionPair::new(None, true, session_ticket_key, true)?;

        // 1-RTT handshake.
        tls_session_pair.do_handshake(false)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(!tls_session_pair.client.is_resumed());
        assert!(tls_session_pair.server.is_completed());
        assert!(!tls_session_pair.server.is_resumed());

        // Change session ticket key.
        let session_ticket_key = vec![0x73; 48];

        // 0-RTT handshake.
        let resumption = tls_session_pair.client.session();
        let mut tls_session_pair = TlsSessionPair::new(resumption, true, session_ticket_key, true)?;
        tls_session_pair.do_handshake(true)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(!tls_session_pair.client.is_resumed());
        assert!(tls_session_pair.client.data.early_data_rejected);
        assert!(tls_session_pair.server.is_completed());
        assert!(!tls_session_pair.server.is_resumed());
        tls_session_pair.check_keys(false)
    }

    fn handshake_with_cert_verify(
        ca_path: &str,
        srv_crt: &str,
        srv_key: &str,
    ) -> Result<TlsSessionPair> {
        const TESTDATA: &str = "./src/tls/testdata/";

        let mut client_config = TlsConfig::new_client_config(vec![b"h3".to_vec()], false)?;
        client_config.set_verify(true);
        client_config.set_ca_certs(&(TESTDATA.to_owned() + ca_path))?;

        let server_config = new_server_config(
            vec![0x0a; 48],
            false,
            vec![b"h3".to_vec()],
            &(TESTDATA.to_owned() + srv_crt),
            &(TESTDATA.to_owned() + srv_key),
        )?;

        let mut tls_session_pair =
            TlsSessionPair::new_with_tls_config(&client_config, &server_config)?;

        // 1-RTT handshake.
        tls_session_pair.do_handshake(false)?;

        Ok(tls_session_pair)
    }

    /// Load ca certificate from file.
    #[test]
    fn handshake_with_cert_verify_success() -> Result<()> {
        // `cert3` is issued by `ca.crt`.
        let tls_session_pair = handshake_with_cert_verify("ca.crt", "cert3.crt", "cert3.key")?;
        assert!(tls_session_pair.client.is_completed());
        assert!(tls_session_pair.server.is_completed());

        Ok(())
    }

    /// Load ca certificate from directory.
    #[test]
    fn handshake_with_cert_verify_success2() -> Result<()> {
        // `cas/56c899cd.0` is same as `cert3.crt`.
        let tls_session_pair = handshake_with_cert_verify("cas", "cert3.crt", "cert3.key")?;
        assert!(tls_session_pair.client.is_completed());
        assert!(tls_session_pair.server.is_completed());

        Ok(())
    }

    #[test]
    fn handshake_with_cert_verify_failed() -> Result<()> {
        // `cert.crt` is self-signed.
        match handshake_with_cert_verify("ca.crt", "cert.crt", "cert.key") {
            Err(Error::TlsFail(err)) => assert!(err.contains("CERTIFICATE_VERIFY_FAILED")),
            Err(_) | Ok(_) => assert!(false),
        }

        Ok(())
    }

    pub struct ServerConfigSelector {
        hash_map: HashMap<String, Arc<TlsConfig>>,
    }

    impl ServerConfigSelector {
        pub fn new() -> Result<ServerConfigSelector> {
            let certs = vec!["src/tls/testdata/cert.crt", "src/tls/testdata/cert2.crt"];
            let keys = vec!["src/tls/testdata/cert.key", "src/tls/testdata/cert2.key"];

            let mut cert_manager = ServerConfigSelector {
                hash_map: HashMap::new(),
            };
            let session_ticket_key = vec![0x0a; 48];
            for (index, cert) in certs.iter().enumerate() {
                let tls_config = new_server_config(
                    session_ticket_key.clone(),
                    true,
                    vec![b"h3".to_vec()],
                    cert,
                    keys[index],
                )?;
                cert_manager
                    .hash_map
                    .insert(index.to_string(), tls_config.into());
            }

            Ok(cert_manager)
        }

        pub fn len(&self) -> usize {
            self.hash_map.len()
        }
    }

    impl TlsConfigSelector for ServerConfigSelector {
        fn get_default(&self) -> Option<Arc<TlsConfig>> {
            self.select("0")
        }

        fn select(&self, server_name: &str) -> Option<Arc<TlsConfig>> {
            self.hash_map.get(server_name).cloned()
        }
    }

    fn handshake_with_multi_cert(
        conf_selector: Arc<ServerConfigSelector>,
        hostname: Option<&str>,
    ) -> Result<TlsSessionPair> {
        // New client and server tls session pair.
        let session_ticket_key = vec![0x0a; 48];
        let mut tls_session_pair =
            TlsSessionPair::new_with_hostname(hostname, None, true, session_ticket_key, true)?;
        tls_session_pair.server.set_config_selector(conf_selector);

        // 1-RTT handshake.
        tls_session_pair.do_handshake(false)?;

        Ok(tls_session_pair)
    }

    #[test]
    fn multi_cert_with_known_sni() -> Result<()> {
        let conf_selector = Arc::new(ServerConfigSelector::new()?);

        for i in 0..conf_selector.len() {
            assert_eq!(Arc::strong_count(&conf_selector), 1);

            let server_name = i.to_string();
            let tls_session_pair =
                handshake_with_multi_cert(conf_selector.clone(), Some(&server_name))?;
            assert!(tls_session_pair.client.is_completed());
            assert!(tls_session_pair.client.peer_cert_chain().is_some());
            assert_eq!(
                tls_session_pair.client.peer_cert_chain().unwrap().len(),
                i + 1
            );
            assert!(tls_session_pair.server.is_completed());
            assert_eq!(Arc::strong_count(&conf_selector), 1);
        }

        Ok(())
    }

    #[test]
    fn multi_cert_with_unknown_sni() -> Result<()> {
        let conf_selector = Arc::new(ServerConfigSelector::new()?);

        match handshake_with_multi_cert(conf_selector.clone(), Some("unknown")) {
            Err(Error::TlsFail(err)) => assert!(err.contains("CERT_CB_ERROR")),
            Err(_) | Ok(_) => assert!(false),
        }

        Ok(())
    }

    #[test]
    fn multi_cert_without_sni() -> Result<()> {
        let conf_selector = Arc::new(ServerConfigSelector::new()?);

        let tls_session_pair = handshake_with_multi_cert(conf_selector.clone(), None)?;
        assert!(tls_session_pair.client.is_completed());
        assert!(tls_session_pair.server.is_completed());
        assert!(tls_session_pair.client.server_name() == None);

        Ok(())
    }
}

#[path = "boringssl/boringssl.rs"]
mod boringssl;

mod key;
