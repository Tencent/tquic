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

use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;

use clap::builder::PossibleValue;
use clap::ValueEnum;
use log::debug;
use mio::net::UdpSocket;
use mio::Interest;
use mio::Registry;
use mio::Token;
use rustc_hash::FxHashMap;
use slab::Slab;

use tquic::PacketInfo;
use tquic::PacketSendHandler;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Supported application protocols.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub enum ApplicationProto {
    /// Proto for QUIC interop, see https://github.com/quic-interop/quic-interop-runner
    Interop,

    /// HTTP/0.9, see https://http.dev/0.9
    Http09,

    /// HTTP/3, see https://www.rfc-editor.org/rfc/rfc9114.html
    #[default]
    H3,
}

impl ApplicationProto {
    /// Create a new ApplicationProto from byte slice.
    pub fn from_slice(proto: &[u8]) -> Self {
        match proto {
            b"hq-interop" => Self::Interop,
            b"http/0.9" => Self::Http09,
            b"h3" => Self::H3,
            _ => unreachable!(),
        }
    }

    /// Convert an ApplicationProto into a byte slice.
    pub fn to_slice(&self) -> &[u8] {
        match self {
            Self::Interop => b"hq-interop",
            Self::Http09 => b"http/0.9",
            Self::H3 => b"h3",
        }
    }

    /// Convert an ApplicationProto slice to a two-dimension byte vector.
    pub fn convert_to_vec(protos: &[Self]) -> Vec<Vec<u8>> {
        protos
            .iter()
            .map(|proto| proto.to_slice().to_vec())
            .collect()
    }
}

impl ValueEnum for ApplicationProto {
    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(match self {
            Self::Interop => PossibleValue::new("hq-interop"),
            Self::Http09 => PossibleValue::new("http/0.9"),
            Self::H3 => PossibleValue::new("h3"),
        })
    }

    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Interop, Self::Http09, Self::H3]
    }
}

/// UDP socket wrapper for QUIC
pub struct QuicSocket {
    /// The underlying UDP sockets for QUIC Endpoint.
    socks: Slab<UdpSocket>,

    /// The mappings between local address and socket identifier.
    addrs: FxHashMap<SocketAddr, usize>,

    /// Local address of the initial socket.
    local_addr: SocketAddr,
}

impl QuicSocket {
    pub fn new(local: &SocketAddr, registry: &Registry) -> Result<Self> {
        let mut socks = Slab::new();
        let mut addrs = FxHashMap::default();

        let socket = UdpSocket::bind(*local)?;
        let local_addr = socket.local_addr()?;
        let sid = socks.insert(socket);
        addrs.insert(local_addr, sid);

        let socket = socks.get_mut(sid).unwrap();
        registry.register(socket, Token(sid), Interest::READABLE)?;

        Ok(Self {
            socks,
            addrs,
            local_addr,
        })
    }

    pub fn new_client_socket(is_ipv4: bool, registry: &Registry) -> Result<Self> {
        let local = match is_ipv4 {
            true => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            false => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        QuicSocket::new(&SocketAddr::new(local, 0), registry)
    }

    /// Return the local address of the initial socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Add additional socket binding with given local address.
    pub fn add(&mut self, local: &SocketAddr, registry: &Registry) -> Result<()> {
        let socket = UdpSocket::bind(*local)?;
        let local_addr = socket.local_addr()?;
        let sid = self.socks.insert(socket);
        self.addrs.insert(local_addr, sid);

        let socket = self.socks.get_mut(sid).unwrap();
        registry.register(socket, Token(sid), Interest::READABLE)?;
        Ok(())
    }

    /// Delete socket binding with given local address.
    pub fn del(&mut self, local: &SocketAddr, registry: &Registry) -> Result<()> {
        let sid = match self.addrs.get(local) {
            Some(sid) => *sid,
            None => return Ok(()),
        };

        let socket = match self.socks.get_mut(sid) {
            Some(socket) => socket,
            None => return Ok(()),
        };

        registry.deregister(socket)?;
        self.socks.remove(sid);
        Ok(())
    }

    /// Receive data from the socket.
    pub fn recv_from(
        &self,
        buf: &mut [u8],
        token: mio::Token,
    ) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
        let socket = match self.socks.get(token.0) {
            Some(socket) => socket,
            None => return Err(std::io::Error::new(ErrorKind::Other, "invalid token")),
        };

        match socket.recv_from(buf) {
            Ok((len, remote)) => Ok((len, socket.local_addr()?, remote)),
            Err(e) => Err(e),
        }
    }

    /// Send data on the socket to the given address.
    /// Note: packets with unknown src address are dropped.
    pub fn send_to(&self, buf: &[u8], src: SocketAddr, dst: SocketAddr) -> std::io::Result<usize> {
        let sid = match self.addrs.get(&src) {
            Some(sid) => sid,
            None => {
                debug!("send_to drop packet with unknown address {:?}", src);
                return Ok(buf.len());
            }
        };

        match self.socks.get(*sid) {
            Some(socket) => Ok(socket.send_to(buf, dst)?),
            None => {
                debug!("send_to drop packet with unknown address {:?}", src);
                Ok(buf.len())
            }
        }
    }
}

impl PacketSendHandler for QuicSocket {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
        let mut count = 0;
        for (pkt, info) in pkts {
            if let Err(e) = self.send_to(pkt, info.src, info.dst) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("socket send would block");
                    return Ok(count);
                }
                return Err(tquic::Error::InvalidOperation(format!(
                    "socket send_to(): {:?}",
                    e
                )));
            }
            debug!("written {} bytes", pkt.len());
            count += 1;
        }
        Ok(count)
    }
}
