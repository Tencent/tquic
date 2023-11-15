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

#![no_main]

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

use lazy_static::lazy_static;
use libfuzzer_sys::fuzz_target;

use tquic::Config;
use tquic::ConnectionId;
use tquic::TlsConfig;

lazy_static! {
    static ref CONFIG: Mutex<tquic::Config> = {
        let mut conf = Config::new().unwrap();
        let tls_conf = TlsConfig::new_client_config(vec![b"h3".to_vec()], false).unwrap();
        conf.set_tls_config(tls_conf);
        Mutex::new(conf)
    };
}

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let local: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let info = tquic::PacketInfo {
        src: remote,
        dst: local,
        time: Instant::now(),
    };

    let mut conn = tquic::Connection::new_client(
        &ConnectionId::random(),
        local,
        remote,
        None,
        &mut CONFIG.lock().unwrap(),
    )
    .unwrap();
    conn.recv(&mut buf, &info).ok();
});
