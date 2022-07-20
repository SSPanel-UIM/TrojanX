// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// 
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use std::net::SocketAddr;

use log::LevelFilter;
use trojan_x::server::{Fallback, TlsConfig};
use trojan_x::sspanel::client::Client;
use trojan_x::sspanel::server::{Server, ServerContext};

fn main() {
    unsafe { simple_logger::init().unwrap_unchecked() };

    log::set_max_level(LevelFilter::Info);

    log::info!("TrojanR for SSPanel. v0.0.1. license under MPL-2.0.");

    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            log::warn!("no config file path provided, using config.json");
            String::from("config.json")
        }
    };

    fn run_with_path(path: String) -> io::Result<()> {
        let file = File::open(path)?;
        let cfg: Config = match serde_json::from_reader(file) {
            Ok(c) => c,
            Err(e) =>  return Err(io::Error::new(io::ErrorKind::InvalidData, e))
        };
        cfg.run()
    }

    if let Err(e) = run_with_path(path) {
        log::error!("exited unexpectedly: {}", e);
    }
}

#[derive(serde::Deserialize)]
pub struct Config {
    log_level: log::LevelFilter,

    listen: Vec<SocketAddr>,

    id: usize,
    key: String,
    base_url: String,
    #[serde(default)]
    duration: Option<u64>,

    #[serde(default)]
    fallback: Fallback,
    #[serde(default)]
    alpn_fallback: HashMap<String, Fallback>,
    
    tls: TlsConfig,
}

impl Config {
    #[inline]
    fn run(self) -> io::Result<()> {
        log::set_max_level(self.log_level);

        // tls context
        let ssl_ctx = self.tls.build()?;

        // all done, start tokio runtime
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

        // server
        let mut server_ctx = ServerContext::new(ssl_ctx);
        server_ctx.fallback = self.fallback;
        server_ctx.alpn_fallback = self.alpn_fallback;
        let server_ctx = Arc::new(server_ctx);

        for bind in self.listen {
            let ctx = server_ctx.clone();
            let server = Server { bind, ctx };
            rt.spawn(async move {
                if let Err(e) = server.run().await {
                    log::error!("server fatal {}", e);
                }
            });
        }

        // client
        let mut client = Client::new(server_ctx);
        client.id = self.id;
        client.key = self.key;
        client.base_url = self.base_url;
        if let Some(d) = self.duration {
            client.duration = Duration::from_secs(d);
        }
        rt.spawn(client.run());

        rt.block_on(tokio::signal::ctrl_c())?;
        log::info!("SIGINT received, exiting...");

        Ok(())
    }
}
