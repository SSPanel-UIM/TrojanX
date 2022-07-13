// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

//! Trojan Server

mod context;
mod session;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::PathBuf;
use std::sync::Arc;

use tokio_rustls::rustls::server::{
    ClientHello, NoServerSessionStorage, ResolvesServerCert, ResolvesServerCertUsingSni,
    ServerSessionMemoryCache,
};
use tokio_rustls::rustls::sign::{any_supported_type, CertifiedKey};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};

pub use context::*;
pub use session::*;

#[derive(serde::Deserialize)]
pub struct TlsConfig {
    servers: HashMap<String, Server>,

    #[serde(default)]
    max_early_data: u32,
    #[serde(default)]
    prefer_server_cipher: bool,
    #[serde(default)]
    session_cache_size: usize,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
    max_fragment_size: Option<usize>,
}

impl TlsConfig {
    pub fn build(self) -> io::Result<Arc<ServerConfig>> {
        let cert_resolver = Arc::new(CertResolver::new(self.servers)?);

        let mut ctx = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver);

        ctx.max_early_data_size = self.max_early_data;
        ctx.max_fragment_size = self.max_fragment_size;
        ctx.ignore_client_order = self.prefer_server_cipher;
        ctx.alpn_protocols = self.alpn.into_iter().map(String::into_bytes).collect();
        ctx.session_storage = if self.session_cache_size > 0 {
            ServerSessionMemoryCache::new(self.session_cache_size)
        } else {
            Arc::new(NoServerSessionStorage {})
        };

        Ok(Arc::new(ctx))
    }
}

#[derive(serde::Deserialize)]
pub struct Server {
    cert_chain: PathBuf,
    priv_key: PathBuf,
}

impl Server {
    pub fn build(self) -> io::Result<CertifiedKey> {
        let cert_file = File::open(self.cert_chain)?;
        let cert: Vec<Certificate> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .map(|x| x.into_iter().map(Certificate).collect())?;

        let key_file = File::open(self.priv_key)?;
        let key = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(key_file))
            .map(|mut keys| keys.pop().map(|key| any_supported_type(&PrivateKey(key))))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty private key"))?
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(CertifiedKey {
            cert,
            key,
            ocsp: None,
            sct_list: None,
        })
    }
}

struct CertResolver {
    inner: ResolvesServerCertUsingSni,
    default: Option<Arc<CertifiedKey>>,
}

impl CertResolver {
    pub fn new(map: HashMap<String, Server>) -> io::Result<CertResolver> {
        let mut inner = ResolvesServerCertUsingSni::new();
        let mut default = None;

        for (name, server) in map {
            let certified_key = server.build()?;
            if name == "default" {
                default = Some(Arc::new(certified_key));
            } else {
                inner
                    .add(&name, certified_key)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            }
        }

        Ok(CertResolver { inner, default })
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(ck) = self.inner.resolve(client_hello) {
            return Some(ck);
        }
        self.default.as_ref().cloned()
    }
}
