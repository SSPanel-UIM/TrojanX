// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::{self, Instant, Sleep};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::server::TlsStream;

use crate::proto::Password;
use crate::session::{Fallback, TrafficControl};
use crate::sspanel::client::{IpData, UpdateData, UserRaw};
use crate::utils::limiter::Limiter;
use crate::utils::RawHasherBuilder;

pub struct UserContext {
    pub id: usize,
    rx: AtomicU64,
    tx: AtomicU64,
    limiter: Limiter,
    ips: Mutex<(HashSet<IpAddr>, Option<usize>)>,
}

impl UserContext {
    pub fn into_session(self: Arc<Self>) -> UserSessionContext {
        UserSessionContext {
            tx: 0,
            rx: 0,
            start: Instant::now(),
            inner: self,
            sleep: Box::pin(time::sleep(Duration::ZERO)),
        }
    }
}

impl UserRaw {
    pub fn as_server_user(&self) -> (Password, Arc<UserContext>) {
        let speed = self.speed_limit();

        let user = UserContext {
            id: self.id,
            rx: AtomicU64::new(0),
            tx: AtomicU64::new(0),
            limiter: Limiter::new(speed),
            ips: Mutex::new((HashSet::default(), self.ip_limit())),
        };
        (self.pwd, Arc::new(user))
    }

    pub fn update_ctx(&self, ctx: &UserContext) {
        ctx.limiter.set_speed_limit(self.speed_limit());
        ctx.ips.lock().unwrap().1 = self.ip_limit();
    }
}

pub enum UserVerifyError {
    Password,
    IpLimit,
}

pub struct ServerContext {
    pub fallback: Fallback,
    pub alpn_fallback: HashMap<String, Fallback>,

    pub(crate) tls: Arc<ServerConfig>,

    pub(crate) users: RwLock<HashMap<Password, Arc<UserContext>, RawHasherBuilder>>,
}

impl ServerContext {
    #[inline]
    pub fn new(tls: Arc<ServerConfig>) -> ServerContext {
        ServerContext {
            tls,
            alpn_fallback: HashMap::new(),
            fallback: Fallback::default(),
            users: RwLock::new(HashMap::with_hasher(RawHasherBuilder)),
        }
    }

    #[inline]
    pub fn verify(
        &self,
        src: &SocketAddr,
        pwd: &Password,
    ) -> Result<Arc<UserContext>, UserVerifyError> {
        let users = self.users.read().unwrap();

        // verify password
        let user = users.get(pwd).ok_or(UserVerifyError::Password)?;

        // online ip
        let ip = src.ip();
        let mut ip_guard = user.ips.lock().unwrap();
        ip_guard.0.insert(ip);

        if let Some(n) = ip_guard.1 {
            if ip_guard.0.len() > n {
                // if ip count has over the ip_limit, it must be the current one
                ip_guard.0.remove(&ip);
                log::info!("user {} from {} exceed ip limit", user.id, src);
                return Err(UserVerifyError::IpLimit);
            }
        }
        Ok(user.clone())
    }

    pub async fn downgrade(
        &self,
        stream: &mut TlsStream<TcpStream>,
        data: &[u8],
    ) -> io::Result<()> {
        let mut fallback = &self.fallback;
        if let Some(alpn) = stream.get_ref().1.alpn_protocol() {
            // SAFETY: just to find in map
            let alpn = unsafe { std::str::from_utf8_unchecked(alpn) };
            if let Some(f) = self.alpn_fallback.get(alpn) {
                fallback = f;
            }
        }
        fallback.fallback(stream, data).await
    }
}

impl ServerContext {
    #[inline]
    pub fn collect_update(&self) -> Vec<UpdateData> {
        let users = self.users.read().unwrap();
        users
            .iter()
            .filter_map(|(p, u)| {
                let tx = u.tx.load(Ordering::Relaxed);
                let rx = u.rx.load(Ordering::Relaxed);
                if tx > 0 || rx > 0 {
                    Some(UpdateData {
                        user_id: u.id,
                        tx,
                        rx,
                        pwd: *p,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    #[inline]
    pub fn assume_update(&self, data: &[UpdateData]) {
        let users = self.users.read().unwrap();
        for i in data {
            if let Some(u) = users.get(&i.pwd) {
                u.tx.fetch_sub(i.tx, Ordering::Relaxed);
                u.rx.fetch_sub(i.rx, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    pub fn collect_ip(&self) -> Vec<IpData> {
        let users = self.users.read().unwrap();
        let mut data = Vec::new();
        let iter = users.values();
        for u in iter {
            let mut guard = u.ips.lock().unwrap();
            data.extend(guard.0.drain().map(|ip| IpData { user_id: u.id, ip }));
        }
        data
    }
}

pub struct UserSessionContext {
    pub tx: u64,
    pub rx: u64,
    pub start: Instant,
    inner: Arc<UserContext>,
    sleep: Pin<Box<Sleep>>,
}

impl UserSessionContext {
    pub fn id(&self) -> usize {
        self.inner.id
    }

    fn consume_limiter(&mut self, bytes: usize) {
        let dur = self.inner.limiter.consume(bytes);
        if !dur.is_zero() {
            let sleep = self.sleep.as_mut();
            let deadline = if sleep.is_elapsed() {
                Instant::now() + dur
            } else {
                sleep.deadline() + dur
            };
            sleep.reset(deadline);
        }
    }
}

impl TrafficControl for UserSessionContext {
    fn consume_tx(&mut self, bytes: usize) {
        self.inner.tx.fetch_add(bytes as u64, Ordering::Relaxed);
        self.tx += bytes as u64;
        self.consume_limiter(bytes);
    }

    fn consume_rx(&mut self, bytes: usize) {
        self.inner.rx.fetch_add(bytes as u64, Ordering::Relaxed);
        self.rx += bytes as u64;
        self.consume_limiter(bytes);
    }

    fn poll_pause(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.sleep.as_mut().poll(cx)
    }
}
