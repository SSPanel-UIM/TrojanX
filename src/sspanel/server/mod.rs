// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// 
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::LazyConfigAcceptor;

use crate::proto::RequestRef;
use crate::server::RelaySession;

pub mod context;

pub use context::{ServerContext, UserContext, UserVerifyError};

use self::context::UserSessionContext;

pub struct Server {
    pub bind: SocketAddr,
    pub ctx: Arc<ServerContext>,
}

impl Server {
    pub async fn run(self) -> io::Result<()> {
        let tcp = TcpListener::bind(self.bind).await?;

        log::info!("listen on {}/tcp", self.bind);
        loop {
            let (stream, src) = match tcp.accept().await {
                Ok(x) => x,
                Err(e) => {
                    log::error!("tcp accept: {}", e);
                    continue;
                }
            };
            let session = ServerSession {
                src,
                ctx: self.ctx.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = session.run(stream).await {
                    log::error!("incoming from {}: {}", src, e);
                }
            });
        }
    }
}

pub struct ServerSession {
    src: SocketAddr,
    ctx: Arc<ServerContext>,
}

impl ServerSession {
    pub async fn run(self, stream: TcpStream) -> io::Result<()> {
        log::debug!("tcp incoming from {}", self.src);

        let _ = stream.set_nodelay(true);
        let acceptor = LazyConfigAcceptor::new(Acceptor::new().unwrap(), stream);
        let handshake = acceptor.await?;

        // try to read early data
        let mut early_data = Vec::new();
        let accept = handshake.into_stream_with(self.ctx.tls.clone(), |c| {
            if c.process_new_packets().is_ok() {
                if let Some(mut d) = c.early_data() {
                    if let Ok(n) = d.read_to_end(&mut early_data) {
                        log::debug!("read {} bytes early data", n);
                    }
                }
            }
        });

        if early_data.is_empty() {
            let mut stream = accept.await?;

            // to read first data, a tiny buffer is enough
            let mut buf = [0; 512];
            let n = stream.read(&mut buf).await?;
            let header = &buf[..n];

            let (req, user) = match self.parse_verify(header) {
                Ok(Some(x)) => x,
                Ok(None) => return Ok(()),
                Err(e) => {
                    self.log_fallback(e);
                    self.ctx.downgrade(&mut stream, header).await?;
                    return Ok(());
                }
            };

            let mut ctx = user.into_session();
            let session = RelaySession::new(&req, &mut ctx).await?;
            let _ = session.run(stream).await;
            self.log_end(ctx, req);
        } else {
            log::debug!("early data session from {}", self.src);
            let (req, user) = match self.parse_verify(&early_data) {
                Ok(Some(x)) => x,
                Ok(None) => return Ok(()),
                Err(e) => {
                    self.log_fallback(e);
                    let mut stream = accept.await?;
                    self.ctx.downgrade(&mut stream, &early_data).await?;
                    return Ok(());
                }
            };

            let mut ctx = user.into_session();
            let (session, stream) = tokio::try_join!(RelaySession::new(&req, &mut ctx), accept)?;
            let _ = session.run(stream).await;
            self.log_end(ctx, req);
        }
        Ok(())
    }

    fn parse_verify<'a>(&self, data: &'a [u8]) -> Result<Option<(RequestRef<'a>, Arc<UserContext>)>, &'static str> {
        let req = RequestRef::from_bytes(data).map_err(|_| "failed to parse")?;
        let user = match self.ctx.verify(&self.src, &req.pwd) {
            Ok(u) => u,
            Err(UserVerifyError::Password) => return Err("bad password"),
            Err(UserVerifyError::IpLimit) => return Ok(None),
        };
        log::info!(
            "user: {}, tunnel {} <-> {}/{} start",
            user.id,
            self.src,
            req.addr,
            req.cmd,
        );
        Ok(Some((req, user)))
    }

    fn log_end(&self, ctx: UserSessionContext, req: RequestRef<'_>) {
        log::info!(
            "user: {}, tunnel {} <-> {}/{} end, {}/{}/{} ms",
            ctx.id(),
            self.src,
            req.addr,
            req.cmd,
            ctx.tx,
            ctx.rx,
            Instant::now().duration_since(ctx.start).as_millis()
        );
    }

    fn log_fallback(&self, err: &'static str) {
        log::info!("fallback from {}: {}", self.src, err);
    }
}
