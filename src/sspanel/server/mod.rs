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
use tokio_rustls::server::TlsStream;

use crate::proto::RequestRef;
use crate::session::ServerRelaySession;

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

        let mut buf = Vec::with_capacity(1024);
        let accept = handshake.into_stream_with(self.ctx.tls.clone(), |c| {
            if c.process_new_packets().is_ok() {
                if let Some(mut d) = c.early_data() {
                    if let Ok(n) = d.read_to_end(&mut buf) {
                        log::debug!("read {} bytes early data", n);
                    }
                }
            }
        });

        let req;
        let mut ctx;
        let (session, stream) = if buf.is_empty() {
            let mut stream = accept.await?;

            stream.read_buf(&mut buf).await?;
            match self.parse_verify(&buf) {
                Ok(Some((r, u))) => {
                    req = r;
                    ctx = u.into_session();
                }
                Ok(None) => return Ok(()),
                Err(e) => return self.fallback(e, stream, &buf).await
            };

            (ServerRelaySession::new(req.cmd, &req.addr, &mut ctx).await?, stream)
        } else {
            log::debug!("early data session from {}", self.src);
            match self.parse_verify(&buf) {
                Ok(Some((r, u))) => {
                    req = r;
                    ctx = u.into_session();
                }
                Ok(None) => return Ok(()),
                Err(e) => {
                    let stream = accept.await?;
                    return self.fallback(e, stream, &buf).await;
                }
            };

            tokio::try_join!(ServerRelaySession::new(req.cmd, &req.addr, &mut ctx), accept)?
        };

        let _ = session.run(stream, req.payload).await;
        self.log_end(ctx, req);
        Ok(())
    }

    fn parse_verify<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<Option<(RequestRef<'a>, Arc<UserContext>)>, &'static str> {
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

    async fn fallback(&self, err: &str, mut src: TlsStream<TcpStream>, data: &[u8]) -> io::Result<()> {
        log::info!("fallback from {}: {}", self.src, err);
        self.ctx.downgrade(&mut src, data).await
    }
}
