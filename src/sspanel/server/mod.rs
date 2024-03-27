use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::rustls::server::Acceptor;
use tokio_rustls::server::TlsStream;
use tokio_rustls::LazyConfigAcceptor;

use crate::proto::Request;
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

        let mut ctx;
        let (session, stream) = if buf.is_empty() {
            // without early data
            let mut stream = accept.await?;

            stream.read_buf(&mut buf).await?;
            let bytes = Bytes::from(buf);
            ctx = match self.parse_verify(bytes.clone()) {
                Ok(Some(x)) => x,
                Ok(None) => return Ok(()),
                Err(e) => return self.fallback(e, stream, &bytes).await,
            };

            (ServerRelaySession::new(&mut ctx).await?, stream)
        } else {
            // with early data
            log::debug!("early data session from {}", self.src);

            let bytes = Bytes::from(buf);
            ctx = match self.parse_verify(bytes.clone()) {
                Ok(Some(x)) => x,
                Ok(None) => return Ok(()),
                Err(e) => {
                    let stream = accept.await?;
                    return self.fallback(e, stream, &bytes).await;
                }
            };

            tokio::try_join!(ServerRelaySession::new(&mut ctx), accept)?
        };

        let _ = session.run(stream).await;
        
        log::info!(
            "user: {}, tunnel {} <-> {}/{} end, {}/{}/{:.2} s",
            ctx.id(),
            self.src,
            ctx.addr(),
            ctx.cmd(),
            ctx.tx,
            ctx.rx,
            Instant::now().duration_since(ctx.start).as_secs_f64()
        );
        Ok(())
    }

    fn parse_verify(&self, data: Bytes) -> Result<Option<UserSessionContext>, &'static str> {
        let req = Request::from_bytes(data).map_err(|_| "failed to parse")?;
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
        let ctx = user.into_session(req);
        Ok(Some(ctx))
    }

    async fn fallback(
        &self,
        err: &str,
        mut src: TlsStream<TcpStream>,
        data: &[u8],
    ) -> io::Result<()> {
        log::info!("fallback from {}: {}", self.src, err);
        self.ctx.downgrade(&mut src, data).await
    }
}
