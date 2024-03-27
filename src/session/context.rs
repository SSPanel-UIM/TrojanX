use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::Bytes;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::proto::{Command, Address};
use crate::utils::ProxyProtocolV2;

/// Fallback Policy
#[derive(Debug, serde::Deserialize)]
pub enum Fallback {
    /// Fallback with proxy protocol
    #[serde(rename = "proxy")]
    Proxy(SocketAddr),
    /// Fallback without proxy protocol
    #[serde(rename = "connect")]
    Connect(SocketAddr),
    /// **NOT RECOMMANDED**: Reject connection
    #[serde(rename = "reject")]
    Reject,
}

impl Default for Fallback {
    /// Default to reject connection
    fn default() -> Self {
        Self::Reject
    }
}

impl Fallback {
    pub async fn fallback<S>(&self, stream: &mut S, data: &[u8]) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + ConnectionInfo + Unpin,
    {
        match self {
            Fallback::Connect(a) => {
                let mut downgrade = TcpStream::connect(a).await?;

                let n = downgrade.write(data).await?;
                debug_assert_eq!(n, data.len());

                tokio::io::copy_bidirectional(stream, &mut downgrade).await?;
            }
            Fallback::Proxy(a) => {
                let src = stream.remote_addr()?;
                let dest = stream.local_addr()?;

                let mut downgrade = TcpStream::connect(a).await?;

                let proxy_headers = ProxyProtocolV2::new(src, dest).encode();
                let n = downgrade.write(&proxy_headers).await?;
                debug_assert_eq!(n, proxy_headers.len());

                let n = downgrade.write(data).await?;
                debug_assert_eq!(n, data.len());
                tokio::io::copy_bidirectional(stream, &mut downgrade).await?;
            }
            Fallback::Reject => { /* Do nothing */ }
        }
        Ok(())
    }
}

pub trait ServerSession {
    fn cmd(&self) -> Command;

    fn address(&self) -> &Address;

    fn payload(&self) -> &Bytes;

    /// Add tx(transmission) bytes number, change self status.
    fn consume_tx(&mut self, bytes: usize);

    /// Add rx(receive) bytes number, change self status.
    fn consume_rx(&mut self, bytes: usize);

    /// Poll pause event.
    fn poll_pause(&mut self, cx: &mut Context<'_>) -> Poll<()>;
}

impl<T> ServerSession for &mut T
where
    T: ServerSession,
{
    fn cmd(&self) -> Command {
        (**self).cmd()
    }

    fn address(&self) -> &Address {
        (**self).address()
    }

    fn payload(&self) -> &Bytes {
        (**self).payload()
    }

    fn consume_rx(&mut self, bytes: usize) {
        (*self).consume_rx(bytes)
    }

    fn consume_tx(&mut self, bytes: usize) {
        (*self).consume_tx(bytes)
    }

    fn poll_pause(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        (*self).poll_pause(cx)
    }
}

pub struct StreamWrapper<IO, C> {
    stream: IO,
    pub ctx: C,
}

impl<IO, C> StreamWrapper<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: ServerSession + Unpin,
{
    pub fn new(stream: IO, ctrl: C) -> Self {
        Self { stream, ctx: ctrl }
    }
}

impl<IO, C> AsyncWrite for StreamWrapper<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: ServerSession + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        ready!(this.ctx.poll_pause(cx));
        let ret = Pin::new(&mut this.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = ret {
            this.ctx.consume_rx(n);
        }
        ret
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        ready!(this.ctx.poll_pause(cx));
        let ret = Pin::new(&mut this.stream).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = ret {
            this.ctx.consume_rx(n);
        }
        ret
    }
}

impl<IO, C> AsyncRead for StreamWrapper<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: ServerSession + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.ctx.poll_pause(cx));
        let ret = Pin::new(&mut this.stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(_)) = ret {
            this.ctx.consume_tx(buf.filled().len());
        }
        ret
    }
}

pub trait ConnectionInfo {
    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn remote_addr(&self) -> io::Result<SocketAddr>;
}

impl ConnectionInfo for TcpStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr()
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr()
    }
}

impl<S> ConnectionInfo for TlsStream<S>
where
    S: ConnectionInfo,
{
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.local_addr()
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.remote_addr()
    }
}
