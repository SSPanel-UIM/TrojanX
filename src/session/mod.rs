// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

use crate::proto::{Command, UdpPacketBuf, UdpPacketRef, Address, AddressRef};
use crate::utils::{poll_fn, ready};

mod context;
pub use context::*;

pub enum ServerRelaySession<C> {
    Udp(UdpSession<C>),
    Tcp(TcpSession<C>),
}

impl<C> ServerRelaySession<C>
where
    C: TrafficControl + Unpin,
{
    /// Init a session without performing any IO
    pub async fn new(cmd: Command, addr: &AddressRef<'_>, ctrl: C) -> io::Result<ServerRelaySession<C>> {
        match cmd {
            Command::Connect => {
                let session = TcpSession::new_accept(addr, ctrl).await?;
                Ok(ServerRelaySession::Tcp(session))
            }
            Command::UdpAssociate => {
                let session = UdpSession::new(addr, ctrl).await?;
                Ok(ServerRelaySession::Udp(session))
            }
        }
    }

    pub async fn run<S>(self, stream: S, payload: &[u8]) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        match self {
            Self::Tcp(s) => s.run(stream, payload).await,
            Self::Udp(s) => s.run(stream, payload).await,
        }
    }
}

pub struct TcpSession<C> {
    ctrl: C,
    socket: TcpStream,
}

impl<C> TcpSession<C>
where
    C: TrafficControl + Unpin,
{
    pub async fn new_accept(addr: &AddressRef<'_>, ctrl: C) -> io::Result<TcpSession<C>> {
        let socket = addr.open_tcp().await?;
        Ok(TcpSession {
            ctrl,
            socket,
        })
    }

    pub async fn run<S>(mut self, stream: S, payload: &[u8]) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !payload.is_empty() {
            let _ = self.socket.write(payload).await?;
            self.ctrl.consume_tx(payload.len());
            poll_fn(|cx| self.ctrl.poll_pause(cx)).await;
        }
        Self::wrap_copy(stream, self.socket, self.ctrl).await
    }

    pub async fn wrap_copy<S>(stream: S, mut socket: TcpStream, ctrl: C) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut stream = StreamWrapper::new(stream, ctrl);
        tokio::io::copy_bidirectional(&mut stream, &mut socket).await?;
        Ok(())
    }
}

const PAYLOAD_LEN: usize = 8192;

pub struct UdpSession<C> {
    ctrl: C,
    socket: UdpSocket,
    dest: Address,
    buf: UdpPacketBuf,
}

impl<C> UdpSession<C>
where
    C: TrafficControl + Unpin,
{
    pub async fn new(addr: &AddressRef<'_>, ctrl: C) -> io::Result<UdpSession<C>> {
        let buf = UdpPacketBuf::new();
        Ok(UdpSession {
            ctrl,
            socket: addr.open_udp().await?,
            dest: (*addr).to_owned(),
            buf,
        })
    }

    pub async fn run<IO>(mut self, stream: IO, payload: &[u8]) -> io::Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.buf.write(payload);
        self.buf.process_new_packet()?;
        let status = match self.buf.read() {
            Some(_) => UdpSessionStatus::UdpSend,
            None => UdpSessionStatus::Recv,
        };

        UdpSessionFut {
            read_buf: vec![0; PAYLOAD_LEN],
            status,
            buf: self.buf,
            ctrl: self.ctrl,
            socket: self.socket,
            dest: self.dest,
            stream,
        }.await
    }
}

enum UdpSessionStatus {
    Recv,
    UdpSend,
    StreamSend(Vec<u8>),
    Shutdown,
}

struct UdpSessionFut<C, IO> {
    read_buf: Vec<u8>,
    status: UdpSessionStatus,
    buf: UdpPacketBuf,
    ctrl: C,
    socket: UdpSocket,
    dest: Address,
    stream: IO,
}

impl<C, IO> Future for UdpSessionFut<C, IO>
where
    C: TrafficControl + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use UdpSessionStatus::*;

        let mut this = self.get_mut();

        loop {
            match &this.status {
                Recv => {
                    ready!(this.ctrl.poll_pause(cx));

                    let mut buf = ReadBuf::new(&mut this.read_buf);
                    if Pin::new(&mut this.stream)
                        .poll_read(cx, &mut buf)?
                        .is_ready()
                    {
                        let filled = buf.filled();
                        if filled.is_empty() {
                            this.status = Shutdown;
                        } else {
                            this.buf.write(filled);
                            this.buf.process_new_packet()?;
                            this.status = UdpSend;
                        }
                        continue;
                    }
                    if this.socket.poll_recv(cx, &mut buf)?.is_ready() {
                        let bytes = UdpPacketRef::new(this.dest.as_ref(), buf.filled()).as_bytes();
                        this.status = StreamSend(bytes);
                        continue;
                    }
                    return Poll::Pending;
                }
                UdpSend => match this.buf.read() {
                    Some(p) => {
                        if p.payload.len() <= PAYLOAD_LEN {
                            let n = ready!(this.socket.poll_send(cx, p.payload))?;
                            this.ctrl.consume_tx(n);
                        }
                        this.buf.process_new_packet()?;
                    }
                    None => this.status = Recv,
                },
                StreamSend(p) => {
                    let n = ready!(Pin::new(&mut this.stream).poll_write(cx, p))?;
                    this.ctrl.consume_rx(n);
                    this.status = Recv;
                }
                Shutdown => {
                    ready!(Pin::new(&mut this.stream).poll_shutdown(cx))?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}
