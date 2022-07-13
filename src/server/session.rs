// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

use crate::proto::{Address, Command, RequestRef, UdpPacketBuf, UdpPacketRef};

use super::{StreamWrapper, TrafficControl};

pub enum RelaySession<'a, C> {
    Udp(UdpSession<'a, C>),
    Tcp(TcpSession<'a, C>),
}

impl<'a, C> RelaySession<'a, C>
where
    C: TrafficControl + Unpin,
{
    /// Init a session without performing any IO
    pub async fn new(req: &'a RequestRef<'a>, ctrl: C) -> io::Result<RelaySession<'a, C>> {
        match req.cmd {
            Command::Connect => {
                let session = TcpSession::new(req, ctrl).await?;
                Ok(RelaySession::Tcp(session))
            }
            Command::UdpAssociate => {
                let session = UdpSession::new(req, ctrl).await?;
                Ok(RelaySession::Udp(session))
            }
        }
    }

    pub async fn run<S>(self, mut stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        match self {
            Self::Tcp(s) => s.run(&mut stream).await,
            Self::Udp(s) => s.run(&mut stream).await,
        }
    }
}

pub struct TcpSession<'a, C> {
    ctrl: C,
    socket: TcpStream,
    payload: &'a [u8],
}

impl<'a, C> TcpSession<'a, C>
where
    C: TrafficControl + Unpin,
{
    pub async fn new(req: &'a RequestRef<'a>, ctrl: C) -> io::Result<TcpSession<'a, C>> {
        let socket = req.addr.into_enum().open_tcp().await?;
        Ok(TcpSession {
            ctrl,
            socket,
            payload: req.payload,
        })
    }

    pub async fn run<IO>(mut self, stream: &'a mut IO) -> io::Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.ctrl.consume_tx(self.payload.len());
        let fut = poll_fn(|cx| self.ctrl.poll_pause(cx));
        tokio::join!(fut, self.socket.write(self.payload)).1?;
        let mut stream = StreamWrapper::new(stream, self.ctrl);
        tokio::io::copy_bidirectional(&mut stream, &mut self.socket).await?;
        Ok(())
    }
}

pub struct UdpSession<'a, C> {
    ctrl: C,
    socket: UdpSocket,
    dest: Address<'a>,
    buf: UdpPacketBuf,
}

impl<'a, C> UdpSession<'a, C>
where
    C: TrafficControl + Unpin,
{
    pub async fn new(req: &'a RequestRef<'a>, ctrl: C) -> io::Result<UdpSession<'a, C>> {
        Ok(UdpSession {
            ctrl,
            socket: req.addr.into_enum().open_udp().await?,
            dest: req.addr,
            buf: UdpPacketBuf::init(req.payload),
        })
    }

    pub async fn run<IO>(mut self, stream: &mut IO) -> io::Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        enum SessionStatus {
            Recv,
            UdpSend,
            StreamSend(Vec<u8>),
            Shutdown,
        }

        struct SessionInner<'a, C, IO> {
            status: SessionStatus,
            buf: UdpPacketBuf,
            ctrl: C,
            socket: UdpSocket,
            dest: Address<'a>,
            stream: IO,
        }

        use SessionStatus::*;

        impl<'a, C, IO> Future for SessionInner<'a, C, IO>
        where
            C: TrafficControl + Unpin,
            IO: AsyncRead + AsyncWrite + Unpin,
        {
            type Output = io::Result<()>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut this = self.get_mut();
                ready!(this.ctrl.poll_pause(cx));

                loop {
                    match &this.status {
                        Recv => {
                            let mut buf = [0; 8192];
                            let mut buf = ReadBuf::new(&mut buf);
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
                                let bytes = UdpPacketRef::new(this.dest, buf.filled()).as_bytes();
                                this.status = StreamSend(bytes);
                                continue;
                            }
                            return Poll::Pending;
                        }
                        UdpSend => match this.buf.read() {
                            Some(p) => {
                                if p.payload().len() <= 8192 {
                                    let n = ready!(this.socket.poll_send(cx, p.payload()))?;
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

        self.buf.process_new_packet()?;
        let status = match self.buf.read() {
            Some(_) => UdpSend,
            None => Recv,
        };

        SessionInner {
            status,
            buf: self.buf,
            ctrl: self.ctrl,
            socket: self.socket,
            dest: self.dest,
            stream,
        }
        .await
    }
}
