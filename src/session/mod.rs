// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::future::poll_fn;
use std::net::{IpAddr, Ipv6Addr};
use std::{io, mem, vec};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::proto::{Address, Command, UdpPacket, UdpPacketBuf};

mod context;
pub use context::*;

pub enum ServerRelaySession<C> {
    Udp(UdpSession<C>),
    Tcp(TcpSession<C>),
}

impl<C> ServerRelaySession<C>
where
    C: ServerSession + Unpin + Send,
{
    /// Init a session without performing any IO
    pub async fn new(ctx: C) -> io::Result<ServerRelaySession<C>> {
        match ctx.cmd() {
            Command::Connect => {
                let session = TcpSession::new(ctx).await?;
                Ok(ServerRelaySession::Tcp(session))
            }
            Command::UdpAssociate => {
                let session = UdpSession::new(ctx).await?;
                Ok(ServerRelaySession::Udp(session))
            }
        }
    }

    pub async fn run<S>(self, stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        match self {
            Self::Tcp(s) => s.run(stream).await,
            Self::Udp(s) => s.run(stream).await,
        }
    }
}

pub struct TcpSession<C> {
    ctx: C,
    socket: TcpStream,
}

impl<C> TcpSession<C>
where
    C: ServerSession + Unpin,
{
    pub async fn new(ctx: C) -> io::Result<TcpSession<C>> {
        let socket = ctx.address().open_tcp().await?;
        Ok(TcpSession { ctx, socket })
    }

    pub async fn run<S>(mut self, stream: S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.ctx.payload().is_empty() {
            let n = self.socket.write(self.ctx.payload()).await?;
            self.ctx.consume_tx(n);
        }
        let mut stream = StreamWrapper::new(stream, self.ctx);
        tokio::io::copy_bidirectional(&mut stream, &mut self.socket).await?;
        Ok(())
    }
}

const PAYLOAD_LEN: usize = 8192;

pub struct UdpSession<C> {
    ctx: C,
    socket: UdpSocket,
    buf: UdpPacketBuf,
}

impl<C> UdpSession<C>
where
    C: ServerSession + Unpin + Send,
{
    pub async fn new(ctx: C) -> io::Result<UdpSession<C>> {
        let mut buf = UdpPacketBuf::new();
        buf.write(ctx.payload());
        buf.process_new_packet()?;

        #[cfg(any(target_os = "linux"))]
        let bind = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        #[cfg(any(not(target_os = "linux")))]
        let bind = {
            use crate::proto::AddressRef;
            use std::net::{Ipv4Addr, SocketAddr};

            match ctx.address().as_ref() {
                AddressRef::IP(SocketAddr::V6(_)) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            }
        };
        let socket = UdpSocket::bind((bind, 0)).await?;

        while let Some(p) = buf.read() {
            p.addr.send_udp(&socket, &p.payload).await?;
            buf.process_new_packet()?;
        }

        Ok(UdpSession { ctx, socket, buf })
    }

    pub async fn run<IO>(mut self, mut stream: IO) -> io::Result<()>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let (r2c_tx, mut r2c_rx) = mpsc::channel::<Vec<u8>>(16);
        let (c2r_tx, mut c2r_rx) = mpsc::channel::<(Address, Vec<u8>)>(16);

        tokio::spawn(async move {
            let mut buf = vec![0; PAYLOAD_LEN];
            loop {
                tokio::select! {
                    x = self.socket.recv_from(&mut buf) => {
                        match x {
                            Ok((n, addr)) => {
                                let bytes = UdpPacket::new(
                                    addr.into(),
                                    // SAFETY: wrap with Bytes without copy, no Bytes::clone() occur
                                    Bytes::from_static(unsafe { mem::transmute(&buf[..n]) }),
                                )
                                .as_bytes();
                                if let Err(TrySendError::Closed(_)) = r2c_tx.try_send(bytes) {
                                    break;
                                }
                            },
                            Err(e) => {
                                log::error!("udp socket recv error: {}", e);
                                break;
                            }
                        }
                    }
                    x = c2r_rx.recv() => {
                        if let Some((addr, payload)) = x {
                            let _ = addr.send_udp(&self.socket, &payload).await;
                        } else {
                            // stream side is closed
                            break;
                        }
                    }
                };
            }
        });

        let mut buf = vec![0; 2048];
        loop {
            tokio::select! {
                x = stream.read(&mut buf) => {
                    let n = x?;
                    if n == 0 {
                        break;
                    }
                    self.buf.write(&buf[..n]);
                    self.buf.process_new_packet()?;
                    while let Some(p) = self.buf.read() {
                        if p.payload.len() < PAYLOAD_LEN {
                            let addr = p.addr.clone();
                            let payload = Vec::from(&p.payload[..]);
                            self.ctx.consume_tx(payload.len());
                            let _ = c2r_tx.try_send((addr, payload));
                        }
                        self.buf.process_new_packet()?;
                    }
                }
                x = r2c_rx.recv() => {
                    if let Some(bytes) = x {
                        stream.write_all(&bytes).await?;
                        self.ctx.consume_rx(bytes.len());
                    } else {
                        // udp socket side is closed
                        break;
                    }
                }
            }
            poll_fn(|cx| self.ctx.poll_pause(cx)).await;
        }

        Ok(())
    }
}
