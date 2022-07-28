// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::net::{TcpStream, UdpSocket};

use super::{AssembleError, ProtocolError};

/// Socks5-like Address Field
///
/// # Protocol
///
/// | ATYP | DST.ADDR | DST.PORT |
/// | ---- | -------- | -------- |
/// |  1   | Variable |    2     |
///
/// ## ATYP
///
/// ### IP V4 address: `0x00`
///
/// the address is a version-4 IP address, with a length of 4 octets.
///
/// ### DOMAINNAME: `0x03`
///
/// the address field contains a fully-qualified domain name. The first
/// octet of the address field contains the number of octets of name that
/// follow, there is no terminating NUL octet.
///
/// ### IP V6 address: `0x04`
///
/// the address is a version-6 IP address, with a length of 16 octets.
#[derive(Clone)]
pub enum Address {
    IP(SocketAddr),
    Name((String, u16)),
}

impl Address {
    pub fn as_ref(&self) -> AddressRef<'_> {
        match self {
            Address::IP(addr) => AddressRef::IP(*addr),
            Address::Name((name, port)) => AddressRef::Name((name, *port)),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::IP(addr)
    }
}

#[derive(Clone, Copy)]
pub enum AddressRef<'a> {
    IP(SocketAddr),
    Name((&'a str, u16)),
}

impl AddressRef<'_> {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<AddressRef<'_>, ProtocolError> {
        Self::from_assemble_bytes(bytes).map_err(|_| ProtocolError)
    }

    #[inline]
    pub fn size(&self) -> usize {
        match self {
            AddressRef::IP(SocketAddr::V4(_)) => 7,
            AddressRef::IP(SocketAddr::V6(_)) => 19,
            AddressRef::Name((n, _)) => n.len() + 4,
        }
    }

    #[inline]
    pub fn to_owned(self) -> Address {
        match self {
            AddressRef::IP(addr) => Address::IP(addr),
            AddressRef::Name((name, port)) => Address::Name((name.to_owned(), port)),
        }
    }

    #[inline]
    pub fn from_assemble_bytes(bytes: &[u8]) -> Result<AddressRef<'_>, AssembleError> {
        let kind = bytes.first().ok_or(AssembleError::NotReady)?;

        match kind {
            0x01 => {
                // IPv4

                // len: 6
                let slice = bytes.get(1..7).ok_or(AssembleError::NotReady)?;

                let addr = <[u8; 4]>::try_from(&slice[..4]).unwrap();
                let port = u16::from_be_bytes([slice[4], slice[5]]);

                Ok(AddressRef::IP(SocketAddrV4::new(addr.into(), port).into()))
            }
            0x03 => {
                // Domain Name

                let name_len = bytes.get(1).ok_or(AssembleError::NotReady)?;
                let name_len = *name_len as usize;

                // len: name_len + 2
                let slice = bytes
                    .get(2..name_len + 2 + 2)
                    .ok_or(AssembleError::NotReady)?;

                let name =
                    std::str::from_utf8(&slice[..name_len]).map_err(|_| AssembleError::Protocol)?;
                let port = u16::from_be_bytes([slice[name_len], slice[name_len + 1]]);

                Ok(AddressRef::Name((name, port)))
            }
            0x04 => {
                // IPv6

                // len: 18
                let bytes = bytes.get(1..19).ok_or(AssembleError::NotReady)?;

                let addr = <[u8; 16]>::try_from(&bytes[..16]).unwrap();
                let port = u16::from_be_bytes([bytes[16], bytes[17]]);

                Ok(AddressRef::IP(
                    SocketAddrV6::new(addr.into(), port, 0, 0).into(),
                ))
            }
            _ => Err(AssembleError::Protocol),
        }
    }

    #[inline]
    pub fn extend_bytes(&self, buf: &mut Vec<u8>) {
        match self {
            AddressRef::IP(SocketAddr::V4(a)) => {
                buf.push(0x01);
                buf.extend(a.ip().octets());
                buf.extend(a.port().to_be_bytes());
            }
            AddressRef::IP(SocketAddr::V6(a)) => {
                buf.push(0x04);
                buf.extend(a.ip().octets());
                buf.extend(a.port().to_be_bytes());
            }
            AddressRef::Name((n, p)) => {
                buf.push(0x03);
                buf.push(n.len() as u8);
                buf.extend(n.as_bytes());
                buf.extend(p.to_be_bytes());
            }
        }
    }

    /// Open a TCP Streamt to the specified address.
    #[inline]
    pub async fn open_tcp(&self) -> io::Result<TcpStream> {
        match self {
            AddressRef::IP(a) => TcpStream::connect(a).await,
            AddressRef::Name(a) => TcpStream::connect(a).await,
        }
    }

    /// Open an connected UDP Socket to the specified address.
    #[inline]
    pub async fn open_udp(&self) -> io::Result<UdpSocket> {
        use std::net::{self, IpAddr};

        #[cfg(any(target_os = "linux"))]
        let bind = IpAddr::V6(net::Ipv6Addr::UNSPECIFIED);
        #[cfg(any(not(target_os = "linux")))]
        let bind = match self {
            AddressRef::IP(SocketAddr::V6(_)) => IpAddr::V6(net::Ipv6Addr::UNSPECIFIED),
            _ => IpAddr::V4(net::Ipv4Addr::UNSPECIFIED),
        };

        let socket = UdpSocket::bind((bind, 0)).await?;
        match self {
            AddressRef::IP(a) => socket.connect(a).await?,
            AddressRef::Name(a) => socket.connect(a).await?,
        }
        Ok(socket)
    }
}

impl Display for AddressRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AddressRef::IP(a) => a.fmt(f),
            AddressRef::Name((n, p)) => write!(f, "{}:{}", n, p),
        }
    }
}
