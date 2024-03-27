use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::Bytes;

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
pub struct Address {
    inner: AddressInner,
}

#[derive(Clone)]
enum AddressInner {
    IP(SocketAddr),
    Name((Bytes, u16)),
}

impl Address {
    /// Get byte size of self.
    #[inline]
    pub fn size(&self) -> usize {
        match &self.inner {
            AddressInner::IP(SocketAddr::V4(_)) => 7,
            AddressInner::IP(SocketAddr::V6(_)) => 19,
            AddressInner::Name((n, _)) => n.len() + 4,
        }
    }

    pub fn as_ref(&self) -> AddressRef<'_> {
        match &self.inner {
            AddressInner::IP(addr) => AddressRef::IP(*addr),
            AddressInner::Name((n, p)) => {
                let n = unsafe { std::str::from_utf8_unchecked(n) };
                AddressRef::Name((n, *p))
            }
        }
    }

    pub fn from_bytes(bytes: Bytes) -> Result<Address, ProtocolError> {
        Self::from_assemble_bytes(bytes).map_err(|_| ProtocolError)
    }

    pub fn from_assemble_bytes(bytes: Bytes) -> Result<Address, AssembleError> {
        let kind = bytes.first().ok_or(AssembleError::NotReady)?;

        let inner = match kind {
            0x01 => {
                // IPv4

                // len: 6
                let slice = bytes.get(1..7).ok_or(AssembleError::NotReady)?;

                let addr = <[u8; 4]>::try_from(&slice[..4]).unwrap();
                let port = u16::from_be_bytes([slice[4], slice[5]]);

                AddressInner::IP(SocketAddrV4::new(addr.into(), port).into())
            }
            0x03 => {
                // Domain Name

                let name_len = bytes.get(1).ok_or(AssembleError::NotReady)?;
                let name_len = *name_len as usize;

                // len: name_len + 2
                let slice = bytes
                    .get(2..name_len + 2 + 2)
                    .ok_or(AssembleError::NotReady)?;

                std::str::from_utf8(&slice[..name_len]).map_err(|_| AssembleError::Protocol)?;
                let port = u16::from_be_bytes([slice[name_len], slice[name_len + 1]]);

                AddressInner::Name((bytes.slice_ref(&slice[..name_len]), port))
            }
            0x04 => {
                // IPv6

                // len: 18
                let bytes = bytes.get(1..19).ok_or(AssembleError::NotReady)?;

                let addr = <[u8; 16]>::try_from(&bytes[..16]).unwrap();
                let port = u16::from_be_bytes([bytes[16], bytes[17]]);

                AddressInner::IP(SocketAddrV6::new(addr.into(), port, 0, 0).into())
            }
            _ => return Err(AssembleError::Protocol),
        };
        Ok(Address { inner })
    }

    #[inline]
    pub fn extend_bytes(&self, buf: &mut Vec<u8>) {
        match &self.inner {
            AddressInner::IP(SocketAddr::V4(a)) => {
                buf.push(0x01);
                buf.extend(a.ip().octets());
                buf.extend(a.port().to_be_bytes());
            }
            AddressInner::IP(SocketAddr::V6(a)) => {
                buf.push(0x04);
                buf.extend(a.ip().octets());
                buf.extend(a.port().to_be_bytes());
            }
            AddressInner::Name((n, p)) => {
                buf.push(0x03);
                buf.push(n.len() as u8);
                buf.extend(n.as_ref());
                buf.extend(p.to_be_bytes());
            }
        }
    }

    /// Open a TCP Streamt to the specified address.
    #[inline]
    pub async fn open_tcp(&self) -> io::Result<TcpStream> {
        match &self.inner {
            AddressInner::IP(a) => TcpStream::connect(a).await,
            AddressInner::Name((n, p)) => {
                // SAFETY: bytes is validated utf8 when building
                let n = unsafe { std::str::from_utf8_unchecked(n) };
                TcpStream::connect((n, *p)).await
            }
        }
    }

    /// Send an UDP packet to the specified address.
    #[inline]
    pub async fn send_udp(&self, socket: &UdpSocket, buf: &[u8]) -> io::Result<usize> {
        match &self.inner {
            AddressInner::IP(a) => socket.send_to(buf, a).await,
            AddressInner::Name((n, p)) => {
                let n = unsafe { std::str::from_utf8_unchecked(n) };
                socket.send_to(buf, (n, *p)).await
            }
        }
    }
}

pub enum AddressRef<'a> {
    IP(SocketAddr),
    Name((&'a str, u16)),
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address {
            inner: AddressInner::IP(addr),
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.inner {
            AddressInner::IP(a) => a.fmt(f),
            AddressInner::Name((n, p)) => {
                // SAFETY: bytes is validated utf8 when building
                let n = unsafe { std::str::from_utf8_unchecked(n) };
                write!(f, "{n}:{p}")
            }
        }
    }
}
