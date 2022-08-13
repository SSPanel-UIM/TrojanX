// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

//! Trojan Protocol
//!
//! Trojan is designed to build a tunnel through firewalls to bypass blocking and censorship.
//!
//! Using TLS just like modern browsers and web servers to reduce potential risks of detection.
//!
//! # Timing
//!
//! The figure below shows how the trojan protocol and fallback service work.
//!
//! ``` text
//! client                server            remote   fallback
//!   |                     |                  |        |
//!   |-----tcp stream----->|                  |        |
//!   |                     |                  |        |
//!   |<---tls handshake--->|                  |        |
//!   |                     |                  |        |
//!   |---trojan request--->|                  |        |
//!   |                     |                  |        |
//!   |               parse & verify           |        |
//!   |                 |       |              |        |
//!   |                 no     yes             |        |
//!   |                 |       |---tcp/udp--->|        |
//!   |                 |       |---payload--->|        |
//!   |                 |       |              |        |
//!   |<----------------------->|<------------>|        |
//!   |                 |                               |
//!   |                 |-------'trojan request'------->|
//!   |<--------------->|<----------------------------->|
//! ```
//!
//! If a trojan server failed to parse trojan request or failed to verify the password presented,
//! it must send all data first received from TLS stream to preset fallback endpoints and open a
//! tunnel between client and alt. This is useful to run another service behind a trojan server
//! (usually at port 443) and prevent active detection.
//!
//! # Early Data
//!
//! TLS 1.3 early data should be accepted by server implementations. It's useful to speed up
//! connection establishment.
//!
//! The early data must be a trojan request. If a server received a tls handshake with early data,
//! it must try to process data or reject early data. If it's a valid trojan request with a valid
//! password, the server should establish a tcp/udp socket to the requested address and send data
//! after tls handshake is complete. If early data is not a trojan request or presents with an
//! invalid password, the server should just send it to alternative endpoint and exchange data
//! after tls stream is established.
//!
//! In the timing figure, it likes:
//!
//! ``` text
//!       |                 |
//! parse & verify          |
//!  |       |              |
//!  no     yes             |
//!  |       |---tcp/udp--->|
//!  |       |...waiting....|<----  wait until tls handshake complete
//!  |       |---payload--->|       if trojan request is from early data
//!  |       |              |
//! ```
//!
//! # ALPN
//!
//! ALPN is meaningless for a trojan server. And a client should use both `h2` and `http/1.1` like
//! most modern browsers do by default.
//!
//! # Protocol Details
//!
//! See [`RequestRef`] and [`UdpPacketRef`].

use std::fmt::{self, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::io;

mod addr;
mod udp_packet;

pub use addr::*;
pub use udp_packet::*;

pub(self) const CRLF: &[u8] = b"\r\n";

/// Error that the data is malformed
#[derive(Debug)]
pub struct ProtocolError;

/// Error that occour in parsing udp packet
#[derive(Debug)]
pub enum AssembleError {
    /// Just as [`ProtocolError`].
    Protocol,
    /// The length of data is not engouth.
    NotReady,
}

impl From<ProtocolError> for io::Error {
    fn from(_: ProtocolError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, "malformed packet received")
    }
}

impl From<ProtocolError> for AssembleError {
    fn from(_: ProtocolError) -> Self {
        AssembleError::Protocol
    }
}

/// SHA224 password digest
///
/// In Trojan Request, it's presented as hexadecimal with 56 bytes.
#[derive(Copy, Clone, Debug, Eq)]
pub struct Password {
    pub raw: [u8; 28],
}

impl Password {
    /// Parse from hexadecimal bytes.
    ///
    /// # Errors
    ///
    /// If `bytes` contains non-hexadecimal characters or the length of `bytes` is less than 56.
    #[inline]
    pub fn from_hex(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes = bytes.get(..56).ok_or(ProtocolError)?;
        unsafe { Self::from_hex_unchecked(bytes) }
    }

    /// Parse from hexadecimal bytes without boundary check.
    ///
    /// # Errors
    ///
    /// If `bytes` contains non-hexadecimal characters.
    ///
    /// # Safety
    ///
    /// The length of `bytes` must >= 56.
    #[inline]
    pub unsafe fn from_hex_unchecked(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut raw = [0; 28];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = hex_to_u8(bytes.get_unchecked(i * 2), bytes.get_unchecked(i * 2 + 1))?;
        }
        Ok(Password { raw })
    }

    /// Convert self to lower hexadecimal bytes.
    ///
    /// # Return Value
    ///
    /// Valid UFT-8 characters bytes which could be convert to `str` uncheckedly.
    #[inline]
    pub fn to_hex(&self) -> [u8; 56] {
        let mut raw = [0; 56];
        for (i, (h0, h1)) in self.raw.iter().map(u8_to_hex).enumerate() {
            raw[2 * i] = h0;
            raw[2 * i + 1] = h1;
        }
        raw
    }
}

impl Display for Password {
    /// Display as lower hexadecimal
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let hex = self.to_hex();

        // SAFETY: hex is valid UTF-8
        let str = unsafe { std::str::from_utf8_unchecked(&hex) };
        f.write_str(str)
    }
}

impl Hash for Password {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.raw);
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.raw.eq(&other.raw)
    }
}

/// Trojan (Socks5-like) Command
///
/// Similar to Socks5 expect `Bind` command which is not supported by Trojan
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum Command {
    /// `0x01`: Connect / TCP Stream
    Connect = 0x01,
    /// `0x03`: UDP Associate / UDP Packets
    UdpAssociate = 0x03,
}

impl Command {
    /// Parse from one byte.
    ///
    /// # Errors
    ///
    /// If `byte` is unknown Command.
    #[inline]
    pub fn from_byte(byte: u8) -> Result<Self, ProtocolError> {
        match byte {
            0x01 => Ok(Command::Connect),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(ProtocolError),
        }
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let str = match self {
            Command::Connect => "tcp",
            Command::UdpAssociate => "udp",
        };
        f.write_str(str)
    }
}

/// Trojan Request
///
/// # Protocol
///
/// | [`Password`] |   CRLF    | [`Command`] | [`Address`] |   CRLF    | Payload  |
/// | ------------ | --------- | ----------- | ----------- | --------- | -------- |
/// |      56      | `b"\r\n"` |      1      |  Variable   | `b"\r\n"` | Variable |
pub struct RequestRef<'a> {
    pub pwd: Password,
    pub cmd: Command,
    pub addr: AddressRef<'a>,
    pub payload: &'a [u8],
}

impl<'a> RequestRef<'a> {
    /// Parse Trojan Request.
    ///
    /// # Errors
    ///
    /// `ProtocolError` would be returned when:
    ///
    /// - Failed to parse each field
    /// - `b"\r\n"` is not present as expectaion
    /// - The length of `bytes` less than expectaion
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        let (pwd, cmd) = {
            let slice = bytes.get(..59).ok_or(ProtocolError)?;
            // SAFETY: The length of slice is 59 which > 56.
            let pwd = unsafe { Password::from_hex_unchecked(slice)? };
            if &slice[56..58] != CRLF {
                return Err(ProtocolError);
            }
            let cmd = Command::from_byte(slice[58])?;
            (pwd, cmd)
        };
        let addr = AddressRef::from_bytes(&bytes[59..])?;

        let payload = {
            let offset = 59 + addr.size() + 2;
            let slice = bytes.get(offset - 2..offset).ok_or(ProtocolError)?;
            if slice != CRLF {
                return Err(ProtocolError);
            }
            &bytes[offset..]
        };

        Ok(RequestRef {
            pwd,
            cmd,
            addr,
            payload,
        })
    }

    /// Convert self as bytes.
    #[inline]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(56 + 2 + 1 + self.addr.size() + 2 + self.payload.len());
        buf.extend(self.pwd.to_hex());
        buf.extend(CRLF);
        buf.push(self.cmd as u8);
        self.addr.extend_bytes(&mut buf);
        buf.extend(CRLF);
        buf.extend(self.payload);
        buf
    }
}

#[inline]
fn hex_to_u8(h0: &u8, h1: &u8) -> Result<u8, ProtocolError> {
    let n0 = match h0 {
        b'0'..=b'9' => h0 - b'0',
        b'a'..=b'f' => h0 - b'a' + 0x0a,
        _ => return Err(ProtocolError),
    };
    let n1 = match h1 {
        b'0'..=b'9' => h1 - b'0',
        b'a'..=b'f' => h1 - b'a' + 0x0a,
        _ => return Err(ProtocolError),
    };

    Ok(n0 << 4 | n1)
}

#[inline]
fn u8_to_hex(n: &u8) -> (u8, u8) {
    let h0 = n >> 4;
    let h1 = n | 0x0f;

    // Makes complier optimize unreachable code
    // SAFETY: h1 & h2 is known <= 0x0f
    let h0 = match h0 {
        0x00..=0x09 => h0 + b'0',
        0x0a..=0x0f => h0 + b'a' - 0x0a,
        _ => unsafe { std::hint::unreachable_unchecked() },
    };
    let h1 = match h1 {
        0x00..=0x09 => h1 + b'0',
        0x0a..=0x0f => h1 + b'a' - 0x0a,
        _ => unsafe { std::hint::unreachable_unchecked() },
    };

    (h0, h1)
}
