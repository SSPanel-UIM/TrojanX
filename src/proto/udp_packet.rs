// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::mem;
use std::ptr;

use super::{AddressRef, AssembleError, ProtocolError, CRLF};

/// UDP Packet
///
/// To read UDP Packet from a stream, see [`UdpPacketBuf`].
///
/// # Protocol
///
/// | [`AddressRef`] | Length |  CRLF   | Payload  |
/// | -------------- | ------ | ------- | -------- |
/// |    Variable    |   2    | b"\r\n" | Variable |
pub struct UdpPacketRef<'a> {
    pub addr: AddressRef<'a>,
    pub payload: &'a [u8],
}

impl UdpPacketRef<'_> {
    /// Build a UdpPacket.
    #[inline]
    pub fn new<'a>(addr: AddressRef<'a>, payload: &'a [u8]) -> UdpPacketRef<'a> {
        UdpPacketRef { addr, payload }
    }

    /// Parse UDP Packet from bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<UdpPacketRef<'_>, AssembleError> {
        let addr = AddressRef::from_assemble_bytes(bytes)?;

        let addr_len = addr.size();
        let len = {
            let slice = bytes
                .get(addr_len..addr_len + 2)
                .ok_or(AssembleError::NotReady)?;
            u16::from_be_bytes([slice[0], slice[1]]) as usize
        };

        let payload = {
            let end = addr_len + 2 + 2 + len;
            let slice = bytes
                .get(addr_len + 2..end)
                .ok_or(AssembleError::NotReady)?;
            if &slice[0..2] != CRLF {
                return Err(AssembleError::Protocol);
            }
            &slice[2..]
        };

        Ok(UdpPacketRef { addr, payload })
    }

    /// Build UdpPacket to bytes.
    #[inline]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        self.addr.extend_bytes(&mut buf);

        let len = self.payload.len() as u16;
        buf.extend(len.to_be_bytes());
        buf.extend_from_slice(CRLF);
        buf.extend(self.payload);
        buf
    }

    /// Get the byte length of current UDP Packet.
    pub fn size(&self) -> usize {
        self.addr.size() + 2 + 2 + self.payload.len()
    }
}

/// A buffer to receive UdpPacket continuously from a stream
///
/// The stream is lined up with UdpPackets with different lengths. Due to UDP and stream, it's
/// impossible to ensure there is only one UdpPacket presenting in a single stream read result
/// (fragmentation). So it's necessary to parse them in a assemble buffer.
#[derive(Default)]
pub struct UdpPacketBuf {
    buf: Vec<u8>,

    /// self reference to buf
    packet: Option<UdpPacketRef<'static>>,
}

impl UdpPacketBuf {
    #[inline]
    pub fn new() -> UdpPacketBuf {
        UdpPacketBuf {
            buf: Vec::new(),
            packet: None,
        }
    }

    /// Try to read current avalaible packet
    #[inline]
    pub fn read(&self) -> Option<&UdpPacketRef<'_>> {
        self.packet.as_ref()
    }

    /// Write some bytes into buffer.
    #[inline]
    pub fn write(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Try to parse next new packet. Any unread packet would be lost after calling this function.
    #[inline]
    pub fn process_new_packet(&mut self) -> Result<(), ProtocolError> {
        if let Some(p) = self.packet.take() {
            let pos = p.size();
            let remain = self.buf.len() - pos;
            unsafe {
                ptr::copy(self.buf.as_ptr().add(pos), self.buf.as_mut_ptr(), remain);
                self.buf.set_len(remain);
            }
        }
        match UdpPacketRef::from_bytes(&self.buf) {
            Ok(p) => {
                // transmute to 'static to store in current struct
                // SAFETY: Managed by Self, could only be immutable borrowed.
                self.packet = Some(unsafe { mem::transmute(p) });
                Ok(())
            }
            Err(AssembleError::NotReady) => Ok(()),
            Err(AssembleError::Protocol) => Err(ProtocolError),
        }
    }
}
