// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::{ptr, mem};

use bytes::Bytes;

use super::{Address, AssembleError, ProtocolError, CRLF};

/// UDP Packet
///
/// To read UDP Packet from a stream, see [`UdpPacketBuf`].
///
/// # Protocol
///
/// |  [`Address`]   | Length |  CRLF   | Payload  |
/// | -------------- | ------ | ------- | -------- |
/// |    Variable    |   2    | b"\r\n" | Variable |
pub struct UdpPacket {
    pub addr: Address,
    pub payload: Bytes,
}

impl UdpPacket {
    /// Build a UdpPacket.
    #[inline]
    pub fn new(addr: Address, payload: Bytes) -> UdpPacket {
        UdpPacket { addr, payload }
    }

    /// Parse UDP Packet from bytes.
    #[inline]
    pub fn from_bytes(bytes: Bytes) -> Result<UdpPacket, AssembleError> {
        let addr = Address::from_assemble_bytes(bytes.clone())?;

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
            bytes.slice_ref(&slice[2..])
        };

        Ok(UdpPacket { addr, payload })
    }

    /// Build UdpPacket to bytes.
    #[inline]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        self.addr.extend_bytes(&mut buf);

        let len = self.payload.len() as u16;
        buf.extend(len.to_be_bytes());
        buf.extend_from_slice(CRLF);
        buf.extend(&self.payload);
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
    packet: Option<UdpPacket>,
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
    pub fn read(&self) -> Option<&UdpPacket> {
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

        // unsafe: check
        match UdpPacket::from_bytes(Bytes::from_static(unsafe { mem::transmute(&self.buf[..]) })) {
            Ok(p) => {
                self.packet = Some(p);
                Ok(())
            }
            Err(AssembleError::NotReady) => Ok(()),
            Err(AssembleError::Protocol) => Err(ProtocolError),
        }
    }
}
