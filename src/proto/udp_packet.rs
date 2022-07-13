// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::marker::PhantomData;
use std::ptr::{self, NonNull};

use super::{Address, AddressInner, AssembleError, ProtocolError, CRLF};

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
    inner: UdpPacketInner,
    _phantom: PhantomData<&'a [u8]>,
}

impl UdpPacketRef<'_> {
    /// Build a UdpPacket.
    #[inline]
    pub fn new<'a>(addr: Address<'_>, payload: &'a [u8]) -> UdpPacketRef<'a> {
        UdpPacketRef {
            inner: UdpPacketInner {
                addr: addr.inner,
                payload: NonNull::new(payload as *const _ as *mut _).unwrap(),
            },
            _phantom: PhantomData,
        }
    }

    /// Parse UDP Packet from bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<UdpPacketRef<'_>, AssembleError> {
        let inner = UdpPacketInner::from_bytes(bytes)?;
        Ok(UdpPacketRef {
            inner,
            _phantom: PhantomData,
        })
    }

    /// Build UdpPacket to bytes.
    #[inline]
    pub fn as_bytes(&self) -> Vec<u8> {
        unsafe { self.inner.as_bytes() }
    }

    /// Get the byte length of current UDP Packet.
    pub fn size(&self) -> usize {
        unsafe { self.inner.size() }
    }
}

/// A buffer to receive UdpPacket continuously from a stream
///
/// The stream is lined up with UdpPackets with different lengths. Due to UDP and stream, it's
/// impossible to ensure there is only one UdpPacket presenting in a single stream read result
/// (fragmentation). So it's necessary to parse them in a assemble buffer.
pub struct UdpPacketBuf {
    buf: Vec<u8>,

    packet: Option<UdpPacketDrain>,
}

impl UdpPacketBuf {
    /// Init [`UdpPacketBuf`] with Trojan Request payload.
    #[inline]
    pub fn init(bytes: &[u8]) -> Self {
        let buf = Vec::from(bytes);
        UdpPacketBuf { buf, packet: None }
    }

    /// Try to read current avalaible packet
    #[inline]
    pub fn read(&self) -> &Option<UdpPacketDrain> {
        &self.packet
    }

    /// Write some bytes into buffer.
    #[inline]
    pub fn write(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
    }

    /// Try to parse next new packet. Any unread packet would be lost after calling this function.
    #[inline]
    pub fn process_new_packet(&mut self) -> Result<(), ProtocolError> {
        if let Some(p) = self.packet.take() {
            let pos = unsafe { p.0.size() };
            let remain = self.buf.len() - pos;
            unsafe {
                ptr::copy(self.buf.as_ptr().add(pos), self.buf.as_mut_ptr(), remain);
                self.buf.set_len(remain);
            }
        }
        match UdpPacketInner::from_bytes(&self.buf) {
            Ok(p) => {
                self.packet = Some(UdpPacketDrain(p));
                Ok(())
            }
            Err(AssembleError::NotReady) => Ok(()),
            Err(AssembleError::Protocol) => Err(ProtocolError),
        }
    }
}

/// UdpPacket referenced from [`UdpPacketBuf`]
pub struct UdpPacketDrain(UdpPacketInner);

impl UdpPacketDrain {
    /// Get UdpPacket bytes payload
    pub fn payload(&self) -> &[u8] {
        // SAFETY: Self is only avaialbe via reference of UdpPacketBuf
        unsafe { self.0.payload.as_ref() }
    }

    /// Get UdpPacket Address
    pub fn address(&self) -> Address<'_> {
        // SAFETY: Self is only avaialbe via reference of UdpPacketBuf
        unsafe { self.0.addr.as_ref() }
    }
}

unsafe impl Send for UdpPacketDrain {}

unsafe impl Sync for UdpPacketDrain {}

struct UdpPacketInner {
    addr: AddressInner,
    payload: NonNull<[u8]>,
}

impl UdpPacketInner {
    pub fn from_bytes(bytes: &[u8]) -> Result<UdpPacketInner, AssembleError> {
        let addr = AddressInner::from_assemble_bytes(bytes)?;

        let addr_len = unsafe { addr.size() };
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
            NonNull::new(&slice[2..] as *const _ as *mut _).unwrap()
        };

        Ok(UdpPacketInner { addr, payload })
    }

    pub unsafe fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = self.addr.as_bytes();
        bytes.reserve(self.size());

        let payload = self.payload.as_ref();
        let len = payload.len() as u16;
        bytes.extend(len.to_be_bytes());
        bytes.extend(CRLF);
        bytes.extend(payload);
        bytes
    }

    pub unsafe fn size(&self) -> usize {
        self.addr.size() + 2 + 2 + self.payload.as_ref().len()
    }
}
