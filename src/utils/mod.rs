// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2022 irohaede <irohaede@proton.me>

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

#[cfg(feature = "sspanel")]
pub mod limiter;
mod unstable;

pub(crate) use unstable::*;

/// PROXY Protocol V2
///
/// [Document](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
///
/// # Note
///
/// This implementation is specified for STREAM PROXY for known address.
pub enum ProxyProtocolV2 {
    V4 {
        src: SocketAddrV4,
        dest: SocketAddrV4,
    },
    V6 {
        src: SocketAddrV6,
        dest: SocketAddrV6,
    },
}

impl ProxyProtocolV2 {
    /// # Panics
    ///
    /// If `src` and `dest` is not same variant.
    #[inline]
    pub fn new(src: SocketAddr, dest: SocketAddr) -> Self {
        match src {
            SocketAddr::V4(src) => match dest {
                SocketAddr::V4(dest) => ProxyProtocolV2::V4 { src, dest },
                _ => panic!("src and dest must be the same variant"),
            },
            SocketAddr::V6(src) => match dest {
                SocketAddr::V6(dest) => ProxyProtocolV2::V6 { src, dest },
                _ => panic!("src and dest must be the same variant"),
            },
        }
    }

    // protocol signature && version: 2, command: PROXY(1)
    const SIG: [u8; 13] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21,
    ];

    #[inline]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::from(Self::SIG);
        match self {
            ProxyProtocolV2::V4 { src, dest } => {
                bytes.reserve(3 + 4 + 4 + 2 + 2);
                bytes.extend([0x11, 0, 12]);
                bytes.extend(src.ip().octets());
                bytes.extend(dest.ip().octets());
                bytes.extend(src.port().to_be_bytes());
                bytes.extend(dest.port().to_be_bytes());
            }
            ProxyProtocolV2::V6 { src, dest } => {
                bytes.reserve(3 + 16 + 16 + 2 + 2);
                bytes.extend([0x21, 0, 36]);
                bytes.extend(src.ip().octets());
                bytes.extend(dest.ip().octets());
                bytes.extend(src.port().to_be_bytes());
                bytes.extend(dest.port().to_be_bytes());
            }
        }
        bytes
    }
}
