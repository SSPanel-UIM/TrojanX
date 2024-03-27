use std::hash::{BuildHasher, Hasher};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

#[cfg(feature = "sspanel")]
pub mod limiter;

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

pub struct RawHasherBuilder;

impl BuildHasher for RawHasherBuilder {
    type Hasher = RawHasher;

    fn build_hasher(&self) -> Self::Hasher {
        RawHasher { raw: 0 }
    }
}

/// A hasher wrapper specified to "hash" [`crate::proto::Password`].
///
/// Do not use it for others.
pub struct RawHasher {
    raw: u64,
}

impl Hasher for RawHasher {
    fn write(&mut self, bytes: &[u8]) {
        // SAFETY: password has 28 bytes and we take its first 8 bytes(64 bit)
        unsafe {
            self.raw = u64::from_be_bytes(bytes.get_unchecked(..8).try_into().unwrap());
        }
    }

    fn finish(&self) -> u64 {
        self.raw
    }
}
