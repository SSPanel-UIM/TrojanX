# TrojanX

A Trojan-based proxy implementation.

[![Check](https://github.com/sspanel-uim/TrojanX/actions/workflows/check.yml/badge.svg)](https://github.com/sspanel-uim/TrojanX/actions/workflows/check.yml)
[![Build](https://github.com/sspanel-uim/TrojanX/actions/workflows/build-release.yml/badge.svg)](https://github.com/sspanel-uim/TrojanX/actions/workflows/build-release.yml)

## Attention

### Early Version

This is an early version. Security, features, and potential bugs may be insufficiently verified.

### Unsafe Codes

To reduce heap allocation and copy, TrojanX uses unsafe codes to operate on raw pointers.

## Features

- TLS 1.3 early data
- TLS fragment size specify
- Multi-server name resolve
- PROXY protocol fallback
- ALPN fallback selection

## Usage

See wiki.

## Build

`cargo build --release`, no build dependencies needed.

## Roadmap

- [x] 0.0.1 First version (server implementation for SSPanel)
- [ ] 0.1.0 General socks5 client and server implementation
- [ ] 0.2.0 Stablization, API fixing and document supplement

## License

[Mozilla Public License Version 2.0](https://mozilla.org/MPL/2.0/)
