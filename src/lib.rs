//! Highly modular & configurable hash & crypto library written in Rust
//!
//! # About
//!
//! Octavo is Rust implementation of cryptographic primitives and [Transport Layer Security][tls].
//! Our goal is to provide safe, fast, full-featured and configurable cryptographic library
//! for modern world.
//!
//! Except of Rust API we want expose also C API for usage with other languages and tools. Probably
//! there will also land thin [OpenSSL][openssl] compatibility cascade for use with existing code.
//!
//! [tls]: https://en.wikipedia.org/wiki/Transport_Layer_Security "Transport Layer Security"
//!
//! ## Legalities
//!
//! Please remember that export/import and/or use of strong cryptography software, providing
//! cryptography hooks, or even just communicating technical details about cryptography software is
//! illegal in some parts of the world. So when you import this package to your country,
//! re-distribute it from there or even just email technical suggestions or even source patches to
//! the authors or other people you are strongly advised to pay close attention to any laws or
//! regulations which apply to you. The authors of Octavo are not liable for any violations you
//! make here. So be careful, it is your responsibility.[^authors]
//!
//! [^authors]: Text of this paragraph is copied from [OpenSSL website][openssl].
//! [openssl]: http://www.openssl.org/ "OpenSSL - Cryptography and SSL/TLS Toolkit"

#![doc(html_logo_url = "https://raw.githubusercontent.com/libOctavo/octavo/master/docs/logo.png",
       html_root_url = "http://libOctavo.github.io/")]

pub extern crate octavo_crypto;
pub extern crate octavo_digest;
pub extern crate octavo_kdf;
pub extern crate octavo_mac;

pub use octavo_crypto as crypto;
pub use octavo_digest as digest;
pub use octavo_kdf as kdf;
pub use octavo_mac as mac;
