//! Fancy pure Rust crypto and hash library that main reason to exist is my own self-teaching
//! about cryptography. Other reason to create this ("We have rust-crypto, why the hell new
//! library?") is that `rust-crypto` was (at the time of creation) big pile of… mess. To be honest
//! I doesn't hate `rust-crypto` but I wanted something that will be organized in fancy way, not
//! new OpenSSL (but wwritten in Rust, so probably less buggy).
//!
//! Other reason is that I want Octavo to became highly configurable via Cargo features. Each
//! cipher, hash family, MAC, etc. should be behind feature.
//!
//! Oh… one more thing. I want to create C wrapper for Octavo (maybe even OpenSSL compatible), so
//! you could use this beautiful peace of crap.
//!
//! Happy coding!
//!
//! ## Examples
//!
//!

extern crate byteorder;
#[cfg(feaure = "num")] extern crate num;

pub mod crypto;
pub mod digest;
pub mod mac;

mod utils;
