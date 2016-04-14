//! Cryptographic hash functions primitives
//!
//! Via [Wikipedia](https://en.wikipedia.org/wiki/Cryptographic_hash_function):
//!
//! > The ideal cryptographic hash function has four main properties:
//! >
//! > - it is easy to compute the hash value for any given message
//! > - it is infeasible to generate a message from its hash
//! > - it is infeasible to modify a message without changing the hash
//! > - it is infeasible to find two different messages with the same hash.
//!
//! # Example
//!
//! Calculate SHA-512 sum:
//!
//! ```rust
//! # extern crate octavo_digest;
//! use octavo_digest::prelude::*;
//!
//! # fn main() {
//! # let data = "Hello World!";
//! let mut result = vec![0; sha2::Sha512::output_bytes()];
//! let mut sha = sha2::Sha512::default();
//!
//! sha.update(data);
//! sha.result(&mut result);
//!
//! for byte in result {
//!     print!("{:2x}", byte);
//! }
//! println!(" {}", data);
//! # }
//! ```

#![doc(html_logo_url = "https://raw.githubusercontent.com/libOctavo/octavo/master/docs/logo.png",
       html_root_url = "http://libOctavo.github.io/")]

#![no_std]

#![forbid(overflowing_literals, missing_docs)]

extern crate generic_array;
extern crate static_buffer;
extern crate typenum;
extern crate byteorder;

use generic_array::ArrayLength;
use typenum::uint::Unsigned;

/// Hash function digest definition
pub trait Digest: Clone {
    /// Output size in bits
    type OutputBits: Unsigned + ArrayLength<u8>;
    /// Output size in bytes
    type OutputBytes: Unsigned + ArrayLength<u8>;

    /// Block size in bytes
    type BlockSize: Unsigned + ArrayLength<u8>;

    /// Update digest with data.
    fn update<T>(&mut self, input: T) where T: AsRef<[u8]>;

    /// Output size in bits
    fn output_bits() -> usize {
        Self::OutputBits::to_usize()
    }
    /// Output size in bytes
    fn output_bytes() -> usize {
        Self::OutputBytes::to_usize()
    }
    /// Block size in bytes
    fn block_size() -> usize {
        Self::BlockSize::to_usize()
    }

    /// Write resulting hash into `output`.
    ///
    /// `output` should be big enough to contain whole output.
    ///
    /// ## Panics
    ///
    /// If output length is less than `Digest::output_bytes`.
    fn result<T>(self, output: T) where T: AsMut<[u8]>;
}

/// Digest prelude
pub mod prelude {
    pub use Digest;

#[cfg(feature = "blake2")]
    pub use blake2;
#[cfg(feature = "md5")]
    pub use md5::Md5;
#[cfg(feature = "ripemd")]
    pub use ripemd::Ripemd160;
#[cfg(feature = "sha1")]
    pub use sha1::Sha1;
#[cfg(feature = "sha2")]
    pub use sha2;
#[cfg(feature = "sha3")]
    pub use sha3;
#[cfg(feature = "tiger")]
    pub use tiger;
#[cfg(feature = "whirlpool")]
    pub use whirlpool;
}

#[cfg(feature = "blake2")]
pub mod blake2;
#[cfg(feature = "md5")]
pub mod md5;
#[cfg(feature = "ripemd")]
pub mod ripemd;
#[cfg(feature = "sha1")]
pub mod sha1;
#[cfg(feature = "sha2")]
pub mod sha2;
#[cfg(feature = "sha3")]
pub mod sha3;
#[cfg(feature = "tiger")]
pub mod tiger;
#[cfg(feature = "whirlpool")]
pub mod whirlpool;
