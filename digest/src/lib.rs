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
//! use octavo_digest::Digest;
//! use octavo_digest::sha2::Sha512;
//!
//! # fn main() {
//! # let data = "Hello World!";
//! let mut result = vec![0; Sha512::output_bytes()];
//! let mut sha = Sha512::default();
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

#![no_std]

#![forbid(overflowing_literals)]

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

    pub use blake2;
    pub use md5::Md5;
    pub use ripemd::Ripemd160;
    pub use sha1::Sha1;
    pub use sha2;
    pub use sha3;
    pub use tiger;
}

pub mod blake2;
pub mod md5;
pub mod ripemd;
pub mod sha1;
pub mod sha2;
pub mod sha3;
pub mod tiger;
pub mod whirlpool;
