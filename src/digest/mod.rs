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
//! **WARNING**: If you want to use one of this functions as password hash then
//! you are evil human being and I really hope that I'm not using any of your services.
//!
//! # Example
//!
//! Calculate SHA-512 sum:
//!
//! ```rust
//! # extern crate octavo;
//! use octavo::digest::Digest;
//! use octavo::digest::sha2::Sha512;
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

    fn output_bits() -> usize {
        Self::OutputBits::to_usize()
    }
    fn output_bytes() -> usize {
        Self::OutputBytes::to_usize()
    }
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

#[cfg(feature = "md4")]pub mod md4;
#[cfg(feature = "md5")]pub mod md5;
#[cfg(feature = "ripemd")]pub mod ripemd;
#[cfg(feature = "sha1")]pub mod sha1;
#[cfg(feature = "sha2")]pub mod sha2;
#[cfg(feature = "sha3")]pub mod sha3;
#[cfg(feature = "tiger")]pub mod tiger;
#[cfg(feature = "whirlpool")]pub mod whirlpool;
