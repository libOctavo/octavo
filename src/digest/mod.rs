//! Implementation of popular (and less popular, but fancy) hashing algorithms.
//!
//! **WARNING**: Not all of them are cryptographic hash functions and there are known attacks on
//! some of them. Use with careful and **always** check that the one you choose fits your
//! requirements!
//!
//! **WARNING**: If you want to use one of this functions as password hash then you are evil human
//! being and I really hope that I'm not using any of your services.
//!
//! ## Cryptographic hash functions
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
//! ### Considered safe
//!
//! - `SHA2` family
//! - `SHA3` family
//!
//! ### Deprecated in favour of stronger functions
//!
//! - `SHA1` - deprecated in favour of `SHA2` family
//!
//! ### Broken or easy breakable on modern hardware
//!
//! - `MD4`
//! - `MD5`

use std::io::Write;

pub trait Digest: Sized {
    /// Update digest with data.
    fn update<T>(&mut self, input: T) where T: AsRef<[u8]>;

    /// Output size in bits
    fn output_bits() -> usize;
    /// Output size in bytes
    fn output_bytes() -> usize {
        (Self::output_bits() + 7) / 8
    }
    fn block_size() -> usize;

    // fn reset() -> Self;

    /// Write resulting hash into `output`.
    ///
    /// `output` should be big enough to contain whole output.
    ///
    /// ## Panics
    ///
    /// If output length is less than `Digest::output_bytes`.
    fn result<T>(self, output: T) where T: AsMut<[u8]>;
    /// Returns hash as lowercase hexadecimal string
    fn hex_result(self) -> String {
        let size = Self::output_bytes();
        let mut hex = Vec::with_capacity(size * 2);
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }
        self.result(&mut buf[..]);

        for i in 0..size {
            write!(hex, "{:02x}", buf[i]).unwrap();
        }
        String::from_utf8(hex).unwrap()
    }
}

#[cfg(feature = "md4")] pub mod md4;
#[cfg(feature = "md5")] pub mod md5;
#[cfg(feature = "ripemd")] pub mod ripemd;
#[cfg(feature = "sha1")] pub mod sha1;
#[cfg(feature = "sha2")] pub mod sha2;
#[cfg(feature = "sha3")] pub mod sha3;
#[cfg(feature = "tiger")] pub mod tiger;
#[cfg(feature = "whirlpool")] pub mod whirlpool;

#[cfg(test)] mod test;
