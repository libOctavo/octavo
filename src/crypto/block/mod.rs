//! Block cryptosystems

use generic_array::ArrayLength;
use typenum::uint::Unsigned;

#[cfg(feature = "blowfish")]
pub mod blowfish;

/// Block encryptor definition
pub trait BlockEncrypt<T> {
    /// Single block size
    type BlockSize: Unsigned + ArrayLength<u8>;

    /// Single block size
    fn block_size() -> usize {
        Self::BlockSize::to_usize()
    }

    /// Encrypt single block of data
    fn encrypt_block<I, O>(&self, input: I, output: O)
        where I: AsRef<[T]>,
              O: AsMut<[T]>;
}

/// Block decryptor definition
pub trait BlockDecrypt<T> {
    /// Single block size
    type BlockSize: Unsigned + ArrayLength<u8>;

    /// Single block size
    fn block_size() -> usize {
        Self::BlockSize::to_usize()
    }

    /// Decrypt single block of data
    fn decrypt_block<I, O>(&self, input: I, output: O)
        where I: AsRef<[T]>,
              O: AsMut<[T]>;
}
