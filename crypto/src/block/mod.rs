//! Block cryptosystems

use generic_array::ArrayLength;
use typenum::uint::Unsigned;

pub mod blowfish;
pub mod aes;

/// Block encryptor definition
pub trait BlockEncrypt {
    /// Single block size
    type BlockSize: Unsigned + ArrayLength<u8>;

    /// Single block size
    fn block_size() -> usize {
        Self::BlockSize::to_usize()
    }

    /// Encrypt single block of data
    fn encrypt_block<I, O>(&self, input: I, output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]>;
}

/// Block decryptor definition
pub trait BlockDecrypt {
    /// Single block size
    type BlockSize: Unsigned + ArrayLength<u8>;

    /// Single block size
    fn block_size() -> usize {
        Self::BlockSize::to_usize()
    }

    /// Decrypt single block of data
    fn decrypt_block<I, O>(&self, input: I, output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]>;
}
