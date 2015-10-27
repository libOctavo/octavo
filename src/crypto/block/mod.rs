//! Block cryptosystems

#[cfg(feature = "blowfish")]
pub mod blowfish;

pub trait BlockEncrypt<T> {
    fn block_size() -> usize;

    fn encrypt_block<I, O>(&self, input: I, output: O)
        where I: AsRef<[T]>,
              O: AsMut<[T]>;
}

pub trait BlockDecrypt<T> {
    fn block_size() -> usize;

    fn decrypt_block<I, O>(&self, input: I, output: O)
        where I: AsRef<[T]>,
              O: AsMut<[T]>;
}
