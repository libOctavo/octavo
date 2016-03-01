use self::safe::*;
use super::{BlockEncrypt, BlockDecrypt};

pub mod safe;

pub struct Aes128 {
    enc: AesSafe128Encryptor,
    dec: AesSafe128Decryptor,
}

impl Aes128 {
    pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
        Aes128 {
            enc: AesSafe128Encryptor::new(key.as_ref()),
            dec: AesSafe128Decryptor::new(key.as_ref()),
        }
    }
}

impl BlockEncrypt for Aes128 {
    type BlockSize = <AesSafe128Encryptor as BlockEncrypt>::BlockSize;

    fn encrypt_block<I, O>(&self, input: I, output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]>
    {
        self.enc.encrypt_block(input, output)
    }
}

impl BlockDecrypt for Aes128 {
    type BlockSize = <AesSafe128Decryptor as BlockDecrypt>::BlockSize;

    fn decrypt_block<I, O>(&self, input: I, output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]>
    {
        self.dec.decrypt_block(input, output)
    }
}
