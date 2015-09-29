#[cfg(feature = "chacha20")] pub mod chacha20;

trait StreamEncrypt {
    fn encrypt_stream<I, O>(&mut self, input: I, output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]>;
}

trait StreamDecrypt {
    fn decrypt_stream<I, O>(&mut self, input: I, output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]>;
}
