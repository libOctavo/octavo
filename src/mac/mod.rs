use std::io::Write;

pub mod hmac;

pub trait MAC: Sized {
    fn update<D: AsRef<[u8]>>(&mut self, data: D);

    /// Output size in bits
    fn output_bits() -> usize;
    /// Output size in bytes
    fn output_bytes() -> usize {
        (Self::output_bits() + 7) / 8
    }
    fn block_size() -> usize;

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
