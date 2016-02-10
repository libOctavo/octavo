extern crate octavo_digest as digest;
extern crate generic_array;

pub mod hmac;

pub trait Mac: Sized {
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
    /// If output length is less than `MAC::output_bytes`.
    fn result<T>(self, output: T) where T: AsMut<[u8]>;
}
