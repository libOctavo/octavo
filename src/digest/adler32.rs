use digest::Digest;

use byteorder::{
    WriteBytesExt,
    BigEndian
};

const MOD32: u32 = 65_521;

pub struct Adler32 {
    a: u16,
    b: u16,
}

impl Default for Adler32 {
    fn default() -> Self {
        Adler32 { a: 1, b: 0 }
    }
}

impl Digest for Adler32 {
    fn update<T: AsRef<[u8]>>(&mut self, update: T) {
        for byte in update.as_ref() {
            self.a = ((self.a as u32).wrapping_add(*byte as u32) % MOD32) as u16;
            self.b = ((self.b as u32).wrapping_add(self.a as u32) % MOD32) as u16;
        }
    }

    fn output_bits() -> usize { 32 }
    fn block_size() -> usize { 1 }

    fn result<T: AsMut<[u8]>>(self, mut out: T) {
        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());

        out.write_u16::<BigEndian>(self.b).unwrap();
        out.write_u16::<BigEndian>(self.a).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;
    use digest::test::Test;

    const TESTS: [Test<'static>; 1] = [
        Test { input: "Wikipedia", output: "11e60398" }
    ];

    #[test]
    fn test_adler32() {
        for test in &TESTS {
            test.test(Adler32::default());
        }
    }
}
