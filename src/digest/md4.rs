use digest;
use utils::buffer::{
    FixedBuffer64,
    FixedBuffer,
    StandardPadding
};

use byteorder::{
    ReadBytesExt,
    WriteBytesExt,
    LittleEndian
};

struct MD4State {
    s0: u32,
    s1: u32,
    s2: u32,
    s3: u32,
}

impl MD4State {
    fn new() -> Self {
        MD4State {
            s0: 0x67452301,
            s1: 0xefcdab89,
            s2: 0x98badcfe,
            s3: 0x10325476
        }
    }

    pub fn process_block(&mut self, mut update: &[u8]) {
        fn f(x: u32, y: u32, z: u32) -> u32 { ((y ^ z) & x) ^ z }
        fn g(x: u32, y: u32, z: u32) -> u32 { (x & y) | (x & z) | (y & z) }
        fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

        fn op_f(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
            a.wrapping_add(f(b, c, d)).wrapping_add(x).rotate_left(s)
        }
        fn op_g(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
            a.wrapping_add(g(b, c, d)).wrapping_add(x).wrapping_add(0x5a827999).rotate_left(s)
        }
        fn op_h(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
            a.wrapping_add(h(b, c, d)).wrapping_add(x).wrapping_add(0x6ed9eba1).rotate_left(s)
        }

        let mut i = 0;
        let mut x = [0u32; 16];

        while let Ok(val) = update.read_u32::<LittleEndian>() {
            x[i] = val;
            i += 1;
        }

        let mut a = self.s0;
        let mut b = self.s1;
        let mut c = self.s2;
        let mut d = self.s3;

        a = op_f(a, b, c, d, x[ 0],  3);
        d = op_f(d, a, b, c, x[ 1],  7);
        c = op_f(c, d, a, b, x[ 2], 11);
        b = op_f(b, c, d, a, x[ 3], 19);
        a = op_f(a, b, c, d, x[ 4],  3);
        d = op_f(d, a, b, c, x[ 5],  7);
        c = op_f(c, d, a, b, x[ 6], 11);
        b = op_f(b, c, d, a, x[ 7], 19);
        a = op_f(a, b, c, d, x[ 8],  3);
        d = op_f(d, a, b, c, x[ 9],  7);
        c = op_f(c, d, a, b, x[10], 11);
        b = op_f(b, c, d, a, x[11], 19);
        a = op_f(a, b, c, d, x[12],  3);
        d = op_f(d, a, b, c, x[13],  7);
        c = op_f(c, d, a, b, x[14], 11);
        b = op_f(b, c, d, a, x[15], 19);

        a = op_g(a, b, c, d, x[ 0],  3);
        d = op_g(d, a, b, c, x[ 4],  5);
        c = op_g(c, d, a, b, x[ 8],  9);
        b = op_g(b, c, d, a, x[12], 13);
        a = op_g(a, b, c, d, x[ 1],  3);
        d = op_g(d, a, b, c, x[ 5],  5);
        c = op_g(c, d, a, b, x[ 9],  9);
        b = op_g(b, c, d, a, x[13], 13);
        a = op_g(a, b, c, d, x[ 2],  3);
        d = op_g(d, a, b, c, x[ 6],  5);
        c = op_g(c, d, a, b, x[10],  9);
        b = op_g(b, c, d, a, x[14], 13);
        a = op_g(a, b, c, d, x[ 3],  3);
        d = op_g(d, a, b, c, x[ 7],  5);
        c = op_g(c, d, a, b, x[11],  9);
        b = op_g(b, c, d, a, x[15], 13);

        a = op_h(a, b, c, d, x[ 0],  3);
        d = op_h(d, a, b, c, x[ 8],  9);
        c = op_h(c, d, a, b, x[ 4], 11);
        b = op_h(b, c, d, a, x[12], 15);
        a = op_h(a, b, c, d, x[ 2],  3);
        d = op_h(d, a, b, c, x[10],  9);
        c = op_h(c, d, a, b, x[ 6], 11);
        b = op_h(b, c, d, a, x[14], 15);
        a = op_h(a, b, c, d, x[ 1],  3);
        d = op_h(d, a, b, c, x[ 9],  9);
        c = op_h(c, d, a, b, x[ 5], 11);
        b = op_h(b, c, d, a, x[13], 15);
        a = op_h(a, b, c, d, x[ 3],  3);
        d = op_h(d, a, b, c, x[11],  9);
        c = op_h(c, d, a, b, x[ 7], 11);
        b = op_h(b, c, d, a, x[15], 15);

        self.s0 = self.s0.wrapping_add(a);
        self.s1 = self.s1.wrapping_add(b);
        self.s2 = self.s2.wrapping_add(c);
        self.s3 = self.s3.wrapping_add(d);
    }
}

pub struct MD4 {
    state: MD4State,
    length: u64,
    buffer: FixedBuffer64,
}

impl Default for MD4 {
    fn default() -> Self {
        MD4 {
            state: MD4State::new(),
            buffer: FixedBuffer64::new(),
            length: 0
        }
    }
}

impl digest::Digest for MD4 {
    fn update<T>(&mut self, update: T) where T: AsRef<[u8]> {
        let update = update.as_ref();
        self.length += update.len() as u64;

        let state = &mut self.state;
        self.buffer.input(update, |d| state.process_block(d));
    }

    fn output_bits() -> usize { 128 }
    fn block_size() -> usize { 64 }

    fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
        let state = &mut self.state;

        self.buffer.standard_padding(8, |d| state.process_block(d));
        self.buffer.next(4).write_u32::<LittleEndian>((self.length << 3) as u32).unwrap();
        self.buffer.next(4).write_u32::<LittleEndian>((self.length >> 29) as u32).unwrap();
        state.process_block(self.buffer.full_buffer());

        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());
        out.write_u32::<LittleEndian>(state.s0).unwrap();
        out.write_u32::<LittleEndian>(state.s1).unwrap();
        out.write_u32::<LittleEndian>(state.s2).unwrap();
        out.write_u32::<LittleEndian>(state.s3).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use digest::test::Test;
    use super::MD4;

    const TESTS: [Test<'static>; 7] = [
        Test { input: "", output: "31d6cfe0d16ae931b73c59d7e0c089c0" },
        Test { input: "a", output: "bde52cb31de33e46245e05fbdbd6fb24" },
        Test { input: "abc", output: "a448017aaf21d8525fc10ae87aa6729d" },
        Test { input: "message digest", output: "d9130a8164549fe818874806e1c7014b" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "d79e1c308aa5bbcdeea8ed63df412da9" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "043f8582f241db351ce627e153e7f0e4" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "e33b4ddc9c38f2199c3e7b164fcc0536" },
    ];

    #[test]
    fn test_md4() {
        // Examples from wikipedia

        // Test that it works when accepting the message all at once
        for test in &TESTS {
            test.test(MD4::default());
        }
    }
}
