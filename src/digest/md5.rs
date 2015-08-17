use digest::Digest;
use utils::buffer::{
    FixedBuffer64,
    FixedBuffer,
    StandardPadding
};
use byteorder::{
    WriteBytesExt,
    ReadBytesExt,
    LittleEndian
};

#[derive(Debug)]
struct MD5State {
    s0: u32,
    s1: u32,
    s2: u32,
    s3: u32
}

impl MD5State {
    fn new() -> Self {
        MD5State {
            s0: 0x67452301,
            s1: 0xefcdab89,
            s2: 0x98badcfe,
            s3: 0x10325476
        }
    }

    fn process_block(&mut self, mut input: &[u8]) {
        fn f(u: u32, v: u32, w: u32) -> u32 {
            (u & v) | (!u & w)
        }

        fn g(u: u32, v: u32, w: u32) -> u32 {
            (u & w) | (v & !w)
        }

        fn h(u: u32, v: u32, w: u32) -> u32 {
            u ^ v ^ w
        }

        fn i(u: u32, v: u32, w: u32) -> u32 {
            v ^ (u | !w)
        }

        fn op_f(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(f(x, y, z)).wrapping_add(m).rotate_left(s).wrapping_add(x)
        }

        fn op_g(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(g(x, y, z)).wrapping_add(m).rotate_left(s).wrapping_add(x)
        }

        fn op_h(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(h(x, y, z)).wrapping_add(m).rotate_left(s).wrapping_add(x)
        }

        fn op_i(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(i(x, y, z)).wrapping_add(m).rotate_left(s).wrapping_add(x)
        }

        let mut a = self.s0;
        let mut b = self.s1;
        let mut c = self.s2;
        let mut d = self.s3;

        let mut i = 0;
        let mut data = [0u32; 16];

        while let Ok(val) = input.read_u32::<LittleEndian>() {
            data[i] = val;
            i += 1;
        }

        // round 1
        for i in (0..4) {
            let i = i * 4;
            a = op_f(a, b, c, d, data[i].wrapping_add(C1[i]), 7);
            d = op_f(d, a, b, c, data[i + 1].wrapping_add(C1[i + 1]), 12);
            c = op_f(c, d, a, b, data[i + 2].wrapping_add(C1[i + 2]), 17);
            b = op_f(b, c, d, a, data[i + 3].wrapping_add(C1[i + 3]), 22);
        }

        // round 2
        let mut t = 1;
        for i in (0..4) {
            let i = i * 4;
            a = op_g(a, b, c, d, data[t & 0x0f].wrapping_add(C2[i]), 5);
            d = op_g(d, a, b, c, data[(t + 5) & 0x0f].wrapping_add(C2[i + 1]), 9);
            c = op_g(c, d, a, b, data[(t + 10) & 0x0f].wrapping_add(C2[i + 2]), 14);
            b = op_g(b, c, d, a, data[(t + 15) & 0x0f].wrapping_add(C2[i + 3]), 20);
            t += 20;
        }

        // round 3
        t = 5;
        for i in (0..4) {
            let i = i * 4;
            a = op_h(a, b, c, d, data[t & 0x0f].wrapping_add(C3[i]), 4);
            d = op_h(d, a, b, c, data[(t + 3) & 0x0f].wrapping_add(C3[i + 1]), 11);
            c = op_h(c, d, a, b, data[(t + 6) & 0x0f].wrapping_add(C3[i + 2]), 16);
            b = op_h(b, c, d, a, data[(t + 9) & 0x0f].wrapping_add(C3[i + 3]), 23);
            t += 12;
        }

        // round 4
        t = 0;
        for i in (0..4) {
            let i = i * 4;
            a = op_i(a, b, c, d, data[t & 0x0f].wrapping_add(C4[i]), 6);
            d = op_i(d, a, b, c, data[(t + 7) & 0x0f].wrapping_add(C4[i + 1]), 10);
            c = op_i(c, d, a, b, data[(t + 14) & 0x0f].wrapping_add(C4[i + 2]), 15);
            b = op_i(b, c, d, a, data[(t + 21) & 0x0f].wrapping_add(C4[i + 3]), 21);
            t += 28;
        }

        self.s0 = self.s0.wrapping_add(a);
        self.s1 = self.s1.wrapping_add(b);
        self.s2 = self.s2.wrapping_add(c);
        self.s3 = self.s3.wrapping_add(d);
    }
}

// Round 1 constants
static C1: [u32; 16] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
];

// Round 2 constants
static C2: [u32; 16] = [
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
];

// Round 3 constants
static C3: [u32; 16] = [
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
];

// Round 4 constants
static C4: [u32; 16] = [
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
];

pub struct MD5 {
    state: MD5State,
    length: u64,
    buffer: FixedBuffer64,
}

impl Default for MD5 {
    fn default() -> Self {
        MD5 {
            state: MD5State::new(),
            length: 0,
            buffer: FixedBuffer64::new(),
        }
    }
}

impl Digest for MD5 {
    fn update<T>(&mut self, input: T) where T: AsRef<[u8]> {
        let input = input.as_ref();
        self.length += input.len() as u64;

        let state = &mut self.state;
        self.buffer.input(&input[..], |d| state.process_block(d));
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
    use digest::Digest;
    use digest::test::Test;
    use super::MD5;

    const TESTS: [Test<'static>; 7] = [
        Test { input: "", output: "d41d8cd98f00b204e9800998ecf8427e" },
        Test { input: "a", output: "0cc175b9c0f1b6a831c399e269772661" },
        Test { input: "abc", output: "900150983cd24fb0d6963f7d28e17f72" },
        Test { input: "message digest", output: "f96b697d7cb7938d525a2f31aaf161d0" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "c3fcd3d76192e4007dfb496cca67e13b" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "d174ab98d277d9f5a5611c2c9f419d9f" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "57edf4a22be3c955ac49da2e2107b67a" },
    ];

    #[test]
    fn test_md5() {
        // Examples from wikipedia

        // Test that it works when accepting the message all at once
        for test in &TESTS {
            test.test(MD5::new());
        }
    }
}
