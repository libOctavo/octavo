use byteorder::{ByteOrder, LittleEndian};

use digest::Digest;
use utils::buffer::{FixedBuffer64, FixedBuffer, StandardPadding};

#[derive(Copy, Clone, Debug)]
struct State {
    s0: u32,
    s1: u32,
    s2: u32,
    s3: u32,
}

impl State {
    fn new() -> Self {
        State {
            s0: 0x67452301,
            s1: 0xefcdab89,
            s2: 0x98badcfe,
            s3: 0x10325476,
        }
    }

    #[allow(needless_range_loop)]
    fn process_block(&mut self, input: &[u8]) {
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

        let mut data = [0u32; 16];

        for (v, c) in data.iter_mut().zip(input.chunks(4)) {
            *v = LittleEndian::read_u32(c);
        }

        // round 1
        for i in 0..4 {
            let i = i * 4;
            a = op_f(a, b, c, d, data[i].wrapping_add(C1[i]), 7);
            d = op_f(d, a, b, c, data[i + 1].wrapping_add(C1[i + 1]), 12);
            c = op_f(c, d, a, b, data[i + 2].wrapping_add(C1[i + 2]), 17);
            b = op_f(b, c, d, a, data[i + 3].wrapping_add(C1[i + 3]), 22);
        }

        // round 2
        let mut t = 1;
        for i in 0..4 {
            let i = i * 4;
            a = op_g(a, b, c, d, data[t & 0x0f].wrapping_add(C2[i]), 5);
            d = op_g(d, a, b, c, data[(t + 5) & 0x0f].wrapping_add(C2[i + 1]), 9);
            c = op_g(c,
                     d,
                     a,
                     b,
                     data[(t + 10) & 0x0f].wrapping_add(C2[i + 2]),
                     14);
            b = op_g(b,
                     c,
                     d,
                     a,
                     data[(t + 15) & 0x0f].wrapping_add(C2[i + 3]),
                     20);
            t += 20;
        }

        // round 3
        t = 5;
        for i in 0..4 {
            let i = i * 4;
            a = op_h(a, b, c, d, data[t & 0x0f].wrapping_add(C3[i]), 4);
            d = op_h(d, a, b, c, data[(t + 3) & 0x0f].wrapping_add(C3[i + 1]), 11);
            c = op_h(c, d, a, b, data[(t + 6) & 0x0f].wrapping_add(C3[i + 2]), 16);
            b = op_h(b, c, d, a, data[(t + 9) & 0x0f].wrapping_add(C3[i + 3]), 23);
            t += 12;
        }

        // round 4
        t = 0;
        for i in 0..4 {
            let i = i * 4;
            a = op_i(a, b, c, d, data[t & 0x0f].wrapping_add(C4[i]), 6);
            d = op_i(d, a, b, c, data[(t + 7) & 0x0f].wrapping_add(C4[i + 1]), 10);
            c = op_i(c,
                     d,
                     a,
                     b,
                     data[(t + 14) & 0x0f].wrapping_add(C4[i + 2]),
                     15);
            b = op_i(b,
                     c,
                     d,
                     a,
                     data[(t + 21) & 0x0f].wrapping_add(C4[i + 3]),
                     21);
            t += 28;
        }

        self.s0 = self.s0.wrapping_add(a);
        self.s1 = self.s1.wrapping_add(b);
        self.s2 = self.s2.wrapping_add(c);
        self.s3 = self.s3.wrapping_add(d);
    }
}

// Round 1 constants
static C1: [u32; 16] = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
                        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821];

// Round 2 constants
static C2: [u32; 16] = [0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
                        0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a];

// Round 3 constants
static C3: [u32; 16] = [0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9,
                        0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665];

// Round 4 constants
static C4: [u32; 16] = [0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
                        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];

#[derive(Clone)]
pub struct Md5 {
    state: State,
    length: u64,
    buffer: FixedBuffer64,
}

impl Default for Md5 {
    fn default() -> Self {
        Md5 {
            state: State::new(),
            length: 0,
            buffer: FixedBuffer64::new(),
        }
    }
}

impl Digest for Md5 {
    fn update<T>(&mut self, input: T)
        where T: AsRef<[u8]>
    {
        let input = input.as_ref();
        self.length += input.len() as u64;

        let state = &mut self.state;
        self.buffer.input(&input[..], |d| state.process_block(d));
    }

    fn output_bits() -> usize {
        128
    }
    fn block_size() -> usize {
        64
    }

    fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
        let state = &mut self.state;

        self.buffer.standard_padding(8, |d| state.process_block(d));
        LittleEndian::write_u64(self.buffer.next(8), self.length << 3);
        state.process_block(self.buffer.full_buffer());

        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());
        LittleEndian::write_u32(&mut out[0..4], state.s0);
        LittleEndian::write_u32(&mut out[4..8], state.s1);
        LittleEndian::write_u32(&mut out[8..12], state.s2);
        LittleEndian::write_u32(&mut out[12..16], state.s3);
    }
}

#[cfg(test)]
mod tests {
    use digest::test::Test;
    use super::Md5;

    const TESTS: [Test<'static>; 7] = [
        Test { input: b"", output: &[ 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,  ] },
        Test { input: b"a", output: &[ 0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61,  ] },
        Test { input: b"abc", output: &[ 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,  ] },
        Test { input: b"message digest", output: &[ 0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0,  ] },
        Test { input: b"abcdefghijklmnopqrstuvwxyz", output: &[ 0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b,  ] },
        Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: &[ 0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f,  ] },
        Test { input: b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: &[ 0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a,  ] },
    ];

    #[test]
    fn rfc1321_test_vectors() {
        for test in &TESTS {
            test.test(Md5::default());
        }
    }

    #[test]
    fn quickcheck() {
        use quickcheck::quickcheck;

        fn prop(vec: Vec<u8>) -> bool {
            use openssl::crypto::hash::{hash, Type};
            use digest::Digest;

            let octavo = {
                let mut dig = Md5::default();
                let mut res = vec![0; 16];

                dig.update(&vec);
                dig.result(&mut res[..]);
                res
            };

            let openssl = hash(Type::MD5, &vec);

            octavo == openssl
        }

        quickcheck(prop as fn(Vec<u8>) -> bool)
    }
}
