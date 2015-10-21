use byteorder::{
    WriteBytesExt,
    ReadBytesExt,
    BigEndian
};

use digest::Digest;
use utils::buffer::{
    FixedBuffer,
    FixedBuffer64,
    FixedBuffer128,
    StandardPadding
};

const SHA224_INIT: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
];
const SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];
const U32_ROUNDS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

const SHA384_INIT: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
];
const SHA512_INIT: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];
const U64_ROUNDS: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

struct State<T> {
    state: [T; 8]
}

impl State<u32> {
    #[allow(needless_range_loop)]
    fn process_block(&mut self, mut data: &[u8]) {
        assert_eq!(data.len(), 64);

        let mut words = [0u32; 64];

        for i in 0..16 {
            words[i] = data.read_u32::<BigEndian>().unwrap();
        }
        for i in 16..64 {
            let s0 = words[i - 15].rotate_right(7)
                ^ words[i - 15].rotate_right(18)
                ^ (words[i - 15] >> 3);
            let s1 = words[i - 2].rotate_right(17)
                ^ words[i - 2].rotate_right(19)
                ^ (words[i - 2] >> 10);
            words[i] = words[i - 16]
                .wrapping_add(s0)
                .wrapping_add(words[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for (&word, &round) in words.iter().zip(U32_ROUNDS.iter()) {
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let tmp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(word).wrapping_add(round);
            let tmp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(tmp1);
            d = c;
            c = b;
            b = a;
            a = tmp1.wrapping_add(tmp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl State<u64> {
    #[allow(needless_range_loop)]
    fn process_block(&mut self, mut data: &[u8]) {
        assert_eq!(data.len(), 128);

        let mut words = [0u64; 80];

        for i in 0..16 {
            words[i] = data.read_u64::<BigEndian>().unwrap();
        }

        for i in 16..80 {
            let s0 = words[i - 15].rotate_right(1)
                ^ words[i - 15].rotate_right(8)
                ^ (words[i - 15] >> 7);
            let s1 = words[i - 2].rotate_right(19)
                ^ words[i - 2].rotate_right(61)
                ^ (words[i - 2] >> 6);
            words[i] = words[i - 16]
                .wrapping_add(s0)
                .wrapping_add(words[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for (&word, &round) in words.iter().zip(U64_ROUNDS.iter()) {
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let tmp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(word).wrapping_add(round);
            let tmp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(tmp1);
            d = c;
            c = b;
            b = a;
            a = tmp1.wrapping_add(tmp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

macro_rules! impl_sha(
    (low $name:ident, $init:ident, $bits:expr) => {
        pub struct $name {
            state: State<u32>,
            buffer: FixedBuffer64,
            length: u64
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    state: State { state: $init },
                    buffer: FixedBuffer64::new(),
                    length: 0
                }
            }
        }

        impl Digest for $name {
            fn update<T: AsRef<[u8]>>(&mut self, data: T) {
                let data = data.as_ref();
                self.length += data.len() as u64;

                let state = &mut self.state;
                self.buffer.input(data, |d| state.process_block(d));
            }

            fn output_bits() -> usize { $bits }
            fn block_size() -> usize { 64 }

            fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
                let state = &mut self.state;

                self.buffer.standard_padding(8, |d| state.process_block(d));
                self.buffer.next(8).write_u64::<BigEndian>(self.length * 8).unwrap();
                state.process_block(self.buffer.full_buffer());

                let mut out = out.as_mut();
                assert!(out.len() >= Self::output_bytes());
                for i in 0..($bits / 32) {
                    out.write_u32::<BigEndian>(state.state[i]).unwrap();
                }
            }
        }
    };
(high $name:ident, $init:ident, $bits:expr) => {
    pub struct $name {
        state: State<u64>,
        buffer: FixedBuffer128,
        length: u64
    }

    impl Default for $name {
        fn default() -> Self {
            $name {
                state: State { state: $init },
                buffer: FixedBuffer128::new(),
                length: 0
            }
        }
    }

    impl Digest for $name {
        fn update<T: AsRef<[u8]>>(&mut self, data: T) {
            let data = data.as_ref();
            self.length += data.len() as u64;

            let state = &mut self.state;
            self.buffer.input(data, |d| state.process_block(d));
        }

        fn output_bits() -> usize { $bits }
        fn block_size() -> usize { 128 }

        fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
            let state = &mut self.state;

            self.buffer.standard_padding(8, |d| state.process_block(d));
            self.buffer.next(8).write_u64::<BigEndian>(self.length * 8).unwrap();
            state.process_block(self.buffer.full_buffer());

            let mut out = out.as_mut();
            assert!(out.len() >= Self::output_bytes());
            for i in 0..($bits / 64) {
                out.write_u64::<BigEndian>(state.state[i]).unwrap();
            }
        }
    }
}
);

impl_sha!(low  Sha224, SHA224_INIT, 224);
impl_sha!(low  Sha256, SHA256_INIT, 256);
impl_sha!(high Sha384, SHA384_INIT, 384);
impl_sha!(high Sha512, SHA512_INIT, 512);

#[cfg(test)]
mod tests {
    mod sha224 {
        use digest::test::Test;
        use digest::sha2::Sha224;
        const TESTS: &'static [Test<'static>] = &[
            Test { input: b"", output: &[ 0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f,  ] },
            Test { input: b"a", output: &[ 0xab, 0xd3, 0x75, 0x34, 0xc7, 0xd9, 0xa2, 0xef, 0xb9, 0x46, 0x5d, 0xe9, 0x31, 0xcd, 0x70, 0x55, 0xff, 0xdb, 0x88, 0x79, 0x56, 0x3a, 0xe9, 0x80, 0x78, 0xd6, 0xd6, 0xd5,  ] },
            Test { input: b"abc", output: &[ 0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,  ] },
            Test { input: b"message digest", output: &[ 0x2c, 0xb2, 0x1c, 0x83, 0xae, 0x2f, 0x00, 0x4d, 0xe7, 0xe8, 0x1c, 0x3c, 0x70, 0x19, 0xcb, 0xcb, 0x65, 0xb7, 0x1a, 0xb6, 0x56, 0xb2, 0x2d, 0x6d, 0x0c, 0x39, 0xb8, 0xeb,  ] },
            Test { input: b"abcdefghijklmnopqrstuvwxyz", output: &[ 0x45, 0xa5, 0xf7, 0x2c, 0x39, 0xc5, 0xcf, 0xf2, 0x52, 0x2e, 0xb3, 0x42, 0x97, 0x99, 0xe4, 0x9e, 0x5f, 0x44, 0xb3, 0x56, 0xef, 0x92, 0x6b, 0xcf, 0x39, 0x0d, 0xcc, 0xc2,  ] },
            Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: &[ 0xbf, 0xf7, 0x2b, 0x4f, 0xcb, 0x7d, 0x75, 0xe5, 0x63, 0x29, 0x00, 0xac, 0x5f, 0x90, 0xd2, 0x19, 0xe0, 0x5e, 0x97, 0xa7, 0xbd, 0xe7, 0x2e, 0x74, 0x0d, 0xb3, 0x93, 0xd9,  ] },
            Test { input: b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: &[ 0xb5, 0x0a, 0xec, 0xbe, 0x4e, 0x9b, 0xb0, 0xb5, 0x7b, 0xc5, 0xf3, 0xae, 0x76, 0x0a, 0x8e, 0x01, 0xdb, 0x24, 0xf2, 0x03, 0xfb, 0x3c, 0xdc, 0xd1, 0x31, 0x48, 0x04, 0x6e,  ] }
        ];

        #[test]
        fn simple_test_vectors() {
            for test in TESTS {
                test.test(Sha224::default());
            }
        }

        #[test]
        fn quickcheck() {
            use quickcheck::quickcheck;

            fn prop(vec: Vec<u8>) -> bool {
                use openssl::crypto::hash::{hash, Type};
                use digest::Digest;

                let octavo = {
                    let mut dig = Sha224::default();
                    let mut res = vec![0; Sha224::output_bytes()];

                    dig.update(&vec);
                    dig.result(&mut res[..]);
                    res
                };

                let openssl = hash(Type::SHA224, &vec);

                octavo == openssl
            }

            quickcheck(prop as fn(Vec<u8>) -> bool)
        }
    }

    mod sha256 {
        use digest::test::Test;
        use digest::sha2::Sha256;

        const TESTS: &'static [Test<'static>] = &[
            Test { input: b"", output: &[ 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,  ] },
            Test { input: b"a", output: &[ 0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca, 0xfa, 0xc2, 0x31, 0xb3, 0x9a, 0x23, 0xdc, 0x4d, 0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72, 0xb9, 0x80, 0x77, 0x85, 0xaf, 0xee, 0x48, 0xbb,  ] },
            Test { input: b"abc", output: &[ 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,  ] },
            Test { input: b"message digest", output: &[ 0xf7, 0x84, 0x6f, 0x55, 0xcf, 0x23, 0xe1, 0x4e, 0xeb, 0xea, 0xb5, 0xb4, 0xe1, 0x55, 0x0c, 0xad, 0x5b, 0x50, 0x9e, 0x33, 0x48, 0xfb, 0xc4, 0xef, 0xa3, 0xa1, 0x41, 0x3d, 0x39, 0x3c, 0xb6, 0x50,  ] },
            Test { input: b"abcdefghijklmnopqrstuvwxyz", output: &[ 0x71, 0xc4, 0x80, 0xdf, 0x93, 0xd6, 0xae, 0x2f, 0x1e, 0xfa, 0xd1, 0x44, 0x7c, 0x66, 0xc9, 0x52, 0x5e, 0x31, 0x62, 0x18, 0xcf, 0x51, 0xfc, 0x8d, 0x9e, 0xd8, 0x32, 0xf2, 0xda, 0xf1, 0x8b, 0x73,  ] },
            Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: &[ 0xdb, 0x4b, 0xfc, 0xbd, 0x4d, 0xa0, 0xcd, 0x85, 0xa6, 0x0c, 0x3c, 0x37, 0xd3, 0xfb, 0xd8, 0x80, 0x5c, 0x77, 0xf1, 0x5f, 0xc6, 0xb1, 0xfd, 0xfe, 0x61, 0x4e, 0xe0, 0xa7, 0xc8, 0xfd, 0xb4, 0xc0,  ] },
            Test { input: b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: &[ 0xf3, 0x71, 0xbc, 0x4a, 0x31, 0x1f, 0x2b, 0x00, 0x9e, 0xef, 0x95, 0x2d, 0xd8, 0x3c, 0xa8, 0x0e, 0x2b, 0x60, 0x02, 0x6c, 0x8e, 0x93, 0x55, 0x92, 0xd0, 0xf9, 0xc3, 0x08, 0x45, 0x3c, 0x81, 0x3e,  ] }
        ];

        #[test]
        fn simple_test_vectors() {
            for test in TESTS {
                test.test(Sha256::default());
            }
        }

        #[test]
        fn quickcheck() {
            use quickcheck::quickcheck;

            fn prop(vec: Vec<u8>) -> bool {
                use openssl::crypto::hash::{hash, Type};
                use digest::Digest;

                let octavo = {
                    let mut dig = Sha256::default();
                    let mut res = vec![0; Sha256::output_bytes()];

                    dig.update(&vec);
                    dig.result(&mut res[..]);
                    res
                };

                let openssl = hash(Type::SHA256, &vec);

                octavo == openssl
            }

            quickcheck(prop as fn(Vec<u8>) -> bool)
        }
    }

    mod sha384 {
        use digest::test::Test;
        use digest::sha2::Sha384;

        const TESTS: &'static [Test<'static>] = &[
            Test { input: b"", output: &[ 0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,  ] },
            Test { input: b"a", output: &[ 0x54, 0xa5, 0x9b, 0x9f, 0x22, 0xb0, 0xb8, 0x08, 0x80, 0xd8, 0x42, 0x7e, 0x54, 0x8b, 0x7c, 0x23, 0xab, 0xd8, 0x73, 0x48, 0x6e, 0x1f, 0x03, 0x5d, 0xce, 0x9c, 0xd6, 0x97, 0xe8, 0x51, 0x75, 0x03, 0x3c, 0xaa, 0x88, 0xe6, 0xd5, 0x7b, 0xc3, 0x5e, 0xfa, 0xe0, 0xb5, 0xaf, 0xd3, 0x14, 0x5f, 0x31,  ] },
            Test { input: b"abc", output: &[ 0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,  ] },
            Test { input: b"message digest", output: &[ 0x47, 0x3e, 0xd3, 0x51, 0x67, 0xec, 0x1f, 0x5d, 0x8e, 0x55, 0x03, 0x68, 0xa3, 0xdb, 0x39, 0xbe, 0x54, 0x63, 0x9f, 0x82, 0x88, 0x68, 0xe9, 0x45, 0x4c, 0x23, 0x9f, 0xc8, 0xb5, 0x2e, 0x3c, 0x61, 0xdb, 0xd0, 0xd8, 0xb4, 0xde, 0x13, 0x90, 0xc2, 0x56, 0xdc, 0xbb, 0x5d, 0x5f, 0xd9, 0x9c, 0xd5,  ] },
            Test { input: b"abcdefghijklmnopqrstuvwxyz", output: &[ 0xfe, 0xb6, 0x73, 0x49, 0xdf, 0x3d, 0xb6, 0xf5, 0x92, 0x48, 0x15, 0xd6, 0xc3, 0xdc, 0x13, 0x3f, 0x09, 0x18, 0x09, 0x21, 0x37, 0x31, 0xfe, 0x5c, 0x7b, 0x5f, 0x49, 0x99, 0xe4, 0x63, 0x47, 0x9f, 0xf2, 0x87, 0x7f, 0x5f, 0x29, 0x36, 0xfa, 0x63, 0xbb, 0x43, 0x78, 0x4b, 0x12, 0xf3, 0xeb, 0xb4,  ] },
            Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: &[ 0x17, 0x61, 0x33, 0x6e, 0x3f, 0x7c, 0xbf, 0xe5, 0x1d, 0xeb, 0x13, 0x7f, 0x02, 0x6f, 0x89, 0xe0, 0x1a, 0x44, 0x8e, 0x3b, 0x1f, 0xaf, 0xa6, 0x40, 0x39, 0xc1, 0x46, 0x4e, 0xe8, 0x73, 0x2f, 0x11, 0xa5, 0x34, 0x1a, 0x6f, 0x41, 0xe0, 0xc2, 0x02, 0x29, 0x47, 0x36, 0xed, 0x64, 0xdb, 0x1a, 0x84,  ] },
            Test { input: b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: &[ 0xb1, 0x29, 0x32, 0xb0, 0x62, 0x7d, 0x1c, 0x06, 0x09, 0x42, 0xf5, 0x44, 0x77, 0x64, 0x15, 0x56, 0x55, 0xbd, 0x4d, 0xa0, 0xc9, 0xaf, 0xa6, 0xdd, 0x9b, 0x9e, 0xf5, 0x31, 0x29, 0xaf, 0x1b, 0x8f, 0xb0, 0x19, 0x59, 0x96, 0xd2, 0xde, 0x9c, 0xa0, 0xdf, 0x9d, 0x82, 0x1f, 0xfe, 0xe6, 0x70, 0x26,  ] },
        ];

        #[test]
        fn simple_test_vectors() {
            for test in TESTS {
                test.test(Sha384::default());
            }
        }

        #[test]
        fn quickcheck() {
            use quickcheck::quickcheck;

            fn prop(vec: Vec<u8>) -> bool {
                use openssl::crypto::hash::{hash, Type};
                use digest::Digest;

                let octavo = {
                    let mut dig = Sha384::default();
                    let mut res = vec![0; Sha384::output_bytes()];

                    dig.update(&vec);
                    dig.result(&mut res[..]);
                    res
                };

                let openssl = hash(Type::SHA384, &vec);

                octavo == openssl
            }

            quickcheck(prop as fn(Vec<u8>) -> bool)
        }
    }

    mod sha512 {
        use digest::test::Test;
        use digest::sha2::Sha512;

        const TESTS: &'static [Test<'static>] = &[
            Test { input: b"", output: &[ 0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,  ] },
            Test { input: b"a", output: &[ 0x1f, 0x40, 0xfc, 0x92, 0xda, 0x24, 0x16, 0x94, 0x75, 0x09, 0x79, 0xee, 0x6c, 0xf5, 0x82, 0xf2, 0xd5, 0xd7, 0xd2, 0x8e, 0x18, 0x33, 0x5d, 0xe0, 0x5a, 0xbc, 0x54, 0xd0, 0x56, 0x0e, 0x0f, 0x53, 0x02, 0x86, 0x0c, 0x65, 0x2b, 0xf0, 0x8d, 0x56, 0x02, 0x52, 0xaa, 0x5e, 0x74, 0x21, 0x05, 0x46, 0xf3, 0x69, 0xfb, 0xbb, 0xce, 0x8c, 0x12, 0xcf, 0xc7, 0x95, 0x7b, 0x26, 0x52, 0xfe, 0x9a, 0x75,  ] },
            Test { input: b"abc", output: &[ 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,  ] },
            Test { input: b"message digest", output: &[ 0x10, 0x7d, 0xbf, 0x38, 0x9d, 0x9e, 0x9f, 0x71, 0xa3, 0xa9, 0x5f, 0x6c, 0x05, 0x5b, 0x92, 0x51, 0xbc, 0x52, 0x68, 0xc2, 0xbe, 0x16, 0xd6, 0xc1, 0x34, 0x92, 0xea, 0x45, 0xb0, 0x19, 0x9f, 0x33, 0x09, 0xe1, 0x64, 0x55, 0xab, 0x1e, 0x96, 0x11, 0x8e, 0x8a, 0x90, 0x5d, 0x55, 0x97, 0xb7, 0x20, 0x38, 0xdd, 0xb3, 0x72, 0xa8, 0x98, 0x26, 0x04, 0x6d, 0xe6, 0x66, 0x87, 0xbb, 0x42, 0x0e, 0x7c,  ] },
            Test { input: b"abcdefghijklmnopqrstuvwxyz", output: &[ 0x4d, 0xbf, 0xf8, 0x6c, 0xc2, 0xca, 0x1b, 0xae, 0x1e, 0x16, 0x46, 0x8a, 0x05, 0xcb, 0x98, 0x81, 0xc9, 0x7f, 0x17, 0x53, 0xbc, 0xe3, 0x61, 0x90, 0x34, 0x89, 0x8f, 0xaa, 0x1a, 0xab, 0xe4, 0x29, 0x95, 0x5a, 0x1b, 0xf8, 0xec, 0x48, 0x3d, 0x74, 0x21, 0xfe, 0x3c, 0x16, 0x46, 0x61, 0x3a, 0x59, 0xed, 0x54, 0x41, 0xfb, 0x0f, 0x32, 0x13, 0x89, 0xf7, 0x7f, 0x48, 0xa8, 0x79, 0xc7, 0xb1, 0xf1,  ] },
            Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: &[ 0x1e, 0x07, 0xbe, 0x23, 0xc2, 0x6a, 0x86, 0xea, 0x37, 0xea, 0x81, 0x0c, 0x8e, 0xc7, 0x80, 0x93, 0x52, 0x51, 0x5a, 0x97, 0x0e, 0x92, 0x53, 0xc2, 0x6f, 0x53, 0x6c, 0xfc, 0x7a, 0x99, 0x96, 0xc4, 0x5c, 0x83, 0x70, 0x58, 0x3e, 0x0a, 0x78, 0xfa, 0x4a, 0x90, 0x04, 0x1d, 0x71, 0xa4, 0xce, 0xab, 0x74, 0x23, 0xf1, 0x9c, 0x71, 0xb9, 0xd5, 0xa3, 0xe0, 0x12, 0x49, 0xf0, 0xbe, 0xbd, 0x58, 0x94,  ] },
            Test { input: b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: &[ 0x72, 0xec, 0x1e, 0xf1, 0x12, 0x4a, 0x45, 0xb0, 0x47, 0xe8, 0xb7, 0xc7, 0x5a, 0x93, 0x21, 0x95, 0x13, 0x5b, 0xb6, 0x1d, 0xe2, 0x4e, 0xc0, 0xd1, 0x91, 0x40, 0x42, 0x24, 0x6e, 0x0a, 0xec, 0x3a, 0x23, 0x54, 0xe0, 0x93, 0xd7, 0x6f, 0x30, 0x48, 0xb4, 0x56, 0x76, 0x43, 0x46, 0x90, 0x0c, 0xb1, 0x30, 0xd2, 0xa4, 0xfd, 0x5d, 0xd1, 0x6a, 0xbb, 0x5e, 0x30, 0xbc, 0xb8, 0x50, 0xde, 0xe8, 0x43,  ] },
        ];

        #[test]
        fn simple_test_vectors() {
            for test in TESTS {
                test.test(Sha512::default());
            }
        }

        #[test]
        fn quickcheck() {
            use quickcheck::quickcheck;

            fn prop(vec: Vec<u8>) -> bool {
                use openssl::crypto::hash::{hash, Type};
                use digest::Digest;

                let octavo = {
                    let mut dig = Sha512::default();
                    let mut res = vec![0; Sha512::output_bytes()];

                    dig.update(&vec);
                    dig.result(&mut res[..]);
                    res
                };

                let openssl = hash(Type::SHA512, &vec);

                octavo == openssl
            }

            quickcheck(prop as fn(Vec<u8>) -> bool)
        }
    }
}
