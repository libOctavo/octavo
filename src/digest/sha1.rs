use byteorder::{
    ReadBytesExt,
    WriteBytesExt,
    BigEndian
};

use digest::Digest;
use utils::buffer::{
    FixedBuffer,
    FixedBuffer64,
    StandardPadding
};

struct State {
    state: [u32; 5]
}

impl State {
    fn new() -> Self {
        State {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
        }
    }

    #[allow(needless_range_loop)]
    fn process_block(&mut self, mut data: &[u8]) {
        assert_eq!(data.len(), 64);

        let mut words = [0u32; 80];

        fn ff(b: u32, c: u32, d: u32) -> u32 { d ^ (b & (c ^ d)) }
        fn gg(b: u32, c: u32, d: u32) -> u32 { b ^ c ^ d }
        fn hh(b: u32, c: u32, d: u32) -> u32 { (b & c) | (d & (b | c)) }
        fn ii(b: u32, c: u32, d: u32) -> u32 { b ^ c ^ d }

        for i in 0..16 {
            words[i] = data.read_u32::<BigEndian>().unwrap();
        }
        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }

        // let (mut a, mut b, mut c, mut d, mut e) = (self.h0, self.h1, self.h2, self.h3, self.h4);
        let mut state = self.state.clone();

        for (i, &word) in words.iter().enumerate() {
            let (f, k) = match i {
                0 ... 19 =>  (ff(state[1], state[2], state[3]), 0x5a827999),
                20 ... 39 => (gg(state[1], state[2], state[3]), 0x6ed9eba1),
                40 ... 59 => (hh(state[1], state[2], state[3]), 0x8f1bbcdc),
                60 ... 79 => (ii(state[1], state[2], state[3]), 0xca62c1d6),
                _ => unreachable!(),
            };

            let tmp = state[0].rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(state[4])
                .wrapping_add(k)
                .wrapping_add(word);
            state[4] = state[3];
            state[3] = state[2];
            state[2] = state[1].rotate_left(30);
            state[1] = state[0];
            state[0] = tmp;
        }

        for (i, byte) in self.state.iter_mut().enumerate() {
            *byte = byte.wrapping_add(state[i]);
        }
    }
}

pub struct Sha1 {
    state: State,
    buffer: FixedBuffer64,
    length: u64
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1 {
            state: State::new(),
            buffer: FixedBuffer64::new(),
            length: 0
        }
    }
}

impl Digest for Sha1 {
    fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        let data = data.as_ref();
        self.length += data.len() as u64;

        let state = &mut self.state;
        self.buffer.input(data, |d| state.process_block(d));
    }

    fn output_bits() -> usize { 160 }
    fn block_size() -> usize { 64 }

    fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
        let state = &mut self.state;

        self.buffer.standard_padding(8, |d| state.process_block(d));
        self.buffer.next(8).write_u64::<BigEndian>(self.length * 8).unwrap();
        state.process_block(self.buffer.full_buffer());

        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());
        for &val in &state.state {
            out.write_u32::<BigEndian>(val).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use digest::test::Test;
    use super::Sha1;

    const TESTS: &'static [Test<'static>] = &[
        Test { input: b"", output: &[ 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,  ] },
        Test { input: b"a", output: &[ 0x86, 0xf7, 0xe4, 0x37, 0xfa, 0xa5, 0xa7, 0xfc, 0xe1, 0x5d, 0x1d, 0xdc, 0xb9, 0xea, 0xea, 0xea, 0x37, 0x76, 0x67, 0xb8,  ] },
        Test { input: b"abc", output: &[ 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,  ] },
        Test { input: b"message digest", output: &[ 0xc1, 0x22, 0x52, 0xce, 0xda, 0x8b, 0xe8, 0x99, 0x4d, 0x5f, 0xa0, 0x29, 0x0a, 0x47, 0x23, 0x1c, 0x1d, 0x16, 0xaa, 0xe3,  ] },
        Test { input: b"abcdefghijklmnopqrstuvwxyz", output: &[ 0x32, 0xd1, 0x0c, 0x7b, 0x8c, 0xf9, 0x65, 0x70, 0xca, 0x04, 0xce, 0x37, 0xf2, 0xa1, 0x9d, 0x84, 0x24, 0x0d, 0x3a, 0x89,  ] },
        Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: &[ 0x76, 0x1c, 0x45, 0x7b, 0xf7, 0x3b, 0x14, 0xd2, 0x7e, 0x9e, 0x92, 0x65, 0xc4, 0x6f, 0x4b, 0x4d, 0xda, 0x11, 0xf9, 0x40,  ] },
        Test { input: b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: &[ 0x50, 0xab, 0xf5, 0x70, 0x6a, 0x15, 0x09, 0x90, 0xa0, 0x8b, 0x2c, 0x5e, 0xa4, 0x0f, 0xa0, 0xe5, 0x85, 0x55, 0x47, 0x32,  ] },
    ];

    #[test]
    fn simple_test_vectors() {
        for test in TESTS {
            test.test(Sha1::default());
        }
    }

    #[test]
    fn quickcheck() {
        use quickcheck::quickcheck;

        fn prop(vec: Vec<u8>) -> bool {
            use openssl::crypto::hash::{hash, Type};
            use digest::Digest;

            let octavo = {
                let mut dig = Sha1::default();
                let mut res = vec![0; 20];

                dig.update(&vec);
                dig.result(&mut res[..]);
                res
            };

            let openssl = hash(Type::SHA1, &vec);

            octavo == openssl
        }

        quickcheck(prop as fn(Vec<u8>) -> bool)
    }
}
