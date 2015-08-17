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

struct SHA1State {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32
}

impl SHA1State {
    fn new() -> Self {
        SHA1State {
            h0: 0x67452301,
            h1: 0xefcdab89,
            h2: 0x98badcfe,
            h3: 0x10325476,
            h4: 0xc3d2e1f0
        }
    }

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

        let (mut a, mut b, mut c, mut d, mut e) = (self.h0, self.h1, self.h2, self.h3, self.h4);

        for (i, &word) in words.iter().enumerate() {
            let (f, k) = match i {
                0 ... 19 => (ff(b, c, d), 0x5a827999),
                20 ... 39 => (gg(b, c, d), 0x6ed9eba1),
                40 ... 59 => (hh(b, c, d), 0x8f1bbcdc),
                60 ... 79 => (ii(b, c, d), 0xca62c1d6),
                _ => unreachable!(),
            };

            let tmp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        self.h0 = self.h0.wrapping_add(a);
        self.h1 = self.h1.wrapping_add(b);
        self.h2 = self.h2.wrapping_add(c);
        self.h3 = self.h3.wrapping_add(d);
        self.h4 = self.h4.wrapping_add(e);
    }
}

pub struct SHA1 {
    state: SHA1State,
    buffer: FixedBuffer64,
    length: u64
}

impl Default for SHA1 {
    fn default() -> Self {
        SHA1 {
            state: SHA1State::new(),
            buffer: FixedBuffer64::new(),
            length: 0
        }
    }
}

impl Digest for SHA1 {
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
        out.write_u32::<BigEndian>(state.h0).unwrap();
        out.write_u32::<BigEndian>(state.h1).unwrap();
        out.write_u32::<BigEndian>(state.h2).unwrap();
        out.write_u32::<BigEndian>(state.h3).unwrap();
        out.write_u32::<BigEndian>(state.h4).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use digest::Digest;
    use digest::test::Test;
    use super::SHA1;

    const TESTS: [Test<'static>; 7] = [
        Test { input: "", output: "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
        Test { input: "a", output: "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8" },
        Test { input: "abc", output: "a9993e364706816aba3e25717850c26c9cd0d89d" },
        Test { input: "message digest", output: "c12252ceda8be8994d5fa0290a47231c1d16aae3" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "32d10c7b8cf96570ca04ce37f2a19d84240d3a89" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "761c457bf73b14d27e9e9265c46f4b4dda11f940" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "50abf5706a150990a08b2c5ea40fa0e585554732" },
    ];

    #[test]
    fn test_sha1() {
        for test in &TESTS {
            test.test(SHA1::new());
        }
    }
}
