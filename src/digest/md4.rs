//! MD4 (Message-Digest Algorithm version 4)
//!
//! # WARNING!!!
//!
//! This hash function has been severely compromised. **Do not use!**
//!
//! Instead you should use SHA-2 or SHA-3 family (if security required) or Tiger (if speed required).
//!
//! # General info
//!
//! | Name | Digest size | Block size | Rounds | Structure            | Reference           |
//! | ---- | ----------: | ---------: | ------:| -------------------- | ------------------- |
//! | MD4  |    128 bits |   512 bits |      3 | [Merkle–Damgård][md] | [RFC 1320][rfc1320] |
//!
//! [rfc1320]: https://tools.ietf.org/html/rfc1320 "The MD4 Message-Digest Algorithm"
//! [md]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

use byteorder::{ByteOrder, LittleEndian};
use typenum::consts::{U16, U64, U128};

use digest;
use utils::buffer::{FixedBuffer64, FixedBuf, StandardPadding};

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

    pub fn process_block(&mut self, update: &[u8]) {
        fn f(x: u32, y: u32, z: u32) -> u32 {
            ((y ^ z) & x) ^ z
        }
        fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (x & z) | (y & z)
        }
        fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        fn op_f(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
            a.wrapping_add(f(b, c, d)).wrapping_add(x).rotate_left(s)
        }
        fn op_g(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
            a.wrapping_add(g(b, c, d)).wrapping_add(x).wrapping_add(0x5a827999).rotate_left(s)
        }
        fn op_h(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
            a.wrapping_add(h(b, c, d)).wrapping_add(x).wrapping_add(0x6ed9eba1).rotate_left(s)
        }

        let mut x = [0u32; 16];
        for (v, c) in x.iter_mut().zip(update.chunks(4)) {
            *v = LittleEndian::read_u32(c);
        }

        let mut a = self.s0;
        let mut b = self.s1;
        let mut c = self.s2;
        let mut d = self.s3;

        // Round 1
        a = op_f(a, b, c, d, x[0], 3);
        d = op_f(d, a, b, c, x[1], 7);
        c = op_f(c, d, a, b, x[2], 11);
        b = op_f(b, c, d, a, x[3], 19);
        a = op_f(a, b, c, d, x[4], 3);
        d = op_f(d, a, b, c, x[5], 7);
        c = op_f(c, d, a, b, x[6], 11);
        b = op_f(b, c, d, a, x[7], 19);
        a = op_f(a, b, c, d, x[8], 3);
        d = op_f(d, a, b, c, x[9], 7);
        c = op_f(c, d, a, b, x[10], 11);
        b = op_f(b, c, d, a, x[11], 19);
        a = op_f(a, b, c, d, x[12], 3);
        d = op_f(d, a, b, c, x[13], 7);
        c = op_f(c, d, a, b, x[14], 11);
        b = op_f(b, c, d, a, x[15], 19);

        // Round 2
        a = op_g(a, b, c, d, x[0], 3);
        d = op_g(d, a, b, c, x[4], 5);
        c = op_g(c, d, a, b, x[8], 9);
        b = op_g(b, c, d, a, x[12], 13);
        a = op_g(a, b, c, d, x[1], 3);
        d = op_g(d, a, b, c, x[5], 5);
        c = op_g(c, d, a, b, x[9], 9);
        b = op_g(b, c, d, a, x[13], 13);
        a = op_g(a, b, c, d, x[2], 3);
        d = op_g(d, a, b, c, x[6], 5);
        c = op_g(c, d, a, b, x[10], 9);
        b = op_g(b, c, d, a, x[14], 13);
        a = op_g(a, b, c, d, x[3], 3);
        d = op_g(d, a, b, c, x[7], 5);
        c = op_g(c, d, a, b, x[11], 9);
        b = op_g(b, c, d, a, x[15], 13);

        // Round 3
        a = op_h(a, b, c, d, x[0], 3);
        d = op_h(d, a, b, c, x[8], 9);
        c = op_h(c, d, a, b, x[4], 11);
        b = op_h(b, c, d, a, x[12], 15);
        a = op_h(a, b, c, d, x[2], 3);
        d = op_h(d, a, b, c, x[10], 9);
        c = op_h(c, d, a, b, x[6], 11);
        b = op_h(b, c, d, a, x[14], 15);
        a = op_h(a, b, c, d, x[1], 3);
        d = op_h(d, a, b, c, x[9], 9);
        c = op_h(c, d, a, b, x[5], 11);
        b = op_h(b, c, d, a, x[13], 15);
        a = op_h(a, b, c, d, x[3], 3);
        d = op_h(d, a, b, c, x[11], 9);
        c = op_h(c, d, a, b, x[7], 11);
        b = op_h(b, c, d, a, x[15], 15);

        self.s0 = self.s0.wrapping_add(a);
        self.s1 = self.s1.wrapping_add(b);
        self.s2 = self.s2.wrapping_add(c);
        self.s3 = self.s3.wrapping_add(d);
    }
}

/// MD4 implementation
///
/// For more details check [module docs](index.html)
#[derive(Clone)]
pub struct Md4 {
    state: State,
    length: u64,
    buffer: FixedBuffer64,
}

impl Default for Md4 {
    fn default() -> Self {
        Md4 {
            state: State::new(),
            buffer: FixedBuffer64::new(),
            length: 0,
        }
    }
}

impl digest::Digest for Md4 {
    type OutputBits = U128;
    type OutputBytes = U16;

    type BlockSize = U64;

    fn update<T>(&mut self, update: T)
        where T: AsRef<[u8]>
    {
        let update = update.as_ref();
        self.length += update.len() as u64;

        let state = &mut self.state;
        self.buffer.input(update, |d| state.process_block(d));
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
