//! SHA-1 (Secure Hash Algorithm)
//!
//! # WARNING!!!
//!
//! This hash function has been severely compromised. **Do not use!**
//!
//! Instead you should use SHA-2 or SHA-3 family.
//!
//! # General info
//!
//! | Name  | Digest size | Block size | Rounds | Structure            | Reference               |
//! | ----- | ----------: | ---------: | -----: | -------------------- | ----------------------- |
//! | SHA-1 |    160 bits |   512 bits |     80 | [Merkle–Damgård][md] | [FIPS 180-4][fips180-4] |
//!
//! [fips180-4]: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf "FIPS 180-4 Secure Hash Standard (SHS)"
//! [md]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

use byteorder::{ByteOrder, BigEndian};
use typenum::consts::{U20, U64, U160};
use static_buffer::{FixedBuf, FixedBuffer64, StandardPadding};

use Digest;
use simd::u32x4;

mod intrinsics;

#[derive(Copy, Clone, Debug)]
struct State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
}

impl State {
    fn new() -> Self {
        State {
            a: 0x67452301,
            b: 0xefcdab89,
            c: 0x98badcfe,
            d: 0x10325476,
            e: 0xc3d2e1f0,
        }
    }

    #[inline]
    fn process_block(&mut self, data: &[u8]) {
        debug_assert!(data.len() == 64);

        let mut words = [0u32; 16];

        for (word, chunk) in words.iter_mut().zip(data.chunks(4)) {
            *word = BigEndian::read_u32(chunk);
        }

        // Rounds 0..20
        let mut h0 = u32x4(self.a, self.b, self.c, self.d);
        let mut w0 = u32x4(words[0], words[1], words[2], words[3]);
        let mut h1 = intrinsics::digest_round_x4(h0, intrinsics::first_add(self.e, w0), 0);
        let mut w1 = u32x4(words[4], words[5], words[6], words[7]);
        h0 = intrinsics::round_x4(h1, h0, w1, 0);
        let mut w2 = u32x4(words[8], words[9], words[10], words[11]);
        h1 = intrinsics::round_x4(h0, h1, w2, 0);
        let mut w3 = u32x4(words[12], words[13], words[14], words[15]);
        h0 = intrinsics::round_x4(h1, h0, w3, 0);
        let mut w4 = intrinsics::schedule(w0, w1, w2, w3);
        h1 = intrinsics::round_x4(h0, h1, w4, 0);

        // Rounds 20..40
        w0 = intrinsics::schedule(w1, w2, w3, w4);
        h0 = intrinsics::round_x4(h1, h0, w0, 1);
        w1 = intrinsics::schedule(w2, w3, w4, w0);
        h1 = intrinsics::round_x4(h0, h1, w1, 1);
        w2 = intrinsics::schedule(w3, w4, w0, w1);
        h0 = intrinsics::round_x4(h1, h0, w2, 1);
        w3 = intrinsics::schedule(w4, w0, w1, w2);
        h1 = intrinsics::round_x4(h0, h1, w3, 1);
        w4 = intrinsics::schedule(w0, w1, w2, w3);
        h0 = intrinsics::round_x4(h1, h0, w4, 1);

        // Rounds 40..60
        w0 = intrinsics::schedule(w1, w2, w3, w4);
        h1 = intrinsics::round_x4(h0, h1, w0, 2);
        w1 = intrinsics::schedule(w2, w3, w4, w0);
        h0 = intrinsics::round_x4(h1, h0, w1, 2);
        w2 = intrinsics::schedule(w3, w4, w0, w1);
        h1 = intrinsics::round_x4(h0, h1, w2, 2);
        w3 = intrinsics::schedule(w4, w0, w1, w2);
        h0 = intrinsics::round_x4(h1, h0, w3, 2);
        w4 = intrinsics::schedule(w0, w1, w2, w3);
        h1 = intrinsics::round_x4(h0, h1, w4, 2);

        // Rounds 60..80
        w0 = intrinsics::schedule(w1, w2, w3, w4);
        h0 = intrinsics::round_x4(h1, h0, w0, 3);
        w1 = intrinsics::schedule(w2, w3, w4, w0);
        h1 = intrinsics::round_x4(h0, h1, w1, 3);
        w2 = intrinsics::schedule(w3, w4, w0, w1);
        h0 = intrinsics::round_x4(h1, h0, w2, 3);
        w3 = intrinsics::schedule(w4, w0, w1, w2);
        h1 = intrinsics::round_x4(h0, h1, w3, 3);
        w4 = intrinsics::schedule(w0, w1, w2, w3);
        h0 = intrinsics::round_x4(h1, h0, w4, 3);

        let e = h1.0.rotate_left(30);
        let u32x4(a, b, c, d) = h0;

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
        self.e = self.e.wrapping_add(e);
    }
}

/// SHA-1 implementation
///
/// For more details check [module docs](index.html)
#[derive(Clone)]
pub struct Sha1 {
    state: State,
    buffer: FixedBuffer64,
    length: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1 {
            state: State::new(),
            buffer: FixedBuffer64::new(),
            length: 0,
        }
    }
}

impl Digest for Sha1 {
    type OutputBits = U160;
    type OutputBytes = U20;

    type BlockSize = U64;

    fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        let data = data.as_ref();
        self.length += data.len() as u64;

        let state = &mut self.state;
        self.buffer.input(data, |d| state.process_block(d));
    }

    fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
        let state = &mut self.state;

        self.buffer.standard_padding(8, |d| state.process_block(d));
        BigEndian::write_u64(self.buffer.next(8), self.length * 8);
        state.process_block(self.buffer.full_buffer());

        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());
        BigEndian::write_u32(&mut out[0..4], state.a);
        BigEndian::write_u32(&mut out[4..8], state.b);
        BigEndian::write_u32(&mut out[8..12], state.c);
        BigEndian::write_u32(&mut out[12..16], state.d);
        BigEndian::write_u32(&mut out[16..20], state.e);
    }
}
