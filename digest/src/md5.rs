//! MD5 (Message-Digest Algorithm version 5)
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
//! | MD5  |    128 bits |   512 bits |      4 | [Merkle–Damgård][md] | [RFC 1321][rfc1321] |
//!
//! [rfc1321]: https://tools.ietf.org/html/rfc1321 "The MD5 Message-Digest Algorithm"
//! [md]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

use byteorder::{ByteOrder, LittleEndian};
use typenum::consts::{U16, U64, U128};
use static_buffer::{FixedBuffer64, FixedBuf, StandardPadding};

use Digest;
use wrapping::*;

#[derive(Copy, Clone, Debug)]
struct State {
    a: w32,
    b: w32,
    c: w32,
    d: w32,
}

macro_rules! process {
    ($w:expr, $x:expr, $y:expr, $z:expr, $m:expr, $s:expr, $f:ident) => {
        $w = ($w + $f($x, $y, $z) + $m).rotate_left($s) + $x
    }
}

#[inline]
fn f(u: w32, v: w32, w: w32) -> w32 {
    (u & v) | (!u & w)
}
#[inline]
fn g(u: w32, v: w32, w: w32) -> w32 {
    (u & w) | (v & !w)
}
#[inline]
fn h(u: w32, v: w32, w: w32) -> w32 {
    u ^ v ^ w
}
#[inline]
fn i(u: w32, v: w32, w: w32) -> w32 {
    v ^ (u | !w)
}

impl State {
    fn new() -> Self {
        State {
            a: W(0x67452301),
            b: W(0xefcdab89),
            c: W(0x98badcfe),
            d: W(0x10325476),
        }
    }

    #[inline]
    fn compress(&mut self, input: &[u8]) {
        let State { mut a, mut b, mut c, mut d } = *self;

        let mut data = [W(0); 16];

        for (v, c) in data.iter_mut().zip(input.chunks(4)) {
            *v = W(LittleEndian::read_u32(c));
        }

        // round 1
        process!(a, b, c, d, data[0] + CONSTS[0][0], 7, f);
        process!(d, a, b, c, data[1] + CONSTS[0][1], 12, f);
        process!(c, d, a, b, data[2] + CONSTS[0][2], 17, f);
        process!(b, c, d, a, data[3] + CONSTS[0][3], 22, f);

        process!(a, b, c, d, data[4] + CONSTS[0][4], 7, f);
        process!(d, a, b, c, data[5] + CONSTS[0][5], 12, f);
        process!(c, d, a, b, data[6] + CONSTS[0][6], 17, f);
        process!(b, c, d, a, data[7] + CONSTS[0][7], 22, f);

        process!(a, b, c, d, data[8] + CONSTS[0][8], 7, f);
        process!(d, a, b, c, data[9] + CONSTS[0][9], 12, f);
        process!(c, d, a, b, data[10] + CONSTS[0][10], 17, f);
        process!(b, c, d, a, data[11] + CONSTS[0][11], 22, f);

        process!(a, b, c, d, data[12] + CONSTS[0][12], 7, f);
        process!(d, a, b, c, data[13] + CONSTS[0][13], 12, f);
        process!(c, d, a, b, data[14] + CONSTS[0][14], 17, f);
        process!(b, c, d, a, data[15] + CONSTS[0][15], 22, f);

        // round 2
        process!(a, b, c, d, data[1] + CONSTS[1][0], 5, g);
        process!(d, a, b, c, data[6] + CONSTS[1][1], 9, g);
        process!(c, d, a, b, data[11] + CONSTS[1][2], 14, g);
        process!(b, c, d, a, data[0] + CONSTS[1][3], 20, g);

        process!(a, b, c, d, data[5] + CONSTS[1][4], 5, g);
        process!(d, a, b, c, data[10] + CONSTS[1][5], 9, g);
        process!(c, d, a, b, data[15] + CONSTS[1][6], 14, g);
        process!(b, c, d, a, data[4] + CONSTS[1][7], 20, g);

        process!(a, b, c, d, data[9] + CONSTS[1][8], 5, g);
        process!(d, a, b, c, data[14] + CONSTS[1][9], 9, g);
        process!(c, d, a, b, data[3] + CONSTS[1][10], 14, g);
        process!(b, c, d, a, data[8] + CONSTS[1][11], 20, g);

        process!(a, b, c, d, data[13] + CONSTS[1][12], 5, g);
        process!(d, a, b, c, data[2] + CONSTS[1][13], 9, g);
        process!(c, d, a, b, data[7] + CONSTS[1][14], 14, g);
        process!(b, c, d, a, data[12] + CONSTS[1][15], 20, g);

        // round 3
        process!(a, b, c, d, data[5] + CONSTS[2][0], 4, h);
        process!(d, a, b, c, data[8] + CONSTS[2][1], 11, h);
        process!(c, d, a, b, data[11] + CONSTS[2][2], 16, h);
        process!(b, c, d, a, data[14] + CONSTS[2][3], 23, h);

        process!(a, b, c, d, data[1] + CONSTS[2][4], 4, h);
        process!(d, a, b, c, data[4] + CONSTS[2][5], 11, h);
        process!(c, d, a, b, data[7] + CONSTS[2][6], 16, h);
        process!(b, c, d, a, data[10] + CONSTS[2][7], 23, h);

        process!(a, b, c, d, data[13] + CONSTS[2][8], 4, h);
        process!(d, a, b, c, data[0] + CONSTS[2][9], 11, h);
        process!(c, d, a, b, data[3] + CONSTS[2][10], 16, h);
        process!(b, c, d, a, data[6] + CONSTS[2][11], 23, h);

        process!(a, b, c, d, data[9] + CONSTS[2][12], 4, h);
        process!(d, a, b, c, data[12] + CONSTS[2][13], 11, h);
        process!(c, d, a, b, data[15] + CONSTS[2][14], 16, h);
        process!(b, c, d, a, data[2] + CONSTS[2][15], 23, h);

        // round 4
        process!(a, b, c, d, data[0] + CONSTS[3][0], 6, i);
        process!(d, a, b, c, data[7] + CONSTS[3][1], 10, i);
        process!(c, d, a, b, data[14] + CONSTS[3][2], 15, i);
        process!(b, c, d, a, data[5] + CONSTS[3][3], 21, i);

        process!(a, b, c, d, data[12] + CONSTS[3][4], 6, i);
        process!(d, a, b, c, data[3] + CONSTS[3][5], 10, i);
        process!(c, d, a, b, data[10] + CONSTS[3][6], 15, i);
        process!(b, c, d, a, data[1] + CONSTS[3][7], 21, i);

        process!(a, b, c, d, data[8] + CONSTS[3][8], 6, i);
        process!(d, a, b, c, data[15] + CONSTS[3][9], 10, i);
        process!(c, d, a, b, data[6] + CONSTS[3][10], 15, i);
        process!(b, c, d, a, data[13] + CONSTS[3][11], 21, i);

        process!(a, b, c, d, data[4] + CONSTS[3][12], 6, i);
        process!(d, a, b, c, data[11] + CONSTS[3][13], 10, i);
        process!(c, d, a, b, data[2] + CONSTS[3][14], 15, i);
        process!(b, c, d, a, data[9] + CONSTS[3][15], 21, i);

        self.a += a;
        self.b += b;
        self.c += c;
        self.d += d;
    }
}

static CONSTS: [[w32; 16]; 4] = [[W(0xd76aa478),
                                  W(0xe8c7b756),
                                  W(0x242070db),
                                  W(0xc1bdceee),
                                  W(0xf57c0faf),
                                  W(0x4787c62a),
                                  W(0xa8304613),
                                  W(0xfd469501),
                                  W(0x698098d8),
                                  W(0x8b44f7af),
                                  W(0xffff5bb1),
                                  W(0x895cd7be),
                                  W(0x6b901122),
                                  W(0xfd987193),
                                  W(0xa679438e),
                                  W(0x49b40821)],
                                 [W(0xf61e2562),
                                  W(0xc040b340),
                                  W(0x265e5a51),
                                  W(0xe9b6c7aa),
                                  W(0xd62f105d),
                                  W(0x02441453),
                                  W(0xd8a1e681),
                                  W(0xe7d3fbc8),
                                  W(0x21e1cde6),
                                  W(0xc33707d6),
                                  W(0xf4d50d87),
                                  W(0x455a14ed),
                                  W(0xa9e3e905),
                                  W(0xfcefa3f8),
                                  W(0x676f02d9),
                                  W(0x8d2a4c8a)],
                                 [W(0xfffa3942),
                                  W(0x8771f681),
                                  W(0x6d9d6122),
                                  W(0xfde5380c),
                                  W(0xa4beea44),
                                  W(0x4bdecfa9),
                                  W(0xf6bb4b60),
                                  W(0xbebfbc70),
                                  W(0x289b7ec6),
                                  W(0xeaa127fa),
                                  W(0xd4ef3085),
                                  W(0x04881d05),
                                  W(0xd9d4d039),
                                  W(0xe6db99e5),
                                  W(0x1fa27cf8),
                                  W(0xc4ac5665)],
                                 [W(0xf4292244),
                                  W(0x432aff97),
                                  W(0xab9423a7),
                                  W(0xfc93a039),
                                  W(0x655b59c3),
                                  W(0x8f0ccc92),
                                  W(0xffeff47d),
                                  W(0x85845dd1),
                                  W(0x6fa87e4f),
                                  W(0xfe2ce6e0),
                                  W(0xa3014314),
                                  W(0x4e0811a1),
                                  W(0xf7537e82),
                                  W(0xbd3af235),
                                  W(0x2ad7d2bb),
                                  W(0xeb86d391)]];

/// MD5 implementation
///
/// For more details check [module docs](index.html)
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
    type OutputBits = U128;
    type OutputBytes = U16;

    type BlockSize = U64;

    fn update<T>(&mut self, input: T)
        where T: AsRef<[u8]>
    {
        let input = input.as_ref();
        self.length += input.len() as u64;

        let state = &mut self.state;
        self.buffer.input(&input[..], |d| state.compress(d));
    }

    fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
        let state = &mut self.state;

        self.buffer.standard_padding(8, |d| state.compress(d));
        LittleEndian::write_u64(self.buffer.next(8), self.length << 3);
        state.compress(self.buffer.full_buffer());

        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());
        LittleEndian::write_u32(&mut out[0..4], state.a.0);
        LittleEndian::write_u32(&mut out[4..8], state.b.0);
        LittleEndian::write_u32(&mut out[8..12], state.c.0);
        LittleEndian::write_u32(&mut out[12..16], state.d.0);
    }
}
