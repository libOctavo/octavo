use std::ops::Div;
use std::num::Wrapping as W;

use byteorder::{ByteOrder, BigEndian};
use typenum::consts::{U8, U64, U128, U224, U256, U384, U512};

use digest::Digest;
use utils::buffer::{FixedBuf, FixedBuffer64, FixedBuffer128, StandardPadding};

const SHA224_INIT: [W<u32>; 8] = [W(0xc1059ed8),
                                  W(0x367cd507),
                                  W(0x3070dd17),
                                  W(0xf70e5939),
                                  W(0xffc00b31),
                                  W(0x68581511),
                                  W(0x64f98fa7),
                                  W(0xbefa4fa4)];
const SHA256_INIT: [W<u32>; 8] = [W(0x6a09e667),
                                  W(0xbb67ae85),
                                  W(0x3c6ef372),
                                  W(0xa54ff53a),
                                  W(0x510e527f),
                                  W(0x9b05688c),
                                  W(0x1f83d9ab),
                                  W(0x5be0cd19)];
const U32_ROUNDS: [W<u32>; 64] = [W(0x428a2f98),
                                  W(0x71374491),
                                  W(0xb5c0fbcf),
                                  W(0xe9b5dba5),
                                  W(0x3956c25b),
                                  W(0x59f111f1),
                                  W(0x923f82a4),
                                  W(0xab1c5ed5),
                                  W(0xd807aa98),
                                  W(0x12835b01),
                                  W(0x243185be),
                                  W(0x550c7dc3),
                                  W(0x72be5d74),
                                  W(0x80deb1fe),
                                  W(0x9bdc06a7),
                                  W(0xc19bf174),
                                  W(0xe49b69c1),
                                  W(0xefbe4786),
                                  W(0x0fc19dc6),
                                  W(0x240ca1cc),
                                  W(0x2de92c6f),
                                  W(0x4a7484aa),
                                  W(0x5cb0a9dc),
                                  W(0x76f988da),
                                  W(0x983e5152),
                                  W(0xa831c66d),
                                  W(0xb00327c8),
                                  W(0xbf597fc7),
                                  W(0xc6e00bf3),
                                  W(0xd5a79147),
                                  W(0x06ca6351),
                                  W(0x14292967),
                                  W(0x27b70a85),
                                  W(0x2e1b2138),
                                  W(0x4d2c6dfc),
                                  W(0x53380d13),
                                  W(0x650a7354),
                                  W(0x766a0abb),
                                  W(0x81c2c92e),
                                  W(0x92722c85),
                                  W(0xa2bfe8a1),
                                  W(0xa81a664b),
                                  W(0xc24b8b70),
                                  W(0xc76c51a3),
                                  W(0xd192e819),
                                  W(0xd6990624),
                                  W(0xf40e3585),
                                  W(0x106aa070),
                                  W(0x19a4c116),
                                  W(0x1e376c08),
                                  W(0x2748774c),
                                  W(0x34b0bcb5),
                                  W(0x391c0cb3),
                                  W(0x4ed8aa4a),
                                  W(0x5b9cca4f),
                                  W(0x682e6ff3),
                                  W(0x748f82ee),
                                  W(0x78a5636f),
                                  W(0x84c87814),
                                  W(0x8cc70208),
                                  W(0x90befffa),
                                  W(0xa4506ceb),
                                  W(0xbef9a3f7),
                                  W(0xc67178f2)];

const SHA384_INIT: [W<u64>; 8] = [W(0xcbbb9d5dc1059ed8),
                                  W(0x629a292a367cd507),
                                  W(0x9159015a3070dd17),
                                  W(0x152fecd8f70e5939),
                                  W(0x67332667ffc00b31),
                                  W(0x8eb44a8768581511),
                                  W(0xdb0c2e0d64f98fa7),
                                  W(0x47b5481dbefa4fa4)];
const SHA512_INIT: [W<u64>; 8] = [W(0x6a09e667f3bcc908),
                                  W(0xbb67ae8584caa73b),
                                  W(0x3c6ef372fe94f82b),
                                  W(0xa54ff53a5f1d36f1),
                                  W(0x510e527fade682d1),
                                  W(0x9b05688c2b3e6c1f),
                                  W(0x1f83d9abfb41bd6b),
                                  W(0x5be0cd19137e2179)];
const SHA512_224_INIT: [W<u64>; 8] = [W(0x8c3d37c819544da2),
                                      W(0x73e1996689dcd4d6),
                                      W(0x1dfab7ae32ff9c82),
                                      W(0x679dd514582f9fcf),
                                      W(0x0f6d2b697bd44da8),
                                      W(0x77e36f7304c48942),
                                      W(0x3f9d85a86a1d36c8),
                                      W(0x1112e6ad91d692a1)];
const SHA512_256_INIT: [W<u64>; 8] = [W(0x22312194fc2bf72c),
                                      W(0x9f555fa3c84c64c2),
                                      W(0x2393b86b6f53b151),
                                      W(0x963877195940eabd),
                                      W(0x96283ee2a88effe3),
                                      W(0xbe5e1e2553863992),
                                      W(0x2b0199fc2c85b8aa),
                                      W(0x0eb72ddc81c52ca2)];

const U64_ROUNDS: [W<u64>; 80] = [W(0x428a2f98d728ae22),
                                  W(0x7137449123ef65cd),
                                  W(0xb5c0fbcfec4d3b2f),
                                  W(0xe9b5dba58189dbbc),
                                  W(0x3956c25bf348b538),
                                  W(0x59f111f1b605d019),
                                  W(0x923f82a4af194f9b),
                                  W(0xab1c5ed5da6d8118),
                                  W(0xd807aa98a3030242),
                                  W(0x12835b0145706fbe),
                                  W(0x243185be4ee4b28c),
                                  W(0x550c7dc3d5ffb4e2),
                                  W(0x72be5d74f27b896f),
                                  W(0x80deb1fe3b1696b1),
                                  W(0x9bdc06a725c71235),
                                  W(0xc19bf174cf692694),
                                  W(0xe49b69c19ef14ad2),
                                  W(0xefbe4786384f25e3),
                                  W(0x0fc19dc68b8cd5b5),
                                  W(0x240ca1cc77ac9c65),
                                  W(0x2de92c6f592b0275),
                                  W(0x4a7484aa6ea6e483),
                                  W(0x5cb0a9dcbd41fbd4),
                                  W(0x76f988da831153b5),
                                  W(0x983e5152ee66dfab),
                                  W(0xa831c66d2db43210),
                                  W(0xb00327c898fb213f),
                                  W(0xbf597fc7beef0ee4),
                                  W(0xc6e00bf33da88fc2),
                                  W(0xd5a79147930aa725),
                                  W(0x06ca6351e003826f),
                                  W(0x142929670a0e6e70),
                                  W(0x27b70a8546d22ffc),
                                  W(0x2e1b21385c26c926),
                                  W(0x4d2c6dfc5ac42aed),
                                  W(0x53380d139d95b3df),
                                  W(0x650a73548baf63de),
                                  W(0x766a0abb3c77b2a8),
                                  W(0x81c2c92e47edaee6),
                                  W(0x92722c851482353b),
                                  W(0xa2bfe8a14cf10364),
                                  W(0xa81a664bbc423001),
                                  W(0xc24b8b70d0f89791),
                                  W(0xc76c51a30654be30),
                                  W(0xd192e819d6ef5218),
                                  W(0xd69906245565a910),
                                  W(0xf40e35855771202a),
                                  W(0x106aa07032bbd1b8),
                                  W(0x19a4c116b8d2d0c8),
                                  W(0x1e376c085141ab53),
                                  W(0x2748774cdf8eeb99),
                                  W(0x34b0bcb5e19b48a8),
                                  W(0x391c0cb3c5c95a63),
                                  W(0x4ed8aa4ae3418acb),
                                  W(0x5b9cca4f7763e373),
                                  W(0x682e6ff3d6b2b8a3),
                                  W(0x748f82ee5defb2fc),
                                  W(0x78a5636f43172f60),
                                  W(0x84c87814a1f0ab72),
                                  W(0x8cc702081a6439ec),
                                  W(0x90befffa23631e28),
                                  W(0xa4506cebde82bde9),
                                  W(0xbef9a3f7b2c67915),
                                  W(0xc67178f2e372532b),
                                  W(0xca273eceea26619c),
                                  W(0xd186b8c721c0c207),
                                  W(0xeada7dd6cde0eb1e),
                                  W(0xf57d4f7fee6ed178),
                                  W(0x06f067aa72176fba),
                                  W(0x0a637dc5a2c898a6),
                                  W(0x113f9804bef90dae),
                                  W(0x1b710b35131c471b),
                                  W(0x28db77f523047d84),
                                  W(0x32caab7b40c72493),
                                  W(0x3c9ebe0a15c9bebc),
                                  W(0x431d67c49c100d4c),
                                  W(0x4cc5d4becb3e42b6),
                                  W(0x597f299cfc657e2a),
                                  W(0x5fcb6fab3ad6faec),
                                  W(0x6c44198c4a475817)];

#[derive(Copy, Clone, Debug)]
struct State<T: Copy> {
    state: [W<T>; 8],
}

macro_rules! impl_state {
    ($typ:ty, $consts:ident, $bsize:expr, $chunk:expr, $size:expr, $read:ident,
         $s1:expr, $s2:expr, $s3:expr, $s4:expr) => {
        impl State<$typ> {
            fn process_block(&mut self, data: &[u8]) {
                debug_assert!(data.len() == $bsize);

                let mut a = self.state[0];
                let mut b = self.state[1];
                let mut c = self.state[2];
                let mut d = self.state[3];
                let mut e = self.state[4];
                let mut f = self.state[5];
                let mut g = self.state[6];
                let mut h = self.state[7];
                let mut w = [W(0); 16];

                for (x, y) in data.chunks($chunk).zip(w.iter_mut()) {
                    *y = W(BigEndian::$read(x));
                }

                Self::round(w[0], a, b, c, &mut d, e, f, g, &mut h, 0);
                Self::round(w[1], h, a, b, &mut c, d, e, f, &mut g, 1);
                Self::round(w[2], g, h, a, &mut b, c, d, e, &mut f, 2);
                Self::round(w[3], f, g, h, &mut a, b, c, d, &mut e, 3);
                Self::round(w[4], e, f, g, &mut h, a, b, c, &mut d, 4);
                Self::round(w[5], d, e, f, &mut g, h, a, b, &mut c, 5);
                Self::round(w[6], c, d, e, &mut f, g, h, a, &mut b, 6);
                Self::round(w[7], b, c, d, &mut e, f, g, h, &mut a, 7);
                Self::round(w[8], a, b, c, &mut d, e, f, g, &mut h, 8);
                Self::round(w[9], h, a, b, &mut c, d, e, f, &mut g, 9);
                Self::round(w[10], g, h, a, &mut b, c, d, e, &mut f, 10);
                Self::round(w[11], f, g, h, &mut a, b, c, d, &mut e, 11);
                Self::round(w[12], e, f, g, &mut h, a, b, c, &mut d, 12);
                Self::round(w[13], d, e, f, &mut g, h, a, b, &mut c, 13);
                Self::round(w[14], c, d, e, &mut f, g, h, a, &mut b, 14);
                Self::round(w[15], b, c, d, &mut e, f, g, h, &mut a, 15);

                for j in 1..($consts.len() / 16) {
                    let i = j * 16;
                    Self::round_with_msg_scheduling(a, b, c, &mut d, e, f, g, &mut h, i + 0, &mut w);
                    Self::round_with_msg_scheduling(h, a, b, &mut c, d, e, f, &mut g, i + 1, &mut w);
                    Self::round_with_msg_scheduling(g, h, a, &mut b, c, d, e, &mut f, i + 2, &mut w);
                    Self::round_with_msg_scheduling(f, g, h, &mut a, b, c, d, &mut e, i + 3, &mut w);
                    Self::round_with_msg_scheduling(e, f, g, &mut h, a, b, c, &mut d, i + 4, &mut w);
                    Self::round_with_msg_scheduling(d, e, f, &mut g, h, a, b, &mut c, i + 5, &mut w);
                    Self::round_with_msg_scheduling(c, d, e, &mut f, g, h, a, &mut b, i + 6, &mut w);
                    Self::round_with_msg_scheduling(b, c, d, &mut e, f, g, h, &mut a, i + 7, &mut w);
                    Self::round_with_msg_scheduling(a, b, c, &mut d, e, f, g, &mut h, i + 8, &mut w);
                    Self::round_with_msg_scheduling(h, a, b, &mut c, d, e, f, &mut g, i + 9, &mut w);
                    Self::round_with_msg_scheduling(g, h, a, &mut b, c, d, e, &mut f, i + 10, &mut w);
                    Self::round_with_msg_scheduling(f, g, h, &mut a, b, c, d, &mut e, i + 11, &mut w);
                    Self::round_with_msg_scheduling(e, f, g, &mut h, a, b, c, &mut d, i + 12, &mut w);
                    Self::round_with_msg_scheduling(d, e, f, &mut g, h, a, b, &mut c, i + 13, &mut w);
                    Self::round_with_msg_scheduling(c, d, e, &mut f, g, h, a, &mut b, i + 14, &mut w);
                    Self::round_with_msg_scheduling(b, c, d, &mut e, f, g, h, &mut a, i + 15, &mut w);
                }

                self.state[0] = self.state[0] + a;
                self.state[1] = self.state[1] + b;
                self.state[2] = self.state[2] + c;
                self.state[3] = self.state[3] + d;
                self.state[4] = self.state[4] + e;
                self.state[5] = self.state[5] + f;
                self.state[6] = self.state[6] + g;
                self.state[7] = self.state[7] + h;
            }

            #[inline(always)]
            fn round(t: W<$typ>, a: W<$typ>, b: W<$typ>, c: W<$typ>, d: &mut W<$typ>,
                     e: W<$typ>, f: W<$typ>, g: W<$typ>, h: &mut W<$typ>, i: usize) {
                let t = t + *h +
                    W(e.0.rotate_right($s3.0) ^ e.0.rotate_right($s3.1) ^ e.0.rotate_right($s3.2)) +
                    ((e & f) ^ (!e & g)) + $consts[i];
                *h = W(a.0.rotate_right($s4.0) ^ a.0.rotate_right($s4.1) ^ a.0.rotate_right($s4.2)) +
                    ((a & b) ^ (a & c) ^ (b & c));
                *d = *d + t;
                *h = *h + t;
            }

            #[inline(always)]
            fn round_with_msg_scheduling(a: W<$typ>, b: W<$typ>, c: W<$typ>,
                                         d: &mut W<$typ>, e: W<$typ>, f: W<$typ>,
                                         g: W<$typ>, h: &mut W<$typ>, i: usize,
                                         w: &mut [W<$typ>; 16]) {
                let w0 = w[(i + 1) & 0xf];
                let w1 = w[(i + 14) & 0xf];
                let s0 = W(w0.0.rotate_right($s1.0) ^ w0.0.rotate_right($s1.1)) ^ (w0 >> $s1.2);
                let s1 = W(w1.0.rotate_right($s2.0) ^ w1.0.rotate_right($s2.1)) ^ (w1 >> $s2.2);
                let t = w[i & 0xf] + s0 + s1 + w[(i + 9) & 0xf];
                w[i & 0xf] = t;
                Self::round(t, a, b, c, d, e, f, g, h, i);
            }
        }
    }
}

impl_state!(u32, U32_ROUNDS,  64, 4, 64, read_u32,
            (7, 18,  3), (17, 19, 10),
            (6, 11, 25), ( 2, 13, 22));
impl_state!(u64, U64_ROUNDS, 128, 8, 80, read_u64,
            ( 1,  8,  7), (19, 61,  6),
            (14, 18, 41), (28, 34, 39));

macro_rules! impl_sha(
    (low $name:ident, $init:ident, $bits:ty) => {
        #[derive(Clone)]
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
            type OutputBits = $bits;
            type OutputBytes = <$bits as Div<U8>>::Output;

            type BlockSize = U64;

            fn update<T: AsRef<[u8]>>(&mut self, data: T) {
                let data = data.as_ref();
                self.length += data.len() as u64;

                let state = &mut self.state;
                self.buffer.input(data, |d| state.process_block(d));
            }

            fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
                let mut out = out.as_mut();
                assert!(out.len() >= Self::output_bytes());

                let state = &mut self.state;

                self.buffer.standard_padding(8, |d| state.process_block(d));
                BigEndian::write_u64(self.buffer.next(8), self.length << 3);
                state.process_block(self.buffer.full_buffer());

                for i in &mut state.state {
                    *i = W(i.0.to_be());
                }

                unsafe {
                    use std::ptr;
                    ptr::copy_nonoverlapping(
                        state.state.as_ptr() as *const u8,
                        out.as_mut_ptr(),
                        Self::output_bytes())
                };
            }
        }
    };
    (high $name:ident, $init:ident, $bits:ty) => {
        #[derive(Clone)]
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
            type OutputBits = $bits;
            type OutputBytes = <$bits as Div<U8>>::Output;

            type BlockSize = U128;

            fn update<T: AsRef<[u8]>>(&mut self, data: T) {
                let data = data.as_ref();
                self.length += data.len() as u64;

                let state = &mut self.state;
                self.buffer.input(data, |d| state.process_block(d));
            }

            fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
                let mut out = out.as_mut();
                assert!(out.len() >= Self::output_bytes());

                let state = &mut self.state;

                self.buffer.standard_padding(16, |d| state.process_block(d));
                BigEndian::write_u64(self.buffer.next(8), 0);
                BigEndian::write_u64(self.buffer.next(8), self.length << 3);
                state.process_block(self.buffer.full_buffer());

                for i in &mut state.state {
                    *i = W(i.0.to_be());
                }

                unsafe {
                    use std::ptr;
                    ptr::copy_nonoverlapping(
                        state.state.as_ptr() as *const u8,
                        out.as_mut_ptr(),
                        Self::output_bytes())
                };
            }
        }
    };
);

impl_sha!(low  Sha224, SHA224_INIT, U224);
impl_sha!(low  Sha256, SHA256_INIT, U256);
impl_sha!(high Sha384, SHA384_INIT, U384);
impl_sha!(high Sha512, SHA512_INIT, U512);

impl_sha!(high Sha512224, SHA512_224_INIT, U224);
impl_sha!(high Sha512256, SHA512_256_INIT, U256);
