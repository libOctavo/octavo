use core::ptr;
use core::ops::Mul;
use core::marker::PhantomData;

use static_buffer::{FixedBuffer128, FixedBuf};
use byteorder::{ByteOrder, LittleEndian};
use generic_array::ArrayLength;
use typenum::uint::Unsigned;
use typenum::consts::{U8, U16, U20, U28, U32, U48, U64, U128};

use Digest;
use wrapping::*;

const INIT: [w64; 8] = [W(0x6a09e667f3bcc908),
                        W(0xbb67ae8584caa73b),
                        W(0x3c6ef372fe94f82b),
                        W(0xa54ff53a5f1d36f1),
                        W(0x510e527fade682d1),
                        W(0x9b05688c2b3e6c1f),
                        W(0x1f83d9abfb41bd6b),
                        W(0x5be0cd19137e2179)];

const R1: u32 = 32;
const R2: u32 = 24;
const R3: u32 = 16;
const R4: u32 = 63;

const SIGMA: [[usize; 16]; 12] = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                                  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
                                  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
                                  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
                                  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
                                  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
                                  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
                                  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
                                  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
                                  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
                                  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                                  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]];

macro_rules! G {
    ($v:ident, $a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $y:expr) => {
        $v[$a] += $v[$b] + $x;
        $v[$d]  = ($v[$d] ^ $v[$a]).rotate_right(R1);
        $v[$c] += $v[$d];
        $v[$b]  = ($v[$b] ^ $v[$c]).rotate_right(R2);
        $v[$a] += $v[$b] + $y;
        $v[$d]  = ($v[$d] ^ $v[$a]).rotate_right(R3);
        $v[$c] += $v[$d];
        $v[$b]  = ($v[$b] ^ $v[$c]).rotate_right(R4);
    }
}

#[derive(Copy, Clone, Debug)]
struct State {
    h: [w64; 8],
}

impl State {
    fn new(key_size: u8, size: u8) -> Self {
        let mut state = INIT;

        state[0] ^= W(0x01010000 | ((key_size as u64) << 8) | (size as u64));

        State { h: state }
    }

    #[inline]
    fn compress(&mut self, input: &[u8], len: Length, last: bool) {
        debug_assert!(input.len() == 128);

        let mut message = [W(0); 16];
        for (word, chunk) in message.iter_mut().zip(input.chunks(8)) {
            *word = W(LittleEndian::read_u64(chunk));
        }

        let mut v = [W(0); 16];
        for (v, state) in v.iter_mut().zip(self.h.iter().chain(&INIT)) {
            *v = *state;
        }
        v[12].0 ^= len.0;
        v[13].0 ^= len.1;
        if last {
            v[14] = !v[14];
        }

        for sigma in &SIGMA {
            G!(v, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]]);
            G!(v, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]]);
            G!(v, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]]);
            G!(v, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]]);

            G!(v, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]]);
            G!(v, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]]);
            G!(v, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]]);
            G!(v, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]]);
        }

        let (head, tail) = v.split_at(8);
        let vs = head.iter().zip(tail).map(|(&a, &b)| a ^ b);

        for (h, v) in self.h.iter_mut().zip(vs) {
            *h ^= v;
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct Length(u64, u64);

impl Length {
    fn increment(&mut self, val: usize) {
        self.0.wrapping_add(val as u64);
        if self.0 < val as u64 {
            self.1 += 1;
        }
    }
}

/// BLAKE2b generic implementation
#[derive(Clone)]
pub struct Blake2b<Size: Unsigned + Clone> {
    state: State,
    len: Length,
    buffer: FixedBuffer128,
    _phantom: PhantomData<Size>,
}

impl<Size> Blake2b<Size>
    where Size: ArrayLength<u8> + Mul<U8> + Clone,
          <Size as Mul<U8>>::Output: ArrayLength<u8>
{
    /// Initialize BLAKE2 hash function with custom key
    pub fn with_key<K: AsRef<[u8]>>(key: K) -> Self {
        let key = key.as_ref();
        assert!(key.len() < 64);

        let mut ret = Blake2b {
            state: State::new(key.len() as u8, Size::to_u8()),
            len: Length(0, 0),
            buffer: FixedBuffer128::new(),
            _phantom: PhantomData,
        };

        if !key.is_empty() {
            ret.update(key);
            ret.buffer.zero_until(128);
        }

        ret
    }
}

impl<Size> Default for Blake2b<Size>
    where Size: ArrayLength<u8> + Mul<U8> + Clone,
          <Size as Mul<U8>>::Output: ArrayLength<u8>
{
    fn default() -> Self {
        Self::with_key(&[])
    }
}

impl<Size> Digest for Blake2b<Size>
    where Size: ArrayLength<u8> + Mul<U8> + Clone,
          <Size as Mul<U8>>::Output: ArrayLength<u8>
{
    type OutputBits = <Self::OutputBytes as Mul<U8>>::Output;
    type OutputBytes = Size;

    type BlockSize = U128;

    fn update<T: AsRef<[u8]>>(&mut self, input: T) {
        let input = input.as_ref();
        let state = &mut self.state;
        let len = &mut self.len;

        self.buffer.input(&input, |d| {
            len.increment(d.len());
            state.compress(d, *len, false);
        });
    }

    fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
        let rest = self.buffer.position();
        self.len.increment(rest);
        self.buffer.zero_until(128);

        self.state.compress(self.buffer.full_buffer(), self.len, true);

        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());

        unsafe {
            ptr::copy_nonoverlapping(self.state.h.as_ptr() as *const u8,
                                     out.as_mut_ptr(),
                                     Self::output_bytes())
        }
    }
}

/// BLAKE2b-160 implementation
pub type Blake2b160 = Blake2b<U20>;
/// BLAKE2b-256 implementation
pub type Blake2b256 = Blake2b<U32>;
/// BLAKE2b-384 implementation
pub type Blake2b384 = Blake2b<U48>;
/// BLAKE2b-512 implementation
pub type Blake2b512 = Blake2b<U64>;
