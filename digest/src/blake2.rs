use core::marker::PhantomData;
use core::{mem, ptr};
use core::num::Wrapping as W;
use core::ops::{Shl, BitXor, Mul};

use static_buffer::{FixedBuffer64, FixedBuffer128, FixedBuf};
use byteorder::{ByteOrder, LittleEndian};
use generic_array::ArrayLength;
use typenum::uint::Unsigned;
use typenum::consts::{U8, U16, U20, U28, U32, U48, U64, U128};

use Digest;

const BLAKE2S_INIT: [W<u32>; 8] = [W(0x6a09e667),
                                   W(0xbb67ae85),
                                   W(0x3c6ef372),
                                   W(0xa54ff53a),
                                   W(0x510e527f),
                                   W(0x9b05688c),
                                   W(0x1f83d9ab),
                                   W(0x5be0cd19)];
const BLAKE2B_INIT: [W<u64>; 8] = [W(0x6a09e667f3bcc908),
                                   W(0xbb67ae8584caa73b),
                                   W(0x3c6ef372fe94f82b),
                                   W(0xa54ff53a5f1d36f1),
                                   W(0x510e527fade682d1),
                                   W(0x9b05688c2b3e6c1f),
                                   W(0x1f83d9abfb41bd6b),
                                   W(0x5be0cd19137e2179)];

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
        $v[$a] = $v[$a] + $v[$b] + $x;
        $v[$d] = W(($v[$d] ^ $v[$a]).0.rotate_right(R1));
        $v[$c] = $v[$c] + $v[$d];
        $v[$b] = W(($v[$b] ^ $v[$c]).0.rotate_right(R2));
        $v[$a] = $v[$a] + $v[$b] + $y;
        $v[$d] = W(($v[$d] ^ $v[$a]).0.rotate_right(R3));
        $v[$c] = $v[$c] + $v[$d];
        $v[$b] = W(($v[$b] ^ $v[$c]).0.rotate_right(R4));
    }
}

#[derive(Copy, Clone, Debug)]
struct State<Word: Copy> {
    h: [W<Word>; 8],
}

impl<Word> State<Word>
    where Word: From<u8> + From<u32> + Copy + BitXor<Output = Word> + Shl<usize, Output = Word> + Default
{
    fn new(mut state: [W<Word>; 8], key_size: u8, size: u8) -> Self {
        state[0] = W(state[0].0 ^ 0x1010000u32.into() ^ ((key_size as u32) << 8).into() ^ size.into());

        State { h: state }
    }
}

macro_rules! blake2_state {
    ($word:ty, $read:ident, $init:ident, $rounds:expr, $r1:expr, $r2:expr, $r3:expr, $r4:expr) => {
        impl State<$word> {
            fn compress(&mut self, input: &[u8], len: Length<$word>, last: bool) {
                const R1: u32 = $r1;
                const R2: u32 = $r2;
                const R3: u32 = $r3;
                const R4: u32 = $r4;

                let word_bytes = mem::size_of::<$word>();

                let mut message = [W(0); 16];
                for (word, chunk) in message.iter_mut().zip(input.chunks(word_bytes)) {
                    *word = W(LittleEndian::$read(chunk));
                }

                let mut v = [W(0); 16];
                for (v, state) in v.iter_mut().take(8).zip(&self.h) {
                    *v = *state;
                }
                for (v, iv) in v.iter_mut().skip(8).zip(&$init) {
                    *v = *iv;
                }
                v[12].0 ^= len.0;
                v[13].0 ^= len.1;
                if last {
                    v[14] = !v[14];
                }

                for sigma in &SIGMA[..$rounds] {
                    G!(v, 0, 4, 8,  12, message[sigma[0]],  message[sigma[1]]);
                    G!(v, 1, 5, 9,  13, message[sigma[2]],  message[sigma[3]]);
                    G!(v, 2, 6, 10, 14, message[sigma[4]],  message[sigma[5]]);
                    G!(v, 3, 7, 11, 15, message[sigma[6]],  message[sigma[7]]);

                    G!(v, 0, 5, 10, 15, message[sigma[8]],  message[sigma[9]]);
                    G!(v, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]]);
                    G!(v, 2, 7, 8,  13, message[sigma[12]], message[sigma[13]]);
                    G!(v, 3, 4, 9,  14, message[sigma[14]], message[sigma[15]]);
                }

                for i in 0..8 {
                    self.h[i] = self.h[i] ^ v[i] ^ v[i + 8];
                }
            }
        }
    }
}

blake2_state!(u32, read_u32, BLAKE2S_INIT, 10, 16, 12, 8, 7);
blake2_state!(u64, read_u64, BLAKE2B_INIT, 12, 32, 24, 16, 63);

#[derive(Copy, Clone, Debug)]
struct Length<T>(T, T);


impl Length<u32> {
    fn increment(&mut self, val: usize) {
        self.0.wrapping_add( val as u32 );
    }
}

impl Length<u64> {
    fn increment(&mut self, val: usize) {
        self.0.wrapping_add(val as u64);
    }
}

macro_rules! blake2 {
    ($name:ident<$word:ty>, $init:ident, $buf:ty, $bsize:ty) => {
        #[derive(Clone)]
        pub struct $name<Size: Unsigned + Clone> {
            state: State<$word>,
            len: Length<$word>,
            buffer: $buf,
            _phantom: PhantomData<Size>,
        }

        impl<Size: Unsigned + Clone> $name<Size> {
            pub fn with_key<K: AsRef<[u8]>>(key: K) -> Self {
                let key = key.as_ref();

                let mut ret = $name {
                    state: State::new($init, key.len() as u8, Size::to_u8()),
                    len: Length(0, 0),
                    buffer: <$buf>::new(),
                    _phantom: PhantomData
                };

                if !key.is_empty() {
                    ret.buffer.input(key, |_| {});
                    ret.buffer.zero_until(<$buf>::size());

                    ret.len.increment(<$buf>::size());
                    ret.state.compress(ret.buffer.full_buffer(),
                                       ret.len,
                                       false);
                }

                ret
            }
        }

        impl<Size: Unsigned + Clone> Default for $name<Size> {
            fn default() -> Self {
                Self::with_key(&[])
            }
        }

        impl<Size> Digest for $name<Size>
            where Size: ArrayLength<u8> + Mul<U8> + Clone,
                  <Size as Mul<U8>>::Output: ArrayLength<u8>
        {
            type OutputBits = <Self::OutputBytes as Mul<U8>>::Output;
            type OutputBytes = Size;
            type BlockSize = $bsize;

            fn update<T: AsRef<[u8]>>(&mut self, input: T) {
                let input = input.as_ref();
                let state = &mut self.state;
                let len = &mut self.len;

                self.buffer.input(&input, |d| {
                    len.increment(d.len());
                    state.compress(d, *len, false);
                })
            }

            fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
                let rest = self.buffer.position();
                self.len.increment(rest);
                self.buffer.zero_until(<$buf>::size());

                self.state.compress(self.buffer.full_buffer(),
                                    self.len,
                                    true);

                let mut out = out.as_mut();
                assert!(out.len() >= Self::output_bytes());

                unsafe {
                    ptr::copy_nonoverlapping(self.state.h.as_ptr() as *const u8,
                                             out.as_mut_ptr(),
                                             Self::output_bytes())
                }
            }
        }
    }
}

blake2!(Blake2s<u32>, BLAKE2S_INIT, FixedBuffer64, U64);
blake2!(Blake2b<u64>, BLAKE2B_INIT, FixedBuffer128, U128);

pub type Blake2b160 = Blake2b<U20>;
pub type Blake2b256 = Blake2b<U32>;
pub type Blake2b384 = Blake2b<U48>;
pub type Blake2b512 = Blake2b<U64>;

pub type Blake2s128 = Blake2s<U16>;
pub type Blake2s160 = Blake2s<U20>;
pub type Blake2s224 = Blake2s<U28>;
pub type Blake2s256 = Blake2s<U32>;
