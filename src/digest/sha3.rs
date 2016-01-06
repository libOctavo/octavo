//! SHA-3 family (Secure Hash Algorithm)
//!
//! # General info
//!
//! | Name     | Digest size | Block size | Rounds | Structure        | Reference           |
//! | -------- | ----------: | ---------: | -----: | ---------------- | ------------------- |
//! | SHA3-224 |    224 bits |  1152 bits |     24 | [Sponge][sponge] | [FIPS 202][fips202] |
//! | SHA3-256 |    256 bits |  1088 bits |     24 | [Sponge][sponge] | [FIPS 202][fips202] |
//! | SHA3-384 |    384 bits |   832 bits |     24 | [Sponge][sponge] | [FIPS 202][fips202] |
//! | SHA3-512 |    512 bits |   576 bits |     24 | [Sponge][sponge] | [FIPS 202][fips202] |
//!
//! [fips202]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
//! [sponge]: https://en.wikipedia.org/wiki/Sponge_function "Sponge function"

use std::ops::Div;

use byteorder::{ByteOrder, LittleEndian};
use typenum::consts::{U8, U72, U104, U136, U144, U224, U256, U384, U512};
use typenum::uint::Unsigned;

use digest;
use utils::buffer::{FixedBuf, FixedBuffer, StandardPadding};

#[derive(Copy)]
struct State {
    hash: [u64; 25],
    rest: usize,
    block_size: usize,
}

impl Clone for State {
    fn clone(&self) -> Self {
        State {
            hash: self.hash,
            rest: self.rest,
            block_size: self.block_size,
        }
    }
}

const ROUND_CONSTS: [u64; 24] = [0x0000000000000001,
                                 0x0000000000008082,
                                 0x800000000000808a,
                                 0x8000000080008000,
                                 0x000000000000808b,
                                 0x0000000080000001,
                                 0x8000000080008081,
                                 0x8000000000008009,
                                 0x000000000000008a,
                                 0x0000000000000088,
                                 0x0000000080008009,
                                 0x000000008000000a,
                                 0x000000008000808b,
                                 0x800000000000008b,
                                 0x8000000000008089,
                                 0x8000000000008003,
                                 0x8000000000008002,
                                 0x8000000000000080,
                                 0x000000000000800a,
                                 0x800000008000000a,
                                 0x8000000080008081,
                                 0x8000000000008080,
                                 0x0000000080000001,
                                 0x8000000080008008];

impl State {
    fn init(bits: usize) -> Self {
        let rate = 1600 - bits * 2;
        assert!(rate <= 1600 && (rate % 64) == 0);
        State {
            hash: [0; 25],
            rest: 0,
            block_size: rate / 8,
        }
    }

    fn permutation(&mut self) {
        let mut a: [u64; 25] = self.hash;
        let mut c: [u64; 5] = [a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20],
                               a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21],
                               a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22],
                               a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23],
                               a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]];
        for i in 0..12 {
            self.round(i * 2, &mut a, &mut c);
            self.round(i * 2 + 1, &mut a, &mut c);
        }
        self.hash = a;
    }

    #[inline(always)]
    fn round(&self, i: usize, a: &mut [u64; 25], c: &mut [u64; 5]) {
        let d0 = c[4] ^ c[1].rotate_left(1);
        let d1 = c[0] ^ c[2].rotate_left(1);
        let d2 = c[1] ^ c[3].rotate_left(1);
        let d3 = c[2] ^ c[4].rotate_left(1);
        let d4 = c[3] ^ c[0].rotate_left(1);

        let b0 = a[0] ^ d0;
        let b10 = (a[1] ^ d1).rotate_left(1);
        let b20 = (a[2] ^ d2).rotate_left(62);
        let b5 = (a[3] ^ d3).rotate_left(28);
        let b15 = (a[4] ^ d4).rotate_left(27);
        let b16 = (a[5] ^ d0).rotate_left(36);
        let b1 = (a[6] ^ d1).rotate_left(44);
        let b11 = (a[7] ^ d2).rotate_left(6);
        let b21 = (a[8] ^ d3).rotate_left(55);
        let b6 = (a[9] ^ d4).rotate_left(20);
        let b7 = (a[10] ^ d0).rotate_left(3);
        let b17 = (a[11] ^ d1).rotate_left(10);
        let b2 = (a[12] ^ d2).rotate_left(43);
        let b12 = (a[13] ^ d3).rotate_left(25);
        let b22 = (a[14] ^ d4).rotate_left(39);
        let b23 = (a[15] ^ d0).rotate_left(41);
        let b8 = (a[16] ^ d1).rotate_left(45);
        let b18 = (a[17] ^ d2).rotate_left(15);
        let b3 = (a[18] ^ d3).rotate_left(21);
        let b13 = (a[19] ^ d4).rotate_left(8);
        let b14 = (a[20] ^ d0).rotate_left(18);
        let b24 = (a[21] ^ d1).rotate_left(2);
        let b9 = (a[22] ^ d2).rotate_left(61);
        let b19 = (a[23] ^ d3).rotate_left(56);
        let b4 = (a[24] ^ d4).rotate_left(14);

        a[0] = (b0 ^ ((!b1) & b2)) ^ ROUND_CONSTS[i];
        c[0] = a[0];
        a[1] = b1 ^ ((!b2) & b3);
        c[1] = a[1];
        a[2] = b2 ^ ((!b3) & b4);
        c[2] = a[2];
        a[3] = b3 ^ ((!b4) & b0);
        c[3] = a[3];
        a[4] = b4 ^ ((!b0) & b1);
        c[4] = a[4];

        a[5] = b5 ^ ((!b6) & b7);
        c[0] ^= a[5];
        a[6] = b6 ^ ((!b7) & b8);
        c[1] ^= a[6];
        a[7] = b7 ^ ((!b8) & b9);
        c[2] ^= a[7];
        a[8] = b8 ^ ((!b9) & b5);
        c[3] ^= a[8];
        a[9] = b9 ^ ((!b5) & b6);
        c[4] ^= a[9];

        a[10] = b10 ^ ((!b11) & b12);
        c[0] ^= a[10];
        a[11] = b11 ^ ((!b12) & b13);
        c[1] ^= a[11];
        a[12] = b12 ^ ((!b13) & b14);
        c[2] ^= a[12];
        a[13] = b13 ^ ((!b14) & b10);
        c[3] ^= a[13];
        a[14] = b14 ^ ((!b10) & b11);
        c[4] ^= a[14];

        a[15] = b15 ^ ((!b16) & b17);
        c[0] ^= a[15];
        a[16] = b16 ^ ((!b17) & b18);
        c[1] ^= a[16];
        a[17] = b17 ^ ((!b18) & b19);
        c[2] ^= a[17];
        a[18] = b18 ^ ((!b19) & b15);
        c[3] ^= a[18];
        a[19] = b19 ^ ((!b15) & b16);
        c[4] ^= a[19];

        a[20] = b20 ^ ((!b21) & b22);
        c[0] ^= a[20];
        a[21] = b21 ^ ((!b22) & b23);
        c[1] ^= a[21];
        a[22] = b22 ^ ((!b23) & b24);
        c[2] ^= a[22];
        a[23] = b23 ^ ((!b24) & b20);
        c[3] ^= a[23];
        a[24] = b24 ^ ((!b20) & b21);
        c[4] ^= a[24];
    }

    fn process(&mut self, data: &[u8]) {
        let max = self.block_size / 8;
        for (h, c) in self.hash[0..max].iter_mut().zip(data.chunks(8)) {
            *h ^= LittleEndian::read_u64(c)
        }

        self.permutation();
    }
}

macro_rules! sha3_impl {
    ($(#[$attr:meta])* struct $name:ident -> $size:ty, $bsize:ty) => {
        #[derive(Clone)]
        pub struct $name {
            state: State,
            buffer: FixedBuffer<$bsize>,
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    state: State::init(<$size as Unsigned>::to_usize()),
                    buffer: FixedBuffer::new(),
                }
            }
        }

        impl digest::Digest for $name {
            type OutputBits = $size;
            type OutputBytes = <$size as Div<U8>>::Output;

            type BlockSize = $bsize;

            fn update<T>(&mut self, data: T) where T: AsRef<[u8]> {
                let state = &mut self.state;
                self.buffer.input(data.as_ref(), |d| state.process(d));
            }

            fn result<T>(mut self, mut out: T) where T: AsMut<[u8]> {
                let mut ret = out.as_mut();
                assert!(ret.len() >= Self::output_bytes());
                let state = &mut self.state;

                self.buffer.pad(0b00000110, 0, |d| state.process(d));
                let buf = self.buffer.full_buffer();
                let last = buf.len() - 1;
                buf[last] |= 0b10000000;
                state.process(buf);

                unsafe {
                    use std::ptr;
                    ptr::copy_nonoverlapping(
                        state.hash.as_ptr() as *const u8,
                        ret.as_mut_ptr(),
                        Self::output_bytes())
                };
            }
        }
    }
}

sha3_impl!(
    /// SHA3-224 implementation
    ///
    /// For more details check [module docs](index.html)
    struct Sha224 -> U224, U144);
sha3_impl!(
    /// SHA3-256 implementation
    ///
    /// For more details check [module docs](index.html)
    struct Sha256 -> U256, U136);
sha3_impl!(
    /// SHA3-384 implementation
    ///
    /// For more details check [module docs](index.html)
    struct Sha384 -> U384, U104);
sha3_impl!(
    /// SHA3-512 implementation
    ///
    /// For more details check [module docs](index.html)
    struct Sha512 -> U512, U72);
