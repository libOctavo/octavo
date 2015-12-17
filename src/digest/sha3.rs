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

const SHIFTS: [u32; 25] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21,
                           8, 18, 2, 61, 56, 14];

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

    #[allow(needless_range_loop)]
    fn theta(&mut self) {
        let mut a = [0u64; 5];
        let mut b = [0u64; 5];

        for i in 0..5 {
            a[i] = self.hash[i] ^ self.hash[i + 5] ^ self.hash[i + 10] ^ self.hash[i + 15] ^
                   self.hash[i + 20];
        }

        for i in 0..5 {
            b[i] = a[(i + 1) % 5].rotate_left(1) ^ a[(i + 4) % 5];
        }

        for i in 0..5 {
            self.hash[i] ^= b[i];
            self.hash[i + 5] ^= b[i];
            self.hash[i + 10] ^= b[i];
            self.hash[i + 15] ^= b[i];
            self.hash[i + 20] ^= b[i];
        }
    }

    fn rho(&mut self) {
        for (i, shift) in SHIFTS.iter().enumerate() {
            self.hash[i] = self.hash[i].rotate_left(*shift);
        }
    }

    fn pi(&mut self) {
        let tmp = self.hash[1];
        self.hash[1] = self.hash[6];
        self.hash[6] = self.hash[9];
        self.hash[9] = self.hash[22];
        self.hash[22] = self.hash[14];
        self.hash[14] = self.hash[20];
        self.hash[20] = self.hash[2];
        self.hash[2] = self.hash[12];
        self.hash[12] = self.hash[13];
        self.hash[13] = self.hash[19];
        self.hash[19] = self.hash[23];
        self.hash[23] = self.hash[15];
        self.hash[15] = self.hash[4];
        self.hash[4] = self.hash[24];
        self.hash[24] = self.hash[21];
        self.hash[21] = self.hash[8];
        self.hash[8] = self.hash[16];
        self.hash[16] = self.hash[5];
        self.hash[5] = self.hash[3];
        self.hash[3] = self.hash[18];
        self.hash[18] = self.hash[17];
        self.hash[17] = self.hash[11];
        self.hash[11] = self.hash[7];
        self.hash[7] = self.hash[10];
        self.hash[10] = tmp;
        // NOTE: self.hash[0] is left untouched
    }

    fn chi(&mut self) {
        for i in 0..5 {
            let i = i * 5;
            let tmp_0 = self.hash[i];
            let tmp_1 = self.hash[i + 1];

            self.hash[i] ^= !tmp_1 & self.hash[i + 2];
            self.hash[i + 1] ^= !self.hash[i + 2] & self.hash[i + 3];
            self.hash[i + 2] ^= !self.hash[i + 3] & self.hash[i + 4];
            self.hash[i + 3] ^= !self.hash[i + 4] & tmp_0;
            self.hash[i + 4] ^= !tmp_0 & tmp_1;
        }
    }

    fn permutation(&mut self) {
        for round in &ROUND_CONSTS {
            self.theta();
            self.rho();
            self.pi();
            self.chi();

            // iota
            self.hash[0] ^= *round;
        }
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
    ($name:ident -> $size:ty, $bsize:ty) => {
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

sha3_impl!(Sha224 -> U224, U144);
sha3_impl!(Sha256 -> U256, U136);
sha3_impl!(Sha384 -> U384, U104);
sha3_impl!(Sha512 -> U512, U72);
