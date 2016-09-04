//! WHIRLPOOL
//!
//! # General info
//!
//! | Name        | Digest size | Block size | Rounds | Structure                                                              | Reference                |
//! | ----------- | ----------: | ---------: | -----: | ---------------------------------------------------------------------- | ------------------------ |
//! | WHIRLPOOL   |    192 bits |   512 bits |     10 | [Miyaguchi-Preneel][mp] hashing with [Merkle–Damgård][md] strengthning | [WHIRLPOOL website][web] |
//!
//! [web]: http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html "The WHIRLPOOL Hash Function"
//! [md]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction
//! [mp]: https://en.wikipedia.org/wiki/One-way_compression_function#Miyaguchi.E2.80.93Preneel

#![allow(eq_op)]

use static_buffer::{FixedBuffer64, FixedBuf, StandardPadding};
use byteorder::{ByteOrder, BigEndian};
use typenum::consts::{U64, U512};

use Digest;
use wrapping::*;

use self::sboxes::SBOXES;

mod sboxes;

const ROUNDS: usize = 10;

const RC: [w64; ROUNDS] = [W(0x1823c6e887b8014f),
                           W(0x36a6d2f5796f9152),
                           W(0x60bc9b8ea30c7b35),
                           W(0x1de0d7c22e4bfe57),
                           W(0x157737e59ff04ada),
                           W(0x58c9290ab1a06b85),
                           W(0xbd5d10f4cb3e0567),
                           W(0xe427418ba77d95d8),
                           W(0xfbee7c66dd17479e),
                           W(0xca2dbf07ad5a8333)];

#[inline]
fn op(src: &[w64], shift: usize) -> w64 {
    W(SBOXES[0][(src[(shift) % 8] >> 56).0 as u8 as usize] ^
      SBOXES[1][(src[(shift + 7) % 8] >> 48).0 as u8 as usize] ^
      SBOXES[2][(src[(shift + 6) % 8] >> 40).0 as u8 as usize] ^
      SBOXES[3][(src[(shift + 5) % 8] >> 32).0 as u8 as usize] ^
      SBOXES[4][(src[(shift + 4) % 8] >> 24).0 as u8 as usize] ^
      SBOXES[5][(src[(shift + 3) % 8] >> 16).0 as u8 as usize] ^
      SBOXES[6][(src[(shift + 2) % 8] >> 8).0 as u8 as usize] ^
      SBOXES[7][(src[(shift + 1) % 8]).0 as u8 as usize])
}

#[derive(Debug, Clone, Copy)]
struct State {
    hash: [w64; 8],
}

impl State {
    fn new() -> Self {
        State { hash: [W(0); 8] }
    }

    #[inline]
    fn compress(&mut self, data: &[u8]) {
        debug_assert!(data.len() == 64);
        let mut key = self.hash;
        let mut state = [W(0u64); 8];

        for ((word, chunk), state) in self.hash
            .iter_mut()
            .zip(data.chunks(8))
            .zip(&mut state) {
            *state = W(BigEndian::read_u64(chunk)) ^ *word;
            *word = *state;
        }

        for &rc in &RC {
            let tmp = key;

            key[0] = op(&tmp, 0) ^ rc;
            key[1] = op(&tmp, 1);
            key[2] = op(&tmp, 2);
            key[3] = op(&tmp, 3);
            key[4] = op(&tmp, 4);
            key[5] = op(&tmp, 5);
            key[6] = op(&tmp, 6);
            key[7] = op(&tmp, 7);

            let tmp = state;
            state[0] = op(&tmp, 0) ^ key[0];
            state[1] = op(&tmp, 1) ^ key[1];
            state[2] = op(&tmp, 2) ^ key[2];
            state[3] = op(&tmp, 3) ^ key[3];
            state[4] = op(&tmp, 4) ^ key[4];
            state[5] = op(&tmp, 5) ^ key[5];
            state[6] = op(&tmp, 6) ^ key[6];
            state[7] = op(&tmp, 7) ^ key[7];
        }

        for (hash, &state) in self.hash.iter_mut().zip(&state) {
            *hash ^= state
        }
    }
}

/// WHIRLPOOL implementation
///
/// For details check out [module documentation](index.html)
#[derive(Clone)]
pub struct Whirlpool {
    state: State,
    buffer: FixedBuffer64,
    length: u64,
}

impl Default for Whirlpool {
    fn default() -> Self {
        Whirlpool {
            state: State::new(),
            buffer: FixedBuffer64::new(),
            length: 0,
        }
    }
}

impl Digest for Whirlpool {
    type OutputBits = U512;
    type OutputBytes = U64;

    type BlockSize = U64;

    fn update<T>(&mut self, update: T)
        where T: AsRef<[u8]>
    {
        let update = update.as_ref();
        self.length += update.len() as u64;

        let state = &mut self.state;
        self.buffer.input(update, |d| state.compress(d));
    }

    fn result<T>(mut self, mut out: T)
        where T: AsMut<[u8]>
    {
        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());
        {
            let state = &mut self.state;

            self.buffer.standard_padding(8, |d| state.compress(d));
            BigEndian::write_u64(self.buffer.next(8), self.length * 8);
            state.compress(self.buffer.full_buffer());
        }

        for (&word, chunk) in self.state.hash.iter().zip(out.chunks_mut(8)) {
            BigEndian::write_u64(chunk, word.0);
        }
    }
}
