//! WHIRLPOOL
//!
//! # General info
//!
//! | Name        | Digest size | Block size | Rounds | Structure            | Reference            |
//! | ----------- | ----------: | ---------: | -----: | -------------------- | -------------------- |
//! | WHIRLPOOL   |    192 bits |   512 bits |     10 | [Merkle–Damgård][md] | [Tiger website][web] |
//!
//! [md]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

use core::num::Wrapping as W;

use static_buffer::{FixedBuffer64, FixedBuf, StandardPadding};
use byteorder::{ByteOrder, BigEndian};
use typenum::consts::{U64, U512};

use Digest;

use self::sboxes::SBOXES;

mod sboxes;

const ROUNDS: usize = 10;

const RC: [u64; ROUNDS] = [
    0x1823c6e887b8014f,
    0x36a6d2f5796f9152,
    0x60bc9b8ea30c7b35,
    0x1de0d7c22e4bfe57,
    0x157737e59ff04ada,
    0x58c9290ab1a06b85,
    0xbd5d10f4cb3e0567,
    0xe427418ba77d95d8,
    0xfbee7c66dd17479e,
    0xca2dbf07ad5a8333,
];

macro_rules! op {
    ($src:expr, $shift:expr) => {
        W(
            SBOXES[0][($src[($shift + 0) & 7].0) as usize >> 56] ^
            SBOXES[1][($src[($shift + 7) & 7].0) as usize >> 48] ^
            SBOXES[2][($src[($shift + 6) & 7].0) as usize >> 40] ^
            SBOXES[3][($src[($shift + 5) & 7].0) as usize >> 32] ^
            SBOXES[4][($src[($shift + 4) & 7].0) as usize >> 24] ^
            SBOXES[5][($src[($shift + 3) & 7].0) as usize >> 16] ^
            SBOXES[6][($src[($shift + 2) & 7].0) as usize >>  8] ^
            SBOXES[7][($src[($shift + 1) & 7].0) as usize >>  0]
         )
    };
}

#[derive(Debug, Clone, Copy)]
struct State {
    hash: [W<u64>; 8],
}

impl State {
    fn new() -> Self {
        State { hash: [W(0); 8] }
    }

    #[inline(always)]
    fn op(src: &[W<u64>; 8], shift: usize) -> W<u64> {
        W(
            SBOXES[0][(src[(shift + 0) & 7] >> 56).0 as u8 as usize] ^
            SBOXES[1][(src[(shift + 7) & 7] >> 48).0 as u8 as usize] ^
            SBOXES[2][(src[(shift + 6) & 7] >> 40).0 as u8 as usize] ^
            SBOXES[3][(src[(shift + 5) & 7] >> 32).0 as u8 as usize] ^
            SBOXES[4][(src[(shift + 4) & 7] >> 24).0 as u8 as usize] ^
            SBOXES[5][(src[(shift + 3) & 7] >> 16).0 as u8 as usize] ^
            SBOXES[6][(src[(shift + 2) & 7] >>  8).0 as u8 as usize] ^
            SBOXES[7][(src[(shift + 1) & 7] >>  0).0 as u8 as usize]
         )
    }

    fn process_block(&mut self, data: &[u8]) {
        let mut key = [[W(0u64); 8]; 2];
        let mut state = [[W(0u64); 8]; 2];

        for (i, (word, chunk)) in self.hash.iter_mut().zip(data.chunks(8)).enumerate() {
            key[0][i] = *word;
            state[0][i] = W(BigEndian::read_u64(chunk)) ^ *word;
            *word = state[0][i];
        }

        for (&m, &rc) in [0usize, 1].iter().cycle().zip(&RC) {
            key[m ^ 1][0] = Self::op(&key[m], 0) ^ W(rc);
            key[m ^ 1][1] = Self::op(&key[m], 1);
            key[m ^ 1][2] = Self::op(&key[m], 2);
            key[m ^ 1][3] = Self::op(&key[m], 3);
            key[m ^ 1][4] = Self::op(&key[m], 4);
            key[m ^ 1][5] = Self::op(&key[m], 5);
            key[m ^ 1][6] = Self::op(&key[m], 6);
            key[m ^ 1][7] = Self::op(&key[m], 7);

            state[m ^ 1][0] = Self::op(&state[m], 0) ^ key[m ^ 1][0];
            state[m ^ 1][1] = Self::op(&state[m], 1) ^ key[m ^ 1][1];
            state[m ^ 1][2] = Self::op(&state[m], 2) ^ key[m ^ 1][2];
            state[m ^ 1][3] = Self::op(&state[m], 3) ^ key[m ^ 1][3];
            state[m ^ 1][4] = Self::op(&state[m], 4) ^ key[m ^ 1][4];
            state[m ^ 1][5] = Self::op(&state[m], 5) ^ key[m ^ 1][5];
            state[m ^ 1][6] = Self::op(&state[m], 6) ^ key[m ^ 1][6];
            state[m ^ 1][7] = Self::op(&state[m], 7) ^ key[m ^ 1][7];
        }

        for (hash, &state) in self.hash.iter_mut().zip(&state[0]) {
            *hash = *hash ^ state
        }
    }
}

/// Some
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
            self.buffer.input(update, |d| state.process_block(d));
        }

    fn result<T>(mut self, mut out: T)
        where T: AsMut<[u8]>
        {
            {
                let state = &mut self.state;

                self.buffer.standard_padding(32, |d| state.process_block(d));
                self.buffer.zero_until(56);
                BigEndian::write_u64(self.buffer.next(8), self.length << 3);
                state.process_block(self.buffer.full_buffer());
            }

            let mut out = out.as_mut();
            assert!(out.len() >= Self::output_bytes());
            for (&word, chunk) in self.state.hash.iter().zip(out.chunks_mut(8)) {
                BigEndian::write_u64(chunk, word.0);
            }
        }
}
