use byteorder::{ByteOrder, BigEndian};
use typenum::consts::{U20, U64, U160};

use digest::Digest;
use utils::buffer::{FixedBuf, FixedBuffer64, StandardPadding};

#[derive(Copy, Clone, Debug)]
struct State {
    state: [u32; 5],
}

impl State {
    fn new() -> Self {
        State { state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0] }
    }

    #[allow(needless_range_loop)]
    fn process_block(&mut self, data: &[u8]) {
        assert_eq!(data.len(), 64);

        let mut words = [0u32; 80];

        fn ff(b: u32, c: u32, d: u32) -> u32 {
            d ^ (b & (c ^ d))
        }
        fn gg(b: u32, c: u32, d: u32) -> u32 {
            b ^ c ^ d
        }
        fn hh(b: u32, c: u32, d: u32) -> u32 {
            (b & c) | (d & (b | c))
        }
        fn ii(b: u32, c: u32, d: u32) -> u32 {
            b ^ c ^ d
        }

        for (c, w) in data.chunks(4).zip(words.iter_mut()) {
            *w = BigEndian::read_u32(c);
        }
        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }

        let mut state = self.state.clone();

        for (i, &word) in words.iter().enumerate() {
            let (f, k) = match i {
                0...19 => (ff(state[1], state[2], state[3]), 0x5a827999),
                20...39 => (gg(state[1], state[2], state[3]), 0x6ed9eba1),
                40...59 => (hh(state[1], state[2], state[3]), 0x8f1bbcdc),
                60...79 => (ii(state[1], state[2], state[3]), 0xca62c1d6),
                _ => unreachable!(),
            };

            let tmp = state[0]
                          .rotate_left(5)
                          .wrapping_add(f)
                          .wrapping_add(state[4])
                          .wrapping_add(k)
                          .wrapping_add(word);
            state[4] = state[3];
            state[3] = state[2];
            state[2] = state[1].rotate_left(30);
            state[1] = state[0];
            state[0] = tmp;
        }

        for (i, byte) in self.state.iter_mut().enumerate() {
            *byte = byte.wrapping_add(state[i]);
        }
    }
}

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
        for (&val, c) in state.state.iter().zip(out.chunks_mut(4)) {
            BigEndian::write_u32(c, val)
        }
    }
}
