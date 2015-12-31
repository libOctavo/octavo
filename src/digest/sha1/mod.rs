use byteorder::{ByteOrder, BigEndian};
use typenum::consts::{U20, U64, U160};

use digest::Digest;
use utils::buffer::{FixedBuf, FixedBuffer64, StandardPadding};

#[cfg(feature = "asm-sha1")]
mod asm;
#[cfg(feature = "asm-sha1")]
use self::asm::compress;

#[cfg(not(feature = "asm-sha1"))]
mod native;
#[cfg(not(feature = "asm-sha1"))]
use self::native::compress;

#[derive(Copy, Clone, Debug)]
struct State {
    state: [u32; 5],
}

impl State {
    fn new() -> Self {
        State { state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0] }
    }

    fn process_block(&mut self, data: &[u8]) {
        assert_eq!(data.len(), 64);

        compress(&mut self.state, data)
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

    fn output_bits() -> usize {
        160
    }
    fn block_size() -> usize {
        64
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
