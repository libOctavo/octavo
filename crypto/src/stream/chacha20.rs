use std::slice;

use super::{StreamEncrypt, StreamDecrypt};

use byteorder::{ByteOrder, LittleEndian};

const ROUNDS: usize = 20;
const STATE_WORDS: usize = 16;
const STATE_BYTES: usize = STATE_WORDS * 4;

#[derive(Copy, Clone)]
struct State([u32; STATE_WORDS]);

macro_rules! quarter_round {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
        $a = $a.wrapping_add($b); $d ^= $a; $d = $d.rotate_left(16);
        $c = $c.wrapping_add($d); $b ^= $c; $b = $b.rotate_left(12);
        $a = $a.wrapping_add($b); $d ^= $a; $d = $d.rotate_left( 8);
        $c = $c.wrapping_add($d); $b ^= $c; $b = $b.rotate_left( 7);
    }}
}

macro_rules! double_round {
    ($x:expr) => {{
        // Column round
        quarter_round!($x[ 0], $x[ 4], $x[ 8], $x[12]);
        quarter_round!($x[ 1], $x[ 5], $x[ 9], $x[13]);
        quarter_round!($x[ 2], $x[ 6], $x[10], $x[14]);
        quarter_round!($x[ 3], $x[ 7], $x[11], $x[15]);
        // Diagonal round
        quarter_round!($x[ 0], $x[ 5], $x[10], $x[15]);
        quarter_round!($x[ 1], $x[ 6], $x[11], $x[12]);
        quarter_round!($x[ 2], $x[ 7], $x[ 8], $x[13]);
        quarter_round!($x[ 3], $x[ 4], $x[ 9], $x[14]);
    }}
}

impl State {
    fn expand(key: &[u8], nonce: &[u8], position: u32) -> Self {
        let mut state = [0u32; STATE_WORDS];

        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for (state, chunk) in state[4..12].iter_mut().zip(key.chunks(4)) {
            *state = LittleEndian::read_u32(chunk);
        }

        state[12] = position;

        for (state, chunk) in state[13..16].iter_mut().zip(nonce.chunks(4)) {
            *state = LittleEndian::read_u32(chunk);
        }

        State(state)
    }

    fn update(&mut self, output: &mut [u32]) {
        let mut state = self.0;

        for _ in 0..ROUNDS / 2 {
            double_round!(state);
        }

        for i in 0..STATE_WORDS {
            output[i] = self.0[i].wrapping_add(state[i]);
        }

        self.0[12] += 1;
    }
}

pub struct ChaCha20 {
    state: State,
    buffer: [u32; STATE_WORDS],
    index: usize,
}

impl ChaCha20 {
    pub fn init(key: &[u8], nonce: &[u8], position: u32) -> Self {
        ChaCha20 {
            state: State::expand(key.as_ref(), nonce.as_ref(), position),
            buffer: [0; STATE_WORDS],
            index: STATE_BYTES,
        }
    }

    pub fn new<Key, Nonce>(key: Key, nonce: Nonce) -> Self
        where Key: AsRef<[u8]>,
              Nonce: AsRef<[u8]>
    {
        Self::init(key.as_ref(), nonce.as_ref(), 1)
    }

    fn update(&mut self) {
        self.state.update(&mut self.buffer[..]);

        self.index = 0;
    }

    fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        if self.index == STATE_BYTES {
            self.update()
        }

        let buffer = unsafe {
            slice::from_raw_parts(self.buffer.as_ptr() as *const u8, STATE_BYTES)
        };

        for i in self.index..input.len() {
            output[i] = input[i] ^ buffer[i];
        }

        self.index = input.len();
    }
}

impl StreamEncrypt for ChaCha20 {
    fn encrypt_stream<I, O>(&mut self, input: I, mut output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]>
    {
        assert_eq!(input.as_ref().len(), output.as_mut().len());
        let input = input.as_ref();
        let output = output.as_mut();

        let from = STATE_BYTES - self.index;

        if from > 0 {
            self.crypt(&input[..from], &mut output[..from]);
        }

        for (i, o) in input[from..]
                          .chunks(STATE_BYTES)
                          .zip(output[from..].chunks_mut(STATE_BYTES)) {
            self.crypt(i, o)
        }
    }
}

impl StreamDecrypt for ChaCha20 {
    fn decrypt_stream<I, O>(&mut self, input: I, mut output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]>
    {
        assert_eq!(input.as_ref().len(), output.as_mut().len());

        let input = input.as_ref().chunks(STATE_BYTES);
        let output = output.as_mut().chunks_mut(STATE_BYTES);
        for (i, o) in input.zip(output) {
            self.crypt(i, o)
        }
    }
}
