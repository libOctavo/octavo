use std::mem;

use super::{StreamEncrypt, StreamDecrypt};

use byteorder::{
    ReadBytesExt,
    LittleEndian
};

const ROUNDS: usize = 20;
const STATE_WORDS: usize = 16;
const STATE_BYTES: usize = STATE_WORDS * 4;

#[derive(Copy, Clone)]
struct State([u32; STATE_WORDS]);

macro_rules! quarter_round {
    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
        $a = $a.wrapping_add($b); $d = $d ^ $a; $d = $d.rotate_left(16);
        $c = $c.wrapping_add($d); $b = $b ^ $c; $b = $b.rotate_left(12);
        $a = $a.wrapping_add($b); $d = $d ^ $a; $d = $d.rotate_left( 8);
        $c = $c.wrapping_add($d); $b = $b ^ $c; $b = $b.rotate_left( 7);
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
    fn expand(mut key: &[u8], mut nonce: &[u8], position: u32) -> Self {
        let mut state = [0; STATE_WORDS];

        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for state in &mut state[4..12] {
            *state = key.read_u32::<LittleEndian>().unwrap();
        }

        state[12] = position;

        for state in &mut state[13..16] {
            *state = nonce.read_u32::<LittleEndian>().unwrap();
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

        self.0[12] = self.0[12] + 1;
    }
}

pub struct ChaCha20 {
    state: State,
    buffer: [u8; STATE_BYTES],
    index: usize
}

impl ChaCha20 {
    pub fn init(key: &[u8], nonce: &[u8], position: u32) -> Self {
        ChaCha20 {
            state: State::expand(key.as_ref(), nonce.as_ref(), position),
            buffer: [0; STATE_BYTES],
            index: STATE_BYTES
        }
    }

    pub fn new<Key, Nonce>(key: Key, nonce: Nonce) -> Self
        where Key: AsRef<[u8]>, Nonce: AsRef<[u8]> {
            Self::init(key.as_ref(), nonce.as_ref(), 1)
        }

    fn update(&mut self) {
        let mut arr: &mut [u32] = unsafe { mem::transmute(&mut self.buffer[..]) };

        self.state.update(arr);

        self.index = 0;
    }

    fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        assert_eq!(input.len(), output.len());

        if self.index == STATE_BYTES { self.update() }

        for i in self.index..input.len() {
            output[i] = input[i] ^ self.buffer[i];
        }

        self.index = input.len();
    }
}

impl StreamEncrypt for ChaCha20 {
    fn encrypt_stream<I, O>(&mut self, input: I, mut output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]> {
                  let input = input.as_ref().chunks(STATE_BYTES);
                  let output = output.as_mut().chunks_mut(STATE_BYTES);
                  for (i, o) in input.zip(output) {
                      self.crypt(i, o)
                  }
              }
}

impl StreamDecrypt for ChaCha20 {
    fn decrypt_stream<I, O>(&mut self, input: I, mut output: O)
        where I: AsRef<[u8]>,
              O: AsMut<[u8]> {
                  let input = input.as_ref().chunks(STATE_BYTES);
                  let output = output.as_mut().chunks_mut(STATE_BYTES);
                  for (i, o) in input.zip(output) {
                      self.crypt(i, o)
                  }
              }
}

#[cfg(test)]
mod test {
    use super::ChaCha20;
    use crypto::stream::{StreamEncrypt, StreamDecrypt};

    struct Test<'a> {
        key: [u8; 32],
        nonce: [u8; 12],
        position: u32,
        plaintext: &'a [u8],
        ciphertext: &'a [u8]
    }

    const TESTS: [Test<'static>; 2] = [
        Test {
            key: [
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            nonce: [
                0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
            position: 0,
            plaintext: &[0; 64],
            ciphertext: &[
                0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
                0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
                0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
                0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
            ]
        },
        Test {
            key: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
            ],
            nonce: [
                0, 0, 0, 0, 0, 0,
                0, 0x4a, 0, 0, 0, 0,
            ],
            position: 1,
            plaintext: b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
            ciphertext: &[
                0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
                0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
                0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
                0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
                0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
                0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
                0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
                0x87, 0x4d,
            ]
        }
    ];

    #[test]
    fn encryption() {
        for test in &TESTS {
            let mut cipher = ChaCha20::init(&test.key[..], &test.nonce[..], test.position);
            let mut buf = vec![0; 64];

            cipher.encrypt_stream(test.plaintext, &mut buf[..]);
            assert_eq!(test.ciphertext, &buf[..]);
        }
    }

    #[test]
    fn decryption() {
        for test in &TESTS {
            let mut cipher = ChaCha20::init(&test.key[..], &test.nonce[..], test.position);
            let mut buf = vec![0; 64];

            cipher.decrypt_stream(test.ciphertext, &mut buf[..]);
            assert_eq!(test.plaintext, &buf[..]);
        }
    }
}
