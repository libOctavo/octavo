use byteorder::{
    ReadBytesExt,
    WriteBytesExt,
    LittleEndian
};

const ROUNDS: usize = 20;
const STATE_WORDS: usize = 16;
const STATE_BYTES: usize = STATE_WORDS * 4;

#[derive(Copy, Clone)]
struct State([u32; STATE_WORDS]);

macro_rules! quarter_round {
    ($a: expr, $b: expr, $c: expr, $d: expr) => {{
        $a = $a.wrapping_add($b); $d = $d ^ $a; $d = $d.rotate_left(16);
        $c = $c.wrapping_add($d); $b = $b ^ $c; $b = $b.rotate_left(12);
        $a = $a.wrapping_add($b); $d = $d ^ $a; $d = $d.rotate_left( 8);
        $c = $c.wrapping_add($d); $b = $b ^ $c; $b = $b.rotate_left( 7);
    }}
}

macro_rules! double_round {
    ($x: expr) => {{
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
            output[i] = output[i].wrapping_add(state[i]);
        }

        self.0[12] = self.0[12] + 1;
    }
}

pub struct ChaCha20 {
    state: State,
    buffer: [u8; STATE_WORDS * 4],
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
}

#[cfg(test)]
mod test {
    use super::ChaCha20;

    struct Test<'a> {
        key: [u8; 32],
        nonce: [u8; 12],
        position: u32,
        plaintext: &'a [u8],
        ciphertext: &'a [u8]
    }

    const TESTS: [Test<'static>; 1] = [
        Test {
            key: [0; 32],
            nonce: [0; 12],
            position: 0,
            plaintext: &[0; 64],
            ciphertext: &[
                0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
                0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
                0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
                0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
            ]
        }
    ];

    #[test]
    fn test_chacha20() {
        let test = &TESTS[0];
        let _ = ChaCha20::init(&test.key[..], &test.nonce[..], test.position);
    }
}
