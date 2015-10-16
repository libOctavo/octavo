use std::num::Wrapping as W;

use digest;
use utils::buffer::{
    FixedBuffer64,
    FixedBuffer,
    StandardPadding
};

use byteorder::{
    ReadBytesExt,
    WriteBytesExt,
    LittleEndian,
    BigEndian
};

/* sboxes.c: Tiger S boxeszz */
const SBOXES: [[u64; 256]; 4] = include!("tiger.sboxes");
const ROUNDS: usize = 3;

#[derive(Debug, Clone)]
struct State {
    a: W<u64>,
    b: W<u64>,
    c: W<u64>,
}

macro_rules! round {
    ($a:expr, $b:expr, $c:expr, $x:expr, $mul:expr) => {
        $c = $c ^ $x;
        $a = $a - W(
            SBOXES[0][($c >> (0*8)).0 as usize & 0xff] ^
            SBOXES[1][($c >> (2*8)).0 as usize & 0xff] ^
            SBOXES[2][($c >> (4*8)).0 as usize & 0xff] ^
            SBOXES[3][($c >> (6*8)).0 as usize & 0xff]);
        $b = $b + W(
            SBOXES[3][($c >> (1*8)).0 as usize & 0xff] ^
            SBOXES[2][($c >> (3*8)).0 as usize & 0xff] ^
            SBOXES[1][($c >> (5*8)).0 as usize & 0xff] ^
            SBOXES[0][($c >> (7*8)).0 as usize & 0xff]);
        $b = $b * W($mul);
    };
}

impl State {
    fn new() -> Self {
        State {
            a: W(0x0123456789abcdef),
            b: W(0xfedcab9876543210),
            c: W(0xf098a5b4c3b2e187),
        }
    }

    fn pass(&mut self, block: &[W<u64>], mul: u64) {
        round!(self.a, self.b, self.c, block[0], mul);
        round!(self.b, self.c, self.a, block[1], mul);
        round!(self.c, self.a, self.b, block[2], mul);
        round!(self.a, self.b, self.c, block[3], mul);
        round!(self.b, self.c, self.a, block[4], mul);
        round!(self.c, self.a, self.b, block[5], mul);
        round!(self.a, self.b, self.c, block[6], mul);
        round!(self.b, self.c, self.a, block[7], mul);
    }

    fn key_schedule(x: &mut [W<u64>]) {
        x[0] = x[0] - (x[7] ^ W(0xa5a5a5a5a5a5a5a5));
        x[1] = x[1] ^ x[0];
        x[2] = x[2] + x[1];
        x[3] = x[3] - (x[2] ^ (!x[1] << 19));
        x[4] = x[4] ^ x[3];
        x[5] = x[5] + x[4];
        x[6] = x[6] - (x[5] ^ (!x[4] >> 23));
        x[7] = x[7] ^ x[6];

        x[0] = x[0] + x[7];
        x[1] = x[1] - (x[0] ^ (!x[7] << 19));
        x[2] = x[2] ^ x[1];
        x[3] = x[3] + x[2];
        x[4] = x[4] - (x[3] ^ (!x[2] >> 23));
        x[5] = x[5] ^ x[4];
        x[6] = x[6] + x[5];
        x[7] = x[7] - (x[6] ^ W(0x0123456789abcdef));
    }

    fn rotate(&mut self) {
        let tmp = self.a;
        self.a = self.c;
        self.c = self.b;
        self.b = tmp;
    }

    fn compress(&mut self, mut block: &[u8]) {
        assert_eq!(block.len(), 64);
        let mut wblock = [W(0); 8];

        for i in 0..8 {
            wblock[i] = W(block.read_u64::<LittleEndian>().unwrap());
        }

        let tmp = self.clone(); // save abc
        for i in 0..ROUNDS {
            if i != 0 { Self::key_schedule(&mut wblock); }
            let mul = match i {
                0 => 5,
                1 => 7,
                _ => 9
            };
            self.pass(&mut wblock, mul);
            self.rotate();
        }

        self.a = self.a ^ tmp.a;
        self.b = self.b - tmp.b;
        self.c = self.c + tmp.c;
    }
}

pub struct Tiger {
    state: State,
    buffer: FixedBuffer64,
    length: u64
}

impl Default for Tiger {
    fn default() -> Self {
        Tiger {
            state: State::new(),
            buffer: FixedBuffer64::new(),
            length: 0
        }
    }
}

impl digest::Digest for Tiger {
    fn update<T>(&mut self, update: T) where T: AsRef<[u8]> {
        let update = update.as_ref();
        self.length += update.len() as u64;

        let state = &mut self.state;
        self.buffer.input(update, |d| state.compress(d));
    }

    fn output_bits() -> usize { 192 }
    fn block_size() -> usize { 64 }

    fn result<T>(mut self, mut out: T) where T: AsMut<[u8]> {
        let state = &mut self.state;

        self.buffer.pad(1, 8, |d| state.compress(d));
        self.buffer.next(8).write_u64::<LittleEndian>(self.length).unwrap();
        state.compress(self.buffer.full_buffer());

        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());
        out.write_u64::<LittleEndian>(state.a.0).unwrap();
        out.write_u64::<LittleEndian>(state.b.0).unwrap();
        out.write_u64::<LittleEndian>(state.c.0).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use digest::test::Test;
    use super::Tiger;

    const TESTS: &'static [Test<'static>] = &[
        Test { input: b"", output: &[0x60, 0xef, 0x6c, 0x0d, 0xbc, 0x07, 0x7b, 0x9c, 0x17, 0x5f, 0xfb, 0x77, 0x71, 0x00, 0x8c, 0x25, 0x3b, 0xac, 0xea, 0x02, 0x4c, 0x9d, 0x01, 0xab] },
        // Test { input: b"a", output: &[ 0xbd, 0xe5, 0x2c, 0xb3, 0x1d, 0xe3, 0x3e, 0x46, 0x24, 0x5e, 0x05, 0xfb, 0xdb, 0xd6, 0xfb, 0x24 ] },
        // Test { input: b"abc", output: &[ 0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d ] },
        // Test { input: b"message digest", output: &[ 0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7, 0x01, 0x4b ] },
        // Test { input: b"abcdefghijklmnopqrstuvwxyz", output: &[ 0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5, 0xbb, 0xcd, 0xee, 0xa8, 0xed, 0x63, 0xdf, 0x41, 0x2d, 0xa9 ] },
        // Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: &[ 0x04, 0x3f, 0x85, 0x82, 0xf2, 0x41, 0xdb, 0x35, 0x1c, 0xe6, 0x27, 0xe1, 0x53, 0xe7, 0xf0, 0xe4 ] },
        // Test { input: b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: &[ 0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x19, 0x9c, 0x3e, 0x7b, 0x16, 0x4f, 0xcc, 0x05, 0x36 ] },
    ];

    #[test]
    fn example_implementation_vectors() {
        // Test that it works when accepting the message all at once
        for test in TESTS {
            test.test(Tiger::default());
        }
    }
}
