use std::num::Wrapping as W;

use digest;
use utils::buffer::{FixedBuffer64, FixedBuf, StandardPadding};

use byteorder::{ByteOrder, BigEndian};
use typenum::consts::{U24, U64, U192};

// sboxes.c: Tiger S boxeszz
const SBOXES: [[u64; 256]; 4] = include!("tiger.sboxes");
const ROUNDS: usize = 3;

#[derive(Debug, Clone, Copy)]
struct State {
    a: W<u64>,
    b: W<u64>,
    c: W<u64>,
}

macro_rules! round {
    ($a:expr, $b:expr, $c:expr, $x:expr, $mul:expr) => {
        $c = $c ^ $x;
        $a = $a - W(
            SBOXES[0][($c.0 >> (0*8)) as usize & 0xff] ^
            SBOXES[1][($c.0 >> (2*8)) as usize & 0xff] ^
            SBOXES[2][($c.0 >> (4*8)) as usize & 0xff] ^
            SBOXES[3][($c.0 >> (6*8)) as usize & 0xff]);
        $b = $b + W(
            SBOXES[3][($c.0 >> (1*8)) as usize & 0xff] ^
            SBOXES[2][($c.0 >> (3*8)) as usize & 0xff] ^
            SBOXES[1][($c.0 >> (5*8)) as usize & 0xff] ^
            SBOXES[0][($c.0 >> (7*8)) as usize & 0xff]);
        $b = $b * W($mul);
    };
}

impl State {
    fn new() -> Self {
        State {
            a: W(0x0123456789abcdef),
            b: W(0xfedcba9876543210),
            c: W(0xf096a5b4c3b2e187),
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

    fn compress(&mut self, block: &[u8]) {
        assert_eq!(block.len(), 64);
        let mut wblock = [W(0); 8];

        for (v, c) in wblock.iter_mut().zip(block.chunks(8)) {
            *v = W(BigEndian::read_u64(c));
        }

        let tmp = *self; // save abc
        for i in 0..ROUNDS {
            if i != 0 {
                Self::key_schedule(&mut wblock);
            }
            let mul = match i {
                0 => 5,
                1 => 7,
                _ => 9,
            };
            self.pass(&mut wblock, mul);
            self.rotate();
        }

        // feedforward
        self.a = self.a ^ tmp.a;
        self.b = self.b - tmp.b;
        self.c = self.c + tmp.c;
    }
}

macro_rules! tiger_impl {
    ($name:ident, $padding:expr) => {
        #[derive(Clone)]
        pub struct $name {
            state: State,
            buffer: FixedBuffer64,
            length: u64,
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    state: State::new(),
                    buffer: FixedBuffer64::new(),
                    length: 0,
                }
            }
        }

        impl digest::Digest for $name {
            type OutputBits = U192;
            type OutputBytes = U24;

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
                    let state = &mut self.state;

                    self.buffer.pad($padding, 8, |d| state.compress(d));
                    BigEndian::write_u64(self.buffer.next(8), self.length << 3);
                    state.compress(self.buffer.full_buffer());

                    let mut out = out.as_mut();
                    assert!(out.len() >= Self::output_bytes());
                    BigEndian::write_u64(&mut out[0..8], state.a.0);
                    BigEndian::write_u64(&mut out[8..16], state.b.0);
                    BigEndian::write_u64(&mut out[16..24], state.c.0);
                }
        }
    };
}

tiger_impl!(Tiger,  0x01);
tiger_impl!(Tiger2, 0x80);
