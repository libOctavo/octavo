use std::num::Wrapping as W;

use digest;
use utils::buffer::{FixedBuffer64, FixedBuffer, StandardPadding};

use byteorder::{ByteOrder, BigEndian};

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
            fn update<T>(&mut self, update: T)
                where T: AsRef<[u8]>
                {
                    let update = update.as_ref();
                    self.length += update.len() as u64;

                    let state = &mut self.state;
                    self.buffer.input(update, |d| state.compress(d));
                }

            fn output_bits() -> usize {
                192
            }
            fn block_size() -> usize {
                64
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

#[cfg(test)]
mod tests {
    use digest::test::Test;
    use super::Tiger;

    const TESTS: &'static [Test<'static>] = &[
        Test { input: b"", output: &[0x60, 0xef, 0x6c, 0x0d, 0xbc, 0x07, 0x7b, 0x9c, 0x17, 0x5f, 0xfb, 0x77, 0x71, 0x00, 0x8c, 0x25, 0x3b, 0xac, 0xea, 0x02, 0x4c, 0x9d, 0x01, 0xab] },
        Test { input: b"abc", output: &[0xc7, 0x9e, 0x79, 0x9e, 0x14, 0xb5, 0x3e, 0x7d, 0xf9, 0x35, 0xd8, 0x34, 0x77, 0xfa, 0x4d, 0xf9, 0x39, 0xd1, 0x8c, 0x44, 0xf7, 0x6b, 0x73, 0xcd] },
        Test { input: b"Tiger", output: &[0xa2, 0x4e, 0xe9, 0x54, 0x0c, 0x41, 0xd7, 0x1b, 0x6a, 0x62, 0x6f, 0x9d, 0xdf, 0x41, 0xd1, 0x2e, 0x30, 0x31, 0x27, 0x2b, 0x6a, 0xab, 0xbd, 0x9a] },
        Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-", output: &[0xaf, 0x58, 0xf9, 0xc0, 0x5b, 0x88, 0x60, 0x48, 0xc1, 0x6f, 0x48, 0xbc, 0x90, 0x4b, 0xef, 0xfd, 0xa8, 0x38, 0xf0, 0x05, 0xff, 0x74, 0x03, 0x5e] },
        Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789", output: &[0x76, 0xaa, 0x09, 0x2e, 0x58, 0x9b, 0x0f, 0x0b, 0x8b, 0x78, 0x09, 0x44, 0xad, 0x1f, 0x0c, 0x41, 0xc9, 0xa5, 0xce, 0xb3, 0x07, 0xd2, 0xfd, 0xe0] },
        Test { input: b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham", output: &[0x82, 0x81, 0x5d, 0x89, 0x24, 0xe2, 0xf1, 0x1a, 0x88, 0xc0, 0xf2, 0x92, 0x91, 0x4c, 0x6c, 0xfd, 0xbf, 0xd8, 0xe7, 0x8e, 0x2c, 0xf2, 0x9a, 0xd0] },
        Test { input: b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.", output: &[0x48, 0x1f, 0x6d, 0xd0, 0xdf, 0x57, 0xe1, 0x03, 0xd7, 0xde, 0x0b, 0x66, 0x3a, 0xdb, 0x05, 0xf5, 0x03, 0xb8, 0x77, 0xf2, 0x76, 0xad, 0xb2, 0x86] },
        Test { input: b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.", output: &[0x69, 0x6d, 0x99, 0x60, 0x61, 0x88, 0x47, 0x25, 0x9f, 0x2f, 0xa5, 0x80, 0xdb, 0x2f, 0x95, 0x55, 0x96, 0xd7, 0xbe, 0xa2, 0x04, 0x6f, 0x46, 0xd7] },
        Test { input: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-", output: &[0x27, 0x20, 0xa3, 0x8d, 0x7f, 0x08, 0x75, 0x54, 0x5f, 0xd9, 0x61, 0x4f, 0x48, 0xf7, 0xe6, 0x7a, 0x92, 0xd3, 0x74, 0x69, 0xda, 0x2e, 0xf3, 0x78] },
    ];

    #[test]
    fn example_implementation_vectors() {
        for test in TESTS {
            test.test(Tiger::default());
        }
    }

    #[test]
    fn hash_of_64k_bytes_string() {
        use digest::Digest;

        let mut hash = Tiger::default();

        for i in 0..65536 {
            hash.update(&[(i & 0xff) as u8]);
        }
        let mut result = [0; 24];
        hash.result(&mut result[..]);

        assert_eq!(&result[..],
                   &[0xcd, 0x7e, 0xb9, 0x64, 0x5f, 0xb4, 0x05, 0xc6, 0x48, 0x5d, 0xd1, 0xaa, 0x14,
                   0x59, 0x6a, 0x63, 0xe5, 0x70, 0x4c, 0xc2, 0xff, 0x28, 0xf2, 0x4a])
    }
}
