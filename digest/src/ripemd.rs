//! RIPEMD (RACE Integrity Primitives Evaluation Message Digest)
//!
//! # General info
//!
//! | Name       | Digest size | Block size | Rounds | Structure            | Reference             |
//! | ---------- | ----------: | ---------: | -----: | -------------------- | --------------------- |
//! | RIPEMD-160 |    160 bits |   512 bits |      4 | [Merkle–Damgård][md] | [RIPEMD website][web] |
//!
//! [web]: http://homes.esat.kuleuven.be/~bosselae/ripemd160.html "The RIPEMD-160 page"
//! [md]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

use byteorder::{ByteOrder, LittleEndian};
use typenum::consts::{U20, U64, U160};
use static_buffer::{FixedBuf, FixedBuffer64, StandardPadding};

use Digest;

#[derive(Copy, Clone, Debug)]
struct State {
    state: [u32; 5],
}

macro_rules! process {
    () => {};
    (proc $block:ident, $value:expr, $rot:expr, $c:expr, $func:block) => {{
        let tmp = $block[0]
            .wrapping_add($func)
            .wrapping_add($value)
            .wrapping_add($c)
            .rotate_left($rot)
            .wrapping_add($block[4]);
        $block[0] = $block[4];
        $block[4] = $block[3];
        $block[3] = $block[2].rotate_left(10);
        $block[2] = $block[1];
        $block[1] = tmp;
    }};
    (ff $block:ident, $value:expr, $rot:expr, $c:expr; $($rest:tt)*) => {
        process!(proc $block, $value, $rot, $c, { $block[1] ^ $block[2] ^ $block[3] });
        process!($($rest)*);
    };
    (gg $block:ident, $value:expr, $rot:expr, $c:expr; $($rest:tt)*) => {
        process!(proc $block, $value, $rot, $c, { ($block[1] & $block[2]) | (!$block[1] & $block[3]) });
        process!($($rest)*);
    };
    (hh $block:ident, $value:expr, $rot:expr, $c:expr; $($rest:tt)*) => {
        process!(proc $block, $value, $rot, $c, { ($block[1] | !$block[2]) ^ $block[3] });
        process!($($rest)*);
    };
    (ii $block:ident, $value:expr, $rot:expr, $c:expr; $($rest:tt)*) => {
        process!(proc $block, $value, $rot, $c, { ($block[1] & $block[3]) | ($block[2] & !$block[3]) });
        process!($($rest)*);
    };
    (jj $block:ident, $value:expr, $rot:expr, $c:expr; $($rest:tt)*) => {
        process!(proc $block, $value, $rot, $c, { $block[1] ^ ($block[2] | !$block[3]) });
        process!($($rest)*);
    };
    ($block:ident;
     $round:ident($c:expr, $($v:expr => $r:expr),*)) => {
        process! {
            $($round $block, $v, $r, $c;)*
        }
    };
}

impl State {
    fn new() -> Self {
        State { state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0] }
    }

    fn process_block(&mut self, block: &[u8]) {
        debug_assert!(block.len() == 64);

        let mut data = [0u32; 16];

        for (c, v) in block.chunks(4).zip(data.iter_mut()) {
            *v = LittleEndian::read_u32(c);
        }

        let mut left = self.state;
        let mut right = self.state;

        process!(left; ff(0x00000000,
                          data[0 ] => 11, data[1 ] => 14, data[2 ] => 15, data[3 ] => 12,
                          data[4 ] => 5 , data[5 ] => 8 , data[6 ] => 7 , data[7 ] => 9 ,
                          data[8 ] => 11, data[9 ] => 13, data[10] => 14, data[11] => 15,
                          data[12] => 6 , data[13] => 7 , data[14] => 9 , data[15] => 8));
        process!(left; gg(0x5a827999,
                          data[7 ] => 7 , data[4 ] => 6 , data[13] => 8 , data[1 ] => 13,
                          data[10] => 11, data[6 ] => 9 , data[15] => 7 , data[3 ] => 15,
                          data[12] => 7 , data[0 ] => 12, data[9 ] => 15, data[5 ] => 9 ,
                          data[2 ] => 11, data[14] => 7 , data[11] => 13, data[8 ] => 12));
        process!(left; hh(0x6ed9eba1,
                          data[3 ] => 11, data[10] => 13, data[14] => 6 , data[4 ] => 7 ,
                          data[9 ] => 14, data[15] => 9 , data[8 ] => 13, data[1 ] => 15,
                          data[2 ] => 14, data[7 ] => 8 , data[0 ] => 13, data[6 ] => 6 ,
                          data[13] => 5 , data[11] => 12, data[5 ] => 7 , data[12] => 5));
        process!(left; ii(0x8f1bbcdc,
                          data[1 ] => 11, data[9 ] => 12, data[11] => 14, data[10] => 15,
                          data[0 ] => 14, data[8 ] => 15, data[12] => 9 , data[4 ] => 8,
                          data[13] => 9 , data[3 ] => 14, data[7 ] => 5 , data[15] => 6,
                          data[14] => 8 , data[5 ] => 6 , data[6 ] => 5 , data[2 ] => 12));
        process!(left; jj(0xa953fd4e,
                          data[4 ] => 9 , data[0 ] => 15, data[5 ] => 5 , data[9 ] => 11,
                          data[7 ] => 6 , data[12] => 8 , data[2 ] => 13, data[10] => 12,
                          data[14] => 5 , data[1 ] => 12, data[3 ] => 13, data[8 ] => 14,
                          data[11] => 11, data[6 ] => 8 , data[15] => 5 , data[13] => 6));

        process!(right; jj(0x50a28be6,
                           data[5 ] => 8,  data[14] => 9 , data[7 ] => 9 , data[0 ] => 11,
                           data[9 ] => 13, data[2 ] => 15, data[11] => 15, data[4 ] => 5 ,
                           data[13] => 7 , data[6 ] => 7 , data[15] => 8,  data[8 ] => 11,
                           data[1 ] => 14, data[10] => 14, data[3 ] => 12, data[12] => 6));
        process!(right; ii(0x5c4dd124,
                           data[6 ] => 9 , data[11] => 13, data[3 ] => 15, data[7 ] => 7,
                           data[0 ] => 12, data[13] => 8 , data[5 ] => 9 , data[10] => 11,
                           data[14] => 7 , data[15] => 7 , data[8 ] => 12, data[12] => 7 ,
                           data[4 ] => 6 , data[9 ] => 15, data[1 ] => 13, data[2 ] => 11));
        process!(right; hh(0x6d703ef3,
                           data[15] => 9 , data[5 ] => 7 , data[1 ] => 15, data[3 ] => 11,
                           data[7 ] => 8 , data[14] => 6 , data[6 ] => 6 , data[9 ] => 14,
                           data[11] => 12, data[8 ] => 13, data[12] => 5 , data[2 ] => 14,
                           data[10] => 13, data[0 ] => 13, data[4 ] => 7 , data[13] => 5));
        process!(right; gg(0x7a6d76e9,
                           data[8 ] => 15, data[6 ] => 5 , data[4 ] => 8 , data[1 ] => 11,
                           data[3 ] => 14, data[11] => 14, data[15] => 6 , data[0 ] => 14,
                           data[5 ] => 6 , data[12] => 9 , data[2 ] => 12, data[13] => 9 ,
                           data[9 ] => 12, data[7 ] => 5 , data[10] => 15, data[14] => 8));
        process!(right; ff(0x00000000,
                           data[12] => 8 , data[15] => 5 , data[10] => 12, data[4 ] => 9 ,
                           data[1 ] => 12, data[5 ] => 5 , data[8 ] => 14, data[7 ] => 6 ,
                           data[6 ] => 8 , data[2 ] => 13, data[13] => 6 , data[14] => 5 ,
                           data[0 ] => 15, data[3 ] => 13, data[9 ] => 11, data[11] => 11));

        let tmp = self.state[1].wrapping_add(left[2]).wrapping_add(right[3]);
        self.state[1] = self.state[2].wrapping_add(left[3]).wrapping_add(right[4]);
        self.state[2] = self.state[3].wrapping_add(left[4]).wrapping_add(right[0]);
        self.state[3] = self.state[4].wrapping_add(left[0]).wrapping_add(right[1]);
        self.state[4] = self.state[0].wrapping_add(left[1]).wrapping_add(right[2]);
        self.state[0] = tmp;
    }
}

/// RIPEMD-160 implementation
///
/// For more details check [module docs](index.html)
#[derive(Clone)]
pub struct Ripemd160 {
    state: State,
    length: u64,
    buffer: FixedBuffer64,
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Ripemd160 {
            state: State::new(),
            length: 0,
            buffer: FixedBuffer64::new(),
        }
    }
}

impl Digest for Ripemd160 {
    type OutputBits = U160;
    type OutputBytes = U20;

    type BlockSize = U64;

    fn update<T>(&mut self, update: T)
        where T: AsRef<[u8]>
    {
        let update = update.as_ref();
        self.length += update.len() as u64;

        let state = &mut self.state;
        self.buffer.input(update, |d| state.process_block(d));
    }

    fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
        let state = &mut self.state;

        self.buffer.standard_padding(8, |d| state.process_block(d));
        LittleEndian::write_u64(self.buffer.next(8), self.length << 3);
        state.process_block(self.buffer.full_buffer());

        let mut out = out.as_mut();
        assert!(out.len() >= Self::output_bytes());
        for (c, &v) in out.chunks_mut(4).zip(&state.state) {
            LittleEndian::write_u32(c, v);
        }
    }
}
