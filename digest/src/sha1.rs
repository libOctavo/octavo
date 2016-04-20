//! SHA-1 (Secure Hash Algorithm)
//!
//! # WARNING!!!
//!
//! This hash function has been severely compromised. **Do not use!**
//!
//! Instead you should use SHA-2 or SHA-3 family.
//!
//! # General info
//!
//! | Name  | Digest size | Block size | Rounds | Structure            | Reference               |
//! | ----- | ----------: | ---------: | -----: | -------------------- | ----------------------- |
//! | SHA-1 |    160 bits |   512 bits |     80 | [Merkle–Damgård][md] | [FIPS 180-4][fips180-4] |
//!
//! [fips180-4]: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf "FIPS 180-4 Secure Hash Standard (SHS)"
//! [md]: https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction

use byteorder::{ByteOrder, BigEndian};
use typenum::consts::{U20, U64, U160};
use static_buffer::{FixedBuf, FixedBuffer64, StandardPadding};

use Digest;

#[derive(Copy, Clone, Debug)]
struct State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
}

macro_rules! schedule {
    ($schedule:ident[$i:expr] = $data:ident) => {
        unsafe {
            *$schedule.get_unchecked_mut($i) =
                  (*$data.get_unchecked($i * 4 + 0) as u32) << 24
                | (*$data.get_unchecked($i * 4 + 1) as u32) << 16
                | (*$data.get_unchecked($i * 4 + 2) as u32) << 8
                | (*$data.get_unchecked($i * 4 + 3) as u32);
        }
    };

    ($schedule:ident[$i:expr]) => {
        unsafe {
            *$schedule.get_unchecked_mut($i & 0xf) = {
                  *$schedule.get_unchecked(($i -  3) & 0xf)
                ^ *$schedule.get_unchecked(($i -  8) & 0xf)
                ^ *$schedule.get_unchecked(($i - 14) & 0xf)
                ^ *$schedule.get_unchecked(($i - 16) & 0xf)
            }.rotate_left(1);
        }
    }
}

macro_rules! process {
    () => ();
    (($a:expr, $b:expr, $c:expr, $d:expr, $e:expr), $f:block, $constant:expr, $schedule:ident, $i:expr) => {{
        $e = $a
             .rotate_left(5)
             .wrapping_add($f)
             .wrapping_add($e)
             .wrapping_add($constant)
             .wrapping_add(unsafe { *$schedule.get_unchecked($i & 0xf) });
        $b = $b.rotate_left(30);
    }};

    (ff(($a:expr, $b:expr, $c:expr, $d:expr, $e:expr), $schedule:ident[$i:expr] , $data:ident); $($rest:tt)*) => {
        schedule!($schedule[$i] = $data);
        process!(($a, $b, $c, $d, $e), {
            ($b & $c) | (!$b & $d)
        }, 0x5a827999, $schedule, $i);
        process!($($rest)*);
    };
    (ff(($a:expr, $b:expr, $c:expr, $d:expr, $e:expr), $schedule:ident[$i:expr]); $($rest:tt)*) => {
        schedule!($schedule[$i]);
        process!(($a, $b, $c, $d, $e), {
            ($b & $c) | (!$b & $d)
        }, 0x5a827999, $schedule, $i);
        process!($($rest)*);
    };
    (gg(($a:expr, $b:expr, $c:expr, $d:expr, $e:expr), $schedule:ident[$i:expr]); $($rest:tt)*) => {
        schedule!($schedule[$i]);
        process!(($a, $b, $c, $d, $e), {
            $b ^ $c ^ $d
        }, 0x6ed9eba1, $schedule, $i);
        process!($($rest)*);
    };
    (hh(($a:expr, $b:expr, $c:expr, $d:expr, $e:expr), $schedule:ident[$i:expr]); $($rest:tt)*) => {
        schedule!($schedule[$i]);
        process!(($a, $b, $c, $d, $e), {
            ($b & $c) ^ ($b & $d) ^ ($c & $d)
        }, 0x8f1bbcdc, $schedule, $i);
        process!($($rest)*);
    };
    (ii(($a:expr, $b:expr, $c:expr, $d:expr, $e:expr), $schedule:ident[$i:expr]); $($rest:tt)*) => {
        schedule!($schedule[$i]);
        process!(($a, $b, $c, $d, $e), {
            $b ^ $c ^ $d
        }, 0xca62c1d6, $schedule, $i);
        process!($($rest)*);
    };
}

impl State {
    fn new() -> Self {
        State {
            a: 0x67452301,
            b: 0xefcdab89,
            c: 0x98badcfe,
            d: 0x10325476,
            e: 0xc3d2e1f0,
        }
    }

    fn process_block(&mut self, data: &[u8]) {
        debug_assert!(data.len() == 64);

        let mut words = [0u32; 16];
        let mut state = self.clone();

        process! {
            ff((state.a, state.b, state.c, state.d, state.e), words[0],  data);
            ff((state.e, state.a, state.b, state.c, state.d), words[1],  data);
            ff((state.d, state.e, state.a, state.b, state.c), words[2],  data);
            ff((state.c, state.d, state.e, state.a, state.b), words[3],  data);
            ff((state.b, state.c, state.d, state.e, state.a), words[4],  data);
            ff((state.a, state.b, state.c, state.d, state.e), words[5],  data);
            ff((state.e, state.a, state.b, state.c, state.d), words[6],  data);
            ff((state.d, state.e, state.a, state.b, state.c), words[7],  data);
            ff((state.c, state.d, state.e, state.a, state.b), words[8],  data);
            ff((state.b, state.c, state.d, state.e, state.a), words[9],  data);
            ff((state.a, state.b, state.c, state.d, state.e), words[10], data);
            ff((state.e, state.a, state.b, state.c, state.d), words[11], data);
            ff((state.d, state.e, state.a, state.b, state.c), words[12], data);
            ff((state.c, state.d, state.e, state.a, state.b), words[13], data);
            ff((state.b, state.c, state.d, state.e, state.a), words[14], data);
            ff((state.a, state.b, state.c, state.d, state.e), words[15], data);
            ff((state.e, state.a, state.b, state.c, state.d), words[16]);
            ff((state.d, state.e, state.a, state.b, state.c), words[17]);
            ff((state.c, state.d, state.e, state.a, state.b), words[18]);
            ff((state.b, state.c, state.d, state.e, state.a), words[19]);
        }
        process! {
            gg((state.a, state.b, state.c, state.d, state.e), words[20]);
            gg((state.e, state.a, state.b, state.c, state.d), words[21]);
            gg((state.d, state.e, state.a, state.b, state.c), words[22]);
            gg((state.c, state.d, state.e, state.a, state.b), words[23]);
            gg((state.b, state.c, state.d, state.e, state.a), words[24]);
            gg((state.a, state.b, state.c, state.d, state.e), words[25]);
            gg((state.e, state.a, state.b, state.c, state.d), words[26]);
            gg((state.d, state.e, state.a, state.b, state.c), words[27]);
            gg((state.c, state.d, state.e, state.a, state.b), words[28]);
            gg((state.b, state.c, state.d, state.e, state.a), words[29]);
            gg((state.a, state.b, state.c, state.d, state.e), words[30]);
            gg((state.e, state.a, state.b, state.c, state.d), words[31]);
            gg((state.d, state.e, state.a, state.b, state.c), words[32]);
            gg((state.c, state.d, state.e, state.a, state.b), words[33]);
            gg((state.b, state.c, state.d, state.e, state.a), words[34]);
            gg((state.a, state.b, state.c, state.d, state.e), words[35]);
            gg((state.e, state.a, state.b, state.c, state.d), words[36]);
            gg((state.d, state.e, state.a, state.b, state.c), words[37]);
            gg((state.c, state.d, state.e, state.a, state.b), words[38]);
            gg((state.b, state.c, state.d, state.e, state.a), words[39]);
        }
        process! {
            hh((state.a, state.b, state.c, state.d, state.e), words[40]);
            hh((state.e, state.a, state.b, state.c, state.d), words[41]);
            hh((state.d, state.e, state.a, state.b, state.c), words[42]);
            hh((state.c, state.d, state.e, state.a, state.b), words[43]);
            hh((state.b, state.c, state.d, state.e, state.a), words[44]);
            hh((state.a, state.b, state.c, state.d, state.e), words[45]);
            hh((state.e, state.a, state.b, state.c, state.d), words[46]);
            hh((state.d, state.e, state.a, state.b, state.c), words[47]);
            hh((state.c, state.d, state.e, state.a, state.b), words[48]);
            hh((state.b, state.c, state.d, state.e, state.a), words[49]);
            hh((state.a, state.b, state.c, state.d, state.e), words[50]);
            hh((state.e, state.a, state.b, state.c, state.d), words[51]);
            hh((state.d, state.e, state.a, state.b, state.c), words[52]);
            hh((state.c, state.d, state.e, state.a, state.b), words[53]);
            hh((state.b, state.c, state.d, state.e, state.a), words[54]);
            hh((state.a, state.b, state.c, state.d, state.e), words[55]);
            hh((state.e, state.a, state.b, state.c, state.d), words[56]);
            hh((state.d, state.e, state.a, state.b, state.c), words[57]);
            hh((state.c, state.d, state.e, state.a, state.b), words[58]);
            hh((state.b, state.c, state.d, state.e, state.a), words[59]);
        }
        process! {
            ii((state.a, state.b, state.c, state.d, state.e), words[60]);
            ii((state.e, state.a, state.b, state.c, state.d), words[61]);
            ii((state.d, state.e, state.a, state.b, state.c), words[62]);
            ii((state.c, state.d, state.e, state.a, state.b), words[63]);
            ii((state.b, state.c, state.d, state.e, state.a), words[64]);
            ii((state.a, state.b, state.c, state.d, state.e), words[65]);
            ii((state.e, state.a, state.b, state.c, state.d), words[66]);
            ii((state.d, state.e, state.a, state.b, state.c), words[67]);
            ii((state.c, state.d, state.e, state.a, state.b), words[68]);
            ii((state.b, state.c, state.d, state.e, state.a), words[69]);
            ii((state.a, state.b, state.c, state.d, state.e), words[70]);
            ii((state.e, state.a, state.b, state.c, state.d), words[71]);
            ii((state.d, state.e, state.a, state.b, state.c), words[72]);
            ii((state.c, state.d, state.e, state.a, state.b), words[73]);
            ii((state.b, state.c, state.d, state.e, state.a), words[74]);
            ii((state.a, state.b, state.c, state.d, state.e), words[75]);
            ii((state.e, state.a, state.b, state.c, state.d), words[76]);
            ii((state.d, state.e, state.a, state.b, state.c), words[77]);
            ii((state.c, state.d, state.e, state.a, state.b), words[78]);
            ii((state.b, state.c, state.d, state.e, state.a), words[79]);
        }

        self.a = self.a.wrapping_add(state.a);
        self.b = self.b.wrapping_add(state.b);
        self.c = self.c.wrapping_add(state.c);
        self.d = self.d.wrapping_add(state.d);
        self.e = self.e.wrapping_add(state.e);
    }
}

/// SHA-1 implementation
///
/// For more details check [module docs](index.html)
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
        BigEndian::write_u32(&mut out[0..4], state.a);
        BigEndian::write_u32(&mut out[4..8], state.b);
        BigEndian::write_u32(&mut out[8..12], state.c);
        BigEndian::write_u32(&mut out[12..16], state.d);
        BigEndian::write_u32(&mut out[16..20], state.e);
    }
}
