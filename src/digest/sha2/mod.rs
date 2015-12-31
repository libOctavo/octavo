use std::ops::Div;

use byteorder::{ByteOrder, BigEndian};
use typenum::consts::{U8, U64, U128, U224, U256, U384, U512};

use digest::Digest;
use utils::buffer::{FixedBuf, FixedBuffer64, FixedBuffer128, StandardPadding};

const SHA224_INIT: [u32; 8] = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31,
                               0x68581511, 0x64f98fa7, 0xbefa4fa4];
const SHA256_INIT: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
                               0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

const SHA384_INIT: [u64; 8] = [0xcbbb9d5dc1059ed8,
                               0x629a292a367cd507,
                               0x9159015a3070dd17,
                               0x152fecd8f70e5939,
                               0x67332667ffc00b31,
                               0x8eb44a8768581511,
                               0xdb0c2e0d64f98fa7,
                               0x47b5481dbefa4fa4];
const SHA512_INIT: [u64; 8] = [0x6a09e667f3bcc908,
                               0xbb67ae8584caa73b,
                               0x3c6ef372fe94f82b,
                               0xa54ff53a5f1d36f1,
                               0x510e527fade682d1,
                               0x9b05688c2b3e6c1f,
                               0x1f83d9abfb41bd6b,
                               0x5be0cd19137e2179];
const SHA512_224_INIT: [u64; 8] = [0x8c3d37c819544da2,
                                   0x73e1996689dcd4d6,
                                   0x1dfab7ae32ff9c82,
                                   0x679dd514582f9fcf,
                                   0x0f6d2b697bd44da8,
                                   0x77e36f7304c48942,
                                   0x3f9d85a86a1d36c8,
                                   0x1112e6ad91d692a1];
const SHA512_256_INIT: [u64; 8] = [0x22312194fc2bf72c,
                                   0x9f555fa3c84c64c2,
                                   0x2393b86b6f53b151,
                                   0x963877195940eabd,
                                   0x96283ee2a88effe3,
                                   0xbe5e1e2553863992,
                                   0x2b0199fc2c85b8aa,
                                   0x0eb72ddc81c52ca2];

mod sha256;
mod sha512;

#[derive(Copy, Clone, Debug)]
struct State<T: Copy> {
    state: [T; 8],
}

impl State<u32> {
    fn process_block(&mut self, data: &[u8]) {
        assert_eq!(data.len(), 64);

        sha256::compress(&mut self.state, data);
    }
}

impl State<u64> {
    fn process_block(&mut self, data: &[u8]) {
        assert_eq!(data.len(), 128);

        sha512::compress(&mut self.state, data);
    }
}

macro_rules! impl_sha(
    ($name:ident, $buffer:ty, $init:ident, $state:ty, $bsize:ty, $bits:ty) => {
        #[derive(Clone)]
        pub struct $name {
            state: State<$state>,
            buffer: $buffer,
            length: u64
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    state: State { state: $init },
                    buffer: <$buffer>::new(),
                    length: 0
                }
            }
        }

        impl Digest for $name {
            type OutputBits = $bits;
            type OutputBytes = <$bits as Div<U8>>::Output;

            type BlockSize = $bsize;

            fn update<T: AsRef<[u8]>>(&mut self, data: T) {
                let data = data.as_ref();
                self.length += data.len() as u64;

                let state = &mut self.state;
                self.buffer.input(data, |d| state.process_block(d));
            }

            fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
                let mut out = out.as_mut();
                assert!(out.len() >= Self::output_bytes());

                let state = &mut self.state;

                self.buffer.standard_padding(8, |d| state.process_block(d));
                BigEndian::write_u64(self.buffer.next(8), self.length << 3);
                state.process_block(self.buffer.full_buffer());

                for i in &mut state.state {
                    *i = i.to_be();
                }

                unsafe {
                    use std::ptr;
                    ptr::copy_nonoverlapping(
                        state.state.as_ptr() as *const u8,
                        out.as_mut_ptr(),
                        Self::output_bytes())
                };
            }
        }
    };
(low $name:ident, $init:ident, $bits:ty) => {
    impl_sha!($name, FixedBuffer64, $init, u32, U64, $bits);
};
(high $name:ident, $init:ident, $bits:ty) => {
    impl_sha!($name, FixedBuffer128, $init, u64, U128, $bits);
};
);

impl_sha!(low  Sha224, SHA224_INIT, U224);
impl_sha!(low  Sha256, SHA256_INIT, U256);
impl_sha!(high Sha384, SHA384_INIT, U384);
impl_sha!(high Sha512, SHA512_INIT, U512);

impl_sha!(high Sha512224, SHA512_224_INIT, U224);
impl_sha!(high Sha512256, SHA512_256_INIT, U256);
