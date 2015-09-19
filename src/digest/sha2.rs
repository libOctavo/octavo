use byteorder::{
    WriteBytesExt,
    ReadBytesExt,
    BigEndian
};

use digest::Digest;
use utils::buffer::{
    FixedBuffer,
    FixedBuffer64,
    FixedBuffer128,
    StandardPadding
};

const SHA224_INIT: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
];
const SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];
const U32_ROUNDS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

const SHA384_INIT: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
];
const SHA512_INIT: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];
const U64_ROUNDS: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

struct SHAState<T> {
    state: [T; 8]
}

impl SHAState<u32> {
    #[allow(needless_range_loop)]
    fn process_block(&mut self, mut data: &[u8]) {
        assert_eq!(data.len(), 64);

        let mut words = [0u32; 64];

        for i in 0..16 {
            words[i] = data.read_u32::<BigEndian>().unwrap();
        }
        for i in 16..64 {
            let s0 = words[i - 15].rotate_right(7)
                ^ words[i - 15].rotate_right(18)
                ^ (words[i - 15] >> 3);
            let s1 = words[i - 2].rotate_right(17)
                ^ words[i - 2].rotate_right(19)
                ^ (words[i - 2] >> 10);
            words[i] = words[i - 16]
                .wrapping_add(s0)
                .wrapping_add(words[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for (&word, &round) in words.iter().zip(U32_ROUNDS.iter()) {
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let tmp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(word).wrapping_add(round);
            let tmp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(tmp1);
            d = c;
            c = b;
            b = a;
            a = tmp1.wrapping_add(tmp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl SHAState<u64> {
    #[allow(needless_range_loop)]
    fn process_block(&mut self, mut data: &[u8]) {
        assert_eq!(data.len(), 128);

        let mut words = [0u64; 80];

        for i in 0..16 {
            words[i] = data.read_u64::<BigEndian>().unwrap();
        }

        for i in 16..80 {
            let s0 = words[i - 15].rotate_right(1)
                ^ words[i - 15].rotate_right(8)
                ^ (words[i - 15] >> 7);
            let s1 = words[i - 2].rotate_right(19)
                ^ words[i - 2].rotate_right(61)
                ^ (words[i - 2] >> 6);
            words[i] = words[i - 16]
                .wrapping_add(s0)
                .wrapping_add(words[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for (&word, &round) in words.iter().zip(U64_ROUNDS.iter()) {
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let tmp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(word).wrapping_add(round);
            let tmp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(tmp1);
            d = c;
            c = b;
            b = a;
            a = tmp1.wrapping_add(tmp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

macro_rules! impl_sha(
    (low $name:ident, $init:ident, $bits:expr) => {
        pub struct $name {
            state: SHAState<u32>,
            buffer: FixedBuffer64,
            length: u64
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    state: SHAState { state: $init },
                    buffer: FixedBuffer64::new(),
                    length: 0
                }
            }
        }

        impl Digest for $name {
            fn update<T: AsRef<[u8]>>(&mut self, data: T) {
                let data = data.as_ref();
                self.length += data.len() as u64;

                let state = &mut self.state;
                self.buffer.input(data, |d| state.process_block(d));
            }

            fn output_bits() -> usize { $bits }
            fn block_size() -> usize { 64 }

            fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
                let state = &mut self.state;

                self.buffer.standard_padding(8, |d| state.process_block(d));
                self.buffer.next(8).write_u64::<BigEndian>(self.length * 8).unwrap();
                state.process_block(self.buffer.full_buffer());

                let mut out = out.as_mut();
                assert!(out.len() >= Self::output_bytes());
                for i in 0..($bits / 32) {
                    out.write_u32::<BigEndian>(state.state[i]).unwrap();
                }
            }
        }
    };
    (high $name:ident, $init:ident, $bits:expr) => {
        pub struct $name {
            state: SHAState<u64>,
            buffer: FixedBuffer128,
            length: u64
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    state: SHAState { state: $init },
                    buffer: FixedBuffer128::new(),
                    length: 0
                }
            }
        }

        impl Digest for $name {
            fn update<T: AsRef<[u8]>>(&mut self, data: T) {
                let data = data.as_ref();
                self.length += data.len() as u64;

                let state = &mut self.state;
                self.buffer.input(data, |d| state.process_block(d));
            }

            fn output_bits() -> usize { $bits }
            fn block_size() -> usize { 128 }

            fn result<T: AsMut<[u8]>>(mut self, mut out: T) {
                let state = &mut self.state;

                self.buffer.standard_padding(8, |d| state.process_block(d));
                self.buffer.next(8).write_u64::<BigEndian>(self.length * 8).unwrap();
                state.process_block(self.buffer.full_buffer());

                let mut out = out.as_mut();
                assert!(out.len() >= Self::output_bytes());
                for i in 0..($bits / 64) {
                    out.write_u64::<BigEndian>(state.state[i]).unwrap();
                }
            }
        }
    }
);

impl_sha!(low SHA224, SHA224_INIT, 224);
impl_sha!(low SHA256, SHA256_INIT, 256);
impl_sha!(high SHA384, SHA384_INIT, 384);
impl_sha!(high SHA512, SHA512_INIT, 512);

#[cfg(test)]
mod tests {
    use digest::test::Test;
    use super::*;

    const SHA224_TESTS: [Test<'static>; 7] = [
        Test { input: "", output: "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" },
        Test { input: "a", output: "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5" },
        Test { input: "abc", output: "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
        Test { input: "message digest", output: "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e" }
    ];

    #[test]
    fn test_sha224() {
        for test in &SHA224_TESTS {
            test.test(SHA224::default());
        }
    }

    const SHA256_TESTS: [Test<'static>; 7] = [
        Test { input: "", output: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        Test { input: "a", output: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
        Test { input: "abc", output: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        Test { input: "message digest", output: "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e" }
    ];

    #[test]
    fn test_sha256() {
        for test in &SHA256_TESTS {
            test.test(SHA256::default());
        }
    }

    const SHA384_TESTS: [Test<'static>; 7] = [
        Test { input: "", output: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
        Test { input: "a", output: "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31" },
        Test { input: "abc", output: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
        Test { input: "message digest", output: "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026" },
    ];

    #[test]
    fn test_sha384() {
        for test in &SHA384_TESTS {
            test.test(SHA384::default());
        }
    }

    const SHA512_TESTS: [Test<'static>; 7] = [
        Test { input: "", output: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
        Test { input: "a", output: "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75" },
        Test { input: "abc", output: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        Test { input: "message digest", output: "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843" },
    ];

    #[test]
    fn test_sha512() {
        for test in &SHA512_TESTS {
            test.test(SHA512::default());
        }
    }
}
