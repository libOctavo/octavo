use digest;
use utils::buffer;

use byteorder::{
    ReadBytesExt,
    WriteBytesExt,
    LittleEndian,
};

use std::io::Read;
use std::hash::Hasher;

struct SHA3State {
    hash: [u64; 25],
    message: [u8; 144],
    rest: usize,
    block_size: usize,
}

const ROUND_CONSTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
];

const SHIFTS: [u32; 25] = [
    0,   1,   62,  28,  27,
    36,  44,  6,   55,  20,
    3,   10,  43,  25,  39,
    41,  45,  15,  21,  8,
    18,  2,   61,  56,  14,
];

impl SHA3State {
    fn init(bits: usize) -> Self {
        let rate = 1600 - bits * 2;
        assert!(rate <= 1600 && (rate % 64) == 0);
        SHA3State {
            hash: [0; 25],
            message: [0; 144],
            rest: 0,
            block_size: rate / 8,
        }
    }

    #[inline(always)]
    fn theta(&mut self) {
        let mut a = [0u64; 5];
        let mut b = [0u64; 5];

        for i in 0..5 {
            a[i] = self.hash[i]
                ^ self.hash[i + 5]
                ^ self.hash[i + 10]
                ^ self.hash[i + 15]
                ^ self.hash[i + 20];
        }

        for i in 0..5 {
            b[i] = a[(i + 1) % 5].rotate_left(1) ^ a[(i + 4) % 5];
        }

        for i in 0..5 {
            self.hash[i]      ^= b[i];
            self.hash[i + 5]  ^= b[i];
            self.hash[i + 10] ^= b[i];
            self.hash[i + 15] ^= b[i];
            self.hash[i + 20] ^= b[i];
        }
    }

    #[inline(always)]
    fn rho(&mut self) {
        for (i, shift) in SHIFTS.iter().enumerate() {
            self.hash[i] = self.hash[i].rotate_left(*shift);
        }
    }

    #[inline(always)]
    fn pi(&mut self) {
        let tmp       = self.hash[ 1];
        self.hash[ 1] = self.hash[ 6];
        self.hash[ 6] = self.hash[ 9];
        self.hash[ 9] = self.hash[22];
        self.hash[22] = self.hash[14];
        self.hash[14] = self.hash[20];
        self.hash[20] = self.hash[ 2];
        self.hash[ 2] = self.hash[12];
        self.hash[12] = self.hash[13];
        self.hash[13] = self.hash[19];
        self.hash[19] = self.hash[23];
        self.hash[23] = self.hash[15];
        self.hash[15] = self.hash[ 4];
        self.hash[ 4] = self.hash[24];
        self.hash[24] = self.hash[21];
        self.hash[21] = self.hash[ 8];
        self.hash[ 8] = self.hash[16];
        self.hash[16] = self.hash[ 5];
        self.hash[ 5] = self.hash[ 3];
        self.hash[ 3] = self.hash[18];
        self.hash[18] = self.hash[17];
        self.hash[17] = self.hash[11];
        self.hash[11] = self.hash[ 7];
        self.hash[ 7] = self.hash[10];
        self.hash[10] = tmp;
        // NOTE: self.hash[0] is left untouched
    }

    #[inline(always)]
    fn chi(&mut self) {
        for i in 0..5 {
            let i = i * 5;
            let tmp_0 = self.hash[i];
            let tmp_1 = self.hash[i + 1];

            self.hash[i]     ^= !tmp_1 & self.hash[i + 2];
            self.hash[i + 1] ^= !self.hash[i + 2] & self.hash[i + 3];
            self.hash[i + 2] ^= !self.hash[i + 3] & self.hash[i + 4];
            self.hash[i + 3] ^= !self.hash[i + 4] & tmp_0;
            self.hash[i + 4] ^= !tmp_0 & tmp_1;
        }
    }

    #[inline(always)]
    fn permutation(&mut self) {
        for round in &ROUND_CONSTS {
            self.theta();
            self.rho();
            self.pi();
            self.chi();

            // iota
            self.hash[0] ^= *round;
        }
    }

    #[inline(always)]
    fn process(&mut self, mut data: &[u8]) {
        for i in 0..9 {
            self.hash[i] ^= data.read_u64::<LittleEndian>().unwrap();
        }
        if self.block_size > 72 {
            for i in 9..13 {
                self.hash[i] ^= data.read_u64::<LittleEndian>().unwrap();
            }
        }
        if self.block_size > 104 {
            for i in 13..17 {
                self.hash[i] ^= data.read_u64::<LittleEndian>().unwrap();
            }
        }
        if self.block_size > 138 {
            self.hash[17] ^= data.read_u64::<LittleEndian>().unwrap();
        }

        self.permutation();
    }

    fn update(&mut self, mut data: &[u8]) {
        while let Ok(len) = data.read(&mut self.message[self.rest..self.block_size]) {
            if len + self.rest < self.block_size {
                self.rest = len;
                return
            }
            assert!(len + self.rest == self.block_size);
            let message = self.message;
            self.process(&message[..]);
            self.rest = 0;
        }
    }

    fn finish(&mut self) {
        buffer::zero(&mut self.message[self.rest..self.block_size]);
        self.message[self.rest] |= 0x06;
        self.message[self.block_size - 1] |= 0x80;

        let message = self.message;
        self.process(&message[..]);
    }
}

macro_rules! sha3_impl {
    ($name:ident -> $size:expr) => {
        pub struct $name {
            state: SHA3State
        }

        impl Default for $name {
            fn default() -> Self {
                $name { state: SHA3State::init($size) }
            }
        }

        impl digest::Digest for $name {
            fn update<T>(&mut self, data: T) where T: AsRef<[u8]> {
                self.state.update(data.as_ref());
            }

            fn output_bits() -> usize { $size }
            fn block_size() -> usize { 1600 - (2 * $size) }

            fn result<T>(mut self, mut out: T) where T: AsMut<[u8]> {
                let mut ret = out.as_mut();
                assert!(ret.len() >= Self::output_bytes());

                self.state.finish();

                let mut tmp = [0u8; 200];
                {
                    let mut p = &mut tmp[..];

                    for i in 0..25 {
                        p.write_u64::<LittleEndian>(self.state.hash[i]).unwrap();
                    }
                }

                for i in 0..(Self::output_bytes()) {
                    ret[i] = tmp[i];
                }
            }
        }
    }
}

sha3_impl!(SHA3224 -> 224);
sha3_impl!(SHA3256 -> 256);
sha3_impl!(SHA3384 -> 384);
sha3_impl!(SHA3512 -> 512);

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;
    use digest::test::Test;

    const SHA3_224_TESTS: [Test<'static>; 8] = [
        Test { input: "", output: "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" },
        Test { input: "a", output: "9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b" },
        Test { input: "abc", output: "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" },
        Test { input: "message digest", output: "18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "a67c289b8250a6f437a20137985d605589a8c163d45261b15419556e" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "0526898e185869f91b3e2a76dd72a15dc6940a67c8164a044cd25cc8" },
        Test { input: "The quick brown fox jumps over the lazy dog", output: "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795" },
    ];

    #[test]
    fn test_sha3_224() {
        for test in &SHA3_224_TESTS {
            test.test(SHA3224::new());
        }
    }

    const SHA3_256_TESTS: [Test<'static>; 8] = [
        Test { input: "", output: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" },
        Test { input: "a", output: "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b" },
        Test { input: "abc", output: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
        Test { input: "message digest", output: "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d" },
        Test { input: "The quick brown fox jumps over the lazy dog", output: "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04" },
    ];

    #[test]
    fn test_sha3_256() {
        for test in &SHA3_256_TESTS {
            test.test(SHA3256::new());
        }
    }

    const SHA3_384_TESTS: [Test<'static>; 8] = [
        Test { input: "", output: "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004" },
        Test { input: "a", output: "1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9" },
        Test { input: "abc", output: "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25" },
        Test { input: "message digest", output: "d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "d5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20cb45aa51bd4f542fc733e2719e999291" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "3c213a17f514638acb3bf17f109f3e24c16f9f14f085b52a2f2b81adc0db83df1a58db2ce013191b8ba72d8fae7e2a5e" },
        Test { input: "The quick brown fox jumps over the lazy dog", output: "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41" },
    ];

    #[test]
    fn test_sha3_384() {
        for test in &SHA3_384_TESTS {
            test.test(SHA3384::new());
        }
    }

    const SHA3_512_TESTS: [Test<'static>; 8] = [
        Test { input: "", output: "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" },
        Test { input: "a", output: "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a" },
        Test { input: "abc", output: "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
        Test { input: "message digest", output: "3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59" },
        Test { input: "abcdefghijklmnopqrstuvwxyz", output: "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68" },
        Test { input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", output: "d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab536b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163" },
        Test { input: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", output: "9524b9a5536b91069526b4f6196b7e9475b4da69e01f0c855797f224cd7335ddb286fd99b9b32ffe33b59ad424cc1744f6eb59137f5fb8601932e8a8af0ae930" },
        Test { input: "The quick brown fox jumps over the lazy dog", output: "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450" },
    ];


    #[test]
    fn test_sha3_512() {
        for test in &SHA3_512_TESTS {
            test.test(SHA3512::new());
        }
    }
}
