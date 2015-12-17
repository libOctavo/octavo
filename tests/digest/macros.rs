#[macro_export]
macro_rules! digest_quick {
    ($octavo:ty, $openssl:expr) => {
#[test]
        fn quickcheck() {
            use quickcheck::quickcheck;

            fn prop(vec: Vec<u8>) -> bool {
                use ::openssl::crypto::hash::{hash, Type};
                use ::octavo::digest::Digest;

                let octavo = {
                    let mut dig = <$octavo>::default();
                    let mut res = vec![0; <$octavo>::output_bytes()];

                    dig.update(&vec);
                    dig.result(&mut res[..]);
                    res
                };

                let openssl = hash($openssl, &vec);

                octavo == openssl
            }

            quickcheck(prop as fn(Vec<u8>) -> bool)
        }
    }
}
