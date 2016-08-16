use std::path::Path;
use std::fs::File;
use std::io::Read;

use toml;

pub mod tests;

#[derive(RustcDecodable)]
pub struct Suite {
    pub tests: Vec<tests::Test>,
}

pub fn load<P: AsRef<Path>>(path: P) -> Suite {
    let mut content = String::new();
    File::open(path).and_then(|mut f| f.read_to_string(&mut content)).unwrap();

    toml::decode_str(&content).unwrap()
}

#[macro_export]
macro_rules! digest_quick {
    ($octavo:ty, $openssl:expr) => {
#[test]
        fn quickcheck() {
            // use quickcheck::quickcheck;

            // fn prop(vec: Vec<u8>) -> bool {
            //     use ::openssl::crypto::hash::{hash, Type};
            //     use ::digest::Digest;

            //     let octavo = {
            //         let mut dig = <$octavo>::default();
            //         let mut res = vec![0; <$octavo>::output_bytes()];

            //         dig.update(&vec);
            //         dig.result(&mut res[..]);
            //         res
            //     };

            //     let openssl = hash($openssl, &vec);

            //     octavo == openssl
            // }

            // quickcheck(prop as fn(Vec<u8>) -> bool)
        }
    }
}
