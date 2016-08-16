use std::path::Path;
use std::fs::File;
use std::io::Read;

use toml;

use utils::tests::Data;

#[derive(RustcDecodable)]
pub struct Test {
    input: Data,
    key: Data,
    output: Data,
}

#[derive(RustcDecodable)]
pub struct Suite {
    tests: Vec<Test>,
}

pub fn load<P: AsRef<Path>>(path: P) -> Suite {
    let mut content = String::new();
    File::open(path).and_then(|mut f| f.read_to_string(&mut content)).unwrap();

    toml::decode_str(&content).unwrap()
}

mod blake2b {
    use super::*;

    use digest::blake2::Blake2b512;
    use digest::Digest;

    use std::str;
    use rustc_serialize::hex::ToHex;

    #[test]
    fn reference_test_vectors() {
        let suite = load("./tests/blake2/blake2b.toml");

        for test in suite.tests {
            let mut digest = Blake2b512::with_key(&*test.key);
            digest.update(&*test.input);

            let mut output = vec![0; 64];
            digest.result(&mut output[..]);

            assert!(&*test.output == &output[..],
                    "Input: {:?} (str: \"{}\")\nKey:      {}\nExpected: {}\nGot:      {}",
                    test.input,
                    str::from_utf8(&*test.input).unwrap_or("<non-UTF8>"),
                    test.key.to_hex(),
                    test.output.to_hex(),
                    output.to_hex());
        }
    }
}
