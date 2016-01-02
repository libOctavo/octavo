use std::str;

use octavo::digest::Digest;

#[macro_use]
mod macros;

mod md4;
mod md5;
mod sha1;
mod sha2;
mod sha3;
mod ripemd;
mod tiger;

pub struct Test<'a> {
    pub input: &'a [u8],
    pub output: &'a [u8],
}

impl<'a> Test<'a> {
    pub fn test<T: Testable>(&self, tested: T) {
        tested.test(self);
    }
}

pub trait Testable: Sized {
    fn test(self, &Test);
}

impl<T> Testable for T where T: Digest + Sized
{
    fn test(mut self, test: &Test) {
        self.update(test.input);
        let mut output = vec![0; T::output_bytes()];

        self.result(&mut output[..]);
        assert!(test.output == &output[..],
                "Input: {:?} (str: {})\nExpected: {:?}\nGot: {:?}",
                test.input,
                str::from_utf8(test.input).unwrap_or("<non-UTF8>"),
                test.output,
                output);
    }
}
