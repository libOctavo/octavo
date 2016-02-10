use std::ops::Deref;
use std::str;

use digest::Digest;
use rustc_serialize as ser;
use rustc_serialize::hex::{FromHex, ToHex};

#[derive(Debug, PartialEq, Eq)]
struct Data(Vec<u8>);
impl Deref for Data {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &*self.0
    }
}

impl ser::Decodable for Data {
    fn decode<D: ser::Decoder>(d: &mut D) -> Result<Data, D::Error> {
        let data = try!(d.read_str());

        if data.starts_with("hex:") {
            Ok(Data(data[4..].from_hex().unwrap()))
        } else {
            Ok(Data(data.into()))
        }
    }
}

#[derive(RustcDecodable)]
pub struct Test {
    input: Data,
    output: Data,
}

impl Test {
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
        self.update(&*test.input);
        let mut output = vec![0; T::output_bytes()];
        self.result(&mut output[..]);
        assert!(&*test.output == &output[..],
                "Input: {:?} (str: \"{}\")\nExpected: {}\nGot:      {}",
                test.input,
                str::from_utf8(&*test.input).unwrap_or("<non-UTF8>"),
                test.output.to_hex(),
                output.to_hex());
    }
}
