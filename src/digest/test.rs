use digest::Digest;

pub struct Test<'a> {
    pub input: &'a str,
    pub output: &'a str
}

impl<'a> Test<'a> {
    pub fn test<T: Testable>(&self, tested: T) {
        tested.test(self);
    }
}

pub trait Testable: Sized {
    fn test<'a>(self, &Test<'a>);
}

impl<T> Testable for T where T: Digest + Sized {
    fn test<'a>(mut self, test: &Test<'a>) {
        self.update(test.input);
        let hex = self.hex_result();
        assert!(test.output == hex, "Input: {:?}\nExpected: {}\nGot: {}", test.input, test.output, hex);
    }
}
