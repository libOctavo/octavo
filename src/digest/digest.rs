use std::io::Write;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum State {
    Ready,
    InProgress,
    Finished
}

pub trait Digest {
    fn input<T>(&mut self, input: T) where T: AsRef<[u8]>;

    fn state(&self) -> State;
    fn reset(&mut self);

    fn output_bits(&self) -> usize;
    fn output_bytes(&self) -> usize {
        (self.output_bits() + 7) / 8
    }

    fn block_size(&self) -> usize;

    fn result<T>(&mut self, T) where T: AsMut<[u8]>;
    fn hex_result(&mut self) -> String {
        let mut hex = Vec::with_capacity(self.output_bytes() * 2);
        let mut buf = Vec::with_capacity(self.output_bytes());
        unsafe { buf.set_len(self.output_bytes()); }
        self.result(&mut buf[..]);

        for i in 0..self.output_bytes() {
            write!(hex, "{:02x}", buf[i]).unwrap();
        }
        String::from_utf8(hex).unwrap()
    }
}
