use std::ptr;
use std::io::Read;

/// A FixedBuffer, likes its name implies, is a fixed size buffer. When the buffer becomes full, it
/// must be processed. The input() method takes care of processing and then clearing the buffer
/// automatically. However, other methods do not and require the caller to process the buffer. Any
/// method that modifies the buffer directory or provides the caller with bytes that can be modifies
/// results in those bytes being marked as used by the buffer.
pub trait FixedBuffer {
    /// Input a vector of bytes. If the buffer becomes full, process it with the provided
    /// function and then clear the buffer.
    fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], func: F);

    /// Reset the buffer.
    fn reset(&mut self);

    /// Zero the buffer up until the specified index. The buffer position currently must not be
    /// greater than that index.
    fn zero_until(&mut self, idx: usize);

    /// Get a slice of the buffer of the specified size. There must be at least that many bytes
    /// remaining in the buffer.
    fn next(&mut self, len: usize) -> &mut [u8];

    /// Get the current buffer. The buffer must already be full. This clears the buffer as well.
    fn full_buffer(&mut self) -> &[u8];

    /// Get the current buffer.
    fn current_buffer(&self) -> &[u8];

    /// Get the current position of the buffer.
    fn position(&self) -> usize;

    /// Get the number of bytes remaining in the buffer until it is full.
    fn remaining(&self) -> usize;

    /// Get the size of the buffer
    fn size() -> usize;
}

macro_rules! impl_fixed_buffer( ($name:ident, $size:expr) => (
        pub struct $name {
            buffer: [u8; $size],
            position: usize,
        }

        impl $name {
            /// Create a new buffer
            pub fn new() -> Self {
                $name {
                    buffer: [0u8; $size],
                    position: 0
                }
            }
        }

        impl FixedBuffer for $name {
            fn input<F: FnMut(&[u8])>(&mut self, mut input: &[u8], mut func: F) {
                while let Ok(size) = input.read(&mut self.buffer[self.position..$size]) {
                    if (size + self.position) < $size {
                        self.position += size;
                        break
                    }
                    func(&self.buffer);
                    self.position = 0;
                }
            }

            fn reset(&mut self) {
                self.position = 0;
            }

            fn zero_until(&mut self, idx: usize) {
                assert!(idx >= self.position);
                zero(&mut self.buffer[self.position..idx]);
                self.position = idx;
            }

            fn next(&mut self, len: usize) -> &mut [u8] {
                self.position += len;
                &mut self.buffer[self.position - len..self.position]
            }

            fn full_buffer(&mut self) -> &[u8] {
                assert!(self.position == $size);
                self.position = 0;
                &self.buffer[..$size]
            }

            fn current_buffer(&self) -> &[u8] {
                &self.buffer[..self.position]
            }

            fn position(&self) -> usize { self.position }

            fn remaining(&self) -> usize { $size - self.position }

            fn size() -> usize { $size }
        }
));

/// A fixed size buffer of 64 bytes useful for cryptographic operations.
impl_fixed_buffer!(FixedBuffer64, 64);

/// A fixed size buffer of 64 bytes useful for cryptographic operations.
impl_fixed_buffer!(FixedBuffer128, 128);

/// The StandardPadding trait adds a method useful for various hash algorithms to a FixedBuffer
/// struct.
pub trait StandardPadding {
    /// Add standard padding to the buffer. The buffer must not be full when this method is called
    /// and is guaranteed to have exactly rem remaining bytes when it returns. If there are not at
    /// least rem bytes available, the buffer will be zero padded, processed, cleared, and then
    /// filled with zeros again until only rem bytes are remaining.
    fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, func: F);
}

impl <T: FixedBuffer> StandardPadding for T {
    fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, mut func: F) {
        let size = Self::size();

        self.next(1)[0] = 0b10000000;

        if self.remaining() < rem {
            self.zero_until(size);
            func(self.full_buffer());
        }

        self.zero_until(size - rem);
    }
}

/// Zero all bytes in dst
#[inline]
pub fn zero(dst: &mut [u8]) {
    unsafe {
        ptr::write_bytes(dst.as_mut_ptr(), 0, dst.len());
    }
}
