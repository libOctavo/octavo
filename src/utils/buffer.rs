use std::cmp;
use std::ptr;

use generic_array::{ArrayLength, GenericArray};
use typenum::uint::Unsigned;
use typenum::consts::{U64, U128};

/// A FixedBuffer, likes its name implies, is a fixed size buffer. When the buffer becomes full, it
/// must be processed. The input() method takes care of processing and then clearing the buffer
/// automatically. However, other methods do not and require the caller to process the buffer. Any
/// method that modifies the buffer directory or provides the caller with bytes that can be modifies
/// results in those bytes being marked as used by the buffer.
pub trait FixedBuf {
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

pub struct FixedBuffer<N: ArrayLength<u8>> {
    buffer: GenericArray<u8, N>,
    position: usize,
}

pub type FixedBuffer64 = FixedBuffer<U64>;
pub type FixedBuffer128 = FixedBuffer<U128>;

impl<N: ArrayLength<u8>> FixedBuffer<N> {
    /// Create a new buffer
    pub fn new() -> Self {
        FixedBuffer {
            buffer: GenericArray::new(),
            position: 0,
        }
    }

    fn fill(&mut self, data: &[u8]) -> bool {
        assert!(self.position + data.len() <= Self::size());
        let start = self.position;

        self.position += data.len();

        // Faster than loop. Benched and tested, gives about 20% speedup.
        //
        // -- Hauleth
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.buffer[start..].as_mut_ptr(), data.len());
        }

        self.position == Self::size()
    }
}

impl<N: ArrayLength<u8>> FixedBuf for FixedBuffer<N> {
    fn input<F: FnMut(&[u8])>(&mut self, input: &[u8], mut func: F) {
        let len = input.len();
        let remaining = cmp::min(self.remaining(), len);

        if !self.fill(&input[..remaining]) {
            return;
        }

        func(&self.buffer);
        self.position = 0;

        let will_remain = len - ((len - remaining) % Self::size());

        for chunk in input[remaining..will_remain].chunks(Self::size()) {
            func(&chunk)
        }

        self.fill(&input[will_remain..]);
    }

    fn reset(&mut self) {
        self.position = 0;
    }

    fn zero_until(&mut self, idx: usize) {
        assert!(idx >= self.position);
        for b in &mut self.buffer[self.position..idx] {
            *b = 0
        }
        self.position = idx;
    }

    fn next(&mut self, len: usize) -> &mut [u8] {
        self.position += len;
        &mut self.buffer[self.position - len..self.position]
    }

    fn full_buffer(&mut self) -> &[u8] {
        assert!(self.position == Self::size());
        self.position = 0;
        &self.buffer[..Self::size()]
    }

    fn current_buffer(&self) -> &[u8] {
        &self.buffer[..self.position]
    }

    fn position(&self) -> usize {
        self.position
    }

    fn remaining(&self) -> usize {
        Self::size() - self.position
    }

    fn size() -> usize {
        <N as Unsigned>::to_usize()
    }
}

impl<N: ArrayLength<u8>> Clone for FixedBuffer<N> {
    fn clone(&self) -> Self {
        FixedBuffer {
            buffer: GenericArray::from_slice(&self.buffer),
            position: self.position,
        }
    }
}

/// The StandardPadding trait adds a method useful for various hash algorithms to a FixedBuffer
/// struct.
pub trait StandardPadding {
    /// Add standard padding to the buffer. The buffer must not be full when this method is called
    /// and is guaranteed to have exactly rem remaining bytes when it returns. If there are not at
    /// least rem bytes available, the buffer will be zero padded, processed, cleared, and then
    /// filled with zeros again until only rem bytes are remaining.
    fn pad<F: FnMut(&[u8])>(&mut self, padding: u8, rem: usize, func: F);

    fn standard_padding<F: FnMut(&[u8])>(&mut self, rem: usize, func: F) {
        self.pad(0b10000000, rem, func)
    }
}

impl<T: FixedBuf> StandardPadding for T {
    fn pad<F: FnMut(&[u8])>(&mut self, padding: u8, rem: usize, mut func: F) {
        let size = T::size();

        self.next(1)[0] = padding;

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
    for byte in dst {
        *byte = 0
    }
}
