use std::ops::*;

/// Temporary drop-in replacement until Rust stabilize SIMD. Till then we hope that LLVM will
/// vectorise this.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct u32x4(pub u32, pub u32, pub u32, pub u32);

impl Default for u32x4 {
    fn default() -> Self {
        u32x4(Default::default(),
              Default::default(),
              Default::default(),
              Default::default())
    }
}

impl u32x4 {
    pub fn filled(val: u32) -> Self {
        u32x4(val, val, val, val)
    }

    pub fn rotate_left(self, s: u32) -> Self {
        u32x4(self.0 << s,
              (self.1 << s) | (self.0 >> (32 - s)),
              (self.2 << s) | (self.1 >> (32 - s)),
              (self.3 << s) | (self.2 >> (32 - s)))
    }

    pub fn rotate_right(self, s: u32) -> Self {
        u32x4((self.0 >> s) | (self.1 << (32 - s)),
              (self.1 >> s) | (self.2 << (32 - s)),
              (self.2 >> s) | (self.3 << (32 - s)),
              self.3 >> s)
    }
}

impl BitAnd for u32x4 {
    type Output = Self;

    fn bitand(self, u32x4(e, f, g, h): Self) -> Self {
        let u32x4(a, b, c, d) = self;
        u32x4(a & e, b & f, c & g, d & h)
    }
}

impl BitXor for u32x4 {
    type Output = Self;

    fn bitxor(self, u32x4(e, f, g, h): Self) -> Self {
        let u32x4(a, b, c, d) = self;
        u32x4(a ^ e, b ^ f, c ^ g, d ^ h)
    }
}

impl BitOr for u32x4 {
    type Output = Self;

    fn bitor(self, u32x4(e, f, g, h): Self) -> Self {
        let u32x4(a, b, c, d) = self;
        u32x4(a | e, b | f, c | g, d | h)
    }
}

impl Not for u32x4 {
    type Output = u32x4;

    fn not(self) -> u32x4 {
        self ^ u32x4(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff)
    }
}
