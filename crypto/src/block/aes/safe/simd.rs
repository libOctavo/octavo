use std::ops::*;

/// Temporary drop-in replacement until Rust stabilize SIMD. Till then we hope that LLVM will
/// vectorise this.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub struct u32x4(pub u32, pub u32, pub u32, pub u32);

impl u32x4 {
    pub fn lsh(self, s: u32) -> u32x4 {
        let u32x4(a0, a1, a2, a3) = self;
        u32x4(a0 << s,
              (a1 << s) | (a0 >> (32 - s)),
              (a2 << s) | (a1 >> (32 - s)),
              (a3 << s) | (a2 >> (32 - s)))
    }

    pub fn rsh(self, s: u32) -> u32x4 {
        let u32x4(a0, a1, a2, a3) = self;
        u32x4((a0 >> s) | (a1 << (32 - s)),
              (a1 >> s) | (a2 << (32 - s)),
              (a2 >> s) | (a3 << (32 - s)),
              a3 >> s)
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

impl Default for u32x4 {
    fn default() -> u32x4 {
        u32x4(0, 0, 0, 0)
    }
}
