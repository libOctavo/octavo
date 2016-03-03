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

#[inline(always)]
fn construct(a: u8, b: u8, c: u8, d: u8) -> u32 {
    a as u32 | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}

impl u32x4 {
    #[inline(always)]
    pub fn filled(val: u32) -> Self {
        u32x4(val, val, val, val)
    }

    pub fn read_row_major(data: &[u8]) -> Self {
        u32x4(construct(data[0], data[1], data[2], data[3]),
            construct(data[4], data[5], data[6], data[7]),
            construct(data[8], data[9], data[10], data[11]),
            construct(data[12], data[13], data[14], data[15]))
    }

    pub fn write_row_major(self, output: &mut [u8]) {
        let u32x4(a0, a1, a2, a3) = self;
        output[0] = a0 as u8;
        output[1] = a1 as u8;
        output[2] = a2 as u8;
        output[3] = a3 as u8;
        output[4] = (a0 >> 8) as u8;
        output[5] = (a1 >> 8) as u8;
        output[6] = (a2 >> 8) as u8;
        output[7] = (a3 >> 8) as u8;
        output[8] = (a0 >> 16) as u8;
        output[9] = (a1 >> 16) as u8;
        output[10] = (a2 >> 16) as u8;
        output[11] = (a3 >> 16) as u8;
        output[12] = (a0 >> 24) as u8;
        output[13] = (a1 >> 24) as u8;
        output[14] = (a2 >> 24) as u8;
        output[15] = (a3 >> 24) as u8;
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

    #[inline(always)]
    fn bitand(self, u32x4(e, f, g, h): Self) -> Self {
        let u32x4(a, b, c, d) = self;
        u32x4(a & e, b & f, c & g, d & h)
    }
}

impl BitXor for u32x4 {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, u32x4(e, f, g, h): Self) -> Self {
        let u32x4(a, b, c, d) = self;
        u32x4(a ^ e, b ^ f, c ^ g, d ^ h)
    }
}

impl BitOr for u32x4 {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, u32x4(e, f, g, h): Self) -> Self {
        let u32x4(a, b, c, d) = self;
        u32x4(a | e, b | f, c | g, d | h)
    }
}

impl Not for u32x4 {
    type Output = u32x4;

    #[inline(always)]
    fn not(self) -> u32x4 {
        self ^ u32x4(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff)
    }
}
