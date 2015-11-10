extern {
    fn OCTAVO_cpuid() -> u64;
    fn OCTAVO_cpuid_ex() -> u64;
}

macro_rules! flag {
    ($map:expr, $bit:expr) => {
        ($map & (1 << $bit)) != 0
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Cpu {
    features: u64,
    extended: u64,
}

impl Cpu {
    pub fn new() -> Self {
        unsafe {
            Cpu {
                features: OCTAVO_cpuid(),
                extended: OCTAVO_cpuid_ex(),
            }
        }
    }

    pub fn sse(&self) -> bool {
        flag!(&self.features, 25)
    }
    pub fn sse2(&self) -> bool {
        flag!(&self.features, 26)
    }
    pub fn sse3(&self) -> bool {
        flag!(&self.features, 32)
    }
    pub fn ssse3(&self) -> bool {
        flag!(&self.features, 40)
    }
    pub fn sse4_1(&self) -> bool {
        flag!(&self.features, 50)
    }
    pub fn sse4_2(&self) -> bool {
        flag!(&self.features, 51)
    }
    pub fn aes(&self) -> bool {
        flag!(&self.features, 56)
    }
    pub fn avx(&self) -> bool {
        flag!(&self.features, 59)
    }
    pub fn avx2(&self) -> bool {
        flag!(&self.extended, 5)
    }
    pub fn sha(&self) -> bool {
        flag!(&self.extended, 29)
    }
}
