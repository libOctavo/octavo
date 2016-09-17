pub use core::num::Wrapping as W;

#[allow(non_camel_case_types)]
pub type w32 = W<u32>;
#[allow(non_camel_case_types)]
pub type w64 = W<u64>;

pub trait Rotate {
    fn rotate_right(self, rotation: u32) -> Self;
    fn rotate_left(self, rotation: u32) -> Self;
}

macro_rules! impl_rotate {
    ($typ:path) => {
        impl Rotate for $typ {
            #[inline]
            fn rotate_right(self, rotation: u32) -> Self {
                $typ(self.0.rotate_right(rotation))
            }

            #[inline]
            fn rotate_left(self, rotation: u32) -> Self {
                $typ(self.0.rotate_left(rotation))
            }
        }
    };
}

impl_rotate!(W<u32>);
impl_rotate!(W<u64>);
