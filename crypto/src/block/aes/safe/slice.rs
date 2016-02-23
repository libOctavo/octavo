use std::ops::*;

pub trait Split {
    type Output;

    fn split(self) -> (Output, Output);

    fn join(left: Output, right: Output) -> Self;
}

#[derive(Copy, Clone, Debug)]
pub struct Bs2<T>(T, T);

impl<T: BitXor<Output=T> + Copy> BitXor for Bs2<T> {
    type Output = Self;

    fn bit_xor(self, other: Self) -> Self {
        Bs2(self.0 ^ other.0, self.1 ^ other.1)
    }
}

impl<T: Copy> Split for Bs4<T> {
    type Output = T;

    fn split(self) -> (T, T) {
        (self.0, self.1)
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Bs4<T>(T, T, T, T);

impl<T: BitXor<Output=T> + Copy> BitXor for Bs4<T> {
    type Ouptut = Self;

    fn bit_xor(self, other: Self) -> Self {
        Bs4(self.0 ^ other.0, self.1 ^ other.1, self.2 ^ other.2, self.3, other.3)
    }
}

impl<T: Copy> Split for Bs4<T> {
    type Output = Bs2<T>;

    fn split(self) -> (Self::Output, Self::Output) {
        (Bs2(self.0, self.1), Bs2(self.2, self.3))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Bs8<T>(T, T, T, T, T, T, T, T);

impl<T: Copy> Split for Bs8<T> {
    type Output = Bs4<T>;

    fn split(self) -> (Self::Output, Self::Output) {
        (Bs2(self.0, self.1, self.2, self.3), Bs2(self.4, self.5, self.6, self.7))
    }
}
