use num::{Zero, One, BigUint};

pub mod power;

pub trait Inverse {
    type Output;

    fn inverse(self, modulo: Self) -> Option<Self::Output>;
}

impl<'a> Inverse for &'a BigUint {
    type Output = BigUint;

    fn inverse(self, modulo: Self) -> Option<Self::Output> {
        let (mut t, mut newt): (BigUint, BigUint) = (Zero::zero(), One::one());
        let (mut r, mut newr) = (self.clone(), modulo.clone());

        while !newr.is_zero() {
            let quo = &r / &newr;
            let tmp = &r - &quo * &newr;
            r = newr; newr = tmp;
            let tmp = &t - &quo * &newt;
            t = newt; newt = tmp;
        }

        if r > One::one() { return None }

        Some(t)
    }
}
