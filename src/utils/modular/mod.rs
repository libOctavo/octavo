use num::{Zero, One, Signed, BigUint, BigInt};
use num::bigint::Sign;

pub mod power;

pub trait Inverse {
    type Output;

    fn inverse(self, modulo: Self) -> Option<Self::Output>;
}

impl<'a> Inverse for &'a BigUint {
    type Output = BigUint;

    fn inverse(self, modulo: Self) -> Option<Self::Output> {
        BigInt::from_biguint(Sign::Plus, self.clone())
            .inverse(&BigInt::from_biguint(Sign::Plus, modulo.clone()))
            .and_then(|n| n.to_biguint())
    }
}

impl<'a> Inverse for &'a BigInt {
    type Output = BigInt;

    fn inverse(self, modulo: Self) -> Option<Self::Output> {
        let (mut t, mut newt): (BigInt, BigInt) = (Zero::zero(), One::one());
        let (mut r, mut newr): (BigInt, BigInt) = (self.clone(), modulo.clone());

        while !newr.is_zero() {
            let quo = &r / &newr;
            let tmp = &r - &quo * &newr;
            r = newr; newr = tmp;
            let tmp = &t - &quo * &newt;
            t = newt; newt = tmp;
        }

        if r > One::one() { return None }
        if t.is_negative() {
            Some(t + modulo)
        } else {
            Some(t)
        }
    }
}
