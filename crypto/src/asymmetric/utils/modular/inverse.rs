use num::{Zero, One, Signed};
use bigint::{BigUint, BigInt, Sign};

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
        let (mut t, mut new_t): (BigInt, BigInt) = (Zero::zero(), One::one());
        let (mut r, mut new_r): (BigInt, BigInt) = (modulo.clone(), self.clone());

        while !new_r.is_zero() {
            let quo = &r / &new_r;
            let tmp = &r - &quo * &new_r;
            r = new_r;
            new_r = tmp;
            let tmp = &t - &quo * &new_t;
            t = new_t;
            new_t = tmp;
        }

        if r != One::one() {
            return None;
        }
        if t.is_negative() {
            Some(t + modulo)
        } else {
            Some(t)
        }
    }
}
