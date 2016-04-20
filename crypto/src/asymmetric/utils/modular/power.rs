use num::{One, Zero};
use bigint::BigUint;
use integer::Integer;

pub trait Power<T> {
    type Output;

    fn pow_mod(self, exp: T, modulus: T) -> Self::Output;
}

impl Power<BigUint> for BigUint {
    type Output = Self;

    fn pow_mod(self, exp: BigUint, modulus: BigUint) -> Self {
        (&self).pow_mod(&exp, &modulus)
    }
}

impl<'a> Power<&'a BigUint> for &'a BigUint {
    type Output = BigUint;

    fn pow_mod(self, exp: &BigUint, modulus: &BigUint) -> BigUint {
        let mut base = self % modulus;
        let mut exp = exp.clone();

        if exp == One::one() {
            return base;
        }

        let mut acc: BigUint = One::one();

        while exp > Zero::zero() {
            if exp.is_odd() {
                acc = (acc * &base) % modulus
            }
            if exp > One::one() {
                base = (&base * &base) % modulus
            }
            exp = exp >> 1;
        }

        acc
    }
}
