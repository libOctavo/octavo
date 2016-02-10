use num::{one, zero, BigUint, Integer};

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

        if exp == one() {
            return base;
        }

        let mut acc: BigUint = one();

        while exp > zero() {
            if exp.is_odd() {
                acc = (acc * &base) % modulus
            }
            if exp > one() {
                base = (&base * &base) % modulus
            }
            exp = exp >> 1;
        }

        acc
    }
}
