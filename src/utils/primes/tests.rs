use num::{one, One, Integer, BigUint};
use num::bigint::{ToBigUint};
use rand::Rng;

use utils::modular::power::Power;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Result {
    PropablyPrime,
    Composite,
}

impl Result {
    pub fn is_composite(&self) -> bool {
        match self {
            &Result::Composite => true,
            _ => false
        }
    }
}

pub trait PrimeTest {
    fn test(&mut self, num: &BigUint) -> Result;

    fn test_loop(&mut self, num: &BigUint, times: usize) -> Result {
        for _ in 0..times {
            if self.test(&num).is_composite() { return Result::Composite }
        }

        Result::PropablyPrime
    }
}

pub struct Fermat<'a, T: Rng + 'a>(pub &'a mut T);

impl<'a, T: Rng + 'a> PrimeTest for Fermat<'a, T> {
    fn test(&mut self, num: &BigUint) -> Result {
        let base = self.0.next_u64().to_biguint().unwrap();
        let num_1 = num - BigUint::one();

        if (&base).pow_mod(&num_1, num) != one() {
            Result::Composite
        } else {
            Result::PropablyPrime
        }
    }
}

pub struct MillerRabin<'a, T: Rng + 'a>(pub &'a mut T);

impl<'a, T: Rng + 'a> MillerRabin<'a, T> {
    fn greatest_2_divisor(num: &BigUint) -> (usize, BigUint) {
        let mut s = 0;
        let mut num = num - BigUint::one();
        while num.is_even() {
            num = num >> 1;
            s += 1;
        }

        (s, num)
    }

    fn witness(num: &BigUint, a: BigUint, d: &BigUint, s: usize) -> Result {
        let mut x = (&a).pow_mod(d, num);
        let num_1 = num - BigUint::one();

        if x == one() || x == num_1 { return Result::PropablyPrime }

        for _ in 0..s {
            x = (&x * &x) % num;
            if x == one() { return Result::Composite }
            if x == num_1 { return Result::PropablyPrime }
        }

        Result::Composite
    }
}

impl<'a, T: Rng + 'a> PrimeTest for MillerRabin<'a, T> {
    fn test(&mut self, num: &BigUint) -> Result {
        let a = self.0.next_u64().to_biguint().unwrap();
        let (s, d) = Self::greatest_2_divisor(&num);

        Self::witness(num, a, &d, s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{StdRng, SeedableRng};
    use num::bigint::ToBigUint;

    const SEED: [usize; 1] = [0x00];

    fn rng() -> StdRng {
        StdRng::from_seed(&SEED[..])
    }

    #[test]
    fn test_fermat_prime() {
        let mut rng = rng();
        let mut fermat = Fermat(&mut rng);
        let res = fermat.test_loop(&4393139u64.to_biguint().unwrap(), 20);

        assert_eq!(res, Result::PropablyPrime);
    }

    #[test]
    fn test_fermat_composite() {
        let mut rng = rng();
        let mut fermat = Fermat(&mut rng);
        let res = fermat.test_loop(&4393137u64.to_biguint().unwrap(), 20);

        assert_eq!(res, Result::Composite);
    }

    #[test]
    fn test_miller_rabin_prime() {
        let mut rng = rng();
        let mut miller_rabin = MillerRabin(&mut rng);
        let res = miller_rabin.test_loop(&4393139u64.to_biguint().unwrap(), 20);

        assert_eq!(res, Result::PropablyPrime);
    }

    #[test]
    fn test_miller_rabin_composite() {
        let mut rng = rng();
        let mut miller_rabin = MillerRabin(&mut rng);
        let res = miller_rabin.test_loop(&4393137u64.to_biguint().unwrap(), 20);

        assert_eq!(res, Result::Composite);
    }
}
