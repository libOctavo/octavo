use num::One;
use integer::Integer;
use bigint::{ToBigUint, BigUint};
use rand::Rng;

use asymmetric::utils::modular::power::Power;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Type {
    PropablyPrime,
    Composite,
}

impl Type {
    pub fn is_composite(&self) -> bool {
        match *self {
            Type::Composite => true,
            _ => false,
        }
    }
}

pub trait PrimeTest {
    fn test(&mut self, num: &BigUint) -> Type;

    fn test_loop(&mut self, num: &BigUint, times: usize) -> Type {
        for _ in 0..times {
            if self.test(num).is_composite() {
                return Type::Composite;
            }
        }

        Type::PropablyPrime
    }
}

pub struct Fermat<'a, T: Rng + 'a>(pub &'a mut T);

impl<'a, T: Rng + 'a> PrimeTest for Fermat<'a, T> {
    fn test(&mut self, num: &BigUint) -> Type {
        let base = self.0.next_u64().to_biguint().unwrap();
        let num_1 = num - BigUint::one();

        if (&base).pow_mod(&num_1, num) != BigUint::one() {
            Type::Composite
        } else {
            Type::PropablyPrime
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

    fn witness(num: &BigUint, a: BigUint, d: &BigUint, s: usize) -> Type {
        let mut x = (&a).pow_mod(d, num);
        let num_1 = num - BigUint::one();

        if x == BigUint::one() || x == num_1 {
            return Type::PropablyPrime;
        }

        for _ in 0..s {
            x = (&x * &x) % num;
            if x == BigUint::one() {
                return Type::Composite;
            }
            if x == num_1 {
                return Type::PropablyPrime;
            }
        }

        Type::Composite
    }
}

impl<'a, T: Rng + 'a> PrimeTest for MillerRabin<'a, T> {
    fn test(&mut self, num: &BigUint) -> Type {
        let a = self.0.next_u64().to_biguint().unwrap();
        let (s, d) = Self::greatest_2_divisor(num);

        Self::witness(num, a, &d, s)
    }
}

#[cfg(test)]
mod tests {
    use rand::{StdRng, SeedableRng};

    const SEED: [usize; 1] = [0x00];

    fn rng() -> StdRng {
        StdRng::from_seed(&SEED[..])
    }

    mod fermat {
        use bigint::ToBigUint;

        use super::rng;
        use super::super::{PrimeTest, Type, Fermat};

        #[test]
        fn prime() {
            let mut rng = rng();
            let mut fermat = Fermat(&mut rng);
            let res = fermat.test_loop(&4393139u64.to_biguint().unwrap(), 20);

            assert_eq!(res, Type::PropablyPrime);
        }

        #[test]
        fn composite() {
            let mut rng = rng();
            let mut fermat = Fermat(&mut rng);
            let res = fermat.test_loop(&4393137u64.to_biguint().unwrap(), 20);

            assert_eq!(res, Type::Composite);
        }
    }

    mod miller_rabin {
        use bigint::ToBigUint;

        use super::rng;
        use super::super::{PrimeTest, Type, MillerRabin};

        #[test]
        fn prime() {
            let mut rng = rng();
            let mut miller_rabin = MillerRabin(&mut rng);
            let res = miller_rabin.test_loop(&4393139u64.to_biguint().unwrap(), 20);

            assert_eq!(res, Type::PropablyPrime);
        }

        #[test]
        fn composite() {
            let mut rng = rng();
            let mut miller_rabin = MillerRabin(&mut rng);
            let res = miller_rabin.test_loop(&4393137u64.to_biguint().unwrap(), 20);

            assert_eq!(res, Type::Composite);
        }
    }
}
