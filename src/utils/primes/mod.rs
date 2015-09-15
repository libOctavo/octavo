use num::bigint::{BigUint, RandBigInt};
use rand::Rng;

use utils::primes::tests::PrimeTest;

pub mod tests;

pub fn generate_prime<T: Rng + RandBigInt>(gen: &mut T, bits: usize) -> BigUint {
    loop {
        let int = gen.gen_biguint(bits);

        if tests::Fermat(gen).test_loop(&int, 50).is_composite() { continue }
        if tests::MillerRabin(gen).test_loop(&int, 50).is_composite() { continue }

        return int
    }
}
