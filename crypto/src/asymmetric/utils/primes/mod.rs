use num::One;
use integer::Integer;
use bigint::{BigUint, RandBigInt};
use rand::Rng;

use asymmetric::utils::primes::tests::PrimeTest;

pub mod tests;

const PRIME_TEST_COUNT: usize = 20;

/// Generate new prime number with given bit size via given random number generator.
///
/// Currently this function give guarantee that it ever ends. In case of bad `Rng` engine
/// this could fall into endless loop.
///
/// This function doesn't reseed `Rng` so You must provide autoreseedable engine, check out
/// [`ReseedingRng`](http://doc.rust-lang.org/rand/rand/reseeding/struct.ReseedingRng.html).
pub fn generate_prime<T: Rng + RandBigInt>(gen: &mut T, bits: usize) -> Option<BigUint> {
    loop {
        let mut int = gen.gen_biguint(bits);

        if int.is_even() {
            int = int + BigUint::one();
        }

        if tests::Fermat(gen).test_loop(&int, PRIME_TEST_COUNT).is_composite() {
            continue;
        }
        if tests::MillerRabin(gen).test_loop(&int, PRIME_TEST_COUNT).is_composite() {
            continue;
        }

        return Some(int);
    }
}
