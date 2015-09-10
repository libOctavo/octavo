use num::bigint::{
    BigInt,
    RandBigInt
};
use num::{One, Zero};
use rand::Rng;

pub struct SecretKeyExtra {
    p: BigInt,
    q: BigInt,
    dmp1: BigInt,
    dmq1: BigInt,
    qinv: BigInt
}

pub enum Key {
    Public {
        /// Modulus
        n: BigInt,
        /// Exponent
        e: BigInt,
    },
    Private {
        /// Modulus
        n: BigInt,
        /// Exponent
        d: BigInt,
        extra: Option<SecretKeyExtra>,
    }
}

type KeyPair = (Key, Key);

// fn inverse(a: BigInt, n: BigInt) -> Option<BigInt> {
//     let mut t = Zero::zero();
//     let mut r = n.clone();
//     let mut newt = One::one();
//     let mut newr = a;

//     while !newr.is_zero() {
//         let quo = &r / &newr;
//         let t = newt;

//     }

//     Some(One::one())
// }

impl Key {
    pub fn keypair_from_primes<P, Q, E>(p: P, q: Q, e: E) -> ()
        where P: Into<BigInt>, Q: Into<BigInt>, E: Into<BigInt> {
            let (p, q, e) = (p.into(), q.into(), e.into());

            let n = &p * &q;
            let fin = &n - (&p + &q - BigInt::one());

            assert!(&fin % &e == BigInt::one());

            let public = Key::Public { n: n.clone(), e: e.clone() };
        }

    pub fn generate_keypair<G, T>(mut rng: G, e: T, bits: usize) -> ()
        where G: RandBigInt, T: Into<BigInt> {
            let p = rng.gen_bigint(bits);
            let q = rng.gen_bigint(bits);

            Self::keypair_from_primes(p, q, e)
        }
}
