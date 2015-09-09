use num::bigint::{
    BigInt,
    RandBigInt
};
use num::One;
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
        n: BigInt,
        e: BigInt,
    },
    Private {
        n: BigInt,
        d: BigInt,
        extra: Option<SecretKeyExtra>,
    }
}

type KeyPair = (Key, Key);

impl KeyData {
    pub fn keypair_from_primes<T: Into<BigInt>>(p: T, q: T) -> () {
        let (p, q) = (p.into(), q.into());

        let n = &p * &q;
        let fin = &n - (&p + &q - BigInt::one());
    }

    pub fn generate_keypair<G: Rng + RandBigInt>(mut rng: G, bits: usize) -> () {
        let p = rng.gen_bigint(bits);
        let q = rng.gen_bigint(bits);

        keypair_from_primes(p, q);
    }
}
