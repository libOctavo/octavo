use num::bigint::{
    BigUint,
    RandBigInt
};
use num::One;

use rand::Rng;

use utils::modular::Inverse;
use utils::primes::generate_prime;

pub struct SecretKeyExtra {
    p: BigUint,
    q: BigUint,
    dmp1: BigUint,
    dmq1: BigUint,
    qinv: BigUint
}

pub enum Key {
    Public {
        /// Modulus
        n: BigUint,
        /// Exponent
        e: BigUint,
    },
    Private {
        /// Modulus
        n: BigUint,
        /// Exponent
        d: BigUint,
        extra: Option<SecretKeyExtra>,
    }
}

pub type KeyPair = (Key, Key);

impl Key {
    pub fn keypair_from_primes<P, Q, E>(p: P, q: Q, e: E) -> KeyPair
        where P: Into<BigUint>, Q: Into<BigUint>, E: Into<BigUint> {
            let (p, q, e) = (p.into(), q.into(), e.into());

            let n = &p * &q;
            let fin = &n - (&p + &q - BigUint::one());

            let d = e.inverse(&fin).expect("Something gone wrong");

            let public = Key::Public { n: n.clone(), e: e };
            let extra = SecretKeyExtra {
                dmp1: &d % (&p - BigUint::one()),
                dmq1: &d % (&q - BigUint::one()),
                qinv: q.inverse(&p).unwrap(),
                p: p,
                q: q,
            };
            let private = Key::Private { n: n, d: d, extra: Some(extra)};

            (public, private)
        }

    pub fn generate_keypair<G, T>(mut rng: G, e: T, bits: usize) -> KeyPair
        where G: Rng + RandBigInt, T: Into<BigUint> {
            let p = generate_prime(&mut rng, bits).expect("Cannot generate safe prime");
            let q = generate_prime(&mut rng, bits).expect("Cannot generate safe prime");

            Self::keypair_from_primes(p, q, e)
        }

    pub fn is_public(&self) -> bool {
        match self {
            &Key::Public { .. } => true,
            _ => false
        }
    }

    pub fn is_private(&self) -> bool {
        match self {
            &Key::Private { .. } => true,
            _ => false
        }
    }
}
