use num::bigint::{BigUint, RandBigInt};
use num::One;

use rand::Rng;

use utils::modular::Inverse;
use utils::modular::Power;
use utils::primes::generate_prime;

pub struct SecretKeyExtra {
    p: BigUint,
    q: BigUint,
    dmp1: BigUint,
    dmq1: BigUint,
    qinv: BigUint,
}

impl SecretKeyExtra {
    fn from_primes(p: BigUint, q: BigUint, d: &BigUint) -> Self {
        SecretKeyExtra {
            dmp1: d % (&p - BigUint::one()),
            dmq1: d % (&q - BigUint::one()),
            qinv: q.inverse(&p).unwrap(),
            p: p,
            q: q,
        }
    }
}

pub enum Rsa {
    Public {
        /// Modulus
        n: BigUint,
        /// Public Exponent
        e: BigUint,
    },
    Private {
        /// Modulus
        n: BigUint,
        /// Private Exponent
        d: BigUint,
        extra: Option<SecretKeyExtra>,
    },
}

pub type KeyPair = (Rsa, Rsa);

impl Rsa {
    pub fn keypair_from_primes<P, Q, E>(p: P, q: Q, e: E) -> KeyPair
        where P: Into<BigUint>,
              Q: Into<BigUint>,
              E: Into<BigUint>
    {
        let (p, q, e) = (p.into(), q.into(), e.into());

        let n = &p * &q;
        let phi_n = &n - (&p + &q - BigUint::one());

        let d = e.inverse(&phi_n).expect("e is irreversible in ring phi(pq) - error");

        let public = Rsa::Public {
            n: n.clone(),
            e: e,
        };
        let private = Rsa::Private {
            n: n,
            extra: Some(SecretKeyExtra::from_primes(p, q, &d)),
            d: d,
        };

        (public, private)
    }

    pub fn generate_keypair<G, T>(mut rng: G, e: T, bits: usize) -> KeyPair
        where G: Rng + RandBigInt,
              T: Into<BigUint>
    {
        let e = e.into();

        let mut p = generate_prime(&mut rng, bits).expect("Cannot generate safe prime");
        while (&p - BigUint::one()) % &e != BigUint::one() {
            p = generate_prime(&mut rng, bits).expect("Cannot generate safe prime");
        }
        let mut q = generate_prime(&mut rng, bits).expect("Cannot generate safe prime");
        while (&q - BigUint::one()) % &e != BigUint::one() {
            q = generate_prime(&mut rng, bits).expect("Cannot generate safe prime");
        }

        Self::keypair_from_primes(p, q, e)
    }

    pub fn is_public(&self) -> bool {
        match *self {
            Rsa::Public { .. } => true,
            _ => false,
        }
    }

    pub fn is_private(&self) -> bool {
        match *self {
            Rsa::Private { .. } => true,
            _ => false,
        }
    }

    pub fn crypt(&self, msg: &BigUint) -> BigUint {
        match *self {
            Rsa::Private { ref n, ref d, ref extra } => crypt(msg, n, d, extra.as_ref()),
            Rsa::Public { ref n, ref e } => crypt(msg, n, e, None),
        }
    }
}

fn crypt(msg: &BigUint,
         modulus: &BigUint,
         exp: &BigUint,
         extra: Option<&SecretKeyExtra>)
         -> BigUint {
    if let Some(ref extra) = extra {
        chinese_remainders_power(msg, extra)
    } else {
        msg.pow_mod(exp, modulus)
    }
}

fn chinese_remainders_power(c: &BigUint, extra: &SecretKeyExtra) -> BigUint {
    let mut m1 = c.pow_mod(&extra.dmp1, &extra.p);
    let m2 = c.pow_mod(&extra.dmq1, &extra.q);

    while m1 < m2 {
        m1 = m1 + &extra.p;
    }

    let h = (&extra.qinv * (m1 - &m2)) % &extra.p;

    m2 + h * &extra.q
}
