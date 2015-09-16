use num::bigint::{
    BigUint,
    RandBigInt
};
use num::One;

use rand::Rng;

use utils::modular::Inverse;
use utils::modular::power::Power;
use utils::primes::generate_prime;

pub struct SecretKeyExtra {
    p: BigUint,
    q: BigUint,
    dmp1: BigUint,
    dmq1: BigUint,
    qinv: BigUint
}

pub enum RSA {
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
    }
}

pub type KeyPair = (RSA, RSA);

impl RSA {
    pub fn keypair_from_primes<P, Q, E>(p: P, q: Q, e: E) -> KeyPair
        where P: Into<BigUint>, Q: Into<BigUint>, E: Into<BigUint> {
            let (p, q, e) = (p.into(), q.into(), e.into());

            let n = &p * &q;
            let fin = &n - (&p + &q - BigUint::one());

            let d = e.inverse(&fin).expect("e is irreversible in ring phi(pq) - error");

            let public = RSA::Public { n: n.clone(), e: e };
            let extra = SecretKeyExtra {
                dmp1: &d % (&p - BigUint::one()),
                dmq1: &d % (&q - BigUint::one()),
                qinv: q.inverse(&p).unwrap(),
                p: p,
                q: q,
            };
            let private = RSA::Private { n: n, d: d, extra: Some(extra)};

            (public, private)
        }

    pub fn generate_keypair<G, T>(mut rng: G, e: T, bits: usize) -> KeyPair
        where G: Rng + RandBigInt, T: Into<BigUint> {
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
        match self {
            &RSA::Public { .. } => true,
            _ => false
        }
    }

    pub fn is_private(&self) -> bool {
        match self {
            &RSA::Private { .. } => true,
            _ => false
        }
    }

    pub fn crypt(&self, msg: &BigUint) -> BigUint {
        match self {
            &RSA::Private { ref n, ref d, ref extra } => crypt(msg, n, d, extra.as_ref()),
            &RSA::Public { ref n, ref e } => crypt(msg, n, e, None),
        }
    }
}

fn crypt(msg: &BigUint,
                 n: &BigUint,
                 d: &BigUint,
                 extra: Option<&SecretKeyExtra>) -> BigUint {
    if let Some(ref extra) = extra {
        chinese_reminders_power(msg, extra)
    } else {
        msg.pow_mod(d, n)
    }
}

fn chinese_reminders_power(msg: &BigUint, extra: &SecretKeyExtra) -> BigUint {
    let mut m1 = msg.pow_mod(&extra.dmp1, &extra.p);
    let m2 = msg.pow_mod(&extra.dmq1, &extra.q);

    while m1 < m2 {
        m1 = m1 + &extra.p;
    }

    let h = &extra.qinv * (m1 - &m2);

    m2 + h * &extra.q
}

#[cfg(test)]
mod tests {
    use super::RSA;

    use num::bigint::{BigUint, ToBigUint};

    fn keys() -> (RSA, RSA) {
        RSA::keypair_from_primes(
            61.to_biguint().unwrap(),
            53.to_biguint().unwrap(),
            17.to_biguint().unwrap())
    }

    fn message() -> BigUint { 65.to_biguint().unwrap() }

    #[test]
    fn test_encryption() {
        let (public, _) = keys();

        let c = public.crypt(&message());

        assert_eq!(c, 2790.to_biguint().unwrap())
    }
}
