use octavo::crypto::asymmetric::rsa::Rsa;

use num::bigint::ToBigUint;

fn keys() -> (Rsa, Rsa) {
    Rsa::keypair_from_primes(61.to_biguint().unwrap(),
    53.to_biguint().unwrap(),
    17.to_biguint().unwrap())
}

#[test]
fn encryption() {
    let (public, _) = keys();
    let c = public.crypt(&65.to_biguint().unwrap());

    assert_eq!(c, 2790.to_biguint().unwrap())
}

#[test]
fn decryption() {
    let (_, private) = keys();
    let m = private.crypt(&2790.to_biguint().unwrap());

    assert_eq!(m, 65.to_biguint().unwrap())
}
