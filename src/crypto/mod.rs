//! Cryptosystems primitives
//!
//! Cryptosystem is a suite of algorithms that describe particular security service, in most cases
//! used for achieving confidentiality. Typically this is set of three algorithms: key generation,
//! encryption function and decryption function.
//!
//! Mathematically it can be described as tuple `(P, C, K, E, D)`, where:
//!
//! - `P` is a set called "plaintext space"
//! - `C` is a set called "ciphertext space"
//! - `K` is a set called "key space"
//! - `E` is a set of functions `e :: k -> p -> c` called "encryption functions"
//! - `D` is a set of functions `d :: k -> c -> p` called "decryption functions"
//!
//! For each `ke ∈ K` there is `kd ∈ K` such that `d(kd, e(ke, p)) = p`. If `kd = ke` then we call
//! that "symmetric cipher" otherwise we call it "asymmetric cipher".
//!
//! In practise we use "asymmetric ciphers" for which computing `kd` from `ke` is computationally
//! hard or impossible.
//!
//! # Kerckhoff's Principle
//!
//! > A cryptosystem should be secure even if everything about the system, except the key, is
//! > public knowledge.
//!
//! This is basic law for moder cryptography. Unfortunately many of people understand this as
//! "keeping cryptosystem hidden is bad". That is big misunderstanding of what that principle
//! states. It is nothing bad to keep cryptosystem in secret, it is yet another obstacle to
//! overcome by eavesdropper, just don't rely on secrecy.

pub mod block;
pub mod stream;
pub mod asymmetric;
