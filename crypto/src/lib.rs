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
//!
//! # Key lengths
//!
//! According to [ECRYPT II][ecrypt] [Yearly Report on Algorithms and Keysizes][d.spa.20] this
//! table presents key-sizes equivalence between types of algorithms:
//!
//! | Symmetric | Factoring Modulus | Discrete Logarithm | Elliptic Curves |
//! | --------: | ----------------: | -----------------: | --------------: |
//! |        48 |               480 |             480/96 |              96 |
//! |        56 |               640 |            640/112 |             112 |
//! |        64 |               816 |            816/128 |             128 |
//! |        80 |              1248 |           1248/160 |             160 |
//! |       112 |              2432 |           2432/224 |             224 |
//! |       128 |              3248 |           3248/256 |             256 |
//! |       160 |              5312 |           5312/320 |             320 |
//! |       192 |              7936 |           7936/384 |             384 |
//! |       256 |             15424 |          15424/512 |             512 |
//!
//! # Security table
//!
//! Levels of security according to [ECRYPT II][ecrypt] [Yearly Report on Algorithms and
//! Keysizes][d.spa.20]
//!
//! | Security Level | Security (bits) | Protection                                                                                            | Comment                                                                    |
//! | -------------- | --------------: | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
//! | 1.             |              32 | Attacks in "real-time" by individuals                                                                 | Only acceptable for auth. tag size                                         |
//! | 2.             |              64 | Very short-term protection against small organizations                                                | Should not be used for confidentiality in new systems                      |
//! | 3.             |              72 | Short-term protection against medium organizations, mediumterm protection against small organizations |                                                                            |
//! | 4.             |              80 | Very short-term protection against agencies, long-term prot. against small organizations              | Smallest general-purpose level, <= 4 years protection                      |
//! | 5.             |              96 | Legacy standard level                                                                                 | 2-key 3DES restricted to ~10^6 plaintext/ciphertexts, ~10 years protection |
//! | 6.             |             112 | Medium-term protection                                                                                | ~20 years protection                                                       |
//! | 7.             |             128 | Long-term protection                                                                                  | Good, generic application-indep. recommendation, ~30 years protection      |
//! | 8.             |             256 | "Foreseeable future"                                                                                  | Good protection against quantum computers unless Shor's algorithm applies  |
//!
//! We recommend at least 128-bit security for general purpose.
//!
//! [ecrypt]: http://www.ecrypt.eu.org/ "European Network of Excellence in Cryptology II "
//! [d.spa.20]: http://www.ecrypt.eu.org/ecrypt2/documents/D.SPA.20.pdf "ECRYPT II Yearly Report on Algorithms and Keysizes"

#![doc(html_logo_url = "https://raw.githubusercontent.com/libOctavo/octavo/master/docs/logo.png",
       html_root_url = "http://libOctavo.github.io/")]

#![allow(many_single_char_names)]

extern crate byteorder;
extern crate generic_array;
extern crate num_bigint as bigint;
extern crate num_traits as num;
extern crate num_integer as integer;
extern crate rand;
extern crate typenum;

pub mod block;
pub mod stream;
pub mod asymmetric;

pub mod prelude {
    pub use block::{BlockEncrypt, BlockDecrypt};
    pub use stream::{StreamEncrypt, StreamDecrypt};
}
