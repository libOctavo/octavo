extern crate octavo_digest as digest;
extern crate toml;
extern crate rustc_serialize;

#[macro_use]
mod utils;

#[cfg(feature = "blake2")]
mod blake2;
#[cfg(feature = "md5")]
mod md5;
// #[cfg(feature = "ripemd")]
// mod ripemd;
#[cfg(feature = "sha1")]
mod sha1;
#[cfg(feature = "sha2")]
mod sha2;
#[cfg(feature = "sha3")]
mod sha3;
#[cfg(feature = "tiger")]
mod tiger;
#[cfg(feature = "whirlpool")]
mod whirlpool;
