extern crate octavo;

use std::io::Write;

use octavo::digest::prelude::*;

fn hex<T: AsRef<[u8]>, D: Digest>(data: T, mut digest: D) -> String {
    digest.update(data);

    let mut result = vec![0; D::output_bytes()];

    digest.result(&mut result[..]);

    let mut out = vec![0; D::output_bytes() * 2];

    for byte in result {
        write!(&mut out, "{:02x}", byte).unwrap();
    }

    String::from_utf8(out).unwrap()
}

fn main() {
    let data = "octavo";

    println!("MD5:         {}", hex(&data, Md5::default()));
    println!("RIPEMD-160:  {}", hex(&data, Ripemd160::default()));
    println!("SHA-1:       {}", hex(&data, Sha1::default()));
    println!("SHA-224:     {}", hex(&data, sha2::Sha224::default()));
    println!("SHA-256:     {}", hex(&data, sha2::Sha256::default()));
    println!("SHA-384:     {}", hex(&data, sha2::Sha384::default()));
    println!("SHA-512:     {}", hex(&data, sha2::Sha512::default()));
    println!("SHA-512/224: {}", hex(&data, sha2::Sha512224::default()));
    println!("SHA-512/256: {}", hex(&data, sha2::Sha512256::default()));
    println!("SHA3-224:    {}", hex(&data, sha3::Sha224::default()));
    println!("SHA3-256:    {}", hex(&data, sha3::Sha256::default()));
    println!("SHA3-384:    {}", hex(&data, sha3::Sha384::default()));
    println!("SHA3-512:    {}", hex(&data, sha3::Sha512::default()));
    println!("Blake2s128:  {}", hex(&data, blake2::Blake2s128::default()));
    println!("Blake2s160:  {}", hex(&data, blake2::Blake2s160::default()));
    println!("Blake2s224:  {}", hex(&data, blake2::Blake2s224::default()));
    println!("Blake2s256:  {}", hex(&data, blake2::Blake2s256::default()));
    println!("Blake2b160:  {}", hex(&data, blake2::Blake2b160::default()));
    println!("Blake2b256:  {}", hex(&data, blake2::Blake2b256::default()));
    println!("Blake2b384:  {}", hex(&data, blake2::Blake2b384::default()));
    println!("Blake2b512:  {}", hex(&data, blake2::Blake2b512::default()));
    println!("Tiger:       {}", hex(&data, tiger::Tiger::default()));
    println!("Tiger2:      {}", hex(&data, tiger::Tiger2::default()));
    println!("WHIRLPOOL:   {}", hex(&data, Whirlpool::default()));
}
