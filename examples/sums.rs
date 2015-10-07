extern crate octavo;

use std::io::Write;

use octavo::digest::Digest;
use octavo::digest::md5::Md5;
use octavo::digest::md4::Md4;
use octavo::digest::ripemd::Ripemd160;
use octavo::digest::sha1::Sha1;
use octavo::digest::sha2::*;
use octavo::digest::sha3::*;

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

    println!("Data: {:?}\n", data);

    println!("MD4:       {}", hex(&data, Md4::default()));
    println!("MD5:       {}", hex(&data, Md5::default()));
    println!("RIPEMD160: {}", hex(&data, Ripemd160::default()));
    println!("SHA1:      {}", hex(&data, Sha1::default()));
    println!("SHA224:    {}", hex(&data, Sha224::default()));
    println!("SHA256:    {}", hex(&data, Sha256::default()));
    println!("SHA384:    {}", hex(&data, Sha384::default()));
    println!("SHA512:    {}", hex(&data, Sha512::default()));
    println!("SHA3-224:  {}", hex(&data, Sha3224::default()));
    println!("SHA3-256:  {}", hex(&data, Sha3256::default()));
    println!("SHA3-384:  {}", hex(&data, Sha3384::default()));
    println!("SHA3-512:  {}", hex(&data, Sha3512::default()));
}
