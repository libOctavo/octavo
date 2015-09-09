extern crate octavo;

use octavo::digest::Digest;
use octavo::digest::md5::MD5;
use octavo::digest::md4::MD4;
use octavo::digest::ripemd::RIPEMD160;
use octavo::digest::sha1::SHA1;
use octavo::digest::sha2::*;
use octavo::digest::sha3::*;

fn hex<T: AsRef<[u8]>, D: Digest>(data: T, mut digest: D) -> String {
    digest.update(data);

    digest.hex_result()
}

fn main() {
    let data = "octavo";

    println!("Data: {:?}\n", data);

    println!("MD4:       {}", hex(&data, MD4::default()));
    println!("MD5:       {}", hex(&data, MD5::default()));
    println!("RIPEMD160: {}", hex(&data, RIPEMD160::default()));
    println!("SHA1:      {}", hex(&data, SHA1::default()));
    println!("SHA224:    {}", hex(&data, SHA224::default()));
    println!("SHA256:    {}", hex(&data, SHA256::default()));
    println!("SHA384:    {}", hex(&data, SHA384::default()));
    println!("SHA512:    {}", hex(&data, SHA512::default()));
    println!("SHA3-224:  {}", hex(&data, SHA3224::default()));
    println!("SHA3-256:  {}", hex(&data, SHA3256::default()));
    println!("SHA3-384:  {}", hex(&data, SHA3384::default()));
    println!("SHA3-512:  {}", hex(&data, SHA3512::default()));
}
