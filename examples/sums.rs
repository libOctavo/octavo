extern crate octavo;

use octavo::digest::Digest;
use octavo::digest::adler32::Adler32;
use octavo::digest::crc32::CRC32;
use octavo::digest::md5::MD5;
use octavo::digest::sha3::*;

fn hex<T: AsRef<[u8]>, D: Digest>(data: T, mut digest: D) -> String {
    digest.update(data);

    digest.hex_result()
}

fn main() {
    let data = "octavo";

    println!("Data: {:?}\n", data);

    println!("Adler32:  {}", hex(&data, Adler32::new()));
    println!("CRC32:    {}", hex(&data, CRC32::new()));
    println!("MD5:      {}", hex(&data, MD5::new()));
    println!("SHA3-224: {}", hex(&data, SHA3224::new()));
    println!("SHA3-256: {}", hex(&data, SHA3256::new()));
    println!("SHA3-384: {}", hex(&data, SHA3384::new()));
    println!("SHA3-512: {}", hex(&data, SHA3512::new()));
}
