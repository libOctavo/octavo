extern crate octavo;

use octavo::digest::Digest;
use octavo::digest::sha3::SHA3;
use octavo::digest::md5::MD5;

fn hex<T: AsRef<[u8]>, D: Digest>(data: T, mut digest: D) -> String {
    digest.input(data);

    digest.hex_result()
}

fn main() {
    let data = "Hello World";

    println!("Data: {:?}\n", data);

    println!("MD5:      {}", hex(data, MD5::new()));
    println!("SHA3-224: {}", hex(data, SHA3::new_224()));
    println!("SHA3-256: {}", hex(data, SHA3::new_256()));
    println!("SHA3-384: {}", hex(data, SHA3::new_384()));
    println!("SHA3-512: {}", hex(data, SHA3::new_512()));
}
