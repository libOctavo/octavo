#![cfg(feature = "tools")]

extern crate octavo;
extern crate clap;

use std::io::{self, Read};

use octavo::digest::{self, Digest};

fn main() {
    let mut buf = [0; 1024 * 1024];
    let mut engine = digest::sha1::SHA1::default();
    let mut input = io::stdin();

    while let Ok(len) = input.read(&mut buf[..]) {
        if len == 0 { break }

        engine.update(&buf[..len]);
    }

    let mut result = vec![0; digest::sha1::SHA1::output_bytes()];
    engine.result(&mut result[..]);

    for byte in result {
        print!("{:02x}", byte);
    }
    println!(" -");
}
