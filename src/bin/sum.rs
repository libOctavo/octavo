#![cfg(feature = "tools")]

extern crate octavo;
extern crate clap;
extern crate rustc_serialize;

use std::io::{self, Read};
use std::fs::File;

use clap::{App, Arg};
use rustc_serialize::hex::ToHex;

use octavo::digest::*;

const ENGINES: &'static [&'static str] = &[
    "MD4",
    "MD5",
    "RIPEMD-160",
    "SHA1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512"
];

fn checksum<Eng: Digest + Default>(input: &mut Read, buffer_size: usize) -> String {
    let mut eng = Eng::default();
    let mut buf = vec![0; buffer_size];

    while let Ok(len) = input.read(&mut buf[..]) {
        if len == 0 { break }

        eng.update(&buf[..len]);
    }

    let mut result = vec![0; Eng::output_bytes()];
    eng.result(&mut result[..]);

    result[..].to_hex()
}

macro_rules! digest_for {
    (match $name:ident with $size:expr, $input:ident { $($val:pat => $eng:ty,)+ }) => {
        match $name {
            $($val => checksum::<$eng>(&mut $input, $size),)*
                _ => unreachable!()
        }
    }
}

fn input(name: &str) -> io::Result<Box<Read>> {
    if name == "-" { return Ok(Box::new(io::stdin())); }

    Ok(Box::new(try!(File::open(name))))
}

fn main() {
    let matches = App::new("sum")
        .arg(Arg::with_name("digest")
             .help("Select checksum engine. Defaults to SHA1.")
             .possible_values(ENGINES)
             .short("D")
             .long("digest")
             .global(true)
             .empty_values(false)
             .takes_value(true))
        .arg(Arg::with_name("FILE")
             .help("Files to compute checksums. `-` means STDIN. Defaults to STDIN.")
             .multiple(true))
        .arg(Arg::with_name("buffer size")
             .help("Size of read buffer in bytes. Defaults to 1MiB.")
             .takes_value(true)
             .long("buffer-size"))
        .get_matches();

    let engine_name = matches.value_of("digest").unwrap_or("SHA1");
    let files = matches.values_of("FILE").unwrap_or(vec!["-"]);
    let buffer_size = matches.value_of("buffer size")
        .and_then(|val| val.parse().ok())
        .unwrap_or(1024 * 1024);

    for file in files {
        let mut input: Box<Read> = input(file).unwrap();

        let result = digest_for! {
            match engine_name with buffer_size, input {
                "MD4" => md4::MD4,
                "MD5" => md5::MD5,
                "RIPEMD-160" => ripemd::RIPEMD160,
                "SHA1" => sha1::SHA1,
                "SHA-224" => sha2::SHA224,
                "SHA-256" => sha2::SHA256,
                "SHA-384" => sha2::SHA384,
                "SHA-512" => sha2::SHA512,
                "SHA3-224" => sha3::SHA3224,
                "SHA3-256" => sha3::SHA3256,
                "SHA3-384" => sha3::SHA3384,
                "SHA3-512" => sha3::SHA3512,
            }
        };

        println!("{} {}", result, file);
    }
}
