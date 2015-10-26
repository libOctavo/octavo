#![cfg(feature = "tools")]

extern crate octavo;
extern crate clap;
extern crate rustc_serialize;

use std::io::{self, Read, BufReader};
use std::fs::File;

use clap::{App, Arg};
use rustc_serialize::hex::ToHex;

use octavo::digest::*;

const ENGINES: &'static [&'static str] = &["MD4",
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
                                           "SHA3-512",
                                           "Tiger"];

fn checksum<Eng: Digest + Default>(input: &mut Read) -> String {
    let mut eng = Eng::default();
    let mut buf = vec![0; Eng::block_size()];

    while let Ok(len) = input.read(&mut buf) {
        if len == 0 {
            break;
        }

        eng.update(&buf[..len]);
    }

    let mut result = vec![0; Eng::output_bytes()];
    eng.result(&mut result[..]);

    result.to_hex()
}

macro_rules! digest_for {
    (match $name:ident with $input:ident { $($val:pat => $eng:ty,)+ }) => {
        match $name {
            $($val => checksum::<$eng>(&mut $input),)*
                _ => unreachable!()
        }
    }
}

fn input(name: &str) -> io::Result<Box<Read>> {
    if name == "-" {
        return Ok(Box::new(io::stdin()));
    }

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
                               .help("Files to compute checksums. `-` means STDIN. Defaults to \
                                      STDIN.")
                               .multiple(true))
                      .get_matches();

    let engine_name = matches.value_of("digest").unwrap_or("SHA1");
    let files = matches.values_of("FILE").unwrap_or(vec!["-"]);

    for file in files {
        let mut input = BufReader::new(input(file).unwrap());

        let result = digest_for! {
            match engine_name with input {
                "MD4" => md4::Md4,
                "MD5" => md5::Md5,
                "RIPEMD-160" => ripemd::Ripemd160,
                "SHA1" => sha1::Sha1,
                "SHA-224" => sha2::Sha224,
                "SHA-256" => sha2::Sha256,
                "SHA-384" => sha2::Sha384,
                "SHA-512" => sha2::Sha512,
                "SHA3-224" => sha3::Sha3224,
                "SHA3-256" => sha3::Sha3256,
                "SHA3-384" => sha3::Sha3384,
                "SHA3-512" => sha3::Sha3512,
                "Tiger" => tiger::Tiger,
            }
        };

        println!("{} {}", result, file);
    }
}
