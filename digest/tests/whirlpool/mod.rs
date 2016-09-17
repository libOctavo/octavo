use digest::Digest;
use digest::whirlpool::*;

use utils;

#[test]
fn sample() {
    let mut digest = Whirlpool::default();

    digest.update("zażółć gęślą jaźń");

    let mut result = [0; 64];

    digest.result(&mut result[..]);
}

#[test]
fn iso_test_vectors() {
    let suite = utils::load("./tests/whirlpool/iso.toml");

    for test in suite.tests {
        test.test(Whirlpool::default());
    }
}
