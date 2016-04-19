use digest::whirlpool::*;

use utils;

#[test]
fn iso_test_vectors() {
    let suite = utils::load("./tests/whirlpool/iso.toml");

    for test in suite.tests {
        test.test(Whirlpool::default());
    }
}
