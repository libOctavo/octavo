use digest::sha2::Sha256;

use utils;

#[test]
fn shavs_short() {
    let suite = utils::load("./tests/sha2/shavs/sha256/short.toml");

    for test in suite.tests {
        test.test(Sha256::default())
    }
}

#[test]
fn shavs_long() {
    let suite = utils::load("./tests/sha2/shavs/sha256/long.toml");

    for test in suite.tests {
        test.test(Sha256::default())
    }
}
