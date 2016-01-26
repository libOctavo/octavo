use digest::sha2::Sha512;

use utils;

#[test]
fn shavs_short() {
    let suite = utils::load("./tests/sha2/shavs/sha512/short.toml");

    for test in suite.tests {
        test.test(Sha512::default())
    }
}

#[test]
fn shavs_long() {
    let suite = utils::load("./tests/sha2/shavs/sha512/long.toml");

    for test in suite.tests {
        test.test(Sha512::default())
    }
}
