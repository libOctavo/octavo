use digest::sha2::Sha224;

use utils;

#[test]
fn shavs_short() {
    let suite = utils::load("./tests/sha2/shavs/sha224/short.toml");

    for test in suite.tests {
        test.test(Sha224::default())
    }
}

#[test]
fn shavs_long() {
    let suite = utils::load("./tests/sha2/shavs/sha224/long.toml");

    for test in suite.tests {
        test.test(Sha224::default())
    }
}
