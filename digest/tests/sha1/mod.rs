use digest::sha1::Sha1;

use utils;

#[test]
fn shavs_short() {
    let suite = utils::load("./tests/sha1/shavs/short.toml");

    for test in suite.tests {
        test.test(Sha1::default())
    }
}

#[test]
fn shavs_long() {
    let suite = utils::load("./tests/sha1/shavs/long.toml");

    for test in suite.tests {
        test.test(Sha1::default())
    }
}
