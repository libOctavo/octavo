use digest::sha2::Sha384;

use utils;

#[test]
fn shavs_short() {
    let suite = utils::load("./tests/sha2/shavs/sha384/short.toml");

    for test in suite.tests {
        test.test(Sha384::default())
    }
}

#[test]
fn shavs_long() {
    let suite = utils::load("./tests/sha2/shavs/sha384/long.toml");

    for test in suite.tests {
        test.test(Sha384::default())
    }
}
