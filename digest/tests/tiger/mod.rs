use digest::tiger::*;

use utils;

#[test]
fn reference_implementation() {
    let suite = utils::load("./tests/tiger/tiger.toml");

    for test in suite.tests {
        test.test(Tiger::default());
    }
}
