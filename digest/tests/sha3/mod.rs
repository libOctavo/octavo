mod sha224 {
    use digest::sha3::Sha224;

    use utils;

    #[test]
    fn simple_test_vectors() {
        let suite = utils::load("./tests/sha3/sha224.toml");

        for test in suite.tests {
            test.test(Sha224::default());
        }
    }
}

mod sha256 {
    use digest::sha3::Sha256;

    use utils;

    #[test]
    fn simple_test_vectors() {
        let suite = utils::load("./tests/sha3/sha256.toml");

        for test in suite.tests {
            test.test(Sha256::default());
        }
    }
}

mod sha384 {
    use digest::sha3::Sha384;

    use utils;

    #[test]
    fn simple_test_vectors() {
        let suite = utils::load("./tests/sha3/sha384.toml");

        for test in suite.tests {
            test.test(Sha384::default());
        }
    }
}

mod sha512 {
    use digest::sha3::Sha512;

    use utils;

    #[test]
    fn simple_test_vectors() {
        let suite = utils::load("./tests/sha3/sha512.toml");

        for test in suite.tests {
            test.test(Sha512::default());
        }
    }
}
