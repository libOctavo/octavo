mod sha224 {
    use test::Bencher;

    use octavo::digest::sha3;

    bench_digest!(sha3::Sha3224);
}

mod sha256 {
    use test::Bencher;

    use octavo::digest::sha3;

    bench_digest!(sha3::Sha3256);
}

mod sha384 {
    use test::Bencher;

    use octavo::digest::sha3;

    bench_digest!(sha3::Sha3384);
}

mod sha512 {
    use test::Bencher;

    use octavo::digest::sha3;

    bench_digest!(sha3::Sha3512);
}
