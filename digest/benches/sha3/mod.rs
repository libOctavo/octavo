mod sha224 {
    use test::Bencher;

    use digest::sha3;

    bench_digest!(sha3::Sha224);
}

mod sha256 {
    use test::Bencher;

    use digest::sha3;

    bench_digest!(sha3::Sha256);
}

mod sha384 {
    use test::Bencher;

    use digest::sha3;

    bench_digest!(sha3::Sha384);
}

mod sha512 {
    use test::Bencher;

    use digest::sha3;

    bench_digest!(sha3::Sha512);
}
