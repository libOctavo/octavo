mod sha224 {
    use test::Bencher;

    use octavo::digest::sha2;

    bench_digest!(sha2::Sha224);
}

mod sha256 {
    use test::Bencher;

    use octavo::digest::sha2;

    bench_digest!(sha2::Sha256);
}

mod sha384 {
    use test::Bencher;

    use octavo::digest::sha2;

    bench_digest!(sha2::Sha384);
}

mod sha512 {
    use test::Bencher;

    use octavo::digest::sha2;

    bench_digest!(sha2::Sha512);
}
