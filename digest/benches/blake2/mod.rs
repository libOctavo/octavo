mod blake2s {
    use test::Bencher;

    use digest::blake2::Blake2s256;

    bench_digest!(Blake2s256);
}

mod blake2b {
    use test::Bencher;

    use digest::blake2::Blake2b512;

    bench_digest!(Blake2b512);
}
