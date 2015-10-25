mod sha224 {
    use test::Bencher;

    use octavo::digest::sha3;

    bench_digest!(bench_16, sha3::Sha3224, 16);
    bench_digest!(bench_128, sha3::Sha3224, 128);
    bench_digest!(bench_256, sha3::Sha3224, 256);
    bench_digest!(bench_512, sha3::Sha3224, 512);
    bench_digest!(bench_1k, sha3::Sha3224, 1024);
    bench_digest!(bench_10k, sha3::Sha3224, 10240);
}

mod sha256 {
    use test::Bencher;

    use octavo::digest::sha3;

    bench_digest!(bench_16, sha3::Sha3256, 16);
    bench_digest!(bench_128, sha3::Sha3256, 128);
    bench_digest!(bench_256, sha3::Sha3256, 256);
    bench_digest!(bench_512, sha3::Sha3256, 512);
    bench_digest!(bench_1k, sha3::Sha3256, 1024);
    bench_digest!(bench_10k, sha3::Sha3256, 10240);
}

mod sha384 {
    use test::Bencher;

    use octavo::digest::sha3;

    bench_digest!(bench_16, sha3::Sha3384, 16);
    bench_digest!(bench_128, sha3::Sha3384, 128);
    bench_digest!(bench_256, sha3::Sha3384, 256);
    bench_digest!(bench_512, sha3::Sha3384, 512);
    bench_digest!(bench_1k, sha3::Sha3384, 1024);
    bench_digest!(bench_10k, sha3::Sha3384, 10240);
}

mod sha512 {
    use test::Bencher;

    use octavo::digest::sha3;

    bench_digest!(bench_16, sha3::Sha3512, 16);
    bench_digest!(bench_128, sha3::Sha3512, 128);
    bench_digest!(bench_256, sha3::Sha3512, 256);
    bench_digest!(bench_512, sha3::Sha3512, 512);
    bench_digest!(bench_1k, sha3::Sha3512, 1024);
    bench_digest!(bench_10k, sha3::Sha3512, 10240);
}
