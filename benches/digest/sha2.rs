mod sha224 {
    use test::Bencher;

    use octavo::digest::sha2;

    bench_digest!(bench_16, sha2::Sha224, 16);
    bench_digest!(bench_128, sha2::Sha224, 128);
    bench_digest!(bench_256, sha2::Sha224, 256);
    bench_digest!(bench_512, sha2::Sha224, 512);
    bench_digest!(bench_1k, sha2::Sha224, 1024);
    bench_digest!(bench_10k, sha2::Sha224, 10240);
}

mod sha256 {
    use test::Bencher;

    use octavo::digest::sha2;

    bench_digest!(bench_16, sha2::Sha256, 16);
    bench_digest!(bench_128, sha2::Sha256, 128);
    bench_digest!(bench_256, sha2::Sha256, 256);
    bench_digest!(bench_512, sha2::Sha256, 512);
    bench_digest!(bench_1k, sha2::Sha256, 1024);
    bench_digest!(bench_10k, sha2::Sha256, 10240);
}

mod sha384 {
    use test::Bencher;

    use octavo::digest::sha2;

    bench_digest!(bench_16, sha2::Sha384, 16);
    bench_digest!(bench_128, sha2::Sha384, 128);
    bench_digest!(bench_256, sha2::Sha384, 256);
    bench_digest!(bench_512, sha2::Sha384, 512);
    bench_digest!(bench_1k, sha2::Sha384, 1024);
    bench_digest!(bench_10k, sha2::Sha384, 10240);
}

mod sha512 {
    use test::Bencher;

    use octavo::digest::sha2;

    bench_digest!(bench_16, sha2::Sha512, 16);
    bench_digest!(bench_128, sha2::Sha512, 128);
    bench_digest!(bench_256, sha2::Sha512, 256);
    bench_digest!(bench_512, sha2::Sha512, 512);
    bench_digest!(bench_1k, sha2::Sha512, 1024);
    bench_digest!(bench_10k, sha2::Sha512, 10240);
}
