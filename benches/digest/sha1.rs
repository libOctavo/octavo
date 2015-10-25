use test::Bencher;

use octavo::digest::sha1::Sha1;

bench_digest!(bench_16, Sha1, 16);
bench_digest!(bench_128, Sha1, 128);
bench_digest!(bench_256, Sha1, 256);
bench_digest!(bench_512, Sha1, 512);
bench_digest!(bench_1k, Sha1, 1024);
bench_digest!(bench_10k, Sha1, 10240);
