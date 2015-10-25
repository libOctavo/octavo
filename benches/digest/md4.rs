use test::Bencher;

use octavo::digest::md4::Md4;

bench_digest!(bench_16, Md4, 16);
bench_digest!(bench_128, Md4, 128);
bench_digest!(bench_256, Md4, 256);
bench_digest!(bench_512, Md4, 512);
bench_digest!(bench_1k, Md4, 1024);
bench_digest!(bench_10k, Md4, 10240);
