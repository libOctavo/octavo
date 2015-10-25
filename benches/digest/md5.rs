use test::Bencher;

use octavo::digest::md5::Md5;

bench_digest!(bench_16, Md5, 16);
bench_digest!(bench_128, Md5, 128);
bench_digest!(bench_256, Md5, 256);
bench_digest!(bench_512, Md5, 512);
bench_digest!(bench_1k, Md5, 1024);
bench_digest!(bench_10k, Md5, 10240);
