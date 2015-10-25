use test::Bencher;

use octavo::digest::tiger::Tiger;

bench_digest!(bench_16, Tiger, 16);
bench_digest!(bench_128, Tiger, 128);
bench_digest!(bench_256, Tiger, 256);
bench_digest!(bench_512, Tiger, 512);
bench_digest!(bench_1k, Tiger, 1024);
bench_digest!(bench_10k, Tiger, 10240);
