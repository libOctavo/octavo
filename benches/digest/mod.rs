macro_rules! bench_digest {
    ($name:ident, $engine:path, $blocks:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            use octavo::digest::Digest;

            let bs = <$engine>::block_size();

            let mut d = <$engine>::default();
            let data = vec![0; bs];

            b.iter(|| {
                for _ in 0..$blocks {
                    d.update(&data);
                }
            });

            b.bytes = bs as u64 * $blocks;
        }
    };

    ($engine:path) => {
        bench_digest!(_1x_block_size,   $engine,   1);
        bench_digest!(_10x_block_size,  $engine,  10);
        bench_digest!(_100x_block_size, $engine, 100);
    }
}

#[cfg(feature = "md4")] #[macro_use]mod md4;
#[cfg(feature = "md5")] #[macro_use]mod md5;
#[cfg(feature = "sha1")] #[macro_use]mod sha1;
#[cfg(feature = "sha2")] #[macro_use]mod sha2;
#[cfg(feature = "sha3")] #[macro_use]mod sha3;
#[cfg(feature = "tiger")] #[macro_use]mod tiger;
