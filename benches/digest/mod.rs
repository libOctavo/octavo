macro_rules! bench_digest {
    ($name:ident, $engine:path, $bytes:expr) => {
        #[bench]
        fn $name(b: &mut Bencher) {
            use octavo::digest::Digest;

            let mut d = <$engine>::default();
            let data = vec![0; $bytes];

            b.iter(|| {
                d.update(&data[..]);
            });

            b.bytes = $bytes as u64;
        }
    };

    ($engine:path) => {
        bench_digest!(bench_block_size, $engine, <$engine>::block_size());
    }
}

#[cfg(feature = "md4")] #[macro_use] mod md4;
#[cfg(feature = "md5")] #[macro_use] mod md5;
#[cfg(feature = "sha1")] #[macro_use] mod sha1;
#[cfg(feature = "sha2")] #[macro_use] mod sha2;
#[cfg(feature = "sha3")] #[macro_use] mod sha3;
#[cfg(feature = "tiger")] #[macro_use] mod tiger;
