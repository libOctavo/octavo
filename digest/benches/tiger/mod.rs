mod tiger {
    use test::Bencher;

    use digest::tiger::Tiger;

    bench_digest!(Tiger);
}

mod tiger2 {
    use test::Bencher;

    use digest::tiger::Tiger2;

    bench_digest!(Tiger2);
}
