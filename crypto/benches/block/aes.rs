mod aes128 {
    use crypto::prelude::*;
    use crypto::block::aes::Aes128;

    use test;

    #[bench]
    fn ecb(bn: &mut test::Bencher) {
        let key = [1u8; 16];
        let input = [2u8; 16];
        let mut output = test::black_box([0; 16]);

        let aes = Aes128::new(key);

        bn.iter(|| aes.encrypt_block(&input, &mut output));

        bn.bytes = input.len() as u64;
    }
}
