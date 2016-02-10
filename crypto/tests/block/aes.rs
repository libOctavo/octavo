use crypto::block::aes::Aes128;
use crypto::block::{BlockEncrypt, BlockDecrypt};

struct Test {
    key: [u8; 16],
    plaintext: [u8; 16],
    ciphertext: [u8; 16],
}

const TESTS: &'static [Test] = &[Test {
                               key: [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,],
                               plaintext: [0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,],
                               ciphertext: [0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97,],
                           }];

#[test]
fn base_encrypt_test_vectors() {
    for test in TESTS.iter() {
        let c = Aes128::new(test.key);
        let mut dat = [0; 16];

        c.encrypt_block(test.plaintext, &mut dat);
        assert_eq!(test.ciphertext, dat);
    }
}

#[test]
fn base_decrypt_test_vectors() {
    for test in TESTS.iter() {
        let c = Aes128::new(test.key);
        let mut dat = [0; 16];

        c.decrypt_block(test.ciphertext, &mut dat);
        assert_eq!(test.plaintext, dat);
    }
}
