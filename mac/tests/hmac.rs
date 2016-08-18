extern crate octavo_mac as mac;
extern crate octavo_digest as digest;

mod md5 {
    use mac::Mac;
    use mac::hmac::Hmac;

    use digest::prelude::*;

    #[test]
    fn rfc2104_test_vector_1() {
        let mut hmac_md5 = Hmac::<Md5>::new(&[0x0b; 16]);
        hmac_md5.update("Hi There");

        let mut output = [0; 16];

        hmac_md5.result(&mut output);

        assert_eq!([0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15,
                    0x8b, 0xfc, 0x9d],
                   output);
    }

    #[test]
    fn rfc2104_test_vector_2() {
        let mut hmac_md5 = Hmac::<Md5>::new("Jefe");
        hmac_md5.update("what do ya want for nothing?");

        let mut output = [0; 16];

        hmac_md5.result(&mut output);

        assert_eq!([0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03, 0xea, 0xa8, 0x6e, 0x31, 0x0a,
                    0x5d, 0xb7, 0x38],
                   output);
    }

    #[test]
    fn rfc2104_test_vector_3() {
        let mut hmac_md5 = Hmac::<Md5>::new(&[0xaa; 16]);
        for _ in 0..50 {
            hmac_md5.update(&[0xdd]);
        }

        let mut output = [0; 16];

        hmac_md5.result(&mut output);

        assert_eq!([0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88, 0xdb, 0xb8, 0xc7, 0x33, 0xf0,
                    0xe8, 0xb3, 0xf6],
                   output);
    }
}
