use digest::Digest;
use mac::Mac;

pub struct Hmac<T: Digest + Default> {
    digest: T,
    key: Vec<u8>,
}

impl<T: Digest + Default> Hmac<T> {
    pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
        Self::with_digest(key.as_ref(), Default::default())
    }

    pub fn with_digest(key: &[u8], mut digest: T) -> Self {
        let key = Self::expand_key(key);
        let ikey: Vec<_> = key.iter().map(|&b| b ^ 0x36).collect();

        digest.update(&ikey);

        Hmac {
            digest: digest,
            key: key,
        }
    }

    fn expand_key(key: &[u8]) -> Vec<u8> {
        let bs = T::block_size();
        let mut exp_key = vec![0; bs];

        if key.len() <= bs {
            for i in 0..key.len() {
                exp_key[i] = key[i];
            }
        } else {
            let mut digest = T::default();
            digest.update(key);
            digest.result(&mut exp_key[..]);
        }

        exp_key
    }

}

impl<T: Digest + Default> Mac for Hmac<T> {
    fn update<D: AsRef<[u8]>>(&mut self, data: D) {
        self.digest.update(data)
    }

    fn output_bits() -> usize {
        T::output_bits()
    }
    fn block_size() -> usize {
        T::block_size()
    }

    fn result<O: AsMut<[u8]>>(mut self, mut output: O) {
        self.digest.result(output.as_mut());
        self.digest = T::default();

        let okey: Vec<_> = self.key.iter().map(|&b| b ^ 0x5c).collect();

        self.digest.update(okey);
        self.digest.update(output.as_mut());
        self.digest.result(output.as_mut());
    }
}

#[cfg(test)]
mod tests {
    mod md5 {
        use mac::Mac;
        use mac::hmac::Hmac;

        use digest::md5::Md5;

        #[test]
        fn rfc2104_test_vector_1() {
            let mut hmac_md5 = Hmac::<Md5>::new(&[0x0b; 16]);
            hmac_md5.update("Hi There");

            let mut output = [0; 16];

            hmac_md5.result(&mut output);

            assert_eq!([0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8,
                        0x15, 0x8b, 0xfc, 0x9d],
                       output);
        }

        #[test]
        fn rfc2104_test_vector_2() {
            let mut hmac_md5 = Hmac::<Md5>::new("Jefe");
            hmac_md5.update("what do ya want for nothing?");

            let mut output = [0; 16];

            hmac_md5.result(&mut output);

            assert_eq!([0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03, 0xea, 0xa8, 0x6e, 0x31,
                        0x0a, 0x5d, 0xb7, 0x38],
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

            assert_eq!([0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88, 0xdb, 0xb8, 0xc7, 0x33,
                        0xf0, 0xe8, 0xb3, 0xf6],
                       output);
        }
    }

    mod quickcheck {
        use quickcheck::quickcheck;

        use openssl::crypto::hash::Type;
        use openssl::crypto::hmac::hmac;

        use digest::*;

        use mac::Mac;
        use mac::hmac::Hmac;

        macro_rules! quickcheck {
            ($name:ident => $octavo:ty, $openssl:path) => {
                #[test]
                fn $name() {
                    fn prop(key:Vec<u8>, data: Vec<u8>) -> bool {
                        let octavo = {
                            let mut dig = Hmac::<$octavo>::new(&key);
                            let mut res = vec![0; <$octavo>::output_bytes()];

                            dig.update(&data);
                            dig.result(&mut res[..]);
                            res
                        };
                        let openssl = hmac($openssl, &key, &data);

                        octavo == openssl
                    }

                    quickcheck(prop as fn(Vec<u8>, Vec<u8>) -> bool)
                }
            }
        }

        quickcheck!(md5    => md5::Md5,     Type::MD5);
        quickcheck!(sha1   => sha1::Sha1,   Type::SHA1);
        quickcheck!(sha224 => sha2::Sha224, Type::SHA224);
        quickcheck!(sha256 => sha2::Sha256, Type::SHA256);
        quickcheck!(sha384 => sha2::Sha384, Type::SHA384);
        quickcheck!(sha512 => sha2::Sha512, Type::SHA512);
    }
}
