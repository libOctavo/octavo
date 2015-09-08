use std::io::Write;

use digest::Digest;
use mac::MAC;

pub struct HMAC<T: Digest + Default> {
    digest: T,
    key: Vec<u8>,
}

impl<T: Digest + Default> HMAC<T> {
    pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
        Self::with_digest(key.as_ref(), Default::default())
    }

    pub fn with_digest(key: &[u8], mut digest: T) -> Self {
        let key = Self::expand_key(key);
        let ikey: Vec<_> = key.iter().map(|&b| b ^ 0x36).collect();

        digest.update(&ikey);

        HMAC {
            digest: digest,
            key: key,
        }
    }

    fn expand_key(key: &[u8]) -> Vec<u8> {
        let bs = T::block_size();
        let mut exp_key = vec![0; bs];

        if key.len() <= bs {
            exp_key.write(key).unwrap();
        } else {
            let mut digest = T::default();
            digest.update(key);
            digest.result(&mut exp_key[..bs]);
        }

        exp_key
    }

}

impl<T: Digest + Default> MAC for HMAC<T> {
    fn update<D: AsRef<[u8]>>(&mut self, data: D) {
        self.digest.update(data)
    }

    fn output_bits() -> usize { T::output_bits() }
    fn block_size() -> usize { T::block_size() }

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
    use super::*;
    use mac::MAC;
    use digest::Digest;
    use digest::md5::MD5;

    #[test]
    fn test_empty_strings() {
        let mut hmac_md5 = HMAC::<MD5>::new("");
        hmac_md5.update("");

        assert_eq!("74e6f7298a9c2d168935f58c001bad88", hmac_md5.hex_result());
    }
}
