use std::io::Write;

use digest::Digest;
use mac::MAC;

pub struct HMAC<T: Digest> {
    digest: T,
    key: Vec<u8>,
}

fn expand_key<T: Digest>(key: &[u8]) -> Vec<u8> {
    let bs = T::block_size();
    let mut exp_key = vec![0; bs];

    if key.len() <= bs {
        exp_key.write(key).unwrap();
    } else {
        let mut dig = T::new();
        dig.update(key);
        dig.result(&mut exp_key[..bs]);
    }

    exp_key
}

impl<T: Digest> HMAC<T> {
    fn with_digest(key: &[u8], mut digest: T) -> Self {
        let key = expand_key::<T>(key);
        let ikey: Vec<_> = key.iter().map(|&b| b ^ 0x36).collect();

        digest.update(&ikey);

        HMAC {
            digest: digest,
            key: key,
        }
    }
}

impl<T: Digest> MAC for HMAC<T> {
    fn new<K: AsRef<[u8]>>(key: K) -> Self {
        Self::with_digest(key.as_ref(), Default::default())
    }

    fn update<D: AsRef<[u8]>>(&mut self, data: D) {
        self.digest.update(data)
    }

    fn output_bits() -> usize { T::output_bits() }
    fn block_size() -> usize { T::block_size() }

    fn result<O: AsMut<[u8]>>(self, mut output: O) {
        self.digest.result(output.as_mut());
        let mut dig = T::new();

        let okey: Vec<_> = self.key.iter().map(|&b| b ^ 0x5c).collect();

        dig.update(okey);
        dig.update(output.as_mut());
        dig.result(output.as_mut());
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
