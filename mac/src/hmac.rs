use digest::Digest;
use generic_array::GenericArray;

use Mac;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

pub struct Hmac<T: Digest> {
    inner: T,
    outer: T,
}

impl<T: Digest + Default> Hmac<T> {
    pub fn new<K: AsRef<[u8]>>(key: K) -> Self {
        Self::with_digest(key.as_ref(), Default::default())
    }
}

impl<T: Digest> Hmac<T> {
    pub fn with_digest(key: &[u8], digest: T) -> Self {
        let mut inner = digest.clone();
        let mut outer = digest.clone();

        let key = Self::expand_key(key, digest);
        for byte in key.iter() {
            inner.update(&[byte ^ IPAD]);
            outer.update(&[byte ^ OPAD]);
        }

        Hmac {
            inner: inner,
            outer: outer,
        }
    }

    fn expand_key(key: &[u8], mut digest: T) -> GenericArray<u8, T::BlockSize> {
        let bs = T::block_size();
        let mut exp_key = GenericArray::new();

        if key.len() <= bs {
            for i in 0..key.len() {
                exp_key[i] = key[i];
            }
        } else {
            digest.update(key);
            digest.result(&mut exp_key[..]);
        }

        exp_key
    }
}

impl<T: Digest> Mac for Hmac<T> {
    fn update<D: AsRef<[u8]>>(&mut self, data: D) {
        self.inner.update(data)
    }

    fn output_bits() -> usize {
        T::output_bits()
    }
    fn block_size() -> usize {
        T::block_size()
    }

    fn result<O: AsMut<[u8]>>(mut self, mut output: O) {
        self.inner.result(output.as_mut());

        self.outer.update(output.as_mut());
        self.outer.result(output.as_mut());
    }
}
