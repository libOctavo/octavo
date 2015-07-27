use std::fmt;
use std::ops::{
    Add,
    BitXor
};

pub trait Feistel<T, K>
where T: Add<Output=T> + BitXor<Output=T> + fmt::Debug {
    fn round_function(input: &T, key: &K) -> T;

    fn round(input: (T, T), key: &K) -> (T, T) {
        let (l, r) = input;
        let a = l ^ Self::round_function(&r, key);
        (r, a)
    }

    fn encrypt<S: AsRef<[K]>>(mut input: (T, T), keys: S) -> (T, T) {
        let keys = keys.as_ref();

        for key in keys {
            input = Self::round(input, key);
        }

        input
    }

    fn decrypt<S: AsRef<[K]>>(input: (T, T), keys: S) -> (T, T) {
        swap(Self::crypt(swap(input), keys))
    }
}

fn swap<T>(t: (T, T)) -> (T, T) {
    (t.1, t.0)
}

#[cfg(test)]
mod test {
    use super::*;

    struct Test;

    impl Feistel<u8, u8> for Test {
        fn round_function(input: &u8, key: &u8) -> u8 {
            input + key
        }
    }

    #[test]
    fn simple_network() {
        let keys = [6; 3];
        let data = (4, 2);

        let crypto = Test::encrypt(data, keys);

        assert_eq!(Test::decrypt(crypto, keys), (4, 2));
    }
}
