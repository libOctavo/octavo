use byteorder::{ByteOrder, BigEndian};

use crypto::block::blowfish::Blowfish;

fn bcrypt_setup(cost: usize, salt: &[u8], key: &[u8]) -> Blowfish {
    let mut state = Blowfish::init().salted_expand_key(salt, key);

    for _ in 0..(1 << cost) {
        state = state.expand_key(key).expand_key(salt);
    }

    state
}

pub fn bcrypt<S: AsRef<[u8]>, I: AsRef<[u8]>, O: AsMut<[u8]>>(cost: usize,
                                                              salt: S,
                                                              input: I,
                                                              mut output: O) {
    assert_eq!(salt.as_ref().len(), 16);
    assert!(0 < input.as_ref().len() && input.as_ref().len() <= 72);
    assert_eq!(output.as_mut().len(), 24);

    let mut output = output.as_mut();

    let state = bcrypt_setup(cost, salt.as_ref(), input.as_ref());
    let mut ctext = [0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274];
    for (chunk, out) in ctext.chunks_mut(2).zip(output.chunks_mut(8)) {
        for _ in 0..64 {
            let (l, r) = state.encrypt_round((chunk[0], chunk[1]));
            chunk[0] = l;
            chunk[1] = r;
        }
        BigEndian::write_u32(&mut out[0..4], chunk[0]);
        BigEndian::write_u32(&mut out[4..8], chunk[1]);
    }
}
