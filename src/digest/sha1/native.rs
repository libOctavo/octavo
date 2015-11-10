use byteorder::{ByteOrder, BigEndian};

macro_rules! round {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $word:expr, $f:expr, $k:expr) => {
            $e = $a.rotate_left(5)
                   .wrapping_add($f)
                   .wrapping_add($e)
                   .wrapping_add($k)
                   .wrapping_add($word);
            $b = $b.rotate_left(30);
    };

    (A: $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $word:expr) => {
        round!($a, $b, $c, $d, $e, $word, $d ^ ($b & ($c ^ $d)), 0x5a827999);
    };
    (B: $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $word:expr) => {
        round!($a, $b, $c, $d, $e, $word, $b ^ $c ^ $d, 0x6ed9eba1);
    };
    (C: $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $word:expr) => {
        round!($a, $b, $c, $d, $e, $word, ($b & $c) | ($d & ($b | $c)), 0x8f1bbcdc);
    };
    (D: $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $word:expr) => {
        round!($a, $b, $c, $d, $e, $word, $b ^ $c ^ $d, 0xca62c1d6);
    };
}

pub fn compress(state: &mut [u32], data: &[u8]) {
    let mut words = [0u32; 80];

    for (c, w) in data.chunks(4).zip(words.iter_mut()) {
        *w = BigEndian::read_u32(c);
    }
    for i in 16..80 {
        words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    round!(A: a, b, c, d, e, words[0]);
    round!(A: e, a, b, c, d, words[1]);
    round!(A: d, e, a, b, c, words[2]);
    round!(A: c, d, e, a, b, words[3]);
    round!(A: b, c, d, e, a, words[4]);

    round!(A: a, b, c, d, e, words[5]);
    round!(A: e, a, b, c, d, words[6]);
    round!(A: d, e, a, b, c, words[7]);
    round!(A: c, d, e, a, b, words[8]);
    round!(A: b, c, d, e, a, words[9]);

    round!(A: a, b, c, d, e, words[10]);
    round!(A: e, a, b, c, d, words[11]);
    round!(A: d, e, a, b, c, words[12]);
    round!(A: c, d, e, a, b, words[13]);
    round!(A: b, c, d, e, a, words[14]);

    round!(A: a, b, c, d, e, words[15]);
    round!(A: e, a, b, c, d, words[16]);
    round!(A: d, e, a, b, c, words[17]);
    round!(A: c, d, e, a, b, words[18]);
    round!(A: b, c, d, e, a, words[19]);

    round!(B: a, b, c, d, e, words[20]);
    round!(B: e, a, b, c, d, words[21]);
    round!(B: d, e, a, b, c, words[22]);
    round!(B: c, d, e, a, b, words[23]);
    round!(B: b, c, d, e, a, words[24]);

    round!(B: a, b, c, d, e, words[25]);
    round!(B: e, a, b, c, d, words[26]);
    round!(B: d, e, a, b, c, words[27]);
    round!(B: c, d, e, a, b, words[28]);
    round!(B: b, c, d, e, a, words[29]);

    round!(B: a, b, c, d, e, words[30]);
    round!(B: e, a, b, c, d, words[31]);
    round!(B: d, e, a, b, c, words[32]);
    round!(B: c, d, e, a, b, words[33]);
    round!(B: b, c, d, e, a, words[34]);

    round!(B: a, b, c, d, e, words[35]);
    round!(B: e, a, b, c, d, words[36]);
    round!(B: d, e, a, b, c, words[37]);
    round!(B: c, d, e, a, b, words[38]);
    round!(B: b, c, d, e, a, words[39]);

    round!(C: a, b, c, d, e, words[40]);
    round!(C: e, a, b, c, d, words[41]);
    round!(C: d, e, a, b, c, words[42]);
    round!(C: c, d, e, a, b, words[43]);
    round!(C: b, c, d, e, a, words[44]);

    round!(C: a, b, c, d, e, words[45]);
    round!(C: e, a, b, c, d, words[46]);
    round!(C: d, e, a, b, c, words[47]);
    round!(C: c, d, e, a, b, words[48]);
    round!(C: b, c, d, e, a, words[49]);

    round!(C: a, b, c, d, e, words[50]);
    round!(C: e, a, b, c, d, words[51]);
    round!(C: d, e, a, b, c, words[52]);
    round!(C: c, d, e, a, b, words[53]);
    round!(C: b, c, d, e, a, words[54]);

    round!(C: a, b, c, d, e, words[55]);
    round!(C: e, a, b, c, d, words[56]);
    round!(C: d, e, a, b, c, words[57]);
    round!(C: c, d, e, a, b, words[58]);
    round!(C: b, c, d, e, a, words[59]);

    round!(D: a, b, c, d, e, words[60]);
    round!(D: e, a, b, c, d, words[61]);
    round!(D: d, e, a, b, c, words[62]);
    round!(D: c, d, e, a, b, words[63]);
    round!(D: b, c, d, e, a, words[64]);

    round!(D: a, b, c, d, e, words[65]);
    round!(D: e, a, b, c, d, words[66]);
    round!(D: d, e, a, b, c, words[67]);
    round!(D: c, d, e, a, b, words[68]);
    round!(D: b, c, d, e, a, words[69]);

    round!(D: a, b, c, d, e, words[70]);
    round!(D: e, a, b, c, d, words[71]);
    round!(D: d, e, a, b, c, words[72]);
    round!(D: c, d, e, a, b, words[73]);
    round!(D: b, c, d, e, a, words[74]);

    round!(D: a, b, c, d, e, words[75]);
    round!(D: e, a, b, c, d, words[76]);
    round!(D: d, e, a, b, c, words[77]);
    round!(D: c, d, e, a, b, words[78]);
    round!(D: b, c, d, e, a, words[79]);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}
