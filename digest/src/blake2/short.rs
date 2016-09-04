use wrapping::*;

const BLAKE2S_INIT: [w32; 8] = [W(0x6a09e667),
                                W(0xbb67ae85),
                                W(0x3c6ef372),
                                W(0xa54ff53a),
                                W(0x510e527f),
                                W(0x9b05688c),
                                W(0x1f83d9ab),
                                W(0x5be0cd19)];

const R1: u32 = 16;
const R2: u32 = 12;
const R3: u32 = 8;
const R4: u32 = 7;

#[derive(Copy, Clone, Debug)]
struct State {
    h: [w32; 8],
}

impl State {
    fn new(key_size: u8, size: u8) -> Self {
        let mut state = BLAKE2S_INIT;

        state[0] ^= W(0x01010000 | ((key_size as u32) << 8) | (size as u32));

        State { h: state }
    }

    #[inline]
    fn compress(&mut self, input: &[u8], len: Length<u32>, last: bool) {
        debug_assert!(input.len() % 16 == 0);

        let mut message = [W(0); 16];
        for (word, chunk) in message.iter_mut().zip(input.chunks(4)) {
            *word = W(LittleEndian::read_u32(chunk));
        }

        let mut v = [W(0); 16];
        for (v, state) in v.iter_mut().zip(self.h.iter().chain(&BLAKE2S_INIT)) {
            *v = *state;
        }
        v[12].0 ^= len.0;
        v[13].0 ^= len.1;
        if last {
            v[14] = !v[14];
        }

        for sigma in &SIGMA {
            G!(v, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]]);
            G!(v, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]]);
            G!(v, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]]);
            G!(v, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]]);

            G!(v, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]]);
            G!(v, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]]);
            G!(v, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]]);
            G!(v, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]]);
        }

        let (head, tail) = v.split_at(8);
        let vs = head.iter().zip(tail).map(|(&a, &b)| a ^ b);

        for (h, v) in self.h.iter_mut().zip(vs) {
            *h ^= v;
        }
    }
}
