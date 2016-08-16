use simd::u32x4;

const K0: u32 = 0x5A827999u32;
const K1: u32 = 0x6ED9EBA1u32;
const K2: u32 = 0x8F1BBCDCu32;
const K3: u32 = 0xCA62C1D6u32;

#[inline]
pub fn first_add(val: u32, u32x4(a, b, c, d): u32x4) -> u32x4 {
    u32x4(a.wrapping_add(val), b, c, d)
}

/// Emulates `llvm.x86.sha1nexte` intrinsic.
#[inline]
pub fn first_half(abcd: u32x4, msg: u32x4) -> u32x4 {
    first_add(abcd.0.rotate_left(30), msg)
}

/// Emulates `llvm.x86.sha1msg1` intrinsic.
#[inline]
fn sha1msg1(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(_, _, w2, w3) = a;
    let u32x4(w4, w5, _, _) = b;
    a ^ u32x4(w2, w3, w4, w5)
}

/// Emulates `llvm.x86.sha1msg2` intrinsic.
#[inline]
fn sha1msg2(a: u32x4, b: u32x4) -> u32x4 {
    let u32x4(x0, x1, x2, x3) = a;
    let u32x4(_, w13, w14, w15) = b;

    let w16 = (x0 ^ w13).rotate_left(1);
    let w17 = (x1 ^ w14).rotate_left(1);
    let w18 = (x2 ^ w15).rotate_left(1);
    let w19 = (x3 ^ w16).rotate_left(1);

    u32x4(w16, w17, w18, w19)
}

/// Performs 4 rounds of the message schedule update.
#[inline]
pub fn schedule(v0: u32x4, v1: u32x4, v2: u32x4, v3: u32x4) -> u32x4 {
    sha1msg2(sha1msg1(v0, v1) ^ v2, v3)
}

#[inline]
pub fn round_x4(h0: u32x4, h1: u32x4, wk: u32x4, i: i8) -> u32x4 {
    digest_round_x4(h0, first_half(h1, wk), i)
}

/// Emulates `llvm.x86.sha1rnds4` intrinsic.
/// Performs 4 rounds of the message block digest.
#[inline]
pub fn digest_round_x4(abcd: u32x4, work: u32x4, i: i8) -> u32x4 {
    const K0V: u32x4 = u32x4(K0, K0, K0, K0);
    const K1V: u32x4 = u32x4(K1, K1, K1, K1);
    const K2V: u32x4 = u32x4(K2, K2, K2, K2);
    const K3V: u32x4 = u32x4(K3, K3, K3, K3);

    match i {
        0 => sha1rnds4c(abcd, work + K0V),
        1 => sha1rnds4p(abcd, work + K1V),
        2 => sha1rnds4m(abcd, work + K2V),
        3 => sha1rnds4p(abcd, work + K3V),
        _ => unreachable!("unknown icosaround index"),
    }
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4c(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => (($c ^ ($a & ($b ^ $c))))
    } // Choose, MD5F, SHA1C

    e = e.wrapping_add(a.rotate_left(5)).wrapping_add(bool3ary_202!(b, c, d)).wrapping_add(t);
    b = b.rotate_left(30);

    d = d.wrapping_add(e.rotate_left(5)).wrapping_add(bool3ary_202!(a, b, c)).wrapping_add(u);
    a = a.rotate_left(30);

    c = c.wrapping_add(d.rotate_left(5)).wrapping_add(bool3ary_202!(e, a, b)).wrapping_add(v);
    e = e.rotate_left(30);

    b = b.wrapping_add(c.rotate_left(5)).wrapping_add(bool3ary_202!(d, e, a)).wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4p(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_150 {
        ($a:expr, $b:expr, $c:expr) => (($a ^ $b ^ $c))
    } // Parity, XOR, MD5H, SHA1P

    e = e.wrapping_add(a.rotate_left(5)).wrapping_add(bool3ary_150!(b, c, d)).wrapping_add(t);
    b = b.rotate_left(30);

    d = d.wrapping_add(e.rotate_left(5)).wrapping_add(bool3ary_150!(a, b, c)).wrapping_add(u);
    a = a.rotate_left(30);

    c = c.wrapping_add(d.rotate_left(5)).wrapping_add(bool3ary_150!(e, a, b)).wrapping_add(v);
    e = e.rotate_left(30);

    b = b.wrapping_add(c.rotate_left(5)).wrapping_add(bool3ary_150!(d, e, a)).wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}

/// Not an intrinsic, but helps emulate `llvm.x86.sha1rnds4` intrinsic.
fn sha1rnds4m(abcd: u32x4, msg: u32x4) -> u32x4 {
    let u32x4(mut a, mut b, mut c, mut d) = abcd;
    let u32x4(t, u, v, w) = msg;
    let mut e = 0u32;

    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => (($a & $b) ^ ($a & $c) ^ ($b & $c))
    } // Majority, SHA1M

    e = e.wrapping_add(a.rotate_left(5)).wrapping_add(bool3ary_232!(b, c, d)).wrapping_add(t);
    b = b.rotate_left(30);

    d = d.wrapping_add(e.rotate_left(5)).wrapping_add(bool3ary_232!(a, b, c)).wrapping_add(u);
    a = a.rotate_left(30);

    c = c.wrapping_add(d.rotate_left(5)).wrapping_add(bool3ary_232!(e, a, b)).wrapping_add(v);
    e = e.rotate_left(30);

    b = b.wrapping_add(c.rotate_left(5)).wrapping_add(bool3ary_232!(d, e, a)).wrapping_add(w);
    d = d.rotate_left(30);

    u32x4(b, c, d, e)
}
