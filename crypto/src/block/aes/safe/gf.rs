use std::ops::*;
use std::mem;

pub trait Split {
    type Output;

    fn split(self) -> (Self::Output, Self::Output);
}

pub trait Join {
    type Output: Sized;

    fn join(self, other: Self) -> Self::Output;
}

// Galois Field GF(2^1) {{{
#[derive(Copy, Clone, Debug)]
pub struct Gf1<T>(T);

impl<T> From<T> for Gf1<T> {
    fn from(value: T) -> Self {
        Gf1(value)
    }
}

impl<T: Default> Default for Gf1<T> {
    fn default() -> Self {
        Gf1(Default::default())
    }
}

impl<T: BitXor<Output = T>> Add for Gf1<T> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Gf1(self.0 ^ other.0)
    }
}

impl<T: BitAnd<Output = T>> Mul for Gf1<T> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Gf1(self.0 & other.0)
    }
}

impl<T: Copy> Join for Gf1<T> {
    type Output = Gf2<T>;

    fn join(self, other: Self) -> Self::Output {
        Gf2(self.0, other.0)
    }
}
// }}}
// Galois field GF(2^2) {{{
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Gf2<T>(pub T, pub T);

impl<T: Default> Default for Gf2<T> {
    fn default() -> Self {
        Gf2(Default::default(), Default::default())
    }
}

impl<T> Gf2<T>
    where T: BitXor<Output = T> + Copy
{
    pub fn scl_n(self) -> Self {
        Gf2(self.0 ^ self.1, self.0)
    }

    pub fn scl_n2(self) -> Self {
        Gf2(self.1, self.0 ^ self.1)
    }
}

impl<T> Gf2<T> {
    pub fn swap(mut self) -> Self {
        mem::swap(&mut self.0, &mut self.1);
        self
    }
    pub fn sq(self) -> Self {
        self.swap()
    }
    pub fn inv(self) -> Self {
        self.swap()
    }
}

impl<T> Mul for Gf2<T>
    where T: BitAnd<Output = T> + BitXor<Output = T> + Copy
{
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let (b, a) = self.split();
        let (d, c) = other.split();

        let e = (a + b) * (c + d);
        let p = (a * c) + e;
        let q = (b * d) + e;

        q.join(p)
    }
}

impl<T> Add for Gf2<T>
    where T: BitAnd<Output = T> + BitXor<Output = T> + Copy
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let (b, a) = self.split();
        let (d, c) = other.split();

        (b + d).join(a + c)
    }
}

impl<T: Copy> Split for Gf2<T> {
    type Output = Gf1<T>;

    fn split(self) -> (Self::Output, Self::Output) {
        (Gf1(self.0), Gf1(self.1))
    }
}

impl<T: Copy> Join for Gf2<T> {
    type Output = Gf4<T>;

    fn join(self, other: Self) -> Self::Output {
        Gf4(self.0, self.1, other.0, other.1)
    }
}
// }}}
// Galois field GF(2^4) {{{
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Gf4<T>(pub T, pub T, pub T, pub T);

impl<T: Default> Default for Gf4<T> {
    fn default() -> Self {
        Gf4(Default::default(),
            Default::default(),
            Default::default(),
            Default::default())
    }
}

impl<T> Gf4<T>
    where T: BitAnd<Output = T> + BitXor<Output = T> + Copy
{
    fn inv(self) -> Self {
        let (b, a) = self.split();

        let c = (a + b).sq().scl_n();
        let d = a * b;
        let e = (c + d).inv();
        let p = e * b;
        let q = e * a;

        q.join(p)
    }

    fn sq_scl(self) -> Self {
        let (b, a) = self.split();

        let p = (a + b).sq();
        let q = b.sq().scl_n2();

        q.join(p)
    }
}

impl<T> Mul for Gf4<T>
    where T: BitAnd<Output = T> + BitXor<Output = T> + Copy
{
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let (b, a) = self.split();
        let (d, c) = other.split();

        let f = c + d;
        let e = ((a + b) * f).scl_n();
        let p = (a * c) + e;
        let q = (b * d) + e;

        q.join(p)
    }
}

impl<T> Add for Gf4<T>
    where T: BitAnd<Output = T> + BitXor<Output = T> + Copy
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let (b, a) = self.split();
        let (d, c) = other.split();

        (b + d).join(a + c)
    }
}

impl<T: Copy> Split for Gf4<T> {
    type Output = Gf2<T>;

    fn split(self) -> (Self::Output, Self::Output) {
        (Gf2(self.0, self.1), Gf2(self.2, self.3))
    }
}

impl<T: Copy> Join for Gf4<T> {
    type Output = Gf8<T>;

    fn join(self, other: Self) -> Self::Output {
        Gf8(self.0,
            self.1,
            self.2,
            self.3,
            other.0,
            other.1,
            other.2,
            other.3)
    }
}
// }}}
// Galois field GF(2^8) {{{
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Gf8<T>(pub T, pub T, pub T, pub T, pub T, pub T, pub T, pub T);

impl<T: Default> Default for Gf8<T> {
    fn default() -> Self {
        Gf8(Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default())
    }
}

impl<T> Gf8<T>
    where T: BitAnd<Output = T> + BitXor<Output = T> + Copy
{
    pub fn inv(self) -> Self {
        let (b, a) = self.split();

        let c = (a + b).sq_scl();
        let d = a * b;
        let e = (c + d).inv();
        let p = e * b;
        let q = e * a;

        q.join(p)
    }
}

impl<T> Add for Gf8<T>
    where T: BitAnd<Output = T> + BitXor<Output = T> + Copy
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let (b, a) = self.split();
        let (d, c) = other.split();

        (b + d).join(a + c)
    }
}

impl<T: Copy + BitXor<Output = T>> Gf8<T> {
    pub fn rebase<B: Base<Self>>(self) -> Self {
        B::rebase(self)
    }
}

impl<T: Copy + Not<Output = T>> Gf8<T> {
    pub fn xor_x63(self) -> Self {
        Gf8(!self.0,
            !self.1,
            self.2,
            self.3,
            self.4,
            !self.5,
            !self.6,
            self.7)
    }
}

impl<T: Copy> Split for Gf8<T> {
    type Output = Gf4<T>;

    fn split(self) -> (Self::Output, Self::Output) {
        (Gf4(self.0, self.1, self.2, self.3),
         Gf4(self.4, self.5, self.6, self.7))
    }
}
// }}}

/// We need to be able to convert a Bs8State to and from a polynomial basis and a normal
/// basis. That transformation could be done via pseudocode that roughly looks like the
/// following:
///
/// ```ignore
/// for x in 0..8 {
///     for y in 0..8 {
///         result.x ^= input.y & MATRIX[7 - y][x]
///     }
/// }
/// ```
///
/// Where the MATRIX is one of the following depending on the conversion being done.
/// (The affine transformation step is included in all of these matrices):
///
/// ```txt
/// A2X = [
///     [ 0,  0,  0, -1, -1,  0,  0, -1],
///     [-1, -1,  0,  0, -1, -1, -1, -1],
///     [ 0, -1,  0,  0, -1, -1, -1, -1],
///     [ 0,  0,  0, -1,  0,  0, -1,  0],
///     [-1,  0,  0, -1,  0,  0,  0,  0],
///     [-1,  0,  0,  0,  0,  0,  0, -1],
///     [-1,  0,  0, -1,  0, -1,  0, -1],
///     [-1, -1, -1, -1, -1, -1, -1, -1]
/// ];
///
/// X2A = [
///     [ 0,  0, -1,  0,  0, -1, -1,  0],
///     [ 0,  0,  0, -1, -1, -1, -1,  0],
///     [ 0, -1, -1, -1,  0, -1, -1,  0],
///     [ 0,  0, -1, -1,  0,  0,  0, -1],
///     [ 0,  0,  0, -1,  0, -1, -1,  0],
///     [-1,  0,  0, -1,  0, -1,  0,  0],
///     [ 0, -1, -1, -1, -1,  0, -1, -1],
///     [ 0,  0,  0,  0,  0, -1, -1,  0],
/// ];
///
/// X2S = [
///     [ 0,  0,  0, -1, -1,  0, -1,  0],
///     [-1,  0, -1, -1,  0, -1,  0,  0],
///     [ 0, -1, -1, -1, -1,  0,  0, -1],
///     [-1, -1,  0, -1,  0,  0,  0,  0],
///     [ 0,  0, -1, -1, -1,  0, -1, -1],
///     [ 0,  0, -1,  0,  0,  0,  0,  0],
///     [-1, -1,  0,  0,  0,  0,  0,  0],
///     [ 0,  0, -1,  0,  0, -1,  0,  0],
/// ];
///
/// S2X = [
///     [ 0,  0, -1, -1,  0,  0,  0, -1],
///     [-1,  0,  0, -1, -1, -1, -1,  0],
///     [-1,  0, -1,  0,  0,  0,  0,  0],
///     [-1, -1,  0, -1,  0, -1, -1, -1],
///     [ 0, -1,  0,  0, -1,  0,  0,  0],
///     [ 0,  0, -1,  0,  0,  0,  0,  0],
///     [-1,  0,  0,  0, -1,  0, -1,  0],
///     [-1, -1,  0,  0, -1,  0, -1,  0],
/// ];
/// ```
///
/// Looking at the pseudocode implementation, we see that there is no point
/// in processing any of the elements in those matrices that have zero values
/// since a logical AND with 0 will produce 0 which will have no effect when it
/// is XORed into the result.
///
/// LLVM doesn't appear to be able to fully unroll the loops in the pseudocode
/// above and to eliminate processing of the 0 elements. So, each transformation is
/// implemented independently directly in fully unrolled form with the 0 elements
/// removed.
///
/// As an optimization, elements that are XORed together multiple times are
/// XORed just once and then used multiple times. I wrote a simple program that
/// greedily looked for terms to combine to create the implementations below.
/// It is likely that this could be optimized more.
pub trait Base<T> {
    fn rebase(T) -> T;
}

pub struct A2X;

impl<T: BitXor<Output = T> + Copy> Base<Gf8<T>> for A2X {
    fn rebase(input: Gf8<T>) -> Gf8<T> {
        let t06 = input.6 ^ input.0;
        let t056 = input.5 ^ t06;
        let t0156 = t056 ^ input.1;
        let t13 = input.1 ^ input.3;

        let x0 = input.2 ^ t06 ^ t13;
        let x1 = t056;
        let x2 = input.0;
        let x3 = input.0 ^ input.4 ^ input.7 ^ t13;
        let x4 = input.7 ^ t056;
        let x5 = t0156;
        let x6 = input.4 ^ t056;
        let x7 = input.2 ^ input.7 ^ t0156;

        Gf8(x0, x1, x2, x3, x4, x5, x6, x7)
    }
}

pub struct X2A;

impl<T: BitXor<Output = T> + Copy> Base<Gf8<T>> for X2A {
    fn rebase(input: Gf8<T>) -> Gf8<T> {
        let t15 = input.1 ^ input.5;
        let t36 = input.3 ^ input.6;
        let t1356 = t15 ^ t36;
        let t07 = input.0 ^ input.7;

        let x0 = input.2;
        let x1 = t15;
        let x2 = input.4 ^ input.7 ^ t15;
        let x3 = input.2 ^ input.4 ^ t1356;
        let x4 = input.1 ^ input.6;
        let x5 = input.2 ^ input.5 ^ t36 ^ t07;
        let x6 = t1356 ^ t07;
        let x7 = input.1 ^ input.4;

        Gf8(x0, x1, x2, x3, x4, x5, x6, x7)
    }
}

pub struct S2X;

impl<T: BitXor<Output = T> + Copy> Base<Gf8<T>> for S2X {
    fn rebase(input: Gf8<T>) -> Gf8<T> {
        let t46 = input.4 ^ input.6;
        let t01 = input.0 ^ input.1;
        let t0146 = t01 ^ t46;

        let x0 = input.5 ^ t0146;
        let x1 = input.0 ^ input.3 ^ input.4;
        let x2 = input.2 ^ input.5 ^ input.7;
        let x3 = input.7 ^ t46;
        let x4 = input.3 ^ input.6 ^ t01;
        let x5 = t46;
        let x6 = t0146;
        let x7 = input.4 ^ input.7;

        Gf8(x0, x1, x2, x3, x4, x5, x6, x7)
    }
}

pub struct X2S;

impl<T: BitXor<Output = T> + Copy> Base<Gf8<T>> for X2S {
    fn rebase(input: Gf8<T>) -> Gf8<T> {
        let t46 = input.4 ^ input.6;
        let t35 = input.3 ^ input.5;
        let t06 = input.0 ^ input.6;
        let t357 = t35 ^ input.7;

        let x0 = input.1 ^ t46;
        let x1 = input.1 ^ input.4 ^ input.5;
        let x2 = input.2 ^ t35 ^ t06;
        let x3 = t46 ^ t357;
        let x4 = t357;
        let x5 = t06;
        let x6 = input.3 ^ input.7;
        let x7 = t35;

        Gf8(x0, x1, x2, x3, x4, x5, x6, x7)
    }
}
