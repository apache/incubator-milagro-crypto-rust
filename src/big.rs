/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
*/

use super::dbig::DBig;
use crate::arch::{self, Chunk, DChunk};
use crate::rand::RAND;

use std::cmp::Ordering;
use std::fmt;

pub use super::rom::BASEBITS;
pub use super::rom::MODBYTES;

pub const NLEN: usize = 1 + (8 * MODBYTES - 1) / BASEBITS;
pub const DNLEN: usize = 2 * NLEN;
pub const BMASK: Chunk = (1 << BASEBITS) - 1;
pub const HBITS: usize = BASEBITS / 2;
pub const HMASK: Chunk = (1 << HBITS) - 1;
pub const NEXCESS: isize = 1 << (arch::CHUNK - BASEBITS - 1);
pub const BIGBITS: usize = MODBYTES * 8;

#[derive(Clone)]
pub struct Big {
    pub w: [Chunk; NLEN],
}

impl fmt::Display for Big {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Big: [ {} ]", self.to_string())
    }
}

impl fmt::Debug for Big {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Big: [ {} ]", self.to_string())
    }
}

impl PartialEq for Big {
    fn eq(&self, other: &Big) -> bool {
        Big::comp(self, other) == 0
    }
}

impl Ord for Big {
    fn cmp(&self, other: &Big) -> Ordering {
        let r = Big::comp(self, other);
        if r > 0 {
            return Ordering::Greater;
        }
        if r < 0 {
            return Ordering::Less;
        }
        Ordering::Equal
    }
}

impl Eq for Big {}

impl PartialOrd for Big {
    fn partial_cmp(&self, other: &Big) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Big {
    /// New
    ///
    /// Creates a new Big set to zero.
    #[inline(always)]
    pub fn new() -> Big {
        Big { w: [0; NLEN] }
    }

    /// New Int
    ///
    /// Convert an integer to a Big
    #[inline(always)]
    pub fn new_int(x: isize) -> Big {
        let mut s = Big::new();
        s.w[0] = x as Chunk;
        s
    }

    /// New Ints
    ///
    /// Takes an array of integers and converts to a Big
    #[inline(always)]
    pub fn new_ints(a: &[Chunk]) -> Big {
        let mut s = Big::new();
        for i in 0..NLEN {
            s.w[i] = a[i]
        }
        s
    }

    /// New Double Copy
    ///
    /// Copies the least significant bytes from a `DBig`.
    #[inline(always)]
    pub fn new_dcopy(y: &DBig) -> Big {
        let mut s = Big::new();
        for i in 0..NLEN {
            s.w[i] = y.w[i]
        }
        s
    }

    /// Get
    ///
    /// Retrives the Chunk at a given index.
    pub fn get(&self, i: usize) -> Chunk {
        self.w[i]
    }

    /// Set
    ///
    /// Sets the chunk at a given index.
    pub fn set(&mut self, i: usize, x: Chunk) {
        self.w[i] = x;
    }

    /// XOR Top
    ///
    /// Performs XOR on the most significant byte.
    pub fn xor_top(&mut self, x: Chunk) {
        self.w[NLEN - 1] ^= x;
    }

    /// Is Zilch
    ///
    /// self == zero
    pub fn is_zilch(&self) -> bool {
        for i in 0..NLEN {
            if self.w[i] != 0 {
                return false;
            }
        }
        true
    }

    /// Zero
    ///
    /// Set to zero.
    pub fn zero(&mut self) {
        for i in 0..NLEN {
            self.w[i] = 0
        }
    }

    /// Is Unity
    ///
    /// self == one
    pub fn is_unity(&self) -> bool {
        for i in 1..NLEN {
            if self.w[i] != 0 {
                return false;
            }
        }
        if self.w[0] != 1 {
            return false;
        }
        true
    }

    /// One
    ///
    /// Set to one.
    pub fn one(&mut self) {
        self.w[0] = 1;
        for i in 1..NLEN {
            self.w[i] = 0;
        }
    }

    /// Double Copy
    ///
    /// Copy least significant bytes from a `DBig`
    pub fn dcopy(&mut self, x: &DBig) {
        for i in 0..NLEN {
            self.w[i] = x.w[i]
        }
    }

    /// Multiply Addition
    ///
    /// Get top and bottom half of  = x * y + c + r
    pub fn mul_add(a: Chunk, b: Chunk, c: Chunk, r: Chunk) -> (Chunk, Chunk) {
        let prod: DChunk = (a as DChunk) * (b as DChunk) + (c as DChunk) + (r as DChunk);
        let bot = (prod & (BMASK as DChunk)) as Chunk;
        let top = (prod >> BASEBITS) as Chunk;
        (top, bot)
    }

    /// Normalise
    ///
    /// Force all digits < 2^BASEBITS
    pub fn norm(&mut self) -> Chunk {
        let mut carry = 0 as Chunk;
        for i in 0..NLEN - 1 {
            let d = self.w[i] + carry;
            self.w[i] = d & BMASK;
            carry = d >> BASEBITS;
        }
        self.w[NLEN - 1] += carry;
        (self.w[NLEN - 1] >> ((8 * MODBYTES) % BASEBITS)) as Chunk
    }

    /// Conditional Swap
    ///
    /// Conditional swap of two bigs depending on d using XOR - no branches
    pub fn cswap(&mut self, b: &mut Big, d: isize) {
        let mut c = d as Chunk;
        c = !(c - 1);
        for i in 0..NLEN {
            let t = c & (self.w[i] ^ b.w[i]);
            self.w[i] ^= t;
            b.w[i] ^= t;
        }
    }

    /// Conditional Move
    ///
    /// Conditional move of two bigs depending on d using XOR - no branches
    pub fn cmove(&mut self, g: &Big, d: isize) {
        let b = -d as Chunk;
        for i in 0..NLEN {
            self.w[i] ^= (self.w[i] ^ g.w[i]) & b;
        }
    }

    /// Partial Shift Right
    ///
    /// Shift right by less than a word.
    pub fn fshr(&mut self, k: usize) -> isize {
        let n = k;
        let w = self.w[0] & ((1 << n) - 1); // shifted out part
        for i in 0..NLEN - 1 {
            self.w[i] = (self.w[i] >> k) | ((self.w[i + 1] << (BASEBITS - n)) & BMASK);
        }
        self.w[NLEN - 1] = self.w[NLEN - 1] >> k;
        return w as isize;
    }

    /// Shift Right
    ///
    /// General shift right.
    pub fn shr(&mut self, k: usize) {
        let n = k % BASEBITS;
        let m = k / BASEBITS;
        for i in 0..NLEN - m - 1 {
            self.w[i] = (self.w[m + i] >> n) | ((self.w[m + i + 1] << (BASEBITS - n)) & BMASK)
        }
        self.w[NLEN - m - 1] = self.w[NLEN - 1] >> n;
        for i in NLEN - m..NLEN {
            self.w[i] = 0
        }
    }

    /// Partial Shift Left
    ///
    /// Shift left by less than a word.
    pub fn fshl(&mut self, k: usize) -> isize {
        let n = k;
        self.w[NLEN - 1] = (self.w[NLEN - 1] << n) | (self.w[NLEN - 2] >> (BASEBITS - n));
        for i in (1..NLEN - 1).rev() {
            self.w[i] = ((self.w[i] << k) & BMASK) | (self.w[i - 1] >> (BASEBITS - n));
        }
        self.w[0] = (self.w[0] << n) & BMASK;
        // return excess - only used in ff.c
        (self.w[NLEN - 1] >> ((8 * MODBYTES) % BASEBITS)) as isize
    }

    /// Shift Left
    ///
    /// General shift left.
    pub fn shl(&mut self, k: usize) {
        let n = k % BASEBITS;
        let m = k / BASEBITS;

        self.w[NLEN - 1] = self.w[NLEN - 1 - m] << n;
        if NLEN >= m + 2 {
            self.w[NLEN - 1] |= self.w[NLEN - m - 2] >> (BASEBITS - n)
        }
        for i in (m + 1..NLEN - 1).rev() {
            self.w[i] = ((self.w[i - m] << n) & BMASK) | (self.w[i - m - 1] >> (BASEBITS - n));
        }
        self.w[m] = (self.w[0] << n) & BMASK;
        for i in 0..m {
            self.w[i] = 0
        }
    }

    /// Number of Bits
    ///
    /// Return number of bits
    pub fn nbits(&self) -> usize {
        let mut k = NLEN - 1;
        let mut s = self.clone();
        s.norm();
        while (k as isize) >= 0 && s.w[k] == 0 {
            k = k.wrapping_sub(1)
        }
        if (k as isize) < 0 {
            return 0;
        }
        let mut bts = BASEBITS * k;
        let mut c = s.w[k];
        while c != 0 {
            c /= 2;
            bts += 1;
        }
        bts
    }

    /// To String
    ///
    /// Converts a `Big` to a hex string.
    pub fn to_string(&self) -> String {
        let mut s = String::new();
        let mut len = self.nbits();

        if len % 4 == 0 {
            len /= 4;
        } else {
            len /= 4;
            len += 1;
        }
        let mb = (MODBYTES * 2) as usize;
        if len < mb {
            len = mb
        }

        for i in (0..len).rev() {
            let mut b = self.clone();
            b.shr(i * 4);
            s = s + &format!("{:X}", b.w[0] & 15);
        }
        s
    }

    /// From String
    ///
    /// Converts to `Big` from hex string.
    #[inline(always)]
    pub fn from_string(val: String) -> Big {
        let mut res = Big::new();
        let len = val.len();
        let op = &val[0..1];
        let n = u8::from_str_radix(op, 16).unwrap();
        res.w[0] += n as Chunk;
        for i in 1..len {
            res.shl(4);
            let op = &val[i..=i];
            let n = u8::from_str_radix(op, 16).unwrap();
            res.w[0] += n as Chunk;
        }
        res
    }

    /// Add
    ///
    /// self += r
    pub fn add(&mut self, r: &Big) {
        for i in 0..NLEN {
            self.w[i] += r.w[i]
        }
    }

    /// OR
    ///
    /// self |= r
    pub fn or(&mut self, r: &Big) {
        for i in 0..NLEN {
            self.w[i] |= r.w[i]
        }
    }

    /// Double
    ///
    /// self *= 2
    pub fn dbl(&mut self) {
        for i in 0..NLEN {
            self.w[i] += self.w[i]
        }
    }

    /// Plus
    ///
    /// Return self + x
    #[inline(always)]
    pub fn plus(&self, x: &Big) -> Big {
        let mut s = Big::new();
        for i in 0..NLEN {
            s.w[i] = self.w[i] + x.w[i];
        }
        s
    }

    /// Increment
    ///
    /// self += x
    pub fn inc(&mut self, x: isize) {
        self.norm();
        self.w[0] += x as Chunk;
    }

    /// Minus
    ///
    /// Return self - x
    #[inline(always)]
    pub fn minus(&self, x: &Big) -> Big {
        let mut d = Big::new();
        for i in 0..NLEN {
            d.w[i] = self.w[i] - x.w[i];
        }
        d
    }

    /// Subtraction
    ///
    /// self -= x
    pub fn sub(&mut self, x: &Big) {
        for i in 0..NLEN {
            self.w[i] -= x.w[i];
        }
    }

    /// Reverse Subtraction
    ///
    /// self = x - self
    pub fn rsub(&mut self, x: &Big) {
        for i in 0..NLEN {
            self.w[i] = x.w[i] - self.w[i]
        }
    }

    /// Decrement
    ///
    /// self -= x, where x is int
    pub fn dec(&mut self, x: isize) {
        self.norm();
        self.w[0] -= x as Chunk;
    }

    /// Integer Multiplication
    ///
    /// self *= x,
    /// Require: x < NEXCESS
    pub fn imul(&mut self, c: isize) {
        for i in 0..NLEN {
            self.w[i] *= c as Chunk;
        }
    }

    /// To Byte Array
    ///
    /// Convert this Big to byte array from index `n`
    pub fn to_byte_array(&self, b: &mut [u8], n: usize) {
        let mut c = self.clone();
        c.norm();

        for i in (0..(MODBYTES as usize)).rev() {
            b[i + n] = (c.w[0] & 0xff) as u8;
            c.fshr(8);
        }
    }

    /// From Byte Array
    ///
    /// Convert from byte array starting at index `n` to Big
    #[inline(always)]
    pub fn from_byte_array(b: &[u8], n: usize) -> Big {
        let mut m = Big::new();

        // Restrict length
        let max_big = MODBYTES;
        let len = if b.len() >= max_big {
            max_big as usize
        } else {
            b.len()
        };

        for i in 0..len {
            m.fshl(8);
            m.w[0] += (b[i + n] & 0xff) as Chunk;
        }
        m
    }

    /// To Bytes
    ///
    /// Convert to bytes from index 0
    pub fn to_bytes(&self, b: &mut [u8]) {
        self.to_byte_array(b, 0)
    }

    /// From bytes
    ///
    /// Convert from bytes from index 0
    /// Panics if input bytes length is less than required.
    #[inline(always)]
    pub fn from_bytes(b: &[u8]) -> Big {
        Big::from_byte_array(b, 0)
    }

    /// P Multiply
    ///
    /// self *= x
    /// Require: x > NEXCESS, returns overflow
    pub fn pmul(&mut self, c: isize) -> Chunk {
        let mut carry = 0 as Chunk;
        for i in 0..NLEN {
            let ak = self.w[i];
            let tuple = Big::mul_add(ak, c as Chunk, carry, 0 as Chunk);
            carry = tuple.0;
            self.w[i] = tuple.1;
        }
        carry
    }

    /// PX Multiply
    ///
    /// self *= c
    /// Note: catches overflow in DBig
    #[inline(always)]
    pub fn pxmul(&self, c: isize) -> DBig {
        let mut m = DBig::new();
        let mut carry = 0 as Chunk;
        for j in 0..NLEN {
            let tuple = Big::mul_add(self.w[j], c as Chunk, carry, m.w[j]);
            carry = tuple.0;
            m.w[j] = tuple.1;
        }
        m.w[NLEN] = carry;
        m
    }

    /// Divide 3
    ///
    /// self /= 3
    /// Returns carry
    pub fn div3(&mut self) -> Chunk {
        let mut carry = 0 as Chunk;
        self.norm();
        let base = 1 << BASEBITS;
        for i in (0..NLEN).rev() {
            let ak = carry * base + self.w[i];
            self.w[i] = ak / 3;
            carry = ak % 3;
        }
        carry
    }

    /// Small Multiply
    ///
    /// return a * b
    /// Require: a * b to fit in a Big.
    #[inline(always)]
    pub fn smul(a: &Big, b: &Big) -> Big {
        let mut c = Big::new();
        for i in 0..NLEN {
            let mut carry = 0 as Chunk;
            for j in 0..NLEN {
                if i + j < NLEN {
                    let tuple = Big::mul_add(a.w[i], b.w[j], carry, c.w[i + j]);
                    carry = tuple.0;
                    c.w[i + j] = tuple.1;
                }
            }
        }
        c
    }

    /// Compare
    ///
    /// Compare a and b, return 0 if a == b; -1 if a < b; +1 if a > b.
    /// Require: a and b must be normalised
    pub fn comp(a: &Big, b: &Big) -> isize {
        for i in (0..NLEN).rev() {
            if a.w[i] == b.w[i] {
                continue;
            }
            if a.w[i] > b.w[i] {
                return 1;
            } else {
                return -1;
            }
        }
        0
    }

    /// Mod 2^m
    ///
    /// set self = self mod 2^m
    pub fn mod2m(&mut self, m: usize) {
        let wd = m / BASEBITS;
        let bt = m % BASEBITS;
        let msk = (1 << bt) - 1;
        self.w[wd] &= msk;
        for i in wd + 1..NLEN {
            self.w[i] = 0
        }
    }

    /// Inverse Modulus 256
    ///
    /// Arazi and Qi inversion mod 256
    pub fn invmod256(a: isize) -> isize {
        let mut t1: isize = 0;
        let mut c = (a >> 1) & 1;
        t1 += c;
        t1 &= 1;
        t1 = 2 - t1;
        t1 <<= 1;
        let mut u = t1 + 1;

        // i=2
        let mut b = a & 3;
        t1 = u * b;
        t1 >>= 2;
        c = (a >> 2) & 3;
        let mut t2 = (u * c) & 3;
        t1 += t2;
        t1 *= u;
        t1 &= 3;
        t1 = 4 - t1;
        t1 <<= 2;
        u += t1;

        // i=4
        b = a & 15;
        t1 = u * b;
        t1 >>= 4;
        c = (a >> 4) & 15;
        t2 = (u * c) & 15;
        t1 += t2;
        t1 *= u;
        t1 &= 15;
        t1 = 16 - t1;
        t1 <<= 4;
        u += t1;

        u
    }

    /// Parity
    ///
    /// Returns self % 2
    pub fn parity(&self) -> isize {
        (self.w[0] % 2) as isize
    }

    /// Bit
    ///
    /// Returns the `n`-th bit
    pub fn bit(&self, n: usize) -> isize {
        if (self.w[n / (BASEBITS as usize)] & (1 << (n % BASEBITS))) > 0 {
            return 1;
        }
        0
    }

    /// Last Bits
    ///
    /// Returns last `n` bits
    pub fn lastbits(&mut self, n: usize) -> isize {
        let msk = ((1 << n) - 1) as Chunk;
        self.norm();
        (self.w[0] & msk) as isize
    }

    /// Inverse Modulu 2^m
    ///
    /// a = 1/a mod 2^256. This is very fast!
    pub fn invmod2m(&mut self) {
        let mut u = Big::new();
        u.inc(Big::invmod256(self.lastbits(8)));

        let mut i = 8;
        while i < BIGBITS {
            u.norm();
            let mut b = self.clone();
            b.mod2m(i);
            let mut t1 = Big::smul(&u, &b);
            t1.shr(i);
            let mut c = self.clone();
            c.shr(i);
            c.mod2m(i);

            let mut t2 = Big::smul(&u, &c);
            t2.mod2m(i);
            t1.add(&t2);
            t1.norm();
            b = Big::smul(&t1, &u);
            t1 = b.clone();
            t1.mod2m(i);

            t2.one();
            t2.shl(i);
            t1.rsub(&t2);
            t1.norm();
            t1.shl(i);
            u.add(&t1);
            i <<= 1;
        }
        u.mod2m(BIGBITS);
        *self = u;
        self.norm();
    }

    /// Reduciton with Modulus
    ///
    /// reduce self mod m
    pub fn rmod(&mut self, n: &Big) {
        let mut k = 0;
        let mut m = n.clone();
        self.norm();
        if Big::comp(self, &m) < 0 {
            return;
        }
        loop {
            m.fshl(1);
            k += 1;
            if Big::comp(self, &m) < 0 {
                break;
            }
        }

        while k > 0 {
            m.fshr(1);

            let mut r = self.clone();
            r.sub(&m);
            r.norm();
            self.cmove(
                &r,
                (1 - ((r.w[NLEN - 1] >> (arch::CHUNK - 1)) & 1)) as isize,
            );
            k -= 1;
        }
    }

    /// Division
    ///
    /// self = self / m
    pub fn div(&mut self, n: &Big) {
        let mut k = 0;
        self.norm();
        let mut e = Big::new_int(1);
        let mut b = self.clone();
        let mut m = n.clone();
        self.zero();

        while Big::comp(&b, &m) >= 0 {
            e.fshl(1);
            m.fshl(1);
            k += 1;
        }

        while k > 0 {
            m.fshr(1);
            e.fshr(1);

            let mut r = b.clone();
            r.sub(&m);
            r.norm();
            let d = (1 - ((r.w[NLEN - 1] >> (arch::CHUNK - 1)) & 1)) as isize;
            b.cmove(&r, d);
            r = self.clone();
            r.add(&e);
            r.norm();
            self.cmove(&r, d);
            k -= 1;
        }
    }

    /// Random
    ///
    /// Get 8*MODBYTES size random number
    #[inline(always)]
    pub fn random(rng: &mut RAND) -> Big {
        let mut m = Big::new();
        let mut j = 0;
        let mut r: u8 = 0;

        // generate random Big
        for _ in 0..8 * (MODBYTES as usize) {
            if j == 0 {
                r = rng.getbyte()
            } else {
                r >>= 1
            }

            let b = (r as Chunk) & 1;
            m.shl(1);
            m.w[0] += b;
            j += 1;
            j &= 7;
        }
        m
    }

    /// Random Number
    ///
    /// Create random Big in portable way, one bit at a time
    #[inline(always)]
    pub fn randomnum(q: &Big, rng: &mut RAND) -> Big {
        let mut d = DBig::new();
        let mut j = 0;
        let mut r: u8 = 0;
        let t = q.clone();
        for _ in 0..2 * t.nbits() {
            if j == 0 {
                r = rng.getbyte();
            } else {
                r >>= 1
            }

            let b = (r as Chunk) & 1;
            d.shl(1);
            d.w[0] += b;
            j += 1;
            j &= 7;
        }
        let m = d.dmod(q);
        m
    }

    /// Jacobi Symbol
    ///
    /// Performs jacobi(self/p)
    /// Returns 0, 1 or -1
    pub fn jacobi(&mut self, p: &Big) -> isize {
        let mut m: usize = 0;
        let one = Big::new_int(1);
        if p.parity() == 0 || self.is_zilch() || Big::comp(p, &one) <= 0 {
            return 0;
        }
        self.norm();

        let mut x = self.clone();
        let mut n = p.clone();
        x.rmod(p);

        while Big::comp(&n, &one) > 0 {
            if x.is_zilch() {
                return 0;
            }
            let n8 = n.lastbits(3) as usize;
            let mut k = 0;
            while x.parity() == 0 {
                k += 1;
                x.shr(1);
            }
            if k % 2 == 1 {
                m += (n8 * n8 - 1) / 8
            }
            m += (n8 - 1) * ((x.lastbits(2) as usize) - 1) / 4;
            let mut t = n.clone();
            t.rmod(&x);
            n = x.clone();
            x = t.clone();
            m %= 2;
        }
        if m == 0 {
            return 1;
        }
        -1
    }

    /// Inverse Modulus
    ///
    /// self = 1/self mod p. Binary method
    pub fn invmodp(&mut self, p: &Big) {
        self.rmod(p);
        let mut u = self.clone();
        let mut v = p.clone();
        let mut x1 = Big::new_int(1);
        let mut x2 = Big::new();
        let one = Big::new_int(1);

        while (Big::comp(&u, &one) != 0) && (Big::comp(&v, &one) != 0) {
            while u.parity() == 0 {
                u.fshr(1);
                if x1.parity() != 0 {
                    x1.add(p);
                    x1.norm();
                }
                x1.fshr(1);
            }
            while v.parity() == 0 {
                v.fshr(1);
                if x2.parity() != 0 {
                    x2.add(p);
                    x2.norm();
                }
                x2.fshr(1);
            }
            if Big::comp(&u, &v) >= 0 {
                u.sub(&v);
                u.norm();
                if Big::comp(&x1, &x2) >= 0 {
                    x1.sub(&x2)
                } else {
                    let mut t = p.clone();
                    t.sub(&x2);
                    x1.add(&t);
                }
                x1.norm();
            } else {
                v.sub(&u);
                v.norm();
                if Big::comp(&x2, &x1) >= 0 {
                    x2.sub(&x1)
                } else {
                    let mut t = p.clone();
                    t.sub(&x1);
                    x2.add(&t);
                }
                x2.norm();
            }
        }
        if Big::comp(&u, &one) == 0 {
            *self = x1
        } else {
            *self = x2
        }
    }

    /// Multiplication
    ///
    /// return a*b as DBig
    pub fn mul(a: &Big, b: &Big) -> DBig {
        let mut c = DBig::new();
        let rm = BMASK as DChunk;
        let rb = BASEBITS;

        let mut d: [DChunk; DNLEN] = [0; DNLEN];
        for i in 0..NLEN {
            d[i] = (a.w[i] as DChunk) * (b.w[i] as DChunk);
        }
        let mut s = d[0];
        let mut t = s;
        c.w[0] = (t & rm) as Chunk;
        let mut co = t >> rb;
        for k in 1..NLEN {
            s += d[k];
            t = co + s;
            for i in 1 + k / 2..=k {
                t += ((a.w[i] - a.w[k - i]) as DChunk) * ((b.w[k - i] - b.w[i]) as DChunk)
            }
            c.w[k] = (t & rm) as Chunk;
            co = t >> rb;
        }
        for k in NLEN..2 * NLEN - 1 {
            s -= d[k - NLEN];
            t = co + s;
            let mut i = 1 + k / 2;
            while i < NLEN {
                t += ((a.w[i] - a.w[k - i]) as DChunk) * ((b.w[k - i] - b.w[i]) as DChunk);
                i += 1;
            }

            c.w[k] = (t & rm) as Chunk;
            co = t >> rb;
        }
        c.w[2 * NLEN - 1] = co as Chunk;
        c
    }

    /// Square
    ///
    /// return a^2 as DBig
    pub fn sqr(a: &Big) -> DBig {
        let mut c = DBig::new();
        let rm = BMASK as DChunk;
        let rb = BASEBITS;

        let mut t = (a.w[0] as DChunk) * (a.w[0] as DChunk);
        c.w[0] = (t & rm) as Chunk;
        let mut co = t >> rb;

        let mut j = 1;
        while j < NLEN - 1 {
            t = (a.w[j] as DChunk) * (a.w[0] as DChunk);
            for i in 1..(j + 1) / 2 {
                t += (a.w[j - i] as DChunk) * (a.w[i] as DChunk);
            }
            t += t;
            t += co;
            c.w[j] = (t & rm) as Chunk;
            co = t >> rb;
            j += 1;
            t = (a.w[j] as DChunk) * (a.w[0] as DChunk);
            for i in 1..(j + 1) / 2 {
                t += (a.w[j - i] as DChunk) * (a.w[i] as DChunk);
            }
            t += t;
            t += co;
            t += (a.w[j / 2] as DChunk) * (a.w[j / 2] as DChunk);
            c.w[j] = (t & rm) as Chunk;
            co = t >> rb;
            j += 1;
        }

        j = NLEN + (NLEN % 2) - 1;
        while j < DNLEN - 3 {
            t = (a.w[NLEN - 1] as DChunk) * (a.w[j + 1 - NLEN] as DChunk);
            for i in j + 2 - NLEN..(j + 1) / 2 {
                t += (a.w[j - i] as DChunk) * (a.w[i] as DChunk);
            }
            t += t;
            t += co;
            c.w[j] = (t & rm) as Chunk;
            co = t >> rb;
            j += 1;
            t = (a.w[NLEN - 1] as DChunk) * (a.w[j + 1 - NLEN] as DChunk);
            for i in j + 2 - NLEN..(j + 1) / 2 {
                t += (a.w[j - i] as DChunk) * (a.w[i] as DChunk);
            }
            t += t;
            t += co;
            t += (a.w[j / 2] as DChunk) * (a.w[j / 2] as DChunk);
            c.w[j] = (t & rm) as Chunk;
            co = t >> rb;
            j += 1;
        }

        t = (a.w[NLEN - 2] as DChunk) * (a.w[NLEN - 1] as DChunk);
        t += t;
        t += co;
        c.w[DNLEN - 3] = (t & rm) as Chunk;
        co = t >> rb;

        t = (a.w[NLEN - 1] as DChunk) * (a.w[NLEN - 1] as DChunk) + co;
        c.w[DNLEN - 2] = (t & rm) as Chunk;
        co = t >> rb;
        c.w[DNLEN - 1] = co as Chunk;

        c
    }

    /// Montegomery Reduction
    ///
    /// https://eprint.iacr.org/2015/1247.pdf
    #[inline(always)]
    pub fn monty(md: &Big, mc: Chunk, d: &mut DBig) -> Big {
        let mut b = Big::new();
        let rm = BMASK as DChunk;
        let rb = BASEBITS;

        let mut dd: [DChunk; NLEN] = [0; NLEN];
        let mut v: [Chunk; NLEN] = [0; NLEN];

        b.zero();

        let mut t = d.w[0] as DChunk;
        v[0] = (((t & rm) as Chunk).wrapping_mul(mc)) & BMASK;
        t += (v[0] as DChunk) * (md.w[0] as DChunk);
        let mut c = (d.w[1] as DChunk) + (t >> rb);
        let mut s: DChunk = 0;
        for k in 1..NLEN {
            t = c + s + (v[0] as DChunk) * (md.w[k] as DChunk);
            let mut i = 1 + k / 2;
            while i < k {
                t += ((v[k - i] - v[i]) as DChunk) * ((md.w[i] - md.w[k - i]) as DChunk);
                i += 1;
            }
            v[k] = (((t & rm) as Chunk).wrapping_mul(mc)) & BMASK;
            t += (v[k] as DChunk) * (md.w[0] as DChunk);
            c = (d.w[k + 1] as DChunk) + (t >> rb);
            dd[k] = (v[k] as DChunk) * (md.w[k] as DChunk);
            s += dd[k];
        }

        for k in NLEN..2 * NLEN - 1 {
            t = c + s;
            let mut i = 1 + k / 2;
            while i < NLEN {
                t += ((v[k - i] - v[i]) as DChunk) * ((md.w[i] - md.w[k - i]) as DChunk);
                i += 1;
            }
            b.w[k - NLEN] = (t & rm) as Chunk;
            c = (d.w[k + 1] as DChunk) + (t >> rb);
            s -= dd[k + 1 - NLEN];
        }
        b.w[NLEN - 1] = (c & rm) as Chunk;
        b
    }

    /// SSN
    pub fn ssn(r: &mut Big, a: &Big, m: &mut Big) -> isize {
        let n = NLEN - 1;
        m.w[0] = (m.w[0] >> 1) | ((m.w[1] << (BASEBITS - 1)) & BMASK);
        r.w[0] = a.w[0] - m.w[0];
        let mut carry = r.w[0] >> BASEBITS;
        r.w[0] &= BMASK;
        for i in 1..n {
            m.w[i] = (m.w[i] >> 1) | ((m.w[i + 1] << (BASEBITS - 1)) & BMASK);
            r.w[i] = a.w[i] - m.w[i] + carry;
            carry = r.w[i] >> BASEBITS;
            r.w[i] &= BMASK;
        }
        m.w[n] >>= 1;
        r.w[n] = a.w[n] - m.w[n] + carry;
        ((r.w[n] >> (arch::CHUNK - 1)) & 1) as isize
    }

    /// Modular Multiplication
    ///
    /// return a*b mod m
    #[inline(always)]
    pub fn modmul(a1: &Big, b1: &Big, m: &Big) -> Big {
        let mut a = a1.clone();
        let mut b = b1.clone();
        a.rmod(m);
        b.rmod(m);
        let mut d = Big::mul(&a, &b);
        d.dmod(m)
    }

    /// return a^2 mod m
    #[inline(always)]
    pub fn modsqr(a1: &Big, m: &Big) -> Big {
        let mut a = a1.clone();
        a.rmod(m);
        let mut d = Big::sqr(&a);
        d.dmod(m)
    }

    /// Modular Negation
    ///
    /// return -a mod m
    #[inline(always)]
    pub fn modneg(a1: &Big, m: &Big) -> Big {
        let mut a = a1.clone();
        a.rmod(m);
        m.minus(&a)
    }

    /// Raise to Power with Modulus
    ///
    /// return this^e mod m
    #[inline(always)]
    pub fn powmod(&mut self, e1: &Big, m: &Big) -> Big {
        self.norm();
        let mut e = e1.clone();
        e.norm();
        let mut a = Big::new_int(1);
        let mut z = e.clone();
        let mut s = self.clone();
        loop {
            let bt = z.parity();
            z.fshr(1);
            if bt == 1 {
                a = Big::modmul(&a, &s, m)
            }
            if z.is_zilch() {
                break;
            }
            s = Big::modsqr(&s, m);
        }
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero() {
        let zero = Big::new_int(0);
        assert!(zero.is_zilch());

        let zero2 = Big::new();
        assert!(zero2.is_zilch());
        assert_eq!(zero, zero2);

        let zero2 = Big::new_ints(&[0; NLEN]);
        assert!(zero2.is_zilch());

        let mut zero2 = Big::new_int(123456789);
        zero2.zero();
        assert!(zero2.is_zilch());

        let mut zero2 = Big::new_int(9876543210);
        let zero_dbig = DBig::new();
        zero2.dcopy(&zero_dbig);
        assert!(zero2.is_zilch());
    }

    #[test]
    fn test_one() {
        let one = Big::new_int(1);
        assert!(one.is_unity());

        let mut one2 = Big::new();
        one2.one();
        assert!(one2.is_unity());
    }

    #[test]
    fn test_add_int() {
        // 9999 + 77 = 10076
        let a = Big::new_int(9999);
        let mut b = Big::new_int(77);
        let mut c = a.clone();
        c.add(&b);
        assert_eq!(c, Big::new_int(10076));

        // 77 + 9999 = 10076
        b.add(&a);
        assert_eq!(b, Big::new_int(10076));

        // -1000 + 1000 = 0
        let mut negatives = Big::new_int(-1000);
        let positives = Big::new_int(1000);
        negatives.add(&positives);
        assert!(negatives.is_zilch());
    }

    #[test]
    fn test_sub_int() {
        // 1 - 1 = 0
        let one = Big::new_int(1);
        let mut zero = one.clone();
        zero.sub(&one);
        assert!(zero.is_zilch());

        // -3 - 1 =  -4
        let mut minus_4 = Big::new_int(-3);
        minus_4.sub(&one);
        assert_eq!(minus_4, Big::new_int(-4));

        // -10 - (-23) = 13
        let mut thirteen = Big::new_int(-10);
        let minus_23 = Big::new_int(-23);
        thirteen.sub(&minus_23);
        assert_eq!(thirteen, Big::new_int(13));

        // 1000 - 333 = 777
        let mut sevens = Big::new_int(1000);
        let twos = Big::new_int(223);
        sevens.sub(&twos);
        assert_eq!(sevens, Big::new_int(777));
    }

    #[test]
    fn test_get_set() {
        let mut big = Big::new();

        for i in 0..NLEN {
            assert_eq!(big.get(i), 0);

            let a: Chunk = (i + 1) as Chunk;
            big.set(i, a);
            assert_eq!(big.get(i), a);
        }
    }

    #[test]
    fn test_xor_top() {
        let mut big = Big::new();
        let a = 0b1100_0011;
        big.set(NLEN - 1, a);

        let b = 0b1001_1001;
        big.xor_top(b);

        assert_eq!(big.get(NLEN - 1), a ^ b);
    }

    #[test]
    fn test_dcopy() {
        // Create DBig with words 0, 1, 2, ...
        let mut dbig = DBig::new();
        for (i, a) in dbig.w.iter_mut().enumerate() {
            *a = i as Chunk;
        }

        let mut big = Big::new();
        big.dcopy(&dbig);
        for i in 0..NLEN {
            assert_eq!(big.get(i), i as Chunk);
        }

        let big2 = Big::new_dcopy(&dbig);
        for i in 0..NLEN {
            assert_eq!(big2.get(i), i as Chunk);
        }
    }
}
