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

use std::str::FromStr;

use super::big;
use super::big::Big;
use super::dbig::DBig;
use super::rom;
use crate::arch::{self, Chunk};
use crate::types::ModType;

#[derive(Clone)]
pub struct FP {
    pub x: Big,
    pub xes: i32,
}

impl PartialEq for FP {
    fn eq(&self, other: &FP) -> bool {
        self.equals(other)
    }
}

impl Eq for FP {}

impl fmt::Display for FP {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FP: [ {} ]", self.to_string())
    }
}

impl fmt::Debug for FP {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FP: [ {} ]", self.to_string())
    }
}

pub use super::rom::{MOD8, MODBITS, MODTYPE, SH};
use std::fmt;
use std::str::SplitWhitespace;

pub const FEXCESS: i32 = (1 << SH) - 1;
pub const OMASK: Chunk = (-1) << (MODBITS % big::BASEBITS);
pub const TBITS: usize = MODBITS % big::BASEBITS; // Number of active bits in top word
pub const TMASK: Chunk = (1 << TBITS) - 1;

impl FP {
    /// New
    ///
    /// Creates a new Fp at 0.
    #[inline(always)]
    pub fn new() -> FP {
        FP {
            x: Big::new(),
            xes: 1,
        }
    }

    /// New Int
    ///
    /// Creates a FP from an int.
    #[inline(always)]
    pub fn new_int(a: isize) -> FP {
        let mut f = FP::new();
        f.x.inc(a);
        f.nres();
        return f;
    }

    /// New Ints
    ///
    /// Creates a Fp from a slice of raw ints in Big form.
    #[inline(always)]
    pub fn new_ints(w: &[Chunk]) -> FP {
        Self::new_big(Big::new_ints(w))
    }

    /// New Big
    ///
    /// Creates a Fp from a Big.
    #[inline(always)]
    pub fn new_big(x: Big) -> FP {
        let mut f = FP { x, xes: 1 };
        f.nres();
        f
    }

    pub fn nres(&mut self) {
        if MODTYPE != ModType::PseudoMersenne && MODTYPE != ModType::GeneralisedMersenne {
            let r = Big::new_ints(&rom::R2MODP);
            let mut d = Big::mul(&(self.x), &r);
            self.x = FP::modulo(&mut d);
            self.xes = 2;
        } else {
            self.xes = 1;
        }
    }

    /// To String
    ///
    /// Converts a `FP` to a hex string.
    pub fn to_string(&self) -> String {
        self.redc().to_string()
    }

    /// From Hex Iterator
    #[inline(always)]
    pub fn from_hex_iter(iter: &mut SplitWhitespace) -> FP {
        let xes = i32::from_str(iter.next().unwrap()).unwrap();
        let x = iter.next().unwrap();
        FP {
            x: Big::from_string(x.to_string()),
            xes,
        }
    }

    /// From Hex
    ///
    /// Converts to Fp from a hex string.
    #[inline(always)]
    pub fn from_hex(val: String) -> FP {
        let mut s = val.split_whitespace();
        FP::from_hex_iter(&mut s)
    }

    /// To Hex
    pub fn to_hex(&self) -> String {
        format!("{} {}", self.xes, self.x.to_string())
    }

    /// Reduce
    ///
    /// convert back to regular form
    pub fn redc(&self) -> Big {
        if MODTYPE != ModType::PseudoMersenne && MODTYPE != ModType::GeneralisedMersenne {
            let mut d = DBig::new_scopy(&(self.x));
            return FP::modulo(&mut d);
        }
        self.x.clone()
    }

    /// Modulo
    ///
    /// reduce a DBig to a Big using the appropriate form of the modulus
    pub fn modulo(d: &mut DBig) -> Big {
        if MODTYPE == ModType::PseudoMersenne {
            let mut b = Big::new();
            let mut t = d.split(MODBITS);
            b.dcopy(&d);
            let v = t.pmul(rom::MCONST as isize);

            t.add(&b);
            t.norm();

            let tw = t.w[big::NLEN - 1];
            t.w[big::NLEN - 1] &= TMASK;
            t.w[0] += rom::MCONST * ((tw >> TBITS) + (v << (big::BASEBITS - TBITS)));
            t.norm();
            return t;
        }

        if MODTYPE == ModType::MontgomeryFriendly {
            let mut b = Big::new();
            for i in 0..big::NLEN {
                let x = d.w[i];

                let tuple = Big::mul_add(x, rom::MCONST - 1, x, d.w[big::NLEN + i - 1]);
                d.w[big::NLEN + i] += tuple.0;
                d.w[big::NLEN + i - 1] = tuple.1;
            }

            b.zero();

            for i in 0..big::NLEN {
                b.w[i] = d.w[big::NLEN + i];
            }
            b.norm();
            return b;
        }

        if MODTYPE == ModType::GeneralisedMersenne {
            // GoldiLocks Only
            let mut b = Big::new();
            let t = d.split(MODBITS);
            let rm2 = (MODBITS / 2) as usize;
            b.dcopy(&d);
            b.add(&t);
            let mut dd = DBig::new_scopy(&t);
            dd.shl(rm2);

            let mut tt = dd.split(MODBITS);
            let lo = Big::new_dcopy(&dd);
            b.add(&tt);
            b.add(&lo);
            b.norm();
            tt.shl(rm2);
            b.add(&tt);

            let carry = b.w[big::NLEN - 1] >> TBITS;
            b.w[big::NLEN - 1] &= TMASK;
            b.w[0] += carry;

            b.w[(224 / big::BASEBITS) as usize] += carry << (224 % big::BASEBITS);
            b.norm();
            return b;
        }
        if MODTYPE == ModType::NotSpecial {
            let m = Big::new_ints(&rom::MODULUS);
            return Big::monty(&m, rom::MCONST, d);
        }
        Big::new()
    }

    /// reduce this mod Modulus
    pub fn reduce(&mut self) {
        let mut m = Big::new_ints(&rom::MODULUS);
        let mut r = m.clone();
        let mut sb: usize;
        self.x.norm();
        if self.xes > 16 {
            let q = FP::quo(&self.x, &m);
            let carry = r.pmul(q);
            r.w[big::NLEN - 1] += carry << big::BASEBITS; // correction - put any carry out back in again
            self.x.sub(&r);
            self.x.norm();
            sb = 2;
        } else {
            sb = FP::logb2((self.xes - 1) as u32);
        }
        m.fshl(sb);

        while sb > 0 {
            let sr = Big::ssn(&mut r, &self.x, &mut m);
            self.x.cmove(&r, 1 - sr);
            sb -= 1;
        }

        self.xes = 1;
    }

    /// Check if self is 0
    pub fn is_zilch(&self) -> bool {
        let mut a = self.clone();
        a.reduce();
        a.x.is_zilch()
    }

    /// copy from Big b
    pub fn bcopy(&mut self, b: &Big) {
        self.x = b.clone();
        self.nres();
    }

    /// set this=0
    pub fn zero(&mut self) {
        self.x.zero();
        self.xes = 1;
    }

    /// set this=1
    pub fn one(&mut self) {
        self.x.one();
        self.nres()
    }

    /// normalise this
    pub fn norm(&mut self) {
        self.x.norm();
    }

    /// swap FPs depending on d
    pub fn cswap(&mut self, b: &mut FP, d: isize) {
        self.x.cswap(&mut (b.x), d);
        let mut c = d as i32;
        c = !(c - 1);
        let t = c & (self.xes ^ b.xes);
        self.xes ^= t;
        b.xes ^= t;
    }

    /// copy FPs depending on d
    pub fn cmove(&mut self, b: &FP, d: isize) {
        self.x.cmove(&(b.x), d);
        let c = d as i32;
        self.xes ^= (self.xes ^ b.xes) & (-c);
    }

    /// this*=b mod Modulus
    pub fn mul(&mut self, b: &FP) {
        if i64::from(self.xes) * i64::from(b.xes) > i64::from(FEXCESS) {
            self.reduce()
        }

        let mut d = Big::mul(&(self.x), &(b.x));
        self.x = FP::modulo(&mut d);
        self.xes = 2;
    }

    fn logb2(w: u32) -> usize {
        let mut v = w;
        v |= v >> 1;
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;

        v = v - ((v >> 1) & 0x55555555);
        v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
        ((((v + (v >> 4)) & 0xF0F0F0F).wrapping_mul(0x1010101)) >> 24) as usize
    }

    /// Find approximation to quotient of a/m
    /// Out by at most 2.
    /// Note that MAXXES is bounded to be 2-bits less than half a word
    fn quo(n: &Big, m: &Big) -> isize {
        let hb = arch::CHUNK / 2;

        if TBITS < hb {
            let sh = hb - TBITS;
            let num = (n.w[big::NLEN - 1] << sh) | (n.w[big::NLEN - 2] >> (big::BASEBITS - sh));
            let den = (m.w[big::NLEN - 1] << sh) | (m.w[big::NLEN - 2] >> (big::BASEBITS - sh));
            return (num / (den + 1)) as isize;
        } else {
            let num = n.w[big::NLEN - 1];
            let den = m.w[big::NLEN - 1];
            return (num / (den + 1)) as isize;
        }
    }

    /// this = -this mod Modulus
    pub fn neg(&mut self) {
        let mut p = Big::new_ints(&rom::MODULUS);
        let sb = FP::logb2((self.xes - 1) as u32);

        p.fshl(sb);
        self.x.rsub(&p);
        self.xes = 1 << (sb as i32) + 1;
        if self.xes > FEXCESS {
            self.reduce()
        }
    }

    /// this*=c mod Modulus, where c is a small int
    pub fn imul(&mut self, c: isize) {
        let mut cc = c;
        let mut s = false;
        if cc < 0 {
            cc = -cc;
            s = true;
        }

        if MODTYPE == ModType::PseudoMersenne || MODTYPE == ModType::GeneralisedMersenne {
            let mut d = self.x.pxmul(cc);
            self.x = FP::modulo(&mut d);
            self.xes = 2
        } else {
            if self.xes * (cc as i32) <= FEXCESS {
                self.x.pmul(cc);
                self.xes *= cc as i32;
            } else {
                let n = FP::new_int(cc);
                self.mul(&n);
            }
        }

        if s {
            self.neg();
            self.norm();
        }
    }

    /// self*=self mod Modulus
    pub fn sqr(&mut self) {
        if i64::from(self.xes) * i64::from(self.xes) > i64::from(FEXCESS) {
            self.reduce()
        }

        let mut d = Big::sqr(&(self.x));
        self.x = FP::modulo(&mut d);
        self.xes = 2
    }

    /// self+=b
    pub fn add(&mut self, b: &FP) {
        self.x.add(&(b.x));
        self.xes += b.xes;
        if self.xes > FEXCESS {
            self.reduce()
        }
    }

    /// self+=self
    pub fn dbl(&mut self) {
        self.x.dbl();
        self.xes += self.xes;
        if self.xes > FEXCESS {
            self.reduce()
        }
    }

    /// self-=b
    pub fn sub(&mut self, b: &FP) {
        let mut n = b.clone();
        n.neg();
        self.add(&n);
    }

    /// self=b-self
    pub fn rsub(&mut self, b: &FP) {
        self.neg();
        self.add(&b);
    }

    /// self/=2 mod Modulus
    pub fn div2(&mut self) {
        if self.x.parity() == 0 {
            self.x.fshr(1);
        } else {
            let p = Big::new_ints(&rom::MODULUS);
            self.x.add(&p);
            self.x.norm();
            self.x.fshr(1);
        }
    }

    /// Modular Inverse for pseudo-Mersenne primes
    ///
    /// Return self ^ (p - 3) / 4 or self ^ (p - 5) / 8
    /// https://eprint.iacr.org/2018/1038
    #[inline(always)]
    pub fn fpow(&self) -> FP {
        let ac: [isize; 11] = [1, 2, 3, 6, 12, 15, 30, 60, 120, 240, 255];
        let mut xp: [FP; 11] = [
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
        ];
        // phase 1
        xp[0] = self.clone(); // 1
        xp[1] = self.clone();
        xp[1].sqr(); // 2
        let mut t = xp[1].clone();
        xp[2] = t.clone();
        xp[2].mul(&self); // 3
        t = xp[2].clone();
        xp[3] = t.clone();
        xp[3].sqr(); // 6
        t = xp[3].clone();
        xp[4] = t.clone();
        xp[4].sqr(); // 12
        t = xp[4].clone();
        t.mul(&xp[2]);
        xp[5] = t.clone(); // 15
        t = xp[5].clone();
        xp[6] = t.clone();
        xp[6].sqr(); // 30
        t = xp[6].clone();
        xp[7] = t.clone();
        xp[7].sqr(); // 60
        t = xp[7].clone();
        xp[8] = t.clone();
        xp[8].sqr(); // 120
        t = xp[8].clone();
        xp[9] = t.clone();
        xp[9].sqr(); // 240
        t = xp[9].clone();
        t.mul(&xp[5]);
        xp[10] = t.clone(); // 255

        let mut n = MODBITS as isize;
        let c: isize;

        if MODTYPE == ModType::GeneralisedMersenne {
            // Goldilocks ONLY
            n /= 2;
        }

        if MOD8 == 5 {
            n -= 3;
            c = ((rom::MCONST as isize) + 5) / 8;
        } else {
            n -= 2;
            c = ((rom::MCONST as isize) + 3) / 4;
        }
        let mut bw = 0;
        let mut w = 1;
        while w < c {
            w *= 2;
            bw += 1;
        }
        let mut k = w - c;

        let mut i = 10;
        let mut key = FP::new();
        if k != 0 {
            while ac[i] > k {
                i -= 1;
            }
            key = xp[i].clone();
            k -= ac[i];
        }
        while k != 0 {
            i -= 1;
            if ac[i] > k {
                continue;
            }
            key.mul(&xp[i]);
            k -= ac[i];
        }
        // phase 2
        t = xp[2].clone();
        xp[1] = t.clone();
        t = xp[5].clone();
        xp[2] = t.clone();
        t = xp[10].clone();
        xp[3] = t.clone();

        let mut j = 3;
        let mut m = 8;
        let nw = n - bw;

        while 2 * m < nw {
            t = xp[j].clone();
            j += 1;
            for _ in 0..m {
                t.sqr();
            }
            let mut r = xp[j - 1].clone();
            r.mul(&t);
            xp[j] = r.clone();
            m *= 2;
        }
        let mut lo = nw - m;
        let mut r = xp[j].clone();

        while lo != 0 {
            m /= 2;
            j -= 1;
            if lo < m {
                continue;
            }
            lo -= m;
            t = r.clone();
            for _ in 0..m {
                t.sqr();
            }
            r = t.clone();
            r.mul(&xp[j]);
        }
        // phase 3
        if bw != 0 {
            for _ in 0..bw {
                r.sqr();
            }
            r.mul(&key);
        }
        if MODTYPE == ModType::GeneralisedMersenne {
            // Goldilocks ONLY
            key = r.clone();
            r.sqr();
            r.mul(&self);
            for _ in 0..=n {
                r.sqr();
            }
            r.mul(&key);
        }
        r
    }

    /// self=1/self mod Modulus
    pub fn inverse(&mut self) {
        if MODTYPE == ModType::PseudoMersenne || MODTYPE == ModType::GeneralisedMersenne {
            let mut y = self.fpow();
            if MOD8 == 5 {
                let mut t = self.clone();
                t.sqr();
                self.mul(&t);
                y.sqr();
            }
            y.sqr();
            y.sqr();
            self.mul(&y);
        } else {
            // Constant time inversion using Fermat's little theorem.
            // Fermat's little theorem says for a prime p and for any a < p, a^p = a % p => a^(p-1) = 1 % p => a^(p-2) = a^-1 % p
            let mut m2 = Big::new_ints(&rom::MODULUS);
            m2.dec(2);
            m2.norm();
            let inv = self.pow(&mut m2);
            *self = inv.clone();
        }
    }

    /// return TRUE if self==a
    pub fn equals(&self, a: &FP) -> bool {
        let mut f = self.clone();
        let mut s = a.clone();
        f.reduce();
        s.reduce();
        if Big::comp(&(f.x), &(s.x)) == 0 {
            return true;
        }
        return false;
    }

    /// Power
    ///
    /// return self ^ e mod Modulus
    #[inline(always)]
    pub fn pow(&mut self, e: &mut Big) -> FP {
        let mut tb: [FP; 16] = [
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
            FP::new(),
        ];
        const CT: usize = 1 + (big::NLEN * (big::BASEBITS as usize) + 3) / 4;
        let mut w: [i8; CT] = [0; CT];

        self.norm();
        let mut t = e.clone();
        t.norm();
        let nb = 1 + (t.nbits() + 3) / 4;

        for i in 0..nb {
            let lsbs = t.lastbits(4);
            t.dec(lsbs);
            t.norm();
            w[i] = lsbs as i8;
            t.fshr(4);
        }
        tb[0].one();
        tb[1] = self.clone();

        for i in 2..16 {
            tb[i] = tb[i - 1].clone();
            tb[i].mul(&self);
        }
        let mut r = tb[w[nb - 1] as usize].clone();
        for i in (0..nb - 1).rev() {
            r.sqr();
            r.sqr();
            r.sqr();
            r.sqr();
            r.mul(&tb[w[i] as usize])
        }
        r.reduce();
        return r;
    }

    /// Square Root
    ///
    /// return sqrt(this) mod Modulus
    #[inline(always)]
    pub fn sqrt(&mut self) -> FP {
        self.reduce();

        if MOD8 == 5 {
            let v: FP;
            let mut i = self.clone();
            i.x.shl(1);
            if MODTYPE == ModType::PseudoMersenne || MODTYPE == ModType::GeneralisedMersenne {
                v = i.fpow();
            } else {
                let mut p = Big::new_ints(&rom::MODULUS);
                p.dec(5);
                p.norm();
                p.shr(3);
                v = i.pow(&mut p);
            }
            i.mul(&v);
            i.mul(&v);
            i.x.dec(1);
            let mut r = self.clone();
            r.mul(&v);
            r.mul(&i);
            r.reduce();
            return r;
        } else {
            let mut r: FP;
            if MODTYPE == ModType::PseudoMersenne || MODTYPE == ModType::GeneralisedMersenne {
                r = self.fpow();
                r.mul(self);
            } else {
                let mut p = Big::new_ints(&rom::MODULUS);
                p.inc(1);
                p.norm();
                p.shr(2);
                r = self.pow(&mut p);
            }
            return r;
        }
    }

    /// return jacobi symbol (this/Modulus)
    pub fn jacobi(&self) -> isize {
        let p = Big::new_ints(&rom::MODULUS);
        let mut w = self.redc();
        return w.jacobi(&p);
    }

    /// Checks sign of a field element
    ///
    /// true if Negative, if a % 2 == 1
    /// false if Positive, if a % 2 == 0
    ///
    /// Not constant time.
    /// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-4.1
    pub fn sgn0(&self) -> bool {
        let x = self.redc();
        if x.parity() == 0 {
            false
        } else {
            true
        }
    }
}
