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

use std::fmt;
use std::str::SplitWhitespace;

use super::big::Big;
use super::dbig::DBig;
use super::fp;
use super::fp::FP;
use super::rom;

#[derive(Clone)]
pub struct FP2 {
    a: FP,
    b: FP,
}

impl PartialEq for FP2 {
    fn eq(&self, other: &FP2) -> bool {
        self.equals(other)
    }
}

impl Eq for FP2 {}

impl fmt::Display for FP2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FP2: [ {}, {} ]", self.a, self.b)
    }
}

impl fmt::Debug for FP2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FP2: [ {}, {} ]", self.a, self.b)
    }
}

impl FP2 {
    /// New
    ///
    /// Create a Fp2 set to 0.
    #[inline(always)]
    pub fn new() -> FP2 {
        FP2 {
            a: FP::new(),
            b: FP::new(),
        }
    }

    /// New Int
    ///
    /// Create a Fp2 setting `a` as an int, `b` to 0.
    #[inline(always)]
    pub fn new_int(a: isize) -> FP2 {
        FP2 {
            a: FP::new_int(a),
            b: FP::new(),
        }
    }

    /// New Ints
    ///
    /// Creates a Fp2 setting `a` and `b` as ints.
    #[inline(always)]
    pub fn new_ints(a: isize, b: isize) -> FP2 {
        FP2 {
            a: FP::new_int(a),
            b: FP::new_int(b),
        }
    }

    /// New Fp's
    ///
    /// Create a new Fp2 from two Fp's.
    #[inline(always)]
    pub fn new_fps(a: FP, b: FP) -> FP2 {
        FP2 { a, b }
    }

    /// New Bigs
    ///
    /// Create a new Fp2 from two Bigs.
    #[inline(always)]
    pub fn new_bigs(c: Big, d: Big) -> FP2 {
        FP2 {
            a: FP::new_big(c),
            b: FP::new_big(d),
        }
    }

    /// New Fp
    ///
    /// Creates a Fp2 setting `a` from a Fp.
    #[inline(always)]
    pub fn new_fp(a: FP) -> FP2 {
        FP2 { a, b: FP::new() }
    }

    /// New Big
    ///
    /// Creates a new Fp2 setting `a` from a Big.
    #[inline(always)]
    pub fn new_big(c: Big) -> FP2 {
        FP2 {
            a: FP::new_big(c),
            b: FP::new(),
        }
    }

    /* reduce components mod Modulus */
    pub fn reduce(&mut self) {
        self.a.reduce();
        self.b.reduce();
    }

    /* normalise components of w */
    pub fn norm(&mut self) {
        self.a.norm();
        self.b.norm();
    }

    /* test self=0 ? */
    pub fn is_zilch(&self) -> bool {
        return self.a.is_zilch() && self.b.is_zilch();
    }

    pub fn cmove(&mut self, g: &FP2, d: isize) {
        self.a.cmove(&g.a, d);
        self.b.cmove(&g.b, d);
    }

    /* test self=1 ? */
    pub fn is_unity(&self) -> bool {
        let one = FP::new_int(1);
        return self.a.equals(&one) && self.b.is_zilch();
    }

    /* test self=x */
    pub fn equals(&self, x: &FP2) -> bool {
        return self.a.equals(&x.a) && self.b.equals(&x.b);
    }

    /* extract a */
    pub fn geta(&self) -> Big {
        return self.a.redc();
    }

    /* extract b */
    pub fn getb(&self) -> Big {
        return self.b.redc();
    }

    /* set self=0 */
    pub fn zero(&mut self) {
        self.a.zero();
        self.b.zero();
    }

    /* set self=1 */
    pub fn one(&mut self) {
        self.a.one();
        self.b.zero();
    }

    /* negate self mod Modulus */
    pub fn neg(&mut self) {
        let mut m = self.a.clone();
        m.add(&self.b);
        m.neg();
        let mut t = m.clone();
        t.add(&self.b);
        self.b = m;
        self.b.add(&self.a);
        self.a = t;
    }

    /* set to a-ib */
    pub fn conj(&mut self) {
        self.b.neg();
        self.b.norm();
    }

    /* self+=a */
    pub fn add(&mut self, x: &FP2) {
        self.a.add(&x.a);
        self.b.add(&x.b);
    }

    pub fn dbl(&mut self) {
        self.a.dbl();
        self.b.dbl();
    }

    /* self-=a */
    pub fn sub(&mut self, x: &FP2) {
        let mut m = x.clone();
        m.neg();
        self.add(&m);
    }

    /* self=a-self */
    pub fn rsub(&mut self, x: &FP2) {
        self.neg();
        self.add(x);
    }

    /* self*=s, where s is an FP */
    pub fn pmul(&mut self, s: &FP) {
        self.a.mul(s);
        self.b.mul(s);
    }

    /* self*=i, where i is an int */
    pub fn imul(&mut self, c: isize) {
        self.a.imul(c);
        self.b.imul(c);
    }

    /* self*=self */
    pub fn sqr(&mut self) {
        let mut w1 = self.a.clone();
        let mut w3 = self.a.clone();
        let mut mb = self.b.clone();

        w1.add(&self.b);

        w3.add(&self.a);
        w3.norm();
        self.b.mul(&w3);

        mb.neg();
        self.a.add(&mb);

        w1.norm();
        self.a.norm();

        self.a.mul(&w1);
    }

    /* this*=y */
    pub fn mul(&mut self, y: &FP2) {
        if i64::from(self.a.xes + self.b.xes) * i64::from(y.a.xes + y.b.xes)
            > i64::from(fp::FEXCESS)
        {
            if self.a.xes > 1 {
                self.a.reduce()
            }
            if self.b.xes > 1 {
                self.b.reduce()
            }
        }

        let p = Big::new_ints(&rom::MODULUS);
        let mut pr = DBig::new();

        pr.ucopy(&p);

        let mut c = self.a.x.clone();
        let mut d = y.a.x.clone();

        let mut a = Big::mul(&self.a.x, &y.a.x);
        let mut b = Big::mul(&self.b.x, &y.b.x);

        c.add(&self.b.x);
        c.norm();
        d.add(&y.b.x);
        d.norm();

        let mut e = Big::mul(&c, &d);
        let mut f = a.clone();
        f.add(&b);
        b.rsub(&pr);

        a.add(&b);
        a.norm();
        e.sub(&f);
        e.norm();

        self.a.x = FP::modulo(&mut a);
        self.a.xes = 3;
        self.b.x = FP::modulo(&mut e);
        self.b.xes = 2;
    }

    /* sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2)) */
    /* returns true if this is QR */
    pub fn sqrt(&mut self) -> bool {
        if self.is_zilch() {
            return true;
        }
        let mut w1 = self.b.clone();
        let mut w2 = self.a.clone();
        w1.sqr();
        w2.sqr();
        w1.add(&w2);
        if w1.jacobi() != 1 {
            self.zero();
            return false;
        }
        w2 = w1.sqrt();
        w1 = w2.clone();
        w2 = self.a.clone();
        w2.add(&w1);
        w2.norm();
        w2.div2();
        if w2.jacobi() != 1 {
            w2 = self.a.clone();
            w2.sub(&w1);
            w2.norm();
            w2.div2();
            if w2.jacobi() != 1 {
                self.zero();
                return false;
            }
        }
        w1 = w2.sqrt();
        self.a = w1.clone();
        w1.dbl();
        w1.inverse();
        self.b.mul(&w1);
        return true;
    }

    /// To String
    ///
    /// Converts a `FP2` to a hex string.
    pub fn to_string(&self) -> String {
        return format!("[{},{}]", self.a.to_string(), self.b.to_string());
    }

    /// To Hex
    pub fn to_hex(&self) -> String {
        format!("{} {}", self.a.to_hex(), self.b.to_hex())
    }

    /// From Hex Iterator
    #[inline(always)]
    pub fn from_hex_iter(iter: &mut SplitWhitespace) -> FP2 {
        FP2 {
            a: FP::from_hex_iter(iter),
            b: FP::from_hex_iter(iter),
        }
    }

    /// From Hex
    #[inline(always)]
    pub fn from_hex(val: String) -> FP2 {
        let mut iter = val.split_whitespace();
        return FP2::from_hex_iter(&mut iter);
    }

    /* self=1/self */
    pub fn inverse(&mut self) {
        self.norm();
        let mut w1 = self.a.clone();
        let mut w2 = self.b.clone();

        w1.sqr();
        w2.sqr();
        w1.add(&w2);
        w1.inverse();
        self.a.mul(&w1);
        w1.neg();
        w1.norm();
        self.b.mul(&w1);
    }

    /* self/=2 */
    pub fn div2(&mut self) {
        self.a.div2();
        self.b.div2();
    }

    /* self*=sqrt(-1) */
    pub fn times_i(&mut self) {
        let z = self.a.clone();
        self.a = self.b.clone();
        self.a.neg();
        self.b = z;
    }

    /* w*=(1+sqrt(-1)) */
    /* where X*2-(1+sqrt(-1)) is irreducible for FP4, assumes p=3 mod 8 */
    pub fn mul_ip(&mut self) {
        let t = self.clone();
        let z = self.a.clone();
        self.a = self.b.clone();
        self.a.neg();
        self.b = z.clone();
        self.add(&t);
    }

    pub fn div_ip2(&mut self) {
        let mut t = FP2::new();
        self.norm();
        t.a = self.a.clone();
        t.a.add(&self.b);
        t.b = self.b.clone();
        t.b.sub(&self.a);
        t.norm();
        *self = t;
    }

    /* w/=(1+sqrt(-1)) */
    pub fn div_ip(&mut self) {
        let mut t = FP2::new();
        self.norm();
        t.a = self.a.clone();
        t.a.add(&self.b);
        t.b = self.b.clone();
        t.b.sub(&self.a);
        t.norm();
        *self = t;
        self.div2();
    }

    // ((a + b) , (a - b))
    pub fn spmt(&mut self) {
        let b = self.b.clone();
        self.b = self.a.clone();
        self.a.add(&b);
        self.b.sub(&b);
    }

    /// Checks sign of a field element
    ///
    /// true if Negative
    /// false if Positive
    ///
    /// Not constant time.
    /// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-4.1
    pub fn sgn0(&self) -> bool {
        if self.a.is_zilch() {
            self.b.sgn0()
        } else {
            self.a.sgn0()
        }
    }
}
