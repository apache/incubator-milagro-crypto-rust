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

use std::str::SplitWhitespace;

use super::big::Big;
use super::fp::FP;
use super::fp2::FP2;

#[derive(Clone)]
pub struct FP4 {
    a: FP2,
    b: FP2,
}

impl PartialEq for FP4 {
    fn eq(&self, other: &FP4) -> bool {
        self.equals(other)
    }
}

impl Eq for FP4 {}

impl FP4 {
    /// New Fp4
    ///
    /// Create a new Fp4 set to 0.
    #[inline(always)]
    pub fn new() -> FP4 {
        FP4 {
            a: FP2::new(),
            b: FP2::new(),
        }
    }

    /// New Int
    #[inline(always)]
    pub fn new_int(a: isize) -> FP4 {
        FP4 {
            a: FP2::new_int(a),
            b: FP2::new(),
        }
    }

    /// New Fp2's
    ///
    /// Create a Fp4 from two Fp2's
    #[inline(always)]
    pub fn new_fp2s(a: FP2, b: FP2) -> FP4 {
        FP4 { a, b }
    }

    /// New Fp2
    ///
    /// Create a Fp4 setting `a` from an Fp and `b` to 0.
    #[inline(always)]
    pub fn new_fp2(a: FP2) -> FP4 {
        FP4 { a, b: FP2::new() }
    }

    pub fn set_fp2s(&mut self, c: &FP2, d: &FP2) {
        self.a = c.clone();
        self.b = d.clone();
    }

    pub fn set_fp2(&mut self, c: &FP2) {
        self.a = c.clone();
        self.b.zero();
    }

    pub fn set_fp2h(&mut self, c: &FP2) {
        self.b = c.clone();
        self.a.zero();
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

    pub fn cmove(&mut self, g: &FP4, d: isize) {
        self.a.cmove(&g.a, d);
        self.b.cmove(&g.b, d);
    }

    /* test self=0 ? */
    pub fn is_zilch(&self) -> bool {
        self.a.is_zilch() && self.b.is_zilch()
    }

    /* test self=1 ? */
    pub fn is_unity(&self) -> bool {
        let one = FP2::new_int(1);
        self.a.equals(&one) && self.b.is_zilch()
    }

    /* test is w real? That is in a+ib test b is zero */
    pub fn isreal(&self) -> bool {
        self.b.is_zilch()
    }

    /// Real
    ///
    /// Extract real part (`a`).
    #[inline(always)]
    pub fn real(&self) -> FP2 {
        self.geta()
    }

    /// Get A
    ///
    /// Returns `a`
    #[inline(always)]
    pub fn geta(&self) -> FP2 {
        self.a.clone()
    }

    /// Get B
    ///
    /// Extract imaginary part (`b`).
    #[inline(always)]
    pub fn getb(&self) -> FP2 {
        self.b.clone()
    }

    /// Equals
    ///
    /// self == x
    pub fn equals(&self, x: &FP4) -> bool {
        return self.a.equals(&x.a) && self.b.equals(&x.b);
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
        self.norm();
        let mut m = self.geta();

        m.add(&self.b);
        m.neg();
        let mut t = m.clone();
        t.add(&self.b);
        self.b = m.clone();
        self.b.add(&self.a);
        self.a = t.clone();
        self.norm();
    }

    /* set to a-ib */
    pub fn conj(&mut self) {
        self.b.neg();
        self.norm();
    }

    /* self=-conjugate(self) */
    pub fn nconj(&mut self) {
        self.a.neg();
        self.norm();
    }

    /* self+=a */
    pub fn add(&mut self, x: &FP4) {
        self.a.add(&x.a);
        self.b.add(&x.b);
    }

    pub fn padd(&mut self, x: &FP2) {
        self.a.add(x);
    }

    pub fn dbl(&mut self) {
        self.a.dbl();
        self.b.dbl();
    }

    /* self-=a */
    pub fn sub(&mut self, x: &FP4) {
        let mut m = x.clone();
        m.neg();
        self.add(&m);
    }

    /* self-=a */
    pub fn rsub(&mut self, x: &FP4) {
        self.neg();
        self.add(x);
    }

    /* self*=s, where s is an FP2 */
    pub fn pmul(&mut self, s: &FP2) {
        self.a.mul(s);
        self.b.mul(s);
    }

    /* self*=s, where s is an FP */
    pub fn qmul(&mut self, s: &FP) {
        self.a.pmul(s);
        self.b.pmul(s);
    }

    /* self*=i, where i is an int */
    pub fn imul(&mut self, c: isize) {
        self.a.imul(c);
        self.b.imul(c);
    }

    /* self*=self */

    pub fn sqr(&mut self) {
        let mut t1 = self.geta();
        let mut t2 = self.getb();
        let mut t3 = self.geta();

        t3.mul(&self.b);
        t1.add(&self.b);
        t2.mul_ip();

        t2.add(&self.a);

        t1.norm();
        t2.norm();

        self.a = t1.clone();

        self.a.mul(&t2);

        t2 = t3.clone();
        t2.mul_ip();
        t2.add(&t3);
        t2.norm();
        t2.neg();
        self.a.add(&t2);

        t3.dbl();
        self.b = t3.clone();

        self.norm();
    }

    /* self*=y */
    pub fn mul(&mut self, y: &FP4) {
        //self.norm();

        let mut t1 = self.geta();
        let mut t2 = self.getb();
        let mut t3 = y.getb();
        let mut t4 = self.getb();

        t1.mul(&y.a);
        t2.mul(&y.b);
        t3.add(&y.a);
        t4.add(&self.a);

        t3.norm();
        t4.norm();

        t4.mul(&t3);

        t3 = t1.clone();
        t3.neg();
        t4.add(&t3);
        t4.norm();

        t3 = t2.clone();
        t3.neg();
        self.b = t4.clone();
        self.b.add(&t3);

        t2.mul_ip();
        self.a = t2.clone();
        self.a.add(&t1);

        self.norm();
    }

    /// To String
    ///
    /// Converts a `FP4` to a hex string.
    pub fn to_string(&self) -> String {
        return format!("[{},{}]", self.a.to_string(), self.b.to_string());
    }

    pub fn to_hex(&self) -> String {
        format!("{} {}", self.a.to_hex(), self.b.to_hex())
    }

    /// From Hex Iterator
    #[inline(always)]
    pub fn from_hex_iter(iter: &mut SplitWhitespace) -> FP4 {
        FP4 {
            a: FP2::from_hex_iter(iter),
            b: FP2::from_hex_iter(iter),
        }
    }

    /// From Hex
    #[inline(always)]
    pub fn from_hex(val: String) -> FP4 {
        let mut iter = val.split_whitespace();
        return FP4::from_hex_iter(&mut iter);
    }

    /// Inverse
    ///
    /// self = 1 / self
    pub fn inverse(&mut self) {
        //self.norm();

        let mut t1 = self.geta();
        let mut t2 = self.getb();

        t1.sqr();
        t2.sqr();
        t2.mul_ip();
        t2.norm();
        t1.sub(&t2);
        t1.inverse();
        self.a.mul(&t1);
        t1.neg();
        t1.norm();
        self.b.mul(&t1);
    }

    /* self*=i where i = sqrt(-1+sqrt(-1)) */
    pub fn times_i(&mut self) {
        let mut s = self.getb();
        let mut t = self.getb();
        s.times_i();
        t.add(&s);
        self.b = self.geta();
        self.a = t.clone();
        self.norm();
    }

    /* self=self^p using Frobenius */
    pub fn frob(&mut self, f: &FP2) {
        self.a.conj();
        self.b.conj();
        self.b.mul(f);
    }

    /// Power
    ///
    /// Return self ^ e
    #[inline(always)]
    pub fn pow(&self, e: &Big) -> FP4 {
        let mut w = self.clone();
        w.norm();
        let mut z = e.clone();
        let mut r = FP4::new_int(1);
        z.norm();
        loop {
            let bt = z.parity();
            z.fshr(1);
            if bt == 1 {
                r.mul(&w)
            };
            if z.is_zilch() {
                break;
            }
            w.sqr();
        }
        r.reduce();
        return r;
    }

    /* XTR xtr_a function */
    pub fn xtr_a(&mut self, w: &FP4, y: &FP4, z: &FP4) {
        let mut r = w.clone();
        let mut t = w.clone();
        r.sub(y);
        r.norm();
        r.pmul(&self.a);
        t.add(y);
        t.norm();
        t.pmul(&self.b);
        t.times_i();

        *self = r.clone();
        self.add(&t);
        self.add(z);

        self.norm();
    }

    /* XTR xtr_d function */
    pub fn xtr_d(&mut self) {
        let mut w = self.clone();
        self.sqr();
        w.conj();
        w.dbl();
        w.norm();
        self.sub(&w);
        self.reduce();
    }

    /// XTR Power
    ///
    /// r = x^n using XTR method on traces of FP12s
    #[inline(always)]
    pub fn xtr_pow(&self, n: &Big) -> FP4 {
        let mut sf = self.clone();
        sf.norm();
        let mut a = FP4::new_int(3);
        let mut b = sf.clone();
        let mut c = b.clone();
        c.xtr_d();

        let par = n.parity();
        let mut v = n.clone();
        v.norm();
        v.fshr(1);
        if par == 0 {
            v.dec(1);
            v.norm();
        }

        let nb = v.nbits();
        for i in (0..nb).rev() {
            if v.bit(i) != 1 {
                let t = b.clone();
                sf.conj();
                c.conj();
                b.xtr_a(&a, &sf, &c);
                sf.conj();
                c = t.clone();
                c.xtr_d();
                a.xtr_d();
            } else {
                let mut t = a.clone();
                t.conj();
                a = b.clone();
                a.xtr_d();
                b.xtr_a(&c, &sf, &t);
                c.xtr_d();
            }
        }
        let mut r = if par == 0 { c.clone() } else { b.clone() };
        r.reduce();
        r
    }

    /// XTR Power 2
    ///
    /// Return ck ^ a * cl ^ n
    /// Using XTR double exponentiation method on traces of FP12s. See Stam thesis.
    #[inline(always)]
    pub fn xtr_pow2(&mut self, ck: &FP4, ckml: &FP4, ckm2l: &FP4, a: &Big, b: &Big) -> FP4 {
        let mut e = a.clone();
        let mut d = b.clone();
        e.norm();
        d.norm();

        let mut cu = ck.clone(); // can probably be passed in w/o copying
        let mut cv = self.clone();
        let mut cumv = ckml.clone();
        let mut cum2v = ckm2l.clone();

        let mut f2: usize = 0;
        while d.parity() == 0 && e.parity() == 0 {
            d.fshr(1);
            e.fshr(1);
            f2 += 1;
        }

        while Big::comp(&d, &e) != 0 {
            if Big::comp(&d, &e) > 0 {
                let mut w = e.clone();
                w.imul(4);
                w.norm();
                if Big::comp(&d, &w) <= 0 {
                    w = d.clone();
                    d = e.clone();
                    e.rsub(&w);
                    e.norm();

                    let mut t = cv.clone();
                    t.xtr_a(&cu, &cumv, &cum2v);
                    cum2v = cumv.clone();
                    cum2v.conj();
                    cumv = cv.clone();
                    cv = cu.clone();
                    cu = t.clone();
                } else {
                    if d.parity() == 0 {
                        d.fshr(1);
                        let mut r = cum2v.clone();
                        r.conj();
                        let mut t = cumv.clone();
                        t.xtr_a(&cu, &cv, &r);
                        cum2v = cumv.clone();
                        cum2v.xtr_d();
                        cumv = t.clone();
                        cu.xtr_d();
                    } else {
                        if e.parity() == 1 {
                            d.sub(&e);
                            d.norm();
                            d.fshr(1);
                            let mut t = cv.clone();
                            t.xtr_a(&cu, &cumv, &cum2v);
                            cu.xtr_d();
                            cum2v = cv.clone();
                            cum2v.xtr_d();
                            cum2v.conj();
                            cv = t.clone();
                        } else {
                            w = d.clone();
                            d = e.clone();
                            d.fshr(1);
                            e = w.clone();
                            let mut t = cumv.clone();
                            t.xtr_d();
                            cumv = cum2v.clone();
                            cumv.conj();
                            cum2v = t.clone();
                            cum2v.conj();
                            t = cv.clone();
                            t.xtr_d();
                            cv = cu.clone();
                            cu = t.clone();
                        }
                    }
                }
            }
            if Big::comp(&d, &e) < 0 {
                let mut w = d.clone();
                w.imul(4);
                w.norm();
                if Big::comp(&e, &w) <= 0 {
                    e.sub(&d);
                    e.norm();
                    let mut t = cv.clone();
                    t.xtr_a(&cu, &cumv, &cum2v);
                    cum2v = cumv.clone();
                    cumv = cu.clone();
                    cu = t.clone()
                } else {
                    if e.parity() == 0 {
                        w = d.clone();
                        d = e.clone();
                        d.fshr(1);
                        e = w.clone();
                        let mut t = cumv.clone();
                        t.xtr_d();
                        cumv = cum2v.clone();
                        cumv.conj();
                        cum2v = t.clone();
                        cum2v.conj();
                        t = cv.clone();
                        t.xtr_d();
                        cv = cu.clone();
                        cu = t.clone();
                    } else {
                        if d.parity() == 1 {
                            w = e.clone();
                            e = d.clone();
                            w.sub(&d);
                            w.norm();
                            d = w.clone();
                            d.fshr(1);
                            let mut t = cv.clone();
                            t.xtr_a(&cu, &cumv, &cum2v);
                            cumv.conj();
                            cum2v = cu.clone();
                            cum2v.xtr_d();
                            cum2v.conj();
                            cu = cv.clone();
                            cu.xtr_d();
                            cv = t.clone();
                        } else {
                            d.fshr(1);
                            let mut r = cum2v.clone();
                            r.conj();
                            let mut t = cumv.clone();
                            t.xtr_a(&cu, &cv, &r);
                            cum2v = cumv.clone();
                            cum2v.xtr_d();
                            cumv = t.clone();
                            cu.xtr_d();
                        }
                    }
                }
            }
        }
        let mut r = cv.clone();
        r.xtr_a(&cu, &cumv, &cum2v);
        for _ in 0..f2 {
            r.xtr_d()
        }
        r = r.xtr_pow(&d);
        return r;
    }

    /* this/=2 */
    pub fn div2(&mut self) {
        self.a.div2();
        self.b.div2();
    }

    pub fn div_i(&mut self) {
        let mut u = self.geta();
        let v = self.getb();
        u.div_ip();
        self.a = v;
        self.b = u;
    }

    pub fn div_2i(&mut self) {
        let mut u = self.geta();
        let mut v = self.getb();
        u.div_ip2();
        v.dbl();
        v.norm();
        self.a = v.clone();
        self.b = u.clone();
    }

    /* sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2)) */
    /* returns true if this is QR */
    pub fn sqrt(&mut self) -> bool {
        if self.is_zilch() {
            return true;
        }

        let mut a = self.geta();
        let mut s = self.getb();
        let mut t = self.geta();

        if s.is_zilch() {
            if t.sqrt() {
                self.a = t.clone();
                self.b.zero();
            } else {
                t.div_ip();
                t.sqrt();
                self.b = t.clone();
                self.a.zero();
            }
            return true;
        }
        s.sqr();
        a.sqr();
        s.mul_ip();
        s.norm();
        a.sub(&s);

        s = a.clone();
        if !s.sqrt() {
            return false;
        }

        a = t.clone();
        a.add(&s);
        a.norm();
        a.div2();

        if !a.sqrt() {
            a = t.clone();
            a.sub(&s);
            a.norm();
            a.div2();
            if !a.sqrt() {
                return false;
            }
        }
        t = self.getb();
        s = a.clone();
        s.add(&a);
        s.inverse();

        t.mul(&s);
        self.a = a;
        self.b = t;

        return true;
    }
}
