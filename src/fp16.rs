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

use super::big::Big;
use super::fp2::FP2;
use super::fp8::FP8;

#[derive(Clone)]
pub struct FP16 {
    a: FP8,
    b: FP8,
}

impl PartialEq for FP16 {
    fn eq(&self, other: &FP16) -> bool {
        self.equals(other)
    }
}

impl Eq for FP16 {}

impl FP16 {
    #[inline(always)]
    pub fn new() -> FP16 {
        FP16 {
            a: FP8::new(),
            b: FP8::new(),
        }
    }

    #[inline(always)]
    pub fn new_int(a: isize) -> FP16 {
        FP16 {
            a: FP8::new_int(a),
            b: FP8::new(),
        }
    }

    #[inline(always)]
    pub fn new_fp8s(a: FP8, b: FP8) -> FP16 {
        FP16 { a, b }
    }

    #[inline(always)]
    pub fn new_fp8(a: FP8) -> FP16 {
        FP16 { a, b: FP8::new() }
    }

    pub fn set_fp8s(&mut self, c: &FP8, d: &FP8) {
        self.a = c.clone();
        self.b = d.clone();
    }

    pub fn set_fp8(&mut self, c: &FP8) {
        self.a = c.clone();
        self.b.zero();
    }

    pub fn set_fp8h(&mut self, c: &FP8) {
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

    pub fn cmove(&mut self, g: &FP16, d: isize) {
        self.a.cmove(&g.a, d);
        self.b.cmove(&g.b, d);
    }

    /* test self=0 ? */
    pub fn is_zilch(&self) -> bool {
        return self.a.is_zilch() && self.b.is_zilch();
    }

    /* test self=1 ? */
    pub fn is_unity(&self) -> bool {
        let one = FP8::new_int(1);
        return self.a.equals(&one) && self.b.is_zilch();
    }

    /// Test is w real? That is in a+ib test b is zero */
    pub fn isreal(&self) -> bool {
        return self.b.is_zilch();
    }

    /// Extract real part a
    #[inline(always)]
    pub fn real(&self) -> FP8 {
        self.geta()
    }

    #[inline(always)]
    pub fn geta(&self) -> FP8 {
        self.a.clone()
    }

    /// Extract imaginary part b
    #[inline(always)]
    pub fn getb(&self) -> FP8 {
        self.b.clone()
    }

    /* test self=x */
    pub fn equals(&self, x: &FP16) -> bool {
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
    pub fn add(&mut self, x: &FP16) {
        self.a.add(&x.a);
        self.b.add(&x.b);
    }

    pub fn padd(&mut self, x: &FP8) {
        self.a.add(x);
    }

    pub fn dbl(&mut self) {
        self.a.dbl();
        self.b.dbl();
    }

    /* self-=a */
    pub fn sub(&mut self, x: &FP16) {
        let mut m = x.clone();
        m.neg();
        self.add(&m);
    }

    /* this-=x */
    pub fn rsub(&mut self, x: &FP16) {
        self.neg();
        self.add(x);
    }

    /* self*=s, where s is an FP8 */
    pub fn pmul(&mut self, s: &FP8) {
        self.a.mul(s);
        self.b.mul(s);
    }

    /* self*=s, where s is an FP2 */
    pub fn qmul(&mut self, s: &FP2) {
        self.a.qmul(s);
        self.b.qmul(s);
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
        t2.times_i();

        t2.add(&self.a);

        t1.norm();
        t2.norm();

        self.a = t1.clone();

        self.a.mul(&t2);

        t2 = t3.clone();
        t2.times_i();
        t2.add(&t3);
        t2.norm();
        t2.neg();
        self.a.add(&t2);

        t3.dbl();
        self.b = t3.clone();

        self.norm();
    }

    /* self*=y */
    pub fn mul(&mut self, y: &FP16) {
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

        t2.times_i();
        self.a = t2.clone();
        self.a.add(&t1);

        self.norm();
    }

    /// To String
    ///
    /// Converts a `FP16` to a hex string.
    pub fn to_string(&self) -> String {
        return format!("[{},{}]", self.a.to_string(), self.b.to_string());
    }

    /* self=1/self */
    pub fn inverse(&mut self) {
        let mut t1 = self.geta();
        let mut t2 = self.getb();

        t1.sqr();
        t2.sqr();
        t2.times_i();
        t2.norm();
        t1.sub(&t2);
        t1.norm();
        t1.inverse();
        self.a.mul(&t1);
        t1.neg();
        t1.norm();
        self.b.mul(&t1);
    }

    /* self*=i where i = sqrt(-1+sqrt(-1)) */
    pub fn times_i(&mut self) {
        let mut s = self.getb();
        let t = self.geta();
        s.times_i();
        self.a = s.clone();
        self.b = t.clone();

        self.norm();
    }

    pub fn times_i2(&mut self) {
        self.a.times_i();
        self.b.times_i();
    }

    pub fn times_i4(&mut self) {
        self.a.times_i2();
        self.b.times_i2();
    }

    /* self=self^p using Frobenius */
    pub fn frob(&mut self, f: &FP2) {
        let mut ff = f.clone();
        ff.sqr();
        ff.norm();
        self.a.frob(&ff);
        self.b.frob(&ff);
        self.b.qmul(f);
        self.b.times_i();
    }

    /* self=self^e */
    #[inline(always)]
    pub fn pow(&self, e: &Big) -> FP16 {
        let mut w = self.clone();
        w.norm();
        let mut z = e.clone();
        let mut r = FP16::new_int(1);
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
    pub fn xtr_a(&mut self, w: &FP16, y: &FP16, z: &FP16) {
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

    /* r=x^n using XTR method on traces of FP24s */
    #[inline(always)]
    pub fn xtr_pow(&self, n: &Big) -> FP16 {
        let mut sf = self.clone();
        sf.norm();
        let mut a = FP16::new_int(3);
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
        let mut r = if par == 0 { c } else { b };
        r.reduce();
        r
    }

    /* r=ck^a.cl^n using XTR double exponentiation method on traces of FP12s. See Stam thesis. */
    #[inline(always)]
    pub fn xtr_pow2(&mut self, ck: &FP16, ckml: &FP16, ckm2l: &FP16, a: &Big, b: &Big) -> FP16 {
        let mut e = a.clone();
        let mut d = b.clone();
        d.norm();
        e.norm();

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
                    cu = t;
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
                        cum2v = t;
                        cum2v.conj();
                        t = cv.clone();
                        t.xtr_d();
                        cv = cu.clone();
                        cu = t;
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
                            cv = t;
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
        let mut r = cv;
        r.xtr_a(&cu, &cumv, &cum2v);
        for _ in 0..f2 {
            r.xtr_d()
        }
        r.xtr_pow(&mut d)
    }
}
