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

use super::big;
use super::big::Big;
use super::ecp;
use super::fp16::FP16;
use super::fp2::FP2;
use super::fp4::FP4;
use super::fp8::FP8;
use super::rom;
use crate::types::SexticTwist;

pub const ZERO: usize = 0;
pub const ONE: usize = 1;
pub const SPARSER: usize = 2;
pub const SPARSE: usize = 3;
pub const DENSE: usize = 4;

#[derive(Clone)]
pub struct FP48 {
    a: FP16,
    b: FP16,
    c: FP16,
    stype: usize,
}

impl PartialEq for FP48 {
    fn eq(&self, other: &FP48) -> bool {
        self.equals(other)
    }
}

impl Eq for FP48 {}

impl FP48 {
    #[inline(always)]
    pub fn new() -> FP48 {
        FP48 {
            a: FP16::new(),
            b: FP16::new(),
            c: FP16::new(),
            stype: ZERO,
        }
    }

    pub fn settype(&mut self, t: usize) {
        self.stype = t;
    }

    pub fn gettype(&self) -> usize {
        return self.stype;
    }

    #[inline(always)]
    pub fn new_int(a: isize) -> FP48 {
        let mut f = FP48::new();
        f.a = FP16::new_int(a);
        f.b.zero();
        f.c.zero();
        if a == 1 {
            f.stype = ONE;
        } else {
            f.stype = SPARSER;
        }
        return f;
    }

    #[inline(always)]
    pub fn new_fp16s(a: FP16, b: FP16, c: FP16) -> FP48 {
        FP48 {
            a,
            b,
            c,
            stype: DENSE,
        }
    }

    #[inline(always)]
    pub fn new_fp16(a: FP16) -> FP48 {
        FP48 {
            a,
            b: FP16::new(),
            c: FP16::new(),
            stype: SPARSER,
        }
    }

    /* reduce components mod Modulus */
    pub fn reduce(&mut self) {
        self.a.reduce();
        self.b.reduce();
        self.c.reduce();
    }

    /* normalise components of w */
    pub fn norm(&mut self) {
        self.a.norm();
        self.b.norm();
        self.c.norm();
    }

    /* test self=0 ? */
    pub fn is_zilch(&self) -> bool {
        return self.a.is_zilch() && self.b.is_zilch() && self.c.is_zilch();
    }

    /* Conditional move of g to self dependant on d */
    pub fn cmove(&mut self, g: &FP48, d: isize) {
        self.a.cmove(&g.a, d);
        self.b.cmove(&g.b, d);
        self.c.cmove(&g.c, d);
        let mut u = d as usize;
        u = !(u - 1);
        self.stype ^= (self.stype ^ g.stype) & u;
    }

    /* return 1 if b==c, no branching */
    fn teq(b: i32, c: i32) -> isize {
        let mut x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1) as isize;
    }

    /* Constant time select from pre-computed table */
    pub fn selector(&mut self, g: &[FP48], b: i32) {
        let m = b >> 31;
        let mut babs = (b ^ m) - m;

        babs = (babs - 1) / 2;

        self.cmove(&g[0], FP48::teq(babs, 0)); // conditional move
        self.cmove(&g[1], FP48::teq(babs, 1));
        self.cmove(&g[2], FP48::teq(babs, 2));
        self.cmove(&g[3], FP48::teq(babs, 3));
        self.cmove(&g[4], FP48::teq(babs, 4));
        self.cmove(&g[5], FP48::teq(babs, 5));
        self.cmove(&g[6], FP48::teq(babs, 6));
        self.cmove(&g[7], FP48::teq(babs, 7));

        let mut invf = self.clone();
        invf.conj();
        self.cmove(&invf, (m & 1) as isize);
    }

    /* test self=1 ? */
    pub fn is_unity(&self) -> bool {
        let one = FP16::new_int(1);
        return self.a.equals(&one) && self.b.is_zilch() && self.c.is_zilch();
    }

    /* test self=x */
    pub fn equals(&self, x: &FP48) -> bool {
        return self.a.equals(&x.a) && self.b.equals(&x.b) && self.c.equals(&x.c);
    }

    #[inline(always)]
    pub fn geta(&self) -> FP16 {
        self.a.clone()
    }

    #[inline(always)]
    pub fn getb(&self) -> FP16 {
        self.b.clone()
    }

    #[inline(always)]
    pub fn getc(&self) -> FP16 {
        self.c.clone()
    }

    /* set self=1 */
    pub fn one(&mut self) {
        self.a.one();
        self.b.zero();
        self.c.zero();
        self.stype = ONE;
    }

    /* set self=0 */
    pub fn zero(&mut self) {
        self.a.zero();
        self.b.zero();
        self.c.zero();
        self.stype = ZERO;
    }

    /* this=conj(this) */
    pub fn conj(&mut self) {
        self.a.conj();
        self.b.nconj();
        self.c.conj();
    }

    /* Granger-Scott Unitary Squaring */
    pub fn usqr(&mut self) {
        let mut a = self.geta();
        let mut b = self.getc();
        let mut c = self.getb();

        self.a.sqr();
        let mut d = self.geta();
        d.add(&self.a);
        self.a.add(&d);

        self.a.norm();
        a.nconj();

        a.dbl();
        self.a.add(&a);
        b.sqr();
        b.times_i();

        d = b.clone();
        d.add(&b);
        b.add(&d);
        b.norm();

        c.sqr();
        d = c.clone();
        d.add(&c);
        c.add(&d);
        c.norm();

        self.b.conj();
        self.b.dbl();
        self.c.nconj();

        self.c.dbl();
        self.b.add(&b);
        self.c.add(&c);
        self.stype = DENSE;
        self.reduce();
    }

    /* Chung-Hasan SQR2 method from http://cacr.uwaterloo.ca/techreports/2006/cacr2006-24.pdf */
    pub fn sqr(&mut self) {
        if self.stype == ONE {
            return;
        }
        let mut a = self.geta();
        let mut b = self.getb();
        let mut c = self.getc();
        let mut d = self.geta();

        a.sqr();
        b.mul(&self.c);
        b.dbl();
        b.norm();
        c.sqr();
        d.mul(&self.b);
        d.dbl();

        self.c.add(&self.a);
        self.c.add(&self.b);
        self.c.norm();
        self.c.sqr();

        self.a = a.clone();
        a.add(&b);
        a.norm();
        a.add(&c);
        a.add(&d);
        a.norm();

        a.neg();
        b.times_i();
        c.times_i();

        self.a.add(&b);

        self.b = c;
        self.b.add(&d);
        self.c.add(&a);
        if self.stype == SPARSER {
            self.stype = SPARSE;
        } else {
            self.stype = DENSE;
        }
        self.norm();
    }

    /* FP48 full multiplication self=self*y */
    pub fn mul(&mut self, y: &FP48) {
        let mut z0 = self.geta();
        let mut z2 = self.getb();
        let mut t0 = self.geta();
        let mut t1 = y.geta();

        z0.mul(&y.a);
        z2.mul(&y.b);

        t0.add(&self.b);
        t1.add(&y.b);

        t0.norm();
        t1.norm();

        let mut z1 = t0.clone();
        z1.mul(&t1);
        t0 = self.getb();
        t0.add(&self.c);
        t1 = y.getb();
        t1.add(&y.c);

        t0.norm();
        t1.norm();

        let mut z3 = t0.clone();
        z3.mul(&t1);

        t0 = z0.clone();
        t0.neg();
        t1 = z2.clone();
        t1.neg();

        z1.add(&t0);
        self.b = z1.clone();
        self.b.add(&t1);

        z3.add(&t1);
        z2.add(&t0);

        t0 = self.geta();
        t0.add(&self.c);
        t0.norm();
        t1 = y.geta();
        t1.add(&y.c);
        t1.norm();
        t0.mul(&t1);
        z2.add(&t0);

        t0 = self.getc();
        t0.mul(&y.c);
        t1 = t0.clone();
        t1.neg();

        self.c = z2;
        self.c.add(&t1);
        z3.add(&t1);
        t0.times_i();
        self.b.add(&t0);
        z3.norm();

        z3.times_i();
        self.a = z0;
        self.a.add(&z3);
        self.stype = DENSE;
        self.norm();
    }

    /// FP48 full multiplication w=w*y
    /// Supports sparse multiplicands
    /// Usually w is denser than y
    pub fn ssmul(&mut self, y: &FP48) {
        if self.stype == ONE {
            *self = y.clone();
            return;
        }
        if y.stype == ONE {
            return;
        }
        if y.stype >= SPARSE {
            let mut z0 = self.geta();
            let mut z2 = FP16::new_int(0);
            z0.mul(&y.a);

            if ecp::SEXTIC_TWIST == SexticTwist::MType {
                if y.stype == SPARSE || self.stype == SPARSE {
                    let mut gb = self.b.getb();
                    gb.mul(&y.b.getb());
                    let mut ga = FP8::new_int(0);
                    if y.stype != SPARSE {
                        ga = self.b.getb();
                        ga.mul(&y.b.geta());
                    }
                    if self.stype != SPARSE {
                        ga = self.b.geta();
                        ga.mul(&y.b.getb());
                    }
                    z2.set_fp8s(&ga, &gb);
                    z2.times_i();
                } else {
                    z2 = self.getb();
                    z2.mul(&y.b);
                }
            } else {
                z2 = self.getb();
                z2.mul(&y.b);
            }
            let mut t0 = self.geta();
            let mut t1 = y.geta();
            t0.add(&self.b);
            t0.norm();
            t1.add(&y.b);
            t1.norm();

            let mut z1 = t0.clone();
            z1.mul(&t1);
            t0 = self.getb();
            t0.add(&self.c);
            t0.norm();
            t1 = y.getb();
            t1.add(&y.c);
            t1.norm();

            let mut z3 = t0.clone();
            z3.mul(&t1);

            t0 = z0.clone();
            t0.neg();
            t1 = z2.clone();
            t1.neg();

            z1.add(&t0);
            self.b = z1.clone();
            self.b.add(&t1);

            z3.add(&t1);
            z2.add(&t0);

            t0 = self.geta();
            t0.add(&self.c);
            t0.norm();
            t1 = y.geta();
            t1.add(&y.c);
            t1.norm();

            t0.mul(&t1);
            z2.add(&t0);

            if ecp::SEXTIC_TWIST == SexticTwist::DType {
                if y.stype == SPARSE || self.stype == SPARSE {
                    let mut ga = self.c.geta();
                    ga.mul(&y.c.geta());
                    let mut gb = FP8::new_int(0);
                    if y.stype != SPARSE {
                        gb = self.c.geta();
                        gb.mul(&y.c.getb());
                    }
                    if self.stype != SPARSE {
                        gb = self.c.getb();
                        gb.mul(&y.c.geta());
                    }
                    t0.set_fp8s(&ga, &gb);
                } else {
                    t0 = self.getc();
                    t0.mul(&y.c);
                }
            } else {
                t0 = self.getc();
                t0.mul(&y.c);
            }
            t1 = t0.clone();
            t1.neg();

            self.c = z2.clone();
            self.c.add(&t1);
            z3.add(&t1);
            t0.times_i();
            self.b.add(&t0);
            z3.norm();
            z3.times_i();
            self.a = z0.clone();
            self.a.add(&z3);
        } else {
            if self.stype == SPARSER {
                self.smul(&y);
                return;
            }
            if ecp::SEXTIC_TWIST == SexticTwist::DType {
                // dense by sparser - 13m
                let mut z0 = self.geta();
                let mut z2 = self.getb();
                let mut z3 = self.getb();
                let mut t1 = y.geta();

                z0.mul(&y.a);
                z2.pmul(&y.b.geta());
                self.b.add(&self.a);
                t1.padd(&y.b.geta());

                t1.norm();
                self.b.norm();
                self.b.mul(&t1);
                z3.add(&self.c);
                z3.norm();
                z3.pmul(&y.b.geta());

                let mut t0 = z0.clone();
                t0.neg();
                t1 = z2.clone();
                t1.neg();

                self.b.add(&t0);

                self.b.add(&t1);
                z3.add(&t1);
                z2.add(&t0);

                t0 = self.geta();
                t0.add(&self.c);
                t0.norm();
                z3.norm();
                t0.mul(&y.a);
                self.c = z2.clone();
                self.c.add(&t0);

                z3.times_i();
                self.a = z0.clone();
                self.a.add(&z3);
            }
            if ecp::SEXTIC_TWIST == SexticTwist::MType {
                let mut t0 = self.geta();
                let mut z0 = self.geta();
                z0.mul(&y.a);
                t0.add(&self.b);
                t0.norm();

                let mut z1 = t0.clone();
                z1.mul(&y.a);
                t0 = self.getb();
                t0.add(&self.c);
                t0.norm();

                let mut z3 = t0.clone();
                z3.pmul(&y.c.getb());
                z3.times_i();

                t0 = z0.clone();
                t0.neg();
                z1.add(&t0);
                self.b = z1.clone();
                let mut z2 = t0.clone();

                t0 = self.geta();
                t0.add(&self.c);
                t0.norm();
                let mut t1 = y.geta();
                t1.add(&y.c);
                t1.norm();

                t0.mul(&t1);
                z2.add(&t0);
                t0 = self.getc();

                t0.pmul(&y.c.getb());
                t0.times_i();
                t1 = t0.clone();
                t1.neg();

                self.c = z2;
                self.c.add(&t1);
                z3.add(&t1);
                t0.times_i();
                self.b.add(&t0);
                z3.norm();
                z3.times_i();
                self.a = z0;
                self.a.add(&z3);
            }
        }
        self.stype = DENSE;
        self.norm();
    }

    /* Special case of multiplication arises from special form of ATE pairing line function */
    pub fn smul(&mut self, y: &FP48) {
        if ecp::SEXTIC_TWIST == SexticTwist::DType {
            let mut w1 = self.a.geta();
            let mut w2 = self.a.getb();
            let mut w3 = self.b.geta();

            w1.mul(&y.a.geta());
            w2.mul(&y.a.getb());
            w3.mul(&y.b.geta());

            let mut ta = self.a.geta();
            let mut tb = y.a.geta();
            ta.add(&self.a.getb());
            ta.norm();
            tb.add(&y.a.getb());
            tb.norm();
            let mut tc = ta.clone();
            tc.mul(&tb);
            let mut t = w1.clone();
            t.add(&w2);
            t.neg();
            tc.add(&t);

            ta = self.a.geta();
            ta.add(&self.b.geta());
            ta.norm();
            tb = y.a.geta();
            tb.add(&y.b.geta());
            tb.norm();
            let mut td = ta.clone();
            td.mul(&tb);
            t = w1.clone();
            t.add(&w3);
            t.neg();
            td.add(&t);

            ta = self.a.getb();
            ta.add(&self.b.geta());
            ta.norm();
            tb = y.a.getb();
            tb.add(&y.b.geta());
            tb.norm();
            let mut te = ta.clone();
            te.mul(&tb);
            t = w2.clone();
            t.add(&w3);
            t.neg();
            te.add(&t);

            w2.times_i();
            w1.add(&w2);

            self.a.set_fp8s(&w1, &tc);
            self.b.set_fp8s(&td, &te);
            self.c.set_fp8(&w3);

            self.a.norm();
            self.b.norm();
        } else {
            let mut w1 = self.a.geta();
            let mut w2 = self.a.getb();
            let mut w3 = self.c.getb();

            w1.mul(&y.a.geta());
            w2.mul(&y.a.getb());
            w3.mul(&y.c.getb());

            let mut ta = self.a.geta();
            let mut tb = y.a.geta();
            ta.add(&self.a.getb());
            ta.norm();
            tb.add(&y.a.getb());
            tb.norm();
            let mut tc = ta.clone();
            tc.mul(&tb);
            let mut t = w1.clone();
            t.add(&w2);
            t.neg();
            tc.add(&t);

            ta = self.a.geta();
            ta.add(&self.c.getb());
            ta.norm();
            tb = y.a.geta();
            tb.add(&y.c.getb());
            tb.norm();
            let mut td = ta.clone();
            td.mul(&tb);
            t = w1.clone();
            t.add(&w3);
            t.neg();
            td.add(&t);

            ta = self.a.getb();
            ta.add(&self.c.getb());
            ta.norm();
            tb = y.a.getb();
            tb.add(&y.c.getb());
            tb.norm();
            let mut te = ta.clone();
            te.mul(&tb);
            t = w2.clone();
            t.add(&w3);
            t.neg();
            te.add(&t);

            w2.times_i();
            w1.add(&w2);
            self.a.set_fp8s(&w1, &tc);

            w3.times_i();
            w3.norm();
            self.b.set_fp8h(&w3);

            te.norm();
            te.times_i();
            self.c.set_fp8s(&te, &td);

            self.a.norm();
            self.c.norm();
        }
        self.stype = SPARSE;
    }

    /* self=1/self */
    pub fn inverse(&mut self) {
        let mut f0 = self.geta();
        let mut f1 = self.getb();
        let mut f2 = self.geta();

        //self.norm();
        f0.sqr();
        f1.mul(&self.c);
        f1.times_i();
        f0.sub(&f1);
        f0.norm();

        f1 = self.getc();
        f1.sqr();
        f1.times_i();
        f2.mul(&self.b);
        f1.sub(&f2);
        f1.norm();

        f2 = self.getb();
        f2.sqr();
        let mut f3 = self.geta();
        f3.mul(&self.c);
        f2.sub(&f3);
        f2.norm();

        f3 = self.getb();
        f3.mul(&f2);
        f3.times_i();
        self.a.mul(&f0);
        f3.add(&self.a);
        self.c.mul(&f1);
        self.c.times_i();

        f3.add(&self.c);
        f3.norm();
        f3.inverse();
        self.a = f0;
        self.a.mul(&f3);
        self.b = f1;
        self.b.mul(&f3);
        self.c = f2;
        self.c.mul(&f3);
        self.stype = DENSE;
    }

    /* self=self^p using Frobenius */
    pub fn frob(&mut self, f: &FP2, n: isize) {
        let mut f2 = f.clone();
        let mut f3 = f.clone();

        f2.sqr();
        f3.mul(&f2);

        f3.mul_ip();
        f3.norm();
        f3.mul_ip();
        f3.norm();

        for _i in 0..n {
            self.a.frob(&f3);
            self.b.frob(&f3);
            self.c.frob(&f3);

            self.b.qmul(f);
            self.b.times_i4();
            self.b.times_i2();
            self.c.qmul(&f2);
            self.c.times_i4();
            self.c.times_i4();
            self.c.times_i4();
        }
        self.stype = DENSE;
    }

    /// Trace function
    #[inline(always)]
    pub fn trace(&mut self) -> FP16 {
        let mut t = self.geta();
        t.imul(3);
        t.reduce();
        t
    }

    /// Convert from byte array to FP48
    #[inline(always)]
    pub fn from_bytes(w: &[u8]) -> FP48 {
        let mut t: [u8; big::MODBYTES as usize] = [0; big::MODBYTES as usize];
        let mb = big::MODBYTES as usize;

        for i in 0..mb {
            t[i] = w[i]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 2 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 3 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let ea = FP4::new_fp2s(c, d);

        for i in 0..mb {
            t[i] = w[i + 4 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 5 * mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 6 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 7 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let eb = FP4::new_fp2s(c, d);

        let ea8 = FP8::new_fp4s(ea, eb);

        for i in 0..mb {
            t[i] = w[i + 8 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 9 * mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 10 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 11 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let ea = FP4::new_fp2s(c, d);

        for i in 0..mb {
            t[i] = w[i + 12 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 13 * mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 14 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 15 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let eb = FP4::new_fp2s(c, d);

        let eb8 = FP8::new_fp4s(ea, eb);

        let e = FP16::new_fp8s(ea8, eb8);

        for i in 0..mb {
            t[i] = w[i + 16 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 17 * mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 18 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 19 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let ea = FP4::new_fp2s(c, d);

        for i in 0..mb {
            t[i] = w[i + 20 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 21 * mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 22 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 23 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let eb = FP4::new_fp2s(c, d);

        let ea8 = FP8::new_fp4s(ea, eb);

        for i in 0..mb {
            t[i] = w[i + 24 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 25 * mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 26 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 27 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let ea = FP4::new_fp2s(c, d);

        for i in 0..mb {
            t[i] = w[i + 28 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 29 * mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 30 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 31 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let eb = FP4::new_fp2s(c, d);

        let eb8 = FP8::new_fp4s(ea, eb);

        let f = FP16::new_fp8s(ea8, eb8);

        for i in 0..mb {
            t[i] = w[i + 32 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 33 * mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 34 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 35 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let ea = FP4::new_fp2s(c, d);

        for i in 0..mb {
            t[i] = w[i + 36 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 37 * mb]
        }
        let b = Big::from_bytes(&t);
        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 38 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 39 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let eb = FP4::new_fp2s(c, d);

        let ea8 = FP8::new_fp4s(ea, eb);

        for i in 0..mb {
            t[i] = w[i + 40 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 41 * mb]
        }
        let b = Big::from_bytes(&t);

        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 42 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 43 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let ea = FP4::new_fp2s(c, d);

        for i in 0..mb {
            t[i] = w[i + 44 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 45 * mb]
        }
        let b = Big::from_bytes(&t);

        let c = FP2::new_bigs(a, b);

        for i in 0..mb {
            t[i] = w[i + 46 * mb]
        }
        let a = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = w[i + 47 * mb]
        }
        let b = Big::from_bytes(&t);
        let d = FP2::new_bigs(a, b);

        let eb = FP4::new_fp2s(c, d);

        let eb8 = FP8::new_fp4s(ea, eb);

        let g = FP16::new_fp8s(ea8, eb8);

        return FP48::new_fp16s(e, f, g);
    }

    /* convert this to byte array */
    pub fn to_bytes(&self, w: &mut [u8]) {
        let mut t: [u8; big::MODBYTES as usize] = [0; big::MODBYTES as usize];
        let mb = big::MODBYTES as usize;

        self.a.geta().geta().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i] = t[i]
        }
        self.a.geta().geta().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + mb] = t[i]
        }
        self.a.geta().geta().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 2 * mb] = t[i]
        }
        self.a.geta().geta().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 3 * mb] = t[i]
        }

        self.a.geta().getb().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 4 * mb] = t[i]
        }
        self.a.geta().getb().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 5 * mb] = t[i]
        }
        self.a.geta().getb().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 6 * mb] = t[i]
        }
        self.a.geta().getb().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 7 * mb] = t[i]
        }

        self.a.getb().geta().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 8 * mb] = t[i]
        }
        self.a.getb().geta().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 9 * mb] = t[i]
        }
        self.a.getb().geta().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 10 * mb] = t[i]
        }
        self.a.getb().geta().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 11 * mb] = t[i]
        }

        self.a.getb().getb().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 12 * mb] = t[i]
        }
        self.a.getb().getb().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 13 * mb] = t[i]
        }
        self.a.getb().getb().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 14 * mb] = t[i]
        }
        self.a.getb().getb().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 15 * mb] = t[i]
        }

        self.b.geta().geta().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 16 * mb] = t[i]
        }
        self.b.geta().geta().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 17 * mb] = t[i]
        }
        self.b.geta().geta().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 18 * mb] = t[i]
        }
        self.b.geta().geta().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 19 * mb] = t[i]
        }

        self.b.geta().getb().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 20 * mb] = t[i]
        }
        self.b.geta().getb().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 21 * mb] = t[i]
        }
        self.b.geta().getb().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 22 * mb] = t[i]
        }
        self.b.geta().getb().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 23 * mb] = t[i]
        }

        self.b.getb().geta().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 24 * mb] = t[i]
        }
        self.b.getb().geta().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 25 * mb] = t[i]
        }
        self.b.getb().geta().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 26 * mb] = t[i]
        }
        self.b.getb().geta().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 27 * mb] = t[i]
        }

        self.b.getb().getb().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 28 * mb] = t[i]
        }
        self.b.getb().getb().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 29 * mb] = t[i]
        }
        self.b.getb().getb().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 30 * mb] = t[i]
        }
        self.b.getb().getb().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 31 * mb] = t[i]
        }

        self.c.geta().geta().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 32 * mb] = t[i]
        }
        self.c.geta().geta().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 33 * mb] = t[i]
        }
        self.c.geta().geta().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 34 * mb] = t[i]
        }
        self.c.geta().geta().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 35 * mb] = t[i]
        }

        self.c.geta().getb().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 36 * mb] = t[i]
        }
        self.c.geta().getb().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 37 * mb] = t[i]
        }
        self.c.geta().getb().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 38 * mb] = t[i]
        }
        self.c.geta().getb().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 39 * mb] = t[i]
        }

        self.c.getb().geta().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 40 * mb] = t[i]
        }
        self.c.getb().geta().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 41 * mb] = t[i]
        }
        self.c.getb().geta().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 42 * mb] = t[i]
        }
        self.c.getb().geta().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 43 * mb] = t[i]
        }

        self.c.getb().getb().geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 44 * mb] = t[i]
        }
        self.c.getb().getb().geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 45 * mb] = t[i]
        }
        self.c.getb().getb().getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 46 * mb] = t[i]
        }
        self.c.getb().getb().getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            w[i + 47 * mb] = t[i]
        }
    }

    /// To String
    ///
    /// Converts `FP48` to a hex string.
    pub fn to_string(&self) -> String {
        return format!(
            "[{},{},{}]",
            self.a.to_string(),
            self.b.to_string(),
            self.c.to_string()
        );
    }

    /* self=self^e */
    #[inline(always)]
    pub fn pow(&self, e: &Big) -> FP48 {
        let mut r = self.clone();
        r.norm();
        let mut e1 = e.clone();
        e1.norm();
        let mut e3 = e1.clone();
        e3.pmul(3);
        e3.norm();
        let mut w = r.clone();

        let nb = e3.nbits();
        for i in (1..nb - 1).rev() {
            w.usqr();
            let bt = e3.bit(i) - e1.bit(i);
            if bt == 1 {
                w.mul(&r);
            }
            if bt == -1 {
                r.conj();
                w.mul(&r);
                r.conj();
            }
        }

        w.reduce();
        return w;
    }

    /// Constant time powering by small integer of max length bts
    pub fn pinpow(&mut self, e: i32, bts: i32) {
        let mut r: [FP48; 2] = [FP48::new_int(1), self.clone()];

        for i in (0..bts).rev() {
            let b: usize = ((e >> i) & 1) as usize;
            let t = r[b].clone();
            r[1 - b].mul(&t);
            r[b].usqr();
        }
        *self = r[0].clone();
    }

    #[inline(always)]
    pub fn compow(&mut self, e: &Big, r: &Big) -> FP16 {
        let f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
        let q = Big::new_ints(&rom::MODULUS);

        let mut g1 = self.clone();
        let mut g2 = self.clone();

        let mut m = q.clone();
        m.rmod(&r);

        let mut a = e.clone();
        a.rmod(&mut m);

        let mut b = e.clone();
        b.div(&mut m);

        let mut c = g1.trace();

        if b.is_zilch() {
            c = c.xtr_pow(&mut a);
            return c;
        }

        g2.frob(&f, 1);
        let cp = g2.trace();
        g1.conj();
        g2.mul(&g1);
        let cpm1 = g2.trace();
        g2.mul(&g1);
        let cpm2 = g2.trace();

        c = c.xtr_pow2(&cp, &cpm1, &cpm2, &mut a, &mut b);

        return c;
    }

    /* p=q0^u0.q1^u1.q2^u2.q3^u3... */
    // Bos & Costello https://eprint.iacr.org/2013/458.pdf
    // Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
    // Side channel attack secure
    #[inline(always)]
    pub fn pow16(q: &[FP48], u: &[Big]) -> FP48 {
        let mut g1: [FP48; 8] = [
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
        ];
        let mut g2: [FP48; 8] = [
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
        ];
        let mut g3: [FP48; 8] = [
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
        ];
        let mut g4: [FP48; 8] = [
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
        ];

        let mut p = FP48::new();
        const CT: usize = 1 + big::NLEN * (big::BASEBITS as usize);
        let mut w1: [i8; CT] = [0; CT];
        let mut s1: [i8; CT] = [0; CT];
        let mut w2: [i8; CT] = [0; CT];
        let mut s2: [i8; CT] = [0; CT];
        let mut w3: [i8; CT] = [0; CT];
        let mut s3: [i8; CT] = [0; CT];
        let mut w4: [i8; CT] = [0; CT];
        let mut s4: [i8; CT] = [0; CT];

        let mut mt = Big::new();
        let mut t: [Big; 16] = [
            u[0].clone(),
            u[1].clone(),
            u[2].clone(),
            u[3].clone(),
            u[4].clone(),
            u[5].clone(),
            u[6].clone(),
            u[7].clone(),
            u[8].clone(),
            u[9].clone(),
            u[10].clone(),
            u[11].clone(),
            u[12].clone(),
            u[13].clone(),
            u[14].clone(),
            u[15].clone(),
        ];

        for i in 0..16 {
            t[i].norm();
        }

        // precomputation
        g1[0] = q[0].clone();
        let mut r = g1[0].clone();
        g1[1] = r.clone();
        g1[1].mul(&q[1]); // q[0].q[1]
        g1[2] = r.clone();
        g1[2].mul(&q[2]);
        r = g1[1].clone(); // q[0].q[2]
        g1[3] = r.clone();
        g1[3].mul(&q[2]);
        r = g1[0].clone(); // q[0].q[1].q[2]
        g1[4] = r.clone();
        g1[4].mul(&q[3]);
        r = g1[1].clone(); // q[0].q[3]
        g1[5] = r.clone();
        g1[5].mul(&q[3]);
        r = g1[2].clone(); // q[0].q[1].q[3]
        g1[6] = r.clone();
        g1[6].mul(&q[3]);
        r = g1[3].clone(); // q[0].q[2].q[3]
        g1[7] = r.clone();
        g1[7].mul(&q[3]); // q[0].q[1].q[2].q[3]

        // Use Frobenius
        let f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
        for i in 0..8 {
            g2[i] = g1[i].clone();
            g2[i].frob(&f, 4);
            g3[i] = g2[i].clone();
            g3[i].frob(&f, 4);
            g4[i] = g3[i].clone();
            g4[i].frob(&f, 4);
        }

        // Make it odd
        let pb1 = 1 - t[0].parity();
        t[0].inc(pb1);
        t[0].norm();

        let pb2 = 1 - t[4].parity();
        t[4].inc(pb2);
        t[4].norm();

        let pb3 = 1 - t[8].parity();
        t[8].inc(pb3);
        t[8].norm();

        let pb4 = 1 - t[12].parity();
        t[12].inc(pb4);
        t[12].norm();

        // Number of bits
        mt.zero();
        for i in 0..16 {
            mt.or(&t[i]);
        }

        let nb = 1 + mt.nbits();

        // Sign pivot

        s1[nb - 1] = 1;
        s2[nb - 1] = 1;
        s3[nb - 1] = 1;
        s4[nb - 1] = 1;
        for i in 0..nb - 1 {
            t[0].fshr(1);
            s1[i] = (2 * t[0].parity() - 1) as i8;
            t[4].fshr(1);
            s2[i] = (2 * t[4].parity() - 1) as i8;
            t[8].fshr(1);
            s3[i] = (2 * t[8].parity() - 1) as i8;
            t[12].fshr(1);
            s4[i] = (2 * t[12].parity() - 1) as i8;
        }

        // Recoded exponent
        for i in 0..nb {
            w1[i] = 0;
            let mut k = 1;
            for j in 1..4 {
                let bt = s1[i] * (t[j].parity() as i8);
                t[j].fshr(1);
                t[j].dec((bt >> 1) as isize);
                t[j].norm();
                w1[i] += bt * (k as i8);
                k = 2 * k;
            }

            w2[i] = 0;
            k = 1;
            for j in 5..8 {
                let bt = s2[i] * (t[j].parity() as i8);
                t[j].fshr(1);
                t[j].dec((bt >> 1) as isize);
                t[j].norm();
                w2[i] += bt * (k as i8);
                k = 2 * k;
            }

            w3[i] = 0;
            k = 1;
            for j in 9..12 {
                let bt = s3[i] * (t[j].parity() as i8);
                t[j].fshr(1);
                t[j].dec((bt >> 1) as isize);
                t[j].norm();
                w3[i] += bt * (k as i8);
                k = 2 * k;
            }

            w4[i] = 0;
            k = 1;
            for j in 13..16 {
                let bt = s4[i] * (t[j].parity() as i8);
                t[j].fshr(1);
                t[j].dec((bt >> 1) as isize);
                t[j].norm();
                w4[i] += bt * (k as i8);
                k = 2 * k;
            }
        }

        // Main loop
        p.selector(&g1, (2 * w1[nb - 1] + 1) as i32);
        r.selector(&g2, (2 * w2[nb - 1] + 1) as i32);
        p.mul(&r);
        r.selector(&g3, (2 * w3[nb - 1] + 1) as i32);
        p.mul(&r);
        r.selector(&g4, (2 * w4[nb - 1] + 1) as i32);
        p.mul(&r);
        for i in (0..nb - 1).rev() {
            p.usqr();
            r.selector(&g1, (2 * w1[i] + s1[i]) as i32);
            p.mul(&r);
            r.selector(&g2, (2 * w2[i] + s2[i]) as i32);
            p.mul(&r);
            r.selector(&g3, (2 * w3[i] + s3[i]) as i32);
            p.mul(&r);
            r.selector(&g4, (2 * w4[i] + s4[i]) as i32);
            p.mul(&r);
        }

        // apply correction
        r = q[0].clone();
        r.conj();
        r.mul(&p);
        p.cmove(&r, pb1);

        r = q[4].clone();
        r.conj();
        r.mul(&p);
        p.cmove(&r, pb2);

        r = q[8].clone();
        r.conj();
        r.mul(&p);
        p.cmove(&r, pb3);

        r = q[12].clone();
        r.conj();
        r.mul(&p);
        p.cmove(&r, pb4);

        p.reduce();
        return p;
    }
}
