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
use super::fp2::FP2;
use super::fp4::FP4;
use super::rom;
use crate::types::{SexticTwist, SignOfX};

#[derive(Clone)]
pub struct ECP4 {
    x: FP4,
    y: FP4,
    z: FP4,
}

impl PartialEq for ECP4 {
    fn eq(&self, other: &ECP4) -> bool {
        self.equals(other)
    }
}

impl Eq for ECP4 {}

#[allow(non_snake_case)]
impl ECP4 {
    /// New
    #[inline(always)]
    pub fn new() -> ECP4 {
        ECP4 {
            x: FP4::new(),
            y: FP4::new_int(1),
            z: FP4::new(),
        }
    }

    /// New Fp4's
    ///
    /// Constructs from (x,y)
    /// Set to infinity if not on curve
    #[inline(always)]
    #[allow(non_snake_case)]
    pub fn new_fp4s(ix: &FP4, iy: &FP4) -> ECP4 {
        let mut E = ECP4::new();
        E.x = ix.clone();
        E.y = iy.clone();
        E.z.one();
        E.x.norm();

        let mut rhs = ECP4::rhs(&E.x);
        let mut y2 = E.getpy();
        y2.sqr();
        if !y2.equals(&mut rhs) {
            E.inf();
        }
        return E;
    }

    /// New Fp4
    ///
    /// Construct this from x, calulating y.
    /// Set to infinity if not on curve.
    #[inline(always)]
    pub fn new_fp4(ix: &FP4) -> ECP4 {
        let mut E = ECP4::new();
        E.x = ix.clone();
        E.y.one();
        E.z.one();
        E.x.norm();

        let mut rhs = ECP4::rhs(&E.x);
        if rhs.sqrt() {
            E.y = rhs;
        } else {
            E.inf();
        }
        return E;
    }

    /* Test this=O? */
    pub fn is_infinity(&self) -> bool {
        let xx = self.getpx();
        let zz = self.getpz();
        return xx.is_zilch() && zz.is_zilch();
    }

    /* set self=O */
    pub fn inf(&mut self) {
        self.x.zero();
        self.y.one();
        self.z.zero();
    }

    /* set self=-self */
    pub fn neg(&mut self) {
        self.y.norm();
        self.y.neg();
        self.y.norm();
    }

    /* Conditional move of Q to self dependant on d */
    pub fn cmove(&mut self, Q: &ECP4, d: isize) {
        self.x.cmove(&Q.x, d);
        self.y.cmove(&Q.y, d);
        self.z.cmove(&Q.z, d);
    }

    /* return 1 if b==c, no branching */
    fn teq(b: i32, c: i32) -> isize {
        let mut x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1) as isize;
    }

    /* Constant time select from pre-computed table */
    pub fn selector(&mut self, W: &[ECP4], b: i32) {
        let m = b >> 31;
        let mut babs = (b ^ m) - m;

        babs = (babs - 1) / 2;

        self.cmove(&W[0], ECP4::teq(babs, 0)); // conditional move
        self.cmove(&W[1], ECP4::teq(babs, 1));
        self.cmove(&W[2], ECP4::teq(babs, 2));
        self.cmove(&W[3], ECP4::teq(babs, 3));
        self.cmove(&W[4], ECP4::teq(babs, 4));
        self.cmove(&W[5], ECP4::teq(babs, 5));
        self.cmove(&W[6], ECP4::teq(babs, 6));
        self.cmove(&W[7], ECP4::teq(babs, 7));

        let mut MP = self.clone();
        MP.neg();
        self.cmove(&MP, (m & 1) as isize);
    }

    /* Test if P == Q */
    pub fn equals(&self, Q: &ECP4) -> bool {
        let mut a = self.getpx();
        let mut b = Q.getpx();

        a.mul(&Q.z);
        b.mul(&self.z);
        if !a.equals(&b) {
            return false;
        }
        a = self.getpy();
        a.mul(&Q.z);
        b = Q.getpy();
        b.mul(&self.z);
        if !a.equals(&b) {
            return false;
        }

        return true;
    }

    /* set to Affine - (x,y,z) to (x,y) */
    pub fn affine(&mut self) {
        if self.is_infinity() {
            return;
        }
        let mut one = FP4::new_int(1);
        if self.z.equals(&mut one) {
            return;
        }
        self.z.inverse();

        self.x.mul(&self.z);
        self.x.reduce();
        self.y.mul(&self.z);
        self.y.reduce();
        self.z = one.clone();
    }

    /* extract affine x as FP4 */
    pub fn getx(&self) -> FP4 {
        let mut W = self.clone();
        W.affine();
        W.getpx()
    }

    /* extract affine y as FP4 */
    pub fn gety(&self) -> FP4 {
        let mut W = self.clone();
        W.affine();
        W.getpy()
    }

    /* extract projective x */
    pub fn getpx(&self) -> FP4 {
        self.x.clone()
    }
    /* extract projective y */
    pub fn getpy(&self) -> FP4 {
        self.y.clone()
    }
    /* extract projective z */
    pub fn getpz(&self) -> FP4 {
        self.z.clone()
    }

    /* convert to byte array */
    pub fn to_bytes(&self, b: &mut [u8]) {
        let mut t: [u8; big::MODBYTES as usize] = [0; big::MODBYTES as usize];
        let mb = big::MODBYTES as usize;

        let mut W = self.clone();

        W.affine();

        W.x.geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            b[i] = t[i]
        }
        W.x.geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            b[i + mb] = t[i]
        }

        W.x.getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            b[i + 2 * mb] = t[i]
        }
        W.x.getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            b[i + 3 * mb] = t[i]
        }

        W.y.geta().geta().to_bytes(&mut t);
        for i in 0..mb {
            b[i + 4 * mb] = t[i]
        }
        W.y.geta().getb().to_bytes(&mut t);
        for i in 0..mb {
            b[i + 5 * mb] = t[i]
        }

        W.y.getb().geta().to_bytes(&mut t);
        for i in 0..mb {
            b[i + 6 * mb] = t[i]
        }
        W.y.getb().getb().to_bytes(&mut t);
        for i in 0..mb {
            b[i + 7 * mb] = t[i]
        }
    }

    /// From Bytes
    ///
    /// Convert from byte array to point
    /// Panics if insufficient bytes are given.
    #[inline(always)]
    pub fn from_bytes(b: &[u8]) -> ECP4 {
        let mut t: [u8; big::MODBYTES as usize] = [0; big::MODBYTES as usize];
        let mb = big::MODBYTES as usize;

        for i in 0..mb {
            t[i] = b[i]
        }
        let ra = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = b[i + mb]
        }
        let rb = Big::from_bytes(&t);

        let ra4 = FP2::new_bigs(ra, rb);

        for i in 0..mb {
            t[i] = b[i + 2 * mb]
        }
        let ra = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = b[i + 3 * mb]
        }
        let rb = Big::from_bytes(&t);

        let rb4 = FP2::new_bigs(ra, rb);

        let rx = FP4::new_fp2s(ra4, rb4);

        for i in 0..mb {
            t[i] = b[i + 4 * mb]
        }
        let ra = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = b[i + 5 * mb]
        }
        let rb = Big::from_bytes(&t);

        let ra4 = FP2::new_bigs(ra, rb);

        for i in 0..mb {
            t[i] = b[i + 6 * mb]
        }
        let ra = Big::from_bytes(&t);
        for i in 0..mb {
            t[i] = b[i + 7 * mb]
        }
        let rb = Big::from_bytes(&t);

        let rb4 = FP2::new_bigs(ra, rb);

        let ry = FP4::new_fp2s(ra4, rb4);

        ECP4::new_fp4s(&rx, &ry)
    }

    /// To String
    ///
    /// Converts `ECP4` to a hex string.
    pub fn to_string(&self) -> String {
        let mut W = self.clone();
        W.affine();
        if W.is_infinity() {
            return String::from("infinity");
        }
        return format!("({},{})", W.x.to_string(), W.y.to_string());
    }


    /* Calculate RHS of twisted curve equation x^3+B/i */
    pub fn rhs(x: &FP4) -> FP4 {
        //x.norm();
        let mut r = x.clone();
        r.sqr();
        let mut b = FP4::new_fp2(FP2::new_big(Big::new_ints(&rom::CURVE_B)));
        if ecp::SEXTIC_TWIST == SexticTwist::DType {
            b.div_i();
        }
        if ecp::SEXTIC_TWIST == SexticTwist::MType {
            b.times_i();
        }

        r.mul(x);
        r.add(&b);

        r.reduce();
        return r;
    }

    /* self+=self */
    pub fn dbl(&mut self) -> isize {
        let mut iy = self.getpy();
        if ecp::SEXTIC_TWIST == SexticTwist::DType {
            iy.times_i(); //iy.norm();
        }

        let mut t0 = self.getpy();
        t0.sqr();
        if ecp::SEXTIC_TWIST == SexticTwist::DType {
            t0.times_i();
        }
        let mut t1 = iy.clone();
        t1.mul(&self.z);
        let mut t2 = self.getpz();
        t2.sqr();

        self.z = t0.clone();
        self.z.add(&t0);
        self.z.norm();
        self.z.dbl();
        self.z.dbl();
        self.z.norm();

        t2.imul(3 * rom::CURVE_B_I);
        if ecp::SEXTIC_TWIST == SexticTwist::MType {
            t2.times_i();
        }
        let mut x3 = t2.clone();
        x3.mul(&self.z);

        let mut y3 = t0.clone();

        y3.add(&t2);
        y3.norm();
        self.z.mul(&t1);
        t1 = t2.clone();
        t1.add(&t2);
        t2.add(&t1);
        t2.norm();
        t0.sub(&t2);
        t0.norm(); //y^2-9bz^2
        y3.mul(&t0);
        y3.add(&x3); //(y^2+3z*2)(y^2-9z^2)+3b.z^2.8y^2
        t1 = self.getpx();
        t1.mul(&iy); //
        self.x = t0.clone();
        self.x.norm();
        self.x.mul(&t1);
        self.x.dbl(); //(y^2-9bz^2)xy2

        self.x.norm();
        self.y = y3.clone();
        self.y.norm();

        return 1;
    }

    /* self+=Q - return 0 for add, 1 for double, -1 for O */
    pub fn add(&mut self, Q: &ECP4) -> isize {
        let b = 3 * rom::CURVE_B_I;
        let mut t0 = self.getpx();
        t0.mul(&Q.x); // x.Q.x
        let mut t1 = self.getpy();
        t1.mul(&Q.y); // y.Q.y

        let mut t2 = self.getpz();
        t2.mul(&Q.z);
        let mut t3 = self.getpx();
        t3.add(&self.y);
        t3.norm(); //t3=X1+Y1
        let mut t4 = Q.getpx();
        t4.add(&Q.y);
        t4.norm(); //t4=X2+Y2
        t3.mul(&t4); //t3=(X1+Y1)(X2+Y2)
        t4 = t0.clone();
        t4.add(&t1); //t4=X1.X2+Y1.Y2

        t3.sub(&t4);
        t3.norm();
        if ecp::SEXTIC_TWIST == SexticTwist::DType {
            t3.times_i(); //t3=(X1+Y1)(X2+Y2)-(X1.X2+Y1.Y2) = X1.Y2+X2.Y1
        }
        t4 = self.getpy();
        t4.add(&self.z);
        t4.norm(); //t4=Y1+Z1
        let mut x3 = Q.getpy();
        x3.add(&Q.z);
        x3.norm(); //x3=Y2+Z2

        t4.mul(&x3); //t4=(Y1+Z1)(Y2+Z2)
        x3 = t1.clone(); //
        x3.add(&t2); //X3=Y1.Y2+Z1.Z2

        t4.sub(&x3);
        t4.norm();
        if ecp::SEXTIC_TWIST == SexticTwist::DType {
            t4.times_i(); //t4=(Y1+Z1)(Y2+Z2) - (Y1.Y2+Z1.Z2) = Y1.Z2+Y2.Z1
        }
        x3 = self.getpx();
        x3.add(&self.z);
        x3.norm(); // x3=X1+Z1
        let mut y3 = Q.getpx();
        y3.add(&Q.z);
        y3.norm(); // y3=X2+Z2
        x3.mul(&y3); // x3=(X1+Z1)(X2+Z2)
        y3 = t0.clone();
        y3.add(&t2); // y3=X1.X2+Z1+Z2
        y3.rsub(&x3);
        y3.norm(); // y3=(X1+Z1)(X2+Z2) - (X1.X2+Z1.Z2) = X1.Z2+X2.Z1

        if ecp::SEXTIC_TWIST == SexticTwist::DType {
            t0.times_i(); // x.Q.x
            t1.times_i(); // y.Q.y
        }
        x3 = t0.clone();
        x3.add(&t0);
        t0.add(&x3);
        t0.norm();
        t2.imul(b);
        if ecp::SEXTIC_TWIST == SexticTwist::MType {
            t2.times_i();
        }
        let mut z3 = t1.clone();
        z3.add(&t2);
        z3.norm();
        t1.sub(&t2);
        t1.norm();
        y3.imul(b);
        if ecp::SEXTIC_TWIST == SexticTwist::MType {
            y3.times_i();
        }
        x3 = y3.clone();
        x3.mul(&t4);
        t2 = t3.clone();
        t2.mul(&t1);
        x3.rsub(&t2);
        y3.mul(&t0);
        t1.mul(&z3);
        y3.add(&t1);
        t0.mul(&t3);
        z3.mul(&t4);
        z3.add(&t0);

        self.x = x3.clone();
        self.x.norm();
        self.y = y3.clone();
        self.y.norm();
        self.z = z3.clone();
        self.z.norm();

        return 0;
    }

    /* set this-=Q */
    pub fn sub(&mut self, Q: &ECP4) -> isize {
        let mut NQ = Q.clone();
        NQ.neg();
        self.add(&NQ)
    }

    pub fn frob_constants() -> [FP2; 3] {
        let f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));

        let mut f0 = f.clone();
        f0.sqr();
        let mut f2 = f0.clone();
        f2.mul_ip();
        f2.norm();
        let mut f1 = f2.clone();
        f1.sqr();
        f2.mul(&f1);
        f1 = f.clone();
        if ecp::SEXTIC_TWIST == SexticTwist::MType {
            f1.mul_ip();
            f1.inverse();
            f0 = f1.clone();
            f0.sqr();
        }
        f0.mul_ip();
        f0.norm();
        f1.mul(&f0);

        let F: [FP2; 3] = [f0, f1, f2];
        return F;
    }

    /* set this*=q, where q is Modulus, using Frobenius */
    pub fn frob(&mut self, f: &[FP2; 3], n: isize) {
        for _i in 0..n {
            self.x.frob(&f[2]);
            self.x.pmul(&f[0]);

            self.y.frob(&f[2]);
            self.y.pmul(&f[1]);
            self.y.times_i();

            self.z.frob(&f[2]);
        }
    }

    /// Multiplication
    ///
    /// Return self * e
    #[inline(always)]
    pub fn mul(&self, e: &Big) -> ECP4 {
        /* fixed size windows */
        if self.is_infinity() {
            return ECP4::new();
        }

        let mut W: [ECP4; 8] = [
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
        ];

        const CT: usize = 1 + (big::NLEN * (big::BASEBITS as usize) + 3) / 4;
        let mut w: [i8; CT] = [0; CT];

        /* precompute table */
        let mut Q = self.clone();
        Q.dbl();

        W[0] = self.clone();

        for i in 1..8 {
            W[i] = W[i - 1].clone();
            W[i].add(&mut Q);
        }

        /* make exponent odd - add 2P if even, P if odd */
        let mut t = e.clone();
        let s = t.parity();
        t.inc(1);
        t.norm();
        let ns = t.parity();
        let mut mt = t.clone();
        mt.inc(1);
        mt.norm();
        t.cmove(&mt, s);
        Q.cmove(&self, ns);
        let mut C = Q.clone();

        let nb = 1 + (t.nbits() + 3) / 4;

        /* convert exponent to signed 4-bit window */
        for i in 0..nb {
            w[i] = (t.lastbits(5) - 16) as i8;
            t.dec(w[i] as isize);
            t.norm();
            t.fshr(4);
        }
        w[nb] = (t.lastbits(5)) as i8;

        let mut P = W[((w[nb] as usize) - 1) / 2].clone();
        for i in (0..nb).rev() {
            Q.selector(&W, w[i] as i32);
            P.dbl();
            P.dbl();
            P.dbl();
            P.dbl();
            P.add(&mut Q);
        }
        P.sub(&mut C);
        P.affine();
        P
    }

    /// Multiplication 8
    ///
    /// P = u0 * Q0 + u1 * Q1 + u2 * Q2 + u3 * Q3 ..
    /// Bos & Costello https://eprint.iacr.org/2013/458.pdf
    /// Faz-Hernandez & Longa & Sanchez  https://eprint.iacr.org/2013/158.pdf
    /// Side channel attack secure
    /// Panics if 8 points and 8 scalars are not given.
    #[inline(always)]
    pub fn mul8(Q: &mut [ECP4], u: &[Big]) -> ECP4 {
        let mut P = ECP4::new();

        let mut T1: [ECP4; 8] = [
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
        ];
        let mut T2: [ECP4; 8] = [
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
            ECP4::new(),
        ];

        let mut mt = Big::new();

        let mut t: [Big; 8] = [
            u[0].clone(),
            u[1].clone(),
            u[2].clone(),
            u[3].clone(),
            u[4].clone(),
            u[5].clone(),
            u[6].clone(),
            u[7].clone(),
        ];

        const CT: usize = 1 + big::NLEN * (big::BASEBITS as usize);
        let mut w1: [i8; CT] = [0; CT];
        let mut s1: [i8; CT] = [0; CT];
        let mut w2: [i8; CT] = [0; CT];
        let mut s2: [i8; CT] = [0; CT];

        for i in 0..8 {
            //Q[i].affine();
            t[i].norm();
        }

        T1[0] = Q[0].clone();
        let mut W = T1[0].clone();
        T1[1] = W.clone();
        T1[1].add(&mut Q[1]); // Q[0]+Q[1]
        T1[2] = W.clone();
        T1[2].add(&mut Q[2]);
        W = T1[1].clone(); // Q[0]+Q[2]
        T1[3] = W.clone();
        T1[3].add(&mut Q[2]);
        W = T1[0].clone(); // Q[0]+Q[1]+Q[2]
        T1[4] = W.clone();
        T1[4].add(&mut Q[3]);
        W = T1[1].clone(); // Q[0]+Q[3]
        T1[5] = W.clone();
        T1[5].add(&mut Q[3]);
        W = T1[2].clone(); // Q[0]+Q[1]+Q[3]
        T1[6] = W.clone();
        T1[6].add(&mut Q[3]);
        W = T1[3].clone(); // Q[0]+Q[2]+Q[3]
        T1[7] = W.clone();
        T1[7].add(&mut Q[3]); // Q[0]+Q[1]+Q[2]+Q[3]

        // Use frobenius
        let f = ECP4::frob_constants();
        for i in 0..8 {
            T2[i] = T1[i].clone();
            T2[i].frob(&f, 4);
        }

        // Make it odd
        let pb1 = 1 - t[0].parity();
        t[0].inc(pb1);
        t[0].norm();

        let pb2 = 1 - t[4].parity();
        t[4].inc(pb2);
        t[4].norm();

        // Number of bits
        mt.zero();
        for i in 0..8 {
            mt.or(&t[i]);
        }

        let nb = 1 + mt.nbits();

        // Sign pivot

        s1[nb - 1] = 1;
        s2[nb - 1] = 1;
        for i in 0..nb - 1 {
            t[0].fshr(1);
            s1[i] = (2 * t[0].parity() - 1) as i8;
            t[4].fshr(1);
            s2[i] = (2 * t[4].parity() - 1) as i8;
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
        }

        // Main loop
        P.selector(&T1, (2 * w1[nb - 1] + 1) as i32);
        W.selector(&T2, (2 * w2[nb - 1] + 1) as i32);
        P.add(&mut W);
        for i in (0..nb - 1).rev() {
            P.dbl();
            W.selector(&T1, (2 * w1[i] + s1[i]) as i32);
            P.add(&mut W);
            W.selector(&T2, (2 * w2[i] + s2[i]) as i32);
            P.add(&mut W);
        }

        // apply correction
        W = P.clone();
        W.sub(&mut Q[0]);
        P.cmove(&W, pb1);

        W = P.clone();
        W.sub(&mut Q[4]);
        P.cmove(&W, pb2);

        P.affine();

        return P;
    }

    /// Generator
    ///
    /// Returns the generator of the group.
    #[inline(always)]
    pub fn generator() -> ECP4 {
        return ECP4::new_fp4s(
            &FP4::new_fp2s(
                FP2::new_bigs(
                    Big::new_ints(&rom::CURVE_PXAA),
                    Big::new_ints(&rom::CURVE_PXAB),
                ),
                FP2::new_bigs(
                    Big::new_ints(&rom::CURVE_PXBA),
                    Big::new_ints(&rom::CURVE_PXBB),
                ),
            ),
            &FP4::new_fp2s(
                FP2::new_bigs(
                    Big::new_ints(&rom::CURVE_PYAA),
                    Big::new_ints(&rom::CURVE_PYAB),
                ),
                FP2::new_bigs(
                    Big::new_ints(&rom::CURVE_PYBA),
                    Big::new_ints(&rom::CURVE_PYBB),
                ),
            ),
        );
    }

    /// Map It
    ///
    /// Maps bytes to a curve point using hash and test.
    /// Not conformant to hash-to-curve standards.
    #[allow(non_snake_case)]
    #[inline(always)]
    pub fn mapit(h: &[u8]) -> ECP4 {
        let mut q = Big::new_ints(&rom::MODULUS);
        let mut x = Big::from_bytes(h);
        x.rmod(&mut q);
        let mut Q: ECP4;
        let one = Big::new_int(1);

        loop {
            let X = FP4::new_fp2(FP2::new_bigs(one.clone(), x.clone()));
            Q = ECP4::new_fp4(&X);
            if !Q.is_infinity() {
                break;
            }
            x.inc(1);
            x.norm();
        }

        let f = ECP4::frob_constants();
        x = Big::new_ints(&rom::CURVE_BNX);

        let mut xQ = Q.mul(&mut x);
        let mut x2Q = xQ.mul(&mut x);
        let mut x3Q = x2Q.mul(&mut x);
        let mut x4Q = x3Q.mul(&mut x);

        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            xQ.neg();
            x3Q.neg();
        }

        x4Q.sub(&x3Q);
        x4Q.sub(&Q);

        x3Q.sub(&x2Q);
        x3Q.frob(&f, 1);

        x2Q.sub(&xQ);
        x2Q.frob(&f, 2);

        xQ.sub(&Q);
        xQ.frob(&f, 3);

        Q.dbl();
        Q.frob(&f, 4);

        Q.add(&x4Q);
        Q.add(&x3Q);
        Q.add(&x2Q);
        Q.add(&xQ);

        Q.affine();
        return Q;
    }
}
