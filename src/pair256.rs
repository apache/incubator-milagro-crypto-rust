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
use super::ecp;
use super::ecp::ECP;
use super::ecp8::ECP8;
use super::fp::FP;
use super::fp16::FP16;
use super::fp2::FP2;
use super::fp48;
use super::fp48::FP48;
use super::rom;
use crate::types::{SexticTwist, SignOfX};

#[allow(non_snake_case)]
#[inline(always)]
fn linedbl(A: &mut ECP8, qx: &FP, qy: &FP) -> FP48 {
    let mut xx = A.getpx(); //X
    let mut yy = A.getpy(); //Y
    let mut zz = A.getpz(); //Z
    let mut yz = yy.clone(); //Y
    yz.mul(&zz); //YZ
    xx.sqr(); //X^2
    yy.sqr(); //Y^2
    zz.sqr(); //Z^2

    yz.imul(4);
    yz.neg();
    yz.norm(); //-2YZ
    yz.tmul(qy); //-2YZ.Ys

    xx.imul(6); //3X^2
    xx.tmul(qx); //3X^2.Xs

    let sb = 3 * rom::CURVE_B_I;
    zz.imul(sb);
    if ecp::SEXTIC_TWIST == SexticTwist::DType {
        zz.div_2i();
    }
    if ecp::SEXTIC_TWIST == SexticTwist::MType {
        zz.times_i();
        zz.dbl();
        yz.times_i();
    }

    zz.norm(); // 3b.Z^2

    yy.dbl();
    zz.sub(&yy);
    zz.norm(); // 3b.Z^2-Y^2

    let a = FP16::new_fp8s(yz, zz); // -2YZ.Ys | 3b.Z^2-Y^2 | 3X^2.Xs
    let mut b = FP16::new();
    let mut c = FP16::new();
    if ecp::SEXTIC_TWIST == SexticTwist::DType {
        b = FP16::new_fp8(xx); // L(0,1) | L(0,0) | L(1,0)
    } else if ecp::SEXTIC_TWIST == SexticTwist::MType {
        c = FP16::new_fp8(xx);
        c.times_i();
    }
    A.dbl();
    let mut res = FP48::new_fp16s(a, b, c);
    res.settype(fp48::SPARSER);
    return res;
}

#[allow(non_snake_case)]
#[inline(always)]
fn lineadd(A: &mut ECP8, B: &ECP8, qx: &FP, qy: &FP) -> FP48 {
    let mut x1 = A.getpx(); // X1
    let mut y1 = A.getpy(); // Y1
    let mut t1 = A.getpz(); // Z1
    let mut t2 = A.getpz(); // Z1

    t1.mul(&B.getpy()); // T1=Z1.Y2
    t2.mul(&B.getpx()); // T2=Z1.X2

    x1.sub(&t2);
    x1.norm(); // X1=X1-Z1.X2
    y1.sub(&t1);
    y1.norm(); // Y1=Y1-Z1.Y2

    t1 = x1.clone(); // T1=X1-Z1.X2
    x1.tmul(qy); // X1=(X1-Z1.X2).Ys
    if ecp::SEXTIC_TWIST == SexticTwist::MType {
        x1.times_i();
    }

    t1.mul(&B.getpy()); // T1=(X1-Z1.X2).Y2

    t2 = y1.clone(); // T2=Y1-Z1.Y2
    t2.mul(&B.getpx()); // T2=(Y1-Z1.Y2).X2
    t2.sub(&t1);
    t2.norm(); // T2=(Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2
    y1.tmul(qx);
    y1.neg();
    y1.norm(); // Y1=-(Y1-Z1.Y2).Xs

    let a = FP16::new_fp8s(x1, t2); // (X1-Z1.X2).Ys  |  (Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2  | - (Y1-Z1.Y2).Xs
    let mut b = FP16::new();
    let mut c = FP16::new();
    if ecp::SEXTIC_TWIST == SexticTwist::DType {
        b = FP16::new_fp8(y1);
    } else if ecp::SEXTIC_TWIST == SexticTwist::MType {
        c = FP16::new_fp8(y1);
        c.times_i();
    }

    A.add(B);
    let mut res = FP48::new_fp16s(a, b, c);
    res.settype(fp48::SPARSER);
    return res;
}

/* prepare ate parameter, n=6u+2 (BN) or n=u (BLS), n3=3*n */
#[allow(non_snake_case)]
fn lbits(n3: &mut Big, n: &mut Big) -> usize {
    *n = Big::new_ints(&rom::CURVE_BNX);
    *n3 = n.clone();
    n3.pmul(3);
    n3.norm();
    n3.nbits()
}

/* prepare for multi-pairing */
#[inline(always)]
pub fn initmp() -> Vec<FP48> {
    let mut r: Vec<FP48> = Vec::with_capacity(rom::ATE_BITS);
    for _ in 0..rom::ATE_BITS {
        r.push(FP48::new_int(1));
    }
    r
}

/* basic Miller loop */
#[inline(always)]
pub fn miller(r: &[FP48]) -> FP48 {
    let mut res = FP48::new_int(1);
    for i in (1..rom::ATE_BITS).rev() {
        res.sqr();
        res.ssmul(&r[i]);
    }

    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        res.conj();
    }
    res.ssmul(&r[0]);
    return res;
}

/* Accumulate another set of line functions for n-pairing */
#[allow(non_snake_case)]
pub fn another(r: &mut [FP48], P1: &ECP8, Q1: &ECP) {
    let mut n = Big::new();
    let mut n3 = Big::new();

    // P is needed in affine form for line function, Q for (Qx,Qy) extraction
    let mut P = P1.clone();
    P.affine();
    let mut Q = Q1.clone();
    Q.affine();

    let qx = Q.getpx();
    let qy = Q.getpy();

    let mut A = P.clone();
    let mut NP = P.clone();
    NP.neg();

    let nb = lbits(&mut n3, &mut n);

    for i in (1..nb - 1).rev() {
        let mut lv = linedbl(&mut A, &qx, &qy);

        let bt = n3.bit(i) - n.bit(i);
        if bt == 1 {
            let lv2 = lineadd(&mut A, &P, &qx, &qy);
            lv.smul(&lv2);
        }
        if bt == -1 {
            let lv2 = lineadd(&mut A, &NP, &qx, &qy);
            lv.smul(&lv2);
        }
        r[i].ssmul(&lv);
    }
}

/* Optimal R-ate pairing */
#[allow(non_snake_case)]
#[inline(always)]
pub fn ate(P1: &ECP8, Q1: &ECP) -> FP48 {
    let mut n = Big::new();
    let mut n3 = Big::new();

    let mut P = P1.clone();
    P.affine();
    let mut Q = Q1.clone();
    Q.affine();

    let qx = Q.getpx();
    let qy = Q.getpy();

    let mut A = P.clone();
    let mut NP = P.clone();
    NP.neg();

    let nb = lbits(&mut n3, &mut n);

    let mut r = FP48::new_int(1);
    for i in (1..nb - 1).rev() {
        r.sqr();
        let mut lv = linedbl(&mut A, &qx, &qy);
        let bt = n3.bit(i) - n.bit(i);
        if bt == 1 {
            let lv2 = lineadd(&mut A, &P, &qx, &qy);
            lv.smul(&lv2);
        }
        if bt == -1 {
            let lv2 = lineadd(&mut A, &NP, &qx, &qy);
            lv.smul(&lv2);
        }
        r.ssmul(&lv);
    }

    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        r.conj();
    }

    return r;
}

/* Optimal R-ate double pairing e(P,Q).e(R,S) */
#[allow(non_snake_case)]
#[inline(always)]
pub fn ate2(P1: &ECP8, Q1: &ECP, R1: &ECP8, S1: &ECP) -> FP48 {
    let mut n = Big::new();
    let mut n3 = Big::new();

    let mut P = P1.clone();
    P.affine();
    let mut Q = Q1.clone();
    Q.affine();
    let mut R = R1.clone();
    R.affine();
    let mut S = S1.clone();
    S.affine();

    let qx = Q.getpx();
    let qy = Q.getpy();

    let sx = S.getpx();
    let sy = S.getpy();

    let mut A = P.clone();
    let mut B = R.clone();

    let mut NP = P.clone();
    NP.neg();
    let mut NR = R.clone();
    NR.neg();

    let nb = lbits(&mut n3, &mut n);

    let mut r = FP48::new_int(1);
    for i in (1..nb - 1).rev() {
        r.sqr();
        let mut lv = linedbl(&mut A, &qx, &qy);
        let lv2 = linedbl(&mut B, &sx, &sy);
        lv.smul(&lv2);
        r.ssmul(&lv);
        let bt = n3.bit(i) - n.bit(i);
        if bt == 1 {
            lv = lineadd(&mut A, &P, &qx, &qy);
            let lv2 = lineadd(&mut B, &R, &sx, &sy);
            lv.smul(&lv2);
            r.ssmul(&lv);
        }
        if bt == -1 {
            lv = lineadd(&mut A, &NP, &qx, &qy);
            let lv2 = lineadd(&mut B, &NR, &sx, &sy);
            lv.smul(&lv2);
            r.ssmul(&lv);
        }
    }

    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        r.conj();
    }

    return r;
}

/* final exponentiation - keep separate for multi-pairings and to avoid thrashing stack */
#[inline(always)]
pub fn fexp(m: &FP48) -> FP48 {
    let f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
    let mut x = Big::new_ints(&rom::CURVE_BNX);
    let mut r = m.clone();

    /* Easy part of final exp */
    let mut lv = r.clone();
    lv.inverse();
    r.conj();

    r.mul(&lv);
    lv = r.clone();
    r.frob(&f, 8);
    r.mul(&lv);
    //    if r.is_unity() {
    //	r.zero();
    //	return r;
    //    }
    /* Hard part of final exp */
    // Ghamman & Fouotsa Method

    let mut t7 = r.clone();
    t7.usqr();
    let mut t1 = t7.pow(&mut x);

    x.fshr(1);
    let mut t2 = t1.pow(&mut x);
    x.fshl(1);

    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    let mut t3 = t1.clone();
    t3.conj();
    t2.mul(&t3);
    t2.mul(&r);

    r.mul(&t7);

    t1 = t2.pow(&mut x);

    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }
    t3 = t1.clone();
    t3.frob(&f, 14);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 13);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 12);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 11);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 10);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 9);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 8);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t2.clone();
    t3.conj();
    t1.mul(&t3);
    t3 = t1.clone();
    t3.frob(&f, 7);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 6);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 5);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 4);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 3);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 2);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    t3 = t1.clone();
    t3.frob(&f, 1);
    r.mul(&t3);
    t1 = t1.pow(&mut x);
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        t1.conj();
    }

    r.mul(&t1);
    t2.frob(&f, 15);
    r.mul(&t2);

    r.reduce();
    return r;
}

/* GLV method */
#[allow(non_snake_case)]
#[inline(always)]
fn glv(e: &Big) -> [Big; 2] {
    let mut u: [Big; 2] = [Big::new(), Big::new()];
    let q = Big::new_ints(&rom::CURVE_ORDER);
    let mut x = Big::new_ints(&rom::CURVE_BNX);
    let mut x2 = Big::smul(&x, &x);
    x = Big::smul(&x2, &x2);
    x2 = Big::smul(&x, &x);
    u[0] = e.clone();
    u[0].rmod(&x2);
    u[1] = e.clone();
    u[1].div(&x2);
    u[1].rsub(&q);

    return u;
}

/* Galbraith & Scott Method */
#[allow(non_snake_case)]
#[inline(always)]
pub fn gs(e: &Big) -> [Big; 16] {
    let mut u: [Big; 16] = [
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
        Big::new(),
    ];
    let q = Big::new_ints(&rom::CURVE_ORDER);
    let x = Big::new_ints(&rom::CURVE_BNX);
    let mut w = e.clone();
    for i in 0..15 {
        u[i] = w.clone();
        u[i].rmod(&x);
        w.div(&x);
    }
    u[15] = w;
    if ecp::SIGN_OF_X == SignOfX::NegativeX {
        u[1] = Big::modneg(&mut u[1], &q);
        u[3] = Big::modneg(&mut u[3], &q);
        u[5] = Big::modneg(&mut u[5], &q);
        u[7] = Big::modneg(&mut u[7], &q);
        u[9] = Big::modneg(&mut u[9], &q);
        u[11] = Big::modneg(&mut u[11], &q);
        u[13] = Big::modneg(&mut u[13], &q);
        u[15] = Big::modneg(&mut u[15], &q);
    }
    u
}

/* Multiply P by e in group G1 */
#[allow(non_snake_case)]
#[inline(always)]
pub fn g1mul(P: &ECP, e: &mut Big) -> ECP {
    if rom::USE_GLV {
        let mut R = P.clone();
        let mut Q = P.clone();
        Q.affine();
        let q = Big::new_ints(&rom::CURVE_ORDER);
        let mut cru = FP::new_big(Big::new_ints(&rom::CURVE_CRU));
        let mut u = glv(e);
        Q.mulx(&mut cru);

        let mut np = u[0].nbits();
        let mut t: Big = Big::modneg(&mut u[0], &q);
        let mut nn = t.nbits();
        if nn < np {
            u[0] = t.clone();
            R.neg();
        }

        np = u[1].nbits();
        t = Big::modneg(&mut u[1], &q);
        nn = t.nbits();
        if nn < np {
            u[1] = t;
            Q.neg();
        }
        u[0].norm();
        u[1].norm();
        R.mul2(&u[0], &mut Q, &u[1])
    } else {
        P.mul(e)
    }
}

/* Multiply P by e in group G2 */
#[allow(non_snake_case)]
#[inline(always)]
pub fn g2mul(P: &ECP8, e: &Big) -> ECP8 {
    if rom::USE_GS_G2 {
        let mut Q: [ECP8; 16] = [
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
            ECP8::new(),
        ];
        let q = Big::new_ints(&rom::CURVE_ORDER);
        let mut u = gs(e);

        let f = ECP8::frob_constants();

        Q[0] = P.clone();
        for i in 1..16 {
            Q[i] = Q[i - 1].clone();
            Q[i].frob(&f, 1);
        }
        for i in 0..16 {
            let np = u[i].nbits();
            let t = Big::modneg(&mut u[i], &q);
            let nn = t.nbits();
            if nn < np {
                u[i] = t.clone();
                Q[i].neg();
            }
            u[i].norm();
        }

        ECP8::mul16(&mut Q, &u)
    } else {
        P.mul(e)
    }
}

/* f=f^e */
/* Note that this method requires a lot of RAM! Better to use compressed XTR method, see FP4.java */
#[inline(always)]
pub fn gtpow(d: &FP48, e: &Big) -> FP48 {
    if rom::USE_GS_GT {
        let mut g: [FP48; 16] = [
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
            FP48::new(),
        ];
        let f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
        let q = Big::new_ints(&rom::CURVE_ORDER);
        let mut u = gs(e);

        g[0] = d.clone();
        for i in 1..16 {
            g[i] = g[i - 1].clone();
            g[i].frob(&f, 1);
        }
        for i in 0..16 {
            let np = u[i].nbits();
            let t = Big::modneg(&mut u[i], &q);
            let nn = t.nbits();
            if nn < np {
                u[i] = t;
                g[i].conj();
            }
            u[i].norm();
        }
        FP48::pow16(&mut g, &u)
    } else {
        d.pow(e)
    }
}
