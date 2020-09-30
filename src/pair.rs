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
use super::dbig::DBig;
use super::ecp;
use super::ecp::ECP;
use super::ecp2::ECP2;
use super::fp::FP;
use super::fp12;
use super::fp12::FP12;
use super::fp2::FP2;
use super::fp4::FP4;
use super::rom;
use crate::types::{CurvePairingType, SexticTwist, SignOfX};

#[allow(non_snake_case)]
#[inline(always)]
fn linedbl(A: &mut ECP2, qx: &FP, qy: &FP) -> FP12 {
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
    yz.pmul(qy); //-2YZ.Ys

    xx.imul(6); //3X^2
    xx.pmul(qx); //3X^2.Xs

    let sb = 3 * rom::CURVE_B_I;
    zz.imul(sb);
    if ecp::SEXTIC_TWIST == SexticTwist::DType {
        zz.div_ip2();
    }
    if ecp::SEXTIC_TWIST == SexticTwist::MType {
        zz.mul_ip();
        zz.dbl();
        yz.mul_ip();
        yz.norm();
    }

    zz.norm(); // 3b.Z^2

    yy.dbl();
    zz.sub(&yy);
    zz.norm(); // 3b.Z^2-Y^2

    let a = FP4::new_fp2s(yz, zz); // -2YZ.Ys | 3b.Z^2-Y^2 | 3X^2.Xs
    let mut b = FP4::new();
    let mut c = FP4::new();
    if ecp::SEXTIC_TWIST == SexticTwist::DType {
        b = FP4::new_fp2(xx); // L(0,1) | L(0,0) | L(1,0)
    } else if ecp::SEXTIC_TWIST == SexticTwist::MType {
        c = FP4::new_fp2(xx);
        c.times_i();
    }
    A.dbl();
    let mut res = FP12::new_fp4s(a, b, c);
    res.settype(fp12::SPARSER);
    res
}

#[allow(non_snake_case)]
#[inline(always)]
fn lineadd(A: &mut ECP2, B: &ECP2, qx: &FP, qy: &FP) -> FP12 {
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
    x1.pmul(qy); // X1=(X1-Z1.X2).Ys
    if ecp::SEXTIC_TWIST == SexticTwist::MType {
        x1.mul_ip();
        x1.norm();
    }

    t1.mul(&B.getpy()); // T1=(X1-Z1.X2).Y2

    t2 = y1.clone(); // T2=Y1-Z1.Y2
    t2.mul(&B.getpx()); // T2=(Y1-Z1.Y2).X2
    t2.sub(&t1);
    t2.norm(); // T2=(Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2
    y1.pmul(qx);
    y1.neg();
    y1.norm(); // Y1=-(Y1-Z1.Y2).Xs

    let a = FP4::new_fp2s(x1, t2); // (X1-Z1.X2).Ys  |  (Y1-Z1.Y2).X2 - (X1-Z1.X2).Y2  | - (Y1-Z1.Y2).Xs
    let mut b = FP4::new();
    let mut c = FP4::new();
    if ecp::SEXTIC_TWIST == SexticTwist::DType {
        b = FP4::new_fp2(y1);
    } else if ecp::SEXTIC_TWIST == SexticTwist::MType {
        c = FP4::new_fp2(y1);
        c.times_i();
    }

    A.add(B);
    let mut res = FP12::new_fp4s(a, b, c);
    res.settype(fp12::SPARSER);
    res
}

/* prepare ate parameter, n=6u+2 (BN) or n=u (BLS), n3=3*n */
#[allow(non_snake_case)]
fn lbits(n3: &mut Big, n: &mut Big) -> usize {
    *n = Big::new_ints(&rom::CURVE_BNX);
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        n.pmul(6);
        if ecp::SIGN_OF_X == SignOfX::PositiveX {
            n.inc(2);
        } else {
            n.dec(2);
        }
    }
    n.norm();
    *n3 = n.clone();
    n3.pmul(3);
    n3.norm();
    n3.nbits()
}

/* prepare for multi-pairing */
#[inline(always)]
pub fn initmp() -> Vec<FP12> {
    let mut r: Vec<FP12> = Vec::with_capacity(rom::ATE_BITS);
    for _ in 0..rom::ATE_BITS {
        r.push(FP12::new_int(1));
    }
    r
}

/* basic Miller loop */
#[inline(always)]
pub fn miller(r: &[FP12]) -> FP12 {
    let mut res = FP12::new_int(1);
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
pub fn another(r: &mut [FP12], P1: &ECP2, Q1: &ECP) {
    let mut f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
    let mut n = Big::new();
    let mut n3 = Big::new();

    // P is needed in affine form for line function, Q for (Qx,Qy) extraction
    let mut P = P1.clone();
    P.affine();
    let mut Q = Q1.clone();
    Q.affine();

    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        if ecp::SEXTIC_TWIST == SexticTwist::MType {
            f.inverse();
            f.norm();
        }
    }

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

    /* R-ate fixup required for BN curves */
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            A.neg();
        }
        let mut K = P.clone();
        K.frob(&f);
        let mut lv = lineadd(&mut A, &K, &qx, &qy);
        K.frob(&f);
        K.neg();
        let lv2 = lineadd(&mut A, &K, &qx, &qy);
        lv.smul(&lv2);
        r[0].ssmul(&lv);
    }
}

/* Optimal R-ate pairing */
#[allow(non_snake_case)]
#[inline(always)]
pub fn ate(P1: &ECP2, Q1: &ECP) -> FP12 {
    let mut f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
    let mut n = Big::new();
    let mut n3 = Big::new();

    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        if ecp::SEXTIC_TWIST == SexticTwist::MType {
            f.inverse();
            f.norm();
        }
    }

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

    let mut r = FP12::new_int(1);
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

    /* R-ate fixup required for BN curves */

    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            A.neg();
        }

        let mut K = P.clone();
        K.frob(&f);

        let mut lv = lineadd(&mut A, &K, &qx, &qy);
        K.frob(&f);
        K.neg();
        let lv2 = lineadd(&mut A, &K, &qx, &qy);
        lv.smul(&lv2);
        r.ssmul(&lv);
    }

    return r;
}

/* Optimal R-ate double pairing e(P,Q).e(R,S) */
#[allow(non_snake_case)]
#[inline(always)]
pub fn ate2(P1: &ECP2, Q1: &ECP, R1: &ECP2, S1: &ECP) -> FP12 {
    let mut f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
    let mut n = Big::new();
    let mut n3 = Big::new();

    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        if ecp::SEXTIC_TWIST == SexticTwist::MType {
            f.inverse();
            f.norm();
        }
    }

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

    let mut r = FP12::new_int(1);

    let mut A = P.clone();
    let mut B = R.clone();

    let mut NP = P.clone();
    NP.neg();
    let mut NR = R.clone();
    NR.neg();

    let nb = lbits(&mut n3, &mut n);

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

    // R-ate fixup
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            A.neg();
            B.neg();
        }
        let mut K = P.clone();
        K.frob(&f);

        let mut lv = lineadd(&mut A, &K, &qx, &qy);
        K.frob(&f);
        K.neg();
        let mut lv2 = lineadd(&mut A, &K, &qx, &qy);
        lv.smul(&lv2);
        r.ssmul(&lv);

        K = R.clone();
        K.frob(&f);

        lv = lineadd(&mut B, &K, &sx, &sy);
        K.frob(&f);
        K.neg();
        lv2 = lineadd(&mut B, &K, &sx, &sy);
        lv.smul(&lv2);
        r.ssmul(&lv);
    }

    return r;
}

// final exponentiation - keep separate for multi-pairings and to avoid thrashing stack
#[inline(always)]
pub fn fexp(m: &FP12) -> FP12 {
    let f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
    let mut x = Big::new_ints(&rom::CURVE_BNX);
    let mut r = m.clone();

    // Easy part of final exp
    let mut lv = r.clone();
    lv.inverse();
    r.conj();

    r.mul(&lv);
    lv = r.clone();
    r.frob(&f);
    r.frob(&f);
    r.mul(&lv);
    //    if r.is_unity() {
    //	r.zero();
    //	return r;
    //    }

    /* Hard part of final exp */
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        lv = r.clone();
        lv.frob(&f);
        let mut x0 = lv.clone();
        x0.frob(&f);
        lv.mul(&r);
        x0.mul(&lv);
        x0.frob(&f);
        let mut x1 = r.clone();
        x1.conj();
        let mut x4 = r.pow(&x);
        if ecp::SIGN_OF_X == SignOfX::PositiveX {
            x4.conj();
        }

        let mut x3 = x4.clone();
        x3.frob(&f);

        let mut x2 = x4.pow(&x);
        if ecp::SIGN_OF_X == SignOfX::PositiveX {
            x2.conj();
        }
        let mut x5 = x2.clone();
        x5.conj();
        lv = x2.pow(&x);
        if ecp::SIGN_OF_X == SignOfX::PositiveX {
            lv.conj();
        }
        x2.frob(&f);
        r = x2.clone();
        r.conj();

        x4.mul(&r);
        x2.frob(&f);

        r = lv.clone();
        r.frob(&f);
        lv.mul(&r);

        lv.usqr();
        lv.mul(&x4);
        lv.mul(&x5);
        r = x3.clone();
        r.mul(&x5);
        r.mul(&lv);
        lv.mul(&x2);
        r.usqr();
        r.mul(&lv);
        r.usqr();
        lv = r.clone();
        lv.mul(&x1);
        r.mul(&x0);
        lv.usqr();
        r.mul(&lv);
        r.reduce();
    } else {
        // Ghamman & Fouotsa Method

        let mut y0 = r.clone();
        y0.usqr();
        let mut y1 = y0.pow(&x);
        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            y1.conj();
        }
        x.fshr(1);
        let mut y2 = y1.pow(&x);
        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            y2.conj();
        }
        x.fshl(1);
        let mut y3 = r.clone();
        y3.conj();
        y1.mul(&y3);

        y1.conj();
        y1.mul(&y2);

        y2 = y1.pow(&x);
        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            y2.conj();
        }
        y3 = y2.pow(&x);
        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            y3.conj();
        }
        y1.conj();
        y3.mul(&y1);

        y1.conj();
        y1.frob(&f);
        y1.frob(&f);
        y1.frob(&f);
        y2.frob(&f);
        y2.frob(&f);
        y1.mul(&y2);

        y2 = y3.pow(&x);
        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            y2.conj();
        }
        y2.mul(&y0);
        y2.mul(&r);

        y1.mul(&y2);
        y2 = y3;
        y2.frob(&f);
        y1.mul(&y2);
        r = y1;
        r.reduce();
    }
    return r;
}

/* GLV method */
#[allow(non_snake_case)]
#[inline(always)]
fn glv(e: &Big) -> [Big; 2] {
    let mut u: [Big; 2] = [Big::new(), Big::new()];
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        let q = Big::new_ints(&rom::CURVE_ORDER);
        let mut v: [Big; 2] = [Big::new(), Big::new()];

        for i in 0..2 {
            let t = Big::new_ints(&rom::CURVE_W[i]); // why not just t=new Big(ROM.CURVE_W[i]);
            let mut d: DBig = Big::mul(&t, e);
            v[i] = d.div(&q);
        }
        u[0] = e.clone();
        for i in 0..2 {
            for j in 0..2 {
                let mut t = Big::new_ints(&rom::CURVE_SB[j][i]);
                t = Big::modmul(&v[j], &t, &q);
                u[i].add(&q);
                u[i].sub(&t);
                u[i].rmod(&q);
            }
        }
    } else {
        let q = Big::new_ints(&rom::CURVE_ORDER);
        let x = Big::new_ints(&rom::CURVE_BNX);
        let x2 = Big::smul(&x, &x);
        u[0] = e.clone();
        u[0].rmod(&x2);
        u[1] = e.clone();
        u[1].div(&x2);
        u[1].rsub(&q);
    }
    return u;
}

/* Galbraith & Scott Method */
#[allow(non_snake_case)]
#[inline(always)]
pub fn gs(e: &Big) -> [Big; 4] {
    let mut u: [Big; 4] = [Big::new(), Big::new(), Big::new(), Big::new()];
    if ecp::CURVE_PAIRING_TYPE == CurvePairingType::Bn {
        let q = Big::new_ints(&rom::CURVE_ORDER);

        let mut v: [Big; 4] = [Big::new(), Big::new(), Big::new(), Big::new()];
        for i in 0..4 {
            let t = Big::new_ints(&rom::CURVE_WB[i]);
            let mut d: DBig = Big::mul(&t, e);
            v[i] = d.div(&q);
        }
        u[0] = e.clone();
        for i in 0..4 {
            for j in 0..4 {
                let t = Big::new_ints(&rom::CURVE_BB[j][i]);
                let t = Big::modmul(&v[j], &t, &q);
                u[i].add(&q);
                u[i].sub(&t);
                u[i].rmod(&q);
            }
        }
    } else {
        let q = Big::new_ints(&rom::CURVE_ORDER);
        let x = Big::new_ints(&rom::CURVE_BNX);
        let mut w = e.clone();
        for i in 0..3 {
            u[i] = w.clone();
            u[i].rmod(&x);
            w.div(&x);
        }
        u[3] = w.clone();
        if ecp::SIGN_OF_X == SignOfX::NegativeX {
            u[1] = Big::modneg(&u[1], &q);
            u[3] = Big::modneg(&u[3], &q);
        }
    }
    return u;
}

/* Multiply P by e in group G1 */
#[allow(non_snake_case)]
#[inline(always)]
pub fn g1mul(P: &ECP, e: &Big) -> ECP {
    if rom::USE_GLV {
        let mut R = P.clone();
        let mut Q = P.clone();
        Q.affine();
        let q = Big::new_ints(&rom::CURVE_ORDER);
        let mut cru = FP::new_big(Big::new_ints(&rom::CURVE_CRU));
        let mut u = glv(e);
        Q.mulx(&mut cru);

        let mut np = u[0].nbits();
        let mut t: Big = Big::modneg(&u[0], &q);
        let mut nn = t.nbits();
        if nn < np {
            u[0] = t.clone();
            R.neg();
        }

        np = u[1].nbits();
        t = Big::modneg(&u[1], &q);
        nn = t.nbits();
        if nn < np {
            u[1] = t;
            Q.neg();
        }
        u[0].norm();
        u[1].norm();
        R.mul2(&u[0], &Q, &u[1])
    } else {
        P.mul(e)
    }
}

/* Multiply P by e in group G2 */
#[allow(non_snake_case)]
#[inline(always)]
pub fn g2mul(P: &ECP2, e: &Big) -> ECP2 {
    if rom::USE_GS_G2 {
        let mut Q: [ECP2; 4] = [ECP2::new(), ECP2::new(), ECP2::new(), ECP2::new()];
        let mut f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
        let q = Big::new_ints(&rom::CURVE_ORDER);
        let mut u = gs(e);

        if ecp::SEXTIC_TWIST == SexticTwist::MType {
            f.inverse();
            f.norm();
        }

        Q[0] = P.clone();
        for i in 1..4 {
            Q[i] = Q[i - 1].clone();
            Q[i].frob(&f);
        }
        for i in 0..4 {
            let np = u[i].nbits();
            let t = Big::modneg(&u[i], &q);
            let nn = t.nbits();
            if nn < np {
                u[i] = t;
                Q[i].neg();
            }
            u[i].norm();
        }

        ECP2::mul4(&mut Q, &u)
    } else {
        P.mul(e)
    }
}

/* f=f^e */
/* Note that this method requires a lot of RAM! Better to use compressed XTR method, see FP4.java */
#[inline(always)]
pub fn gtpow(d: &FP12, e: &Big) -> FP12 {
    if rom::USE_GS_GT {
        let mut g: [FP12; 4] = [FP12::new(), FP12::new(), FP12::new(), FP12::new()];
        let f = FP2::new_bigs(Big::new_ints(&rom::FRA), Big::new_ints(&rom::FRB));
        let q = Big::new_ints(&rom::CURVE_ORDER);
        let mut u = gs(e);

        g[0] = d.clone();
        for i in 1..4 {
            g[i] = g[i - 1].clone();
            g[i].frob(&f);
        }
        for i in 0..4 {
            let np = u[i].nbits();
            let t = Big::modneg(&mut u[i], &q);
            let nn = t.nbits();
            if nn < np {
                u[i] = t;
                g[i].conj();
            }
            u[i].norm();
        }
        FP12::pow4(&g, &u)
    } else {
        d.pow(e)
    }
}
