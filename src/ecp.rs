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
use super::fp::FP;
use super::rom;

use std::fmt;
use std::str::SplitWhitespace;

pub use super::rom::{AESKEY, CURVETYPE, CURVE_PAIRING_TYPE, HASH_TYPE, SEXTIC_TWIST, SIGN_OF_X};
pub use crate::types::CurveType;

#[derive(Clone)]
pub struct ECP {
    x: FP,
    y: FP,
    z: FP,
}

impl PartialEq for ECP {
    fn eq(&self, other: &ECP) -> bool {
        self.equals(other)
    }
}

impl Eq for ECP {}

impl fmt::Display for ECP {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ECP: [ {}, {}, {} ]", self.x, self.y, self.z)
    }
}

impl fmt::Debug for ECP {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ECP: [ {}, {}, {} ]", self.x, self.y, self.z)
    }
}

#[allow(non_snake_case)]
impl ECP {
    /// Projective New
    ///
    /// Creates a new projective elliptic curve point at infinity (0, 1, 0).
    #[inline(always)]
    pub fn pnew() -> ECP {
        ECP {
            x: FP::new(),
            y: FP::new_int(1),
            z: FP::new(),
        }
    }

    /// New
    ///
    /// Creates a new ECP at infinity
    #[inline(always)]
    pub fn new() -> ECP {
        let mut E = ECP::pnew();
        if CURVETYPE == CurveType::Edwards {
            E.z.one();
        }
        return E;
    }

    /// New Bigs
    ///
    /// Set (x,y) from two Bigs
    /// Set to infinity if not on curve.
    #[inline(always)]
    pub fn new_bigs(ix: &Big, iy: &Big) -> ECP {
        let mut E = ECP::new();
        E.x.bcopy(ix);
        E.y.bcopy(iy);
        E.z.one();
        E.x.norm();
        let rhs = ECP::rhs(&E.x);
        if CURVETYPE == CurveType::Montgomery {
            if rhs.jacobi() != 1 {
                E.inf();
            }
        } else {
            let mut y2 = E.y.clone();
            y2.sqr();
            if !y2.equals(&rhs) {
                E.inf();
            }
        }
        return E;
    }

    /// New BigInt
    ///
    /// Set (x, y) from x and sign of y.
    /// Set to infinity if not on curve.
    #[inline(always)]
    pub fn new_bigint(ix: &Big, s: isize) -> ECP {
        let mut E = ECP::new();
        E.x.bcopy(ix);
        E.x.norm();
        E.z.one();

        let mut rhs = ECP::rhs(&E.x);

        if rhs.jacobi() == 1 {
            let mut ny = rhs.sqrt();
            if ny.redc().parity() != s {
                ny.neg()
            }
            E.y = ny;
        } else {
            E.inf()
        }
        E
    }

    /// New Big
    ///
    /// Create point from x, calculates y from curve equation
    /// Set to infinity if not on curve.
    #[inline(always)]
    #[allow(non_snake_case)]
    pub fn new_big(ix: &Big) -> ECP {
        let mut E = ECP::new();
        E.x.bcopy(ix);
        E.x.norm();
        E.z.one();
        let mut rhs = ECP::rhs(&E.x);
        if rhs.jacobi() == 1 {
            if CURVETYPE != CurveType::Montgomery {
                E.y = rhs.sqrt()
            }
        } else {
            E.inf();
        }
        return E;
    }

    /// New Fp's
    ///
    /// Constructs from (x,y).
    /// Set to infinity if not on curve.
    #[inline(always)]
    pub fn new_fps(x: FP, y: FP) -> ECP {
        let mut point = ECP {
            x,
            y,
            z: FP::new_int(1),
        };

        let rhs = ECP::rhs(&point.x);
        let mut y2 = point.y.clone();
        y2.sqr();
        if !y2.equals(&rhs) {
            point.inf();
        }
        point
    }

    /// New Projective
    ///
    /// Create new point from (X, Y, Z).
    /// Assumes coordinates are valid.
    #[inline(always)]
    pub fn new_projective(x: FP, y: FP, z: FP) -> ECP {
        ECP { x, y, z }
    }

    /// Infinity
    ///
    /// Set self to infinity.
    pub fn inf(&mut self) {
        self.x.zero();
        if CURVETYPE != CurveType::Montgomery {
            self.y.one();
        }
        if CURVETYPE != CurveType::Edwards {
            self.z.zero();
        } else {
            self.z.one()
        }
    }

    /// Right Hand Side
    ///
    /// Calculate RHS of curve equation.
    fn rhs(x: &FP) -> FP {
        let mut r = x.clone();
        r.sqr();

        if CURVETYPE == CurveType::Weierstrass {
            // x^3+Ax+B
            let b = FP::new_big(Big::new_ints(&rom::CURVE_B));
            r.mul(x);
            if rom::CURVE_A == -3 {
                let mut cx = x.clone();
                cx.imul(3);
                cx.neg();
                cx.norm();
                r.add(&cx);
            }
            r.add(&b);
        }
        if CURVETYPE == CurveType::Edwards {
            // (Ax^2-1)/(Bx^2-1)
            let mut b = FP::new_big(Big::new_ints(&rom::CURVE_B));
            let one = FP::new_int(1);
            b.mul(&r);
            b.sub(&one);
            b.norm();
            if rom::CURVE_A == -1 {
                r.neg()
            }
            r.sub(&one);
            r.norm();
            b.inverse();
            r.mul(&b);
        }
        if CURVETYPE == CurveType::Montgomery {
            // x^3+Ax^2+x
            let mut x3 = r.clone();
            x3.mul(x);
            r.imul(rom::CURVE_A);
            r.add(&x3);
            r.add(&x);
        }
        r.reduce();
        return r;
    }

    /// Is Infinity
    ///
    /// self == infinity
    pub fn is_infinity(&self) -> bool {
        match CURVETYPE {
            CurveType::Edwards => self.x.is_zilch() && self.y.equals(&self.z),
            CurveType::Weierstrass => self.x.is_zilch() && self.z.is_zilch(),
            CurveType::Montgomery => self.z.is_zilch(),
        }
    }

    /// Conditional Swap
    ///
    /// Conditional swap of self and Q dependant on d
    pub fn cswap(&mut self, Q: &mut ECP, d: isize) {
        self.x.cswap(&mut Q.x, d);
        if CURVETYPE != CurveType::Montgomery {
            self.y.cswap(&mut Q.y, d)
        }
        self.z.cswap(&mut Q.z, d);
    }

    /// Conditional Move
    ///
    /// Conditional move of Q to self dependant on d
    pub fn cmove(&mut self, Q: &ECP, d: isize) {
        self.x.cmove(&Q.x, d);
        if CURVETYPE != CurveType::Montgomery {
            self.y.cmove(&Q.y, d)
        }
        self.z.cmove(&Q.z, d);
    }

    /// ConstantTime Equals
    ///
    /// Return 1 if b == c, no branching
    fn teq(b: i32, c: i32) -> isize {
        let mut x = b ^ c;
        x -= 1; // if x=0, x now -1
        return ((x >> 31) & 1) as isize;
    }

    /// Negation
    ///
    /// self = -self
    pub fn neg(&mut self) {
        if CURVETYPE == CurveType::Weierstrass {
            self.y.neg();
            self.y.norm();
        }
        if CURVETYPE == CurveType::Edwards {
            self.x.neg();
            self.x.norm();
        }
        return;
    }

    /// Multiply X
    ///
    /// Multiplies the X coordinate
    pub fn mulx(&mut self, c: &mut FP) {
        self.x.mul(c);
    }

    /// Selector
    ///
    /// Constant time select from pre-computed table.
    fn selector(&mut self, W: &[ECP], b: i32) {
        let m = b >> 31;
        let mut babs = (b ^ m) - m;

        babs = (babs - 1) / 2;

        self.cmove(&W[0], ECP::teq(babs, 0)); // conditional move
        self.cmove(&W[1], ECP::teq(babs, 1));
        self.cmove(&W[2], ECP::teq(babs, 2));
        self.cmove(&W[3], ECP::teq(babs, 3));
        self.cmove(&W[4], ECP::teq(babs, 4));
        self.cmove(&W[5], ECP::teq(babs, 5));
        self.cmove(&W[6], ECP::teq(babs, 6));
        self.cmove(&W[7], ECP::teq(babs, 7));

        let mut MP = self.clone();
        MP.neg();
        self.cmove(&MP, (m & 1) as isize);
    }

    /// Equals
    ///
    /// self == Q
    pub fn equals(&self, Q: &ECP) -> bool {
        let mut a = self.getpx();
        a.mul(&Q.z);
        let mut b = Q.getpx();
        b.mul(&self.z);
        if !a.equals(&b) {
            return false;
        }
        if CURVETYPE != CurveType::Montgomery {
            a = self.getpy();
            a.mul(&Q.z);
            b = Q.getpy();
            b.mul(&self.z);
            if !a.equals(&b) {
                return false;
            }
        }
        return true;
    }

    /// Affine
    ///
    /// Set to affine, from (X, Y, Z) to (x, y).
    pub fn affine(&mut self) {
        if self.is_infinity() {
            return;
        }
        let one = FP::new_int(1);
        if self.z.equals(&one) {
            return;
        }
        self.z.inverse();

        self.x.mul(&self.z);
        self.x.reduce();
        if CURVETYPE != CurveType::Montgomery {
            self.y.mul(&self.z);
            self.y.reduce();
        }
        self.z = one;
    }

    /// Get X
    ///
    /// Extract affine x as a Big.
    pub fn getx(&self) -> Big {
        let mut W = self.clone();
        W.affine();
        return W.x.redc();
    }

    /// Get Y
    ///
    /// Extract affine y as a Big.
    pub fn gety(&self) -> Big {
        let mut W = self.clone();
        W.affine();
        return W.y.redc();
    }

    /// Get Sign Y
    ///
    /// Returns the sign of Y.
    pub fn gets(&self) -> isize {
        let y = self.gety();
        return y.parity();
    }

    /// Get Proejctive X
    ///
    /// Extract X as an FP.
    pub fn getpx(&self) -> FP {
        self.x.clone()
    }

    /// Get Projective Y
    ///
    /// Extract Y as an FP.
    pub fn getpy(&self) -> FP {
        self.y.clone()
    }

    /// Get Porjective Z
    ///
    /// Extract Z as an FP.
    pub fn getpz(&self) -> FP {
        self.z.clone()
    }

    /// To Bytes
    ///
    /// Convert to byte array
    /// Panics if byte array is insufficient length.
    pub fn to_bytes(&self, b: &mut [u8], compress: bool) {
        let mb = big::MODBYTES as usize;
        let mut t: [u8; big::MODBYTES as usize] = [0; big::MODBYTES as usize];
        let mut W = self.clone();

        W.affine();
        W.x.redc().to_bytes(&mut t);
        for i in 0..mb {
            b[i + 1] = t[i]
        }

        if CURVETYPE == CurveType::Montgomery {
            b[0] = 0x06;
            return;
        }

        if compress {
            b[0] = 0x02;
            if W.y.redc().parity() == 1 {
                b[0] = 0x03
            }
            return;
        }

        b[0] = 0x04;

        W.y.redc().to_bytes(&mut t);
        for i in 0..mb {
            b[i + mb + 1] = t[i]
        }
    }

    /// From Bytes
    ///
    /// Convert from byte array to point
    /// Panics if input bytes are less than required bytes.
    #[inline(always)]
    pub fn from_bytes(b: &[u8]) -> ECP {
        let mut t: [u8; big::MODBYTES as usize] = [0; big::MODBYTES as usize];
        let mb = big::MODBYTES as usize;
        let p = Big::new_ints(&rom::MODULUS);

        for i in 0..mb {
            t[i] = b[i + 1]
        }
        let px = Big::from_bytes(&t);
        if Big::comp(&px, &p) >= 0 {
            return ECP::new();
        }

        if CURVETYPE == CurveType::Montgomery {
            return ECP::new_big(&px);
        }

        if b[0] == 0x04 {
            for i in 0..mb {
                t[i] = b[i + mb + 1]
            }
            let py = Big::from_bytes(&t);
            if Big::comp(&py, &p) >= 0 {
                return ECP::new();
            }
            return ECP::new_bigs(&px, &py);
        }

        if b[0] == 0x02 || b[0] == 0x03 {
            return ECP::new_bigint(&px, (b[0] & 1) as isize);
        }

        return ECP::new();
    }

    /// To String
    ///
    /// Converts `ECP` to a hex string.
    pub fn to_string(&self) -> String {
        let mut W = self.clone();
        W.affine();
        if W.is_infinity() {
            return String::from("infinity");
        }
        if CURVETYPE == CurveType::Montgomery {
            return format!("({})", W.x.redc().to_string());
        } else {
            return format!("({},{})", W.x.redc().to_string(), W.y.redc().to_string());
        };
    }

    /// To Hex
    ///
    /// Converts the projectives to a hex string separated by a space.
    pub fn to_hex(&self) -> String {
        format!(
            "{} {} {}",
            self.x.to_hex(),
            self.y.to_hex(),
            self.z.to_hex()
        )
    }

    /// From Hex Iterator
    #[inline(always)]
    pub fn from_hex_iter(iter: &mut SplitWhitespace) -> ECP {
        ECP {
            x: FP::from_hex_iter(iter),
            y: FP::from_hex_iter(iter),
            z: FP::from_hex_iter(iter),
        }
    }

    /// From Hex
    #[inline(always)]
    pub fn from_hex(val: String) -> ECP {
        let mut iter = val.split_whitespace();
        return ECP::from_hex_iter(&mut iter);
    }

    /// Double
    ///
    /// self *= 2
    pub fn dbl(&mut self) {
        if CURVETYPE == CurveType::Weierstrass {
            if rom::CURVE_A == 0 {
                let mut t0 = self.y.clone();
                t0.sqr();
                let mut t1 = self.y.clone();
                t1.mul(&self.z);
                let mut t2 = self.z.clone();
                t2.sqr();

                self.z = t0.clone();
                self.z.add(&t0);
                self.z.norm();
                self.z.dbl();
                self.z.dbl();
                self.z.norm();
                t2.imul(3 * rom::CURVE_B_I);

                let mut x3 = t2.clone();
                x3.mul(&self.z);

                let mut y3 = t0.clone();
                y3.add(&t2);
                y3.norm();
                self.z.mul(&t1);
                t1 = t2.clone();
                t1.add(&t2);
                t2.add(&t1);
                t0.sub(&t2);
                t0.norm();
                y3.mul(&t0);
                y3.add(&x3);
                t1 = self.getpx();
                t1.mul(&self.y);
                self.x = t0.clone();
                self.x.norm();
                self.x.mul(&t1);
                self.x.dbl();
                self.x.norm();
                self.y = y3.clone();
                self.y.norm();
            } else {
                let mut t0 = self.x.clone();
                let mut t1 = self.y.clone();
                let mut t2 = self.z.clone();
                let mut t3 = self.x.clone();
                let mut z3 = self.z.clone();
                let mut b = FP::new();

                if rom::CURVE_B_I == 0 {
                    b = FP::new_big(Big::new_ints(&rom::CURVE_B));
                }

                t0.sqr(); //1    x^2
                t1.sqr(); //2    y^2
                t2.sqr(); //3

                t3.mul(&self.y); //4
                t3.dbl();
                t3.norm(); //5
                z3.mul(&self.x); //6
                z3.dbl();
                z3.norm(); //7
                let mut y3 = t2.clone();

                if rom::CURVE_B_I == 0 {
                    y3.mul(&b); //8
                } else {
                    y3.imul(rom::CURVE_B_I);
                }

                y3.sub(&z3); //9  ***
                let mut x3 = y3.clone();
                x3.add(&y3);
                x3.norm(); //10

                y3.add(&x3); //11
                x3 = t1.clone();
                x3.sub(&y3);
                x3.norm(); //12
                y3.add(&t1);
                y3.norm(); //13
                y3.mul(&x3); //14
                x3.mul(&t3); //15
                t3 = t2.clone();
                t3.add(&t2); //16
                t2.add(&t3); //17

                if rom::CURVE_B_I == 0 {
                    z3.mul(&b); //18
                } else {
                    z3.imul(rom::CURVE_B_I);
                }

                z3.sub(&t2); //19
                z3.sub(&t0);
                z3.norm(); //20  ***
                t3 = z3.clone();
                t3.add(&z3); //21

                z3.add(&t3);
                z3.norm(); //22
                t3 = t0.clone();
                t3.add(&t0); //23
                t0.add(&t3); //24
                t0.sub(&t2);
                t0.norm(); //25

                t0.mul(&z3); //26
                y3.add(&t0); //27
                t0 = self.getpy();
                t0.mul(&self.z); //28
                t0.dbl();
                t0.norm(); //29
                z3.mul(&t0); //30
                x3.sub(&z3); //31
                t0.dbl();
                t0.norm(); //32
                t1.dbl();
                t1.norm(); //33
                z3 = t0.clone();
                z3.mul(&t1); //34

                self.x = x3.clone();
                self.x.norm();
                self.y = y3.clone();
                self.y.norm();
                self.z = z3.clone();
                self.z.norm();
            }
        }
        if CURVETYPE == CurveType::Edwards {
            let mut c = self.x.clone();
            let mut d = self.y.clone();
            let mut h = self.z.clone();

            self.x.mul(&self.y);
            self.x.dbl();
            self.x.norm();
            c.sqr();
            d.sqr();
            if rom::CURVE_A == -1 {
                c.neg()
            }
            self.y = c.clone();
            self.y.add(&d);
            self.y.norm();
            h.sqr();
            h.dbl();
            self.z = self.getpy();
            let mut j = self.getpy();
            j.sub(&h);
            j.norm();
            self.x.mul(&j);
            c.sub(&d);
            c.norm();
            self.y.mul(&c);
            self.z.mul(&j);
        }
        if CURVETYPE == CurveType::Montgomery {
            let mut a = self.x.clone();
            let mut b = self.x.clone();

            a.add(&self.z);
            a.norm();
            let mut aa = a.clone();
            aa.sqr();
            b.sub(&self.z);
            b.norm();
            let mut bb = b.clone();
            bb.sqr();
            let mut c = aa.clone();
            c.sub(&bb);
            c.norm();

            self.x = aa.clone();
            self.x.mul(&bb);

            a = c.clone();
            a.imul((rom::CURVE_A + 2) / 4);

            bb.add(&a);
            bb.norm();
            self.z = bb;
            self.z.mul(&c);
        }
    }

    /// Addition
    ///
    /// self += Q
    pub fn add(&mut self, Q: &ECP) {
        if CURVETYPE == CurveType::Weierstrass {
            if rom::CURVE_A == 0 {
                let b = 3 * rom::CURVE_B_I;
                let mut t0 = self.x.clone();
                t0.mul(&Q.x);
                let mut t1 = self.y.clone();
                t1.mul(&Q.y);
                let mut t2 = self.z.clone();
                t2.mul(&Q.z);
                let mut t3 = self.x.clone();
                t3.add(&self.y);
                t3.norm();
                let mut t4 = Q.x.clone();
                t4.add(&Q.y);
                t4.norm();
                t3.mul(&t4);
                t4 = t0.clone();
                t4.add(&t1);

                t3.sub(&t4);
                t3.norm();
                t4 = self.getpy();
                t4.add(&self.z);
                t4.norm();
                let mut x3 = Q.y.clone();
                x3.add(&Q.z);
                x3.norm();

                t4.mul(&x3);
                x3 = t1.clone();
                x3.add(&t2);

                t4.sub(&x3);
                t4.norm();
                x3 = self.getpx();
                x3.add(&self.z);
                x3.norm();
                let mut y3 = Q.x.clone();
                y3.add(&Q.z);
                y3.norm();
                x3.mul(&y3);
                y3 = t0.clone();
                y3.add(&t2);
                y3.rsub(&x3);
                y3.norm();
                x3 = t0.clone();
                x3.add(&t0);
                t0.add(&x3);
                t0.norm();
                t2.imul(b);

                let mut z3 = t1.clone();
                z3.add(&t2);
                z3.norm();
                t1.sub(&t2);
                t1.norm();
                y3.imul(b);

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
            } else {
                let mut t0 = self.x.clone();
                let mut t1 = self.y.clone();
                let mut t2 = self.z.clone();
                let mut t3 = self.x.clone();
                let mut t4 = Q.x.clone();
                let mut y3 = Q.x.clone();
                let mut x3 = Q.y.clone();
                let mut b = FP::new();

                if rom::CURVE_B_I == 0 {
                    b = FP::new_big(Big::new_ints(&rom::CURVE_B));
                }

                t0.mul(&Q.x); //1
                t1.mul(&Q.y); //2
                t2.mul(&Q.z); //3

                t3.add(&self.y);
                t3.norm(); //4
                t4.add(&Q.y);
                t4.norm(); //5
                t3.mul(&t4); //6
                t4 = t0.clone();
                t4.add(&t1); //7
                t3.sub(&t4);
                t3.norm(); //8
                t4 = self.getpy();
                t4.add(&self.z);
                t4.norm(); //9
                x3.add(&Q.z);
                x3.norm(); //10
                t4.mul(&x3); //11
                x3 = t1.clone();
                x3.add(&t2); //12

                t4.sub(&x3);
                t4.norm(); //13
                x3 = self.getpx();
                x3.add(&self.z);
                x3.norm(); //14
                y3.add(&Q.z);
                y3.norm(); //15

                x3.mul(&y3); //16
                y3 = t0.clone();
                y3.add(&t2); //17

                y3.rsub(&x3);
                y3.norm(); //18
                let mut z3 = t2.clone();

                if rom::CURVE_B_I == 0 {
                    z3.mul(&b); //18
                } else {
                    z3.imul(rom::CURVE_B_I);
                }

                x3 = y3.clone();
                x3.sub(&z3);
                x3.norm(); //20
                z3 = x3.clone();
                z3.add(&x3); //21

                x3.add(&z3); //22
                z3 = t1.clone();
                z3.sub(&x3);
                z3.norm(); //23
                x3.add(&t1);
                x3.norm(); //24

                if rom::CURVE_B_I == 0 {
                    y3.mul(&b); //18
                } else {
                    y3.imul(rom::CURVE_B_I);
                }

                t1 = t2.clone();
                t1.add(&t2); //t1.norm();//26
                t2.add(&t1); //27

                y3.sub(&t2); //28

                y3.sub(&t0);
                y3.norm(); //29
                t1 = y3.clone();
                t1.add(&y3); //30
                y3.add(&t1);
                y3.norm(); //31

                t1 = t0.clone();
                t1.add(&t0); //32
                t0.add(&t1); //33
                t0.sub(&t2);
                t0.norm(); //34
                t1 = t4.clone();
                t1.mul(&y3); //35
                t2 = t0.clone();
                t2.mul(&y3); //36
                y3 = x3.clone();
                y3.mul(&z3); //37
                y3.add(&t2); //y3.norm();//38
                x3.mul(&t3); //39
                x3.sub(&t1); //40
                z3.mul(&t4); //41
                t1 = t3.clone();
                t1.mul(&t0); //42
                z3.add(&t1);
                self.x = x3.clone();
                self.x.norm();
                self.y = y3.clone();
                self.y.norm();
                self.z = z3.clone();
                self.z.norm();
            }
        }
        if CURVETYPE == CurveType::Edwards {
            let bb = FP::new_big(Big::new_ints(&rom::CURVE_B));
            let mut a = self.z.clone();
            let mut c = self.x.clone();
            let mut d = self.y.clone();

            a.mul(&Q.z);
            let mut b = a.clone();
            b.sqr();
            c.mul(&Q.x);
            d.mul(&Q.y);

            let mut e = c.clone();
            e.mul(&d);
            e.mul(&bb);
            let mut f = b.clone();
            f.sub(&e);
            let mut g = b.clone();
            g.add(&e);

            if rom::CURVE_A == 1 {
                e = d.clone();
                e.sub(&c);
            }
            c.add(&d);

            b = self.getpx();
            b.add(&self.y);
            d = Q.getpx();
            d.add(&Q.y);
            b.norm();
            d.norm();
            b.mul(&d);
            b.sub(&c);
            b.norm();
            f.norm();
            b.mul(&f);
            self.x = a.clone();
            self.x.mul(&b);
            g.norm();
            if rom::CURVE_A == 1 {
                e.norm();
                c = e.clone();
                c.mul(&g);
            }
            if rom::CURVE_A == -1 {
                c.norm();
                c.mul(&g);
            }
            self.y = a.clone();
            self.y.mul(&c);
            self.z = f.clone();
            self.z.mul(&g);
        }
        return;
    }

    /// Differential Add for Montgomery curves.
    ///
    /// self += Q
    /// where W is (self - Q) and is affine
    pub fn dadd(&mut self, Q: &ECP, W: &ECP) {
        let mut a = self.x.clone();
        let mut b = self.x.clone();
        let mut c = Q.x.clone();
        let mut d = Q.x.clone();

        a.add(&self.z);
        b.sub(&self.z);

        c.add(&Q.z);
        d.sub(&Q.z);

        a.norm();
        d.norm();

        let mut da = d.clone();
        da.mul(&a);

        c.norm();
        b.norm();

        let mut cb = c.clone();
        cb.mul(&b);

        a = da.clone();
        a.add(&cb);
        a.norm();
        a.sqr();
        b = da.clone();
        b.sub(&cb);
        b.norm();
        b.sqr();

        self.x = a.clone();
        self.z = W.getpx();
        self.z.mul(&b);
    }

    /// Subtraction
    ///
    /// self -= Q
    pub fn sub(&mut self, Q: &ECP) {
        let mut NQ = Q.clone();
        NQ.neg();
        self.add(&NQ);
    }

    /// Pin Multiplication
    ///
    /// Constant time multiply by small integer of length bts - use ladder
    #[inline(always)]
    pub fn pinmul(&self, e: i32, bts: i32) -> ECP {
        if CURVETYPE == CurveType::Montgomery {
            return self.mul(&mut Big::new_int(e as isize));
        } else {
            let mut R0 = ECP::new();
            let mut R1 = self.clone();

            for i in (0..bts).rev() {
                let b = ((e >> i) & 1) as isize;
                let mut P = R1.clone();
                P.add(&R0);
                R0.cswap(&mut R1, b);
                R1 = P.clone();
                R0.dbl();
                R0.cswap(&mut R1, b);
            }
            let mut P = R0.clone();
            P.affine();
            P
        }
    }

    /// Multiplication
    ///
    /// Return e * self
    #[inline(always)]
    pub fn mul(&self, e: &Big) -> ECP {
        if e.is_zilch() || self.is_infinity() {
            return ECP::new();
        }
        let mut T = if CURVETYPE == CurveType::Montgomery {
            /* use Ladder */
            let mut R0 = self.clone();
            let mut R1 = self.clone();
            R1.dbl();
            let mut D = self.clone();
            D.affine();
            let nb = e.nbits();

            for i in (0..nb - 1).rev() {
                let b = e.bit(i);
                let mut P = R1.clone();
                P.dadd(&mut R0, &D);
                R0.cswap(&mut R1, b);
                R1 = P.clone();
                R0.dbl();
                R0.cswap(&mut R1, b);
            }
            R0.clone()
        } else {
            let mut W: [ECP; 8] = [
                ECP::new(),
                ECP::new(),
                ECP::new(),
                ECP::new(),
                ECP::new(),
                ECP::new(),
                ECP::new(),
                ECP::new(),
            ];

            const CT: usize = 1 + (big::NLEN * (big::BASEBITS as usize) + 3) / 4;
            let mut w: [i8; CT] = [0; CT];

            let mut Q = self.clone();
            Q.dbl();

            W[0] = self.clone();

            for i in 1..8 {
                W[i] = W[i - 1].clone();
                W[i].add(&Q);
            }

            // make exponent odd - add 2P if even, P if odd
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
            let C = Q.clone();

            let nb = 1 + (t.nbits() + 3) / 4;

            // convert exponent to signed 4-bit window
            for i in 0..nb {
                w[i] = (t.lastbits(5) - 16) as i8;
                t.dec(w[i] as isize);
                t.norm();
                t.fshr(4);
            }
            w[nb] = t.lastbits(5) as i8;

            let mut P = W[((w[nb] as usize) - 1) / 2].clone();
            for i in (0..nb).rev() {
                Q.selector(&W, w[i] as i32);
                P.dbl();
                P.dbl();
                P.dbl();
                P.dbl();
                P.add(&Q);
            }
            P.sub(&C); /* apply correction */
            P
        };
        T.affine();
        T
    }

    /// Multiply two points by scalars
    ///
    /// Return e * self + f * Q
    #[inline(always)]
    pub fn mul2(&self, e: &Big, Q: &ECP, f: &Big) -> ECP {
        let mut W: [ECP; 8] = [
            ECP::new(),
            ECP::new(),
            ECP::new(),
            ECP::new(),
            ECP::new(),
            ECP::new(),
            ECP::new(),
            ECP::new(),
        ];

        const CT: usize = 1 + (big::NLEN * (big::BASEBITS as usize) + 1) / 2;
        let mut w: [i8; CT] = [0; CT];

        let mut te = e.clone();
        let mut tf = f.clone();

        // precompute table

        W[1] = self.clone();
        W[1].sub(Q);
        W[2] = self.clone();
        W[2].add(Q);
        let mut S = Q.clone();
        S.dbl();
        let mut C = W[1].clone();
        W[0] = C.clone();
        W[0].sub(&S); // copy to C is stupid Rust thing..
        C = W[2].clone();
        W[3] = C.clone();
        W[3].add(&S);
        let mut T = self.clone();
        T.dbl();
        C = W[1].clone();
        W[5] = C.clone();
        W[5].add(&T);
        C = W[2].clone();
        W[6] = C.clone();
        W[6].add(&T);
        C = W[5].clone();
        W[4] = C.clone();
        W[4].sub(&S);
        C = W[6].clone();
        W[7] = C.clone();
        W[7].add(&S);

        // if multiplier is odd, add 2, else add 1 to multiplier, and add 2P or P to correction

        let mut s = te.parity();
        te.inc(1);
        te.norm();
        let mut ns = te.parity();
        let mut mt = te.clone();
        mt.inc(1);
        mt.norm();
        te.cmove(&mt, s);
        T.cmove(&self, ns);
        C = T.clone();

        s = tf.parity();
        tf.inc(1);
        tf.norm();
        ns = tf.parity();
        mt = tf.clone();
        mt.inc(1);
        mt.norm();
        tf.cmove(&mt, s);
        S.cmove(&Q, ns);
        C.add(&S);

        mt = te.clone();
        mt.add(&tf);
        mt.norm();
        let nb = 1 + (mt.nbits() + 1) / 2;

        // convert exponent to signed 2-bit window
        for i in 0..nb {
            let a = te.lastbits(3) - 4;
            te.dec(a);
            te.norm();
            te.fshr(2);
            let b = tf.lastbits(3) - 4;
            tf.dec(b);
            tf.norm();
            tf.fshr(2);
            w[i] = (4 * a + b) as i8;
        }
        w[nb] = (4 * te.lastbits(3) + tf.lastbits(3)) as i8;
        S = W[((w[nb] as usize) - 1) / 2].clone();

        for i in (0..nb).rev() {
            T.selector(&W, w[i] as i32);
            S.dbl();
            S.dbl();
            S.add(&T);
        }
        S.sub(&C); /* apply correction */
        S.affine();
        return S;
    }

    // Multiply itself by cofactor of the curve
    pub fn cfp(&mut self) {
        let cf = rom::CURVE_COF_I;
        if cf == 1 {
            return;
        }
        if cf == 4 {
            self.dbl();
            self.dbl();
            return;
        }
        if cf == 8 {
            self.dbl();
            self.dbl();
            self.dbl();
            return;
        }
        let c = Big::new_ints(&rom::CURVE_COF);
        let P = self.mul(&c);
        *self = P.clone();
    }


    /// Map It
    ///
    /// Maps bytes to a curve point using hash and test.
    /// Not conformant to hash-to-curve standards.
    #[allow(non_snake_case)]
    #[inline(always)]
    pub fn mapit(h: &[u8]) -> ECP {
        let q = Big::new_ints(&rom::MODULUS);
        let mut x = Big::from_bytes(h);
        x.rmod(&q);
        let mut P: ECP;

        loop {
            loop {
                if CURVETYPE != CurveType::Montgomery {
                    P = ECP::new_bigint(&x, 0);
                } else {
                    P = ECP::new_big(&x);
                }
                x.inc(1);
                x.norm();
                if !P.is_infinity() {
                    break;
                }
            }
            P.cfp();
            if !P.is_infinity() {
                break;
            }
        }

        return P;
    }

    /// Generator
    ///
    /// Returns the generator of the group.
    #[inline(always)]
    pub fn generator() -> ECP {
        let G: ECP;

        let gx = Big::new_ints(&rom::CURVE_GX);

        if CURVETYPE != CurveType::Montgomery {
            let gy = Big::new_ints(&rom::CURVE_GY);
            G = ECP::new_bigs(&gx, &gy);
        } else {
            G = ECP::new_big(&gx);
        }
        return G;
    }
}
