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
use super::big::{Big, MODBYTES};
use crate::arch;
use crate::arch::Chunk;

#[derive(Clone)]
pub struct DBig {
    pub w: [Chunk; big::DNLEN],
}

impl DBig {

    /// Creates new DBig as 0.
    #[inline(always)]
    pub fn new() -> DBig {
        DBig {
            w: [0; big::DNLEN as usize],
        }
    }

    /// New Small Copy
    ///
    /// Creates a new DBig from a Big
    /// Most significant bits are set to zero.
    #[inline(always)]
    pub fn new_scopy(x: &Big) -> DBig {
        let mut b = DBig::new();
        for i in 0..big::NLEN {
            b.w[i] = x.w[i];
        }
        b.w[big::NLEN - 1] = x.get(big::NLEN - 1) & big::BMASK; // top word normalized
        b.w[big::NLEN] = x.get(big::NLEN - 1) >> big::BASEBITS;

        for i in big::NLEN + 1..big::DNLEN {
            b.w[i] = 0
        }
        b
    }

    /// Split DBig
    ///
    /// Splits the DBig at position n, return higher half, keep lower half
    #[inline(always)]
    pub fn split(&mut self, n: usize) -> Big {
        let mut t = Big::new();
        let m = n % big::BASEBITS;
        let mut carry = self.w[big::DNLEN - 1] << (big::BASEBITS - m);

        for i in (big::NLEN - 1..big::DNLEN - 1).rev() {
            let nw = (self.w[i] >> m) | carry;
            carry = (self.w[i] << (big::BASEBITS - m)) & big::BMASK;
            t.set(i + 1 - big::NLEN, nw);
        }
        self.w[big::NLEN - 1] &= ((1 as Chunk) << m) - 1;
        t
    }

    /// General shift left
    pub fn shl(&mut self, k: usize) {
        let n = k % big::BASEBITS;
        let m = k / big::BASEBITS;
        self.w[big::DNLEN - 1] =
            (self.w[big::DNLEN - 1 - m] << n) | (self.w[big::DNLEN - m - 2] >> (big::BASEBITS - n));
        for i in (m + 1..big::DNLEN - 1).rev() {
            self.w[i] =
                ((self.w[i - m] << n) & big::BMASK) | (self.w[i - m - 1] >> (big::BASEBITS - n));
        }

        self.w[m] = (self.w[0] << n) & big::BMASK;
        for i in 0..m {
            self.w[i] = 0
        }
    }

    /// General shift right
    pub fn shr(&mut self, k: usize) {
        let n = k % big::BASEBITS;
        let m = k / big::BASEBITS;
        for i in 0..big::DNLEN - m - 1 {
            self.w[i] =
                (self.w[m + i] >> n) | ((self.w[m + i + 1] << (big::BASEBITS - n)) & big::BMASK);
        }
        self.w[big::DNLEN - m - 1] = self.w[big::DNLEN - 1] >> n;
        for i in big::DNLEN - m..big::DNLEN {
            self.w[i] = 0
        }
    }

    /// Copy from a Big
    pub fn ucopy(&mut self, x: &Big) {
        for i in 0..big::NLEN {
            self.w[i] = 0;
        }
        for i in big::NLEN..big::DNLEN {
            self.w[i] = x.w[i - big::NLEN];
        }
    }

    pub fn cmove(&mut self, g: &DBig, d: isize) {
        let b = -d as Chunk;
        for i in 0..big::DNLEN {
            self.w[i] ^= (self.w[i] ^ g.w[i]) & b;
        }
    }

    /// self += x
    pub fn add(&mut self, x: &DBig) {
        for i in 0..big::DNLEN {
            self.w[i] += x.w[i];
        }
    }

    /// self -= x
    pub fn sub(&mut self, x: &DBig) {
        for i in 0..big::DNLEN {
            self.w[i] -= x.w[i];
        }
    }

    /// self = x - self
    pub fn rsub(&mut self, x: &DBig) {
        for i in 0..big::DNLEN {
            self.w[i] = x.w[i] - self.w[i];
        }
    }

    /// Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b. Inputs must be normalised
    pub fn comp(a: &DBig, b: &DBig) -> isize {
        for i in (0..big::DNLEN).rev() {
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

    /// Normalise Big - force all digits < 2^big::BASEBITS
    pub fn norm(&mut self) {
        let mut carry = 0 as Chunk;
        for i in 0..big::DNLEN - 1 {
            let d = self.w[i] + carry;
            self.w[i] = d & big::BMASK;
            carry = d >> big::BASEBITS;
        }
        self.w[big::DNLEN - 1] += carry
    }

    /// Reduces self DBig mod a Big, and returns the Big
    #[inline(always)]
    pub fn dmod(&mut self, c: &Big) -> Big {
        let mut k = 0;
        self.norm();
        let mut m = DBig::new_scopy(c);

        if DBig::comp(self, &m) < 0 {
            return Big::new_dcopy(self);
        }

        loop {
            m.shl(1);
            k += 1;
            if DBig::comp(self, &m) < 0 {
                break;
            }
        }

        while k > 0 {
            m.shr(1);

            let mut dr = self.clone();
            dr.sub(&m);
            dr.norm();
            self.cmove(
                &dr,
                (1 - ((dr.w[big::DNLEN - 1] >> (arch::CHUNK - 1)) & 1)) as isize,
            );

            k -= 1;
        }
        Big::new_dcopy(self)
    }

    /// return self / c
    #[inline(always)]
    pub fn div(&mut self, c: &Big) -> Big {
        let mut k = 0;
        let mut m = DBig::new_scopy(c);
        let mut a = Big::new();
        let mut e = Big::new_int(1);
        self.norm();

        while DBig::comp(self, &m) >= 0 {
            e.fshl(1);
            m.shl(1);
            k += 1;
        }

        while k > 0 {
            m.shr(1);
            e.shr(1);

            let mut dr = self.clone();
            dr.sub(&m);
            dr.norm();
            let d = (1 - ((dr.w[big::DNLEN - 1] >> (arch::CHUNK - 1)) & 1)) as isize;
            self.cmove(&dr, d);
            let mut r = a.clone();
            r.add(&e);
            r.norm();
            a.cmove(&r, d);

            k -= 1;
        }
        a
    }

    /// set x = x mod 2^m
    pub fn mod2m(&mut self, m: usize) {
        let wd = m / big::BASEBITS;
        let bt = m % big::BASEBITS;
        let msk = (1 << bt) - 1;
        self.w[wd] &= msk;
        for i in wd + 1..big::DNLEN {
            self.w[i] = 0
        }
    }

    /// Return number of bits
    pub fn nbits(&self) -> usize {
        let mut k = big::DNLEN - 1;
        let mut s = self.clone();
        s.norm();
        while (k as isize) >= 0 && s.w[k] == 0 {
            k = k.wrapping_sub(1)
        }
        if (k as isize) < 0 {
            return 0;
        }
        let mut bts = (big::BASEBITS as usize) * k;
        let mut c = s.w[k];
        while c != 0 {
            c /= 2;
            bts += 1;
        }
        bts
    }

    /// Convert to Hex String
    pub fn to_string(&self) -> String {
        let mut s = String::new();
        let mut len = self.nbits();

        if len % 4 == 0 {
            len /= 4;
        } else {
            len /= 4;
            len += 1;
        }

        for i in (0..len).rev() {
            let mut b = self.clone();
            b.shr(i * 4);
            s = s + &format!("{:X}", b.w[0] & 15);
        }
        s
    }

    // convert from byte array to DBig
    #[inline(always)]
    pub fn from_bytes(b: &[u8]) -> DBig {
        let mut m = DBig::new();

        // Restrict length
        let max_dbig = 2 * MODBYTES;
        let len = if b.len() >= max_dbig {
            max_dbig as usize
        } else {
            b.len()
        };

        for i in 0..len {
            m.shl(8);
            m.w[0] += (b[i] & 0xff) as Chunk;
        }
        m
    }
}
