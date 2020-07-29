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

use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use super::big;
use super::big::Big;
use super::ecp;
use super::ecp::ECP;
use super::ecp2::ECP2;
use super::fp12::FP12;
use super::fp4::FP4;
use super::pair;
use super::rom;
use crate::hash256::HASH256;
use crate::hash384::HASH384;
use crate::hash512::HASH512;
use crate::rand::RAND;

// MPIN API Functions

// Configure mode of operation
pub const EFS: usize = big::MODBYTES as usize;
pub const EGS: usize = big::MODBYTES as usize;
pub const BAD_PARAMS: isize = -11;
pub const INVALID_POINT: isize = -14;
pub const WRONG_ORDER: isize = -18;
pub const BAD_PIN: isize = -19;
pub const SHA256: usize = 32;
pub const SHA384: usize = 48;
pub const SHA512: usize = 64;

// Configure your PIN here
pub const MAXPIN: i32 = 10000; // PIN less than this
pub const PBLEN: i32 = 14; // Number of bits in PIN
pub const TS: usize = 10; // 10 for 4 digit PIN, 14 for 6-digit PIN - 2^TS/TS approx = sqrt(MAXPIN)
pub const TRAP: usize = 200; // 200 for 4 digit PIN, 2000 for 6-digit PIN  - approx 2*sqrt(MAXPIN)

#[allow(non_snake_case)]
fn hash(sha: usize, c: &mut FP4, U: &mut ECP, r: &mut [u8]) -> bool {
    let mut w: [u8; EFS] = [0; EFS];
    let mut t: [u8; 6 * EFS] = [0; 6 * EFS];

    c.geta().geta().to_bytes(&mut w);
    for i in 0..EFS {
        t[i] = w[i]
    }
    c.geta().getb().to_bytes(&mut w);
    for i in EFS..2 * EFS {
        t[i] = w[i - EFS]
    }
    c.getb().geta().to_bytes(&mut w);
    for i in 2 * EFS..3 * EFS {
        t[i] = w[i - 2 * EFS]
    }
    c.getb().getb().to_bytes(&mut w);
    for i in 3 * EFS..4 * EFS {
        t[i] = w[i - 3 * EFS]
    }

    U.getx().to_bytes(&mut w);
    for i in 4 * EFS..5 * EFS {
        t[i] = w[i - 4 * EFS]
    }
    U.gety().to_bytes(&mut w);
    for i in 5 * EFS..6 * EFS {
        t[i] = w[i - 5 * EFS]
    }

    if sha == SHA256 {
        let mut h = HASH256::new();
        h.process_array(&t);
        let sh = h.hash();
        for i in 0..ecp::AESKEY {
            r[i] = sh[i]
        }
        return true;
    }
    if sha == SHA384 {
        let mut h = HASH384::new();
        h.process_array(&t);
        let sh = h.hash();
        for i in 0..ecp::AESKEY {
            r[i] = sh[i]
        }
        return true;
    }
    if sha == SHA512 {
        let mut h = HASH512::new();
        h.process_array(&t);
        let sh = h.hash();
        for i in 0..ecp::AESKEY {
            r[i] = sh[i]
        }
        return true;
    }
    return false;
}

/// Hash number (optional) and string to point on curve
fn hashit(sha: usize, n: usize, id: &[u8], w: &mut [u8]) -> bool {
    let mut r: [u8; 64] = [0; 64];
    let mut didit = false;
    if sha == SHA256 {
        let mut h = HASH256::new();
        if n > 0 {
            h.process_num(n as i32)
        }
        h.process_array(id);
        let hs = h.hash();
        for i in 0..sha {
            r[i] = hs[i];
        }
        didit = true;
    }
    if sha == SHA384 {
        let mut h = HASH384::new();
        if n > 0 {
            h.process_num(n as i32)
        }
        h.process_array(id);
        let hs = h.hash();
        for i in 0..sha {
            r[i] = hs[i];
        }
        didit = true;
    }
    if sha == SHA512 {
        let mut h = HASH512::new();
        if n > 0 {
            h.process_num(n as i32)
        }
        h.process_array(id);
        let hs = h.hash();
        for i in 0..sha {
            r[i] = hs[i];
        }
        didit = true;
    }
    if !didit {
        return false;
    }

    let rm = big::MODBYTES as usize;

    if sha > rm {
        for i in 0..rm {
            w[i] = r[i]
        }
    } else {
        for i in 0..sha {
            w[i + rm - sha] = r[i]
        }
        for i in 0..(rm - sha) {
            w[i] = 0
        }
    }

    return true;
}

/// Return time in slots since epoch
pub fn today() -> usize {
    return (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / (60 * 1440)) as usize;
}

// these next two functions help to implement elligator squared - http://eprint.iacr.org/2014/043
/// Maps a random u to a point on the curve
#[allow(non_snake_case)]
fn emap(u: &Big, cb: isize) -> ECP {
    let mut P: ECP;
    let mut x = u.clone();
    let p = Big::new_ints(&rom::MODULUS);
    x.rmod(&p);
    loop {
        P = ECP::new_bigint(&x, cb);
        if !P.is_infinity() {
            break;
        }
        x.inc(1);
        x.norm();
    }
    return P;
}

/// Returns u derived from P. Random value in range 1 to return value should then be added to u
#[allow(non_snake_case)]
fn unmap(u: &mut Big, P: &mut ECP) -> isize {
    let s = P.gets();
    let mut R: ECP;
    let mut r = 0;
    let x = P.getx();
    *u = x.clone();
    loop {
        u.dec(1);
        u.norm();
        r += 1;
        R = ECP::new_bigint(u, s);
        if !R.is_infinity() {
            break;
        }
    }
    return r as isize;
}

pub fn hash_id(sha: usize, id: &[u8], w: &mut [u8]) -> bool {
    return hashit(sha, 0, id, w);
}

// These next two functions implement elligator squared - http://eprint.iacr.org/2014/043
// Elliptic curve point E in format (0x04,x,y} is converted to form {0x0-,u,v}
// Note that u and v are indistinguisible from random strings
#[allow(non_snake_case)]
pub fn encoding(rng: &mut RAND, e: &mut [u8]) -> isize {
    let mut t: [u8; EFS] = [0; EFS];

    for i in 0..EFS {
        t[i] = e[i + 1]
    }
    let mut u = Big::from_bytes(&t);
    for i in 0..EFS {
        t[i] = e[i + EFS + 1]
    }
    let mut v = Big::from_bytes(&t);

    let mut P = ECP::new_bigs(&u, &v);
    if P.is_infinity() {
        return INVALID_POINT;
    }

    let p = Big::new_ints(&rom::MODULUS);
    u = Big::randomnum(&p, rng);

    let mut su = rng.getbyte() as isize;
    su %= 2;

    let W = emap(&u, su);
    P.sub(&W);
    let sv = P.gets();
    let rn = unmap(&mut v, &mut P);
    let mut m = rng.getbyte() as isize;
    m %= rn;
    v.inc(m + 1);
    e[0] = (su + 2 * sv) as u8;
    u.to_bytes(&mut t);
    for i in 0..EFS {
        e[i + 1] = t[i]
    }
    v.to_bytes(&mut t);
    for i in 0..EFS {
        e[i + EFS + 1] = t[i]
    }

    return 0;
}

#[allow(non_snake_case)]
pub fn decoding(d: &mut [u8]) -> isize {
    let mut t: [u8; EFS] = [0; EFS];

    if (d[0] & 0x04) != 0 {
        return INVALID_POINT;
    }

    for i in 0..EFS {
        t[i] = d[i + 1]
    }
    let mut u = Big::from_bytes(&t);
    for i in 0..EFS {
        t[i] = d[i + EFS + 1]
    }
    let mut v = Big::from_bytes(&t);

    let su = (d[0] & 1) as isize;
    let sv = ((d[0] >> 1) & 1) as isize;
    let W = emap(&u, su);
    let mut P = emap(&v, sv);
    P.add(&W);
    u = P.getx();
    v = P.gety();
    d[0] = 0x04;
    u.to_bytes(&mut t);
    for i in 0..EFS {
        d[i + 1] = t[i]
    }
    v.to_bytes(&mut t);
    for i in 0..EFS {
        d[i + EFS + 1] = t[i]
    }

    return 0;
}

/// R=R1+R2 in group G1
#[allow(non_snake_case)]
pub fn recombine_g1(r1: &[u8], r2: &[u8], r: &mut [u8]) -> isize {
    let mut P = ECP::from_bytes(&r1);
    let Q = ECP::from_bytes(&r2);

    if P.is_infinity() || Q.is_infinity() {
        return INVALID_POINT;
    }

    P.add(&Q);

    P.to_bytes(r, false);
    return 0;
}

/// W=W1+W2 in group G2
#[allow(non_snake_case)]
pub fn recombine_g2(w1: &[u8], w2: &[u8], w: &mut [u8]) -> isize {
    let mut P = ECP2::from_bytes(&w1);
    let Q = ECP2::from_bytes(&w2);

    if P.is_infinity() || Q.is_infinity() {
        return INVALID_POINT;
    }

    P.add(&Q);

    P.to_bytes(w);
    return 0;
}

/// create random secret S
pub fn random_generate(rng: &mut RAND, s: &mut [u8]) -> isize {
    let r = Big::new_ints(&rom::CURVE_ORDER);
    let sc = Big::randomnum(&r, rng);
    sc.to_bytes(s);
    return 0;
}

/// Extract Server Secret SST=S*Q where Q is fixed generator in G2 and S is master secret
#[allow(non_snake_case)]
pub fn get_server_secret(s: &[u8], sst: &mut [u8]) -> isize {
    let mut Q = ECP2::generator();

    let sc = Big::from_bytes(s);
    Q = pair::g2mul(&Q, &sc);
    Q.to_bytes(sst);
    return 0;
}

/// W=x*H(G);
/// if RNG == NULL then X is passed in
/// if RNG != NULL the X is passed out
/// if type=0 W=x*G where G is point on the curve, else W=x*M(G), where M(G) is mapping of octet G to point on the curve
#[allow(non_snake_case)]
pub fn get_g1_multiple(
    rng: Option<&mut RAND>,
    typ: usize,
    x: &mut [u8],
    g: &[u8],
    w: &mut [u8],
) -> isize {
    let mut sx: Big;
    let r = Big::new_ints(&rom::CURVE_ORDER);

    if let Some(rd) = rng {
        sx = Big::randomnum(&r, rd);
        sx.to_bytes(x);
    } else {
        sx = Big::from_bytes(x);
    }
    let P: ECP;

    if typ == 0 {
        P = ECP::from_bytes(g);
        if P.is_infinity() {
            return INVALID_POINT;
        }
    } else {
        P = ECP::mapit(g)
    }

    pair::g1mul(&P, &mut sx).to_bytes(w, false);
    return 0;
}

/// Client secret CST=S*H(CID) where CID is client ID and S is master secret
/// CID is hashed externally
pub fn get_client_secret(s: &mut [u8], cid: &[u8], cst: &mut [u8]) -> isize {
    return get_g1_multiple(None, 1, s, cid, cst);
}

/// Extract PIN from TOKEN for identity CID
#[allow(non_snake_case)]
pub fn extract_pin(sha: usize, cid: &[u8], pin: i32, token: &mut [u8]) -> isize {
    return extract_factor(sha, cid, pin % MAXPIN, PBLEN, token);
}

/// Extract factor from TOKEN for identity CID
#[allow(non_snake_case)]
pub fn extract_factor(
    sha: usize,
    cid: &[u8],
    factor: i32,
    facbits: i32,
    token: &mut [u8],
) -> isize {
    let mut P = ECP::from_bytes(&token);
    const RM: usize = big::MODBYTES as usize;
    let mut h: [u8; RM] = [0; RM];
    if P.is_infinity() {
        return INVALID_POINT;
    }
    hashit(sha, 0, cid, &mut h);
    let mut R = ECP::mapit(&h);

    R = R.pinmul(factor, facbits);
    P.sub(&R);

    P.to_bytes(token, false);

    return 0;
}

/// Restore factor to TOKEN for identity CID
#[allow(non_snake_case)]
pub fn restore_factor(
    sha: usize,
    cid: &[u8],
    factor: i32,
    facbits: i32,
    token: &mut [u8],
) -> isize {
    let mut P = ECP::from_bytes(&token);
    const RM: usize = big::MODBYTES as usize;
    let mut h: [u8; RM] = [0; RM];
    if P.is_infinity() {
        return INVALID_POINT;
    }
    hashit(sha, 0, cid, &mut h);
    let mut R = ECP::mapit(&h);

    R = R.pinmul(factor, facbits);
    P.add(&R);

    P.to_bytes(token, false);

    return 0;
}

/// Functions to support M-Pin Full
#[allow(non_snake_case)]
pub fn precompute(token: &[u8], cid: &[u8], g1: &mut [u8], g2: &mut [u8]) -> isize {
    let T = ECP::from_bytes(&token);
    if T.is_infinity() {
        return INVALID_POINT;
    }

    let P = ECP::mapit(&cid);

    let Q = ECP2::generator();

    let mut g = pair::ate(&Q, &T);
    g = pair::fexp(&g);
    g.to_bytes(g1);

    g = pair::ate(&Q, &P);
    g = pair::fexp(&g);
    g.to_bytes(g2);

    return 0;
}

/// Time Permit CTT=S*(date|H(CID)) where S is master secret
#[allow(non_snake_case)]
pub fn get_client_permit(sha: usize, date: usize, s: &[u8], cid: &[u8], ctt: &mut [u8]) -> isize {
    const RM: usize = big::MODBYTES as usize;
    let mut h: [u8; RM] = [0; RM];
    hashit(sha, date, cid, &mut h);
    let P = ECP::mapit(&h);

    let mut sc = Big::from_bytes(s);
    pair::g1mul(&P, &mut sc).to_bytes(ctt, false);
    return 0;
}

/// Implement step 1 on client side of MPin protocol
#[allow(non_snake_case)]
pub fn client_1(
    sha: usize,
    date: usize,
    client_id: &[u8],
    rng: Option<&mut RAND>,
    x: &mut [u8],
    pin: usize,
    token: &[u8],
    sec: &mut [u8],
    xid: Option<&mut [u8]>,
    xcid: Option<&mut [u8]>,
    permit: Option<&[u8]>,
) -> isize {
    let r = Big::new_ints(&rom::CURVE_ORDER);

    let mut sx: Big;

    if let Some(rd) = rng {
        sx = Big::randomnum(&r, rd);
        sx.to_bytes(x);
    } else {
        sx = Big::from_bytes(x);
    }

    const RM: usize = big::MODBYTES as usize;
    let mut h: [u8; RM] = [0; RM];

    hashit(sha, 0, &client_id, &mut h);
    let mut P = ECP::mapit(&h);

    let mut T = ECP::from_bytes(&token);
    if T.is_infinity() {
        return INVALID_POINT;
    }

    let mut W = P.pinmul((pin as i32) % MAXPIN, PBLEN);
    T.add(&W);
    if date != 0 {
        if let Some(rpermit) = permit {
            W = ECP::from_bytes(&rpermit);
        }
        if W.is_infinity() {
            return INVALID_POINT;
        }
        T.add(&W);
        let mut h2: [u8; RM] = [0; RM];
        hashit(sha, date, &h, &mut h2);
        W = ECP::mapit(&h2);
        if let Some(mut rxid) = xid {
            P = pair::g1mul(&P, &mut sx);
            P.to_bytes(&mut rxid, false);
            W = pair::g1mul(&W, &mut sx);
            P.add(&W);
        } else {
            P.add(&W);
            P = pair::g1mul(&P, &mut sx);
        }
        if let Some(mut rxcid) = xcid {
            P.to_bytes(&mut rxcid, false)
        }
    } else {
        if let Some(mut rxid) = xid {
            P = pair::g1mul(&P, &mut sx);
            P.to_bytes(&mut rxid, false);
        }
    }

    T.to_bytes(sec, false);
    return 0;
}

/// Outputs H(CID) and H(T|H(CID)) for time permits. If no time permits set HID=HTID
#[allow(non_snake_case)]
pub fn server_1(sha: usize, date: usize, cid: &[u8], hid: &mut [u8], htid: Option<&mut [u8]>) {
    const RM: usize = big::MODBYTES as usize;
    let mut h: [u8; RM] = [0; RM];

    hashit(sha, 0, cid, &mut h);

    let mut P = ECP::mapit(&h);

    P.to_bytes(hid, false);
    if date != 0 {
        let mut h2: [u8; RM] = [0; RM];
        hashit(sha, date, &h, &mut h2);
        let R = ECP::mapit(&h2);
        P.add(&R);
        if let Some(rhtid) = htid {
            P.to_bytes(rhtid, false);
        }
    }
}

/// Implement step 2 on client side of MPin protocol
#[allow(non_snake_case)]
pub fn client_2(x: &[u8], y: &[u8], sec: &mut [u8]) -> isize {
    let r = Big::new_ints(&rom::CURVE_ORDER);
    let mut P = ECP::from_bytes(sec);
    if P.is_infinity() {
        return INVALID_POINT;
    }

    let mut px = Big::from_bytes(x);
    let py = Big::from_bytes(y);
    px.add(&py);
    px.rmod(&r);

    P = pair::g1mul(&P, &mut px);
    P.neg();
    P.to_bytes(sec, false);

    return 0;
}

/// return time since epoch
pub fn get_time() -> usize {
    return (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()) as usize;
}

/// Generate Y = H(epoch, xCID/xID)
pub fn get_y(sha: usize, timevalue: usize, xcid: &[u8], y: &mut [u8]) {
    const RM: usize = big::MODBYTES as usize;
    let mut h: [u8; RM] = [0; RM];

    hashit(sha, timevalue, xcid, &mut h);

    let mut sy = Big::from_bytes(&h);
    let q = Big::new_ints(&rom::CURVE_ORDER);
    sy.rmod(&q);
    sy.to_bytes(y);
}

/// Implement step 2 of MPin protocol on server side
#[allow(non_snake_case)]
pub fn server_2(
    date: usize,
    hid: &[u8],
    htid: Option<&[u8]>,
    y: &[u8],
    sst: &[u8],
    xid: Option<&[u8]>,
    xcid: Option<&[u8]>,
    msec: &[u8],
    e: Option<&mut [u8]>,
    f: Option<&mut [u8]>,
) -> isize {
    let Q = ECP2::generator();

    let sQ = ECP2::from_bytes(&sst);
    if sQ.is_infinity() {
        return INVALID_POINT;
    }

    let mut R: ECP;
    if date != 0 {
        if let Some(rxcid) = xcid {
            R = ECP::from_bytes(&rxcid);
        } else {
            return BAD_PARAMS;
        }
    } else {
        if let Some(rxid) = xid {
            R = ECP::from_bytes(&rxid)
        } else {
            return BAD_PARAMS;
        }
    }
    if R.is_infinity() {
        return INVALID_POINT;
    }

    let mut sy = Big::from_bytes(&y);
    let mut P: ECP;
    if date != 0 {
        if let Some(rhtid) = htid {
            P = ECP::from_bytes(&rhtid)
        } else {
            return BAD_PARAMS;
        }
    } else {
        P = ECP::from_bytes(&hid);
    }

    if P.is_infinity() {
        return INVALID_POINT;
    }

    P = pair::g1mul(&P, &mut sy);
    P.add(&R);
    R = ECP::from_bytes(&msec);
    if R.is_infinity() {
        return INVALID_POINT;
    }

    let mut g: FP12;

    g = pair::ate2(&Q, &R, &sQ, &P);
    g = pair::fexp(&g);

    if !g.is_unity() {
        if let Some(rxid) = xid {
            if let Some(re) = e {
                if let Some(rf) = f {
                    g.to_bytes(re);
                    if date != 0 {
                        P = ECP::from_bytes(&hid);
                        if P.is_infinity() {
                            return INVALID_POINT;
                        }
                        R = ECP::from_bytes(&rxid);
                        if R.is_infinity() {
                            return INVALID_POINT;
                        }
                        P = pair::g1mul(&P, &mut sy);
                        P.add(&R); //P.affine();
                    }
                    g = pair::ate(&Q, &P);
                    g = pair::fexp(&g);
                    g.to_bytes(rf);
                }
            }
        }

        return BAD_PIN;
    }

    return 0;
}

/// Pollards kangaroos used to return PIN error
pub fn kangaroo(e: &[u8], f: &[u8]) -> isize {
    let mut ge = FP12::from_bytes(e);
    let mut gf = FP12::from_bytes(f);
    let mut distance: [isize; TS] = [0; TS];
    let mut t = gf.clone();

    let mut table: Vec<FP12> = Vec::with_capacity(TS);
    let mut s: isize = 1;
    for m in 0..TS {
        distance[m] = s;
        table.push(t.clone());
        s *= 2;
        t.usqr();
    }
    t.one();
    let mut dn: isize = 0;
    let mut i: usize;
    for _ in 0..TRAP {
        i = (t.geta().geta().geta().lastbits(20) % (TS as isize)) as usize;
        t.mul(&table[i]);
        dn += distance[i];
    }
    gf = t.clone();
    gf.conj();
    let mut steps: usize = 0;
    let mut dm: isize = 0;
    let mut res: isize = 0;
    while dm - dn < MAXPIN as isize {
        steps += 1;
        if steps > 4 * TRAP {
            break;
        }
        i = (ge.geta().geta().geta().lastbits(20) % (TS as isize)) as usize;
        ge.mul(&table[i]);
        dm += distance[i];
        if ge.equals(&t) {
            res = dm - dn;
            break;
        }
        if ge.equals(&gf) {
            res = dn - dm;
            break;
        }
    }
    if steps > 4 * TRAP || dm - dn >= MAXPIN as isize {
        res = 0
    } // Trap Failed  - probable invalid token
    return res;
}

/// Hash the M-Pin transcript - new
pub fn hash_all(
    sha: usize,
    hid: &[u8],
    xid: &[u8],
    xcid: Option<&[u8]>,
    sec: &[u8],
    y: &[u8],
    r: &[u8],
    w: &[u8],
    h: &mut [u8],
) -> bool {
    let mut tlen: usize = 0;
    const RM: usize = big::MODBYTES as usize;
    let mut t: [u8; 10 * RM + 4] = [0; 10 * RM + 4];

    for i in 0..hid.len() {
        t[i] = hid[i]
    }
    tlen += hid.len();

    if let Some(rxcid) = xcid {
        for i in 0..rxcid.len() {
            t[i + tlen] = rxcid[i]
        }
        tlen += rxcid.len();
    } else {
        for i in 0..xid.len() {
            t[i + tlen] = xid[i]
        }
        tlen += xid.len();
    }

    for i in 0..sec.len() {
        t[i + tlen] = sec[i]
    }
    tlen += sec.len();
    for i in 0..y.len() {
        t[i + tlen] = y[i]
    }
    tlen += y.len();
    for i in 0..r.len() {
        t[i + tlen] = r[i]
    }
    tlen += r.len();
    for i in 0..w.len() {
        t[i + tlen] = w[i]
    }
    tlen += w.len();
    if tlen != 10 * RM + 4 {
        return false;
    }

    return hashit(sha, 0, &t, h);
}

/// Calculate common key on client side
/// wCID = w.(A+AT)
#[allow(non_snake_case)]
pub fn client_key(
    sha: usize,
    g1: &[u8],
    g2: &[u8],
    pin: usize,
    r: &[u8],
    x: &[u8],
    h: &[u8],
    wcid: &[u8],
    ck: &mut [u8],
) -> isize {
    let mut g1 = FP12::from_bytes(&g1);
    let mut g2 = FP12::from_bytes(&g2);
    let mut z = Big::from_bytes(&r);
    let mut x = Big::from_bytes(&x);
    let h = Big::from_bytes(&h);

    let mut W = ECP::from_bytes(&wcid);
    if W.is_infinity() {
        return INVALID_POINT;
    }

    W = pair::g1mul(&W, &mut x);

    let r = Big::new_ints(&rom::CURVE_ORDER);

    z.add(&h); //new
    z.rmod(&r);

    g2.pinpow(pin as i32, PBLEN);
    g1.mul(&g2);

    let mut c = g1.compow(&z, &r);

    hash(sha, &mut c, &mut W, ck);

    return 0;
}

/// calculate common key on server side
/// Z=r.A - no time permits involved
#[allow(non_snake_case)]
pub fn server_key(
    sha: usize,
    z: &[u8],
    sst: &[u8],
    w: &[u8],
    h: &[u8],
    hid: &[u8],
    xid: &[u8],
    xcid: Option<&[u8]>,
    sk: &mut [u8],
) -> isize {
    let sQ = ECP2::from_bytes(&sst);
    if sQ.is_infinity() {
        return INVALID_POINT;
    }
    let mut R = ECP::from_bytes(&z);
    if R.is_infinity() {
        return INVALID_POINT;
    }
    let mut A = ECP::from_bytes(&hid);
    if A.is_infinity() {
        return INVALID_POINT;
    }

    let mut U = if let Some(rxcid) = xcid {
        ECP::from_bytes(&rxcid)
    } else {
        ECP::from_bytes(&xid)
    };

    if U.is_infinity() {
        return INVALID_POINT;
    }

    let mut w = Big::from_bytes(&w);
    let mut h = Big::from_bytes(&h);
    A = pair::g1mul(&A, &mut h); // new
    R.add(&A);

    U = pair::g1mul(&U, &mut w);
    let mut g = pair::ate(&sQ, &R);
    g = pair::fexp(&g);

    let mut c = g.trace();

    hash(sha, &mut c, &mut U, sk);

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_mpin_valid() {
        let mut rng = create_rng();

        pub const PERMITS: bool = true;
        pub const PINERROR: bool = true;
        pub const FULL: bool = true;

        let mut s: [u8; EGS] = [0; EGS];
        const RM: usize = EFS as usize;
        let mut hcid: [u8; RM] = [0; RM];
        let mut hsid: [u8; RM] = [0; RM];

        const G1S: usize = 2 * EFS + 1; // Group 1 Size
        const G2S: usize = 4 * EFS; // Group 2 Size
        const EAS: usize = ecp::AESKEY;

        let mut sst: [u8; G2S] = [0; G2S];
        let mut token: [u8; G1S] = [0; G1S];
        let mut permit: [u8; G1S] = [0; G1S];
        let mut g1: [u8; 12 * EFS] = [0; 12 * EFS];
        let mut g2: [u8; 12 * EFS] = [0; 12 * EFS];
        let mut xid: [u8; G1S] = [0; G1S];
        let mut xcid: [u8; G1S] = [0; G1S];
        let mut x: [u8; EGS] = [0; EGS];
        let mut y: [u8; EGS] = [0; EGS];
        let mut sec: [u8; G1S] = [0; G1S];
        let mut r: [u8; EGS] = [0; EGS];
        let mut z: [u8; G1S] = [0; G1S];
        let mut hid: [u8; G1S] = [0; G1S];
        let mut htid: [u8; G1S] = [0; G1S];
        let mut rhid: [u8; G1S] = [0; G1S];
        let mut w: [u8; EGS] = [0; EGS];
        let mut t: [u8; G1S] = [0; G1S];
        let mut e: [u8; 12 * EFS] = [0; 12 * EFS];
        let mut f: [u8; 12 * EFS] = [0; 12 * EFS];
        let mut h: [u8; RM] = [0; RM];
        let mut ck: [u8; EAS] = [0; EAS];
        let mut sk: [u8; EAS] = [0; EAS];

        let sha = ecp::HASH_TYPE;

        println!("\nTesting MPIN - PIN is 1234");
        // Trusted Authority set-up

        random_generate(&mut rng, &mut s);
        print!("Master Secret s: 0x");
        printbinary(&s);

        // Create Client Identity
        let name = "testUser@miracl.com";
        let client_id = name.as_bytes();

        print!("Client ID= ");
        printbinary(&client_id);

        hash_id(sha, &client_id, &mut hcid); // Either Client or TA calculates Hash(ID) - you decide!

        // Client and Server are issued secrets by DTA
        get_server_secret(&s, &mut sst);
        print!("Server Secret SS: 0x");
        printbinary(&sst);

        get_client_secret(&mut s, &hcid, &mut token);
        print!("Client Secret CS: 0x");
        printbinary(&token);

        // Client extracts PIN from secret to create Token
        let pin: i32 = 1234;
        println!("Client extracts PIN= {}", pin);
        let mut rtn = extract_pin(sha, &client_id, pin, &mut token);
        if rtn != 0 {
            println!("FAILURE: EXTRACT_PIN rtn: {}", rtn);
        }

        print!("Client Token TK: 0x");
        printbinary(&token);

        if FULL {
            precompute(&token, &hcid, &mut g1, &mut g2);
        }

        let mut date = 0;
        if PERMITS {
            date = today();
            // Client gets "Time Token" permit from DTA

            get_client_permit(sha, date, &s, &hcid, &mut permit);
            print!("Time Permit TP: 0x");
            printbinary(&permit);

            // This encoding makes Time permit look random - Elligator squared
            encoding(&mut rng, &mut permit);
            print!("Encoded Time Permit TP: 0x");
            printbinary(&permit);
            decoding(&mut permit);
            print!("Decoded Time Permit TP: 0x");
            printbinary(&permit);
        }

        let pin = 1234;

        println!("MPIN Multi Pass");
        // Send U=x.ID to server, and recreate secret from token and pin
        rtn = client_1(
            sha,
            date,
            &client_id,
            Some(&mut rng),
            &mut x,
            pin,
            &token,
            &mut sec,
            Some(&mut xid[..]),
            Some(&mut xcid[..]),
            Some(&permit[..]),
        );
        if rtn != 0 {
            println!("FAILURE: CLIENT_1 rtn: {}", rtn);
        }

        if FULL {
            hash_id(sha, &client_id, &mut hcid);
            get_g1_multiple(Some(&mut rng), 1, &mut r, &hcid, &mut z); // Also Send Z=r.ID to Server, remember random r
        }

        // Server calculates H(ID) and H(T|H(ID)) (if time PERMITS enabled), and maps them to points on the curve HID and HTID resp.

        server_1(sha, date, &client_id, &mut hid, Some(&mut htid[..]));

        if date != 0 {
            rhid.clone_from_slice(&htid[..]);
        } else {
            rhid.clone_from_slice(&hid[..]);
        }

        // Server generates Random number Y and sends it to Client
        random_generate(&mut rng, &mut y);

        if FULL {
            hash_id(sha, &client_id, &mut hsid);
            get_g1_multiple(Some(&mut rng), 0, &mut w, &rhid, &mut t); // Also send T=w.ID to client, remember random w
        }

        // Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC
        rtn = client_2(&x, &y, &mut sec);
        if rtn != 0 {
            println!("FAILURE: CLIENT_2 rtn: {}", rtn);
        }

        // Server Second pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help kangaroos to find error.
        // If PIN error not required, set E and F = null

        if !PINERROR {
            rtn = server_2(
                date,
                &hid,
                Some(&htid[..]),
                &y,
                &sst,
                Some(&xid[..]),
                Some(&xcid[..]),
                &sec,
                None,
                None,
            );
        } else {
            rtn = server_2(
                date,
                &hid,
                Some(&htid[..]),
                &y,
                &sst,
                Some(&xid[..]),
                Some(&xcid[..]),
                &sec,
                Some(&mut e),
                Some(&mut f),
            );
        }

        if rtn == BAD_PIN {
            println!("Server says - Bad Pin. I don't know you. Feck off.");
            if PINERROR {
                let err = kangaroo(&e, &f);
                if err != 0 {
                    println!("(Client PIN is out by {})", err)
                }
            }
            return;
        } else {
            println!("Server says - PIN is good! You really are {}", name);
        }

        if FULL {
            let mut pxcid = None;
            if PERMITS {
                pxcid = Some(&xcid[..])
            };

            hash_all(sha, &hcid, &xid, pxcid, &sec, &y, &z, &t, &mut h);
            client_key(sha, &g1, &g2, pin, &r, &x, &h, &t, &mut ck);
            print!("Client Key =  0x");
            printbinary(&ck);

            hash_all(sha, &hsid, &xid, pxcid, &sec, &y, &z, &t, &mut h);
            server_key(sha, &z, &sst, &w, &h, &hid, &xid, pxcid, &mut sk);
            print!("Server Key =  0x");
            printbinary(&sk);
        }
    }
}
