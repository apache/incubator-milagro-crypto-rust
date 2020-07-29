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
use super::ecp::ECP;
use super::rom;

use crate::aes;
use crate::aes::AES;
use crate::hash256::HASH256;
use crate::hash384::HASH384;
use crate::hash512::HASH512;
use crate::rand::RAND;

pub const INVALID_PUBLIC_KEY: isize = -2;
pub const ERROR: isize = -3;
pub const INVALID: isize = -4;
pub const EFS: usize = big::MODBYTES as usize;
pub const EGS: usize = big::MODBYTES as usize;
pub const SHA256: usize = 32;
pub const SHA384: usize = 48;
pub const SHA512: usize = 64;

#[allow(non_snake_case)]

fn intto_bytes(n: usize, b: &mut [u8]) {
    let mut i = b.len();
    let mut m = n;
    while m > 0 && i > 0 {
        i -= 1;
        b[i] = (m & 0xff) as u8;
        m /= 256;
    }
}

/// Hash to curve function using Hash and Test on SHA256, 384 or 512
fn hashit(sha: usize, a: &[u8], n: usize, b: Option<&[u8]>, pad: usize, w: &mut [u8]) {
    let mut r: [u8; 64] = [0; 64];
    if sha == SHA256 {
        let mut h = HASH256::new();
        h.process_array(a);
        if n > 0 {
            h.process_num(n as i32)
        }
        if let Some(x) = b {
            h.process_array(x);
        }
        let hs = h.hash();
        for i in 0..sha {
            r[i] = hs[i];
        }
    }
    if sha == SHA384 {
        let mut h = HASH384::new();
        h.process_array(a);
        if n > 0 {
            h.process_num(n as i32)
        }
        if let Some(x) = b {
            h.process_array(x);
        }
        let hs = h.hash();
        for i in 0..sha {
            r[i] = hs[i];
        }
    }
    if sha == SHA512 {
        let mut h = HASH512::new();
        h.process_array(a);
        if n > 0 {
            h.process_num(n as i32)
        }
        if let Some(x) = b {
            h.process_array(x);
        }
        let hs = h.hash();
        for i in 0..sha {
            r[i] = hs[i];
        }
    }

    if pad == 0 {
        for i in 0..sha {
            w[i] = r[i]
        }
    } else {
        if pad <= sha {
            for i in 0..pad {
                w[i] = r[i]
            }
        } else {
            for i in 0..sha {
                w[i + pad - sha] = r[i]
            }
            for i in 0..(pad - sha) {
                w[i] = 0
            }
        }
    }
}

// Key Derivation Function 1
// Input octet Z
// Output key of length olen
pub fn kdf1(sha: usize, z: &[u8], olen: usize, k: &mut [u8]) {
    // NOTE: the parameter olen is the length of the output K in bytes
    let hlen = sha;
    let mut lk = 0;

    let mut cthreshold = olen / hlen;
    if olen % hlen != 0 {
        cthreshold += 1
    }

    for counter in 0..cthreshold {
        let mut b: [u8; 64] = [0; 64];
        hashit(sha, z, counter, None, 0, &mut b);
        if lk + hlen > olen {
            for i in 0..(olen % hlen) {
                k[lk] = b[i];
                lk += 1
            }
        } else {
            for i in 0..hlen {
                k[lk] = b[i];
                lk += 1
            }
        }
    }
}

// Key Derivation Function 2
// Input octet Z
// Output key of length olen
pub fn kdf2(sha: usize, z: &[u8], p: Option<&[u8]>, olen: usize, k: &mut [u8]) {
    // NOTE: the parameter olen is the length of the output K in bytes
    let hlen = sha;
    let mut lk = 0;

    let mut cthreshold = olen / hlen;
    if olen % hlen != 0 {
        cthreshold += 1
    }

    for counter in 1..=cthreshold {
        let mut b: [u8; 64] = [0; 64];
        hashit(sha, z, counter, p, 0, &mut b);
        if lk + hlen > olen {
            for i in 0..(olen % hlen) {
                k[lk] = b[i];
                lk += 1
            }
        } else {
            for i in 0..hlen {
                k[lk] = b[i];
                lk += 1
            }
        }
    }
}

/// Password based Key Derivation Function
/// Input password p, salt s, and repeat count
/// Output key of length olen
pub fn pbkdf2(sha: usize, pass: &[u8], salt: &[u8], rep: usize, olen: usize, k: &mut [u8]) {
    let mut d = olen / sha;
    if olen % sha != 0 {
        d += 1
    }
    let mut f: [u8; 64] = [0; 64];
    let mut u: [u8; 64] = [0; 64];
    let mut ku: [u8; 64] = [0; 64];
    let mut s: [u8; 36] = [0; 36]; // Maximum salt of 32 bytes + 4
    let mut n: [u8; 4] = [0; 4];

    let sl = salt.len();
    let mut kp = 0;
    for i in 0..d {
        for j in 0..sl {
            s[j] = salt[j]
        }
        intto_bytes(i + 1, &mut n);
        for j in 0..4 {
            s[sl + j] = n[j]
        }

        hmac(sha, &s[0..sl + 4], pass, sha, &mut f);

        for j in 0..sha {
            u[j] = f[j]
        }
        for _ in 1..rep {
            hmac(sha, &u, pass, sha, &mut ku);
            for k in 0..sha {
                u[k] = ku[k];
                f[k] ^= u[k]
            }
        }
        for j in 0..EFS {
            if kp < olen && kp < f.len() {
                k[kp] = f[j]
            }
            kp += 1
        }
    }
}

/// Calculate HMAC of m using key k. HMAC is tag of length olen (which is length of tag)
pub fn hmac(sha: usize, m: &[u8], k: &[u8], olen: usize, tag: &mut [u8]) -> bool {
    // Input is from an octet m
    // olen is requested output length in bytes. k is the key
    // The output is the calculated tag
    let mut b: [u8; 64] = [0; 64]; // Not good
    let mut k0: [u8; 128] = [0; 128];

    if olen < 4 {
        return false;
    }

    let mut lb = 64;
    if sha > 32 {
        lb = 128
    }

    for i in 0..lb {
        k0[i] = 0
    }

    if k.len() > lb {
        hashit(sha, k, 0, None, 0, &mut b);
        for i in 0..sha {
            k0[i] = b[i]
        }
    } else {
        for i in 0..k.len() {
            k0[i] = k[i]
        }
    }

    for i in 0..lb {
        k0[i] ^= 0x36
    }
    hashit(sha, &k0[0..lb], 0, Some(m), 0, &mut b);

    for i in 0..lb {
        k0[i] ^= 0x6a
    }
    hashit(sha, &k0[0..lb], 0, Some(&b[0..sha]), olen, tag);

    return true;
}

/// AES encryption/decryption. Encrypt byte array m using key k and returns ciphertext c
pub fn cbc_iv0_encrypt(k: &[u8], m: &[u8]) -> Vec<u8> {
    // AES CBC encryption, with Null IV and key K
    // Input is from an octet string m, output is to an octet string c
    // Input is padded as necessary to make up a full final block
    let mut a = AES::new();
    let mut fin = false;
    let mut c: Vec<u8> = Vec::new();

    let mut buff: [u8; 16] = [0; 16];

    a.init(aes::CBC, k.len(), k, None);

    let mut ipt = 0;
    let mut i;
    loop {
        i = 0;
        while i < 16 {
            if ipt < m.len() {
                buff[i] = m[ipt];
                i += 1;
                ipt += 1;
            } else {
                fin = true;
                break;
            }
        }
        if fin {
            break;
        }
        a.encrypt(&mut buff);
        for j in 0..16 {
            c.push(buff[j]);
        }
    }

    // last block, filled up to i-th index

    let padlen = 16 - i;
    for j in i..16 {
        buff[j] = padlen as u8
    }

    a.encrypt(&mut buff);

    for j in 0..16 {
        c.push(buff[j]);
    }
    a.end();
    c
}

/// Returns plaintext if all consistent, else returns null string
pub fn cbc_iv0_decrypt(k: &[u8], c: &[u8]) -> Option<Vec<u8>> {
    // padding is removed
    let mut a = AES::new();
    let mut fin = false;
    let mut m: Vec<u8> = Vec::new();

    let mut buff: [u8; 16] = [0; 16];

    a.init(aes::CBC, k.len(), k, None);

    let mut ipt = 0;
    let mut i;

    if c.len() == 0 {
        return None;
    }
    let mut ch = c[ipt];
    ipt += 1;

    loop {
        i = 0;
        while i < 16 {
            buff[i] = ch;
            if ipt >= c.len() {
                fin = true;
                break;
            } else {
                ch = c[ipt];
                ipt += 1
            }
            i += 1;
        }
        a.decrypt(&mut buff);
        if fin {
            break;
        }
        for j in 0..16 {
            m.push(buff[j]);
        }
    }

    a.end();
    let mut bad = false;
    let padlen = buff[15] as usize;
    if i != 15 || padlen < 1 || padlen > 16 {
        bad = true
    }
    if padlen >= 2 && padlen <= 16 {
        for j in 16 - padlen..16 {
            if buff[j] != padlen as u8 {
                bad = true
            }
        }
    }

    if !bad {
        for i in 0..16 - padlen {
            m.push(buff[i]);
        }
    }

    if bad {
        return None;
    }
    Some(m)
}

/// Calculate a public/private EC GF(p) key pair w,s where W=s.G mod EC(p),
/// where s is the secret key and W is the public key
/// and G is fixed generator.
/// If RNG is NULL then the private key is provided externally in s
/// otherwise it is generated randomly internally
#[allow(non_snake_case)]
pub fn key_pair_generate(rng: Option<&mut RAND>, s: &mut [u8], w: &mut [u8]) -> isize {
    let res = 0;
    let mut sc: Big;
    let G = ECP::generator();

    let r = Big::new_ints(&rom::CURVE_ORDER);

    if let Some(mut x) = rng {
        sc = Big::randomnum(&r, &mut x);
    } else {
        sc = Big::from_bytes(&s);
        sc.rmod(&r);
    }

    sc.to_bytes(s);

    let WP = G.mul(&sc);

    WP.to_bytes(w, false); // To use point compression on public keys, change to true

    res
}

/// Validate public key
#[allow(non_snake_case)]
pub fn public_key_validate(w: &[u8]) -> isize {
    let mut WP = ECP::from_bytes(w);
    let mut res = 0;

    let r = Big::new_ints(&rom::CURVE_ORDER);

    if WP.is_infinity() {
        res = INVALID_PUBLIC_KEY
    }
    if res == 0 {
        let q = Big::new_ints(&rom::MODULUS);
        let nb = q.nbits();
        let mut k = Big::new();
        k.one();
        k.shl((nb + 4) / 2);
        k.add(&q);
        k.div(&r);

        while k.parity() == 0 {
            k.shr(1);
            WP.dbl();
        }

        if !k.is_unity() {
            WP = WP.mul(&k)
        }
        if WP.is_infinity() {
            res = INVALID_PUBLIC_KEY
        }
    }
    res
}

/// IEEE-1363 Diffie-Hellman online calculation Z=S.WD
#[allow(non_snake_case)]
pub fn ecpsvdp_dh(s: &[u8], wd: &[u8], z: &mut [u8]) -> isize {
    let mut res = 0;
    let mut t: [u8; EFS] = [0; EFS];

    let mut sc = Big::from_bytes(&s);

    let mut W = ECP::from_bytes(&wd);
    if W.is_infinity() {
        res = ERROR
    }

    if res == 0 {
        let r = Big::new_ints(&rom::CURVE_ORDER);
        sc.rmod(&r);
        W = W.mul(&sc);
        if W.is_infinity() {
            res = ERROR;
        } else {
            W.getx().to_bytes(&mut t);
            for i in 0..EFS {
                z[i] = t[i]
            }
        }
    }
    res
}

/// IEEE ECDSA Signature, C and D are signature on F using private key S
#[allow(non_snake_case)]
pub fn ecpsp_dsa(
    sha: usize,
    rng: &mut RAND,
    s: &[u8],
    f: &[u8],
    c: &mut [u8],
    d: &mut [u8],
) -> isize {
    let mut t: [u8; EFS] = [0; EFS];
    let mut b: [u8; big::MODBYTES as usize] = [0; big::MODBYTES as usize];

    hashit(sha, f, 0, None, big::MODBYTES as usize, &mut b);

    let G = ECP::generator();

    let r = Big::new_ints(&rom::CURVE_ORDER);

    let sc = Big::from_bytes(s); // s or &s?
    let fb = Big::from_bytes(&b);

    let mut cb = Big::new();
    let mut db = Big::new();

    while db.is_zilch() {
        let mut u = Big::randomnum(&r, rng);
        let w = Big::randomnum(&r, rng); // side channel masking

        let mut V = G.clone();
        V = V.mul(&u);
        let vx = V.getx();
        cb = vx.clone();
        cb.rmod(&r);
        if cb.is_zilch() {
            continue;
        }

        let mut tb = Big::modmul(&u, &w, &r);
        u = tb.clone();

        u.invmodp(&r);
        db = Big::modmul(&sc, &cb, &r);
        db.add(&fb);

        tb = Big::modmul(&db, &w, &r);
        db = tb.clone();

        tb = Big::modmul(&u, &db, &r);
        db = tb.clone();
    }

    cb.to_bytes(&mut t);
    for i in 0..EFS {
        c[i] = t[i]
    }
    db.to_bytes(&mut t);
    for i in 0..EFS {
        d[i] = t[i]
    }
    0
}

/// IEEE1363 ECDSA Signature Verification. Signature C and D on F is verified using public key W
#[allow(non_snake_case)]
pub fn ecpvp_dsa(sha: usize, w: &[u8], f: &[u8], c: &[u8], d: &[u8]) -> isize {
    let mut res = 0;

    let mut b: [u8; big::MODBYTES as usize] = [0; big::MODBYTES as usize];

    hashit(sha, f, 0, None, big::MODBYTES as usize, &mut b);

    let G = ECP::generator();
    let r = Big::new_ints(&rom::CURVE_ORDER);

    let cb = Big::from_bytes(c); // c or &c ?
    let mut db = Big::from_bytes(d); // d or &d ?

    if cb.is_zilch() || Big::comp(&cb, &r) >= 0 || db.is_zilch() || Big::comp(&db, &r) >= 0 {
        res = INVALID;
    }

    if res == 0 {
        let mut fb = Big::from_bytes(&b);
        db.invmodp(&r);
        let tb = Big::modmul(&fb, &db, &r);
        fb = tb.clone();
        let h2 = Big::modmul(&cb, &db, &r);

        let WP = ECP::from_bytes(&w);
        if WP.is_infinity() {
            res = ERROR;
        } else {
            let mut P = WP.clone();

            P = P.mul2(&h2, &G, &fb);

            if P.is_infinity() {
                res = INVALID;
            } else {
                db = P.getx();
                db.rmod(&r);

                if Big::comp(&db, &cb) != 0 {
                    res = INVALID
                }
            }
        }
    }

    res
}

/// IEEE1363 ECIES encryption. Encryption of plaintext M uses public key W and produces ciphertext V,C,T
#[allow(non_snake_case)]
pub fn ecies_encrypt(
    sha: usize,
    p1: &[u8],
    p2: &[u8],
    rng: &mut RAND,
    w: &[u8],
    m: &[u8],
    v: &mut [u8],
    t: &mut [u8],
) -> Option<Vec<u8>> {
    let mut z: [u8; EFS] = [0; EFS];
    let mut k1: [u8; ecp::AESKEY] = [0; ecp::AESKEY];
    let mut k2: [u8; ecp::AESKEY] = [0; ecp::AESKEY];
    let mut u: [u8; EGS] = [0; EGS];
    let mut vz: [u8; 3 * EFS + 1] = [0; 3 * EFS + 1];
    let mut k: [u8; 2 * ecp::AESKEY] = [0; 2 * ecp::AESKEY];

    if key_pair_generate(Some(rng), &mut u, v) != 0 {
        return None;
    }
    if ecpsvdp_dh(&u, &w, &mut z) != 0 {
        return None;
    }

    for i in 0..=2 * EFS {
        vz[i] = v[i]
    }
    for i in 0..EFS {
        vz[2 * EFS + 1 + i] = z[i]
    }

    kdf2(sha, &vz, Some(p1), 2 * ecp::AESKEY, &mut k);

    for i in 0..ecp::AESKEY {
        k1[i] = k[i];
        k2[i] = k[ecp::AESKEY + i]
    }

    let mut c = cbc_iv0_encrypt(&k1, m);

    let mut l2: [u8; 8] = [0; 8];
    let p2l = p2.len();

    intto_bytes(p2l, &mut l2);

    for i in 0..p2l {
        c.push(p2[i]);
    }
    for i in 0..8 {
        c.push(l2[i]);
    }

    hmac(sha, &c, &k2, t.len(), t);

    for _ in 0..p2l + 8 {
        c.pop();
    }

    Some(c)
}

/// constant time n-byte compare
fn ncomp(t1: &[u8], t2: &[u8], n: usize) -> bool {
    let mut res = 0;
    for i in 0..n {
        res |= (t1[i] ^ t2[i]) as isize;
    }
    if res == 0 {
        return true;
    }
    false
}

/// IEEE1363 ECIES decryption. Decryption of ciphertext V,C,T using private key U outputs plaintext M
#[allow(non_snake_case)]
pub fn ecies_decrypt(
    sha: usize,
    p1: &[u8],
    p2: &[u8],
    v: &[u8],
    c: &mut Vec<u8>,
    t: &[u8],
    u: &[u8],
) -> Option<Vec<u8>> {
    let mut z: [u8; EFS] = [0; EFS];
    let mut k1: [u8; ecp::AESKEY] = [0; ecp::AESKEY];
    let mut k2: [u8; ecp::AESKEY] = [0; ecp::AESKEY];
    let mut vz: [u8; 3 * EFS + 1] = [0; 3 * EFS + 1];
    let mut k: [u8; 2 * ecp::AESKEY] = [0; 2 * ecp::AESKEY];

    let mut tag: [u8; 32] = [0; 32]; /* 32 is max length of tag */

    for i in 0..t.len() {
        tag[i] = t[i]
    }

    if ecpsvdp_dh(&u, &v, &mut z) != 0 {
        return None;
    }

    for i in 0..2 * EFS + 1 {
        vz[i] = v[i]
    }
    for i in 0..EFS {
        vz[2 * EFS + 1 + i] = z[i]
    }

    kdf2(sha, &vz, Some(p1), 2 * ecp::AESKEY, &mut k);

    for i in 0..ecp::AESKEY {
        k1[i] = k[i];
        k2[i] = k[ecp::AESKEY + i]
    }

    let m = cbc_iv0_decrypt(&k1, &c);

    if m == None {
        return None;
    }

    let mut l2: [u8; 8] = [0; 8];
    let p2l = p2.len();

    intto_bytes(p2l, &mut l2);

    for i in 0..p2l {
        c.push(p2[i]);
    }
    for i in 0..8 {
        c.push(l2[i]);
    }

    hmac(sha, &c, &k2, t.len(), &mut tag);

    for _ in 0..p2l + 8 {
        c.pop();
    }

    if !ncomp(&t, &tag, t.len()) {
        return None;
    }

    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::types::CurveType;

    #[test]
    fn test_ecdh() {
        let mut rng = create_rng();

        let pw = "M0ng00se";
        let pp: &[u8] = b"M0ng00se";
        const EAS: usize = ecp::AESKEY;

        let sha = ecp::HASH_TYPE;
        let mut salt: [u8; 8] = [0; 8];
        let mut s1: [u8; EGS] = [0; EGS];
        let mut w0: [u8; 2 * EFS + 1] = [0; 2 * EFS + 1];
        let mut w1: [u8; 2 * EFS + 1] = [0; 2 * EFS + 1];
        let mut z0: [u8; EFS] = [0; EFS];
        let mut z1: [u8; EFS] = [0; EFS];
        let mut key: [u8; EAS] = [0; EAS];
        let mut cs: [u8; EGS] = [0; EGS];
        let mut ds: [u8; EGS] = [0; EGS];
        let mut m: Vec<u8> = vec![0; 32]; // array that could be of any length. So use heap.
        let mut p1: [u8; 3] = [0; 3];
        let mut p2: [u8; 4] = [0; 4];
        let mut v: [u8; 2 * EFS + 1] = [0; 2 * EFS + 1];
        let mut t: [u8; 12] = [0; 12];

        for i in 0..8 {
            salt[i] = (i + 1) as u8
        } // set Salt

        println!("\nTesting ECDH/ECDSA/ECIES");
        println!("Alice's Passphrase= {}", pw);

        let mut s0: [u8; EFS] = [0; EGS];
        pbkdf2(sha, pp, &salt, 1000, EGS, &mut s0);

        print!("Alice's private key= 0x");
        printbinary(&s0);

        /* Generate Key pair S/W */
        key_pair_generate(None, &mut s0, &mut w0);

        print!("Alice's public key= 0x");
        printbinary(&w0);

        let mut res = public_key_validate(&w0);
        if res != 0 {
            println!("ECP Public Key is invalid!");
            return;
        }

        /* Random private key for other party */
        key_pair_generate(Some(&mut rng), &mut s1, &mut w1);

        print!("Servers private key= 0x");
        printbinary(&s1);

        print!("Servers public key= 0x");
        printbinary(&w1);

        res = public_key_validate(&w1);
        if res != 0 {
            println!("ECP Public Key is invalid!");
            return;
        }
        /* Calculate common key using DH - IEEE 1363 method */

        ecpsvdp_dh(&s0, &w1, &mut z0);
        ecpsvdp_dh(&s1, &w0, &mut z1);

        let mut same = true;
        for i in 0..EFS {
            if z0[i] != z1[i] {
                same = false
            }
        }

        if !same {
            println!("*** ECPSVDP-DH Failed");
            return;
        }

        kdf2(sha, &z0, None, EAS, &mut key);

        print!("Alice's DH Key=  0x");
        printbinary(&key);
        print!("Servers DH Key=  0x");
        printbinary(&key);

        if ecp::CURVETYPE != CurveType::Montgomery {
            for i in 0..17 {
                m[i] = i as u8
            }

            println!("Testing ECIES");

            p1[0] = 0x0;
            p1[1] = 0x1;
            p1[2] = 0x2;
            p2[0] = 0x0;
            p2[1] = 0x1;
            p2[2] = 0x2;
            p2[3] = 0x3;

            let cc = ecies_encrypt(sha, &p1, &p2, &mut rng, &w1, &m[0..17], &mut v, &mut t);

            if let Some(mut c) = cc {
                println!("Ciphertext= ");
                print!("V= 0x");
                printbinary(&v);
                print!("C= 0x");
                printbinary(&c);
                print!("T= 0x");
                printbinary(&t);

                let mm = ecies_decrypt(sha, &p1, &p2, &v, &mut c, &t, &s1);
                if let Some(rm) = mm {
                    println!("Decryption succeeded");
                    print!("Message is 0x");
                    printbinary(&rm);
                } else {
                    println!("*** ECIES Decryption Failed");
                    return;
                }
            } else {
                println!("*** ECIES Encryption Failed");
                return;
            }

            println!("Testing ECDSA");

            if ecpsp_dsa(sha, &mut rng, &s0, &m[0..17], &mut cs, &mut ds) != 0 {
                println!("***ECDSA Signature Failed");
                return;
            }
            println!("Signature= ");
            print!("C= 0x");
            printbinary(&cs);
            print!("D= 0x");
            printbinary(&ds);

            if ecpvp_dsa(sha, &w0, &m[0..17], &cs, &ds) != 0 {
                println!("***ECDSA Verification Failed");
                return;
            } else {
                println!("ECDSA Signature/Verification succeeded ")
            }
        }
    }
}
