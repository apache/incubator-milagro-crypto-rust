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

const HASH512_H0: u64 = 0x6a09e667f3bcc908;
const HASH512_H1: u64 = 0xbb67ae8584caa73b;
const HASH512_H2: u64 = 0x3c6ef372fe94f82b;
const HASH512_H3: u64 = 0xa54ff53a5f1d36f1;
const HASH512_H4: u64 = 0x510e527fade682d1;
const HASH512_H5: u64 = 0x9b05688c2b3e6c1f;
const HASH512_H6: u64 = 0x1f83d9abfb41bd6b;
const HASH512_H7: u64 = 0x5be0cd19137e2179;

const HASH512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// The block size of each round.
pub const BLOCK_SIZE: usize = 128;
/// Hash Length in Bytes
pub const HASH_BYTES: usize = 64;
// Ipad Byte
const IPAD_BYTE: u8 = 0x36;
// Opad Byte
const OPAD_BYTE: u8 = 0x5c;

pub struct HASH512 {
    length: [u64; 2],
    h: [u64; 8],
    w: [u64; 80],
}

impl HASH512 {
    fn s(n: u64, x: u64) -> u64 {
        return ((x) >> n) | ((x) << (64 - n));
    }
    fn r(n: u64, x: u64) -> u64 {
        return (x) >> n;
    }

    fn ch(x: u64, y: u64, z: u64) -> u64 {
        return (x & y) ^ (!(x) & z);
    }

    fn maj(x: u64, y: u64, z: u64) -> u64 {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    fn sig0(x: u64) -> u64 {
        return Self::s(28, x) ^ Self::s(34, x) ^ Self::s(39, x);
    }

    fn sig1(x: u64) -> u64 {
        return Self::s(14, x) ^ Self::s(18, x) ^ Self::s(41, x);
    }

    fn theta0(x: u64) -> u64 {
        return Self::s(1, x) ^ Self::s(8, x) ^ Self::r(7, x);
    }

    fn theta1(x: u64) -> u64 {
        return Self::s(19, x) ^ Self::s(61, x) ^ Self::r(6, x);
    }

    fn transform(&mut self) {
        /* basic transformation step */
        for j in 16..80 {
            self.w[j] = Self::theta1(self.w[j - 2])
                .wrapping_add(self.w[j - 7])
                .wrapping_add(Self::theta0(self.w[j - 15]))
                .wrapping_add(self.w[j - 16]);
        }
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut hh = self.h[7];
        for j in 0..80 {
            /* 64 times - mush it up */
            let t1 = hh
                .wrapping_add(Self::sig1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(HASH512_K[j])
                .wrapping_add(self.w[j]);
            let t2 = Self::sig0(a).wrapping_add(Self::maj(a, b, c));
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(hh);
    }

    /* Initialise Hash function */
    pub fn init(&mut self) {
        /* initialise */
        for i in 0..64 {
            self.w[i] = 0
        }
        self.length[0] = 0;
        self.length[1] = 0;
        self.h[0] = HASH512_H0;
        self.h[1] = HASH512_H1;
        self.h[2] = HASH512_H2;
        self.h[3] = HASH512_H3;
        self.h[4] = HASH512_H4;
        self.h[5] = HASH512_H5;
        self.h[6] = HASH512_H6;
        self.h[7] = HASH512_H7;
    }

    pub fn new() -> Self {
        let mut nh = Self {
            length: [0; 2],
            h: [0; 8],
            w: [0; 80],
        };
        nh.init();
        return nh;
    }

    /* process a single byte */
    pub fn process(&mut self, byt: u8) {
        /* process the next message byte */
        let cnt = ((self.length[0] / 64) % 16) as usize;
        self.w[cnt] <<= 8;
        self.w[cnt] |= (byt & 0xFF) as u64;
        self.length[0] += 8;
        if self.length[0] == 0 {
            self.length[1] += 1;
            self.length[0] = 0
        }
        if (self.length[0] % 1024) == 0 {
            self.transform()
        }
    }

    /* process an array of bytes */

    pub fn process_array(&mut self, b: &[u8]) {
        for i in 0..b.len() {
            self.process(b[i])
        }
    }

    /* process a 32-bit integer */
    pub fn process_num(&mut self, n: i32) {
        self.process(((n >> 24) & 0xff) as u8);
        self.process(((n >> 16) & 0xff) as u8);
        self.process(((n >> 8) & 0xff) as u8);
        self.process((n & 0xff) as u8);
    }

    /* Generate 64-byte Hash */
    pub fn hash(&mut self) -> [u8; 64] {
        /* pad message and finish - supply digest */
        let mut digest: [u8; 64] = [0; 64];
        let len0 = self.length[0];
        let len1 = self.length[1];
        self.process(0x80);
        while (self.length[0] % 1024) != 896 {
            self.process(0)
        }
        self.w[14] = len1;
        self.w[15] = len0;
        self.transform();
        for i in 0..64 {
            /* convert to bytes */
            digest[i] = ((self.h[i / 8] >> (8 * (7 - i % 8))) & 0xff) as u8;
        }
        self.init();
        return digest;
    }

    /// Generate a HMAC
    ///
    /// https://tools.ietf.org/html/rfc2104
    pub fn hmac(key: &[u8], text: &[u8]) -> [u8; 64] {
        let mut k = key.to_vec();

        // Verify length of key < BLOCK_SIZE
        if k.len() > BLOCK_SIZE {
            // Reduce key to 64 bytes by hashing
            let mut hash512 = Self::new();
            hash512.init();
            hash512.process_array(&k);
            k = hash512.hash().to_vec();
        }

        // Prepare inner and outer paddings
        // inner = (ipad XOR k)
        // outer = (opad XOR k)
        let mut inner = vec![IPAD_BYTE; BLOCK_SIZE];
        let mut outer = vec![OPAD_BYTE; BLOCK_SIZE];
        for (i, byte) in k.iter().enumerate() {
            inner[i] = inner[i] ^ byte;
            outer[i] = outer[i] ^ byte;
        }

        // Concatenate inner with text = (ipad XOR k || text)
        inner.extend_from_slice(text);

        // hash inner = H(ipad XOR k || text)
        let mut hash512 = Self::new();
        hash512.init();
        hash512.process_array(&inner);
        let inner = hash512.hash();

        // Concatenate outer with hash of inner = (opad XOR k) || H(ipad XOR k || text)
        outer.extend_from_slice(&inner);

        // Final hash = H((opad XOR k) || H(ipad XOR k || text))
        let mut hash512 = Self::new();
        hash512.init();
        hash512.process_array(&outer);
        hash512.hash()
    }

    /// HKDF-Extract
    ///
    /// https://tools.ietf.org/html/rfc5869
    pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_BYTES] {
        Self::hmac(salt, ikm)
    }

    /// HKDF-Extend
    ///
    /// https://tools.ietf.org/html/rfc5869
    pub fn hkdf_extend(prk: &[u8], info: &[u8], l: u8) -> Vec<u8> {
        // n = cieling(l / 64)
        let mut n = l / (HASH_BYTES as u8);
        if n * (HASH_BYTES as u8) < l {
            n += 1;
        }

        let mut okm: Vec<u8> = vec![];
        let mut previous = vec![]; // T(0) = []

        for i in 0..n as usize {
            // Concatenate (T(i) || info || i)
            let mut text: Vec<u8> = previous;
            text.extend_from_slice(info);
            text.push((i + 1) as u8); // Note: i <= 254

            // T(i+1) = HMAC(PRK, T(i) || info || i)
            previous = Self::hmac(prk, &text).to_vec();
            okm.extend_from_slice(&previous);
        }

        // Reduce length to size L
        okm.resize(l as usize, 0);
        okm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash512_simple() {
        let text = [0x01];
        let mut hash512 = HASH512::new();
        hash512.init();
        hash512.process_array(&text);
        let output = hash512.hash().to_vec();

        let expected =
            hex::decode("7b54b66836c1fbdd13d2441d9e1434dc62ca677fb68f5fe66a464baadecdbd00576f8d6b5ac3bcc80844b7d50b1cc6603444bbe7cfcf8fc0aa1ee3c636d9e339")
                .unwrap();

        assert_eq!(expected, output);
    }

    #[test]
    fn test_hash512_empty() {
        let text = [];
        let mut hash512 = HASH512::new();
        hash512.init();
        hash512.process_array(&text);
        let output = hash512.hash().to_vec();

        let expected =
            hex::decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
                .unwrap();

        assert_eq!(expected, output);
    }

    #[test]
    fn test_hash512_long() {
        let text = hex::decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e01").unwrap();
        let mut hash512 = HASH512::new();
        hash512.init();
        hash512.process_array(&text);
        let output = hash512.hash().to_vec();

        let expected =
            hex::decode("ca3088651246c66ac9c7a8afd727539ab2d8ce9234b5e1fec311e1e435d6d9eb152e41e8e9ad953dd737d0271ad2b0299cbd6f4eb9536de34c3a01411766c7be")
                .unwrap();

        assert_eq!(expected, output);
    }

    #[test]
    fn test_hmac_simple() {
        let text = [0x01];
        let key = [0x01];
        let expected =
            hex::decode("503deb5732606d9595e308c8893fe56923fe470fc57021cf252dacb0ad15de020943e139d7a84e77956d34df3cc78142c090b959049a813cb19627c5b49c5761")
                .unwrap();

        let output = HASH512::hmac(&key, &text).to_vec();
        assert_eq!(expected, output);
    }

    #[test]
    fn test_hmac_empty() {
        let text = [];
        let key = [];
        let expected =
            hex::decode("b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47")
                .unwrap();

        let output = HASH512::hmac(&key, &text).to_vec();
        assert_eq!(expected, output);
    }

    #[test]
    fn test_hmac_long() {
        let text = hex::decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e01").unwrap();
        let key = [0x01];
        let expected =
            hex::decode("d4a8d1b936eb79e6f56b85306e62dea59a54e81690a616e804eaefe2b1e0d7319eecd68494913b3a7e78755a0e1716bb0f0f3b60a810c65f61a909562811d372")
                .unwrap();

        let output = HASH512::hmac(&key, &text).to_vec();
        assert_eq!(expected, output);
    }

    #[test]
    fn test_hkdf_case_a() {
        // From https://www.kullo.net/blog/hkdf-sha-512-test-vectors/
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let expected_prk =
            hex::decode("665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237")
            .unwrap();

        let output_prk = HASH512::hkdf_extract(&salt, &ikm).to_vec();
        assert_eq!(expected_prk, output_prk);

        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let l = 42;
        let expected_okm = hex::decode(
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
        )
        .unwrap();

        let output_okm = HASH512::hkdf_extend(&expected_prk, &info, l);
        assert_eq!(expected_okm, output_okm);
    }

    #[test]
    fn test_hkdf_case_b() {
        // From https://www.kullo.net/blog/hkdf-sha-512-test-vectors/
        let ikm = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap();
        let salt = hex::decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
        let expected_prk =
            hex::decode("35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a")
            .unwrap();

        let output_prk = HASH512::hkdf_extract(&salt, &ikm).to_vec();
        assert_eq!(expected_prk, output_prk);

        let info = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let l = 82;
        let expected_okm = hex::decode(
                "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93",
            )
            .unwrap();

        let output_okm = HASH512::hkdf_extend(&expected_prk, &info, l);
        assert_eq!(expected_okm, output_okm);
    }

    #[test]
    fn test_hkdf_case_c() {
        // From https://www.kullo.net/blog/hkdf-sha-512-test-vectors/
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = vec![];
        let expected_prk =
            hex::decode("fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6")
            .unwrap();

        let output_prk = HASH512::hkdf_extract(&salt, &ikm).to_vec();
        assert_eq!(expected_prk, output_prk);

        let info = vec![];
        let l = 42;
        let expected_okm = hex::decode(
            "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac",
        )
        .unwrap();

        let output_okm = HASH512::hkdf_extend(&expected_prk, &info, l);
        assert_eq!(expected_okm, output_okm);
    }

    #[test]
    fn test_hkdf_case_d() {
        // From https://www.kullo.net/blog/hkdf-sha-512-test-vectors/
        let ikm = hex::decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap();
        let salt = vec![];
        let expected_prk =
            hex::decode("5346b376bf3aa9f84f8f6ed5b1c4f489172e244dac303d12f68ecc766ea600aa88495e7fb605803122fa136924a840b1f0719d2d5f68e29b242299d758ed680c")
            .unwrap();

        let output_prk = HASH512::hkdf_extract(&salt, &ikm).to_vec();
        assert_eq!(expected_prk, output_prk);

        let info = vec![];
        let l = 42;
        let expected_okm = hex::decode(
            "1407d46013d98bc6decefcfee55f0f90b0c7f63d68eb1a80eaf07e953cfc0a3a5240a155d6e4daa965bb",
        )
        .unwrap();

        let output_okm = HASH512::hkdf_extend(&expected_prk, &info, l);
        assert_eq!(expected_okm, output_okm);
    }
}
