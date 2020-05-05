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

const HASH384_H0: u64 = 0xcbbb9d5dc1059ed8;
const HASH384_H1: u64 = 0x629a292a367cd507;
const HASH384_H2: u64 = 0x9159015a3070dd17;
const HASH384_H3: u64 = 0x152fecd8f70e5939;
const HASH384_H4: u64 = 0x67332667ffc00b31;
const HASH384_H5: u64 = 0x8eb44a8768581511;
const HASH384_H6: u64 = 0xdb0c2e0d64f98fa7;
const HASH384_H7: u64 = 0x47b5481dbefa4fa4;

const HASH384_K: [u64; 80] = [
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
pub const HASH_BYTES: usize = 48;
// Ipad Byte
const IPAD_BYTE: u8 = 0x36;
// Opad Byte
const OPAD_BYTE: u8 = 0x5c;

pub struct HASH384 {
    length: [u64; 2],
    h: [u64; 8],
    w: [u64; 80],
}

impl HASH384 {
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
        // basic transformation step
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
                .wrapping_add(HASH384_K[j])
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

    /// Initialise Hash function
    pub fn init(&mut self) {
        // initialise
        for i in 0..64 {
            self.w[i] = 0
        }
        self.length[0] = 0;
        self.length[1] = 0;
        self.h[0] = HASH384_H0;
        self.h[1] = HASH384_H1;
        self.h[2] = HASH384_H2;
        self.h[3] = HASH384_H3;
        self.h[4] = HASH384_H4;
        self.h[5] = HASH384_H5;
        self.h[6] = HASH384_H6;
        self.h[7] = HASH384_H7;
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

    /// Process a single byte
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

    /// Process an array of bytes
    pub fn process_array(&mut self, b: &[u8]) {
        for i in 0..b.len() {
            self.process(b[i])
        }
    }

    /// Process a 32-bit integer
    pub fn process_num(&mut self, n: i32) {
        self.process(((n >> 24) & 0xff) as u8);
        self.process(((n >> 16) & 0xff) as u8);
        self.process(((n >> 8) & 0xff) as u8);
        self.process((n & 0xff) as u8);
    }

    /// Generate 48-byte Hash
    pub fn hash(&mut self) -> [u8; HASH_BYTES] {
        /* pad message and finish - supply digest */
        let mut digest: [u8; 48] = [0; HASH_BYTES];
        let len0 = self.length[0];
        let len1 = self.length[1];
        self.process(0x80);
        while (self.length[0] % 1024) != 896 {
            self.process(0)
        }
        self.w[14] = len1;
        self.w[15] = len0;
        self.transform();
        for i in 0..HASH_BYTES {
            // convert to bytes
            digest[i] = ((self.h[i / 8] >> (8 * (7 - i % 8))) & 0xff) as u8;
        }
        self.init();
        return digest;
    }

    /// Generate a HMAC
    ///
    /// https://tools.ietf.org/html/rfc2104
    pub fn hmac(key: &[u8], text: &[u8]) -> [u8; HASH_BYTES] {
        let mut k = key.to_vec();

        // Verify length of key < BLOCK_SIZE
        if k.len() > BLOCK_SIZE {
            // Reduce key to 64 bytes by hashing
            let mut hash384 = Self::new();
            hash384.init();
            hash384.process_array(&k);
            k = hash384.hash().to_vec();
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
        let mut hash384 = Self::new();
        hash384.init();
        hash384.process_array(&inner);
        let inner = hash384.hash();

        // Concatenate outer with hash of inner = (opad XOR k) || H(ipad XOR k || text)
        outer.extend_from_slice(&inner);

        // Final hash = H((opad XOR k) || H(ipad XOR k || text))
        let mut hash384 = Self::new();
        hash384.init();
        hash384.process_array(&outer);
        hash384.hash()
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
        // n = cieling(l / 48)
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
    // TODO: Test HKDF
    use super::*;

    #[test]
    fn test_hash384_simple() {
        let text = [0x01];
        let mut hash384 = HASH384::new();
        hash384.init();
        hash384.process_array(&text);
        let output = hash384.hash().to_vec();

        let expected =
            hex::decode("8d2ce87d86f55fcfab770a047b090da23270fa206832dfea7e0c946fff451f819add242374be551b0d6318ed6c7d41d8")
                .unwrap();

        assert_eq!(expected, output);
    }

    #[test]
    fn test_hash384_empty() {
        let text = [];
        let mut hash384 = HASH384::new();
        hash384.init();
        hash384.process_array(&text);
        let output = hash384.hash().to_vec();

        let expected =
            hex::decode("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
                .unwrap();

        assert_eq!(expected, output);
    }

    #[test]
    fn test_hash384_long() {
        let text = hex::decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e01").unwrap();
        let mut hash384 = HASH384::new();
        hash384.init();
        hash384.process_array(&text);
        let output = hash384.hash().to_vec();

        let expected =
            hex::decode("1793c4989b4e68154c7159bee9756e5b72dbc0bd57c7583bb09c9a1c111f46fcaf8ef9faf1715e1eff36526c6c15a1f1")
                .unwrap();

        assert_eq!(expected, output);
    }

    #[test]
    fn test_hmac_simple() {
        let text = [0x01];
        let key = [0x01];
        let expected =
            hex::decode("52650d924c6c3ed9f7b0fc64107e139d0d9254e8ecfb32e5780535897532ccee5272d61ec5d2abd19fa60e9f69f8711d")
                .unwrap();

        let output = HASH384::hmac(&key, &text).to_vec();
        assert_eq!(expected, output);
    }

    #[test]
    fn test_hmac_empty() {
        let text = [];
        let key = [];
        let expected =
            hex::decode("6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc")
                .unwrap();

        let output = HASH384::hmac(&key, &text).to_vec();
        assert_eq!(expected, output);
    }

    #[test]
    fn test_hmac_long() {
        let text = hex::decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e01").unwrap();
        let key = [0x01];
        let expected =
            hex::decode("dee07cba20bcf23f3913c6a885ac08b90702e2c5765f64040b336375c5ad35cce89e9c9f62983be516447e35e65de70c")
                .unwrap();

        let output = HASH384::hmac(&key, &text).to_vec();
        assert_eq!(expected, output);
    }
}
