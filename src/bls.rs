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
use super::ecp::ECP;
use super::ecp2::ECP2;
use super::pair;
use super::rom;
use crate::rand::RAND;
use crate::sha3::SHA3;
use crate::sha3::SHAKE256;

use std::str;

// BLS API Functions
pub const BFS: usize = big::MODBYTES as usize;
pub const BGS: usize = big::MODBYTES as usize;
pub const BLS_OK: isize = 0;
pub const BLS_FAIL: isize = -1;

// hash a message to an ECP point, using SHA3
#[allow(non_snake_case)]
fn bls_hashit(m: &str) -> ECP {
    let mut sh = SHA3::new(SHAKE256);
    let mut hm: [u8; BFS] = [0; BFS];
    let t = m.as_bytes();
    for i in 0..m.len() {
        sh.process(t[i]);
    }
    sh.shake(&mut hm, BFS);
    let P = ECP::mapit(&hm);
    P
}

/// Generate key pair, private key s, public key w
pub fn key_pair_generate(mut rng: &mut RAND, s: &mut [u8], w: &mut [u8]) -> isize {
    let q = Big::new_ints(&rom::CURVE_ORDER);
    let g = ECP2::generator();
    let sc = Big::randomnum(&q, &mut rng);
    sc.to_bytes(s);
    pair::g2mul(&g, &sc).to_bytes(w);
    BLS_OK
}

/// Sign message m using private key s to produce signature sig.
pub fn sign(sig: &mut [u8], m: &str, s: &[u8]) -> isize {
    let d = bls_hashit(m);
    let mut sc = Big::from_bytes(&s);
    pair::g1mul(&d, &mut sc).to_bytes(sig, true);
    BLS_OK
}

/// Verify signature given message m, the signature sig, and the public key w
pub fn verify(sig: &[u8], m: &str, w: &[u8]) -> isize {
    let hm = bls_hashit(m);
    let mut d = ECP::from_bytes(&sig);
    let g = ECP2::generator();
    let pk = ECP2::from_bytes(&w);
    d.neg();

    // Use new multi-pairing mechanism
    let mut r = pair::initmp();
    pair::another(&mut r, &g, &d);
    pair::another(&mut r, &pk, &hm);
    let mut v = pair::miller(&r);

    //.. or alternatively
    //    let mut v = pair::ate2(&g, &d, &pk, &hm);

    v = pair::fexp(&v);
    if v.is_unity() {
        return BLS_OK;
    }
    BLS_FAIL
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn test_bls() {
        let mut rng = create_rng();

        let mut s: [u8; BGS] = [0; BGS];

        const G1S: usize = BFS + 1; /* Group 1 Size */
        const G2S: usize = 4 * BFS; /* Group 2 Size */

        let mut w: [u8; G2S] = [0; G2S];
        let mut sig: [u8; G1S] = [0; G1S];

        let m = String::from("This is a test message");

        key_pair_generate(&mut rng, &mut s, &mut w);
        print!("Private key : 0x");
        printbinary(&s);
        print!("Public  key : 0x");
        printbinary(&w);

        sign(&mut sig, &m, &s);
        print!("Signature : 0x");
        printbinary(&sig);

        let res = verify(&sig, &m, &w);
        if res == 0 {
            println!("Signature is OK");
        } else {
            println!("Signature is *NOT* OK");
        }
    }
}
