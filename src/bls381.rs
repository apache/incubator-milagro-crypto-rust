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

/// BLS12-381
///
/// An implementation of BLS12-381 as specified by the following standard:
/// https://github.com/cfrg/draft-irtf-cfrg-bls-signature
pub mod iso;

use self::iso::{iso11_to_ecp, iso3_to_ecp2};
use super::big::Big;
use super::ecp::ECP;
use super::ecp2::ECP2;
use super::fp::FP;
use super::fp2::FP2;
use super::hash_to_curve::{
    hash_to_field_fp, hash_to_field_fp2, simplified_swu_fp, simplified_swu_fp2,
};
use super::pair;
use super::rom::*;

use rand::RAND;
use sha3::SHA3;
use sha3::SHAKE256;
use std::str;

// BLS API Functions
pub const BFS: usize = MODBYTES as usize;
pub const BGS: usize = MODBYTES as usize;
pub const BLS_OK: isize = 0;
pub const BLS_FAIL: isize = -1;

// Hash a message to an ECP point, using SHA3
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
    let q = Big::new_ints(&CURVE_ORDER);
    let g = ECP2::generator();
    let sc = Big::randomnum(&q, &mut rng);
    sc.tobytes(s);
    pair::g2mul(&g, &sc).tobytes(w);
    BLS_OK
}

/// Sign message m using private key s to produce signature sig.
pub fn sign(sig: &mut [u8], m: &str, s: &[u8]) -> isize {
    let d = bls_hashit(m);
    let mut sc = Big::frombytes(&s);
    pair::g1mul(&d, &mut sc).tobytes(sig, true);
    BLS_OK
}

/// Verify signature given message m, the signature sig, and the public key w
pub fn verify(sig: &[u8], m: &str, w: &[u8]) -> isize {
    let hm = bls_hashit(m);
    let mut d = ECP::frombytes(&sig);
    let g = ECP2::generator();
    let pk = ECP2::frombytes(&w);
    d.neg();

    // Use new multi-pairing mechanism
    let mut r = pair::initmp();
    pair::another(&mut r, &g, &d);
    pair::another(&mut r, &pk, &hm);
    let mut v = pair::miller(&r);

    //.. or alternatively
    //    let mut v = pair::ate2(&g, &d, &pk, &hm);

    v = pair::fexp(&v);
    if v.isunity() {
        return BLS_OK;
    }
    BLS_FAIL
}

/*************************************************************************************************
* Functions for hashing to curve when signatures are on ECP
*************************************************************************************************/
/// Hash to Curve
///
/// Takes a message as input and converts it to a Curve Point
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-3
pub fn hash_to_curve_g1(msg: &[u8]) -> ECP {
    let u =
        hash_to_field_fp(msg, 2, DST).expect("hash to field should not fail for given parameters");
    let mut q0 = map_to_curve_g1(u[0].clone());
    let q1 = map_to_curve_g1(u[1].clone());
    q0.add(&q1);
    let p = q0.mul(&H_EFF_G1);
    p
}

// Simplified SWU for Pairing-Friendly Curves
//
// Take a field point and map it to a Curve Point.
// SSWU - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-6.6.2
// ISO11 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#appendix-C.2
fn map_to_curve_g1(u: FP) -> ECP {
    let (x, y) = simplified_swu_fp(u);
    iso11_to_ecp(&x, &y)
}

/*************************************************************************************************
* Functions for hashing to curve when signatures are on ECP2
*************************************************************************************************/
/// Hash to Curve
///
/// Takes a message as input and converts it to a Curve Point
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-3
pub fn hash_to_curve_g2(msg: &[u8]) -> ECP2 {
    let u =
        hash_to_field_fp2(msg, 2, DST).expect("hash to field should not fail for given parameters");
    let mut q0 = map_to_curve_g2(u[0].clone());
    let q1 = map_to_curve_g2(u[1].clone());
    q0.add(&q1);
    q0.clear_cofactor();
    q0
}

// Simplified SWU for Pairing-Friendly Curves
//
// Take a field point and map it to a Curve Point.
// SSWU - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-6.6.2
// ISO3 - https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#appendix-C.3
fn map_to_curve_g2(u: FP2) -> ECP2 {
    let (x, y) = simplified_swu_fp2(u);
    iso3_to_ecp2(&x, &y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    #[cfg(feature = "bls381g2")]
    fn test_hash_to_curve_g2() {
        // Only run when signatures are on G2
        if BLS_SIG_G1 {
            return;
        }

        // Read hash to curve test vector
        let reader = json_reader(H2C_SUITE);
        let test_vectors: Bls12381Ro = serde_json::from_reader(reader).unwrap();

        // Iterate through each individual case
        for case in test_vectors.vectors {
            // Execute hash to curve
            let u = hash_to_field_fp2(case.msg.as_bytes(), 2, test_vectors.dst.as_bytes()).unwrap();
            let q0 = map_to_curve_g2(u[0].clone());
            let q1 = map_to_curve_g2(u[1].clone());
            let mut r = q0.clone();
            r.add(&q1);
            let mut p = r.clone();
            p.clear_cofactor();

            // Verify hash to curve outputs
            // Check u
            assert_eq!(case.u.len(), u.len());
            for (i, u_str) in case.u.iter().enumerate() {
                // Convert case 'u[i]' to FP2
                let u_str_parts: Vec<&str> = u_str.split(',').collect();
                let a = Big::frombytes(&hex::decode(&u_str_parts[0].get(2..).unwrap()).unwrap());
                let b = Big::frombytes(&hex::decode(&u_str_parts[1].get(2..).unwrap()).unwrap());
                let expected_u_i = FP2::new_bigs(a, b);

                // Verify u[i]
                assert_eq!(expected_u_i, u[i]);
            }

            // Check Q0
            let x_str_parts: Vec<&str> = case.Q0.x.split(',').collect();
            let a = Big::frombytes(&hex::decode(&x_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::frombytes(&hex::decode(&x_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_x = FP2::new_bigs(a, b);

            let y_str_parts: Vec<&str> = case.Q0.y.split(',').collect();
            let a = Big::frombytes(&hex::decode(&y_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::frombytes(&hex::decode(&y_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_y = FP2::new_bigs(a, b);

            let expected_q0 = ECP2::new_fp2s(expected_x, expected_y);
            assert_eq!(expected_q0, q0);

            // Check Q1
            let x_str_parts: Vec<&str> = case.Q1.x.split(',').collect();
            let a = Big::frombytes(&hex::decode(&x_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::frombytes(&hex::decode(&x_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_x = FP2::new_bigs(a, b);

            let y_str_parts: Vec<&str> = case.Q1.y.split(',').collect();
            let a = Big::frombytes(&hex::decode(&y_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::frombytes(&hex::decode(&y_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_y = FP2::new_bigs(a, b);

            let expected_q1 = ECP2::new_fp2s(expected_x, expected_y);
            assert_eq!(expected_q1, q1);

            // Check P
            let x_str_parts: Vec<&str> = case.P.x.split(',').collect();
            let a = Big::frombytes(&hex::decode(&x_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::frombytes(&hex::decode(&x_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_x = FP2::new_bigs(a, b);

            let y_str_parts: Vec<&str> = case.P.y.split(',').collect();
            let a = Big::frombytes(&hex::decode(&y_str_parts[0].get(2..).unwrap()).unwrap());
            let b = Big::frombytes(&hex::decode(&y_str_parts[1].get(2..).unwrap()).unwrap());
            let expected_y = FP2::new_bigs(a, b);

            let expected_p = ECP2::new_fp2s(expected_x, expected_y);
            assert_eq!(expected_p, p);
        }
    }

    #[test]
    #[cfg(feature = "bls381g1")]
    fn test_hash_to_curve_g1() {
        // Only run when signatures are on G2
        if !BLS_SIG_G1 {
            return;
        }

        // Read hash to curve test vector
        let reader = json_reader(H2C_SUITE);
        let test_vectors: Bls12381Ro = serde_json::from_reader(reader).unwrap();

        // Iterate through each individual case
        for case in test_vectors.vectors {
            // Execute hash to curve
            let u = hash_to_field_fp(case.msg.as_bytes(), 2, test_vectors.dst.as_bytes()).unwrap();
            let q0 = map_to_curve_g1(u[0].clone());
            let q1 = map_to_curve_g1(u[1].clone());
            let mut r = q0.clone();
            r.add(&q1);
            let p = r.mul(&H_EFF_G1);

            // Verify hash to curve outputs
            // Check u
            assert_eq!(case.u.len(), u.len());
            for (i, u_str) in case.u.iter().enumerate() {
                // Convert case 'u[i]' to FP
                let a = Big::frombytes(&hex::decode(&u_str.get(2..).unwrap()).unwrap());
                let expected_u_i = FP::new_big(a);

                // Verify u[i]
                assert_eq!(expected_u_i, u[i]);
            }

            // Check Q0
            let a = Big::frombytes(&hex::decode(&case.Q0.x.get(2..).unwrap()).unwrap());
            let expected_x = FP::new_big(a);

            let a = Big::frombytes(&hex::decode(&case.Q0.y.get(2..).unwrap()).unwrap());
            let expected_y = FP::new_big(a);

            let expected_q0 = ECP::new_fps(expected_x, expected_y);
            assert_eq!(expected_q0, q0);

            // Check Q1
            let a = Big::frombytes(&hex::decode(&case.Q1.x.get(2..).unwrap()).unwrap());
            let expected_x = FP::new_big(a);

            let a = Big::frombytes(&hex::decode(&case.Q1.y.get(2..).unwrap()).unwrap());
            let expected_y = FP::new_big(a);

            let expected_q1 = ECP::new_fps(expected_x, expected_y);
            assert_eq!(expected_q1, q1);

            // Check P
            let a = Big::frombytes(&hex::decode(&case.P.x.get(2..).unwrap()).unwrap());
            let expected_x = FP::new_big(a);

            let a = Big::frombytes(&hex::decode(&case.P.y.get(2..).unwrap()).unwrap());
            let expected_y = FP::new_big(a);

            let expected_p = ECP::new_fps(expected_x, expected_y);
            assert_eq!(expected_p, p);
        }
    }
}
