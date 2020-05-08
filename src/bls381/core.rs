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

use super::super::big::Big;
use super::super::ecp::ECP;
use super::super::ecp2::ECP2;
use super::super::fp::FP;
use super::super::fp2::FP2;
use super::super::hash_to_curve::*;
use super::super::pair;
use super::super::rom::*;
use super::iso::{iso11_to_ecp, iso3_to_ecp2};

use errors::AmclError;
use hash256::HASH256;
use rand::RAND;

// Key Generation Constants
/// Domain for key generation.
pub const KEY_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
/// L = ceil((3 * ceil(log2(r))) / 16) = 48.
pub const KEY_GENERATION_L: u8 = 48;

// Length of objects in bytes
/// The required number of bytes for a secret key
pub const SECRET_KEY_BYTES: usize = 32;
/// The required number of bytes for a compressed G1 point
pub const G1_BYTES: usize = MODBYTES + 1;
/// The required number of bytes for an uncompressed G2 point
pub const G2_BYTES: usize = MODBYTES * 4 + 1;

/// KeyGenerate
///
/// Generate a new Secret Key based off Initial Keying Material (IKM) and Key Info (salt).
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.3
pub(crate) fn key_generate(ikm: &[u8], key_info: &[u8]) -> [u8; SECRET_KEY_BYTES] {
    // PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1))
    let mut prk = Vec::<u8>::with_capacity(1 + ikm.len());
    prk.extend_from_slice(ikm);
    prk.push(0);
    let prk = HASH256::hkdf_extract(KEY_SALT, &prk);

    // OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
    let mut info = key_info.to_vec();
    info.extend_from_slice(&[0, KEY_GENERATION_L]);
    let okm = HASH256::hkdf_extend(&prk, &info, KEY_GENERATION_L);

    // SK = OS2IP(OKM) mod r
    let r = Big::new_ints(&CURVE_ORDER);
    let mut secret_key = Big::frombytes(&okm);
    secret_key.rmod(&r);

    secret_key_to_bytes(&secret_key)
}

// Converts secret key bytes to a Big
pub(crate) fn secret_key_from_bytes(secret_key: &[u8]) -> Result<Big, AmclError> {
    if secret_key.len() != SECRET_KEY_BYTES {
        return Err(AmclError::InvalidSecretKeySize);
    }

    // Prepend to MODBYTES in length
    let mut secret_key_bytes = [0u8; MODBYTES];
    secret_key_bytes[MODBYTES - SECRET_KEY_BYTES..].copy_from_slice(secret_key);

    // Ensure secret key is in the range [0, r-1].
    let secret_key = Big::frombytes(&secret_key_bytes);
    if secret_key >= Big::new_ints(&CURVE_ORDER) {
        return Err(AmclError::InvalidSecretKeyRange);
    }

    Ok(secret_key)
}

// Converts secret key Big to bytes
pub(crate) fn secret_key_to_bytes(secret_key: &Big) -> [u8; SECRET_KEY_BYTES] {
    let mut big_bytes = [0u8; MODBYTES];
    secret_key.tobytes(&mut big_bytes);
    let mut secret_key_bytes = [0u8; SECRET_KEY_BYTES];
    secret_key_bytes.copy_from_slice(&big_bytes[MODBYTES - SECRET_KEY_BYTES..]);
    secret_key_bytes
}

// Verifies a G1 point is in subgroup `r`.
pub(crate) fn subgroup_check_g1(point: &ECP) -> bool {
    let r = Big::new_ints(&CURVE_ORDER);
    let check = pair::g1mul(&point, &r);
    check.is_infinity()
}

// Verifies a G2 point is in subgroup `r`.
pub(crate) fn subgroup_check_g2(point: &ECP2) -> bool {
    let r = Big::new_ints(&CURVE_ORDER);
    let check = pair::g2mul(&point, &r);
    check.is_infinity()
}

/*************************************************************************************************
* Core BLS Functions when signatures are on G1
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2
*************************************************************************************************/

/// Generate key pair - (secret key, public key)
pub(crate) fn key_pair_generate_g1(rng: &mut RAND) -> ([u8; SECRET_KEY_BYTES], [u8; G2_BYTES]) {
    // Fill random bytes
    let mut ikm = [0u8; SECRET_KEY_BYTES];
    for byte in ikm.iter_mut() {
        *byte = rng.getbyte();
    }

    // Generate key pair
    let secret_key = key_generate(&ikm, &[]);
    let public_key =
        secret_key_to_public_key_g1(&secret_key).expect("Valid secret key was generated");

    (secret_key, public_key)
}

/// Secret Key To Public Key
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.4
pub(crate) fn secret_key_to_public_key_g1(secret_key: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP2::generator();
    let public_key = pair::g2mul(&g, &secret_key);

    // Convert to bytes
    let mut public_key_bytes = [0u8; G2_BYTES];
    public_key.tobytes(&mut public_key_bytes);
    Ok(public_key_bytes)
}

// CoreSign
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.7
pub(crate) fn core_sign_g1(secret_key: &[u8], msg: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let hash = hash_to_curve_g1(msg, DST_G1);
    let signature = pair::g1mul(&hash, &secret_key);

    let mut signed_message_bytes = [0u8; G1_BYTES];
    signature.tobytes(&mut signed_message_bytes, true);
    Ok(signed_message_bytes)
}

// CoreVerify
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.7
pub(crate) fn core_verify_g1(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    // TODO: return false if bytes are invalid.
    let public_key = ECP2::frombytes(public_key);
    let signature = ECP::frombytes(signature);

    // Subgroup checks for signature and public key
    if !subgroup_check_g1(&signature) || !subgroup_check_g2(&public_key) {
        return false;
    }

    // Hash msg and negate generator for pairing
    let hash = hash_to_curve_g1(msg, DST_G1);
    let mut g = ECP2::generator();
    g.neg();

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &g, &signature);
    pair::another(&mut r, &public_key, &hash);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.isunity()
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.8
pub(crate) fn aggregate_g1(points: &[&[u8]]) -> Result<[u8; G1_BYTES], AmclError> {
    if points.len() == 0 {
        return Err(AmclError::AggregateEmptyPoints);
    }

    // TODO: Error rather than panic if bytes are invalid
    let mut aggregate = ECP::frombytes(&points[0]);
    for point in points.iter().skip(1) {
        aggregate.add(&ECP::frombytes(&point));
    }

    // Return compressed point
    let mut aggregate_bytes = [0u8; G1_BYTES];
    aggregate.tobytes(&mut aggregate_bytes, true);
    Ok(aggregate_bytes)
}

// CoreAggregateVerify
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.9
pub(crate) fn core_aggregate_verify_g1(
    public_keys: &[&[u8]],
    msgs: &[&[u8]],
    signature: &[u8],
) -> bool {
    // Preconditions
    if public_keys.len() == 0 || public_keys.len() != msgs.len() {
        return false;
    }

    // TODO: return false if point is invalid bytes
    let signature = ECP::frombytes(signature);

    // Subgroup checks for signature
    if !subgroup_check_g1(&signature) {
        return false;
    }

    // Pair e(signature, -g)
    let mut g = ECP2::generator();
    g.neg();
    let mut r = pair::initmp();
    pair::another(&mut r, &g, &signature);

    for (i, public_key) in public_keys.iter().enumerate() {
        let public_key = ECP2::frombytes(public_key);
        // Subgroup check for public key
        if !subgroup_check_g2(&public_key) {
            return false;
        }

        // Pair *= e(pk[i], H(msgs[i]))
        let hash = hash_to_curve_g1(msgs[i], DST_G1);
        pair::another(&mut r, &public_key, &hash);
    }

    // True if pairing output is 1
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);
    v.isunity()
}

/*************************************************************************************************
* Core BLS Functions when signatures are on G2
*
* https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2
*************************************************************************************************/

/// Generate key pair - (secret key, public key)
pub(crate) fn key_pair_generate_g2(rng: &mut RAND) -> ([u8; SECRET_KEY_BYTES], [u8; G1_BYTES]) {
    // Fill random bytes
    let mut ikm = [0u8; SECRET_KEY_BYTES];
    for byte in ikm.iter_mut() {
        *byte = rng.getbyte();
    }

    // Generate key pair
    let secret_key = key_generate(&ikm, &[]);
    let public_key =
        secret_key_to_public_key_g2(&secret_key).expect("Valid secret key was generated");

    (secret_key, public_key)
}

/// Secret Key To Public Key
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.4
pub(crate) fn secret_key_to_public_key_g2(secret_key: &[u8]) -> Result<[u8; G1_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;
    let g = ECP::generator();
    let public_key = pair::g1mul(&g, &secret_key);

    // Convert to bytes
    let mut public_key_bytes = [0u8; G1_BYTES];
    public_key.tobytes(&mut public_key_bytes, true);
    Ok(public_key_bytes)
}

// CoreSign
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.7
pub(crate) fn core_sign_g2(secret_key: &[u8], msg: &[u8]) -> Result<[u8; G2_BYTES], AmclError> {
    let secret_key = secret_key_from_bytes(secret_key)?;

    let hash = hash_to_curve_g2(msg, DST_G2);
    let signature = pair::g2mul(&hash, &secret_key);

    let mut signed_message_bytes = [0u8; G2_BYTES];
    signature.tobytes(&mut signed_message_bytes);
    Ok(signed_message_bytes)
}

// CoreVerify
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.7
pub(crate) fn core_verify_g2(public_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    // TODO: return false if bytes are invalid.
    let public_key = ECP::frombytes(public_key);
    let signature = ECP2::frombytes(signature);

    // Subgroup checks for signature and public key
    if !subgroup_check_g1(&public_key) || !subgroup_check_g2(&signature) {
        return false;
    }

    // Hash msg and negate generator for pairing
    let hash = hash_to_curve_g2(msg, DST_G2);
    let mut g = ECP::generator();
    g.neg();

    // Pair e(H(msg), pk) * e(signature, -g)
    let mut r = pair::initmp();
    pair::another(&mut r, &signature, &g);
    pair::another(&mut r, &hash, &public_key);
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);

    // True if pairing output is 1
    v.isunity()
}

/// Aggregate
///
/// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.8
pub(crate) fn aggregate_g2(points: &[&[u8]]) -> Result<[u8; G2_BYTES], AmclError> {
    if points.len() == 0 {
        return Err(AmclError::AggregateEmptyPoints);
    }

    // TODO: Error if bytes are invalid
    let mut aggregate = ECP2::frombytes(&points[0]);
    for point in points.iter().skip(1) {
        aggregate.add(&ECP2::frombytes(&point));
    }

    // Return uncompressed point
    let mut aggregate_bytes = [0u8; G2_BYTES];
    aggregate.tobytes(&mut aggregate_bytes);
    Ok(aggregate_bytes)
}

// CoreAggregateVerify
//
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.9
pub(crate) fn core_aggregate_verify_g2(
    public_keys: &[&[u8]],
    msgs: &[&[u8]],
    signature: &[u8],
) -> bool {
    // TODO: return false if invalid bytes
    let signature = ECP2::frombytes(signature);

    // Preconditions
    if public_keys.len() == 0 || public_keys.len() != msgs.len() {
        return false;
    }

    // Subgroup checks for signature
    if !subgroup_check_g2(&signature) {
        return false;
    }

    // Pair e(signature, -g)
    let mut g = ECP::generator();
    g.neg();
    let mut r = pair::initmp();
    pair::another(&mut r, &signature, &g);

    for (i, public_key) in public_keys.iter().enumerate() {
        let public_key = ECP::frombytes(public_key);

        // Subgroup check for public key
        if !subgroup_check_g1(&public_key) {
            return false;
        }

        // Pair *= e(pk[i], H(msgs[i]))
        let hash = hash_to_curve_g2(msgs[i], DST_G2);
        pair::another(&mut r, &hash, &public_key);
    }

    // True if pairing output is 1
    let mut v = pair::miller(&r);
    v = pair::fexp(&v);
    v.isunity()
}

/*************************************************************************************************
* Functions for hashing to curve when signatures are on G1
*************************************************************************************************/

/// Hash to Curve
///
/// Takes a message as input and converts it to a Curve Point
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-3
pub fn hash_to_curve_g1(msg: &[u8], dst: &[u8]) -> ECP {
    let u =
        hash_to_field_fp(msg, 2, dst).expect("hash to field should not fail for given parameters");
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
* Functions for hashing to curve when signatures are on G2
*************************************************************************************************/

/// Hash to Curve
///
/// Takes a message as input and converts it to a Curve Point
/// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-3
pub fn hash_to_curve_g2(msg: &[u8], dst: &[u8]) -> ECP2 {
    let u =
        hash_to_field_fp2(msg, 2, dst).expect("hash to field should not fail for given parameters");
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
    #[cfg(feature = "bls381")]
    fn test_hash_to_curve_g2() {
        // Read hash to curve test vector
        let reader = json_reader(H2C_SUITE_G2);
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

            // Verify against hash_to_curve()
            let hash_to_curve_p =
                hash_to_curve_g2(case.msg.as_bytes(), test_vectors.dst.as_bytes());
            assert_eq!(hash_to_curve_p, p);

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
    #[cfg(feature = "bls381")]
    fn test_hash_to_curve_g1() {
        // Read hash to curve test vector
        let reader = json_reader(H2C_SUITE_G1);
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

            // Verify against hash_to_curve()
            let hash_to_curve_p =
                hash_to_curve_g1(case.msg.as_bytes(), test_vectors.dst.as_bytes());
            assert_eq!(hash_to_curve_p, p);

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
